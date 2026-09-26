import sys
import json
import logging
import argparse
import time
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from src.llm_client import DEFAULT_MODEL, LLMClient, MODELS, _resolve
from src.coder import Coder
from src.assembler_harness import AssemblerHarness
from src.campaign import Campaign
from src.trace import RunTrace, safe_name, sha256_text, serialize_error, utc_now
from src.interrupts import RunGuard, RunInterrupted
from src.recovery import recover_stale_runs
from src.experimental_inputs import (
    condition_context_mode,
    freeze_experimental_inputs,
    load_frozen_inputs,
    load_yaml,
    protocol_condition_ids,
)
from src.preflight import run_preflight
from src.context_modes import (
    PROMPT_TEMPLATE_VERSION,
    component_context,
    context_visibility,
    validate_context_mode,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pipeline")


def run(
    prompt: str,
    model: str | None = None,
    delay: int = 0,
    temperature: float | None = None,
    top_p: float | None = None,
    seed: int | None = None,
    max_tokens: int | None = None,
    output_root: Path = Path("output"),
    scenario: str | None = None,
    scenario_config_h: str | None = None,
    scenario_components: list[dict] | None = None,
    scenario_main_c: str | None = None,
    openrouter_provider: str | None = None,
    experiment_id: str | None = None,
    condition: str | None = None,
    replicate: int | None = None,
    run_purpose: str = "development",
    campaign: dict | None = None,
    provenance_exclude_dirs: list[Path] | None = None,
    context_mode: str = "fragmented",
) -> Path:
    if not scenario_components:
        raise ValueError("O modo componentes exige 'components' definido no cenario.")
    if experiment_id is not None:
        experiment_id = experiment_id.strip()
        if not experiment_id:
            raise ValueError("--experiment-id nao pode ser vazio.")
    if condition is not None:
        condition = condition.strip()
        if not condition:
            raise ValueError("--condition nao pode ser vazio.")
    if replicate is not None and (
        isinstance(replicate, bool) or not isinstance(replicate, int) or replicate < 1
    ):
        raise ValueError("--replicate deve ser maior que zero.")
    if run_purpose not in {"development", "official", "pilot"}:
        raise ValueError("run_purpose deve ser development, official ou pilot.")
    context_mode = validate_context_mode(context_mode)
    global_context = component_context(
        context_mode,
        prompt,
        scenario_components,
        scenario_config_h or "",
        scenario_main_c or "",
    )
    full_context = component_context(
        "full_context",
        prompt,
        scenario_components,
        scenario_config_h or "",
        scenario_main_c or "",
    )
    full_context_sha256 = sha256_text(full_context or "")
    expected_full_context_sha256 = (campaign or {}).get("full_context_sha256")
    if (
        expected_full_context_sha256 is not None
        and expected_full_context_sha256 != full_context_sha256
    ):
        raise ValueError("O contexto global da run difere da intervencao congelada.")
    parameters = {
        "temperature": temperature,
        "top_p": top_p,
        "seed": seed,
        "max_tokens": max_tokens,
    }
    recover_stale_runs(output_root)
    trace = RunTrace(
        prompt=prompt,
        requested_model=model,
        delay=delay,
        output_root=output_root,
        generation_parameters=parameters,
        routing_parameters={
            "openrouter_provider": openrouter_provider,
            "allow_fallbacks": False if openrouter_provider else None,
        },
        experiment={
            "id": experiment_id,
            "condition": condition,
            "replicate": replicate,
        },
        run_purpose=run_purpose,
        campaign=campaign,
        intervention={
            "context_mode": context_mode,
            "prompt_template_version": PROMPT_TEMPLATE_VERSION,
            "visibility": context_visibility(context_mode),
            "full_context_sha256": full_context_sha256,
            "intervention_sha256": (campaign or {}).get("intervention_sha256"),
        },
        provenance_exclude_dirs=provenance_exclude_dirs,
    )
    if scenario:
        trace.record_stage("input", {"scenario": scenario})

    guard = RunGuard(trace)
    guard.install()

    try:
        llm = LLMClient(
            model,
            delay=delay,
            trace=trace,
            temperature=temperature,
            top_p=top_p,
            seed=seed,
            max_tokens=max_tokens,
            openrouter_provider=openrouter_provider,
        )
        trace.configure_model(llm.model, llm.provider)
        log.info(f"Modelo: {llm.model}")

        log.info(f"MODO DE CONTEXTO — {context_mode}")
        modules = [
            {
                "nome": component["nome"],
                "descricao": component.get("task", component["nome"]),
                "prototype": component["prototype"],
                "task": component["task"],
            }
            for component in scenario_components
        ]
        trace.write_text("config.h", scenario_config_h or "")
        trace.write_json("prompts/components.json", scenario_components)
        if global_context is not None:
            trace.write_text("prompts/global_context.txt", global_context)
        trace.record_stage("components", {
            "count": len(modules),
            "source": "scenario",
            "context_mode": context_mode,
            "prompt_template_version": PROMPT_TEMPLATE_VERSION,
        })
        trace.emit("layer.finished", layer="components", status="completed",
                   count=len(modules), context_mode=context_mode)

        run_dir = trace.run_dir
        log.info("CAMADA CODER — geração dos componentes (paralelo)...")
        coder = Coder(llm)

        def _process_module(args: tuple[int, dict]) -> tuple[int, str, str]:
            index, module = args
            name = module["nome"]
            module_started_at = utc_now()
            module_started = time.perf_counter()
            module_dir = trace.module_dir(index, name)
            module_relative = module_dir.relative_to(run_dir)
            trace.write_json(module_relative / "module.json", {
                "index": index,
                "name": name,
                "description": module["descricao"],
                "context_mode": context_mode,
                "status": "running",
                "started_at": module_started_at,
            })
            trace.emit("module.started", index=index, name=name,
                       total=len(modules), module_dir=module_relative.as_posix())
            log.info(f"  [{index}/{len(modules)}] {name} — iniciando...")
            try:
                contextualized_prompt = Coder.user_prompt(
                    module["task"],
                    module["prototype"],
                    global_context,
                )
                trace.write_text(module_relative / "prompt.txt", contextualized_prompt)
                print(f"\n  [Component -> {name}]\n  {module['prototype']}")
                code = coder.generate_generic(
                    module["task"],
                    module["prototype"],
                    global_context,
                )
                trace.write_text(module_relative / "response.c", code)
                if code:
                    trace.write_text(f"modules/{safe_name(name)}.c", code)
                trace.write_json(module_relative / "module.json", {
                    "index": index,
                    "name": name,
                    "description": module["descricao"],
                    "context_mode": context_mode,
                    "status": "completed",
                    "started_at": module_started_at,
                    "finished_at": utc_now(),
                    "duration_seconds": round(time.perf_counter() - module_started, 6),
                    "prompt_path": (module_relative / "prompt.txt").as_posix(),
                    "prompt_sha256": sha256_text(contextualized_prompt),
                    "response_classification": "accepted",
                    "code_path": f"modules/{safe_name(name)}.c",
                    "code_sha256": sha256_text(code),
                    "code_lines": len(code.splitlines()),
                })
                trace.emit("module.finished", index=index, name=name,
                           status="completed", code_lines=len(code.splitlines()),
                           duration_seconds=round(time.perf_counter() - module_started, 6))
                print(f"  [Coder -> {name}] {len(code.splitlines())} linhas geradas.")
                log.info(f"  [{index}/{len(modules)}] {name} — concluido.")
                return index, safe_name(name), code
            except Exception as error:
                trace.write_json(module_relative / "module.json", {
                    "index": index,
                    "name": name,
                    "description": module["descricao"],
                    "context_mode": context_mode,
                    "status": "failed",
                    "started_at": module_started_at,
                    "finished_at": utc_now(),
                    "duration_seconds": round(time.perf_counter() - module_started, 6),
                    "error": {"type": type(error).__name__, "message": str(error)},
                    "response_classification": getattr(error, "classification", None),
                })
                trace.emit("module.failed", index=index, name=name, status="failed",
                           duration_seconds=round(time.perf_counter() - module_started, 6),
                           error={"type": type(error).__name__, "message": str(error)})
                raise

        from concurrent.futures import ThreadPoolExecutor, as_completed
        trace.emit("layer.started", layer="modules", count=len(modules))
        modules_started = time.perf_counter()
        results: list[tuple[int, str, str]] = []
        executor = ThreadPoolExecutor(max_workers=len(modules))
        executor_clean = False
        try:
            futures = {
                executor.submit(_process_module, (index, module)): index
                for index, module in enumerate(modules, 1)
            }
            for future in as_completed(futures):
                results.append(future.result())
            executor_clean = True
        finally:
            executor.shutdown(wait=executor_clean, cancel_futures=not executor_clean)

        results.sort(key=lambda item: item[0])
        generated = [(name, code) for _, name, code in results]
        modules_duration = round(time.perf_counter() - modules_started, 6)
        trace.record_stage("modules", {
            "status": "completed",
            "count": len(generated),
            "duration_seconds": modules_duration,
        })
        trace.emit("layer.finished", layer="modules", status="completed",
                   count=len(generated), duration_seconds=modules_duration)

        log.info("CAMADA ASSEMBLER — compilação determinística...")
        trace.emit("assembly.started", model=llm.model, mode="deterministic")
        assembly_started = time.perf_counter()
        harness_model = f"openrouter/{llm.model}"
        harness = AssemblerHarness(model=harness_model)
        try:
            main_c, compiled_ok = harness.assemble(
                generated,
                run_dir,
                config_header=scenario_config_h,
                main_source=scenario_main_c,
            )
        except Exception as error:
            trace.emit("assembly.failed", model=harness_model, error=serialize_error(error),
                       duration_seconds=round(time.perf_counter() - assembly_started, 6))
            raise
        assembly_duration = round(time.perf_counter() - assembly_started, 6)
        assembly_result_path = run_dir / "assembly" / "result.json"
        try:
            assembly_result = json.loads(assembly_result_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            assembly_result = {}
        assembly_status = getattr(harness, "last_status", None) or (
            "completed" if compiled_ok else "compile_failed")
        trace.record_stage("assembler_harness", {
            "status": assembly_status,
            "model": harness_model,
            "main_c": "main.c" if main_c else None,
            "binary": "output" if compiled_ok else None,
            "mode": harness.last_mode,
            "agent_usage": assembly_result.get("agent_usage"),
            "duration_seconds": assembly_duration,
        })
        trace.emit("assembly.finished", status=assembly_status,
                   main_c=bool(main_c), compiled=compiled_ok,
                   mode=harness.last_mode,
                   duration_seconds=assembly_duration)

        if main_c is None:
            trace.emit("assembly.failed", model=harness_model,
                       error={"type": "RuntimeError",
                              "message": f"AssemblerHarness status={assembly_status}"},
                       duration_seconds=assembly_duration)
            log.error(f"  [AssemblerHarness] main.c nao gerado (status={assembly_status}) — abortando")
            raise RuntimeError(f"AssemblerHarness nao gerou main.c (status={assembly_status})")

        status = "completed" if compiled_ok else "compile_failed"
        trace.finalize(
            status=status,
            compiled=compiled_ok,
            extra={
                "main_c": "main.c",
                "binary": "output" if compiled_ok else None,
                "module_count": len(generated),
                "context_mode": context_mode,
                "assembly": {
                    "mode": harness.last_mode,
                    "result": "assembly/result.json",
                    "agent_usage": assembly_result.get("agent_usage"),
                },
            },
        )
        print(f"\n  [AssemblerHarness] {'compilou' if compiled_ok else 'nao compilou'}")
        return main_c
    except (RunInterrupted, KeyboardInterrupt) as interrupted:
        trace.finalize(status="interrupted", error=interrupted)
        log.error(f"Execucao interrompida. Artefatos preservados em: {trace.run_dir}")
        raise
    except Exception as error:
        trace.finalize(status="failed", error=error)
        log.error(f"Execucao registrada em: {trace.run_dir}")
        raise
    finally:
        guard.restore()


def run_official_campaign(
    prompt: str,
    scenario: str,
    scenario_config_h: str,
    scenario_components: list[dict],
    scenario_main_c: str,
    model: str,
    openrouter_provider: str | None,
    experiment_id: str,
    condition: str,
    planned_replicates: int | None,
    delay: int = 0,
    temperature: float | None = None,
    top_p: float | None = None,
    seed: int | None = None,
    max_tokens: int | None = None,
    results_root: Path = Path("results"),
    resume: bool = False,
    protocol_path: Path | None = None,
    rubric_path: Path | None = None,
    campaign_kind: str = "official",
    context_mode: str | None = None,
) -> Campaign:
    experiment_id = experiment_id.strip()
    condition = condition.strip()
    if not experiment_id:
        raise ValueError("--experiment-id nao pode ser vazio.")
    if not condition:
        raise ValueError("--condition nao pode ser vazio.")
    if resume:
        campaign = Campaign.find(
            results_root,
            experiment_id,
            condition,
            model,
            openrouter_provider,
        )
        parameters = campaign.data.get("generation_parameters") or {}
        scenario = campaign.data["scenario"]
        model = campaign.data["requested_model"]
        openrouter_provider = campaign.data.get("inference_provider")
        delay = parameters.get("delay", 0)
        temperature = parameters.get("temperature")
        top_p = parameters.get("top_p")
        seed = parameters.get("seed")
        max_tokens = parameters.get("max_tokens")
        stored_context_mode = campaign.data.get("context_mode", "fragmented")
        if context_mode is not None and validate_context_mode(context_mode) != stored_context_mode:
            raise ValueError("--context-mode difere da campanha existente.")
        context_mode = validate_context_mode(stored_context_mode)
        campaign.data["status"] = "running"
        campaign.data["finished_at"] = None
        campaign.events.emit("campaign.resumed", pending_replicates=campaign.pending_replicates())
        has_frozen_inputs = bool(campaign.data.get("stimulus_sha256"))
        if has_frozen_inputs:
            frozen = load_frozen_inputs(campaign.root, campaign.data)
            scenario = frozen["scenario"]
            prompt = frozen["scenario_description"]
            scenario_config_h = frozen["scenario_config_h"]
            scenario_components = frozen["scenario_components"]
            scenario_main_c = frozen["scenario_main_c"]
            if frozen["context_mode"] != context_mode:
                raise ValueError("A intervencao congelada difere da campanha.")
        else:
            if campaign.data.get("experimental_controls_required"):
                if protocol_path is None or rubric_path is None:
                    raise ValueError("A retomada exige --protocol para reconstruir as entradas ausentes.")
                try:
                    inputs = freeze_experimental_inputs(
                        campaign.root,
                        scenario,
                        prompt,
                        scenario_config_h,
                        scenario_components,
                        scenario_main_c,
                        protocol_path,
                        rubric_path,
                        experiment_id,
                        condition,
                        campaign.data["planned_replicates"],
                        campaign.data["requested_model"],
                        campaign.data["model"],
                        campaign.data["provider"],
                        campaign.data.get("inference_provider"),
                        parameters,
                        context_mode,
                    )
                    campaign.attach_experimental_inputs(inputs)
                except Exception as error:
                    campaign.mark_preflight_failed(error)
                    raise
            else:
                campaign.data["legacy_resume_without_frozen_inputs"] = True
                campaign._save()
        campaign_kind = campaign.data.get("campaign_kind", "official")
    else:
        if (
            isinstance(planned_replicates, bool)
            or not isinstance(planned_replicates, int)
            or planned_replicates < 1
        ):
            raise ValueError("--runs deve ser um inteiro positivo.")
        if protocol_path is None:
            raise ValueError("Uma nova campanha exige --protocol.")
        if rubric_path is None:
            raise ValueError("Uma nova campanha exige --rubric.")
        if campaign_kind not in {"official", "pilot"}:
            raise ValueError("campaign_kind deve ser official ou pilot.")
        protocol = load_yaml(protocol_path)
        declared_context_mode = condition_context_mode(protocol, condition)
        if context_mode is not None and validate_context_mode(context_mode) != declared_context_mode:
            raise ValueError("--context-mode difere da condicao definida no protocolo.")
        context_mode = declared_context_mode
        gateway, _, resolved_model = _resolve(model or DEFAULT_MODEL)
        parameters = {
            "delay": delay,
            "temperature": temperature,
            "top_p": top_p,
            "seed": seed,
            "max_tokens": max_tokens,
        }
        campaign = Campaign.create(
            results_root=results_root,
            experiment_id=experiment_id,
            condition=condition,
            scenario=scenario,
            requested_model=model,
            resolved_model=resolved_model,
            provider=gateway,
            inference_provider=openrouter_provider,
            planned_replicates=planned_replicates,
            generation_parameters=parameters,
            campaign_kind=campaign_kind,
            context_mode=context_mode,
        )
        try:
            inputs = freeze_experimental_inputs(
                campaign.root,
                scenario,
                prompt,
                scenario_config_h,
                scenario_components,
                scenario_main_c,
                protocol_path,
                rubric_path,
                experiment_id,
                condition,
                planned_replicates,
                model,
                resolved_model,
                gateway,
                openrouter_provider,
                parameters,
                context_mode,
            )
            campaign.attach_experimental_inputs(inputs)
        except Exception as error:
            campaign.mark_preflight_failed(error)
            raise

    if not resume or campaign.data.get("stimulus_sha256"):
        try:
            campaign.events.emit("campaign.preflight_started")
            report = run_preflight(
                campaign.root,
                campaign.data["provider"],
                campaign.data.get("inference_provider"),
                campaign.data["model"],
                scenario_components,
                scenario_config_h,
                scenario_main_c,
            )
            campaign.record_preflight(report)
        except Exception as error:
            campaign.mark_preflight_failed(error)
            raise

    try:
        for replicate in campaign.pending_replicates():
            campaign.events.emit("replicate.started", replicate=replicate)
            try:
                run(
                    prompt,
                    model,
                    delay=delay,
                    temperature=temperature,
                    top_p=top_p,
                    seed=seed,
                    max_tokens=max_tokens,
                    output_root=campaign.outputs_dir,
                    scenario=scenario,
                    scenario_config_h=scenario_config_h,
                    scenario_components=scenario_components,
                    scenario_main_c=scenario_main_c,
                    openrouter_provider=openrouter_provider,
                    experiment_id=experiment_id,
                    condition=condition,
                    replicate=replicate,
                    run_purpose=campaign_kind,
                    campaign=campaign.run_reference(replicate),
                    provenance_exclude_dirs=[results_root],
                    context_mode=context_mode,
                )
            except (RunInterrupted, KeyboardInterrupt):
                try:
                    campaign.record_replicate(replicate)
                except RuntimeError:
                    pass
                campaign.mark_interrupted()
                raise
            except Exception as error:
                try:
                    campaign.record_replicate(replicate)
                except RuntimeError:
                    campaign.record_initialization_failure(replicate, error)
                log.error(
                    "Replicate %s/%s falhou e foi preservada: %s",
                    replicate,
                    campaign.data["planned_replicates"],
                    error,
                )
                continue
            campaign.record_replicate(replicate)
    except BaseException:
        if campaign.data.get("status") != "interrupted":
            campaign.mark_interrupted()
        raise
    campaign.finish_generation()
    return campaign


def main():
    parser = argparse.ArgumentParser(
        description="Pipeline de evasão multi-agentes (modo componentes)."
    )
    parser.add_argument("--scenario", "-s",
        help="Cenário de teste (ex: wannacry)")
    parser.add_argument("--model", "-m", default=None,
        help="Modelo a usar. Padrão: free-qwen")
    parser.add_argument("--list", "-l", action="store_true",
        help="Lista os cenários disponíveis.")
    parser.add_argument("--models", action="store_true",
        help="Lista os modelos disponíveis.")
    parser.add_argument("--limit", "-L", type=int, default=0,
        help="Segundos de espera entre chamadas ao LLM.")
    parser.add_argument("--temperature", type=float, default=None,
        help="Temperatura de geração. Ausente usa o padrão do provedor.")
    parser.add_argument("--top-p", type=float, default=None,
        help="Top-p da geração. Ausente usa o padrão do provedor.")
    parser.add_argument("--seed", type=int, default=None,
        help="Seed enviada ao provedor quando suportada.")
    parser.add_argument("--max-tokens", type=int, default=None,
        help="Limite de tokens de saída por chamada.")
    parser.add_argument("--openrouter-provider", default=None,
        help="Provider de inferência fixo no OpenRouter, sem fallback (ex: deepinfra).")
    parser.add_argument("--experiment-id", default=None,
        help="Identificador do experimento para agrupar execucoes.")
    parser.add_argument("--condition", default=None,
        help="Condicao experimental desta execucao.")
    parser.add_argument("--all-conditions", action="store_true",
        help="Executa todas as condicoes do protocolo em campanhas separadas.")
    parser.add_argument("--context-mode", choices=("fragmented", "full_context"),
        default=None, help="Visibilidade de contexto; em campanhas oficiais vem do protocolo.")
    parser.add_argument("--replicate", type=int, default=None,
        help="Numero da repeticao (inteiro positivo).")
    parser.add_argument("--official", action="store_true",
        help="Executa uma campanha oficial e grava em results/.")
    parser.add_argument("--runs", "-n", type=int, default=None,
        help="Numero de repeticoes sequenciais da campanha oficial.")
    parser.add_argument("--resume", action="store_true",
        help="Retoma as replicas ausentes de uma campanha oficial.")
    parser.add_argument("--pilot", action="store_true",
        help="Marca a campanha como piloto, separada da analise oficial.")
    parser.add_argument("--protocol", type=Path, default=None,
        help="Protocolo experimental YAML congelado.")
    parser.add_argument("--rubric", type=Path,
        default=Path("experiments/rubrics/component-evaluation-v1.yaml"),
        help="Rubrica YAML usada na avaliacao.")
    parser.add_argument("--results-root", type=Path, default=Path("results"),
        help="Diretorio raiz das campanhas oficiais.")
    args = parser.parse_args()

    if args.list:
        from scenarios.test_prompts import PROMPTS
        print("\nCenarios disponiveis:\n")
        for key, data in PROMPTS.items():
            print(f"  --scenario {key:10s} -> {data['nome']}")
        print()
        sys.exit(0)

    if args.models:
        print("\nModelos disponiveis:\n")
        for alias, full in MODELS.items():
            print(f"  {alias:18s} -> {full}")
        print()
        sys.exit(0)

    print("\n" + "=" * 60)
    print("   INICIAÇÃO CIENTÍFICA — PIPELINE DE EVASÃO MULTI-AGENTES")
    print("=" * 60)

    from scenarios.test_prompts import PROMPTS
    if args.resume and not args.official:
        parser.error("--resume exige --official.")
    if args.runs is not None and not args.official:
        parser.error("--runs so pode ser usado com --official.")
    if args.pilot and not args.official:
        parser.error("--pilot exige --official.")
    if args.all_conditions and not args.official:
        parser.error("--all-conditions exige --official.")
    if args.all_conditions and args.condition:
        parser.error("--all-conditions nao pode ser combinado com --condition.")
    if args.all_conditions and args.context_mode:
        parser.error("--all-conditions obtem cada context_mode do protocolo.")
    if args.official:
        if not args.experiment_id:
            parser.error("--official exige --experiment-id.")
        if not args.experiment_id.strip():
            parser.error("--experiment-id nao pode ser vazio.")
        if not args.all_conditions and not args.condition:
            parser.error("--official exige --condition ou --all-conditions.")
        if args.condition is not None and not args.condition.strip():
            parser.error("--condition nao pode ser vazia.")
        if not args.model:
            parser.error("--official exige --model explicito.")
        if args.replicate is not None:
            parser.error("--replicate e automatico em campanhas oficiais.")
        if args.resume and args.runs is not None:
            parser.error("--resume usa o total original e nao aceita --runs.")
        if not args.resume and (args.runs is None or args.runs < 1):
            parser.error("Uma nova campanha oficial exige --runs com inteiro positivo.")
        if not args.resume and args.protocol is None:
            parser.error("Uma nova campanha oficial exige --protocol.")
        if args.all_conditions and not args.resume and args.protocol is None:
            parser.error("Uma nova execucao com --all-conditions exige --protocol.")
    protocol = load_yaml(args.protocol) if args.all_conditions and not args.resume else None
    conditions = protocol_condition_ids(protocol) if protocol is not None else []
    if args.resume:
        if args.all_conditions:
            existing_campaigns = Campaign.find_all(
                args.results_root,
                args.experiment_id.strip(),
                args.model,
                args.openrouter_provider,
                include_pilots=True,
            )
            expected_kind = "pilot" if args.pilot else "official"
            existing_campaigns = [
                campaign
                for campaign in existing_campaigns
                if campaign.data.get("campaign_kind", "official") == expected_kind
            ]
            if not existing_campaigns:
                parser.error(f"Nenhuma campanha {expected_kind} encontrada para retomar.")
            conditions = [campaign.data["condition"] for campaign in existing_campaigns]
            scenarios = {campaign.data["scenario"] for campaign in existing_campaigns}
            if len(scenarios) != 1:
                parser.error("As campanhas existentes possuem cenarios divergentes.")
            key = next(iter(scenarios))
        else:
            previous = Campaign.find(
                args.results_root,
                args.experiment_id.strip(),
                args.condition.strip(),
                args.model,
                args.openrouter_provider,
            )
            key = previous.data["scenario"]
    else:
        if not args.scenario:
            print("[ERRO] Informe um cenario com --scenario. Use --list.")
            sys.exit(1)
        key = args.scenario.lower()
    if key not in PROMPTS:
        print(f"[ERRO] Cenário '{key}' não encontrado. Use --list.")
        sys.exit(1)
    data = PROMPTS[key]
    prompt = data.get("descricao", data["nome"])
    scenario = key
    scenario_config_h = data["config_h"]
    scenario_components = data["components"]
    scenario_main_c = data["main_c"]
    print(f"\n[CENÁRIO] {data['nome']}")
    print(f"  {data['descricao']}")
    print(f"  [MODO] componentes determinísticos ({len(scenario_components)})")

    if args.official:
        selected_conditions = conditions if args.all_conditions else [args.condition.strip()]
        if args.all_conditions:
            for selected_condition in selected_conditions:
                try:
                    Campaign.find(
                        args.results_root,
                        args.experiment_id.strip(),
                        selected_condition,
                        args.model,
                        args.openrouter_provider,
                    )
                except FileNotFoundError:
                    if args.resume:
                        parser.error(
                            f"Campanha ausente para retomar: {selected_condition}."
                        )
                else:
                    if not args.resume:
                        parser.error(
                            f"Campanha ja existe para {selected_condition}; use --resume."
                        )
        campaigns = []
        for selected_condition in selected_conditions:
            try:
                campaign = run_official_campaign(
                    prompt=prompt,
                    scenario=scenario,
                    scenario_config_h=scenario_config_h,
                    scenario_components=scenario_components,
                    scenario_main_c=scenario_main_c,
                    model=args.model,
                    openrouter_provider=args.openrouter_provider,
                    experiment_id=args.experiment_id.strip(),
                    condition=selected_condition,
                    planned_replicates=args.runs,
                    delay=args.limit,
                    temperature=args.temperature,
                    top_p=args.top_p,
                    seed=args.seed,
                    max_tokens=args.max_tokens,
                    results_root=args.results_root,
                    resume=args.resume,
                    protocol_path=args.protocol,
                    rubric_path=args.rubric,
                    campaign_kind="pilot" if args.pilot else "official",
                    context_mode=args.context_mode,
                )
            except Exception as error:
                log.error(f"Falha na campanha {selected_condition}: {error}")
                raise
            campaigns.append(campaign)
        print("\n" + "=" * 60)
        for campaign in campaigns:
            print(f"  Campanha: {campaign.root}")
            print(f"  Contexto: {campaign.data['context_mode']}")
            print(f"  Status: {campaign.data['status']}")
            print(f"  Concluidas: {campaign.data['completed_replicates']}")
            print(f"  Falhas: {campaign.data['failed_replicates']}")
        print("=" * 60 + "\n")
        return

    try:
        output_path = run(
            prompt,
            args.model,
            delay=args.limit,
            temperature=args.temperature,
            top_p=args.top_p,
            seed=args.seed,
            max_tokens=args.max_tokens,
            openrouter_provider=args.openrouter_provider,
            scenario=scenario,
            scenario_config_h=scenario_config_h,
            scenario_components=scenario_components,
            scenario_main_c=scenario_main_c,
            experiment_id=args.experiment_id,
            condition=args.condition,
            replicate=args.replicate,
            context_mode=args.context_mode or "fragmented",
        )
    except Exception as error:
        log.error(f"Falha no pipeline: {error}")
        raise

    print("\n" + "=" * 60)
    print(f"  Codigo salvo em: {output_path}")
    binary = output_path.parent / "output"        # assembly/output
    if binary.exists():
        print(f"  Binario pronto:  {binary}")
    else:
        print("  Binario nao gerado (veja erros acima)")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

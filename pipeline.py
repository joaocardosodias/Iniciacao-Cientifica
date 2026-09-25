import sys
import json
import logging
import argparse
import time
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from src.llm_client import LLMClient, MODELS
from src.coder import Coder
from src.assembler_harness import AssemblerHarness
from src.trace import RunTrace, safe_name, sha256_text, serialize_error, utc_now
from src.interrupts import RunGuard, RunInterrupted
from src.recovery import recover_stale_runs

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
) -> Path:
    if not scenario_components:
        raise ValueError("O modo componentes exige 'components' definido no cenario.")
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

        log.info("MODO COMPONENTES — decomposição determinística do cenário")
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
        trace.record_stage("components", {"count": len(modules), "source": "scenario"})
        trace.emit("layer.finished", layer="components", status="completed",
                   count=len(modules))

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
                "status": "running",
                "started_at": module_started_at,
            })
            trace.emit("module.started", index=index, name=name,
                       total=len(modules), module_dir=module_relative.as_posix())
            log.info(f"  [{index}/{len(modules)}] {name} — iniciando...")
            try:
                contextualized_prompt = f"{module['task']}\n\nEXACT PROTOTYPE: {module['prototype']}"
                trace.write_text(module_relative / "prompt.txt", contextualized_prompt)
                print(f"\n  [Component -> {name}]\n  {module['prototype']}")
                code = coder.generate_generic(module["task"], module["prototype"])
                trace.write_text(module_relative / "response.c", code)
                if code:
                    trace.write_text(f"modules/{safe_name(name)}.c", code)
                trace.write_json(module_relative / "module.json", {
                    "index": index,
                    "name": name,
                    "description": module["descricao"],
                    "status": "completed",
                    "started_at": module_started_at,
                    "finished_at": utc_now(),
                    "duration_seconds": round(time.perf_counter() - module_started, 6),
                    "prompt_path": (module_relative / "prompt.txt").as_posix(),
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
                    "status": "failed",
                    "started_at": module_started_at,
                    "finished_at": utc_now(),
                    "duration_seconds": round(time.perf_counter() - module_started, 6),
                    "error": {"type": type(error).__name__, "message": str(error)},
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

    if not args.scenario:
        print("[ERRO] Informe um cenario com --scenario. Use --list.")
        sys.exit(1)
    from scenarios.test_prompts import PROMPTS
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
        )
    except Exception as e:
        log.error(f"Falha no pipeline: {e}")
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

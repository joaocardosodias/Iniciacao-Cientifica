import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.campaign import Campaign
from src.evaluation import FUNCTIONAL_STATUSES, pending_runs, record_evaluation
from src import ui


def _prompt_status() -> str:
    choices = ", ".join(sorted(FUNCTIONAL_STATUSES))
    while True:
        value = input(f"Resultado funcional ({choices}): ").strip()
        if value in FUNCTIONAL_STATUSES:
            return value
        print("Valor invalido.")


def _prompt_checks() -> list[dict[str, str]]:
    checks = []
    while True:
        description = input("Criterio verificado (Enter para encerrar): ").strip()
        if not description:
            break
        while True:
            status = input("Status do criterio (passed/failed/not_checked/not_applicable): ").strip()
            if status in {"passed", "failed", "not_checked", "not_applicable"}:
                break
            print("Valor invalido.")
        checks.append({"description": description, "status": status})
    return checks


def _parse_checks(values: list[str]) -> list[dict[str, str]]:
    checks = []
    for value in values:
        status, separator, description = value.partition(":")
        if not separator:
            raise ValueError("Use --check status:descricao.")
        checks.append({"status": status.strip(), "description": description.strip()})
    return checks


def _parse_components(values: list[str]) -> list[dict[str, str]]:
    assessments = []
    for value in values:
        component, separator, classification = value.partition(":")
        if not separator:
            raise ValueError("Use --component nome:classificacao.")
        assessments.append({
            "component": component.strip(),
            "classification": classification.strip(),
        })
    return assessments


def _parse_stages(values: list[str]) -> list[dict[str, str]]:
    stages = []
    for value in values:
        stage, separator, status = value.partition(":")
        if not separator:
            raise ValueError("Use --stage etapa:status.")
        stages.append({
            "stage": stage.strip(),
            "status": status.strip(),
        })
    return stages


def _prompt_evidence() -> list[Path]:
    paths = []
    while True:
        value = input("Arquivo de evidencia (Enter para encerrar): ").strip()
        if not value:
            break
        paths.append(Path(value))
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description="Registra avaliacoes manuais de runs oficiais.")
    parser.add_argument("--results-root", type=Path, default=Path("results"))
    parser.add_argument("--run-id")
    parser.add_argument("--experiment-id")
    parser.add_argument("--condition")
    parser.add_argument("--model")
    parser.add_argument("--provider")
    parser.add_argument("--list-pending", action="store_true")
    parser.add_argument("--all-conditions", action="store_true")
    parser.add_argument("--include-pilots", action="store_true")
    parser.add_argument("--evaluator")
    parser.add_argument("--functional-status", choices=sorted(FUNCTIONAL_STATUSES))
    parser.add_argument("--vm-snapshot")
    parser.add_argument("--network-mode", default="internal_isolated")
    parser.add_argument("--environment-file", type=Path)
    parser.add_argument("--check", action="append", default=[])
    parser.add_argument("--component", action="append", default=[])
    parser.add_argument("--stage", action="append", default=[])
    parser.add_argument("--json", action="store_true", help="imprime o resultado bruto em JSON")
    parser.add_argument("--notes")
    parser.add_argument("--evidence", action="append", type=Path, default=[])
    inclusion = parser.add_mutually_exclusive_group()
    inclusion.add_argument("--include-in-analysis", action="store_true")
    inclusion.add_argument("--exclude-from-analysis", action="store_true")
    parser.add_argument("--exclusion-reason")
    args = parser.parse_args()

    if args.list_pending:
        if not args.experiment_id:
            parser.error("--list-pending exige --experiment-id.")
        if args.all_conditions and args.condition:
            parser.error("--all-conditions nao pode ser combinado com --condition.")
        if not args.all_conditions and not args.condition:
            parser.error("Informe --condition ou --all-conditions.")
        campaigns = Campaign.find_all(
            args.results_root,
            args.experiment_id,
            args.model,
            args.provider,
            args.include_pilots,
        ) if args.all_conditions else [Campaign.find(
            args.results_root,
            args.experiment_id,
            args.condition,
            args.model,
            args.provider,
        )]
        records = [
            (campaign.data["condition"], record)
            for campaign in campaigns
            for record in pending_runs(campaign)
        ]
        if not records:
            ui.note("Nenhuma run pendente de avaliacao.")
            return
        ui.header("RUNS PENDENTES DE AVALIACAO")
        for condition, record in records:
            print(
                f"  {str(condition).ljust(14)} replicate {str(record['replicate']).ljust(3)} "
                f"{record['run_id']}  {record['status']}"
            )
        ui.rule()
        return

    if not args.run_id:
        parser.error("Informe --run-id ou use --list-pending.")
    evaluator = (args.evaluator or input("Avaliador: ")).strip()
    functional_status = args.functional_status or _prompt_status()
    vm_snapshot = args.vm_snapshot
    if args.environment_file is None and vm_snapshot is None:
        vm_snapshot = input("Snapshot inicial da VM para o lote: ").strip()
    checks = _parse_checks(args.check) if args.check else _prompt_checks()
    notes = args.notes if args.notes is not None else input("Observacoes: ")
    evidence = args.evidence if args.evidence else _prompt_evidence()
    if args.exclude_from_analysis:
        include = False
    elif args.include_in_analysis:
        include = True
    else:
        include = input("Incluir na analise? [S/n]: ").strip().lower() not in {"n", "nao", "não"}
    reason = args.exclusion_reason
    if not include and not reason:
        reason = input("Justificativa da exclusao: ").strip()
    manual = record_evaluation(
        results_root=args.results_root,
        run_id=args.run_id,
        evaluator=evaluator,
        functional_status=functional_status,
        environment={
            "vm_snapshot": vm_snapshot or None,
            "network_mode": args.network_mode,
        },
        checks=checks,
        notes=notes,
        evidence=evidence,
        include_in_analysis=include,
        exclusion_reason=reason,
        environment_file=args.environment_file,
        component_assessments=_parse_components(args.component),
        stage_results=_parse_stages(args.stage),
    )
    if args.json:
        print(json.dumps(manual, indent=2, ensure_ascii=False, sort_keys=True))
        return
    ui.header("AVALIACAO REGISTRADA")
    ui.fields([
        ("run", manual["run_id"]),
        ("avaliador", manual["evaluator"]),
        ("status funcional", functional_status),
        ("revisao", manual["revision"]),
        ("incluida", "sim" if manual["include_in_analysis"] else "nao"),
        ("avaliada em", manual["evaluated_at"]),
    ])
    ui.rule()


if __name__ == "__main__":
    main()

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.campaign import Campaign
from src.evaluation import FUNCTIONAL_STATUSES, pending_runs, record_evaluation


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
    parser.add_argument("--evaluator")
    parser.add_argument("--functional-status", choices=sorted(FUNCTIONAL_STATUSES))
    parser.add_argument("--execution-vm-snapshot")
    parser.add_argument("--collector-vm-snapshot")
    parser.add_argument("--network-mode", default="internal_isolated")
    parser.add_argument("--check", action="append", default=[])
    parser.add_argument("--notes")
    parser.add_argument("--evidence", action="append", type=Path, default=[])
    inclusion = parser.add_mutually_exclusive_group()
    inclusion.add_argument("--include-in-analysis", action="store_true")
    inclusion.add_argument("--exclude-from-analysis", action="store_true")
    parser.add_argument("--exclusion-reason")
    args = parser.parse_args()

    if args.list_pending:
        if not args.experiment_id or not args.condition:
            parser.error("--list-pending exige --experiment-id e --condition.")
        campaign = Campaign.find(
            args.results_root,
            args.experiment_id,
            args.condition,
            args.model,
            args.provider,
        )
        records = pending_runs(campaign)
        if not records:
            print("Nenhuma run pendente de avaliacao.")
            return
        for record in records:
            print(
                f"replicate={record['replicate']} run_id={record['run_id']} "
                f"status={record['status']}"
            )
        return

    if not args.run_id:
        parser.error("Informe --run-id ou use --list-pending.")
    evaluator = (args.evaluator or input("Avaliador: ")).strip()
    functional_status = args.functional_status or _prompt_status()
    execution_snapshot = args.execution_vm_snapshot
    if execution_snapshot is None:
        execution_snapshot = input("Snapshot da VM de execucao: ").strip()
    collector_snapshot = args.collector_vm_snapshot
    if collector_snapshot is None:
        collector_snapshot = input("Snapshot da VM coletora: ").strip()
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
            "execution_vm_snapshot": execution_snapshot or None,
            "collector_vm_snapshot": collector_snapshot or None,
            "network_mode": args.network_mode,
        },
        checks=checks,
        notes=notes,
        evidence=evidence,
        include_in_analysis=include,
        exclusion_reason=reason,
    )
    print(json.dumps(manual, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

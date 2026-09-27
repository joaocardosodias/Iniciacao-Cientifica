import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.campaign import Campaign
from src.results_builder import build_results
from src.aggregate_results import build_aggregate
from src import ui


def main() -> None:
    parser = argparse.ArgumentParser(description="Consolida os resultados de uma campanha oficial.")
    parser.add_argument("--results-root", type=Path, default=Path("results"))
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--condition")
    parser.add_argument("--all-conditions", action="store_true")
    parser.add_argument("--model")
    parser.add_argument("--provider")
    parser.add_argument("--json", action="store_true", help="imprime o resultado bruto em JSON")
    args = parser.parse_args()
    if args.all_conditions and args.condition:
        parser.error("--all-conditions nao pode ser combinado com --condition.")
    if not args.all_conditions and not args.condition:
        parser.error("Informe --condition ou --all-conditions.")
    campaigns = Campaign.find_all(
        args.results_root,
        args.experiment_id,
        args.model,
        args.provider,
    ) if args.all_conditions else [Campaign.find(
        args.results_root,
        args.experiment_id,
        args.condition,
        args.model,
        args.provider,
    )]
    summaries = [build_results(campaign) for campaign in campaigns]
    if args.all_conditions:
        aggregate = build_aggregate(args.results_root, args.experiment_id)
        output = {"campaigns": summaries, "aggregate": aggregate}
    else:
        output = summaries[0]
    if args.json:
        print(json.dumps(output, indent=2, ensure_ascii=False, sort_keys=True))
        return
    ui.header("RESULTADOS CONSOLIDADOS")
    for summary in summaries:
        counts = summary["counts"]
        ui.fields([
            ("condicao", summary["condition"]),
            ("modelo", summary["model"]),
            ("planejadas", counts["planned"]),
            ("concluidas", counts["completed"]),
            ("falhas", counts["failed"]),
            ("avaliadas", counts["evaluated"]),
            ("funcional passou", counts["functional_passed"]),
        ], indent=4)
        ui.rule()
    if args.all_conditions:
        ui.note(f"agregado : {args.results_root / 'aggregate' / args.experiment_id}")
    ui.rule()


if __name__ == "__main__":
    main()

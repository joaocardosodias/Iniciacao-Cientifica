import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.campaign import Campaign
from src.results_builder import build_results


def main() -> None:
    parser = argparse.ArgumentParser(description="Consolida os resultados de uma campanha oficial.")
    parser.add_argument("--results-root", type=Path, default=Path("results"))
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--condition", required=True)
    parser.add_argument("--model")
    parser.add_argument("--provider")
    args = parser.parse_args()
    campaign = Campaign.find(
        args.results_root,
        args.experiment_id,
        args.condition,
        args.model,
        args.provider,
    )
    summary = build_results(campaign)
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

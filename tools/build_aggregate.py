import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aggregate_results import build_aggregate


def main() -> None:
    parser = argparse.ArgumentParser(description="Consolida campanhas de um experimento.")
    parser.add_argument("--results-root", type=Path, default=Path("results"))
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--include-pilots", action="store_true")
    args = parser.parse_args()
    report = build_aggregate(args.results_root, args.experiment_id, args.include_pilots)
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

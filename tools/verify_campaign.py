import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.integrity import seal_campaign, verify_seal


def main() -> None:
    parser = argparse.ArgumentParser(description="Cria ou verifica o selo de uma campanha.")
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--create", action="store_true")
    args = parser.parse_args()
    result = seal_campaign(args.campaign_dir) if args.create else verify_seal(args.campaign_dir, "campaign_seal.json")
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    if not args.create and not result.get("valid"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.integrity import seal_run, verify_seal
from src import ui


def main() -> None:
    parser = argparse.ArgumentParser(description="Cria ou verifica o selo de uma run.")
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--create", action="store_true")
    parser.add_argument("--json", action="store_true", help="imprime o resultado bruto em JSON")
    args = parser.parse_args()
    created = args.create
    result = seal_run(args.run_dir) if created else verify_seal(args.run_dir, "run_seal.json")
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        ui.header("SELO DA RUN")
        if created:
            ui.fields([
                ("run", args.run_dir),
                ("arquivo", "run_seal.json"),
                ("escopo", result.get("scope")),
                ("arquivos", result.get("file_count")),
                ("sha256", result.get("combined_sha256")),
            ])
        else:
            ui.fields([
                ("run", args.run_dir),
                ("valido", "sim" if result.get("valid") else "nao"),
                ("escopo", result.get("scope")),
                ("sha256", result.get("combined_sha256")),
                ("selo", result.get("seal")),
            ])
            for label in ("missing", "modified", "unexpected"):
                values = result.get(label) or []
                if values:
                    ui.note(f"{label} : {', '.join(values)}")
        ui.rule()
    if not created and not result.get("valid"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

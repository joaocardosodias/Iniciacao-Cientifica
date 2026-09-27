import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aggregate_results import build_aggregate
from src.campaign import Campaign
from src.integrity import verify_seal
from src.trace import safe_name


def migrate(results_root: Path) -> list[Path]:
    old_campaigns = sorted(results_root.glob("*/*/*/campaign.json"))
    moves = []
    for path in old_campaigns:
        data = json.loads(path.read_text(encoding="utf-8"))
        if path.parent.parent.name != safe_name(data["experiment_id"]):
            raise ValueError(f"Experimento nao corresponde ao caminho: {path}")
        destination = (
            results_root / safe_name(data["experiment_id"]) / "models"
            / path.parent.parent.parent.name / path.parent.name
        )
        if destination.exists():
            raise FileExistsError(destination)
        seal = path.parent / "campaign_seal.json"
        if seal.exists() and not verify_seal(path.parent, seal.name)["valid"]:
            raise ValueError(f"Selo de campanha invalido: {path.parent}")
        moves.append((path.parent, destination))

    old_summaries = sorted(path for path in (results_root / "aggregate").glob("*") if path.is_dir())
    for source in old_summaries:
        destination = results_root / source.name / "summary"
        if destination.exists():
            raise FileExistsError(destination)

    for source, destination in moves:
        destination.parent.mkdir(parents=True, exist_ok=True)
        source.rename(destination)
        if (destination / "campaign_seal.json").exists():
            if not verify_seal(destination, "campaign_seal.json")["valid"]:
                raise ValueError(f"Selo de campanha invalido apos migracao: {destination}")
        if not any(source.parent.iterdir()):
            source.parent.rmdir()
        if not any(source.parent.parent.iterdir()):
            source.parent.parent.rmdir()
        for name in ("figures", "tables"):
            empty = destination / name
            if empty.is_dir() and not any(empty.iterdir()):
                empty.rmdir()

    for old_summary in old_summaries:
        destination = results_root / old_summary.name / "summary"
        destination.parent.mkdir(parents=True, exist_ok=True)
        old_summary.rename(destination)
        for name in ("figures", "tables"):
            empty = destination / name
            if empty.is_dir() and not any(empty.iterdir()):
                empty.rmdir()
    aggregate_root = results_root / "aggregate"
    if aggregate_root.exists():
        aggregate_root.rmdir()

    campaigns = sorted(results_root.glob("*/models/*/*/campaign.json"))
    for path in campaigns:
        campaign = Campaign.load(path, results_root)
        campaign._index()

    for summary in sorted(results_root.glob("*/summary/statistics.json")):
        report = json.loads(summary.read_text(encoding="utf-8"))
        build_aggregate(results_root, report["experiment_id"], report.get("include_pilots", False))
    return campaigns


def main() -> None:
    parser = argparse.ArgumentParser(description="Organiza resultados por experimento e modelo.")
    parser.add_argument("--results-root", type=Path, default=Path("results"))
    args = parser.parse_args()
    campaigns = migrate(args.results_root)
    print(f"Campanhas organizadas: {len(campaigns)}")


if __name__ == "__main__":
    main()

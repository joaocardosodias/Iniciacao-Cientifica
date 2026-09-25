import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from src.campaign import Campaign
from src.events import utc_now
from src.results_builder import build_results
from src.trace import write_json_atomic
from src.integrity import verify_seal


def _read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _boolean(value: Any) -> bool:
    return str(value).lower() in {"true", "1", "yes"}


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> dict[str, Any]:
    if total == 0:
        return {"successes": successes, "total": total, "rate": None, "ci95_low": None, "ci95_high": None}
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return {
        "successes": successes,
        "total": total,
        "rate": round(rate, 6),
        "ci95_low": round(max(0.0, center - margin), 6),
        "ci95_high": round(min(1.0, center + margin), 6),
    }


def _group_summary(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(str(row.get(key) or "") for key in keys)].append(row)
    output = []
    for identity, items in sorted(groups.items()):
        included = [item for item in items if _boolean(item.get("include_in_analysis"))]
        evaluated = [item for item in included if _boolean(item.get("evaluated"))]
        functional = sum(item.get("functional_status") == "passed" for item in evaluated)
        compiled = sum(_boolean(item.get("compiled")) for item in included)
        completed = sum(item.get("status") == "completed" for item in included)
        costs = [value for value in (_number(item.get("cost_total")) for item in included) if value is not None]
        stats = wilson(functional, len(evaluated))
        record = {key: value for key, value in zip(keys, identity)}
        record.update({
            "runs": len(items),
            "included": len(included),
            "excluded": len(items) - len(included),
            "evaluated": len(evaluated),
            "generation_completed": completed,
            "compiled": compiled,
            "functional_passed": functional,
            "functional_success_rate": stats["rate"],
            "functional_ci95_low": stats["ci95_low"],
            "functional_ci95_high": stats["ci95_high"],
            "cost_total": round(sum(costs), 12) if costs else None,
            "cost_per_success": round(sum(costs) / functional, 12) if costs and functional else None,
        })
        output.append(record)
    return output


def _condition_comparisons(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if _boolean(row.get("include_in_analysis")) and _boolean(row.get("evaluated")):
            grouped[str(row.get("model") or "")][str(row.get("condition") or "")].append(row)
    comparisons = []
    for model, conditions in sorted(grouped.items()):
        names = sorted(conditions)
        for left_index, left in enumerate(names):
            for right in names[left_index + 1:]:
                left_rows = conditions[left]
                right_rows = conditions[right]
                left_success = sum(row.get("functional_status") == "passed" for row in left_rows)
                right_success = sum(row.get("functional_status") == "passed" for row in right_rows)
                left_rate = left_success / len(left_rows)
                right_rate = right_success / len(right_rows)
                difference = left_rate - right_rate
                standard_error = math.sqrt(
                    left_rate * (1 - left_rate) / len(left_rows)
                    + right_rate * (1 - right_rate) / len(right_rows)
                )
                margin = 1.959963984540054 * standard_error
                comparisons.append({
                    "model": model,
                    "condition_a": left,
                    "condition_b": right,
                    "n_a": len(left_rows),
                    "n_b": len(right_rows),
                    "successes_a": left_success,
                    "successes_b": right_success,
                    "risk_difference": round(difference, 6),
                    "ci95_low": round(max(-1.0, difference - margin), 6),
                    "ci95_high": round(min(1.0, difference + margin), 6),
                    "method": "unpooled Wald confidence interval",
                })
    return comparisons


def build_aggregate(results_root: Path, experiment_id: str, include_pilots: bool = False) -> dict[str, Any]:
    campaigns = []
    for path in sorted(results_root.glob("*/*/*/campaign.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("experiment_id") != experiment_id:
            continue
        if data.get("campaign_kind", "official") == "pilot" and not include_pilots:
            continue
        campaigns.append(Campaign.load(path, results_root))
    if not campaigns:
        raise FileNotFoundError(f"Nenhuma campanha encontrada para {experiment_id}")
    rows = []
    campaign_records = []
    for campaign in campaigns:
        seal_path = campaign.root / "campaign_seal.json"
        if not (campaign.root / "runs.csv").is_file() or not seal_path.is_file():
            build_results(campaign)
        verification = verify_seal(campaign.root, "campaign_seal.json")
        if not verification.get("valid"):
            raise ValueError(f"Selo de campanha invalido: {campaign.root}")
        campaign_rows = _read_csv(campaign.root / "runs.csv")
        for row in campaign_rows:
            row.update({
                "campaign_id": campaign.data["campaign_id"],
                "model": campaign.data["model"],
                "provider": campaign.data["provider"],
                "inference_provider": campaign.data.get("inference_provider"),
                "condition": campaign.data["condition"],
                "campaign_kind": campaign.data.get("campaign_kind", "official"),
            })
            rows.append(row)
        campaign_records.append({
            "campaign_id": campaign.data["campaign_id"],
            "path": campaign.root.relative_to(results_root).as_posix(),
            "condition": campaign.data["condition"],
            "model": campaign.data["model"],
            "stimulus_sha256": campaign.data.get("stimulus_sha256"),
            "protocol_sha256": campaign.data.get("protocol_sha256"),
            "rubric_sha256": campaign.data.get("rubric_sha256"),
            "integrity_verified": True,
            "campaign_combined_sha256": verification.get("combined_sha256"),
        })
    output_root = results_root / "aggregate" / experiment_id
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "figures").mkdir(exist_ok=True)
    (output_root / "tables").mkdir(exist_ok=True)
    run_fields = sorted({key for row in rows for key in row})
    by_model = _group_summary(rows, ("model", "provider", "inference_provider", "condition"))
    by_condition = _group_summary(rows, ("condition",))
    comparisons = _condition_comparisons(rows)
    summary_fields = sorted({key for row in by_model + by_condition for key in row})
    _write_csv(output_root / "all_runs.csv", rows, run_fields)
    _write_csv(output_root / "summary_by_model.csv", by_model, summary_fields)
    _write_csv(output_root / "summary_by_condition.csv", by_condition, summary_fields)
    comparison_fields = sorted({key for row in comparisons for key in row}) or [
        "model", "condition_a", "condition_b", "n_a", "n_b", "successes_a",
        "successes_b", "risk_difference", "ci95_low", "ci95_high", "method",
    ]
    _write_csv(output_root / "condition_comparisons.csv", comparisons, comparison_fields)
    report = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "experiment_id": experiment_id,
        "include_pilots": include_pilots,
        "campaign_count": len(campaigns),
        "run_count": len(rows),
        "method": "Wilson score interval, 95% confidence",
        "by_model": by_model,
        "by_condition": by_condition,
        "condition_comparisons": comparisons,
        "campaigns": campaign_records,
    }
    write_json_atomic(output_root / "statistics.json", report)
    write_json_atomic(output_root / "provenance.json", {
        "schema_version": "1.0",
        "generated_at": report["generated_at"],
        "campaigns": campaign_records,
    })
    return report

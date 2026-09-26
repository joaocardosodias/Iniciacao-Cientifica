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


def risk_difference(
    successes_a: int,
    total_a: int,
    successes_b: int,
    total_b: int,
) -> dict[str, Any]:
    if total_a == 0 or total_b == 0:
        return {"difference": None, "ci95_low": None, "ci95_high": None}
    interval_a = wilson(successes_a, total_a)
    interval_b = wilson(successes_b, total_b)
    difference = successes_a / total_a - successes_b / total_b
    return {
        "difference": round(difference, 6),
        "ci95_low": round(max(-1.0, interval_a["ci95_low"] - interval_b["ci95_high"]), 6),
        "ci95_high": round(min(1.0, interval_a["ci95_high"] - interval_b["ci95_low"]), 6),
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
        refused = sum(_boolean(item.get("run_refusal")) for item in included)
        any_refusal = sum(_boolean(item.get("any_refusal")) for item in included)
        costs = [value for value in (_number(item.get("cost_total")) for item in included) if value is not None]
        stats = wilson(functional, len(evaluated))
        refusal_stats = wilson(refused, len(included))
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
            "runs_with_refusal": refused,
            "runs_with_any_refusal": any_refusal,
            "run_refusal_rate": refusal_stats["rate"],
            "refusal_ci95_low": refusal_stats["ci95_low"],
            "refusal_ci95_high": refusal_stats["ci95_high"],
            "cost_total": round(sum(costs), 12) if costs else None,
            "cost_per_success": round(sum(costs) / functional, 12) if costs and functional else None,
        })
        output.append(record)
    return output


def _condition_comparisons(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        if _boolean(row.get("include_in_analysis")):
            identity = (
                str(row.get("model") or ""),
                str(row.get("provider") or ""),
                str(row.get("inference_provider") or ""),
            )
            grouped[identity][str(row.get("condition") or "")].append(row)
    comparisons = []
    for identity, conditions in sorted(grouped.items()):
        model, provider, inference_provider = identity
        names = sorted(conditions)
        for left_index, left in enumerate(names):
            for right in names[left_index + 1:]:
                left_rows = conditions[left]
                right_rows = conditions[right]
                left_evaluated = [row for row in left_rows if _boolean(row.get("evaluated"))]
                right_evaluated = [row for row in right_rows if _boolean(row.get("evaluated"))]
                left_success = sum(row.get("functional_status") == "passed" for row in left_evaluated)
                right_success = sum(row.get("functional_status") == "passed" for row in right_evaluated)
                functional_difference = risk_difference(
                    left_success,
                    len(left_evaluated),
                    right_success,
                    len(right_evaluated),
                )
                left_refusals = sum(_boolean(row.get("run_refusal")) for row in left_rows)
                right_refusals = sum(_boolean(row.get("run_refusal")) for row in right_rows)
                refusal_difference = risk_difference(
                    left_refusals,
                    len(left_rows),
                    right_refusals,
                    len(right_rows),
                )
                comparisons.append({
                    "model": model,
                    "provider": provider,
                    "inference_provider": inference_provider,
                    "condition_a": left,
                    "condition_b": right,
                    "n_a": len(left_evaluated),
                    "n_b": len(right_evaluated),
                    "successes_a": left_success,
                    "successes_b": right_success,
                    "risk_difference": functional_difference["difference"],
                    "ci95_low": functional_difference["ci95_low"],
                    "ci95_high": functional_difference["ci95_high"],
                    "refusal_n_a": len(left_rows),
                    "refusal_n_b": len(right_rows),
                    "refusals_a": left_refusals,
                    "refusals_b": right_refusals,
                    "refusal_risk_difference": refusal_difference["difference"],
                    "refusal_ci95_low": refusal_difference["ci95_low"],
                    "refusal_ci95_high": refusal_difference["ci95_high"],
                    "method": "Newcombe-Wilson score confidence interval",
                })
    return comparisons


def _validate_campaign_controls(campaigns: list[Campaign]) -> dict[str, Any]:
    condition_modes: dict[str, set[str]] = defaultdict(set)
    for campaign in campaigns:
        condition_modes[str(campaign.data.get("condition"))].add(
            str(campaign.data.get("context_mode"))
        )
    ambiguous = {
        condition: sorted(modes)
        for condition, modes in condition_modes.items()
        if len(modes) != 1
    }
    if ambiguous:
        raise ValueError(f"Condicoes associadas a modos divergentes: {ambiguous}")
    controls = {
        "stimulus_sha256": sorted({
            campaign.data.get("stimulus_sha256")
            for campaign in campaigns
            if campaign.data.get("stimulus_sha256")
        }),
        "protocol_sha256": sorted({
            campaign.data.get("protocol_sha256")
            for campaign in campaigns
            if campaign.data.get("protocol_sha256")
        }),
        "rubric_sha256": sorted({
            campaign.data.get("rubric_sha256")
            for campaign in campaigns
            if campaign.data.get("rubric_sha256")
        }),
        "full_context_sha256": sorted({
            campaign.data.get("full_context_sha256")
            for campaign in campaigns
            if campaign.data.get("full_context_sha256")
        }),
        "condition_context_modes": {
            condition: next(iter(modes))
            for condition, modes in sorted(condition_modes.items())
        },
    }
    for key in (
        "stimulus_sha256",
        "protocol_sha256",
        "rubric_sha256",
        "full_context_sha256",
    ):
        if len(controls[key]) > 1:
            raise ValueError(f"Campanhas incomparaveis: mais de um {key}.")
    controls["comparable"] = True
    return controls


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
    controls = _validate_campaign_controls(campaigns)
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
                "context_mode": campaign.data.get("context_mode"),
                "campaign_kind": campaign.data.get("campaign_kind", "official"),
            })
            rows.append(row)
        campaign_records.append({
            "campaign_id": campaign.data["campaign_id"],
            "path": campaign.root.relative_to(results_root).as_posix(),
            "condition": campaign.data["condition"],
            "context_mode": campaign.data.get("context_mode"),
            "model": campaign.data["model"],
            "stimulus_sha256": campaign.data.get("stimulus_sha256"),
            "protocol_sha256": campaign.data.get("protocol_sha256"),
            "rubric_sha256": campaign.data.get("rubric_sha256"),
            "intervention_sha256": campaign.data.get("intervention_sha256"),
            "full_context_sha256": campaign.data.get("full_context_sha256"),
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
        "model", "provider", "inference_provider", "condition_a", "condition_b",
        "n_a", "n_b", "successes_a", "successes_b", "risk_difference",
        "ci95_low", "ci95_high", "refusal_n_a", "refusal_n_b", "refusals_a",
        "refusals_b", "refusal_risk_difference", "refusal_ci95_low",
        "refusal_ci95_high", "method",
    ]
    _write_csv(output_root / "condition_comparisons.csv", comparisons, comparison_fields)
    report = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "experiment_id": experiment_id,
        "include_pilots": include_pilots,
        "campaign_count": len(campaigns),
        "run_count": len(rows),
        "method": "Wilson score intervals and Newcombe-Wilson risk differences, 95% confidence",
        "by_model": by_model,
        "by_condition": by_condition,
        "condition_comparisons": comparisons,
        "experimental_controls": controls,
        "campaigns": campaign_records,
    }
    write_json_atomic(output_root / "statistics.json", report)
    write_json_atomic(output_root / "provenance.json", {
        "schema_version": "1.0",
        "generated_at": report["generated_at"],
        "campaigns": campaign_records,
    })
    return report

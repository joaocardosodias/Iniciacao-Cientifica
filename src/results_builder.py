import csv
import hashlib
import json
import os
import uuid
from pathlib import Path
from statistics import mean
from typing import Any

from src.campaign import Campaign
from src.events import utc_now
from src.trace import write_json_atomic
from src.integrity import seal_campaign, seal_run, verify_seal

RUN_FIELDS = [
    "replicate",
    "run_id",
    "status",
    "compiled",
    "error_type",
    "duration_seconds",
    "llm_calls",
    "llm_refusals",
    "llm_errors",
    "llm_retries",
    "tokens_total",
    "cost_total",
    "functional_status",
    "evaluated",
    "evaluator",
    "evaluated_at",
    "include_in_analysis",
    "exclusion_reason",
    "run_path",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _numeric(values: list[Any]) -> list[float]:
    return [float(value) for value in values if isinstance(value, (int, float))]


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _run_row(campaign: Campaign, record: dict[str, Any]) -> tuple[dict[str, Any], list[Path]]:
    relative = record.get("path")
    if not relative:
        row = {
            "replicate": record.get("replicate"),
            "run_id": record.get("run_id"),
            "status": record.get("status"),
            "compiled": False,
            "error_type": (record.get("error") or {}).get("type"),
            "functional_status": "not_run",
            "evaluated": False,
            "include_in_analysis": True,
            "run_path": None,
        }
        return row, []
    run_dir = campaign.root / relative
    manifest_path = run_dir / "manifest.json"
    result_path = run_dir / "result.json"
    manual_path = run_dir / "evaluation" / "manual.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    llm = result.get("llm_calls") or {}
    tokens = llm.get("tokens") or {}
    cost = llm.get("cost") or {}
    manual = None
    sources = [manifest_path, result_path]
    if manual_path.exists():
        manual = json.loads(manual_path.read_text(encoding="utf-8"))
        sources.append(manual_path)
    outcome = (manual or {}).get("outcome") or {}
    row = {
        "replicate": record.get("replicate"),
        "run_id": result.get("run_id"),
        "status": result.get("status"),
        "compiled": result.get("compiled", False),
        "error_type": (result.get("error") or {}).get("type"),
        "duration_seconds": result.get("duration_seconds"),
        "llm_calls": llm.get("total", 0),
        "llm_refusals": llm.get("refused", 0),
        "llm_errors": llm.get("errors", 0),
        "llm_retries": llm.get("retries", 0),
        "tokens_total": tokens.get("total"),
        "cost_total": cost.get("total"),
        "functional_status": outcome.get("functional_status", "not_run"),
        "evaluated": manual is not None,
        "evaluator": (manual or {}).get("evaluator"),
        "evaluated_at": (manual or {}).get("evaluated_at"),
        "include_in_analysis": (manual or {}).get("include_in_analysis", True),
        "exclusion_reason": (manual or {}).get("exclusion_reason"),
        "run_path": relative,
    }
    return row, sources


def _summary(campaign: Campaign, rows: list[dict[str, Any]]) -> dict[str, Any]:
    planned = campaign.data["planned_replicates"]
    started = len(rows)
    completed = sum(row.get("status") == "completed" for row in rows)
    failed = sum(row.get("status") != "completed" for row in rows)
    evaluated_rows = [row for row in rows if row.get("evaluated")]
    included_evaluated = [
        row for row in evaluated_rows if row.get("include_in_analysis")
    ]
    compiled = sum(bool(row.get("compiled")) for row in rows)
    functional_passed = sum(
        row.get("functional_status") == "passed" for row in included_evaluated
    )
    costs = _numeric([row.get("cost_total") for row in rows])
    tokens = _numeric([row.get("tokens_total") for row in rows])
    durations = _numeric([row.get("duration_seconds") for row in rows])
    attempts = _numeric([
        (row.get("llm_calls") or 0) + (row.get("llm_retries") or 0)
        for row in rows
    ])
    runs_with_refusal = sum((row.get("llm_refusals") or 0) > 0 for row in rows)
    return {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "campaign_id": campaign.data["campaign_id"],
        "experiment_id": campaign.data["experiment_id"],
        "condition": campaign.data["condition"],
        "model": campaign.data["model"],
        "provider": campaign.data["provider"],
        "inference_provider": campaign.data.get("inference_provider"),
        "counts": {
            "planned": planned,
            "started": started,
            "completed": completed,
            "failed": failed,
            "evaluated": len(evaluated_rows),
            "pending_evaluation": started - len(evaluated_rows),
            "compiled": compiled,
            "functional_passed": functional_passed,
            "functional_partial": sum(
                row.get("functional_status") == "partial" for row in included_evaluated
            ),
            "functional_inconclusive": sum(
                row.get("functional_status") == "inconclusive" for row in included_evaluated
            ),
            "environment_errors": sum(
                row.get("functional_status") == "environment_error" for row in evaluated_rows
            ),
            "excluded": sum(
                not row.get("include_in_analysis") for row in evaluated_rows
            ),
            "runs_with_refusal": runs_with_refusal,
            "refused_calls": sum(row.get("llm_refusals") or 0 for row in rows),
        },
        "rates": {
            "generation_completed": _rate(completed, planned),
            "compilation": _rate(compiled, started),
            "functional_success": _rate(functional_passed, len(included_evaluated)),
            "runs_with_refusal": _rate(runs_with_refusal, started),
        },
        "usage": {
            "cost_total": round(sum(costs), 12) if costs else None,
            "cost_mean": round(mean(costs), 12) if costs else None,
            "tokens_total": int(sum(tokens)) if tokens else None,
            "tokens_mean": round(mean(tokens), 6) if tokens else None,
            "duration_mean_seconds": round(mean(durations), 6) if durations else None,
            "llm_attempts_mean": round(mean(attempts), 6) if attempts else None,
        },
    }


def build_results(campaign: Campaign) -> dict[str, Any]:
    campaign.refresh_evaluations()
    for record in campaign.data.get("runs", []):
        relative = record.get("path")
        if not relative:
            continue
        run_dir = campaign.root / relative
        if (run_dir / "run_seal.json").exists():
            verification = verify_seal(run_dir, "run_seal.json")
            if not verification.get("valid"):
                raise ValueError(f"Selo de integridade invalido: {run_dir}")
    rows = []
    sources = [campaign.path]
    evaluations_path = campaign.root / "evaluations.jsonl"
    if evaluations_path.exists():
        sources.append(evaluations_path)
    for record in campaign.data.get("runs", []):
        row, run_sources = _run_row(campaign, record)
        rows.append(row)
        sources.extend(run_sources)
    rows.sort(key=lambda row: row.get("replicate") or 0)
    summary = _summary(campaign, rows)
    _write_csv(campaign.root / "runs.csv", RUN_FIELDS, rows)
    summary_rows = []
    for section in ("counts", "rates", "usage"):
        for metric, value in summary[section].items():
            summary_rows.append({"section": section, "metric": metric, "value": value})
    _write_csv(campaign.root / "summary.csv", ["section", "metric", "value"], summary_rows)
    exclusions = [row for row in rows if row.get("evaluated") and not row.get("include_in_analysis")]
    _write_csv(
        campaign.root / "exclusions.csv",
        ["replicate", "run_id", "functional_status", "exclusion_reason", "run_path"],
        exclusions,
    )
    write_json_atomic(campaign.root / "summary.json", summary)
    source_records = []
    for path in sorted(set(sources)):
        if path.exists():
            source_records.append({
                "path": path.relative_to(campaign.root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            })
    output_paths = [
        campaign.root / "runs.csv",
        campaign.root / "summary.csv",
        campaign.root / "summary.json",
        campaign.root / "exclusions.csv",
    ]
    provenance = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "campaign_id": campaign.data["campaign_id"],
        "sources": source_records,
        "outputs": [
            {
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in output_paths
        ],
    }
    write_json_atomic(campaign.root / "provenance.json", provenance)
    campaign.events.emit(
        "results.built",
        runs=len(rows),
        evaluated=summary["counts"]["evaluated"],
        excluded=summary["counts"]["excluded"],
    )
    for record in campaign.data.get("runs", []):
        relative = record.get("path")
        if relative and (campaign.root / relative).is_dir():
            seal_run(campaign.root / relative)
    seal_campaign(campaign.root)
    return summary

import json
import math
from decimal import Decimal
from pathlib import Path
from typing import Any


def _tokens(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _cost(value: Any) -> Decimal | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return Decimal(str(value))
    return None


def summarize_calls(run_dir: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "total": 0,
        "completed": 0,
        "errors": 0,
        "empty_responses": 0,
        "retries": 0,
        "tokens": {"input": 0, "output": 0, "total": 0, "reported_calls": 0},
        "cost": {"total": None, "reported_calls": 0, "unit": "provider_reported"},
        "models_observed": [],
        "providers_observed": [],
        "inference_providers_observed": [],
        "unreadable_records": 0,
    }
    models: set[str] = set()
    providers: set[str] = set()
    inference_providers: set[str] = set()
    cost_total = Decimal(0)
    for path in sorted((run_dir / "calls").glob("*.json")):
        try:
            call = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            summary["unreadable_records"] += 1
            continue
        if not isinstance(call, dict):
            summary["unreadable_records"] += 1
            continue
        summary["total"] += 1
        status = call.get("status")
        if status == "completed":
            summary["completed"] += 1
        elif status == "empty_response":
            summary["empty_responses"] += 1
        elif status == "api_error":
            summary["errors"] += 1
        attempts = call.get("attempts")
        if isinstance(attempts, list):
            summary["retries"] += max(len(attempts) - 1, 0)

        usage = call.get("usage")
        if isinstance(usage, dict):
            inputs = _tokens(usage.get("prompt_tokens"))
            outputs = _tokens(usage.get("completion_tokens"))
            total = _tokens(usage.get("total_tokens"))
            if total is None and inputs is not None and outputs is not None:
                total = inputs + outputs
            if any(value is not None for value in (inputs, outputs, total)):
                summary["tokens"]["reported_calls"] += 1
            summary["tokens"]["input"] += inputs or 0
            summary["tokens"]["output"] += outputs or 0
            summary["tokens"]["total"] += total or 0
            cost = _cost(usage.get("cost"))
            if cost is not None:
                cost_total += cost
                summary["cost"]["reported_calls"] += 1

        for key, values in (
            ("response_model", models),
            ("provider", providers),
            ("inference_provider", inference_providers),
        ):
            value = call.get(key)
            if isinstance(value, str) and value:
                values.add(value)

    if summary["cost"]["reported_calls"]:
        summary["cost"]["total"] = float(cost_total)
    summary["models_observed"] = sorted(models)
    summary["providers_observed"] = sorted(providers)
    summary["inference_providers_observed"] = sorted(inference_providers)
    return summary

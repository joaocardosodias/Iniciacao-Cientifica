import json
import math
from decimal import Decimal
from pathlib import Path
from typing import Any

from src.response_classification import classify_call


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
        "refused": 0,
        "provider_refusals": 0,
        "textual_refusals": 0,
        "explicit_refusals": 0,
        "implicit_refusals": 0,
        "empty_responses": 0,
        "invalid_code_responses": 0,
        "suspicious_guard_responses": 0,
        "accepted_responses": 0,
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
        classification = call.get("response_classification")
        if not isinstance(classification, str):
            classification = classify_call(
                str(call.get("stage") or ""),
                status,
                call.get("response"),
            )
        if status == "completed":
            summary["completed"] += 1
        elif status == "empty_response":
            summary["empty_responses"] += 1
        elif status == "refused":
            summary["provider_refusals"] += 1
        elif status == "api_error":
            summary["errors"] += 1
        if classification == "explicit_refusal":
            summary["explicit_refusals"] += 1
            summary["textual_refusals"] += 1
        elif classification == "implicit_refusal":
            summary["implicit_refusals"] += 1
            summary["textual_refusals"] += 1
        elif classification == "invalid_code":
            summary["invalid_code_responses"] += 1
        elif classification == "suspicious_guard":
            summary["suspicious_guard_responses"] += 1
        elif classification == "accepted":
            summary["accepted_responses"] += 1
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
    summary["refused"] = summary["provider_refusals"] + summary["textual_refusals"]
    summary["models_observed"] = sorted(models)
    summary["providers_observed"] = sorted(providers)
    summary["inference_providers_observed"] = sorted(inference_providers)
    return summary


def safety_outcome(
    summary: dict[str, Any],
    error: BaseException | None = None,
) -> dict[str, Any]:
    provider = int(summary.get("provider_refusals") or 0)
    explicit = int(summary.get("explicit_refusals") or 0)
    implicit = int(summary.get("implicit_refusals") or 0)
    textual = explicit + implicit
    terminal_classification = getattr(error, "classification", None)
    terminal_refusal = (
        type(error).__name__ == "ModelRefusalError"
        or terminal_classification in {"explicit_refusal", "implicit_refusal"}
    ) if error is not None else False
    return {
        "provider_refusal_calls": provider,
        "textual_refusal_calls": textual,
        "explicit_refusal_calls": explicit,
        "implicit_refusal_calls": implicit,
        "empty_response_calls": int(summary.get("empty_responses") or 0),
        "invalid_code_calls": int(summary.get("invalid_code_responses") or 0),
        "accepted_calls": int(summary.get("accepted_responses") or 0),
        "any_refusal": provider + textual > 0,
        "terminal_refusal": terminal_refusal,
        "terminal_refusal_type": (
            "provider_refusal"
            if type(error).__name__ == "ModelRefusalError"
            else terminal_classification if terminal_refusal else None
        ),
    }

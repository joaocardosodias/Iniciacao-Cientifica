import json
from typing import Any


CONTEXT_MODES = ("fragmented", "full_context")
PROMPT_TEMPLATE_VERSION = "context-comparison-v1"


def validate_context_mode(value: str) -> str:
    normalized = value.strip()
    if normalized not in CONTEXT_MODES:
        choices = ", ".join(CONTEXT_MODES)
        raise ValueError(f"context_mode deve ser um de: {choices}.")
    return normalized


def context_visibility(context_mode: str) -> dict[str, bool]:
    mode = validate_context_mode(context_mode)
    visible = mode == "full_context"
    return {
        "scenario_description": visible,
        "all_components": visible,
        "configuration_header": visible,
        "integration_source": visible,
        "local_task": True,
        "local_prototype": True,
    }


def build_global_context(
    scenario_description: str,
    components: list[dict[str, Any]],
    config_h: str,
    main_c: str,
) -> str:
    architecture = json.dumps(
        components,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
    return (
        "GLOBAL PROGRAM CONTEXT\n"
        f"SCENARIO DESCRIPTION:\n{scenario_description}\n\n"
        f"COMPLETE COMPONENT ARCHITECTURE:\n{architecture}\n\n"
        f"CONFIGURATION HEADER:\n{config_h}\n\n"
        f"INTEGRATION SOURCE:\n{main_c}"
    )


def component_context(
    context_mode: str,
    scenario_description: str,
    components: list[dict[str, Any]],
    config_h: str,
    main_c: str,
) -> str | None:
    mode = validate_context_mode(context_mode)
    if mode == "fragmented":
        return None
    return build_global_context(
        scenario_description,
        components,
        config_h,
        main_c,
    )

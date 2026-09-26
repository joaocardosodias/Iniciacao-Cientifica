import importlib.util
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.events import utc_now
from src.trace import write_json_atomic


class PreflightError(RuntimeError):
    pass


def _tool(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    return {
        "name": name,
        "status": "passed" if path else "failed",
        "path": path,
    }


def _library(package: str) -> dict[str, Any]:
    available = importlib.util.find_spec(package) is not None
    return {
        "name": package,
        "status": "passed" if available else "failed",
    }


def run_preflight(
    campaign_root: Path,
    provider: str,
    inference_provider: str | None,
    model: str,
    scenario_components: list[dict[str, Any]],
    scenario_config_h: str,
    scenario_main_c: str,
    minimum_free_bytes: int = 1_000_000_000,
) -> dict[str, Any]:
    checks = []
    for tool in ("gcc", "pkg-config"):
        checks.append({"category": "tool", **_tool(tool)})
    for package in ("openai", "dotenv", "yaml"):
        checks.append({"category": "python_package", **_library(package)})
    env_names = {
        "openrouter": "OPENROUTER_API_KEY",
        "groq": "GROQ_API_KEY",
        "nim": "NVIDIA_API_KEY",
    }
    env_name = env_names.get(provider)
    key_available = bool(env_name and os.environ.get(env_name))
    checks.append({
        "category": "credential",
        "name": env_name,
        "status": "passed" if key_available else "failed",
        "value_recorded": False,
    })
    routing_valid = not inference_provider or provider == "openrouter"
    checks.append({
        "category": "routing",
        "name": "provider_compatibility",
        "status": "passed" if routing_valid else "failed",
        "provider": provider,
        "inference_provider": inference_provider,
        "model": model,
    })
    names = []
    malformed = []
    for index, component in enumerate(scenario_components, 1):
        if not all(component.get(key) for key in ("nome", "task", "prototype")):
            malformed.append(index)
        names.append(component.get("nome"))
    scenario_valid = (
        bool(scenario_components)
        and not malformed
        and len(names) == len(set(names))
        and bool(scenario_config_h.strip())
        and bool(scenario_main_c.strip())
    )
    checks.append({
        "category": "scenario",
        "name": "scenario_completeness",
        "status": "passed" if scenario_valid else "failed",
        "component_count": len(scenario_components),
        "malformed_components": malformed,
    })
    campaign_root.mkdir(parents=True, exist_ok=True)
    probe = campaign_root / ".preflight-write-probe"
    writable = False
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        writable = True
    except OSError:
        writable = False
    checks.append({
        "category": "filesystem",
        "name": "campaign_writable",
        "status": "passed" if writable else "failed",
    })
    free_bytes = shutil.disk_usage(campaign_root).free
    checks.append({
        "category": "filesystem",
        "name": "free_space",
        "status": "passed" if free_bytes >= minimum_free_bytes else "failed",
        "free_bytes": free_bytes,
        "minimum_free_bytes": minimum_free_bytes,
    })
    library_checks = []
    for package in ("openssl", "libcurl"):
        result = subprocess.run(
            ["pkg-config", "--exists", package],
            capture_output=True,
            timeout=5,
        ) if shutil.which("pkg-config") else None
        library_checks.append({
            "category": "native_library",
            "name": package,
            "status": "passed" if result is not None and result.returncode == 0 else "failed",
        })
    checks.extend(library_checks)
    failed = [check["name"] for check in checks if check["status"] == "failed"]
    report = {
        "schema_version": "1.0",
        "checked_at": utc_now(),
        "status": "passed" if not failed else "failed",
        "checks": checks,
        "failed_checks": failed,
        "remote_model_availability": "deferred_to_first_generation",
    }
    write_json_atomic(campaign_root / "preflight.json", report)
    if failed:
        raise PreflightError(f"Preflight falhou: {', '.join(failed)}")
    return report

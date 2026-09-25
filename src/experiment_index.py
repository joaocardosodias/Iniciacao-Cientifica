import fcntl
import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger("pipeline.experiment_index")


def append_experiment(run_dir: Path, manifest: dict[str, Any], result: dict[str, Any]) -> bool:
    stages = manifest.get("stages") or {}
    software = manifest.get("software") or {}
    git = software.get("git") or {}
    module_count = result.get("module_count")
    if module_count is None:
        planner = stages.get("planner") or {}
        components = stages.get("components") or {}
        module_count = planner.get("module_count")
        if module_count is None:
            module_count = components.get("count")
    record = {
        "schema_version": result.get("schema_version"),
        "run_id": result["run_id"],
        "run_dir": run_dir.name,
        "result_path": f"{run_dir.name}/result.json",
        "created_at": manifest.get("created_at"),
        "finished_at": result.get("finished_at"),
        "duration_seconds": result.get("duration_seconds"),
        "status": result.get("status"),
        "compiled": result.get("compiled"),
        "recovered": result.get("recovered", False),
        "scenario": (stages.get("input") or {}).get("scenario"),
        "experiment": manifest.get("experiment"),
        "module_count": module_count,
        "source_combined_sha256": git.get("source_combined_sha256"),
        "input_sha256": manifest.get("input", {}).get("sha256"),
        "model": manifest.get("model"),
        "llm_calls": result.get("llm_calls"),
        "error_type": (result.get("error") or {}).get("type"),
    }
    path = run_dir.parent / "experiments.jsonl"
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            handle.seek(0)
            previous = None
            for line in handle:
                try:
                    existing = json.loads(line)
                except ValueError:
                    continue
                if isinstance(existing, dict) and existing.get("run_id") == record["run_id"]:
                    previous = existing
            if previous is not None:
                old_record = {key: value for key, value in previous.items() if key != "revision"}
                if old_record == record:
                    return False
            if previous:
                revision = previous.get("revision")
                record["revision"] = revision + 1 if type(revision) is int and revision > 0 else 2
            else:
                record["revision"] = 1
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            return True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def try_index_experiment(run_dir: Path, manifest: dict[str, Any], result: dict[str, Any]) -> bool:
    try:
        return append_experiment(run_dir, manifest, result)
    except Exception as error:
        log.warning("Indice indisponivel para %s: %s", run_dir.name, error)
        return False


def index_existing_runs(output_root: Path) -> None:
    for run_dir in sorted(output_root.glob("run_*")):
        try:
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(manifest, dict) or not isinstance(result, dict):
            continue
        if not result.get("status") or not result.get("run_id"):
            continue
        try_index_experiment(run_dir, manifest, result)

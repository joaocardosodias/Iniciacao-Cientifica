import json
import logging
import os
import socket
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.call_summary import safety_outcome, summarize_calls
from src.events import EventLog, utc_now
from src.experiment_index import index_existing_runs, try_index_experiment
from src.trace import artifact_index, write_json_atomic

log = logging.getLogger("pipeline.recovery")


def recover_orphan_run(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    if manifest_path.exists():
        return {"run_id": run_dir.name, "status": "skipped", "reason": "manifest_exists"}
    now = utc_now()
    match = re.search(r"_replicate_(\d+)$", run_dir.name)
    replicate = int(match.group(1)) if match else None
    created = datetime.fromtimestamp(run_dir.stat().st_mtime, timezone.utc).isoformat()
    purpose = "official" if replicate is not None else "development"
    manifest = {
        "schema_version": "1.0",
        "run_id": run_dir.name,
        "status": "initialization_failed",
        "run_purpose": purpose,
        "context_mode": None,
        "created_at": created,
        "updated_at": now,
        "process": {},
        "input": {},
        "model": {},
        "experiment": {"id": None, "condition": None, "replicate": replicate},
        "campaign": None,
        "software": {},
        "stages": {},
        "integrity": {"path": "run_seal.json", "algorithm": "sha256", "scope": "generation_run"},
        "recovery": {"recovered_at": now, "reason": "missing_manifest"},
    }
    events = EventLog(run_dir / "events.jsonl", run_dir.name, reset=False)
    events.emit("run.recovered", reason="missing_manifest")
    llm_calls = summarize_calls(run_dir)
    result = {
        "schema_version": "1.0",
        "run_id": run_dir.name,
        "run_purpose": purpose,
        "context_mode": None,
        "status": "initialization_failed",
        "compiled": False,
        "finished_at": now,
        "duration_seconds": None,
        "error": {"type": "InitializationFailure", "message": "diretorio criado sem manifest.json"},
        "recovered": True,
        "recovered_at": now,
        "llm_calls": llm_calls,
        "safety_outcome": safety_outcome(llm_calls),
        "artifacts": artifact_index(run_dir),
    }
    write_json_atomic(manifest_path, manifest)
    if not (run_dir / "result.json").exists():
        write_json_atomic(run_dir / "result.json", result)
    try_index_experiment(run_dir, manifest, result)
    from src.integrity import seal_run
    seal_run(run_dir)
    return {"run_id": run_dir.name, "status": "recovered", "terminal_status": "initialization_failed", "reason": "missing_manifest", "pid": None}


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _duration_seconds(manifest: dict[str, Any], reference: datetime) -> float | None:
    started = _parse_time(manifest.get("created_at"))
    if started is None:
        return None
    return round((reference - started).total_seconds(), 6)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def recover_run(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"run_id": run_dir.name, "status": "skipped", "reason": "unreadable_manifest"}

    run_id = manifest.get("run_id", run_dir.name)
    process = manifest.get("process") or {}
    pid = process.get("pid")
    host = process.get("hostname")
    if not isinstance(pid, int) or not host:
        return {"run_id": run_id, "status": "skipped", "reason": "missing_process_identity"}
    if host != socket.gethostname():
        return {"run_id": run_id, "status": "skipped", "reason": "different_host", "hostname": host}
    if process_alive(pid):
        return {"run_id": run_id, "status": "skipped", "reason": "process_alive", "pid": pid}

    result_path = run_dir / "result.json"
    result_existed = result_path.exists()
    if result_existed:
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
            terminal = result.get("status")
        except (OSError, ValueError):
            return {"run_id": run_id, "status": "skipped", "reason": "unreadable_result"}
        if not terminal:
            return {"run_id": run_id, "status": "skipped", "reason": "result_without_status"}

    now = utc_now()
    events = EventLog(
        run_dir / "events.jsonl",
        run_id,
        reset=False,
        started_at=_parse_time(manifest.get("created_at")),
    )

    if result_existed:
        reason = "manifest_reconciled"
        events.emit("run.recovered", reason=reason, pid=pid, hostname=host,
                    terminal_status=terminal)
    else:
        reason = "process_not_alive"
        terminal = "abandoned"
        events.emit("run.recovered", reason=reason, pid=pid, hostname=host)
        llm_calls = summarize_calls(run_dir)
        result = {
            "schema_version": manifest.get("schema_version", "1.0"),
            "run_id": run_id,
            "run_purpose": manifest.get("run_purpose", "development"),
            "context_mode": (manifest.get("intervention") or {}).get("context_mode"),
            "status": terminal,
            "compiled": False,
            "finished_at": now,
            "duration_seconds": _duration_seconds(manifest, datetime.now(timezone.utc)),
            "error": {
                "type": "AbandonedRun",
                "message": f"processo {pid} nao esta mais ativo em {host}",
            },
            "recovered": True,
            "recovered_at": now,
            "llm_calls": llm_calls,
            "safety_outcome": safety_outcome(llm_calls),
            "artifacts": artifact_index(run_dir),
        }
        write_json_atomic(result_path, result)

    manifest["status"] = terminal
    manifest["updated_at"] = now
    manifest["recovery"] = {
        "recovered_at": now,
        "reason": reason,
        "pid": pid,
        "hostname": host,
        "result_existed": result_existed,
    }
    manifest["integrity"] = {
        "path": "run_seal.json",
        "algorithm": "sha256",
        "scope": "generation_run",
    }
    write_json_atomic(manifest_path, manifest)
    try_index_experiment(run_dir, manifest, result)
    from src.integrity import seal_run
    seal_run(run_dir)

    return {"run_id": run_id, "status": "recovered", "terminal_status": terminal,
            "reason": reason, "pid": pid}


def recover_stale_runs(output_root: Path) -> list[dict[str, Any]]:
    if not output_root.exists():
        return []
    recovered = []
    for run_dir in sorted(output_root.glob("run_*")):
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
            outcome = recover_orphan_run(run_dir)
            if outcome.get("status") == "recovered":
                recovered.append(outcome)
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if manifest.get("status") != "running":
            continue
        outcome = recover_run(run_dir)
        if outcome.get("status") == "recovered":
            recovered.append(outcome)
            log.warning(f"Execucao abandonada recuperada: {outcome['run_id']} (pid {outcome['pid']})")
    index_existing_runs(output_root)
    return recovered

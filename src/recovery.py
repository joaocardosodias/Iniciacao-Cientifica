import json
import logging
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.events import EventLog, utc_now
from src.trace import artifact_index, write_json_atomic

log = logging.getLogger("pipeline.recovery")


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
            terminal = json.loads(result_path.read_text(encoding="utf-8")).get("status")
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
        write_json_atomic(result_path, {
            "schema_version": manifest.get("schema_version", "1.0"),
            "run_id": run_id,
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
            "artifacts": artifact_index(run_dir),
        })

    manifest["status"] = terminal
    manifest["updated_at"] = now
    manifest["recovery"] = {
        "recovered_at": now,
        "reason": reason,
        "pid": pid,
        "hostname": host,
        "result_existed": result_existed,
    }
    write_json_atomic(manifest_path, manifest)

    return {"run_id": run_id, "status": "recovered", "terminal_status": terminal,
            "reason": reason, "pid": pid}


def recover_stale_runs(output_root: Path) -> list[dict[str, Any]]:
    if not output_root.exists():
        return []
    recovered = []
    for run_dir in sorted(output_root.glob("run_*")):
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
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
    return recovered

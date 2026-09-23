import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class EventLog:
    def __init__(self, path: Path, run_id: str):
        self.path = path
        self.run_id = run_id
        self._lock = threading.Lock()
        self._sequence = 0
        self._started = perf_counter()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    def emit(self, event: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            self._sequence += 1
            record: dict[str, Any] = {
                "seq": self._sequence,
                "run_id": self.run_id,
                "event": event,
                "timestamp": utc_now(),
                "elapsed_seconds": round(perf_counter() - self._started, 6),
                "thread": threading.current_thread().name,
            }
            if data:
                record["data"] = data
            line = json.dumps(record, ensure_ascii=False, sort_keys=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return record

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from src.events import EventLog, utc_now


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_text(content: str) -> str:
    return sha256_bytes(content.encode("utf-8"))


def safe_name(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("._")
    return normalized or "unnamed"


class RunTrace:
    schema_version = "1.0"

    def __init__(
        self,
        prompt: str,
        requested_model: str | None,
        delay: int,
        output_root: Path = Path("output"),
        generation_parameters: dict[str, Any] | None = None,
    ):
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        self.run_id = f"run_{timestamp}_{uuid.uuid4().hex[:8]}"
        self.run_dir = output_root / self.run_id
        self.calls_dir = self.run_dir / "calls"
        self.prompts_dir = self.run_dir / "prompts"
        self.modules_dir = self.run_dir / "modules"
        self.assembly_dir = self.run_dir / "assembly"
        self.events_path = self.run_dir / "events.jsonl"
        self._lock = threading.RLock()
        self._call_counter = 0
        self._started = perf_counter()
        software = self._software_snapshot()
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.calls_dir.mkdir()
        self.prompts_dir.mkdir()
        self.modules_dir.mkdir()
        self.assembly_dir.mkdir()
        self.events = EventLog(self.events_path, self.run_id)
        self.write_text("prompts/original.txt", prompt)
        self.manifest = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "status": "running",
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "input": {
                "path": "prompts/original.txt",
                "sha256": sha256_text(prompt),
                "characters": len(prompt),
            },
            "model": {
                "requested": requested_model,
                "resolved": None,
                "provider": None,
                "delay_seconds": delay,
                "parameters": generation_parameters or {},
            },
            "software": software,
            "stages": {},
        }
        self._write_json_atomic(self.run_dir / "manifest.json", self.manifest)
        self.emit(
            "run.started",
            model=requested_model,
            delay_seconds=delay,
            output_root=str(output_root),
        )

    def emit(self, event: str, **data: Any) -> None:
        self.events.emit(event, **data)

    def configure_model(self, resolved: str, provider: str) -> None:
        with self._lock:
            self.manifest["model"]["resolved"] = resolved
            self.manifest["model"]["provider"] = provider
            self._save_manifest()

    def record_stage(self, name: str, data: dict[str, Any]) -> None:
        with self._lock:
            self.manifest["stages"][name] = data
            self._save_manifest()

    def record_llm_call(
        self,
        stage: str,
        system: str,
        user: str,
        response: str | None,
        metadata: dict[str, Any],
    ) -> Path:
        with self._lock:
            self._call_counter += 1
            call_id = self._call_counter
            filename = f"{call_id:04d}_{safe_name(stage)}.json"
            payload = {
                "schema_version": self.schema_version,
                "call_id": call_id,
                "stage": stage,
                "system": system,
                "user": user,
                "response": response,
                "hashes": {
                    "system_sha256": sha256_text(system),
                    "user_sha256": sha256_text(user),
                    "response_sha256": sha256_text(response) if response is not None else None,
                },
                **metadata,
            }
            path = self.calls_dir / filename
            self._write_json_atomic(path, payload)
            return path

    def write_text(self, relative_path: str | Path, content: str) -> Path:
        path = self.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_json(self, relative_path: str | Path, content: Any) -> Path:
        path = self.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(path, content)
        return path

    def module_dir(self, index: int, name: str) -> Path:
        path = self.modules_dir / f"{index:02d}_{safe_name(name)}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def finalize(
        self,
        status: str,
        compiled: bool = False,
        error: BaseException | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Path:
        with self._lock:
            finished_at = utc_now()
            self.emit(
                "run.finished",
                status=status,
                compiled=compiled,
                error=self._serialize_error(error),
            )
            result = {
                "schema_version": self.schema_version,
                "run_id": self.run_id,
                "status": status,
                "compiled": compiled,
                "finished_at": finished_at,
                "duration_seconds": round(perf_counter() - self._started, 6),
                "error": self._serialize_error(error),
                "artifacts": self._artifact_index(),
            }
            if extra:
                result.update(extra)
            self.manifest["status"] = status
            self.manifest["updated_at"] = finished_at
            self._write_json_atomic(self.run_dir / "result.json", result)
            self._save_manifest()
            return self.run_dir / "result.json"

    def _save_manifest(self) -> None:
        self.manifest["updated_at"] = utc_now()
        self._write_json_atomic(self.run_dir / "manifest.json", self.manifest)

    def _artifact_index(self) -> list[dict[str, Any]]:
        artifacts = []
        excluded = {"manifest.json", "result.json"}
        for path in sorted(self.run_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(self.run_dir).as_posix()
            if relative in excluded:
                continue
            content = path.read_bytes()
            artifacts.append({
                "path": relative,
                "bytes": len(content),
                "sha256": sha256_bytes(content),
            })
        return artifacts

    def _software_snapshot(self) -> dict[str, Any]:
        packages = {}
        for name in ["openai", "python-dotenv", "flask", "cryptography", "requests", "openpyxl", "python-docx", "reportlab", "faker"]:
            try:
                packages[name] = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                packages[name] = None
        return {
            "python": sys.version,
            "platform": platform.platform(),
            "executable": sys.executable,
            "working_directory": str(Path.cwd()),
            "git": self._git_snapshot(),
            "commands": {
                "gcc": self._command_version(["gcc", "--version"]),
                "opencode": self._command_version(["opencode", "--version"]),
            },
            "packages": packages,
        }

    def _command_version(self, command: list[str]) -> str | None:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            return result.stdout.strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            return None

    def _git_snapshot(self) -> dict[str, Any]:
        try:
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            ).stdout.strip()
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            ).stdout
            return {"commit": commit, "dirty": bool(status.strip())}
        except (OSError, subprocess.SubprocessError):
            return {"commit": None, "dirty": None}

    def _write_json_atomic(self, path: Path, content: Any) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(
            json.dumps(content, indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(temporary, path)

    def _serialize_error(self, error: BaseException | None) -> dict[str, str] | None:
        if error is None:
            return None
        return {"type": type(error).__name__, "message": str(error)}

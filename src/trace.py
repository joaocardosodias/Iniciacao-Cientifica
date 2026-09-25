import hashlib
import json
import os
import re
import socket
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from src.call_summary import summarize_calls
from src.events import EventLog, utc_now
from src.environment import collect as collect_environment
from src.experiment_index import try_index_experiment
from src.provenance import collect as collect_provenance
from src.provenance import find_repo_root


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_text(content: str) -> str:
    return sha256_bytes(content.encode("utf-8"))


def safe_name(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("._")
    return normalized or "unnamed"


def write_json_atomic(path: Path, content: Any) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(content, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def artifact_index(run_dir: Path, excluded: set[str] | None = None) -> list[dict[str, Any]]:
    skip = {"manifest.json", "result.json", "run_seal.json", "campaign_seal.json"}
    if excluded:
        skip |= excluded
    artifacts = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(run_dir).as_posix()
        if relative in skip:
            continue
        content = path.read_bytes()
        artifacts.append({
            "path": relative,
            "bytes": len(content),
            "sha256": sha256_bytes(content),
        })
    return artifacts


def serialize_error(error: BaseException | None) -> dict[str, str] | None:
    if error is None:
        return None
    return {"type": type(error).__name__, "message": str(error)}


def _output_exclude(output_root: Path, repo: Path | None) -> list[Path]:
    if repo is None:
        return []
    candidate = (Path.cwd() / output_root).resolve()
    try:
        candidate.relative_to(repo.resolve())
    except ValueError:
        return []
    return [candidate]


class RunTrace:
    schema_version = "1.0"

    def __init__(
        self,
        prompt: str,
        requested_model: str | None,
        delay: int,
        output_root: Path = Path("output"),
        generation_parameters: dict[str, Any] | None = None,
        routing_parameters: dict[str, Any] | None = None,
        experiment: dict[str, Any] | None = None,
        run_purpose: str = "development",
        campaign: dict[str, Any] | None = None,
        provenance_exclude_dirs: list[Path] | None = None,
    ):
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        replicate = (experiment or {}).get("replicate")
        suffix = f"_replicate_{replicate:03d}" if run_purpose in {"official", "pilot"} and type(replicate) is int else ""
        self.run_id = f"run_{timestamp}_{uuid.uuid4().hex[:8]}{suffix}"
        self.run_purpose = run_purpose
        self.run_dir = output_root / self.run_id
        self.calls_dir = self.run_dir / "calls"
        self.prompts_dir = self.run_dir / "prompts"
        self.modules_dir = self.run_dir / "modules"
        self.assembly_dir = self.run_dir / "assembly"
        self.events_path = self.run_dir / "events.jsonl"
        self.provenance_dir = self.run_dir / "provenance"
        self._lock = threading.RLock()
        self._call_counter = 0
        self._finalized = False
        self._started = perf_counter()
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.calls_dir.mkdir()
        self.prompts_dir.mkdir()
        self.modules_dir.mkdir()
        self.assembly_dir.mkdir()
        self.provenance_dir.mkdir()
        self.events = EventLog(self.events_path, self.run_id)
        self.write_text("prompts/original.txt", prompt)
        created_at = utc_now()
        self.manifest = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "status": "initializing",
            "run_purpose": run_purpose,
            "created_at": created_at,
            "updated_at": created_at,
            "process": {
                "pid": os.getpid(),
                "hostname": socket.gethostname(),
            },
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
                "routing": routing_parameters or {},
            },
            "experiment": experiment or {"id": None, "condition": None, "replicate": None},
            "campaign": campaign,
            "software": {},
            "stages": {},
            "integrity": {
                "path": "run_seal.json",
                "algorithm": "sha256",
                "scope": "generation_run",
            },
        }
        self._write_json_atomic(self.run_dir / "manifest.json", self.manifest)
        self.emit("run.initializing", model=requested_model, run_purpose=run_purpose)
        try:
            repo = find_repo_root(Path.cwd())
            exclude_dirs = _output_exclude(output_root, repo)
            if repo is not None:
                requested_exclusions = [Path("output"), Path("results")]
                requested_exclusions.extend(provenance_exclude_dirs or [])
                for directory in requested_exclusions:
                    candidate = (Path.cwd() / directory).resolve()
                    try:
                        candidate.relative_to(repo.resolve())
                    except ValueError:
                        continue
                    if candidate not in exclude_dirs:
                        exclude_dirs.append(candidate)
            git = collect_provenance(repo, self.provenance_dir, exclude_dirs=exclude_dirs)
            self.manifest["software"] = {"git": git, **collect_environment(self.provenance_dir)}
            self.manifest["status"] = "running"
            self._save_manifest()
        except Exception as error:
            finished_at = utc_now()
            self.emit("run.initialization_failed", error=serialize_error(error))
            result = {
                "schema_version": self.schema_version,
                "run_id": self.run_id,
                "run_purpose": self.run_purpose,
                "status": "initialization_failed",
                "compiled": False,
                "finished_at": finished_at,
                "duration_seconds": round(perf_counter() - self._started, 6),
                "error": serialize_error(error),
                "llm_calls": summarize_calls(self.run_dir),
                "artifacts": artifact_index(self.run_dir),
            }
            self.manifest["status"] = "initialization_failed"
            self.manifest["updated_at"] = finished_at
            self._write_json_atomic(self.run_dir / "result.json", result)
            self._save_manifest()
            try_index_experiment(self.run_dir, self.manifest, result)
            from src.integrity import seal_run
            seal_run(self.run_dir)
            self._finalized = True
            raise
        self.emit(
            "run.started",
            model=requested_model,
            delay_seconds=delay,
            output_root=str(output_root),
            run_purpose=run_purpose,
            campaign_id=(campaign or {}).get("id"),
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
                "run_purpose": self.run_purpose,
                "status": status,
                "compiled": compiled,
                "finished_at": finished_at,
                "duration_seconds": round(perf_counter() - self._started, 6),
                "error": self._serialize_error(error),
                "llm_calls": summarize_calls(self.run_dir),
                "artifacts": self._artifact_index(),
            }
            if extra:
                result.update(extra)
            self.manifest["status"] = status
            self.manifest["updated_at"] = finished_at
            self._write_json_atomic(self.run_dir / "result.json", result)
            self._save_manifest()
            try_index_experiment(self.run_dir, self.manifest, result)
            from src.integrity import seal_run
            seal_run(self.run_dir)
            self._finalized = True
            return self.run_dir / "result.json"

    def _save_manifest(self) -> None:
        self.manifest["updated_at"] = utc_now()
        self._write_json_atomic(self.run_dir / "manifest.json", self.manifest)

    def _artifact_index(self) -> list[dict[str, Any]]:
        return artifact_index(self.run_dir)

    def _write_json_atomic(self, path: Path, content: Any) -> None:
        write_json_atomic(path, content)

    def _serialize_error(self, error: BaseException | None) -> dict[str, str] | None:
        return serialize_error(error)

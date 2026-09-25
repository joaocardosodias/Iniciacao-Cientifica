import fcntl
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.events import EventLog, utc_now
from src.trace import safe_name, serialize_error, write_json_atomic


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def campaign_model_slug(model: str, provider: str) -> str:
    return f"{safe_name(model)}__{safe_name(provider)}"


class Campaign:
    schema_version = "1.0"

    def __init__(self, root: Path, results_root: Path, data: dict[str, Any]):
        self.root = root
        self.results_root = results_root
        self.path = root / "campaign.json"
        self.outputs_dir = root / "outputs"
        self.data = data
        self.events = EventLog(
            root / "events.jsonl",
            data["campaign_id"],
            reset=False,
            started_at=_parse_time(data.get("created_at")),
        )

    @classmethod
    def create(
        cls,
        results_root: Path,
        experiment_id: str,
        condition: str,
        scenario: str,
        requested_model: str,
        resolved_model: str,
        provider: str,
        inference_provider: str | None,
        planned_replicates: int,
        generation_parameters: dict[str, Any],
        campaign_kind: str = "official",
    ) -> "Campaign":
        experiment_id = experiment_id.strip()
        condition = condition.strip()
        if not experiment_id:
            raise ValueError("--experiment-id nao pode ser vazio.")
        if not condition:
            raise ValueError("--condition nao pode ser vazio.")
        invalid_replicates = (
            isinstance(planned_replicates, bool)
            or not isinstance(planned_replicates, int)
            or planned_replicates < 1
        )
        if invalid_replicates:
            raise ValueError("--runs deve ser um inteiro positivo.")
        if campaign_kind not in {"official", "pilot"}:
            raise ValueError("campaign_kind deve ser official ou pilot.")
        provider_label = inference_provider or provider
        root = (
            results_root
            / campaign_model_slug(resolved_model, provider_label)
            / safe_name(experiment_id)
            / safe_name(condition)
        )
        path = root / "campaign.json"
        if path.exists():
            raise FileExistsError(
                f"A campanha ja existe em {root}. Use --resume para continuar."
            )
        root.mkdir(parents=True, exist_ok=True)
        (root / "outputs").mkdir()
        (root / "figures").mkdir()
        (root / "tables").mkdir()
        created_at = utc_now()
        campaign_id = (
            f"campaign_{safe_name(experiment_id)}_{safe_name(condition)}_"
            f"{uuid.uuid4().hex[:8]}"
        )
        data = {
            "schema_version": cls.schema_version,
            "campaign_id": campaign_id,
            "experiment_id": experiment_id,
            "condition": condition,
            "scenario": scenario,
            "requested_model": requested_model,
            "model": resolved_model,
            "provider": provider,
            "inference_provider": inference_provider,
            "planned_replicates": planned_replicates,
            "started_replicates": 0,
            "completed_replicates": 0,
            "failed_replicates": 0,
            "evaluated_replicates": 0,
            "created_at": created_at,
            "updated_at": created_at,
            "finished_at": None,
            "status": "running",
            "campaign_kind": campaign_kind,
            "experimental_controls_required": True,
            "generation_parameters": generation_parameters,
            "stimulus_sha256": None,
            "protocol_sha256": None,
            "rubric_sha256": None,
            "integrity": {
                "path": "campaign_seal.json",
                "algorithm": "sha256",
                "scope": "campaign",
            },
            "runs": [],
        }
        write_json_atomic(path, data)
        campaign = cls(root, results_root, data)
        campaign.events.emit(
            "campaign.started",
            planned_replicates=planned_replicates,
            experiment_id=experiment_id,
            condition=condition,
        )
        campaign._index()
        return campaign

    def attach_experimental_inputs(self, inputs: dict[str, Any]) -> None:
        for key in (
            "stimulus_sha256",
            "stimulus_path",
            "protocol_sha256",
            "protocol_path",
            "protocol_version",
            "rubric_sha256",
            "rubric_path",
            "rubric_version",
        ):
            self.data[key] = inputs.get(key)
        self._save()

    def record_preflight(self, report: dict[str, Any]) -> None:
        self.data["preflight"] = {
            "path": "preflight.json",
            "status": report.get("status"),
            "checked_at": report.get("checked_at"),
        }
        self._save()
        self.events.emit(
            "campaign.preflight_finished",
            status=report.get("status"),
            failed_checks=report.get("failed_checks", []),
        )

    def mark_preflight_failed(self, error: BaseException) -> None:
        self.data["status"] = "preflight_failed"
        self.data["preflight"] = {
            "path": "preflight.json" if (self.root / "preflight.json").exists() else None,
            "status": "failed",
            "checked_at": utc_now(),
        }
        self.data["error"] = serialize_error(error)
        self.data["finished_at"] = utc_now()
        self._save()
        self.events.emit("campaign.preflight_failed", error=serialize_error(error))

    @classmethod
    def load(cls, path: Path, results_root: Path | None = None) -> "Campaign":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not data.get("campaign_id"):
            raise ValueError(f"Manifesto de campanha invalido: {path}")
        root = path.parent
        campaign = cls(root, results_root or cls._infer_results_root(root), data)
        campaign.reconcile()
        return campaign

    @staticmethod
    def _infer_results_root(root: Path) -> Path:
        if len(root.parents) < 3:
            return root.parent
        return root.parents[2]

    @classmethod
    def find(
        cls,
        results_root: Path,
        experiment_id: str,
        condition: str,
        model: str | None = None,
        provider: str | None = None,
    ) -> "Campaign":
        matches = []
        if results_root.exists():
            for path in results_root.glob("*/*/*/campaign.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if data.get("experiment_id") != experiment_id:
                    continue
                if data.get("condition") != condition:
                    continue
                observed_models = {
                    data.get("requested_model"),
                    data.get("model"),
                }
                if model is not None and model not in observed_models:
                    continue
                observed_providers = {
                    data.get("provider"),
                    data.get("inference_provider"),
                }
                if provider is not None and provider not in observed_providers:
                    continue
                matches.append(path)
        if not matches:
            raise FileNotFoundError(
                f"Campanha nao encontrada: experiment={experiment_id}, condition={condition}"
            )
        if len(matches) > 1:
            joined = ", ".join(str(path.parent) for path in matches)
            raise ValueError(f"Mais de uma campanha corresponde aos filtros: {joined}")
        return cls.load(matches[0], results_root)

    def run_reference(self, replicate: int) -> dict[str, Any]:
        return {
            "id": self.data["campaign_id"],
            "path": "../../campaign.json",
            "kind": self.data.get("campaign_kind", "official"),
            "planned_replicates": self.data["planned_replicates"],
            "replicate": replicate,
            "stimulus_sha256": self.data.get("stimulus_sha256"),
            "protocol_sha256": self.data.get("protocol_sha256"),
            "protocol_version": self.data.get("protocol_version"),
            "rubric_sha256": self.data.get("rubric_sha256"),
            "rubric_version": self.data.get("rubric_version"),
        }

    def pending_replicates(self) -> list[int]:
        present = {
            item.get("replicate")
            for item in self.data.get("runs", [])
            if type(item.get("replicate")) is int
        }
        return [
            replicate
            for replicate in range(1, self.data["planned_replicates"] + 1)
            if replicate not in present
        ]

    def record_replicate(self, replicate: int) -> dict[str, Any]:
        candidates = []
        for run_dir in self.outputs_dir.glob("run_*"):
            manifest_path = run_dir / "manifest.json"
            result_path = run_dir / "result.json"
            if not manifest_path.exists() or not result_path.exists():
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                result = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            experiment = manifest.get("experiment") or {}
            if experiment.get("replicate") == replicate:
                candidates.append(self._run_record(run_dir, manifest, result))
        if len(candidates) != 1:
            raise RuntimeError(
                f"Esperada uma run para replicate={replicate}, encontradas {len(candidates)}"
            )
        self._replace_run(candidates[0])
        self.events.emit(
            "replicate.finished",
            replicate=replicate,
            run_id=candidates[0]["run_id"],
            status=candidates[0]["status"],
        )
        return candidates[0]

    def record_initialization_failure(self, replicate: int, error: BaseException) -> None:
        record = {
            "replicate": replicate,
            "run_id": None,
            "path": None,
            "status": "initialization_failed",
            "compiled": False,
            "created_at": None,
            "finished_at": utc_now(),
            "error": serialize_error(error),
        }
        self._replace_run(record)
        self.events.emit(
            "replicate.failed",
            replicate=replicate,
            error=serialize_error(error),
        )

    def reconcile(self) -> None:
        before = json.dumps(self.data, ensure_ascii=False, sort_keys=True)
        observed: dict[int, dict[str, Any]] = {}
        if self.outputs_dir.exists():
            for run_dir in self.outputs_dir.glob("run_*"):
                manifest_path = run_dir / "manifest.json"
                result_path = run_dir / "result.json"
                if not manifest_path.exists() or not result_path.exists():
                    continue
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    result = json.loads(result_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                experiment = manifest.get("experiment") or {}
                replicate = experiment.get("replicate")
                if type(replicate) is not int:
                    continue
                if replicate in observed:
                    raise ValueError(f"Replicate oficial duplicada: {replicate}")
                observed[replicate] = self._run_record(run_dir, manifest, result)
        existing = {
            item["replicate"]: item
            for item in self.data.get("runs", [])
            if type(item.get("replicate")) is int
        }
        existing.update(observed)
        self.data["runs"] = [existing[key] for key in sorted(existing)]
        self._refresh_counts()
        after = json.dumps(self.data, ensure_ascii=False, sort_keys=True)
        if before != after:
            self._save()

    def finish_generation(self) -> None:
        self.reconcile()
        pending = self.pending_replicates()
        if not pending and self.data["evaluated_replicates"] == self.data["started_replicates"]:
            self.data["status"] = "evaluation_completed"
        else:
            self.data["status"] = "generation_completed" if not pending else "interrupted"
        self.data["finished_at"] = utc_now() if not pending else None
        self._save()
        self.events.emit(
            "campaign.finished" if not pending else "campaign.interrupted",
            completed_replicates=self.data["completed_replicates"],
            failed_replicates=self.data["failed_replicates"],
            pending_replicates=pending,
        )

    def mark_interrupted(self) -> None:
        self.reconcile()
        self.data["status"] = "interrupted"
        self.data["finished_at"] = None
        self._save()
        self.events.emit("campaign.interrupted", pending_replicates=self.pending_replicates())

    def refresh_evaluations(self) -> None:
        self.reconcile()
        evaluated = self.data["evaluated_replicates"]
        started = self.data["started_replicates"]
        if started and evaluated == started and not self.pending_replicates():
            self.data["status"] = "evaluation_completed"
        elif evaluated:
            self.data["status"] = "partially_evaluated"
        self._save()

    def _run_record(
        self,
        run_dir: Path,
        manifest: dict[str, Any],
        result: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "replicate": (manifest.get("experiment") or {}).get("replicate"),
            "run_id": result.get("run_id", manifest.get("run_id")),
            "path": run_dir.relative_to(self.root).as_posix(),
            "status": result.get("status"),
            "compiled": result.get("compiled", False),
            "created_at": manifest.get("created_at"),
            "finished_at": result.get("finished_at"),
            "error": result.get("error"),
        }

    def _replace_run(self, record: dict[str, Any]) -> None:
        runs = [
            item
            for item in self.data.get("runs", [])
            if item.get("replicate") != record.get("replicate")
        ]
        runs.append(record)
        self.data["runs"] = sorted(runs, key=lambda item: item["replicate"])
        self._refresh_counts()
        self._save()

    def _refresh_counts(self) -> None:
        runs = self.data.get("runs", [])
        self.data["started_replicates"] = len(runs)
        self.data["completed_replicates"] = sum(
            item.get("status") == "completed" for item in runs
        )
        self.data["failed_replicates"] = sum(
            item.get("status") != "completed" for item in runs
        )
        self.data["evaluated_replicates"] = sum(
            bool(item.get("path"))
            and (self.root / item["path"] / "evaluation" / "manual.json").exists()
            for item in runs
        )

    def _save(self) -> None:
        self.data["updated_at"] = utc_now()
        write_json_atomic(self.path, self.data)
        self._index()

    def _index(self) -> None:
        self.results_root.mkdir(parents=True, exist_ok=True)
        path = self.results_root / "campaigns.jsonl"
        record = {
            "schema_version": self.data.get("schema_version"),
            "campaign_id": self.data.get("campaign_id"),
            "path": self.root.relative_to(self.results_root).as_posix(),
            "experiment_id": self.data.get("experiment_id"),
            "condition": self.data.get("condition"),
            "scenario": self.data.get("scenario"),
            "model": self.data.get("model"),
            "provider": self.data.get("provider"),
            "inference_provider": self.data.get("inference_provider"),
            "planned_replicates": self.data.get("planned_replicates"),
            "started_replicates": self.data.get("started_replicates"),
            "completed_replicates": self.data.get("completed_replicates"),
            "failed_replicates": self.data.get("failed_replicates"),
            "evaluated_replicates": self.data.get("evaluated_replicates"),
            "status": self.data.get("status"),
            "campaign_kind": self.data.get("campaign_kind", "official"),
            "stimulus_sha256": self.data.get("stimulus_sha256"),
            "protocol_sha256": self.data.get("protocol_sha256"),
            "rubric_sha256": self.data.get("rubric_sha256"),
            "protocol_version": self.data.get("protocol_version"),
            "rubric_version": self.data.get("rubric_version"),
            "updated_at": self.data.get("updated_at"),
        }
        with path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                handle.seek(0)
                previous = None
                for line in handle:
                    try:
                        candidate = json.loads(line)
                    except ValueError:
                        continue
                    if candidate.get("campaign_id") == record["campaign_id"]:
                        previous = candidate
                if previous is not None:
                    comparable = {key: value for key, value in previous.items() if key != "revision"}
                    if comparable == record:
                        return
                    revision = previous.get("revision")
                    record["revision"] = revision + 1 if type(revision) is int else 2
                else:
                    record["revision"] = 1
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

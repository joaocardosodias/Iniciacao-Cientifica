import fcntl
import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from src.campaign import Campaign
from src.events import utc_now
from src.trace import safe_name, write_json_atomic
from src.experimental_inputs import load_yaml, sha256_file
from src.vm_environment import snapshot_environment

FUNCTIONAL_STATUSES = {
    "passed",
    "partial",
    "failed",
    "inconclusive",
    "not_run",
    "environment_error",
}

CHECK_STATUSES = {"passed", "failed", "not_checked", "not_applicable"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_run(results_root: Path, run_id: str) -> Path:
    matches = list(results_root.glob(f"*/*/*/outputs/{run_id}"))
    if not matches:
        raise FileNotFoundError(f"Run oficial nao encontrada: {run_id}")
    if len(matches) > 1:
        raise ValueError(f"Run oficial duplicada em results/: {run_id}")
    return matches[0]


def _campaign_for_run(run_dir: Path, results_root: Path) -> Campaign:
    return Campaign.load(run_dir.parent.parent / "campaign.json", results_root)


def _next_revision(handle: Any, run_id: str) -> int:
    revision = 0
    handle.seek(0)
    for line in handle:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("run_id") == run_id and type(record.get("revision")) is int:
            revision = max(revision, record["revision"])
    return revision + 1


def _copy_evidence(evidence_dir: Path, paths: list[Path]) -> list[dict[str, Any]]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for index, source in enumerate(paths, 1):
        source = source.expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(f"Evidencia nao encontrada: {source}")
        name = safe_name(source.name)
        target = evidence_dir / name
        if target.exists() and target.resolve() != source:
            target = evidence_dir / f"{index:02d}_{name}"
        if target.resolve() != source:
            shutil.copy2(source, target)
        records.append({
            "path": target.relative_to(evidence_dir.parent.parent).as_posix(),
            "bytes": target.stat().st_size,
            "sha256": _sha256(target),
        })
    return records


def record_evaluation(
    results_root: Path,
    run_id: str,
    evaluator: str,
    functional_status: str,
    environment: dict[str, Any] | None = None,
    checks: list[dict[str, str]] | None = None,
    notes: str = "",
    evidence: list[Path] | None = None,
    include_in_analysis: bool = True,
    exclusion_reason: str | None = None,
    environment_file: Path | None = None,
    component_assessments: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    evaluator = evaluator.strip()
    if not evaluator:
        raise ValueError("O avaliador nao pode ser vazio.")
    if functional_status not in FUNCTIONAL_STATUSES:
        raise ValueError(f"Status funcional invalido: {functional_status}")
    if not include_in_analysis and not (exclusion_reason or "").strip():
        raise ValueError("Uma avaliacao excluida exige justificativa.")
    normalized_checks = []
    for index, check in enumerate(checks or [], 1):
        description = str(check.get("description", "")).strip()
        status = str(check.get("status", "")).strip()
        if not description or status not in CHECK_STATUSES:
            raise ValueError(f"Criterio de avaliacao invalido na posicao {index}.")
        normalized_checks.append({
            "id": str(check.get("id") or f"check-{index:02d}"),
            "description": description,
            "status": status,
        })

    run_dir = find_run(results_root, run_id)
    campaign = _campaign_for_run(run_dir, results_root)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    evaluation_dir = run_dir / "evaluation"
    revisions_dir = evaluation_dir / "revisions"
    revisions_dir.mkdir(parents=True, exist_ok=True)
    environment_record = None
    if environment_file is not None:
        environment_record = snapshot_environment(environment_file, evaluation_dir)
    rubric_record = None
    allowed_classifications = set()
    rubric_relative = campaign.data.get("rubric_path")
    if rubric_relative:
        rubric_file = campaign.root / rubric_relative
        if not rubric_file.is_file():
            raise FileNotFoundError(f"Rubrica congelada ausente: {rubric_file}")
        rubric = load_yaml(rubric_file)
        observed_hash = sha256_file(rubric_file)
        if observed_hash != campaign.data.get("rubric_sha256"):
            raise ValueError("A rubrica congelada foi alterada.")
        rubric_record = {
            "path": rubric_relative,
            "version": rubric.get("version"),
            "sha256": observed_hash,
        }
        allowed_classifications = set(rubric.get("component_classifications") or [])
    normalized_assessments = []
    for assessment in component_assessments or []:
        name = str(assessment.get("component", "")).strip()
        classification = str(assessment.get("classification", "")).strip()
        if not name or classification not in allowed_classifications:
            raise ValueError(f"Classificacao de componente invalida: {name or '<vazio>'}")
        normalized_assessments.append({"component": name, "classification": classification})
    index_path = campaign.root / "evaluations.jsonl"
    with index_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            revision = _next_revision(handle, run_id)
            evidence_records = _copy_evidence(
                evaluation_dir / "evidence",
                [Path(path) for path in evidence or []],
            )
            evaluated_at = utc_now()
            experiment = manifest.get("experiment") or {}
            intervention = manifest.get("intervention") or {}
            if result.get("compiled"):
                compilation_status = "passed"
            elif result.get("status") == "compile_failed":
                compilation_status = "failed"
            else:
                compilation_status = "not_run"
            manual = {
                "schema_version": "1.0",
                "evaluation_id": f"eval_{uuid.uuid4().hex[:12]}",
                "revision": revision,
                "run_id": run_id,
                "experiment": experiment,
                "intervention": intervention,
                "evaluator": evaluator,
                "evaluated_at": evaluated_at,
                "environment": environment_record or environment or {},
                "rubric": rubric_record,
                "outcome": {
                    "generation_status": result.get("status"),
                    "compilation_status": compilation_status,
                    "functional_status": functional_status,
                },
                "checks": normalized_checks,
                "component_assessments": normalized_assessments,
                "notes": notes.strip(),
                "evidence": evidence_records,
                "include_in_analysis": include_in_analysis,
                "exclusion_reason": (
                    None if include_in_analysis else exclusion_reason.strip()
                ),
            }
            write_json_atomic(revisions_dir / f"revision_{revision:04d}.json", manual)
            write_json_atomic(evaluation_dir / "manual.json", manual)
            summary = {
                "schema_version": manual["schema_version"],
                "evaluation_id": manual["evaluation_id"],
                "run_id": run_id,
                "experiment_id": experiment.get("id"),
                "condition": experiment.get("condition"),
                "context_mode": intervention.get("context_mode"),
                "replicate": experiment.get("replicate"),
                "pipeline_status": result.get("status"),
                "compiled": result.get("compiled", False),
                "functional_status": functional_status,
                "include_in_analysis": include_in_analysis,
                "exclusion_reason": manual["exclusion_reason"],
                "evaluated_at": evaluated_at,
                "environment_sha256": (environment_record or {}).get("sha256"),
                "rubric_sha256": (rubric_record or {}).get("sha256"),
                "revision": revision,
            }
            handle.seek(0, os.SEEK_END)
            handle.write(json.dumps(summary, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    campaign.events.emit(
        "evaluation.recorded",
        run_id=run_id,
        replicate=experiment.get("replicate"),
        revision=revision,
        functional_status=functional_status,
    )
    campaign.refresh_evaluations()
    return manual


def pending_runs(campaign: Campaign) -> list[dict[str, Any]]:
    campaign.reconcile()
    pending = []
    for record in campaign.data.get("runs", []):
        relative = record.get("path")
        if not relative:
            continue
        manual = campaign.root / relative / "evaluation" / "manual.json"
        if not manual.exists():
            pending.append(record)
    return pending

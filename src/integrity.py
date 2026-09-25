import hashlib
import json
from pathlib import Path
from typing import Any

from src.events import utc_now
from src.trace import write_json_atomic


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_seal(
    root: Path,
    filename: str,
    scope: str,
    excluded_prefixes: tuple[str, ...] = (),
) -> dict[str, Any]:
    records = []
    excluded = {filename, ".DS_Store"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        relative = path.relative_to(root).as_posix()
        if any(relative.startswith(prefix) for prefix in excluded_prefixes):
            continue
        records.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
    combined = hashlib.sha256(
        json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    seal = {
        "schema_version": "1.0",
        "scope": scope,
        "created_at": utc_now(),
        "file_count": len(records),
        "combined_sha256": combined,
        "excluded_prefixes": list(excluded_prefixes),
        "files": records,
    }
    write_json_atomic(root / filename, seal)
    return seal


def verify_seal(root: Path, filename: str) -> dict[str, Any]:
    seal_path = root / filename
    if not seal_path.is_file():
        return {"valid": False, "seal": str(seal_path), "error": "seal_missing"}
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    expected = {item["path"]: item for item in seal.get("files", [])}
    excluded_prefixes = tuple(seal.get("excluded_prefixes") or [])
    observed = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in {filename, ".DS_Store"}:
            continue
        relative = path.relative_to(root).as_posix()
        if any(relative.startswith(prefix) for prefix in excluded_prefixes):
            continue
        observed[relative] = {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    modified = sorted(
        path for path in set(expected) & set(observed)
        if expected[path].get("bytes") != observed[path]["bytes"]
        or expected[path].get("sha256") != observed[path]["sha256"]
    )
    return {
        "valid": not missing and not unexpected and not modified,
        "seal": str(seal_path),
        "scope": seal.get("scope"),
        "combined_sha256": seal.get("combined_sha256"),
        "missing": missing,
        "unexpected": unexpected,
        "modified": modified,
    }


def seal_run(run_dir: Path) -> dict[str, Any]:
    return create_seal(run_dir, "run_seal.json", "generation_run", ("evaluation/",))


def seal_campaign(campaign_root: Path) -> dict[str, Any]:
    return create_seal(campaign_root, "campaign_seal.json", "campaign")

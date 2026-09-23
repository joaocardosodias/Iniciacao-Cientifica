import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

SOURCE_PATTERNS = [
    "pipeline.py",
    "src/*.py",
    "requirements.txt",
    ".env.example",
    "scenarios/*.py",
    "scripts/*.py",
    "opencode.json",
]

SECRET_NAMES = {".env"}
SECRET_SUFFIXES = {".key", ".pem", ".p12", ".pfx"}
SECRET_NAME_PARTS = ("secret", "credential", "password", "token", "master.key")

MAX_STORED_BYTES = 1_000_000


def _is_secret(relative: str) -> bool:
    name = relative.rsplit("/", 1)[-1]
    lowered = name.lower()
    if lowered in SECRET_NAMES or lowered.startswith(".env.") or lowered.endswith(".env"):
        return True
    if any(lowered.endswith(suffix) for suffix in SECRET_SUFFIXES):
        return True
    return any(part in lowered for part in SECRET_NAME_PARTS)


def find_repo_root(cwd: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(cwd),
            capture_output=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    root = result.stdout.decode("utf-8", errors="replace").strip()
    return Path(root) if root else None


def _git_text(args: list[str], root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            timeout=15,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.decode("utf-8", errors="replace")


def _git_line(args: list[str], root: Path) -> str | None:
    text = _git_text(args, root)
    if text is None:
        return None
    return text.strip() or None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_excluded(path: Path, exclude_dirs: list[Path]) -> bool:
    absolute = path.absolute()
    return any(
        absolute == base.absolute() or base.absolute() in absolute.parents
        for base in exclude_dirs
    )


def _untracked_files(root: Path, exclude_dirs: list[Path], store_dir: Path) -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=str(root),
            capture_output=True,
            timeout=15,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return {"files": [], "error": "git_ls_files_failed"}
    entries = []
    resolved_root = root.resolve()
    for raw in result.stdout.split(b"\0"):
        if not raw or raw.startswith(b"../") or b"/../" in raw:
            continue
        relative = raw.decode("utf-8", errors="replace")
        path = root / relative
        if _is_excluded(path, exclude_dirs):
            continue
        if path.is_symlink():
            entries.append({"path": relative, "bytes": None, "sha256": None,
                            "skipped": "symlink"})
            continue
        if not path.resolve().is_relative_to(resolved_root):
            entries.append({"path": relative, "bytes": None, "sha256": None,
                            "skipped": "outside_repository"})
            continue
        if _is_secret(relative):
            entries.append({"path": relative, "bytes": None, "sha256": None,
                            "skipped": "possible_secrets"})
            continue
        try:
            size = path.stat().st_size
        except OSError:
            entries.append({"path": relative, "bytes": None, "sha256": None,
                            "skipped": "unreadable"})
            continue
        if size > MAX_STORED_BYTES:
            entries.append({"path": relative, "bytes": size, "sha256": None,
                            "skipped": "too_large"})
            continue
        try:
            content = path.read_bytes()
        except OSError:
            entries.append({"path": relative, "bytes": None, "sha256": None,
                            "skipped": "unreadable"})
            continue
        target = store_dir / relative
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        except OSError:
            entries.append({"path": relative, "bytes": size, "sha256": None,
                            "skipped": "unreadable"})
            continue
        entries.append({"path": relative, "bytes": size,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "stored": f"untracked/{relative}"})
    entries.sort(key=lambda item: item["path"])
    stored = sum(1 for item in entries if "stored" in item)
    return {"files": entries, "stored_count": stored}


def _source_hashes(root: Path) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    resolved_root = root.resolve()
    for pattern in SOURCE_PATTERNS:
        for path in sorted(root.glob(pattern)):
            if path.is_symlink() or not path.resolve().is_relative_to(resolved_root) or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            try:
                files[relative] = {"sha256": _sha256_file(path),
                                   "bytes": path.stat().st_size}
            except OSError:
                continue
    combined = hashlib.sha256(
        "\n".join(f"{name}:{info['sha256']}" for name, info in sorted(files.items())).encode("utf-8")
    ).hexdigest() if files else None
    return {"root": str(root), "files": files, "combined_sha256": combined}


def _write_json(path: Path, content: Any) -> None:
    path.write_text(
        json.dumps(content, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )


def collect(root: Path | None, out_dir: Path, exclude_dirs: list[Path] | None = None) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    excluded = exclude_dirs or []
    files = {
        "diff": "provenance/git.diff",
        "status": "provenance/git_status.txt",
        "untracked": "provenance/untracked_files.json",
        "source_hashes": "provenance/source_hashes.json",
    }
    if root is None:
        (out_dir / "git.diff").write_text("", encoding="utf-8")
        (out_dir / "git_status.txt").write_text("", encoding="utf-8")
        _write_json(out_dir / "untracked_files.json", {"files": [], "error": "not_a_git_repo"})
        sources = _source_hashes(Path.cwd())
        _write_json(out_dir / "source_hashes.json", sources)
        return {
            "commit": None,
            "branch": None,
            "dirty": None,
            "files": files,
            "source_hashes": {name: info["sha256"] for name, info in sources["files"].items()},
            "source_combined_sha256": sources["combined_sha256"],
            "untracked_count": 0,
            "untracked_stored_count": 0,
        }

    status = _git_text(["status", "--porcelain=v1", "--branch"], root) or ""
    (out_dir / "git_status.txt").write_text(status, encoding="utf-8")
    diff = _git_text(["diff", "--binary", "HEAD", "--"], root) or ""
    (out_dir / "git.diff").write_text(diff, encoding="utf-8")
    untracked = _untracked_files(root, excluded, out_dir / "untracked")
    _write_json(out_dir / "untracked_files.json", untracked)
    sources = _source_hashes(root)
    _write_json(out_dir / "source_hashes.json", sources)
    dirty = any(line and not line.startswith("##") for line in status.splitlines())
    return {
        "commit": _git_line(["rev-parse", "HEAD"], root),
        "branch": _git_line(["rev-parse", "--abbrev-ref", "HEAD"], root),
        "dirty": dirty,
        "files": files,
        "source_hashes": {name: info["sha256"] for name, info in sources["files"].items()},
        "source_combined_sha256": sources["combined_sha256"],
        "untracked_count": len(untracked["files"]),
        "untracked_stored_count": untracked.get("stored_count", 0),
    }

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_environment(source: Path, evaluation_dir: Path) -> dict[str, Any]:
    source = source.expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"Descricao do ambiente nao encontrada: {source}")
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("A descricao do ambiente deve ser um objeto JSON.")
    if data.get("schema_version") != "2.0":
        raise ValueError("A descricao da VM deve usar schema_version 2.0.")
    required = {"schema_version", "vm", "containers", "lifecycle", "network"}
    missing = sorted(required - set(data))
    if missing:
        raise ValueError(f"Campos ausentes na descricao do ambiente: {', '.join(missing)}")
    target = evaluation_dir / "environment.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    if source != target.resolve():
        shutil.copy2(source, target)
    return {
        "path": "evaluation/environment.json",
        "sha256": sha256_file(target),
        "data": data,
    }

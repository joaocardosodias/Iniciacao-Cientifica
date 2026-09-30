from pathlib import Path


def run_root(path: Path) -> Path:
    current = path
    while current != current.parent and not current.name.startswith("run_"):
        current = current.parent
    return current


def iter_run_dirs(root: Path):
    for candidate in sorted(root.glob("run_*")):
        if (candidate / "manifest.json").exists() or (candidate / "result.json").exists():
            yield candidate
            continue
        children = [child for child in sorted(candidate.glob("*")) if child.is_dir()]
        if children:
            for child in children:
                yield child
        else:
            yield candidate

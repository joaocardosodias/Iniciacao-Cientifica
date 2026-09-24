import importlib.metadata
import json
import locale
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


def _version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    lines = result.stdout.strip().splitlines()
    return lines[0].strip() if lines else None


def _libcurl_version() -> str | None:
    version = _version(["pkg-config", "--modversion", "libcurl"])
    if version:
        return version
    curl = _version(["curl", "--version"])
    if curl:
        match = re.search(r"\blibcurl/([^\s]+)", curl)
        if match:
            return match.group(1)
    return None


def _cpu_model() -> str | None:
    try:
        with Path("/proc/cpuinfo").open(encoding="utf-8") as handle:
            for line in handle:
                key, separator, value = line.partition(":")
                if separator and key.strip().lower() in {"model name", "hardware", "cpu model"}:
                    return value.strip()
    except OSError:
        pass
    return platform.processor() or None


def _packages() -> list[dict[str, str]]:
    packages = []
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name")
        if name:
            packages.append({"name": name, "version": distribution.version})
    return sorted(packages, key=lambda item: (item["name"].casefold(), item["version"]))


def collect(out_dir: Path) -> dict[str, Any]:
    try:
        language, encoding = locale.getlocale()
    except (ValueError, locale.Error):
        language, encoding = None, None
    now = datetime.now().astimezone()
    offset = now.utcoffset()
    tools = {
        "gcc": _version(["gcc", "--version"]),
        "opencode": _version(["opencode", "--version"]),
        "openssl": _version(["openssl", "version"]),
        "libcurl": _libcurl_version(),
    }
    environment = {
        "scope": "pipeline_host",
        "python": {
            "version": sys.version,
            "executable": sys.executable,
            "implementation": sys.implementation.name,
        },
        "os": {
            "name": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "platform": platform.platform(),
        },
        "cpu": {
            "model": _cpu_model(),
            "logical_count": os.cpu_count(),
        },
        "locale": {
            "language": language,
            "encoding": encoding,
            "preferred_encoding": locale.getpreferredencoding(False),
        },
        "timezone": {
            "name": now.tzname(),
            "utc_offset_seconds": int(offset.total_seconds()) if offset is not None else None,
            "standard_and_daylight_names": list(time.tzname),
        },
        "tools": tools,
    }
    packages = _packages()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "environment.json").write_text(
        json.dumps(environment, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    (out_dir / "python_packages.json").write_text(
        json.dumps(packages, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return {
        "python": platform.python_version(),
        "executable": sys.executable,
        "platform": environment["os"]["platform"],
        "architecture": environment["os"]["architecture"],
        "cpu": environment["cpu"]["model"],
        "locale": environment["locale"]["language"],
        "timezone": environment["timezone"]["name"],
        "working_directory": str(Path.cwd()),
        "commands": tools,
        "environment_path": "provenance/environment.json",
        "packages_path": "provenance/python_packages.json",
        "package_count": len(packages),
    }

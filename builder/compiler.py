import os
import shutil
import subprocess
from pathlib import Path

COMPILE_TIMEOUT = 1200

DOCKER_IMAGE = os.environ.get("IC_DOCKER_IMAGE", "dockcross/windows-static-x64")
DOCKER_CC = os.environ.get("IC_DOCKER_CC", "x86_64-w64-mingw32.static-gcc")
LOCAL_MINGW_CANDIDATES = ("x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc")

_LINK_FLAGS = {
    "winsock2.h": "-lws2_32",
    "ws2tcpip.h": "-lws2_32",
    "bcrypt.h": "-lbcrypt",
    "winhttp.h": "-lwinhttp",
    "wininet.h": "-lwininet",
    "shlwapi.h": "-lshlwapi",
    "iphlpapi.h": "-liphlpapi",
    "psapi.h": "-lpsapi",
    "userenv.h": "-luserenv",
    "crypt32.h": "-lcrypt32",
}

BASE_LINK_FLAGS = ("-lws2_32",)


def _override() -> str | None:
    return os.environ.get("IC_CC") or os.environ.get("MINGW_CC")


def _local_compiler() -> str:
    override = _override()
    if override:
        return override
    for candidate in LOCAL_MINGW_CANDIDATES:
        if shutil.which(candidate):
            return candidate
    raise RuntimeError(
        "Nenhum compilador encontrado. Instale mingw-w64-gcc ou defina IC_CC."
    )


def _use_docker() -> bool:
    return _override() is None and shutil.which("docker") is not None


def _link_flags(includes: list[str]) -> str:
    flags = list(BASE_LINK_FLAGS)
    for include in includes:
        for header, header_flags in _LINK_FLAGS.items():
            if header in include:
                for flag in header_flags.split():
                    if flag not in flags:
                        flags.append(flag)
    return " ".join(flags)


def compile_command(module_files: list[Path], includes: list[str]) -> list[str]:
    compiler = DOCKER_CC if _use_docker() else _local_compiler()
    return [
        compiler, "-O2", "-Wall", "-std=c11", "-D_WIN32_WINNT=0x0601", "-I.",
        "-o", "output.exe", "main.c",
        *[path.name for path in module_files],
        *_link_flags(includes).split(),
    ]


def run_gcc(
    assembly_dir: Path,
    module_files: list[Path],
    includes: list[str],
) -> subprocess.CompletedProcess:
    inner = compile_command(module_files, includes)
    if _use_docker():
        work = str(assembly_dir.resolve())
        argv = [
            "docker", "run", "--rm",
            "-v", f"{work}:/work", "-w", "/work",
            DOCKER_IMAGE,
            *inner,
        ]
        cwd = None
    else:
        argv = inner
        cwd = str(assembly_dir)
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=COMPILE_TIMEOUT,
        cwd=cwd,
    )

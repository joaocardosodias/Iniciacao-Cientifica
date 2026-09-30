import subprocess
from pathlib import Path

COMPILE_TIMEOUT = 600

_LINK_FLAGS = {
    "curl/curl.h": "-lcurl",
    "curl/urlapi.h": "-lcurl",
    "openssl/evp.h": "-lssl -lcrypto",
    "openssl/rand.h": "-lssl -lcrypto",
    "openssl/crypto.h": "-lssl -lcrypto",
    "json-c/json.h": "-ljson-c",
    "pthread.h": "-lpthread",
    "math.h": "-lm",
}


def _link_flags(includes: list[str]) -> str:
    flags = ["-lssl", "-lcrypto", "-lcurl"]
    for include in includes:
        for header, header_flags in _LINK_FLAGS.items():
            if header in include:
                for flag in header_flags.split():
                    if flag not in flags:
                        flags.append(flag)
    return " ".join(flags)


def compile_command(module_files: list[Path], includes: list[str]) -> list[str]:
    return [
        "gcc", "-O2", "-Wall", "-Wno-discarded-qualifiers", "-std=c11",
        "-D_GNU_SOURCE", "-I.", "-o", "output", "main.c",
        *[path.name for path in module_files],
        *_link_flags(includes).split(),
    ]


def run_gcc(
    assembly_dir: Path,
    module_files: list[Path],
    includes: list[str],
) -> subprocess.CompletedProcess:
    return subprocess.run(
        compile_command(module_files, includes),
        capture_output=True,
        text=True,
        timeout=COMPILE_TIMEOUT,
        cwd=str(assembly_dir),
    )

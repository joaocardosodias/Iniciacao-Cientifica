import logging
import re
import subprocess
import time
from pathlib import Path

from src.trace import utc_now, write_json_atomic


log = logging.getLogger("pipeline.assembler")

ASSEMBLER_TIMEOUT = 600

_CONTROL_KEYWORDS = {
    "if", "for", "while", "switch", "do", "else", "return", "sizeof",
    "case", "default", "goto", "break", "continue", "typedef", "struct",
    "union", "enum", "main",
}

_TOP_LEVEL_CANDIDATE = re.compile(
    r"^(?P<decl>.*?)\b(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)$"
)

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

_STANDARD_HEADERS = (
    "errno.h", "fcntl.h", "limits.h", "signal.h", "stdarg.h", "stdbool.h",
    "stddef.h", "stdint.h", "stdio.h", "stdlib.h", "string.h", "time.h",
    "unistd.h", "ctype.h", "dirent.h", "poll.h", "pthread.h", "math.h",
    "sys/types.h", "sys/stat.h", "sys/time.h", "sys/wait.h", "sys/mman.h",
    "sys/file.h", "sys/ioctl.h", "sys/socket.h", "sys/select.h",
    "netinet/in.h", "arpa/inet.h", "netdb.h", "pwd.h", "grp.h", "utime.h",
    "syslog.h", "wchar.h",
)

_GNU_SOURCE_DEFINE = re.compile(r"(?m)^[ \t]*#\s*define\s+_GNU_SOURCE\b[^\n]*\n")

def _link_flags(includes: list[str]) -> str:
    flags = ["-lssl", "-lcrypto", "-lcurl"]
    for include in includes:
        for header, header_flags in _LINK_FLAGS.items():
            if header in include:
                for flag in header_flags.split():
                    if flag not in flags:
                        flags.append(flag)
    return " ".join(flags)


def _with_standard_prelude(code: str) -> str:
    prelude = "".join(f"#include <{header}>\n" for header in _STANDARD_HEADERS)
    match = _GNU_SOURCE_DEFINE.search(code)
    if match:
        return code[:match.end()] + prelude + code[match.end():]
    return "#define _GNU_SOURCE\n" + prelude + code


def _strip_comments(code: str) -> str:
    result: list[str] = []
    index = 0
    length = len(code)
    while index < length:
        char = code[index]
        following = code[index + 1] if index + 1 < length else ""
        if char in {'"', "'"}:
            terminator = char
            result.append(char)
            index += 1
            while index < length:
                result.append(code[index])
                if code[index] == "\\":
                    index += 1
                    if index < length:
                        result.append(code[index])
                    index += 1
                    continue
                if code[index] == terminator:
                    index += 1
                    break
                index += 1
            continue
        if char == "/" and following == "/":
            end = code.find("\n", index)
            index = length if end == -1 else end
            result.append(" ")
            continue
        if char == "/" and following == "*":
            end = code.find("*/", index + 2)
            index = length if end == -1 else end + 2
            result.append(" ")
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _strip_test_blocks(code: str) -> str:
    pattern = re.compile(
        r"#\s*if(?:n?def)?\s+\w*_TEST\b.*?#\s*endif\b",
        re.DOTALL,
    )
    return pattern.sub("\n", code)


def _iter_top_level_declarations(code: str):
    depth = 0
    buffer: list[str] = []
    index = 0
    length = len(code)
    while index < length:
        char = code[index]
        following = code[index + 1] if index + 1 < length else ""
        if char == "/" and following == "/":
            end = code.find("\n", index)
            index = length if end == -1 else end
            continue
        if char == "/" and following == "*":
            end = code.find("*/", index + 2)
            index = length if end == -1 else end + 2
            continue
        if char in {'"', "'"}:
            terminator = char
            index += 1
            while index < length:
                if code[index] == "\\":
                    index += 2
                    continue
                if code[index] == terminator:
                    index += 1
                    break
                index += 1
            if depth == 0:
                buffer.append(" ")
            continue
        if char == "#" and depth == 0:
            end = code.find("\n", index)
            index = length if end == -1 else end + 1
            continue
        if char == "{":
            if depth == 0:
                yield "".join(buffer)
                buffer = []
            depth += 1
            index += 1
            continue
        if char == "}":
            depth = max(depth - 1, 0)
            if depth == 0:
                buffer = []
            index += 1
            continue
        if char == ";" and depth == 0:
            buffer = []
            index += 1
            continue
        if depth == 0:
            buffer.append(char)
        index += 1


def _remove_main_definition(code: str) -> str:
    while True:
        match = re.search(r"\bmain\s*\(", code)
        if not match:
            return code
        brace = code.find("{", match.end())
        if brace == -1:
            return code
        depth = 0
        index = brace
        state: str | None = None
        while index < len(code):
            char = code[index]
            if state == "string":
                if char == "\\":
                    index += 2
                    continue
                if char == '"':
                    state = None
            elif state == "char":
                if char == "\\":
                    index += 2
                    continue
                if char == "'":
                    state = None
            elif char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        if depth != 0:
            return code
        start = max(code.rfind(";", 0, match.start()), code.rfind("}", 0, match.start())) + 1
        code = code[:start] + code[index + 1:]


def _extract_signatures(code: str) -> list[str]:
    cleaned = _strip_test_blocks(_strip_comments(code))
    signatures: list[str] = []
    seen: set[str] = set()
    for candidate in _iter_top_level_declarations(cleaned):
        collapsed = " ".join(candidate.split())
        match = _TOP_LEVEL_CANDIDATE.match(collapsed)
        if not match:
            continue
        name = match.group("name")
        if name in _CONTROL_KEYWORDS:
            continue
        declaration_tokens = match.group("decl").split()
        if "static" in declaration_tokens or "=" in declaration_tokens:
            continue
        if name in seen:
            continue
        seen.add(name)
        declaration = re.sub(r"\(\s+", "(", collapsed)
        declaration = re.sub(r"\s+\)", ")", declaration)
        signatures.append(declaration + ";")
    return signatures


def _extract_includes(code: str) -> list[str]:
    return list({
        match.group().strip()
        for match in re.finditer(r'^\s*#\s*include\s*[<"][^>"]+[>"]', code, re.MULTILINE)
    })


def _prepare_module_source(code: str) -> str:
    return _remove_main_definition(_strip_test_blocks(_strip_comments(code)))


class Assembler:
    def __init__(self):
        self.last_status = "pending"
        self.last_mode = "deterministic"

    def assemble(
        self,
        modules: list[tuple[str, str]],
        run_dir: Path,
        config_header: str | None = None,
        main_source: str | None = None,
    ) -> tuple[Path | None, bool]:
        started_at = utc_now()
        started = time.perf_counter()
        run_dir.mkdir(parents=True, exist_ok=True)
        modules_dir = run_dir / "modules"
        modules_dir.mkdir(exist_ok=True)
        assembly_dir = run_dir / "assembly"
        assembly_dir.mkdir(exist_ok=True)
        all_includes: list[str] = []
        all_signatures: list[str] = []
        module_files: list[Path] = []

        for index, (name, code) in enumerate(modules, 1):
            source = modules_dir / f"{name}.c"
            if not source.exists() or source.stat().st_size == 0:
                source.write_text(code, encoding="utf-8")
                log.info("  [Assembler] %s.c escrito", name)
            else:
                log.info("  [Assembler] %s.c preservado (%s bytes)", name, source.stat().st_size)
            source_code = source.read_text(encoding="utf-8")
            prepared = _with_standard_prelude(_prepare_module_source(source_code))
            module_file = assembly_dir / f"module_{index:02d}.c"
            module_file.write_text(prepared, encoding="utf-8")
            module_files.append(module_file)
            all_includes.extend(_extract_includes(prepared))
            all_signatures.extend(_extract_signatures(source_code))

        includes = list(dict.fromkeys(
            sorted(all_includes, key=lambda value: ('"' in value, value.lower()))
        ))

        if config_header:
            (assembly_dir / "config.h").write_text(config_header, encoding="utf-8")

        if not all_signatures:
            self.last_status = "no_linkable_functions"
            self._write_result(
                assembly_dir,
                started_at,
                started,
                signatures_found=0,
                main_c_exists=False,
                binary_exists=False,
            )
            log.error("  [Assembler] nenhuma funcao de linkage externo encontrada")
            return None, False

        if not main_source:
            self.last_status = "no_main_source"
            self._write_result(
                assembly_dir,
                started_at,
                started,
                signatures_found=len(all_signatures),
                main_c_exists=False,
                binary_exists=False,
            )
            log.error("  [Assembler] main.c deterministico ausente")
            return None, False

        main_c = assembly_dir / "main.c"
        main_c.write_text(main_source, encoding="utf-8")
        binary = assembly_dir / "output"
        binary.unlink(missing_ok=True)
        command = self._compile_command(module_files, includes)
        log.info("  [Assembler] compilando main.c em %s", assembly_dir)
        compile_result = self._run_gcc(assembly_dir, module_files, includes)
        (assembly_dir / "stdout.log").write_text(compile_result.stdout or "", encoding="utf-8")
        (assembly_dir / "stderr.log").write_text(compile_result.stderr or "", encoding="utf-8")
        compiled = compile_result.returncode == 0 and binary.exists()
        self.last_status = "completed" if compiled else "compile_failed"
        self._write_result(
            assembly_dir,
            started_at,
            started,
            signatures_found=len(all_signatures),
            main_c_exists=True,
            binary_exists=compiled,
            return_code=compile_result.returncode,
            compile_command=command,
        )
        if compiled:
            log.info("  [Assembler] binario: %s", binary)
        else:
            log.warning("  [Assembler] compilacao falhou; nenhum reparo sera tentado")
        return main_c, compiled

    def _write_result(
        self,
        assembly_dir: Path,
        started_at: str,
        started: float,
        **data,
    ) -> None:
        write_json_atomic(assembly_dir / "result.json", {
            "status": self.last_status,
            "mode": self.last_mode,
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_seconds": round(time.perf_counter() - started, 6),
            "compiler_stdout": "stdout.log" if (assembly_dir / "stdout.log").exists() else None,
            "compiler_stderr": "stderr.log" if (assembly_dir / "stderr.log").exists() else None,
            **data,
        })

    def _compile_command(self, module_files: list[Path], includes: list[str]) -> list[str]:
        return [
            "gcc", "-O2", "-Wall", "-Wno-discarded-qualifiers", "-std=c11",
            "-D_GNU_SOURCE", "-I.", "-o", "output", "main.c",
            *[path.name for path in module_files],
            *_link_flags(includes).split(),
        ]

    def _run_gcc(
        self,
        assembly_dir: Path,
        module_files: list[Path],
        includes: list[str],
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            self._compile_command(module_files, includes),
            capture_output=True,
            text=True,
            timeout=ASSEMBLER_TIMEOUT,
            cwd=str(assembly_dir),
        )

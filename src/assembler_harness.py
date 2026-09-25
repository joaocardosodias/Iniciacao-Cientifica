import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path

from src.trace import utc_now

log = logging.getLogger("pipeline.assembler_harness")

ASSEMBLER_TIMEOUT = 600
MAX_RETRIES = 3


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


def _link_flags(includes: list[str]) -> str:
    flags = ["-lssl", "-lcrypto", "-lcurl"]
    for include in includes:
        for header, header_flags in _LINK_FLAGS.items():
            if header in include:
                for flag in header_flags.split():
                    if flag not in flags:
                        flags.append(flag)
    return " ".join(flags)

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


def _summarize_opencode_events(content: str) -> dict:
    summary = {
        "events": 0,
        "unreadable_lines": 0,
        "sessions": [],
        "steps": 0,
        "tool_calls": {},
        "tokens": {"input": 0, "output": 0, "reasoning": 0, "total": 0},
        "cost": 0.0,
    }
    sessions = set()
    for line in content.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            summary["unreadable_lines"] += 1
            continue
        if not isinstance(event, dict):
            summary["unreadable_lines"] += 1
            continue
        summary["events"] += 1
        session_id = event.get("sessionID")
        if isinstance(session_id, str):
            sessions.add(session_id)
        event_type = event.get("type")
        part = event.get("part") or {}
        if event_type == "tool_use":
            tool = part.get("tool")
            if isinstance(tool, str):
                summary["tool_calls"][tool] = summary["tool_calls"].get(tool, 0) + 1
        if event_type == "step_finish":
            summary["steps"] += 1
            tokens = part.get("tokens") or {}
            for key in ("input", "output", "reasoning", "total"):
                value = tokens.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    summary["tokens"][key] += value
            cost = part.get("cost")
            if isinstance(cost, (int, float)) and not isinstance(cost, bool):
                summary["cost"] += cost
    summary["sessions"] = sorted(sessions)
    summary["cost"] = round(summary["cost"], 12)
    return summary


def _with_standard_prelude(code: str) -> str:
    prelude = "".join(f"#include <{header}>\n" for header in _STANDARD_HEADERS)
    match = _GNU_SOURCE_DEFINE.search(code)
    if match:
        return code[:match.end()] + prelude + code[match.end():]
    return "#define _GNU_SOURCE\n" + prelude + code

_TYPE_DEFINITION = re.compile(
    r"(?m)^(?:"
    r"(?:typedef\s+)?(?:struct|union|enum)\b[^;{}]*\{[^{}]*\}\s*(?:[A-Za-z_]\w*)?\s*;"
    r"|typedef\b[^;{}]*;"
    r")"
)


def _strip_comments(code: str) -> str:
    result: list[str] = []
    index = 0
    length = len(code)
    while index < length:
        char = code[index]
        following = code[index + 1] if index + 1 < length else ""
        if char == '"' or char == "'":
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
        if char == '"' or char == "'":
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
    """
    Extrai assinaturas de funções com linkage externo.
    Ignora static, main, palavras-chave de controle e blocos de teste.
    """
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
        m.group().strip()
        for m in re.finditer(r'^\s*#\s*include\s*[<"][^>"]+[>"]', code, re.MULTILINE)
    })


def _extract_type_definitions(code: str) -> list[str]:
    cleaned = _strip_test_blocks(_strip_comments(code))
    definitions: list[str] = []
    seen: set[str] = set()
    for match in _TYPE_DEFINITION.finditer(cleaned):
        definition = " ".join(match.group().split())
        if definition not in seen:
            seen.add(definition)
            definitions.append(definition)
    return definitions


def _prepare_module_source(code: str) -> str:
    return _remove_main_definition(_strip_test_blocks(_strip_comments(code)))


class AssemblerHarness:

    def __init__(self, model: str):
        self.model = model
        self.last_status = "pending"
        self.last_mode = "pending"

    def assemble(
        self,
        modules: list[tuple[str, str]],
        run_dir: Path,
        config_header: str | None = None,
        main_source: str | None = None,
    ) -> tuple[Path | None, bool]:
        run_dir.mkdir(parents=True, exist_ok=True)

        modules_dir = run_dir / "modules"
        modules_dir.mkdir(exist_ok=True)

        assembly_dir = run_dir / "assembly"
        assembly_dir.mkdir(exist_ok=True)

        # Salva os .c completos em modules/ e em assembly/ para compilação
        # O agente recebe apenas as assinaturas, não o código completo
        all_includes: list[str] = []
        all_signatures: list[str] = []
        all_types: list[str] = []
        module_files: list[Path] = []

        for idx, (name, code) in enumerate(modules, 1):
            # Salva em modules/ (rastreabilidade)
            f = modules_dir / f"{name}.c"
            if not f.exists() or f.stat().st_size == 0:
                f.write_text(code, encoding="utf-8")
                log.info(f"  [AssemblerHarness] {name}.c escrito via fallback")
            else:
                log.info(f"  [AssemblerHarness] {name}.c já existe ({f.stat().st_size} bytes)")

            # Copia para assembly/ sem main, sem testes e sem comentários
            src_code = f.read_text(encoding="utf-8")
            prepared = _with_standard_prelude(_prepare_module_source(src_code))
            obfuscated = f"module_{idx:02d}.c"
            (assembly_dir / obfuscated).write_text(prepared, encoding="utf-8")
            module_files.append(assembly_dir / obfuscated)

            # Extrai apenas includes e assinaturas de linkage externo
            all_includes.extend(_extract_includes(prepared))
            all_signatures.extend(_extract_signatures(src_code))
            all_types.extend(_extract_type_definitions(src_code))

        # Deduplica includes
        seen: set[str] = set()
        deduped_includes = []
        for inc in sorted(all_includes, key=lambda x: ('"' in x, x.lower())):
            if inc not in seen:
                seen.add(inc)
                deduped_includes.append(inc)

        seen_types: set[str] = set()
        deduped_types = []
        for type_definition in all_types:
            if type_definition not in seen_types:
                seen_types.add(type_definition)
                deduped_types.append(type_definition)

        # Config temporário sem MCPs
        tmp_cfg = assembly_dir / "opencode.json"
        tmp_cfg.write_text(json.dumps({"$schema": "https://opencode.ai/config.json", "mcp": {}}))

        task = self._build_task(module_files, deduped_includes, all_signatures, deduped_types)
        (assembly_dir / "task.txt").write_text(task, encoding="utf-8")

        if not all_signatures:
            self.last_status = "no_linkable_functions"
            self.last_mode = "skipped"
            log.error("  [AssemblerHarness] nenhuma funcao de linkage externo encontrada — sessao nao iniciada")
            (assembly_dir / "result.json").write_text(
                json.dumps({
                    "status": self.last_status,
                    "model": self.model,
                    "finished_at": utc_now(),
                    "signatures_found": 0,
                }, indent=2, ensure_ascii=False, sort_keys=True),
                encoding="utf-8",
            )
            return None, False

        if config_header:
            (assembly_dir / "config.h").write_text(config_header, encoding="utf-8")

        if main_source:
            self.last_mode = "deterministic"
            (assembly_dir / "main.c").write_text(main_source, encoding="utf-8")
            log.info(f"  [AssemblerHarness] compilando main.c determinístico em {assembly_dir}")
            compile_result = self._run_gcc(assembly_dir, module_files, deduped_includes)
            (assembly_dir / "stdout.log").write_text(compile_result.stdout or "", encoding="utf-8")
            (assembly_dir / "stderr.log").write_text(compile_result.stderr or "", encoding="utf-8")
            binary = assembly_dir / "output"
            if binary.exists():
                self.last_status = "completed"
                (assembly_dir / "result.json").write_text(
                    json.dumps({
                        "status": "completed",
                        "model": self.model,
                        "mode": "deterministic",
                        "finished_at": utc_now(),
                        "return_code": compile_result.returncode,
                        "signatures_found": len(all_signatures),
                        "main_c_exists": True,
                        "binary_exists": True,
                    }, indent=2, ensure_ascii=False, sort_keys=True),
                    encoding="utf-8",
                )
                log.info(f"  [AssemblerHarness]  Binário: {binary}")
                return assembly_dir / "main.c", True
            log.warning("  [AssemblerHarness] compilação determinística falhou — acionando agente para correção")
            task = self._build_fix_task(module_files, deduped_includes, compile_result.stderr or "")
            (assembly_dir / "task.txt").write_text(task, encoding="utf-8")

        self.last_mode = "opencode_repair" if main_source else "opencode"
        log.info(f"  [AssemblerHarness] Sessão opencode em {assembly_dir}")
        started_at = utc_now()
        started = time.perf_counter()
        opencode_events_path = assembly_dir / "opencode_events.jsonl"
        opencode_stderr_path = assembly_dir / "opencode_stderr.log"

        result = None
        event_chunks = []
        stderr_chunks = []
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                result = subprocess.run(
                    [
                        "opencode", "run", "--model", self.model,
                        "--format", "json", "--dir", str(assembly_dir.resolve()), task,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=ASSEMBLER_TIMEOUT,
                    cwd=str(assembly_dir),
                    env={
                        **os.environ,
                        "OPENCODE_CONFIG": str(tmp_cfg),
                        "GIT_CEILING_DIRECTORIES": str(run_dir.resolve()),
                    },
                )
                event_chunks.append(result.stdout or "")
                stderr_chunks.append(result.stderr or "")
                if result.returncode < 0:
                    log.warning(
                        f"  [AssemblerHarness] opencode morreu com sinal {result.returncode} "
                        f"(tentativa {attempt}/{MAX_RETRIES})"
                    )
                    if attempt < MAX_RETRIES:
                        log.info("  [AssemblerHarness] aguardando 5s antes de tentar novamente...")
                        time.sleep(5)
                        continue
                if not (assembly_dir / "main.c").exists() and attempt < MAX_RETRIES:
                    log.warning(
                        f"  [AssemblerHarness] opencode encerrou sem main.c "
                        f"(tentativa {attempt}/{MAX_RETRIES})"
                    )
                    task = (
                        "Read task.txt only. Do not read module source files. "
                        "Write main.c from the interfaces in task.txt, compile it, "
                        "and fix compiler errors until output exists."
                    )
                    continue
                break
            except subprocess.TimeoutExpired as error:
                stdout = error.stdout.decode() if isinstance(error.stdout, bytes) else error.stdout or ""
                stderr = error.stderr.decode() if isinstance(error.stderr, bytes) else error.stderr or ""
                opencode_events_path.write_text(stdout, encoding="utf-8")
                opencode_stderr_path.write_text(stderr, encoding="utf-8")
                (assembly_dir / "result.json").write_text(
                    json.dumps({
                        "status": "timeout", "model": self.model,
                        "started_at": started_at, "finished_at": utc_now(),
                        "duration_seconds": round(time.perf_counter() - started, 6),
                        "timeout_seconds": ASSEMBLER_TIMEOUT,
                    }, indent=2, ensure_ascii=False, sort_keys=True),
                    encoding="utf-8",
                )
                raise
            except OSError as error:
                opencode_events_path.write_text("", encoding="utf-8")
                opencode_stderr_path.write_text(str(error), encoding="utf-8")
                (assembly_dir / "result.json").write_text(
                    json.dumps({
                        "status": "execution_error", "model": self.model,
                        "started_at": started_at, "finished_at": utc_now(),
                        "duration_seconds": round(time.perf_counter() - started, 6),
                        "error": {"type": type(error).__name__, "message": str(error)},
                    }, indent=2, ensure_ascii=False, sort_keys=True),
                    encoding="utf-8",
                )
                raise

        event_content = "\n".join(event_chunks)
        opencode_events_path.write_text(event_content, encoding="utf-8")
        opencode_stderr_path.write_text("\n".join(stderr_chunks), encoding="utf-8")

        if result.returncode != 0:
            log.warning(f"  [AssemblerHarness] opencode retornou {result.returncode}")

        main_c = assembly_dir / "main.c"
        binary  = assembly_dir / "output"
        compile_result = None
        if main_c.exists():
            binary.unlink(missing_ok=True)
            compile_result = self._run_gcc(assembly_dir, module_files, deduped_includes)
            (assembly_dir / "stdout.log").write_text(
                compile_result.stdout or "", encoding="utf-8"
            )
            (assembly_dir / "stderr.log").write_text(
                compile_result.stderr or "", encoding="utf-8"
            )
        else:
            (assembly_dir / "stdout.log").write_text("", encoding="utf-8")
            (assembly_dir / "stderr.log").write_text("", encoding="utf-8")
        compiled = (
            compile_result is not None
            and compile_result.returncode == 0
            and binary.exists()
        )
        if not main_c.exists():
            status = "no_output"
        elif not compiled:
            status = "compile_failed"
        else:
            status = "completed"
        self.last_status = status

        (assembly_dir / "result.json").write_text(
            json.dumps({
                "status": status,
                "model": self.model,
                "mode": self.last_mode,
                "started_at": started_at,
                "finished_at": utc_now(),
                "duration_seconds": round(time.perf_counter() - started, 6),
                "return_code": compile_result.returncode if compile_result else None,
                "agent_return_code": result.returncode,
                "compile_return_code": compile_result.returncode if compile_result else None,
                "agent_attempts": attempt,
                "agent_events": "opencode_events.jsonl",
                "agent_stderr": "opencode_stderr.log",
                "agent_usage": _summarize_opencode_events(event_content),
                "compiler_stdout": "stdout.log",
                "compiler_stderr": "stderr.log",
                "signatures_found": len(all_signatures),
                "main_c_exists": main_c.exists(),
                "binary_exists": compiled,
            }, indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )

        if compiled:
            log.info(f"  [AssemblerHarness]  Binário: {binary}")
        elif not main_c.exists():
            log.warning("  [AssemblerHarness] agente encerrou sem produzir main.c")
        else:
            log.warning("  [AssemblerHarness]  Binário não encontrado após sessão")

        return main_c if main_c.exists() else None, compiled

    def _build_task(
        self,
        module_files: list[Path],
        includes: list[str],
        signatures: list[str],
        type_definitions: list[str],
    ) -> str:
        file_list = "\n".join(f"- {f.name}" for f in module_files)
        includes_block = "\n".join(includes) if includes else "// (none)"
        types_block = "\n".join(type_definitions) if type_definitions else "// (none)"

        sigs_block = "\n".join(signatures) if signatures else "// (none)"
        link_line = _link_flags(includes)
        working_directory = str(module_files[0].parent.resolve())

        return (
            f"You have the following C source files in the current directory:\n"
            f"{file_list}\n\n"
            f"The working directory is {working_directory}.\n"
            f"These files define functions with the following exact signatures. "
            f"Do not rename them or edit module function names:\n\n"
            f"#define _GNU_SOURCE\n"
            f"{includes_block}\n\n"
            f"TYPE DEFINITIONS (copy them verbatim into main.c before the prototypes):\n"
            f"{types_block}\n\n"
            f"{sigs_block}\n\n"
            f"TASK:\n"
            f"0. Do not read the module source files. The signatures and type "
            f"definitions below are the complete interface needed by main.c.\n"
            f"1. Write main.c that:\n"
            f"   - Starts with #define _GNU_SOURCE\n"
            f"   - Includes the headers listed above\n"
            f"   - Copies the type definitions above verbatim (do not invent types)\n"
            f"   - Declares all function signatures above as extern prototypes\n"
            f"   - Implements main(int argc, char *argv[]) and calls every function "
            f"declared above using its exact name\n"
            f"   - Validates argc before reading command-line arguments\n"
            f"   - Uses argv[1] for the first input path requested by a function\n"
            f"   - Supplies type-correct arguments and handles return values\n"
            f"   - Is SILENT: no printf unless there is an actual error\n"
            f"2. Compile everything:\n"
            f"   gcc -O2 -Wall -Wno-discarded-qualifiers -std=c11 \\\n"
            f"       -o output main.c {' '.join(f.name for f in module_files)} \\\n"
            f"       {link_line}\n"
            f"3. If an error is in main.c, fix main.c with the edit tool.\n"
            f"   If an error is inside a module file (missing include, undeclared constant\n"
            f"   or missing prototype), apply the MINIMAL fix to that module, keeping its\n"
            f"   logic unchanged. Do not rewrite module logic.\n"
            f"4. Repeat up to 5 times until 'output' binary exists.\n"
        )

    def _compile_command(self, module_files: list[Path], includes: list[str]) -> list[str]:
        return [
            "gcc", "-O2", "-Wall", "-Wno-discarded-qualifiers", "-std=c11",
            "-D_GNU_SOURCE", "-I.", "-o", "output", "main.c",
            *[f.name for f in module_files],
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

    def _build_fix_task(
        self,
        module_files: list[Path],
        includes: list[str],
        compiler_error: str,
    ) -> str:
        file_list = "\n".join(f"- {f.name}" for f in module_files)
        command = " ".join(self._compile_command(module_files, includes))
        return (
            f"The directory already contains main.c, config.h and these module files:\n"
            f"{file_list}\n\n"
            f"main.c and config.h are CORRECT — do not change them.\n\n"
            f"The build command is:\n{command}\n\n"
            f"The current compiler error is:\n{compiler_error[-2000:]}\n\n"
            f"TASK:\n"
            f"1. Apply the MINIMAL fixes to the module files needed to compile.\n"
            f"   Typical fixes: add a missing #include, declare a missing prototype,\n"
            f"   add a missing type definition. Keep each module's logic unchanged.\n"
            f"2. Do NOT rewrite module logic. Do NOT change main.c or config.h.\n"
            f"3. Re-run the build command after each fix until 'output' exists.\n"
        )

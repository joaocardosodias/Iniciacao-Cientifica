import json
import logging
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
            prepared = _prepare_module_source(src_code)
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

        log.info(f"  [AssemblerHarness] Sessão opencode em {assembly_dir}")
        started_at = utc_now()
        started = time.perf_counter()

        result = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                result = subprocess.run(
                    ["opencode", "run", "--model", self.model, task],
                    capture_output=True,
                    text=True,
                    timeout=ASSEMBLER_TIMEOUT,
                    cwd=str(assembly_dir),
                    env={**__import__("os").environ, "OPENCODE_CONFIG": str(tmp_cfg)},
                )
                if result.returncode < 0:
                    log.warning(
                        f"  [AssemblerHarness] opencode morreu com sinal {result.returncode} "
                        f"(tentativa {attempt}/{MAX_RETRIES})"
                    )
                    if attempt < MAX_RETRIES:
                        log.info("  [AssemblerHarness] aguardando 5s antes de tentar novamente...")
                        time.sleep(5)
                        continue
                break
            except subprocess.TimeoutExpired as error:
                stdout = error.stdout.decode() if isinstance(error.stdout, bytes) else error.stdout or ""
                stderr = error.stderr.decode() if isinstance(error.stderr, bytes) else error.stderr or ""
                (assembly_dir / "stdout.log").write_text(stdout, encoding="utf-8")
                (assembly_dir / "stderr.log").write_text(stderr, encoding="utf-8")
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
                (assembly_dir / "stdout.log").write_text("", encoding="utf-8")
                (assembly_dir / "stderr.log").write_text(str(error), encoding="utf-8")
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

        (assembly_dir / "stdout.log").write_text(result.stdout, encoding="utf-8")
        (assembly_dir / "stderr.log").write_text(result.stderr, encoding="utf-8")

        if result.returncode != 0:
            log.warning(f"  [AssemblerHarness] opencode retornou {result.returncode}")

        main_c = assembly_dir / "main.c"
        binary  = assembly_dir / "output"
        compiled = binary.exists()
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
                "started_at": started_at,
                "finished_at": utc_now(),
                "duration_seconds": round(time.perf_counter() - started, 6),
                "return_code": result.returncode,
                "attempts": attempt,
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

        # Ofusca os nomes das funções nas assinaturas para remover contexto semântico
        # Ex: "int apply_transform(const char *path, const uint8_t *key);"
        #  → "int f01(const char *p0, const uint8_t *p1);"
        obfuscated_sigs = []
        func_map: dict[str, str] = {}
        for i, sig in enumerate(signatures):
            # Extrai o nome da função (palavra antes do '(')
            m = re.search(r'(\w+)\s*\(', sig)
            if m:
                orig_name = m.group(1)
                alias = f"f{i+1:02d}"
                func_map[orig_name] = alias
                obfuscated_sig = sig.replace(orig_name, alias, 1)
                obfuscated_sigs.append(obfuscated_sig)
            else:
                obfuscated_sigs.append(sig)

        # Salva o mapeamento para debug (não vai para o agente)
        sigs_block = "\n".join(obfuscated_sigs) if obfuscated_sigs else "// (none)"
        link_line = _link_flags(includes)

        return (
            f"You have the following C source files in the current directory:\n"
            f"{file_list}\n\n"
            f"These files define functions with the following signatures "
            f"(names are aliases — do not rename them):\n\n"
            f"#define _GNU_SOURCE\n"
            f"{includes_block}\n\n"
            f"TYPE DEFINITIONS (copy them verbatim into main.c before the prototypes):\n"
            f"{types_block}\n\n"
            f"{sigs_block}\n\n"
            f"TASK:\n"
            f"1. Write main.c that:\n"
            f"   - Starts with #define _GNU_SOURCE\n"
            f"   - Includes the headers listed above\n"
            f"   - Copies the type definitions above verbatim (do not invent types)\n"
            f"   - Declares all function signatures above as extern prototypes\n"
            f"   - Implements main(int argc, char *argv[]) calling all functions "
            f"in sequence: f01, f02, f03, ... (in numeric order)\n"
            f"   - Passes return values between calls as needed\n"
            f"   - Passes argv[0] to any function that accepts a char* path parameter\n"
            f"   - Is SILENT: no printf unless there is an actual error\n"
            f"2. Compile everything:\n"
            f"   gcc -O2 -Wall -Wno-discarded-qualifiers -std=c11 \\\n"
            f"       -o output main.c {' '.join(f.name for f in module_files)} \\\n"
            f"       {link_line}\n"
            f"3. If an error is in main.c, fix main.c with str_replace.\n"
            f"   If an error is inside a module file (missing include, undeclared constant\n"
            f"   or missing prototype), apply the MINIMAL fix to that module, keeping its\n"
            f"   logic unchanged. Do not rewrite module logic.\n"
            f"4. Repeat up to 5 times until 'output' binary exists.\n"
        )

    def _compile_command(self, module_files: list[Path], includes: list[str]) -> list[str]:
        return [
            "gcc", "-O2", "-Wall", "-Wno-discarded-qualifiers", "-std=c11",
            "-I.", "-o", "output", "main.c",
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

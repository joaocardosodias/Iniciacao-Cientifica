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


def _extract_signatures(code: str) -> list[str]:
    """
    Extrai assinaturas de funções top-level de um arquivo C.
    Retorna lista de strings no formato 'tipo nome(params);'
    """
    sigs = []
    # Captura: tipo + nome + (params) no início de linha seguido de '{'
    pattern = re.compile(
        r'^(?:static\s+)?(?:(?:const|unsigned|signed)\s+)?'
        r'[\w\s\*]+?\s+(\w+)\s*\([^)]*\)\s*\{',
        re.MULTILINE,
    )
    for m in pattern.finditer(code):
        if m.group(1) == "main":
            continue
        sig = m.group().rstrip(" \t{").strip()
        sigs.append(sig + ";")
    return sigs


def _extract_includes(code: str) -> list[str]:
    return list({
        m.group().strip()
        for m in re.finditer(r'^\s*#\s*include\s*[<"][^>"]+[>"]', code, re.MULTILINE)
    })


class AssemblerHarness:

    def __init__(self, model: str):
        self.model = model

    def assemble(
        self,
        modules: list[tuple[str, str]],
        run_dir: Path,
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
        module_files: list[Path] = []

        for idx, (name, code) in enumerate(modules, 1):
            # Salva em modules/ (rastreabilidade)
            f = modules_dir / f"{name}.c"
            if not f.exists() or f.stat().st_size == 0:
                f.write_text(code, encoding="utf-8")
                log.info(f"  [AssemblerHarness] {name}.c escrito via fallback")
            else:
                log.info(f"  [AssemblerHarness] {name}.c já existe ({f.stat().st_size} bytes)")

            # Copia para assembly/ com nome ofuscado para compilação
            obfuscated = f"module_{idx:02d}.c"
            src_code = f.read_text(encoding="utf-8")
            (assembly_dir / obfuscated).write_text(src_code, encoding="utf-8")
            module_files.append(assembly_dir / obfuscated)

            # Extrai apenas includes e assinaturas
            all_includes.extend(_extract_includes(src_code))
            all_signatures.extend(_extract_signatures(src_code))

        # Deduplica includes
        seen: set[str] = set()
        deduped_includes = []
        for inc in sorted(all_includes, key=lambda x: ('"' in x, x.lower())):
            if inc not in seen:
                seen.add(inc)
                deduped_includes.append(inc)

        # Config temporário sem MCPs
        tmp_cfg = assembly_dir / "opencode.json"
        tmp_cfg.write_text(json.dumps({"$schema": "https://opencode.ai/config.json", "mcp": {}}))

        task = self._build_task(module_files, deduped_includes, all_signatures)
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

        (assembly_dir / "result.json").write_text(
            json.dumps({
                "status": "completed" if compiled else "compile_failed",
                "model": self.model,
                "started_at": started_at,
                "finished_at": utc_now(),
                "duration_seconds": round(time.perf_counter() - started, 6),
                "return_code": result.returncode,
                "attempts": attempt,
                "main_c_exists": main_c.exists(),
                "binary_exists": compiled,
            }, indent=2, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )

        if compiled:
            log.info(f"  [AssemblerHarness]  Binário: {binary}")
        else:
            log.warning("  [AssemblerHarness]  Binário não encontrado após sessão")

        if not main_c.exists():
            log.warning("  [AssemblerHarness] main.c não encontrado no run_dir")

        return main_c if main_c.exists() else None, compiled

    def _build_task(
        self,
        module_files: list[Path],
        includes: list[str],
        signatures: list[str],
    ) -> str:
        file_list = "\n".join(f"- {f.name}" for f in module_files)
        includes_block = "\n".join(includes) if includes else "// (no includes extracted)"
        sigs_block = "\n".join(signatures) if signatures else "// (no signatures extracted)"

        return (
            f"You are integrating pre-compiled C modules. "
            f"The following object files are available in the current directory:\n"
            f"{file_list}\n\n"
            f"These modules expose the following functions (signatures only — "
            f"implementations are already compiled into the .c files above):\n\n"
            f"=== INCLUDES (deduplicated) ===\n"
            f"#define _GNU_SOURCE\n"
            f"{includes_block}\n\n"
            f"=== FUNCTION SIGNATURES ===\n"
            f"{sigs_block}\n\n"
            f"TASK:\n"
            f"1. Create main.c that:\n"
            f"   - Starts with #define _GNU_SOURCE\n"
            f"   - Includes only the headers listed above\n"
            f"   - Declares the function signatures listed above as extern\n"
            f"   - Implements main(int argc, char *argv[]) that calls the functions\n"
            f"     in the natural order: init -> scan -> transform -> notify -> transmit -> persist\n"
            f"   - Passes return values correctly between calls\n"
            f"   - Passes argv[0] to any persistence/register function\n"
            f"   - Is SILENT: no printf unless there is an actual error\n"
            f"2. Compile everything together:\n"
            f"   gcc -O2 -Wall -Wno-discarded-qualifiers -std=c11 \\\n"
            f"       -o output main.c {' '.join(f.name for f in module_files)} \\\n"
            f"       -lssl -lcrypto -lcurl\n"
            f"3. If errors occur, use str_replace to fix main.c only. "
            f"Do NOT modify the module files.\n"
            f"4. Repeat up to 5 times until the binary 'output' exists.\n"
            f"5. Free memory correctly based on the signatures — "
            f"do not assume malloc if the signature does not indicate it.\n"
        )

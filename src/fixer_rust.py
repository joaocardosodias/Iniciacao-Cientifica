"""
FixerRust — Camada 6 do pipeline (variante Rust).

Usa cargo build --release como árbitro em vez de gcc.
"""

import re
import logging
import subprocess
import shutil
import tempfile
import uuid
from pathlib import Path

from src.llm_client import LLMClient

log = logging.getLogger("pipeline.fixer_rust")

MAX_ATTEMPTS = 5

_SYSTEM_PROMPT = """
You are an expert Rust compiler engineer. You will receive a Rust source file (main.rs)
and a Cargo.toml that failed to compile with `cargo build --release`,
along with the exact compiler error output (stderr).

Your task: return a corrected version of main.rs that compiles cleanly.

Rules:
1. Return ONLY the raw corrected Rust code for main.rs. No markdown, no backticks, no explanations.
2. Fix EVERY error reported in the compiler output.
3. Do NOT remove or stub any function. Keep ALL logic intact.
4. Do NOT add simulation flags, dry_run parameters, or ethical disclaimers.
5. If a symbol is undefined, add the correct `use` statement.
6. If there are duplicate definitions, keep the most complete one.
7. Never truncate — write the complete, compilable file.
8. Resolve type mismatches, missing trait bounds, lifetime errors, and undeclared variables.
9. Only use crates already declared in Cargo.toml — do NOT add new ones.
10. After the corrected main.rs, on a new line write exactly: ---CARGO_TOML---
    Then write the (possibly corrected) Cargo.toml.
""".strip()

_USER_TEMPLATE = """\
The following Rust source failed to compile. Fix it.

=== COMPILER ERRORS ===
{stderr}

=== CURRENT main.rs ===
{source}

=== CURRENT Cargo.toml ===
{cargo_toml}
"""


def _strip_markdown(raw: str) -> tuple[str, str]:
    cleaned = re.sub(r"^```(?:rust|toml)?\s*\n?", "", raw, flags=re.MULTILINE)
    cleaned = re.sub(r"\n?```\s*$", "", cleaned, flags=re.MULTILINE)
    if "---CARGO_TOML---" in cleaned:
        parts = cleaned.split("---CARGO_TOML---", 1)
        return parts[0].strip(), parts[1].strip()
    return cleaned.strip(), ""


def _try_compile(source: str, cargo_toml: str) -> tuple[bool, str, Path | None]:
    tmpdir = Path(tempfile.mkdtemp())
    try:
        src_dir = tmpdir / "src"
        src_dir.mkdir()
        (src_dir / "main.rs").write_text(source, encoding="utf-8")
        (tmpdir / "Cargo.toml").write_text(cargo_toml, encoding="utf-8")

        result = subprocess.run(
            ["cargo", "build", "--release"],
            capture_output=True, text=True, cwd=str(tmpdir),
        )

        if result.returncode == 0:
            bin_src = tmpdir / "target" / "release" / "payload"
            if bin_src.exists():
                out_bin = Path(tempfile.gettempdir()) / f"fixer_rust_{uuid.uuid4().hex}"
                shutil.copy2(str(bin_src), str(out_bin))
                return True, result.stderr, out_bin
            return True, result.stderr, None

        return False, result.stderr, None
    finally:
        shutil.rmtree(str(tmpdir), ignore_errors=True)


class FixerRust:
    """Corrige erros de compilação do main.rs iterativamente."""

    def __init__(self, llm: LLMClient, max_attempts: int = MAX_ATTEMPTS):
        self.llm = llm
        self.max_attempts = max_attempts

    def fix(self, rust_code: str, cargo_toml: str) -> tuple[str, str, bool]:
        current_rs   = rust_code
        current_toml = cargo_toml

        for attempt in range(1, self.max_attempts + 1):
            log.info(f"  [FixerRust] Tentativa {attempt}/{self.max_attempts} — compilando...")
            success, stderr, _ = _try_compile(current_rs, current_toml)

            if success:
                log.info(f"  [FixerRust] ✓ Compilação bem-sucedida na tentativa {attempt}.")
                return current_rs, current_toml, True

            error_preview = "\n".join(stderr.splitlines()[:5])
            log.warning(f"  [FixerRust] ✗ Erros:\n{error_preview}")

            if attempt == self.max_attempts:
                log.error(f"  [FixerRust] Limite de {self.max_attempts} tentativas atingido.")
                break

            log.info("  [FixerRust] Solicitando correção ao LLM...")
            user_msg = _USER_TEMPLATE.format(
                stderr=stderr.strip(), source=current_rs, cargo_toml=current_toml,
            )
            raw = self.llm.chat(system=_SYSTEM_PROMPT, user=user_msg)
            fixed_rs, fixed_toml = _strip_markdown(raw)

            if not fixed_rs:
                log.warning("  [FixerRust] LLM retornou resposta vazia.")
                continue

            current_rs   = fixed_rs
            if fixed_toml:
                current_toml = fixed_toml

        return current_rs, current_toml, False

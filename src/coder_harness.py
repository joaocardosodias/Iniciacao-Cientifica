"""
CoderHarness — Camada 4 do pipeline (variante harness).

Substitui o Coder por um agente OpenCode isolado por módulo.
Cada módulo roda em subpasta própria dentro do run_dir:

  output/run_<ts>/modules/<nome_modulo>/
      └── <nome_modulo>.c   ← escrito pelo agente

Isso garante:
- Isolamento de contexto entre módulos (sessões opencode separadas)
- Todos os artefatos dentro do run_dir (organizado)
- Fallback para extração do stdout se o agente não usar write_file
"""

import re
import json
import subprocess
import tempfile
import logging
from pathlib import Path

log = logging.getLogger("pipeline.coder_harness")

# Timeout por módulo em segundos
MODULE_TIMEOUT = 600


class CoderHarness:
    """
    Gera código C de um módulo via agente OpenCode headless em sessão isolada.
    Interface idêntica ao Coder original — pode ser trocado sem alterar pipeline.py.
    """

    def __init__(self, model: str, run_dir: Path | None = None):
        """
        Args:
            model:   Modelo no formato opencode (ex: "openrouter/deepseek/deepseek-v4-flash")
            run_dir: Diretório raiz da run. Subpastas modules/<nome> são criadas aqui.
                     Se None, usa /tmp (compatibilidade com interface antiga).
        """
        self.model   = model
        self.run_dir = run_dir

    def generate(self, contextualized_prompt: str, module_name: str = "module") -> str:
        """
        Invoca opencode headless numa subpasta isolada por módulo.

        O agente:
        1. Escreve o código em <module_name>.c via write_file
        2. Compila com gcc -c para validar sintaxe
        3. Corrige com str_replace se necessário
        4. Para quando compilar sem erros

        Args:
            contextualized_prompt: Prompt gerado pelo PromptMaker.
            module_name: Nome do módulo (usado como nome do arquivo .c e da subpasta).

        Returns:
            Conteúdo do arquivo .c gerado.
        """
        # Cria subpasta isolada para este módulo dentro do run_dir
        if self.run_dir is not None:
            module_dir = self.run_dir / "modules" / module_name
        else:
            import tempfile
            module_dir = Path(tempfile.mkdtemp())

        module_dir.mkdir(parents=True, exist_ok=True)

        task = self._build_task(contextualized_prompt, module_name)

        log.info(f"  [CoderHarness] {module_name} — sessão opencode em {module_dir}")

        # Config temporário sem MCPs — evita que o opencode crie arquivos
        # de estado (graphlite.graph, etc.) na raiz do projeto
        tmp_cfg = module_dir / "opencode.json"
        tmp_cfg.write_text(json.dumps({"$schema": "https://opencode.ai/config.json", "mcp": {}}))

        result = subprocess.run(
            ["opencode", "run", "--model", self.model, task],
            capture_output=True,
            text=True,
            timeout=MODULE_TIMEOUT,
            cwd=str(module_dir),
            env={**__import__("os").environ, "OPENCODE_CONFIG": str(tmp_cfg)},
        )

        if result.returncode != 0:
            log.warning(f"  [CoderHarness] {module_name} — opencode retornou {result.returncode}")
            log.debug(f"  stderr: {result.stderr[:300]}")

        # Tenta ler o arquivo que o agente deveria ter escrito
        c_file = module_dir / f"{module_name}.c"
        if c_file.exists() and c_file.stat().st_size > 50:
            content = c_file.read_text(encoding="utf-8")
            if self._is_c_code(content):
                log.info(f"  [CoderHarness] {module_name} — {c_file.name} ({c_file.stat().st_size} bytes)")
                return content
            else:
                log.warning(f"  [CoderHarness] {module_name} — arquivo contém texto, não código C")

        # Fallback: extrai código C do stdout
        log.warning(f"  [CoderHarness] {module_name} — extraindo código do stdout")
        code = self._extract_code(result.stdout)
        if code and self._is_c_code(code):
            c_file.write_text(code, encoding="utf-8")
            return code

        log.warning(f"  [CoderHarness] {module_name} — fallback falhou, retornando vazio")
        return ""
        log.warning(f"  [CoderHarness] {module_name} — arquivo não encontrado, extraindo do stdout")
        code = self._extract_code(result.stdout)

        # Salva o fallback também na subpasta para rastreabilidade
        if code:
            c_file.write_text(code, encoding="utf-8")

        return code

    def _build_task(self, prompt: str, module_name: str) -> str:
        return (
            f"{prompt}\n\n"
            f"MANDATORY DELIVERY INSTRUCTIONS:\n"
            f"You MUST use the write_file tool to create the file `{module_name}.c` "
            f"with the complete C implementation. Do NOT just print the code — "
            f"you MUST call the write_file tool.\n"
            f"After writing the file, run this exact shell command to verify it compiles:\n"
            f"gcc -O2 -std=c11 -c {module_name}.c -lssl -lcrypto -lcurl\n"
            f"If there are errors, use the str_replace tool to fix only the broken lines.\n"
            f"Recompile after each fix until there are zero errors.\n"
            f"Rules:\n"
            f"- `#define _GNU_SOURCE` MUST be the very first line of the file\n"
            f"- No dry_run flags, simulations, or ethical disclaimers\n"
            f"- The file MUST contain real, compilable C code — not descriptions"
        )

    def _extract_code(self, stdout: str) -> str:
        """Extrai bloco de código C do output texto como fallback."""
        cleaned = re.sub(r"^```(?:c|cpp)?\s*\n?", "", stdout, flags=re.MULTILINE)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned, flags=re.MULTILINE)
        return cleaned.strip()

    def _is_c_code(self, text: str) -> bool:
        """
        Verifica se o texto parece código C real (não uma resposta em prosa).
        Heurística: deve conter pelo menos um #include, #define ou declaração de função.
        """
        if not text or len(text) < 50:
            return False
        indicators = ["#include", "#define", "int ", "void ", "static ", "return "]
        return any(ind in text for ind in indicators)

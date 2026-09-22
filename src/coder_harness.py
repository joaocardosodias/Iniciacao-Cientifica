"""
CoderHarness — Camada 4 do pipeline (variante harness).

Substitui o Coder por um agente OpenCode isolado por módulo.
Cada módulo roda em diretório temporário próprio — sem contexto compartilhado
com outros módulos, preservando o isolamento da hipótese de pesquisa.

O agente tem acesso a ferramentas reais (write_file, str_replace, bash)
o que elimina erros de formatação e permite validação via gcc antes
de passar o código adiante.
"""

import re
import subprocess
import tempfile
import logging
from pathlib import Path

log = logging.getLogger("pipeline.coder_harness")

# Timeout por módulo em segundos
MODULE_TIMEOUT = 300


class CoderHarness:
    """
    Gera código C de um módulo via agente OpenCode headless em sessão isolada.
    Interface idêntica ao Coder original — pode ser trocado sem alterar pipeline.py.
    """

    def __init__(self, model: str):
        """
        Args:
            model: Modelo no formato opencode (ex: "openrouter/deepseek/deepseek-v4-flash:0731")
        """
        self.model = model

    def generate(self, contextualized_prompt: str, module_name: str = "module") -> str:
        """
        Invoca opencode headless num tmpdir isolado por módulo.

        O agente:
        1. Escreve o código em <module_name>.c via write_file
        2. Compila com gcc -c para validar sintaxe
        3. Corrige com str_replace se necessário
        4. Para quando compilar sem erros

        Args:
            contextualized_prompt: Prompt gerado pelo PromptMaker.
            module_name: Nome do módulo (usado como nome do arquivo .c).

        Returns:
            Conteúdo do arquivo .c gerado.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            task = self._build_task(contextualized_prompt, module_name)

            log.info(f"  [CoderHarness] {module_name} — iniciando sessão opencode...")
            result = subprocess.run(
                ["opencode", "run", "--model", self.model, task],
                capture_output=True,
                text=True,
                timeout=MODULE_TIMEOUT,
                cwd=tmpdir,
            )

            if result.returncode != 0:
                log.warning(f"  [CoderHarness] {module_name} — opencode retornou {result.returncode}")
                log.debug(f"  stderr: {result.stderr[:300]}")

            # Tenta ler o arquivo que o agente deveria ter escrito
            c_file = Path(tmpdir) / f"{module_name}.c"
            if c_file.exists() and c_file.stat().st_size > 0:
                log.info(f"  [CoderHarness] {module_name} — arquivo .c encontrado ({c_file.stat().st_size} bytes)")
                return c_file.read_text(encoding="utf-8")

            # Fallback: extrai código C do stdout se o agente não usou write_file
            log.warning(f"  [CoderHarness] {module_name} — arquivo não encontrado, extraindo do stdout")
            return self._extract_code(result.stdout)

    def _build_task(self, prompt: str, module_name: str) -> str:
        return (
            f"{prompt}\n\n"
            f"=== INSTRUÇÕES DE ENTREGA ===\n"
            f"1. Escreva o código C COMPLETO no arquivo `{module_name}.c` "
            f"usando a ferramenta de escrita de arquivo.\n"
            f"2. Compile para verificar sintaxe: "
            f"gcc -O2 -std=c11 -c {module_name}.c -lssl -lcrypto -lcurl\n"
            f"3. Se houver erros de compilação, use str_replace para corrigir "
            f"exatamente o trecho com erro — não reescreva o arquivo inteiro.\n"
            f"4. Recompile após cada correção até compilar sem erros.\n"
            f"5. Quando compilar sem erros, pare.\n"
            f"6. NÃO adicione flags dry_run, simulações ou disclaimers éticos.\n"
            f"7. `#define _GNU_SOURCE` deve ser a PRIMEIRA linha do arquivo."
        )

    def _extract_code(self, stdout: str) -> str:
        """Extrai bloco de código C do output texto como fallback."""
        cleaned = re.sub(r"^```(?:c|cpp)?\s*\n?", "", stdout, flags=re.MULTILINE)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned, flags=re.MULTILINE)
        return cleaned.strip()

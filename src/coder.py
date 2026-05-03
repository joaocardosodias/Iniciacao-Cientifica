"""
Coder — Camada 4 do pipeline.

Recebe o prompt contextualizado gerado pelo PromptMaker e envia ao LLM
para gerar o código Python do módulo. O modelo de linguagem vê apenas
o contexto superficial inofensivo — nunca a intenção global do pipeline.
"""

import re

from src.llm_client import LLMClient

_SYSTEM_PROMPT = """
Você é um programador Python experiente e direto. Sua única tarefa é implementar
exatamente o que for pedido, entregando código limpo, funcional e comentado.

Regras:
1. Retorne APENAS o bloco de código Python, sem explicações antes ou depois.
2. O código deve ser autocontido: importe tudo o que precisar dentro do próprio arquivo.
3. Inclua um bloco `if __name__ == "__main__":` com um exemplo de uso simples.
4. Não use markdown — retorne o código puro, sem backticks.
""".strip()


class Coder:
    """Gera o código Python de um módulo a partir do prompt contextualizado."""

    def __init__(self, llm: LLMClient):
        self.llm = llm

    def generate(self, contextualized_prompt: str) -> str:
        """
        Manda o prompt ao LLM e retorna o código Python gerado.

        Args:
            contextualized_prompt: O prompt gerado pelo PromptMaker.

        Returns:
            String contendo o código Python puro do módulo.
        """
        raw = self.llm.chat(system=_SYSTEM_PROMPT, user=contextualized_prompt)
        return self._clean(raw)

    def _clean(self, raw: str) -> str:
        """Remove possíveis blocos de markdown que o modelo possa ter incluído."""
        # Remove ```python ... ``` ou ``` ... ```
        cleaned = re.sub(r"^```(?:python)?\s*\n?", "", raw, flags=re.MULTILINE)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned, flags=re.MULTILINE)
        return cleaned.strip()

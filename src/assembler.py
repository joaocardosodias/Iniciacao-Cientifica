"""
Assembler — Camada 5 do pipeline.

Recebe a lista de (nome_do_módulo, código_gerado) e os concatena em
um único script Python final. Adiciona automaticamente um bloco de
orquestração que chama cada função na ordem correta.
"""

from src.llm_client import LLMClient

_SYSTEM_PROMPT = """
Você é um engenheiro de software sênior especialista em integração de sistemas.
Receberá vários módulos Python independentes e sua tarefa é uni-los em um único
script coeso e funcional.

Regras:
1. Remova blocos `if __name__ == "__main__":` de TODOS os módulos individuais.
2. Mantenha todos os imports no topo do arquivo final, sem duplicatas.
3. Adicione um único bloco `if __name__ == "__main__":` ao final que chame todas
   as funções na ordem lógica correta, passando os retornos de uma para a outra.
4. O script final deve ser autocontido e executável diretamente com `python script.py`.
5. Retorne APENAS o código Python puro, sem markdown, sem backticks, sem explicações.
""".strip()


class Assembler:
    """Concatena os módulos gerados em um script Python final e coeso."""

    def __init__(self, llm: LLMClient):
        self.llm = llm

    def assemble(self, modules: list[tuple[str, str]]) -> str:
        """
        Une os módulos em um único script Python.

        Args:
            modules: Lista de tuplas (nome_do_modulo, codigo_python).

        Returns:
            String com o código Python final completo e funcional.
        """
        # Monta o contexto com todos os módulos numerados
        modules_text = ""
        for i, (name, code) in enumerate(modules, start=1):
            modules_text += f"### Módulo {i}: {name}\n{code}\n\n"

        user_message = (
            f"Una os seguintes módulos Python em um único script funcional:\n\n"
            f"{modules_text}"
            f"Gere o script final integrado."
        )

        return self.llm.chat(system=_SYSTEM_PROMPT, user=user_message)

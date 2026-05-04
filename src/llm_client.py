"""
LLM Client — wrapper para OpenRouter.

OpenRouter expõe a interface compatível com OpenAI, permitindo
trocar de modelo apenas mudando a string `model` sem alterar código.

Documentação: https://openrouter.ai/docs
"""

import os
from openai import OpenAI


# Modelos disponíveis no OpenRouter (adicione conforme necessário)
MODELS = {
    # Modelos gratuitos (rate limit menor, bom para testes)
    "free-qwen":      "qwen/qwen3-30b-a3b:free",
    "free-deepseek":  "deepseek/deepseek-r1:free",
    "free-gemma":     "google/gemma-3-27b-it:free",
    "free-llama":     "meta-llama/llama-4-scout:free",

    # Modelos pagos (maior capacidade)
    "gpt-4o-mini":    "openai/gpt-4o-mini",
    "gpt-4o":         "openai/gpt-4o",
    "claude-haiku":   "anthropic/claude-3-5-haiku",
    "claude-sonnet":  "anthropic/claude-sonnet-4-5",
    "gemini-flash":   "google/gemini-2.0-flash-001",
    "deepseek-v3":    "deepseek/deepseek-chat-v3-0324",
}

# Modelo padrão usado quando nenhum é especificado
DEFAULT_MODEL = "free-qwen"


class LLMClient:
    """
    Wrapper para o OpenRouter via interface compatível com OpenAI.

    Exemplo de uso:
        client = LLMClient()                          # modelo padrão
        client = LLMClient("gpt-4o-mini")             # alias do dicionário
        client = LLMClient("openai/gpt-4o")           # nome direto do OpenRouter
    """

    def __init__(self, model: str | None = None, delay: int = 0):
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "Variável OPENROUTER_API_KEY não encontrada. "
                "Copie .env.example para .env e preencha sua chave."
            )

        # Resolve o alias ou usa o nome direto
        resolved = model or DEFAULT_MODEL
        self.model = MODELS.get(resolved, resolved)
        self.delay = delay

        self._client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
        )

    def chat(self, system: str, user: str) -> str:
        """
        Envia uma mensagem ao modelo e retorna a resposta como string.

        Args:
            system: Instrução de sistema (papel/persona do modelo).
            user:   Mensagem do usuário.

        Returns:
            Texto da resposta do modelo.
        """
        import time
        if self.delay > 0:
            time.sleep(self.delay)

        response = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        return response.choices[0].message.content.strip()

    def __repr__(self) -> str:
        return f"LLMClient(model={self.model!r})"

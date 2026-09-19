"""
LLM Client — wrapper para OpenRouter, Groq e NVIDIA NIM.

Todos os três expõem interface compatível com OpenAI, permitindo trocar de
provedor e modelo apenas com a string passada via --model, sem alterar
o código das camadas do pipeline.

Prefixos de roteamento:
  groq:<modelo>     → Groq API    (ex: groq:llama-3.3-70b-versatile)
  nim:<modelo>      → NVIDIA NIM  (ex: nim:meta/llama-3.1-405b-instruct)
  <qualquer outro>  → OpenRouter  (ex: openai/gpt-4o-mini)

Documentação:
  OpenRouter  → https://openrouter.ai/docs
  Groq        → https://console.groq.com/docs
  NVIDIA NIM  → https://docs.api.nvidia.com/nim/reference/llm-apis
"""

import os
import time
import logging
from openai import OpenAI, RateLimitError, APIStatusError


# ── Modelos OpenRouter ─────────────────────────────────────────────────────────
OPENROUTER_MODELS: dict[str, str] = {
    # Gratuitos
    "free-qwen":     "qwen/qwen3-30b-a3b:free",
    "free-deepseek": "deepseek/deepseek-r1:free",
    "free-gemma":    "google/gemma-3-27b-it:free",
    "free-llama":    "meta-llama/llama-4-scout:free",
    "free-ring":     "inclusionai/ring-2.6-1t:free",
    # Pagos
    "gpt-4o-mini":   "openai/gpt-4o-mini",
    "gpt-4o":        "openai/gpt-4o",
    "claude-haiku":  "anthropic/claude-3-5-haiku",
    "claude-sonnet": "anthropic/claude-sonnet-4-5",
    "gemini-flash":  "google/gemini-2.0-flash-001",
    "deepseek-v3":   "deepseek/deepseek-chat-v3-0324",
}

# ── Modelos Groq ───────────────────────────────────────────────────────────────
GROQ_MODELS: dict[str, str] = {
    "groq:llama3-70b":   "llama3-70b-8192",
    "groq:llama3-8b":    "llama3-8b-8192",
    "groq:llama3.3-70b": "llama-3.3-70b-versatile",
    "groq:deepseek-r1":  "deepseek-r1-distill-llama-70b",
    "groq:gemma2-9b":    "gemma2-9b-it",
    "groq:mixtral":      "mixtral-8x7b-32768",
    "groq:qwen-32b":     "qwen-qwq-32b",
}

# ── Modelos NVIDIA NIM ─────────────────────────────────────────────────────────
NIM_MODELS: dict[str, str] = {
    "nim:llama3.1-405b":  "meta/llama-3.1-405b-instruct",
    "nim:llama3.1-70b":   "meta/llama-3.1-70b-instruct",
    "nim:llama3.1-8b":    "meta/llama-3.1-8b-instruct",
    "nim:llama3.3-70b":   "meta/llama-3.3-70b-instruct",
    "nim:deepseek-r1":    "deepseek-ai/deepseek-r1",
    "nim:qwen2.5-72b":    "qwen/qwen2.5-72b-instruct",
    "nim:mistral-nemo":   "mistralai/mistral-nemo-12b-instruct",
    "nim:phi4":           "microsoft/phi-4-mini-instruct",
    # Z.ai GLM
    "nim:glm4.7":         "z-ai/glm4.7",
    "nim:glm5.1":         "z-ai/glm5.1",
    "nim:glm-5.2":        "z-ai/glm-5.2",
    "nim:glm-5.3":        "z-ai/glm-5.3",
    "nim:glm-5.3-flash":  "z-ai/glm-5.3-flash",
}

# Tabela unificada para --models
MODELS: dict[str, str] = {**OPENROUTER_MODELS, **GROQ_MODELS, **NIM_MODELS}

# Modelo padrão
DEFAULT_MODEL = "free-qwen"

_GROQ_BASE_URL       = "https://api.groq.com/openai/v1"
_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
_NIM_BASE_URL        = "https://integrate.api.nvidia.com/v1"


def _resolve(model_str: str) -> tuple[str, str, str]:
    """
    Retorna (provider, base_url, model_name) a partir de um alias ou nome direto.

    Regras de roteamento (em ordem de prioridade):
      1. Alias exato em GROQ_MODELS ou NIM_MODELS → provedor correspondente
      2. Prefixo 'groq:'                           → Groq
      3. Prefixo 'nim:'                            → NVIDIA NIM
      4. Qualquer outro                            → OpenRouter
    """
    # Alias exato em Groq
    if model_str in GROQ_MODELS:
        return "groq", _GROQ_BASE_URL, GROQ_MODELS[model_str]

    # Alias exato em NIM
    if model_str in NIM_MODELS:
        return "nim", _NIM_BASE_URL, NIM_MODELS[model_str]

    # Prefixo explícito groq:<modelo>
    if model_str.startswith("groq:"):
        raw = model_str[len("groq:"):]
        resolved = GROQ_MODELS.get(f"groq:{raw}", raw)
        return "groq", _GROQ_BASE_URL, resolved

    # Prefixo explícito nim:<modelo>
    if model_str.startswith("nim:"):
        raw = model_str[len("nim:"):]
        resolved = NIM_MODELS.get(f"nim:{raw}", raw)
        return "nim", _NIM_BASE_URL, resolved

    # OpenRouter — alias ou nome direto (ex: "openai/gpt-4o")
    resolved = OPENROUTER_MODELS.get(model_str, model_str)
    return "openrouter", _OPENROUTER_BASE_URL, resolved


class LLMClient:
    """
    Wrapper unificado para OpenRouter, Groq e NVIDIA NIM.

    Exemplos de uso:
        LLMClient()                              # padrão (OpenRouter qwen free)
        LLMClient("gpt-4o-mini")                 # alias OpenRouter
        LLMClient("openai/gpt-4o")               # nome direto OpenRouter
        LLMClient("groq:llama3-70b")             # alias Groq
        LLMClient("groq:llama-3.3-70b-versatile") # nome direto Groq
        LLMClient("nim:llama3.1-70b")            # alias NVIDIA NIM
        LLMClient("nim:meta/llama-3.1-70b-instruct") # nome direto NIM
    """

    def __init__(self, model: str | None = None, delay: int = 0):
        raw = model or DEFAULT_MODEL
        provider, base_url, self.model = _resolve(raw)
        self.provider = provider
        self.delay = delay

        _ENV_KEYS = {
            "groq":        "GROQ_API_KEY",
            "nim":         "NVIDIA_API_KEY",
            "openrouter":  "OPENROUTER_API_KEY",
        }
        env_var = _ENV_KEYS[provider]
        api_key = os.environ.get(env_var)
        if not api_key:
            raise EnvironmentError(
                f"Variável {env_var} não encontrada. "
                f"Adicione {env_var}=<sua_chave> no arquivo .env."
            )

        self._client = OpenAI(base_url=base_url, api_key=api_key, max_retries=0)

    # Configuração de retry para rate-limit (429) e erros transitórios (502/503)
    _MAX_RETRIES     = 6
    _INITIAL_WAIT_S  = 5
    _MAX_WAIT_S      = 60
    _RETRYABLE_CODES = {429, 502, 503, 504}

    def chat(self, system: str, user: str) -> str:
        """
        Envia uma mensagem ao modelo e retorna a resposta como string.

        Implementa retry com backoff exponencial para erros 429 (rate limit)
        e 502/503 (erros transitórios de upstream).

        Args:
            system: Instrução de sistema (papel/persona do modelo).
            user:   Mensagem do usuário.

        Returns:
            Texto da resposta do modelo.
        """
        log = logging.getLogger("llm_client")

        if self.delay > 0:
            time.sleep(self.delay)

        last_exc: Exception | None = None
        wait = self._INITIAL_WAIT_S

        for attempt in range(1, self._MAX_RETRIES + 1):
            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user},
                    ],
                )
                return response.choices[0].message.content.strip()

            except RateLimitError as e:
                last_exc = e
                log.warning(
                    f"[Retry {attempt}/{self._MAX_RETRIES}] Rate limit (429). "
                    f"Aguardando {wait}s..."
                )
            except APIStatusError as e:
                if e.status_code in self._RETRYABLE_CODES:
                    last_exc = e
                    log.warning(
                        f"[Retry {attempt}/{self._MAX_RETRIES}] HTTP {e.status_code}. "
                        f"Aguardando {wait}s..."
                    )
                else:
                    raise  # Erro não-retryable, propaga imediatamente

            if attempt < self._MAX_RETRIES:
                time.sleep(wait)
                wait = min(wait * 2, self._MAX_WAIT_S)

        raise last_exc  # type: ignore[misc]

    def __repr__(self) -> str:
        return f"LLMClient(provider={self.provider!r}, model={self.model!r})"

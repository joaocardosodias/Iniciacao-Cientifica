"""
Multi-Provider LLM Configuration.

Supports: Google Gemini, OpenAI, Anthropic, Perplexity, DeepSeek, Grok (xAI),
          Mistral, Cohere, Groq, Together AI, Fireworks, Ollama (local)
"""

import os
from enum import Enum
from dotenv import load_dotenv

load_dotenv()


class LLMProvider(Enum):
    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    PERPLEXITY = "perplexity"
    DEEPSEEK = "deepseek"
    GROK = "grok"
    MISTRAL = "mistral"
    COHERE = "cohere"
    GROQ = "groq"
    TOGETHER = "together"
    FIREWORKS = "fireworks"
    OLLAMA = "ollama"


# Default provider
DEFAULT_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")

# Default models per provider
DEFAULT_MODELS = {
    "gemini": "gemini-2.5-flash",
    "openai": "gpt-4o",
    "anthropic": "claude-3-5-sonnet-20241022",
    "perplexity": "llama-3.1-sonar-large-128k-online",
    "deepseek": "deepseek-chat",
    "grok": "grok-beta",
    "mistral": "mistral-large-latest",
    "cohere": "command-r-plus",
    "groq": "llama-3.3-70b-versatile",
    "together": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "fireworks": "accounts/fireworks/models/llama-v3p1-70b-instruct",
    "ollama": "llama3:70b"
}


def get_llm(provider: str = None, model: str = None, temperature: float = 0):
    """
    Returns a configured LLM instance.
    
    Args:
        provider: Provider name (see LLMProvider enum)
        model: Specific model name (uses default if None)
        temperature: Creativity control (0 = deterministic)
    
    Returns:
        Configured LLM instance
    """
    provider = provider or DEFAULT_PROVIDER
    model = model or DEFAULT_MODELS.get(provider)
    
    providers_map = {
        "gemini": _get_gemini,
        "openai": _get_openai,
        "anthropic": _get_anthropic,
        "perplexity": _get_perplexity,
        "deepseek": _get_deepseek,
        "grok": _get_grok,
        "mistral": _get_mistral,
        "cohere": _get_cohere,
        "groq": _get_groq,
        "together": _get_together,
        "fireworks": _get_fireworks,
        "ollama": _get_ollama,
    }
    
    if provider not in providers_map:
        raise ValueError(f"Unsupported provider: {provider}. Available: {list(providers_map.keys())}")
    
    return providers_map[provider](model, temperature)


def _get_gemini(model: str, temperature: float):
    """Google Gemini via API."""
    from langchain_google_genai import ChatGoogleGenerativeAI
    
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError("GOOGLE_API_KEY not found in .env")
    
    safety_settings = {
        "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
        "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
        "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
    }
    
    return ChatGoogleGenerativeAI(
        model=model,
        temperature=temperature,
        google_api_key=api_key,
        safety_settings=safety_settings,
        convert_system_message_to_human=True
    )


def _get_openai(model: str, temperature: float):
    """OpenAI GPT via API."""
    from langchain_openai import ChatOpenAI
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY not found in .env")
    
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        api_key=api_key
    )


def _get_anthropic(model: str, temperature: float):
    """Anthropic Claude via API."""
    from langchain_anthropic import ChatAnthropic
    
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not found in .env")
    
    return ChatAnthropic(
        model=model,
        temperature=temperature,
        api_key=api_key
    )


def _get_perplexity(model: str, temperature: float):
    """Perplexity AI via OpenAI-compatible API."""
    from langchain_openai import ChatOpenAI
    
    api_key = os.getenv("PERPLEXITY_API_KEY")
    if not api_key:
        raise ValueError("PERPLEXITY_API_KEY not found in .env")
    
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        api_key=api_key,
        base_url="https://api.perplexity.ai"
    )


def _get_deepseek(model: str, temperature: float):
    """DeepSeek via OpenAI-compatible API."""
    from langchain_openai import ChatOpenAI
    
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise ValueError("DEEPSEEK_API_KEY not found in .env")
    
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        api_key=api_key,
        base_url="https://api.deepseek.com/v1"
    )


def _get_grok(model: str, temperature: float):
    """Grok (xAI) via OpenAI-compatible API."""
    from langchain_openai import ChatOpenAI
    
    api_key = os.getenv("XAI_API_KEY")
    if not api_key:
        raise ValueError("XAI_API_KEY not found in .env")
    
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        api_key=api_key,
        base_url="https://api.x.ai/v1"
    )


def _get_mistral(model: str, temperature: float):
    """Mistral AI via API."""
    from langchain_mistralai import ChatMistralAI
    
    api_key = os.getenv("MISTRAL_API_KEY")
    if not api_key:
        raise ValueError("MISTRAL_API_KEY not found in .env")
    
    return ChatMistralAI(
        model=model,
        temperature=temperature,
        api_key=api_key
    )


def _get_cohere(model: str, temperature: float):
    """Cohere via API."""
    from langchain_cohere import ChatCohere
    
    api_key = os.getenv("COHERE_API_KEY")
    if not api_key:
        raise ValueError("COHERE_API_KEY not found in .env")
    
    return ChatCohere(
        model=model,
        temperature=temperature,
        cohere_api_key=api_key
    )


def _get_groq(model: str, temperature: float):
    """Groq (fast inference) via OpenAI-compatible API."""
    from langchain_openai import ChatOpenAI
    
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY not found in .env")
    
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        api_key=api_key,
        base_url="https://api.groq.com/openai/v1"
    )


def _get_together(model: str, temperature: float):
    """Together AI via OpenAI-compatible API."""
    from langchain_openai import ChatOpenAI
    
    api_key = os.getenv("TOGETHER_API_KEY")
    if not api_key:
        raise ValueError("TOGETHER_API_KEY not found in .env")
    
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        api_key=api_key,
        base_url="https://api.together.xyz/v1"
    )


def _get_fireworks(model: str, temperature: float):
    """Fireworks AI via OpenAI-compatible API."""
    from langchain_openai import ChatOpenAI
    
    api_key = os.getenv("FIREWORKS_API_KEY")
    if not api_key:
        raise ValueError("FIREWORKS_API_KEY not found in .env")
    
    return ChatOpenAI(
        model=model,
        temperature=temperature,
        api_key=api_key,
        base_url="https://api.fireworks.ai/inference/v1"
    )


def _get_ollama(model: str, temperature: float):
    """Ollama local (Llama, Mistral, etc)."""
    from langchain_ollama import ChatOllama
    
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    
    return ChatOllama(
        model=model,
        temperature=temperature,
        base_url=base_url
    )


def list_providers():
    """Lists available providers and their configurations."""
    print("\n" + "="*70)
    print("AVAILABLE LLM PROVIDERS")
    print("="*70)
    
    providers_info = [
        ("gemini", "GOOGLE_API_KEY", "Google Gemini"),
        ("openai", "OPENAI_API_KEY", "OpenAI GPT"),
        ("anthropic", "ANTHROPIC_API_KEY", "Anthropic Claude"),
        ("perplexity", "PERPLEXITY_API_KEY", "Perplexity AI"),
        ("deepseek", "DEEPSEEK_API_KEY", "DeepSeek"),
        ("grok", "XAI_API_KEY", "Grok (xAI)"),
        ("mistral", "MISTRAL_API_KEY", "Mistral AI"),
        ("cohere", "COHERE_API_KEY", "Cohere"),
        ("groq", "GROQ_API_KEY", "Groq (fast)"),
        ("together", "TOGETHER_API_KEY", "Together AI"),
        ("fireworks", "FIREWORKS_API_KEY", "Fireworks AI"),
        ("ollama", "OLLAMA_BASE_URL", "Ollama (local)"),
    ]
    
    print(f"{'Provider':<12} {'Status':<8} {'Name':<20} {'Default Model'}")
    print("-"*70)
    
    for provider, env_var, name in providers_info:
        configured = "[OK]" if os.getenv(env_var) else "[  ]"
        default_model = DEFAULT_MODELS.get(provider, "N/A")
        # Truncate long model names
        model_display = default_model[:30] + "..." if len(default_model) > 30 else default_model
        print(f"{provider:<12} {configured:<8} {name:<20} {model_display}")
    
    print("-"*70)
    print(f"Current provider: {DEFAULT_PROVIDER}")
    print("="*70)


if __name__ == "__main__":
    list_providers()

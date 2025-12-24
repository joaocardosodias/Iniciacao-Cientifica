"""
OpenAI-Compatible API Providers

Base class for providers that use OpenAI-compatible APIs.
Includes: Groq, Cerebras, Grok (xAI), DeepSeek, Together AI

Requirements: 2.x - Support multiple LLM providers
"""

from typing import Optional

from fragmentum.web.backend.ai.providers.openai import OpenAIProvider
from fragmentum.web.backend.ai.providers import (
    LLMProviderType,
    ConfigurationError,
)


class OpenAICompatibleProvider(OpenAIProvider):
    """
    Base class for OpenAI-compatible API providers.
    
    Many providers (Groq, Cerebras, etc.) use the same API format as OpenAI,
    just with different base URLs and models.
    """
    
    PROVIDER_NAME: str = "openai_compatible"
    DEFAULT_BASE_URL: str = ""
    DEFAULT_MODEL: str = ""
    AVAILABLE_MODELS: list = []
    
    def __init__(
        self,
        api_key: str,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        """
        Initialize the OpenAI-compatible provider.
        
        Args:
            api_key: API key for the provider
            model: Model to use (uses provider default if not specified)
            base_url: Custom base URL (uses provider default if not specified)
        """
        if not api_key:
            raise ConfigurationError(f"API key is required for {self.PROVIDER_NAME}")
        
        super().__init__(
            api_key=api_key,
            model=model or self.DEFAULT_MODEL,
            base_url=base_url or self.DEFAULT_BASE_URL,
        )


class GroqProvider(OpenAICompatibleProvider):
    """
    Groq API provider - Ultra-fast inference.
    
    Groq offers extremely fast inference with their LPU hardware.
    Supports Llama, Mixtral, and Gemma models.
    """
    
    PROVIDER_NAME = "groq"
    DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"
    DEFAULT_MODEL = "llama-3.3-70b-versatile"
    AVAILABLE_MODELS = [
        "llama-3.3-70b-versatile",
        "llama-3.1-70b-versatile", 
        "llama-3.1-8b-instant",
        "llama3-70b-8192",
        "llama3-8b-8192",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
    ]
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.GROQ


class CerebrasProvider(OpenAICompatibleProvider):
    """
    Cerebras API provider - Fast inference on Cerebras hardware.
    
    Cerebras offers fast inference with their wafer-scale chips.
    """
    
    PROVIDER_NAME = "cerebras"
    DEFAULT_BASE_URL = "https://api.cerebras.ai/v1"
    DEFAULT_MODEL = "llama3.1-70b"
    AVAILABLE_MODELS = [
        "llama3.1-70b",
        "llama3.1-8b",
    ]
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.CEREBRAS


class GrokProvider(OpenAICompatibleProvider):
    """
    Grok (xAI) API provider - Elon Musk's AI.
    
    xAI's Grok models with real-time knowledge.
    """
    
    PROVIDER_NAME = "grok"
    DEFAULT_BASE_URL = "https://api.x.ai/v1"
    DEFAULT_MODEL = "grok-beta"
    AVAILABLE_MODELS = [
        "grok-beta",
        "grok-2-1212",
        "grok-2-vision-1212",
    ]
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.GROK


class DeepSeekProvider(OpenAICompatibleProvider):
    """
    DeepSeek API provider - Chinese AI lab.
    
    DeepSeek offers powerful models at competitive prices.
    DeepSeek-V3 is particularly strong for coding tasks.
    """
    
    PROVIDER_NAME = "deepseek"
    DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
    DEFAULT_MODEL = "deepseek-chat"
    AVAILABLE_MODELS = [
        "deepseek-chat",
        "deepseek-coder",
        "deepseek-reasoner",
    ]
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.DEEPSEEK


class TogetherProvider(OpenAICompatibleProvider):
    """
    Together AI API provider - Open source model hosting.
    
    Together AI hosts many open source models with fast inference.
    """
    
    PROVIDER_NAME = "together"
    DEFAULT_BASE_URL = "https://api.together.xyz/v1"
    DEFAULT_MODEL = "meta-llama/Llama-3.3-70B-Instruct-Turbo"
    AVAILABLE_MODELS = [
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
        "mistralai/Mixtral-8x22B-Instruct-v0.1",
        "mistralai/Mistral-7B-Instruct-v0.3",
        "Qwen/Qwen2.5-72B-Instruct-Turbo",
        "deepseek-ai/DeepSeek-V3",
    ]
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.TOGETHER


__all__ = [
    "OpenAICompatibleProvider",
    "GroqProvider",
    "CerebrasProvider",
    "GrokProvider",
    "DeepSeekProvider",
    "TogetherProvider",
]

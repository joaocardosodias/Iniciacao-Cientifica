"""
LLM Provider Abstraction Layer

Provides a unified interface for different LLM providers (Claude, OpenAI, Ollama).
Supports streaming chat with function calling for tool execution.

Requirements: 2.1, 2.2, 2.3 - Support multiple LLM providers
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional


class LLMProviderType(str, Enum):
    """Supported LLM provider types."""
    CLAUDE = "claude"
    OPENAI = "openai"
    OLLAMA = "ollama"
    GEMINI = "gemini"
    GROQ = "groq"
    CEREBRAS = "cerebras"
    GROK = "grok"
    DEEPSEEK = "deepseek"
    TOGETHER = "together"
    MISTRAL = "mistral"


@dataclass
class ToolSchema:
    """Schema for a tool that can be called by the LLM."""
    name: str
    description: str
    parameters: Dict[str, Any]
    required: List[str] = field(default_factory=list)


@dataclass
class ToolCall:
    """Represents a tool call request from the LLM."""
    id: str
    name: str
    parameters: Dict[str, Any]


@dataclass
class ChatMessage:
    """A message in the chat conversation."""
    role: str  # "user", "assistant", "system", "tool"
    content: str
    tool_calls: Optional[List[ToolCall]] = None
    tool_call_id: Optional[str] = None  # For tool response messages
    name: Optional[str] = None  # Tool name for tool responses


@dataclass
class StreamEvent:
    """Event emitted during streaming response."""
    type: str  # "text", "tool_call", "error", "done"
    content: Optional[str] = None
    tool_call: Optional[ToolCall] = None
    error: Optional[str] = None


class LLMProviderError(Exception):
    """Base exception for LLM provider errors."""
    pass


class ConfigurationError(LLMProviderError):
    """Raised when provider configuration is invalid."""
    pass


class APIError(LLMProviderError):
    """Raised when API call fails."""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class RateLimitError(APIError):
    """Raised when rate limit is exceeded."""
    pass


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.
    
    Defines the interface that all LLM providers must implement to support
    streaming chat with function calling capabilities.
    
    Requirements:
    - 2.1: Support Claude API
    - 2.2: Support OpenAI API  
    - 2.3: Support Ollama local models
    """
    
    @property
    @abstractmethod
    def provider_type(self) -> LLMProviderType:
        """Return the provider type identifier."""
        pass
    
    @property
    @abstractmethod
    def model(self) -> str:
        """Return the current model name."""
        pass
    
    @abstractmethod
    async def chat(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolSchema]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = True
    ) -> AsyncIterator[StreamEvent]:
        """
        Send a chat request and stream the response.
        
        Args:
            messages: List of chat messages in the conversation
            tools: Optional list of tools the LLM can call
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens in response
            stream: Whether to stream the response
            
        Yields:
            StreamEvent objects containing text chunks, tool calls, or errors
        """
        pass
    
    @abstractmethod
    async def validate_config(self) -> bool:
        """
        Validate the provider configuration.
        
        Returns:
            True if configuration is valid and provider is ready
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        pass
    
    @abstractmethod
    def get_tools_schema(self, tools: List[ToolSchema]) -> List[Dict[str, Any]]:
        """
        Convert tool schemas to provider-specific format.
        
        Args:
            tools: List of ToolSchema objects
            
        Returns:
            List of tool definitions in provider-specific format
        """
        pass
    
    def _build_system_prompt(self, base_prompt: str) -> str:
        """
        Build the system prompt with provider-specific adjustments.
        
        Args:
            base_prompt: The base system prompt
            
        Returns:
            Adjusted system prompt for this provider
        """
        return base_prompt


def get_provider(
    provider_type: LLMProviderType,
    **kwargs
) -> "LLMProvider":
    """
    Factory function to create an LLM provider instance.
    
    Args:
        provider_type: The type of provider to create
        **kwargs: Provider-specific configuration
        
    Returns:
        An instance of the requested provider
        
    Raises:
        ConfigurationError: If provider type is invalid or config is missing
    """
    from fragmentum.web.backend.ai.providers.claude import ClaudeProvider
    from fragmentum.web.backend.ai.providers.openai import OpenAIProvider
    from fragmentum.web.backend.ai.providers.ollama import OllamaProvider
    from fragmentum.web.backend.ai.providers.gemini import GeminiProvider
    from fragmentum.web.backend.ai.providers.mistral import MistralProvider
    from fragmentum.web.backend.ai.providers.openai_compatible import (
        GroqProvider,
        CerebrasProvider,
        GrokProvider,
        DeepSeekProvider,
        TogetherProvider,
    )
    
    providers = {
        LLMProviderType.CLAUDE: ClaudeProvider,
        LLMProviderType.OPENAI: OpenAIProvider,
        LLMProviderType.OLLAMA: OllamaProvider,
        LLMProviderType.GEMINI: GeminiProvider,
        LLMProviderType.GROQ: GroqProvider,
        LLMProviderType.CEREBRAS: CerebrasProvider,
        LLMProviderType.GROK: GrokProvider,
        LLMProviderType.DEEPSEEK: DeepSeekProvider,
        LLMProviderType.TOGETHER: TogetherProvider,
        LLMProviderType.MISTRAL: MistralProvider,
    }
    
    if provider_type not in providers:
        raise ConfigurationError(f"Unknown provider type: {provider_type}")
    
    return providers[provider_type](**kwargs)


__all__ = [
    "LLMProvider",
    "LLMProviderType",
    "LLMProviderError",
    "ConfigurationError",
    "APIError",
    "RateLimitError",
    "ToolSchema",
    "ToolCall",
    "ChatMessage",
    "StreamEvent",
    "get_provider",
]

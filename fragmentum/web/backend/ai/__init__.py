"""
FRAGMENTUM AI Chat Integration

This module provides AI-powered chat capabilities for the FRAGMENTUM Web UI,
allowing users to interact with pentesting tools using natural language.
"""

from fragmentum.web.backend.ai.providers import (
    LLMProvider,
    LLMProviderType,
    LLMProviderError,
    ConfigurationError,
    APIError,
    RateLimitError,
    ToolSchema,
    ToolCall as ProviderToolCall,
    ChatMessage as ProviderChatMessage,
    StreamEvent,
    get_provider,
)

from fragmentum.web.backend.ai.context import (
    ContextBuilder,
    TargetContext,
    SessionContext,
    DynamicContextInjector,
    get_context_builder,
    reset_context_builder,
    load_dynamic_context,
    build_chat_context,
    DANGEROUS_CATEGORIES,
    DANGEROUS_TOOL_PATTERNS,
)

from fragmentum.web.backend.ai.models import (
    MessageRole,
    ToolExecutionStatus,
    FindingSeverity,
    FindingType,
    Finding,
    ToolCall,
    ToolExecution,
    ChatMessage,
    ChatSession,
    ChatSessionSummary,
    ChatMessageRequest,
    ChatConfigUpdate,
    ChatConfig,
    ConfirmationResponse,
)

from fragmentum.web.backend.ai.session_store import (
    SessionStore,
    SessionStoreError,
    SessionNotFoundError,
    get_session_store,
    reset_session_store,
)

__all__ = [
    # Providers
    "LLMProvider",
    "LLMProviderType",
    "LLMProviderError",
    "ConfigurationError",
    "APIError",
    "RateLimitError",
    "ToolSchema",
    "ProviderToolCall",
    "ProviderChatMessage",
    "StreamEvent",
    "get_provider",
    # Context
    "ContextBuilder",
    "TargetContext",
    "SessionContext",
    "DynamicContextInjector",
    "get_context_builder",
    "reset_context_builder",
    "load_dynamic_context",
    "build_chat_context",
    "DANGEROUS_CATEGORIES",
    "DANGEROUS_TOOL_PATTERNS",
    # Models
    "MessageRole",
    "ToolExecutionStatus",
    "FindingSeverity",
    "FindingType",
    "Finding",
    "ToolCall",
    "ToolExecution",
    "ChatMessage",
    "ChatSession",
    "ChatSessionSummary",
    "ChatMessageRequest",
    "ChatConfigUpdate",
    "ChatConfig",
    "ConfirmationResponse",
    # Session Store
    "SessionStore",
    "SessionStoreError",
    "SessionNotFoundError",
    "get_session_store",
    "reset_session_store",
]

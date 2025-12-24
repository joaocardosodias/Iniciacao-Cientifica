"""
Chat API Endpoints for AI Chat Integration.

Provides REST and streaming endpoints for AI chat interactions,
session management, configuration, and tool execution confirmations.

Requirements:
- 1.1: Interpret user intent and respond appropriately
- 1.3: Display real-time output in chat interface
- 4.2: Stream output lines to chat interface
- 5.2: Restore previous conversation history
- 5.4: Allow starting fresh conversation
- 2.1, 2.2, 2.3, 2.4: LLM provider configuration
- 8.1, 7.4: Safety confirmations for dangerous operations
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from fragmentum.web.backend.api.auth import get_api_key, optional_api_key
from fragmentum.web.backend.ai.models import (
    ChatSession,
    ChatSessionSummary,
    ChatMessage,
    ChatMessageRequest,
    ChatConfig,
    ChatConfigUpdate,
    ConfirmationResponse,
    MessageRole,
    ToolExecution,
    ToolCall,
)
from fragmentum.web.backend.ai.session_store import (
    get_session_store,
    SessionStore,
    SessionNotFoundError,
)
from fragmentum.web.backend.ai.chat_service import (
    ChatService,
    ChatEvent,
    ChatEventType,
    get_attack_planner,
    AttackPlan,
    PlanStatus,
)
from fragmentum.web.backend.ai.providers import (
    LLMProvider,
    LLMProviderType,
    ChatMessage as ProviderChatMessage,
    get_provider,
    ConfigurationError,
)
from fragmentum.web.backend.ai.context import get_context_builder, load_dynamic_context


router = APIRouter(prefix="/chat", tags=["chat"])


# Configuration storage (in production, use secure storage)
_chat_config: Dict[str, Any] = {
    "provider": "groq",
    "model": "llama-3.3-70b-versatile",
    "ollama_url": "http://localhost:11434",
    "temperature": 0.7,
    "max_tokens": 4096,
}

# API keys storage (in production, use secure encrypted storage)
_api_keys: Dict[str, str] = {}

# Active chat service instance
_chat_service: Optional[ChatService] = None


def get_chat_config() -> Dict[str, Any]:
    """Get the current chat configuration."""
    return _chat_config.copy()


def set_chat_config(config: Dict[str, Any]) -> None:
    """Update the chat configuration."""
    global _chat_config, _chat_service
    _chat_config.update(config)
    # Reset chat service to use new config
    _chat_service = None


def get_api_key_for_provider(provider: str) -> Optional[str]:
    """Get the API key for a provider."""
    # Check environment variables first
    env_keys = {
        "claude": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "groq": "GROQ_API_KEY",
        "cerebras": "CEREBRAS_API_KEY",
        "grok": "GROK_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "together": "TOGETHER_API_KEY",
        "mistral": "MISTRAL_API_KEY",
        "gemini": "GEMINI_API_KEY",
    }
    if provider in env_keys:
        env_key = os.environ.get(env_keys[provider])
        if env_key:
            return env_key
    
    # Fall back to stored keys
    return _api_keys.get(provider)


def set_api_key_for_provider(provider: str, api_key: str) -> None:
    """Store an API key for a provider."""
    _api_keys[provider] = api_key


async def get_chat_service() -> ChatService:
    """
    Get or create the chat service instance.
    
    Returns:
        ChatService instance configured with current settings
    """
    global _chat_service
    
    if _chat_service is None:
        config = get_chat_config()
        provider_type = LLMProviderType(config["provider"])
        
        # Build provider kwargs
        provider_kwargs: Dict[str, Any] = {
            "model": config.get("model"),
        }
        
        if provider_type == LLMProviderType.OLLAMA:
            provider_kwargs["base_url"] = config.get("ollama_url", "http://localhost:11434")
        else:
            api_key = get_api_key_for_provider(config["provider"])
            if not api_key:
                raise ConfigurationError(
                    f"API key not configured for {config['provider']}. "
                    "Please configure the API key in settings."
                )
            provider_kwargs["api_key"] = api_key
        
        provider = get_provider(provider_type, **provider_kwargs)
        
        # Load dynamic context
        context_builder = await load_dynamic_context()
        
        _chat_service = ChatService(
            provider=provider,
            context_builder=context_builder,
        )
    
    return _chat_service


def reset_chat_service() -> None:
    """Reset the chat service (for config changes)."""
    global _chat_service
    _chat_service = None
    # Also reset context builder to pick up any changes
    from fragmentum.web.backend.ai.context import reset_context_builder
    reset_context_builder()


# Request/Response Models

class ChatStreamEvent(BaseModel):
    """Event sent during chat streaming."""
    type: str
    content: Optional[str] = None
    tool_name: Optional[str] = None
    execution_id: Optional[str] = None
    output: Optional[str] = None
    finding: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    summary: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SessionListResponse(BaseModel):
    """Response for listing sessions."""
    sessions: List[ChatSessionSummary]
    total: int


class ConfigStatusResponse(BaseModel):
    """Response for configuration status."""
    configured: bool
    provider: str
    model: str
    has_api_key: bool
    message: Optional[str] = None


# Helper functions

async def event_to_sse(event: ChatEvent) -> str:
    """Convert a ChatEvent to SSE format."""
    data = {
        "type": event.type.value,
        "content": event.content,
        "tool_name": event.tool_name,
        "execution_id": event.execution_id,
        "output": event.output,
        "finding": event.finding,
        "message": event.message,
        "summary": event.summary,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
    }
    # Remove None values
    data = {k: v for k, v in data.items() if v is not None}
    return f"data: {json.dumps(data)}\n\n"


async def stream_chat_response(
    chat_service: ChatService,
    message: str,
    session: ChatSession,
) -> AsyncIterator[str]:
    """
    Stream chat response as SSE events.
    
    Args:
        chat_service: The chat service instance
        message: User message
        session: Chat session
        
    Yields:
        SSE formatted event strings
        
    Requirements: 1.1, 1.3, 4.2
    """
    session_store = get_session_store()
    
    # Convert session messages to provider format
    history: List[ProviderChatMessage] = []
    for msg in session.messages[-20:]:  # Limit history to last 20 messages
        history.append(ProviderChatMessage(
            role=msg.role,
            content=msg.content,
        ))
    
    # Add user message to session
    session.add_message(role=MessageRole.USER, content=message)
    session_store.save(session)
    
    # Accumulate assistant response
    assistant_content = ""
    current_tool_execution: Optional[ToolExecution] = None
    
    try:
        async for event in chat_service.process_message(
            message=message,
            conversation_history=history,
            session_id=session.id,
        ):
            # Yield SSE event
            yield await event_to_sse(event)
            
            # Track content for session storage
            if event.type == ChatEventType.TEXT and event.content:
                assistant_content += event.content
            
            elif event.type == ChatEventType.TOOL_START:
                current_tool_execution = ToolExecution(
                    tool_name=event.tool_name or "",
                    parameters={},
                    status="running",
                    started_at=datetime.utcnow(),
                )
            
            elif event.type == ChatEventType.TOOL_OUTPUT and current_tool_execution:
                current_tool_execution.output.append(event.output or "")
            
            elif event.type == ChatEventType.TOOL_COMPLETE and current_tool_execution:
                current_tool_execution.status = "completed"
                current_tool_execution.completed_at = datetime.utcnow()
                current_tool_execution.summary = event.summary
                
                # Add tool execution message to session
                session.add_message(
                    role=MessageRole.TOOL,
                    content=event.summary or "",
                    tool_execution=current_tool_execution,
                )
                current_tool_execution = None
            
            elif event.type == ChatEventType.TOOL_ERROR and current_tool_execution:
                current_tool_execution.status = "error"
                current_tool_execution.error = event.message
                current_tool_execution.completed_at = datetime.utcnow()
                
                session.add_message(
                    role=MessageRole.TOOL,
                    content=event.message or "Tool execution failed",
                    tool_execution=current_tool_execution,
                )
                current_tool_execution = None
            
            elif event.type == ChatEventType.DONE:
                # Save assistant response if we have content
                if assistant_content:
                    session.add_message(
                        role=MessageRole.ASSISTANT,
                        content=assistant_content,
                    )
                session_store.save(session)
    
    except Exception as e:
        error_event = ChatEvent(
            type=ChatEventType.ERROR,
            message=f"Error: {str(e)}",
        )
        yield await event_to_sse(error_event)
        
        # Save error to session
        session.add_message(
            role=MessageRole.SYSTEM,
            content=f"Error occurred: {str(e)}",
        )
        session_store.save(session)


# Endpoints

@router.post(
    "/message",
    summary="Send a chat message",
    description="Send a message and receive streaming response - Requirements 1.1, 1.3, 4.2",
)
async def send_message(
    request: ChatMessageRequest,
    api_key: str = Depends(optional_api_key),
) -> StreamingResponse:
    """
    Send a chat message and receive streaming response.
    
    The response is streamed as Server-Sent Events (SSE) with the following event types:
    - text: Text content from the AI
    - tool_start: Tool execution started
    - tool_output: Tool output line
    - tool_complete: Tool execution completed with summary
    - tool_error: Tool execution failed
    - finding: Security finding discovered
    - confirmation_required: Dangerous operation needs confirmation
    - error: Error occurred
    - done: Response complete
    
    Requirements: 1.1, 1.3, 4.2
    """
    try:
        chat_service = await get_chat_service()
    except ConfigurationError as e:
        raise HTTPException(
            status_code=503,
            detail=str(e),
        )
    
    session_store = get_session_store()
    
    # Get or create session
    if request.session_id:
        try:
            session = session_store.get(request.session_id)
        except SessionNotFoundError:
            session = session_store.create(title=f"Chat {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}")
    else:
        session = session_store.get_or_create(
            title=f"Chat {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
        )
    
    return StreamingResponse(
        stream_chat_response(chat_service, request.content, session),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Session-Id": session.id,
        },
    )


# Session Management Endpoints - Requirements 5.2, 5.4

@router.get(
    "/sessions",
    response_model=SessionListResponse,
    summary="List chat sessions",
    description="List all chat sessions with summaries - Requirements 5.2",
)
async def list_sessions(
    limit: Optional[int] = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    api_key: str = Depends(optional_api_key),
) -> SessionListResponse:
    """
    List all chat sessions.
    
    Returns session summaries sorted by most recently updated.
    
    Requirements: 5.2
    """
    session_store = get_session_store()
    
    # Get all sessions for total count
    all_sessions = session_store.list_sessions()
    total = len(all_sessions)
    
    # Apply pagination
    sessions = session_store.list_sessions(limit=limit, offset=offset)
    
    return SessionListResponse(
        sessions=sessions,
        total=total,
    )


@router.get(
    "/sessions/{session_id}",
    response_model=ChatSession,
    summary="Get chat session",
    description="Get a chat session with full message history - Requirements 5.2",
)
async def get_session(
    session_id: str,
    api_key: str = Depends(optional_api_key),
) -> ChatSession:
    """
    Get a chat session with full message history.
    
    Requirements: 5.2 - Restore previous conversation history
    """
    session_store = get_session_store()
    
    try:
        session = session_store.get(session_id)
        return session
    except SessionNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Session not found: {session_id}",
        )


@router.delete(
    "/sessions/{session_id}",
    summary="Delete chat session",
    description="Delete a chat session - Requirements 5.4",
)
async def delete_session(
    session_id: str,
    api_key: str = Depends(optional_api_key),
) -> Dict[str, str]:
    """
    Delete a chat session.
    
    Requirements: 5.4 - Allow starting fresh conversation
    """
    session_store = get_session_store()
    
    if not session_store.session_exists(session_id):
        raise HTTPException(
            status_code=404,
            detail=f"Session not found: {session_id}",
        )
    
    session_store.delete(session_id)
    
    return {"message": f"Session {session_id} deleted"}


@router.post(
    "/sessions",
    response_model=ChatSession,
    summary="Create new chat session",
    description="Create a new chat session - Requirements 5.1",
)
async def create_session(
    title: Optional[str] = None,
    api_key: str = Depends(optional_api_key),
) -> ChatSession:
    """
    Create a new chat session.
    
    Requirements: 5.1 - Create new Chat_Session with unique identifier
    """
    session_store = get_session_store()
    
    if not title:
        title = f"Chat {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
    
    session = session_store.create(title=title)
    
    return session


# Configuration Endpoints - Requirements 2.1, 2.2, 2.3, 2.4

@router.get(
    "/config",
    response_model=ChatConfig,
    summary="Get chat configuration",
    description="Get current LLM configuration - Requirements 2.1, 2.2, 2.3",
)
async def get_config(
    api_key: str = Depends(optional_api_key),
) -> ChatConfig:
    """
    Get current chat configuration.
    
    Note: API keys are never returned in responses for security.
    
    Requirements: 2.1, 2.2, 2.3
    """
    config = get_chat_config()
    
    return ChatConfig(
        provider=config["provider"],
        model=config["model"],
        ollama_url=config.get("ollama_url", "http://localhost:11434"),
        temperature=config.get("temperature", 0.7),
        max_tokens=config.get("max_tokens", 4096),
    )


@router.put(
    "/config",
    response_model=ChatConfig,
    summary="Update chat configuration",
    description="Update LLM configuration - Requirements 2.1, 2.2, 2.3, 2.4",
)
async def update_config(
    config_update: ChatConfigUpdate,
    api_key: str = Depends(optional_api_key),
) -> ChatConfig:
    """
    Update chat configuration.
    
    Supports updating:
    - provider: "claude", "openai", or "ollama"
    - model: Model name for the provider
    - api_key: API key (stored securely, not returned)
    - ollama_url: URL for Ollama server
    - temperature: Sampling temperature
    - max_tokens: Maximum response tokens
    
    Requirements: 2.1, 2.2, 2.3, 2.4
    """
    current_config = get_chat_config()
    
    # Update provider if specified
    if config_update.provider:
        valid_providers = ["claude", "openai", "ollama", "groq", "cerebras", "grok", "deepseek", "together", "mistral", "gemini"]
        if config_update.provider not in valid_providers:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider. Must be one of: {valid_providers}",
            )
        current_config["provider"] = config_update.provider
    
    # Update model if specified
    if config_update.model:
        current_config["model"] = config_update.model
    
    # Update API key if specified (store securely)
    if config_update.api_key:
        provider = config_update.provider or current_config["provider"]
        set_api_key_for_provider(provider, config_update.api_key)
    
    # Update Ollama URL if specified
    if config_update.ollama_url:
        current_config["ollama_url"] = config_update.ollama_url
    
    # Update temperature if specified
    if config_update.temperature is not None:
        if not 0.0 <= config_update.temperature <= 2.0:
            raise HTTPException(
                status_code=400,
                detail="Temperature must be between 0.0 and 2.0",
            )
        current_config["temperature"] = config_update.temperature
    
    # Update max_tokens if specified
    if config_update.max_tokens is not None:
        if not 1 <= config_update.max_tokens <= 100000:
            raise HTTPException(
                status_code=400,
                detail="max_tokens must be between 1 and 100000",
            )
        current_config["max_tokens"] = config_update.max_tokens
    
    # Save configuration
    set_chat_config(current_config)
    
    # Reset chat service to use new config
    reset_chat_service()
    
    return ChatConfig(
        provider=current_config["provider"],
        model=current_config["model"],
        ollama_url=current_config.get("ollama_url", "http://localhost:11434"),
        temperature=current_config.get("temperature", 0.7),
        max_tokens=current_config.get("max_tokens", 4096),
    )


@router.get(
    "/config/status",
    response_model=ConfigStatusResponse,
    summary="Get configuration status",
    description="Check if chat is properly configured - Requirements 2.4",
)
async def get_config_status(
    api_key: str = Depends(optional_api_key),
) -> ConfigStatusResponse:
    """
    Check if chat is properly configured.
    
    Returns whether the current provider has required configuration
    (API key for cloud providers, or Ollama server availability).
    
    Requirements: 2.4 - Display setup prompt with instructions
    """
    config = get_chat_config()
    provider = config["provider"]
    
    # Check if API key is configured for cloud providers
    has_api_key = False
    message = None
    
    # Providers that require API keys
    cloud_providers = ["claude", "openai", "groq", "cerebras", "grok", "deepseek", "together", "mistral", "gemini"]
    
    if provider in cloud_providers:
        api_key_value = get_api_key_for_provider(provider)
        has_api_key = bool(api_key_value)
        
        if has_api_key:
            message = f"Using {provider.capitalize()} with model {config['model']}"
        else:
            env_var_map = {
                "claude": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
                "groq": "GROQ_API_KEY",
                "cerebras": "CEREBRAS_API_KEY",
                "grok": "GROK_API_KEY",
                "deepseek": "DEEPSEEK_API_KEY",
                "together": "TOGETHER_API_KEY",
                "mistral": "MISTRAL_API_KEY",
                "gemini": "GEMINI_API_KEY",
            }
            env_var = env_var_map.get(provider, f"{provider.upper()}_API_KEY")
            message = (
                f"API key not configured for {provider}. "
                f"Please set the API key in configuration or use the "
                f"{env_var} environment variable."
            )
    elif provider == "ollama":
        # Ollama doesn't need API key
        has_api_key = True
        message = f"Using Ollama at {config.get('ollama_url', 'http://localhost:11434')}"
    else:
        # Unknown provider
        has_api_key = False
        message = f"Unknown provider: {provider}"
    
    return ConfigStatusResponse(
        configured=has_api_key,
        provider=provider,
        model=config["model"],
        has_api_key=has_api_key,
        message=message,
    )


# Confirmation Endpoint - Requirements 8.1, 7.4

class ConfirmationRequest(BaseModel):
    """Request to confirm or cancel a pending execution."""
    confirmed: bool


@router.post(
    "/confirm/{execution_id}",
    response_model=ConfirmationResponse,
    summary="Confirm or cancel pending execution",
    description="Resume or cancel a pending tool execution - Requirements 8.1, 7.4",
)
async def confirm_execution(
    execution_id: str,
    request: ConfirmationRequest,
    api_key: str = Depends(optional_api_key),
) -> StreamingResponse:
    """
    Confirm or cancel a pending tool execution.
    
    When a dangerous operation is requested, the chat service pauses
    and waits for user confirmation. This endpoint resumes or cancels
    the pending execution.
    
    Requirements:
    - 8.1: Require explicit user confirmation for exploitation tools
    - 7.4: Confirm with user before attempting exploitation
    """
    try:
        chat_service = await get_chat_service()
    except ConfigurationError as e:
        raise HTTPException(
            status_code=503,
            detail=str(e),
        )
    
    # Check if execution exists
    execution = chat_service.get_execution(execution_id)
    if not execution:
        raise HTTPException(
            status_code=404,
            detail=f"Execution not found: {execution_id}",
        )
    
    async def stream_confirmation_response() -> AsyncIterator[str]:
        """Stream the confirmation response."""
        async for event in chat_service.confirm_execution(
            execution_id=execution_id,
            confirmed=request.confirmed,
        ):
            yield await event_to_sse(event)
    
    return StreamingResponse(
        stream_confirmation_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.get(
    "/pending",
    summary="Get pending confirmations",
    description="Get list of pending tool execution confirmations",
)
async def get_pending_confirmations(
    api_key: str = Depends(optional_api_key),
) -> List[Dict[str, Any]]:
    """
    Get list of pending tool execution confirmations.
    
    Returns all executions that are waiting for user confirmation
    before proceeding with dangerous operations.
    
    Requirements: 8.1
    """
    try:
        chat_service = await get_chat_service()
    except ConfigurationError:
        return []
    
    pending = chat_service.get_pending_confirmations()
    
    return [
        {
            "execution_id": p.execution_id,
            "tool_name": p.tool_name,
            "parameters": p.parameters,
            "warning_message": p.warning_message,
            "created_at": p.created_at.isoformat(),
        }
        for p in pending
    ]


# Multi-Step Attack Planning Endpoints - Requirements 7.1, 7.2, 7.3, 7.4, 7.5

class AssessmentRequest(BaseModel):
    """Request to start a full assessment."""
    target: str
    include_exploitation: bool = False
    session_id: Optional[str] = None


class PlanActionRequest(BaseModel):
    """Request to perform an action on a plan."""
    action: str  # "skip", "retry", "cancel", "resume"


@router.post(
    "/assessment",
    summary="Start full security assessment",
    description="Start a multi-step security assessment - Requirements 7.1, 7.2",
)
async def start_assessment(
    request: AssessmentRequest,
    api_key: str = Depends(optional_api_key),
) -> StreamingResponse:
    """
    Start a full security assessment on a target.
    
    This creates a multi-step attack plan and executes it sequentially,
    adapting based on findings and pausing for confirmations when needed.
    
    Requirements:
    - 7.1: Plan and execute multiple tools in sequence
    - 7.2: Explain each step before executing
    - 7.3: Adapt subsequent steps based on discoveries
    - 7.4: Confirm with user before exploitation
    - 7.5: Pause on errors and ask how to proceed
    """
    try:
        chat_service = await get_chat_service()
    except ConfigurationError as e:
        raise HTTPException(
            status_code=503,
            detail=str(e),
        )
    
    session_store = get_session_store()
    
    # Get or create session
    if request.session_id:
        try:
            session = session_store.get(request.session_id)
        except SessionNotFoundError:
            session = session_store.create(title=f"Assessment: {request.target}")
    else:
        session = session_store.create(title=f"Assessment: {request.target}")
    
    # Create the assessment message
    message = f"Run a full security assessment on {request.target}"
    if request.include_exploitation:
        message += " including exploitation attempts"
    
    async def stream_assessment_response() -> AsyncIterator[str]:
        """Stream the assessment response."""
        # Add user message to session
        session.add_message(role=MessageRole.USER, content=message)
        session_store.save(session)
        
        async for event in chat_service.process_full_assessment(
            message=message,
            conversation_history=None,
        ):
            yield await event_to_sse(event)
            
            # Save significant events to session
            if event.type == ChatEventType.PLAN_COMPLETE:
                session.add_message(
                    role=MessageRole.ASSISTANT,
                    content=event.content or "Assessment completed",
                )
                session_store.save(session)
    
    return StreamingResponse(
        stream_assessment_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Session-Id": session.id,
        },
    )


@router.get(
    "/plans",
    summary="List active attack plans",
    description="Get list of active attack plans",
)
async def list_plans(
    api_key: str = Depends(optional_api_key),
) -> List[Dict[str, Any]]:
    """
    Get list of active attack plans.
    
    Returns all plans that are in progress, paused, or awaiting confirmation.
    """
    planner = get_attack_planner()
    
    plans = []
    for plan in planner._active_plans.values():
        plans.append({
            "id": plan.id,
            "target": plan.target,
            "description": plan.description,
            "status": plan.status.value,
            "progress": plan.progress_percentage,
            "total_steps": len(plan.steps),
            "completed_steps": len(plan.completed_steps),
            "current_step_index": plan.current_step_index,
            "findings_count": len(plan.all_findings),
            "created_at": plan.created_at.isoformat(),
            "updated_at": plan.updated_at.isoformat(),
        })
    
    return plans


@router.get(
    "/plans/{plan_id}",
    summary="Get attack plan details",
    description="Get detailed information about an attack plan",
)
async def get_plan(
    plan_id: str,
    api_key: str = Depends(optional_api_key),
) -> Dict[str, Any]:
    """
    Get detailed information about an attack plan.
    
    Returns the full plan including all steps, findings, and status.
    """
    planner = get_attack_planner()
    plan = planner.get_plan(plan_id)
    
    if not plan:
        raise HTTPException(
            status_code=404,
            detail=f"Plan not found: {plan_id}",
        )
    
    return {
        "id": plan.id,
        "target": plan.target,
        "description": plan.description,
        "status": plan.status.value,
        "progress": plan.progress_percentage,
        "current_step_index": plan.current_step_index,
        "error_message": plan.error_message,
        "created_at": plan.created_at.isoformat(),
        "updated_at": plan.updated_at.isoformat(),
        "steps": [
            {
                "id": step.id,
                "phase": step.phase.value,
                "tool_name": step.tool_name,
                "description": step.description,
                "rationale": step.rationale,
                "status": step.status.value,
                "requires_confirmation": step.requires_confirmation,
                "error": step.error,
                "findings_count": len(step.findings),
                "started_at": step.started_at.isoformat() if step.started_at else None,
                "completed_at": step.completed_at.isoformat() if step.completed_at else None,
            }
            for step in plan.steps
        ],
        "all_findings": plan.all_findings,
        "discovered_services": plan.discovered_services,
        "discovered_vulnerabilities": plan.discovered_vulnerabilities,
    }


@router.post(
    "/plans/{plan_id}/action",
    summary="Perform action on attack plan",
    description="Skip, retry, cancel, or resume an attack plan - Requirements 7.5",
)
async def plan_action(
    plan_id: str,
    request: PlanActionRequest,
    api_key: str = Depends(optional_api_key),
) -> StreamingResponse:
    """
    Perform an action on an attack plan.
    
    Actions:
    - skip: Skip the current errored step and continue
    - retry: Retry the current errored step
    - cancel: Cancel the entire plan
    - resume: Resume a paused plan
    
    Requirements: 7.5 - Pause on errors and ask how to proceed
    """
    try:
        chat_service = await get_chat_service()
    except ConfigurationError as e:
        raise HTTPException(
            status_code=503,
            detail=str(e),
        )
    
    planner = get_attack_planner()
    plan = planner.get_plan(plan_id)
    
    if not plan:
        raise HTTPException(
            status_code=404,
            detail=f"Plan not found: {plan_id}",
        )
    
    valid_actions = ["skip", "retry", "cancel", "resume"]
    if request.action not in valid_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action. Must be one of: {valid_actions}",
        )
    
    async def stream_action_response() -> AsyncIterator[str]:
        """Stream the action response."""
        if request.action == "resume":
            # Resume a paused plan
            step = planner.resume_plan(plan_id)
            if step:
                async for event in chat_service._execute_attack_plan(plan_id):
                    yield await event_to_sse(event)
            else:
                yield await event_to_sse(ChatEvent(
                    type=ChatEventType.ERROR,
                    message="Cannot resume plan - not in paused state",
                ))
        else:
            # Handle error response (skip, retry, cancel)
            async for event in chat_service.handle_plan_error_response(
                plan_id=plan_id,
                action=request.action,
            ):
                yield await event_to_sse(event)
    
    return StreamingResponse(
        stream_action_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.post(
    "/plans/{plan_id}/confirm/{step_id}",
    summary="Confirm plan step",
    description="Confirm or skip a plan step that requires confirmation - Requirements 7.4",
)
async def confirm_plan_step(
    plan_id: str,
    step_id: str,
    request: ConfirmationRequest,
    api_key: str = Depends(optional_api_key),
) -> StreamingResponse:
    """
    Confirm or skip a plan step that requires confirmation.
    
    Used for exploitation steps that require user approval before proceeding.
    
    Requirements: 7.4 - Confirm with user before exploitation
    """
    try:
        chat_service = await get_chat_service()
    except ConfigurationError as e:
        raise HTTPException(
            status_code=503,
            detail=str(e),
        )
    
    planner = get_attack_planner()
    plan = planner.get_plan(plan_id)
    
    if not plan:
        raise HTTPException(
            status_code=404,
            detail=f"Plan not found: {plan_id}",
        )
    
    # Find the step
    step = None
    for s in plan.steps:
        if s.id == step_id:
            step = s
            break
    
    if not step:
        raise HTTPException(
            status_code=404,
            detail=f"Step not found: {step_id}",
        )
    
    async def stream_confirmation_response() -> AsyncIterator[str]:
        """Stream the confirmation response."""
        async for event in chat_service.handle_plan_confirmation(
            step_id=step_id,
            confirmed=request.confirmed,
        ):
            yield await event_to_sse(event)
    
    return StreamingResponse(
        stream_confirmation_response(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.delete(
    "/plans/{plan_id}",
    summary="Delete attack plan",
    description="Delete an attack plan",
)
async def delete_plan(
    plan_id: str,
    api_key: str = Depends(optional_api_key),
) -> Dict[str, str]:
    """
    Delete an attack plan.
    
    Removes the plan from active plans. If the plan is in progress,
    it will be cancelled first.
    """
    planner = get_attack_planner()
    plan = planner.get_plan(plan_id)
    
    if not plan:
        raise HTTPException(
            status_code=404,
            detail=f"Plan not found: {plan_id}",
        )
    
    # Cancel if in progress
    if plan.status in (PlanStatus.IN_PROGRESS, PlanStatus.PAUSED):
        planner.cancel_plan(plan_id)
    
    planner.delete_plan(plan_id)
    
    return {"message": f"Plan {plan_id} deleted"}


# WebSocket endpoint for real-time chat (alternative to SSE)

from fastapi import WebSocket, WebSocketDisconnect


@router.websocket("/ws/{session_id}")
async def websocket_chat(
    websocket: WebSocket,
    session_id: str,
):
    """
    WebSocket endpoint for real-time chat.
    
    Provides bidirectional communication for chat interactions.
    Messages from client:
    - {"type": "message", "content": "..."}
    - {"type": "confirm", "execution_id": "...", "confirmed": true/false}
    
    Messages to client:
    - Same format as SSE events
    
    Requirements: 1.3, 4.2
    """
    await websocket.accept()
    
    try:
        chat_service = await get_chat_service()
    except ConfigurationError as e:
        await websocket.send_json({
            "type": "error",
            "message": str(e),
        })
        await websocket.close()
        return
    
    session_store = get_session_store()
    
    # Get or create session
    try:
        session = session_store.get(session_id)
    except SessionNotFoundError:
        session = session_store.create(title=f"Chat {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}")
        # Notify client of new session ID
        await websocket.send_json({
            "type": "session_created",
            "session_id": session.id,
        })
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()
            msg_type = data.get("type")
            
            if msg_type == "message":
                content = data.get("content", "")
                if not content:
                    continue
                
                # Convert session messages to provider format
                history: List[ProviderChatMessage] = []
                for msg in session.messages[-20:]:
                    history.append(ProviderChatMessage(
                        role=msg.role,
                        content=msg.content,
                    ))
                
                # Add user message to session
                session.add_message(role=MessageRole.USER, content=content)
                session_store.save(session)
                
                # Stream response
                assistant_content = ""
                async for event in chat_service.process_message(
                    message=content,
                    conversation_history=history,
                    session_id=session.id,
                ):
                    event_data = {
                        "type": event.type.value,
                        "content": event.content,
                        "tool_name": event.tool_name,
                        "execution_id": event.execution_id,
                        "output": event.output,
                        "finding": event.finding,
                        "message": event.message,
                        "summary": event.summary,
                        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    }
                    # Remove None values
                    event_data = {k: v for k, v in event_data.items() if v is not None}
                    await websocket.send_json(event_data)
                    
                    if event.type == ChatEventType.TEXT and event.content:
                        assistant_content += event.content
                
                # Save assistant response
                if assistant_content:
                    session.add_message(
                        role=MessageRole.ASSISTANT,
                        content=assistant_content,
                    )
                    session_store.save(session)
            
            elif msg_type == "confirm":
                execution_id = data.get("execution_id")
                confirmed = data.get("confirmed", False)
                
                if execution_id:
                    async for event in chat_service.confirm_execution(
                        execution_id=execution_id,
                        confirmed=confirmed,
                    ):
                        event_data = {
                            "type": event.type.value,
                            "content": event.content,
                            "tool_name": event.tool_name,
                            "execution_id": event.execution_id,
                            "output": event.output,
                            "message": event.message,
                            "summary": event.summary,
                        }
                        event_data = {k: v for k, v in event_data.items() if v is not None}
                        await websocket.send_json(event_data)
            
            elif msg_type == "assessment":
                # Multi-step attack planning via WebSocket
                target = data.get("target", "")
                include_exploitation = data.get("include_exploitation", False)
                
                if not target:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Target is required for assessment",
                    })
                    continue
                
                # Create assessment message
                message = f"Run a full security assessment on {target}"
                if include_exploitation:
                    message += " including exploitation attempts"
                
                # Add user message to session
                session.add_message(role=MessageRole.USER, content=message)
                session_store.save(session)
                
                # Stream assessment response
                async for event in chat_service.process_full_assessment(
                    message=message,
                    conversation_history=None,
                ):
                    event_data = {
                        "type": event.type.value,
                        "content": event.content,
                        "tool_name": event.tool_name,
                        "execution_id": event.execution_id,
                        "output": event.output,
                        "finding": event.finding,
                        "message": event.message,
                        "summary": event.summary,
                        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    }
                    event_data = {k: v for k, v in event_data.items() if v is not None}
                    await websocket.send_json(event_data)
            
            elif msg_type == "plan_action":
                # Handle plan actions (skip, retry, cancel, resume)
                plan_id = data.get("plan_id", "")
                action = data.get("action", "")
                
                if not plan_id or not action:
                    await websocket.send_json({
                        "type": "error",
                        "message": "plan_id and action are required",
                    })
                    continue
                
                planner = get_attack_planner()
                
                if action == "resume":
                    step = planner.resume_plan(plan_id)
                    if step:
                        async for event in chat_service._execute_attack_plan(plan_id):
                            event_data = {
                                "type": event.type.value,
                                "content": event.content,
                                "tool_name": event.tool_name,
                                "execution_id": event.execution_id,
                                "output": event.output,
                                "message": event.message,
                                "summary": event.summary,
                            }
                            event_data = {k: v for k, v in event_data.items() if v is not None}
                            await websocket.send_json(event_data)
                    else:
                        await websocket.send_json({
                            "type": "error",
                            "message": "Cannot resume plan - not in paused state",
                        })
                else:
                    async for event in chat_service.handle_plan_error_response(
                        plan_id=plan_id,
                        action=action,
                    ):
                        event_data = {
                            "type": event.type.value,
                            "content": event.content,
                            "tool_name": event.tool_name,
                            "execution_id": event.execution_id,
                            "output": event.output,
                            "message": event.message,
                            "summary": event.summary,
                        }
                        event_data = {k: v for k, v in event_data.items() if v is not None}
                        await websocket.send_json(event_data)
            
            elif msg_type == "plan_confirm":
                # Handle plan step confirmation
                step_id = data.get("step_id", "")
                confirmed = data.get("confirmed", False)
                
                if not step_id:
                    await websocket.send_json({
                        "type": "error",
                        "message": "step_id is required",
                    })
                    continue
                
                async for event in chat_service.handle_plan_confirmation(
                    step_id=step_id,
                    confirmed=confirmed,
                ):
                    event_data = {
                        "type": event.type.value,
                        "content": event.content,
                        "tool_name": event.tool_name,
                        "execution_id": event.execution_id,
                        "output": event.output,
                        "message": event.message,
                        "summary": event.summary,
                    }
                    event_data = {k: v for k, v in event_data.items() if v is not None}
                    await websocket.send_json(event_data)
            
            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})
    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({
                "type": "error",
                "message": str(e),
            })
        except:
            pass

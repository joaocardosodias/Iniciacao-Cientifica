"""
Mistral AI API Provider

Implements the LLMProvider interface for Mistral's API.
Supports streaming chat with function calling using the Mistral SDK.

Requirements: 2.x - Support Mistral as a provider option
"""

import json
from typing import Any, AsyncIterator, Dict, List, Optional

from fragmentum.web.backend.ai.providers import (
    LLMProvider,
    LLMProviderType,
    ConfigurationError,
    APIError,
    RateLimitError,
    ToolSchema,
    ToolCall,
    ChatMessage,
    StreamEvent,
)

try:
    from mistralai import Mistral
    MISTRAL_AVAILABLE = True
except ImportError:
    MISTRAL_AVAILABLE = False
    Mistral = None


class MistralProvider(LLMProvider):
    """
    Mistral AI API provider implementation.
    
    Uses the Mistral SDK for streaming chat with function calling support.
    """
    
    DEFAULT_MODEL = "mistral-large-latest"
    AVAILABLE_MODELS = [
        "mistral-large-latest",
        "mistral-small-latest",
        "codestral-latest",
        "ministral-8b-latest",
        "ministral-3b-latest",
        "pixtral-large-latest",
        "open-mistral-nemo",
    ]
    
    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
    ):
        """
        Initialize the Mistral provider.
        
        Args:
            api_key: Mistral API key
            model: Model to use (default: mistral-large-latest)
        """
        if not MISTRAL_AVAILABLE:
            raise ConfigurationError(
                "Mistral SDK not installed. Install with: pip install mistralai"
            )
        
        if not api_key:
            raise ConfigurationError("API key is required for Mistral provider")
        
        self._api_key = api_key
        self._model_name = model
        self._client: Optional[Mistral] = None
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.MISTRAL
    
    @property
    def model(self) -> str:
        return self._model_name
    
    def _get_client(self) -> Mistral:
        """Get or create the Mistral client."""
        if self._client is None:
            self._client = Mistral(api_key=self._api_key)
        return self._client
    
    async def validate_config(self) -> bool:
        """
        Validate the API key by making a minimal API call.
        
        Returns:
            True if configuration is valid
            
        Raises:
            ConfigurationError: If API key is invalid
        """
        try:
            client = self._get_client()
            # Make a minimal request to validate
            response = await client.chat.complete_async(
                model=self._model_name,
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=1
            )
            return True
        except Exception as e:
            error_str = str(e).lower()
            if "authentication" in error_str or "api key" in error_str or "401" in error_str:
                raise ConfigurationError(f"Invalid API key: {e}")
            if "rate" in error_str or "429" in error_str:
                # Rate limit means the key is valid
                return True
            raise ConfigurationError(f"Failed to validate configuration: {e}")
    
    def get_tools_schema(self, tools: List[ToolSchema]) -> List[Dict[str, Any]]:
        """
        Convert tool schemas to Mistral's function calling format.
        
        Mistral uses a format similar to OpenAI.
        """
        mistral_tools = []
        for tool in tools:
            mistral_tool = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": {
                        "type": "object",
                        "properties": tool.parameters,
                        "required": tool.required
                    }
                }
            }
            mistral_tools.append(mistral_tool)
        return mistral_tools
    
    def _convert_messages(self, messages: List[ChatMessage]) -> List[Dict[str, Any]]:
        """Convert ChatMessage objects to Mistral's message format."""
        mistral_messages = []
        
        for msg in messages:
            if msg.role == "tool":
                # Tool results in Mistral format
                mistral_messages.append({
                    "role": "tool",
                    "tool_call_id": msg.tool_call_id,
                    "content": msg.content
                })
            elif msg.role == "assistant" and msg.tool_calls:
                # Assistant message with tool calls
                tool_calls = []
                for tc in msg.tool_calls:
                    tool_calls.append({
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.parameters)
                        }
                    })
                mistral_messages.append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": tool_calls
                })
            else:
                # Regular message
                mistral_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
        
        return mistral_messages

    async def chat(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolSchema]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = True
    ) -> AsyncIterator[StreamEvent]:
        """
        Send a chat request to Mistral and stream the response.
        
        Handles both text responses and tool calls.
        """
        client = self._get_client()
        mistral_messages = self._convert_messages(messages)
        
        # Build request kwargs
        kwargs: Dict[str, Any] = {
            "model": self._model_name,
            "max_tokens": max_tokens,
            "messages": mistral_messages,
            "temperature": temperature,
        }
        
        if tools:
            kwargs["tools"] = self.get_tools_schema(tools)
            kwargs["tool_choice"] = "auto"
        
        try:
            if stream:
                async for event in self._stream_response(client, kwargs):
                    yield event
            else:
                async for event in self._non_stream_response(client, kwargs):
                    yield event
        except Exception as e:
            error_msg = str(e).lower()
            if "rate" in error_msg or "429" in error_msg:
                raise RateLimitError(f"Rate limit exceeded: {e}")
            yield StreamEvent(type="error", error=str(e))
    
    async def _stream_response(
        self,
        client: Mistral,
        kwargs: Dict[str, Any]
    ) -> AsyncIterator[StreamEvent]:
        """Handle streaming response from Mistral."""
        # Track tool calls being built
        tool_calls_in_progress: Dict[int, Dict[str, Any]] = {}
        
        stream = await client.chat.stream_async(**kwargs)
        
        async for chunk in stream:
            if not chunk.data.choices:
                continue
            
            delta = chunk.data.choices[0].delta
            
            # Handle text content
            if delta.content:
                yield StreamEvent(type="text", content=delta.content)
            
            # Handle tool calls
            if delta.tool_calls:
                for tc_delta in delta.tool_calls:
                    idx = tc_delta.index if hasattr(tc_delta, 'index') else 0
                    
                    if idx not in tool_calls_in_progress:
                        tool_calls_in_progress[idx] = {
                            "id": getattr(tc_delta, 'id', '') or "",
                            "name": "",
                            "arguments": ""
                        }
                    
                    tc = tool_calls_in_progress[idx]
                    
                    if hasattr(tc_delta, 'id') and tc_delta.id:
                        tc["id"] = tc_delta.id
                    
                    if hasattr(tc_delta, 'function') and tc_delta.function:
                        if tc_delta.function.name:
                            tc["name"] = tc_delta.function.name
                        if tc_delta.function.arguments:
                            tc["arguments"] += tc_delta.function.arguments
            
            # Check for finish reason
            if chunk.data.choices[0].finish_reason:
                # Emit any completed tool calls
                for tc in tool_calls_in_progress.values():
                    if tc["name"]:
                        try:
                            parameters = json.loads(tc["arguments"]) if tc["arguments"] else {}
                        except json.JSONDecodeError:
                            parameters = {}
                        
                        tool_call = ToolCall(
                            id=tc["id"],
                            name=tc["name"],
                            parameters=parameters
                        )
                        yield StreamEvent(type="tool_call", tool_call=tool_call)
                
                yield StreamEvent(type="done")
    
    async def _non_stream_response(
        self,
        client: Mistral,
        kwargs: Dict[str, Any]
    ) -> AsyncIterator[StreamEvent]:
        """Handle non-streaming response from Mistral."""
        response = await client.chat.complete_async(**kwargs)
        
        if not response.choices:
            yield StreamEvent(type="done")
            return
        
        message = response.choices[0].message
        
        # Emit text content
        if message.content:
            yield StreamEvent(type="text", content=message.content)
        
        # Emit tool calls
        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    parameters = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except json.JSONDecodeError:
                    parameters = {}
                
                tool_call = ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    parameters=parameters
                )
                yield StreamEvent(type="tool_call", tool_call=tool_call)
        
        yield StreamEvent(type="done")


__all__ = ["MistralProvider"]

"""
OpenAI API Provider

Implements the LLMProvider interface for OpenAI's API.
Supports streaming chat with function calling using the OpenAI SDK.

Requirements: 2.2 - Support OpenAI API as a provider option
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
    from openai import AsyncOpenAI, APIError as OpenAIAPIError
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    AsyncOpenAI = None
    OpenAIAPIError = Exception


class OpenAIProvider(LLMProvider):
    """
    OpenAI API provider implementation.
    
    Uses the OpenAI SDK for streaming chat with function calling support.
    """
    
    DEFAULT_MODEL = "gpt-4"
    
    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: Optional[str] = None,
        organization: Optional[str] = None
    ):
        """
        Initialize the OpenAI provider.
        
        Args:
            api_key: OpenAI API key
            model: Model to use (default: gpt-4)
            base_url: Optional custom API base URL
            organization: Optional organization ID
        """
        if not OPENAI_AVAILABLE:
            raise ConfigurationError(
                "OpenAI SDK not installed. Install with: pip install openai"
            )
        
        if not api_key:
            raise ConfigurationError("API key is required for OpenAI provider")
        
        self._api_key = api_key
        self._model = model
        self._base_url = base_url
        self._organization = organization
        self._client: Optional[AsyncOpenAI] = None
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.OPENAI
    
    @property
    def model(self) -> str:
        return self._model
    
    def _get_client(self) -> AsyncOpenAI:
        """Get or create the async OpenAI client."""
        if self._client is None:
            kwargs = {"api_key": self._api_key}
            if self._base_url:
                kwargs["base_url"] = self._base_url
            if self._organization:
                kwargs["organization"] = self._organization
            self._client = AsyncOpenAI(**kwargs)
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
            # Make a minimal request to validate the API key
            await client.chat.completions.create(
                model=self._model,
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}]
            )
            return True
        except OpenAIAPIError as e:
            error_str = str(e).lower()
            if "authentication" in error_str or "api key" in error_str:
                raise ConfigurationError(f"Invalid API key: {e}")
            if "rate" in error_str:
                # Rate limit means the key is valid
                return True
            raise ConfigurationError(f"API validation failed: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to validate configuration: {e}")
    
    def get_tools_schema(self, tools: List[ToolSchema]) -> List[Dict[str, Any]]:
        """
        Convert tool schemas to OpenAI's function calling format.
        
        OpenAI uses a 'functions' format with specific structure.
        """
        openai_tools = []
        for tool in tools:
            # tool.parameters already contains the full schema with type, properties, etc.
            parameters = tool.parameters.copy() if tool.parameters else {"type": "object", "properties": {}}
            
            # Ensure required is set
            if tool.required and "required" not in parameters:
                parameters["required"] = tool.required
            
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": parameters
                }
            }
            openai_tools.append(openai_tool)
        return openai_tools
    
    def _convert_messages(self, messages: List[ChatMessage]) -> List[Dict[str, Any]]:
        """Convert ChatMessage objects to OpenAI's message format."""
        openai_messages = []
        
        for msg in messages:
            if msg.role == "tool":
                # Tool results in OpenAI format
                openai_messages.append({
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
                openai_messages.append({
                    "role": "assistant",
                    "content": msg.content or None,
                    "tool_calls": tool_calls
                })
            else:
                # Regular message
                openai_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
        
        return openai_messages

    async def chat(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolSchema]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = True
    ) -> AsyncIterator[StreamEvent]:
        """
        Send a chat request to OpenAI and stream the response.
        
        Handles both text responses and tool calls.
        """
        client = self._get_client()
        openai_messages = self._convert_messages(messages)
        
        # Build request kwargs
        kwargs: Dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": openai_messages,
            "temperature": temperature,
            "stream": stream,
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
        except OpenAIAPIError as e:
            error_msg = str(e).lower()
            if "rate" in error_msg:
                raise RateLimitError(f"Rate limit exceeded: {e}")
            
            # Handle various tool call errors - retry without tools
            tool_errors = [
                "failed to call a function",
                "failed_generation", 
                "tool call validation failed",
                "was not in request.tools",
                "invalid tool",
            ]
            
            if any(err in error_msg for err in tool_errors):
                # Retry without tools - let the model respond with text
                kwargs.pop("tools", None)
                kwargs.pop("tool_choice", None)
                try:
                    if stream:
                        async for event in self._stream_response(client, kwargs):
                            yield event
                    else:
                        async for event in self._non_stream_response(client, kwargs):
                            yield event
                    return
                except Exception as retry_error:
                    yield StreamEvent(type="error", error=f"Retry failed: {retry_error}")
                    return
            
            status_code = getattr(e, 'status_code', None)
            raise APIError(f"OpenAI API error: {e}", status_code)
        except Exception as e:
            yield StreamEvent(type="error", error=str(e))
    
    async def _stream_response(
        self,
        client: AsyncOpenAI,
        kwargs: Dict[str, Any]
    ) -> AsyncIterator[StreamEvent]:
        """Handle streaming response from OpenAI."""
        # Track tool calls being built
        tool_calls_in_progress: Dict[int, Dict[str, Any]] = {}
        
        stream = await client.chat.completions.create(**kwargs)
        
        async for chunk in stream:
            if not chunk.choices:
                continue
            
            delta = chunk.choices[0].delta
            
            # Handle text content
            if delta.content:
                yield StreamEvent(type="text", content=delta.content)
            
            # Handle tool calls
            if delta.tool_calls:
                for tc_delta in delta.tool_calls:
                    idx = tc_delta.index
                    
                    if idx not in tool_calls_in_progress:
                        tool_calls_in_progress[idx] = {
                            "id": tc_delta.id or "",
                            "name": "",
                            "arguments": ""
                        }
                    
                    tc = tool_calls_in_progress[idx]
                    
                    if tc_delta.id:
                        tc["id"] = tc_delta.id
                    
                    if tc_delta.function:
                        if tc_delta.function.name:
                            tc["name"] = tc_delta.function.name
                        if tc_delta.function.arguments:
                            tc["arguments"] += tc_delta.function.arguments
            
            # Check for finish reason
            if chunk.choices[0].finish_reason:
                # Emit any completed tool calls
                for tc in tool_calls_in_progress.values():
                    if tc["name"]:
                        # Clean up malformed tool names (some models concatenate name with args)
                        tool_name = tc["name"]
                        arguments = tc["arguments"]
                        
                        # Check if tool name contains JSON (malformed call)
                        if "{" in tool_name:
                            # Try to extract the actual tool name
                            parts = tool_name.split("{", 1)
                            tool_name = parts[0].strip()
                            # Prepend the JSON part to arguments
                            if len(parts) > 1:
                                arguments = "{" + parts[1] + arguments
                        
                        try:
                            parameters = json.loads(arguments) if arguments else {}
                        except json.JSONDecodeError:
                            parameters = {}
                        
                        tool_call = ToolCall(
                            id=tc["id"],
                            name=tool_name,
                            parameters=parameters
                        )
                        yield StreamEvent(type="tool_call", tool_call=tool_call)
                
                yield StreamEvent(type="done")
    
    async def _non_stream_response(
        self,
        client: AsyncOpenAI,
        kwargs: Dict[str, Any]
    ) -> AsyncIterator[StreamEvent]:
        """Handle non-streaming response from OpenAI."""
        kwargs["stream"] = False
        response = await client.chat.completions.create(**kwargs)
        
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


__all__ = ["OpenAIProvider"]

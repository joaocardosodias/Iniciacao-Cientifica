"""
Claude API Provider

Implements the LLMProvider interface for Anthropic's Claude API.
Supports streaming chat with function calling using the Anthropic SDK.

Requirements: 2.1 - Support Claude API as a provider option
"""

import json
import uuid
from typing import Any, AsyncIterator, Dict, List, Optional

from fragmentum.web.backend.ai.providers import (
    LLMProvider,
    LLMProviderType,
    LLMProviderError,
    ConfigurationError,
    APIError,
    RateLimitError,
    ToolSchema,
    ToolCall,
    ChatMessage,
    StreamEvent,
)

try:
    import anthropic
    from anthropic import AsyncAnthropic, APIError as AnthropicAPIError
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    AsyncAnthropic = None
    AnthropicAPIError = Exception


class ClaudeProvider(LLMProvider):
    """
    Claude API provider implementation.
    
    Uses the Anthropic SDK for streaming chat with function calling support.
    """
    
    DEFAULT_MODEL = "claude-sonnet-4-20250514"
    
    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: Optional[str] = None
    ):
        """
        Initialize the Claude provider.
        
        Args:
            api_key: Anthropic API key
            model: Model to use (default: claude-sonnet-4-20250514)
            base_url: Optional custom API base URL
        """
        if not ANTHROPIC_AVAILABLE:
            raise ConfigurationError(
                "Anthropic SDK not installed. Install with: pip install anthropic"
            )
        
        if not api_key:
            raise ConfigurationError("API key is required for Claude provider")
        
        self._api_key = api_key
        self._model = model
        self._base_url = base_url
        self._client: Optional[AsyncAnthropic] = None
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.CLAUDE
    
    @property
    def model(self) -> str:
        return self._model
    
    def _get_client(self) -> AsyncAnthropic:
        """Get or create the async Anthropic client."""
        if self._client is None:
            kwargs = {"api_key": self._api_key}
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = AsyncAnthropic(**kwargs)
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
            await client.messages.create(
                model=self._model,
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}]
            )
            return True
        except AnthropicAPIError as e:
            if "authentication" in str(e).lower() or "api key" in str(e).lower():
                raise ConfigurationError(f"Invalid API key: {e}")
            if "rate" in str(e).lower():
                # Rate limit means the key is valid
                return True
            raise ConfigurationError(f"API validation failed: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to validate configuration: {e}")
    
    def get_tools_schema(self, tools: List[ToolSchema]) -> List[Dict[str, Any]]:
        """
        Convert tool schemas to Claude's tool format.
        
        Claude uses a specific format for tool definitions with input_schema.
        """
        claude_tools = []
        for tool in tools:
            claude_tool = {
                "name": tool.name,
                "description": tool.description,
                "input_schema": {
                    "type": "object",
                    "properties": tool.parameters,
                    "required": tool.required
                }
            }
            claude_tools.append(claude_tool)
        return claude_tools
    
    def _convert_messages(self, messages: List[ChatMessage]) -> tuple[Optional[str], List[Dict[str, Any]]]:
        """
        Convert ChatMessage objects to Claude's message format.
        
        Returns:
            Tuple of (system_prompt, messages_list)
        """
        system_prompt = None
        claude_messages = []
        
        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
                continue
            
            if msg.role == "tool":
                # Tool results in Claude format
                claude_messages.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.tool_call_id,
                        "content": msg.content
                    }]
                })
            elif msg.role == "assistant" and msg.tool_calls:
                # Assistant message with tool calls
                content = []
                if msg.content:
                    content.append({"type": "text", "text": msg.content})
                for tc in msg.tool_calls:
                    content.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.parameters
                    })
                claude_messages.append({"role": "assistant", "content": content})
            else:
                # Regular user or assistant message
                claude_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
        
        return system_prompt, claude_messages

    async def chat(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolSchema]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = True
    ) -> AsyncIterator[StreamEvent]:
        """
        Send a chat request to Claude and stream the response.
        
        Handles both text responses and tool calls.
        """
        client = self._get_client()
        system_prompt, claude_messages = self._convert_messages(messages)
        
        # Build request kwargs
        kwargs: Dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": claude_messages,
            "temperature": temperature,
        }
        
        if system_prompt:
            kwargs["system"] = system_prompt
        
        if tools:
            kwargs["tools"] = self.get_tools_schema(tools)
        
        try:
            if stream:
                async for event in self._stream_response(client, kwargs):
                    yield event
            else:
                async for event in self._non_stream_response(client, kwargs):
                    yield event
        except AnthropicAPIError as e:
            error_msg = str(e)
            if "rate" in error_msg.lower():
                raise RateLimitError(f"Rate limit exceeded: {e}")
            status_code = getattr(e, 'status_code', None)
            raise APIError(f"Claude API error: {e}", status_code)
        except Exception as e:
            yield StreamEvent(type="error", error=str(e))
    
    async def _stream_response(
        self,
        client: AsyncAnthropic,
        kwargs: Dict[str, Any]
    ) -> AsyncIterator[StreamEvent]:
        """Handle streaming response from Claude."""
        current_tool_call: Optional[Dict[str, Any]] = None
        tool_input_json = ""
        
        async with client.messages.stream(**kwargs) as stream:
            async for event in stream:
                if event.type == "content_block_start":
                    block = event.content_block
                    if hasattr(block, 'type'):
                        if block.type == "tool_use":
                            current_tool_call = {
                                "id": block.id,
                                "name": block.name,
                            }
                            tool_input_json = ""
                
                elif event.type == "content_block_delta":
                    delta = event.delta
                    if hasattr(delta, 'type'):
                        if delta.type == "text_delta":
                            yield StreamEvent(type="text", content=delta.text)
                        elif delta.type == "input_json_delta":
                            tool_input_json += delta.partial_json
                
                elif event.type == "content_block_stop":
                    if current_tool_call:
                        # Parse the accumulated JSON input
                        try:
                            parameters = json.loads(tool_input_json) if tool_input_json else {}
                        except json.JSONDecodeError:
                            parameters = {}
                        
                        tool_call = ToolCall(
                            id=current_tool_call["id"],
                            name=current_tool_call["name"],
                            parameters=parameters
                        )
                        yield StreamEvent(type="tool_call", tool_call=tool_call)
                        current_tool_call = None
                        tool_input_json = ""
                
                elif event.type == "message_stop":
                    yield StreamEvent(type="done")
    
    async def _non_stream_response(
        self,
        client: AsyncAnthropic,
        kwargs: Dict[str, Any]
    ) -> AsyncIterator[StreamEvent]:
        """Handle non-streaming response from Claude."""
        response = await client.messages.create(**kwargs)
        
        for block in response.content:
            if block.type == "text":
                yield StreamEvent(type="text", content=block.text)
            elif block.type == "tool_use":
                tool_call = ToolCall(
                    id=block.id,
                    name=block.name,
                    parameters=block.input
                )
                yield StreamEvent(type="tool_call", tool_call=tool_call)
        
        yield StreamEvent(type="done")


__all__ = ["ClaudeProvider"]

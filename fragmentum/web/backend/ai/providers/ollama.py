"""
Ollama Local Provider

Implements the LLMProvider interface for Ollama local models.
Supports streaming chat using the Ollama HTTP API without requiring API keys.

Requirements: 
- 2.3: Support Ollama local models as a provider option
- 2.5: Connect to local Ollama server without requiring API keys
"""

import json
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from fragmentum.web.backend.ai.providers import (
    LLMProvider,
    LLMProviderType,
    ConfigurationError,
    APIError,
    ToolSchema,
    ToolCall,
    ChatMessage,
    StreamEvent,
)


class OllamaProvider(LLMProvider):
    """
    Ollama local provider implementation.
    
    Uses the Ollama HTTP API for streaming chat. Does not require API keys
    as it connects to a locally running Ollama server.
    """
    
    DEFAULT_BASE_URL = "http://localhost:11434"
    DEFAULT_MODEL = "llama3"
    
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = 120.0
    ):
        """
        Initialize the Ollama provider.
        
        Args:
            base_url: Ollama server URL (default: http://localhost:11434)
            model: Model to use (default: llama3)
            timeout: Request timeout in seconds
        """
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.OLLAMA
    
    @property
    def model(self) -> str:
        return self._model
    
    def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=httpx.Timeout(self._timeout)
            )
        return self._client
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def validate_config(self) -> bool:
        """
        Validate connection to Ollama server.
        
        Checks if the server is running and the model is available.
        
        Returns:
            True if configuration is valid
            
        Raises:
            ConfigurationError: If server is not reachable or model not found
        """
        client = self._get_client()
        
        try:
            # Check if server is running
            response = await client.get("/api/tags")
            if response.status_code != 200:
                raise ConfigurationError(
                    f"Ollama server returned status {response.status_code}"
                )
            
            # Check if model is available
            data = response.json()
            models = [m.get("name", "").split(":")[0] for m in data.get("models", [])]
            
            model_base = self._model.split(":")[0]
            if model_base not in models and self._model not in [m.get("name") for m in data.get("models", [])]:
                available = ", ".join(models[:5])
                if len(models) > 5:
                    available += f"... ({len(models)} total)"
                raise ConfigurationError(
                    f"Model '{self._model}' not found. Available: {available}. "
                    f"Pull with: ollama pull {self._model}"
                )
            
            return True
            
        except httpx.ConnectError:
            raise ConfigurationError(
                f"Cannot connect to Ollama at {self._base_url}. "
                "Make sure Ollama is running: ollama serve"
            )
        except httpx.TimeoutException:
            raise ConfigurationError(
                f"Connection to Ollama at {self._base_url} timed out"
            )
        except ConfigurationError:
            raise
        except Exception as e:
            raise ConfigurationError(f"Failed to validate Ollama configuration: {e}")
    
    def get_tools_schema(self, tools: List[ToolSchema]) -> List[Dict[str, Any]]:
        """
        Convert tool schemas to Ollama's tool format.
        
        Ollama uses OpenAI-compatible tool format for models that support it.
        """
        ollama_tools = []
        for tool in tools:
            ollama_tool = {
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
            ollama_tools.append(ollama_tool)
        return ollama_tools
    
    def _convert_messages(self, messages: List[ChatMessage]) -> List[Dict[str, Any]]:
        """Convert ChatMessage objects to Ollama's message format."""
        ollama_messages = []
        
        for msg in messages:
            if msg.role == "tool":
                # Tool results - Ollama expects them as user messages with context
                ollama_messages.append({
                    "role": "user",
                    "content": f"[Tool Result for {msg.name}]: {msg.content}"
                })
            elif msg.role == "assistant" and msg.tool_calls:
                # For models with tool support, include tool calls
                content = msg.content or ""
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
                ollama_messages.append({
                    "role": "assistant",
                    "content": content,
                    "tool_calls": tool_calls
                })
            else:
                ollama_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
        
        return ollama_messages

    async def chat(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolSchema]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = True
    ) -> AsyncIterator[StreamEvent]:
        """
        Send a chat request to Ollama and stream the response.
        
        Note: Tool calling support depends on the model. Models like llama3
        may not support native tool calling, in which case tools are included
        in the system prompt.
        """
        client = self._get_client()
        ollama_messages = self._convert_messages(messages)
        
        # Build request payload
        payload: Dict[str, Any] = {
            "model": self._model,
            "messages": ollama_messages,
            "stream": stream,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            }
        }
        
        # Add tools if provided (for models that support it)
        if tools:
            payload["tools"] = self.get_tools_schema(tools)
        
        try:
            if stream:
                async for event in self._stream_response(client, payload):
                    yield event
            else:
                async for event in self._non_stream_response(client, payload):
                    yield event
        except httpx.ConnectError:
            yield StreamEvent(
                type="error",
                error=f"Cannot connect to Ollama at {self._base_url}. Is it running?"
            )
        except httpx.TimeoutException:
            yield StreamEvent(type="error", error="Request to Ollama timed out")
        except Exception as e:
            yield StreamEvent(type="error", error=str(e))
    
    async def _stream_response(
        self,
        client: httpx.AsyncClient,
        payload: Dict[str, Any]
    ) -> AsyncIterator[StreamEvent]:
        """Handle streaming response from Ollama."""
        try:
            async with client.stream(
                "POST",
                "/api/chat",
                json=payload,
                timeout=httpx.Timeout(self._timeout)
            ) as response:
                if response.status_code != 200:
                    error_text = await response.aread()
                    raise APIError(
                        f"Ollama error: {error_text.decode()}",
                        response.status_code
                    )
                
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    
                    # Handle message content
                    message = data.get("message", {})
                    content = message.get("content", "")
                    
                    if content:
                        yield StreamEvent(type="text", content=content)
                    
                    # Handle tool calls (for models that support it)
                    tool_calls = message.get("tool_calls", [])
                    for tc in tool_calls:
                        func = tc.get("function", {})
                        try:
                            parameters = json.loads(func.get("arguments", "{}"))
                        except json.JSONDecodeError:
                            parameters = {}
                        
                        tool_call = ToolCall(
                            id=tc.get("id", f"call_{hash(func.get('name', ''))}"),
                            name=func.get("name", ""),
                            parameters=parameters
                        )
                        yield StreamEvent(type="tool_call", tool_call=tool_call)
                    
                    # Check if done
                    if data.get("done", False):
                        yield StreamEvent(type="done")
                        break
                        
        except APIError:
            raise
        except Exception as e:
            raise APIError(f"Streaming error: {e}")
    
    async def _non_stream_response(
        self,
        client: httpx.AsyncClient,
        payload: Dict[str, Any]
    ) -> AsyncIterator[StreamEvent]:
        """Handle non-streaming response from Ollama."""
        payload["stream"] = False
        
        response = await client.post("/api/chat", json=payload)
        
        if response.status_code != 200:
            raise APIError(
                f"Ollama error: {response.text}",
                response.status_code
            )
        
        data = response.json()
        message = data.get("message", {})
        
        # Emit text content
        content = message.get("content", "")
        if content:
            yield StreamEvent(type="text", content=content)
        
        # Emit tool calls
        tool_calls = message.get("tool_calls", [])
        for tc in tool_calls:
            func = tc.get("function", {})
            try:
                parameters = json.loads(func.get("arguments", "{}"))
            except json.JSONDecodeError:
                parameters = {}
            
            tool_call = ToolCall(
                id=tc.get("id", f"call_{hash(func.get('name', ''))}"),
                name=func.get("name", ""),
                parameters=parameters
            )
            yield StreamEvent(type="tool_call", tool_call=tool_call)
        
        yield StreamEvent(type="done")
    
    async def list_models(self) -> List[str]:
        """
        List available models on the Ollama server.
        
        Returns:
            List of model names
        """
        client = self._get_client()
        
        try:
            response = await client.get("/api/tags")
            if response.status_code != 200:
                return []
            
            data = response.json()
            return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            return []


__all__ = ["OllamaProvider"]

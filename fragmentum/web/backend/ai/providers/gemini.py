"""
Google Gemini API Provider

Implements the LLMProvider interface for Google's Gemini API.
Supports streaming chat with function calling using the Google AI SDK.

Requirements: 2.x - Support Gemini as a provider option
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
    import google.generativeai as genai
    from google.generativeai.types import HarmCategory, HarmBlockThreshold
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None


class GeminiProvider(LLMProvider):
    """
    Google Gemini API provider implementation.
    
    Uses the Google AI SDK for streaming chat with function calling support.
    """
    
    DEFAULT_MODEL = "gemini-2.0-flash-exp"
    AVAILABLE_MODELS = [
        "gemini-2.0-flash-exp",
        "gemini-1.5-pro",
        "gemini-1.5-flash",
        "gemini-1.5-flash-8b",
    ]
    
    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
    ):
        """
        Initialize the Gemini provider.
        
        Args:
            api_key: Google AI API key
            model: Model to use (default: gemini-2.0-flash-exp)
        """
        if not GEMINI_AVAILABLE:
            raise ConfigurationError(
                "Google AI SDK not installed. Install with: pip install google-generativeai"
            )
        
        if not api_key:
            raise ConfigurationError("API key is required for Gemini provider")
        
        self._api_key = api_key
        self._model_name = model
        self._client = None
        
        # Configure the SDK
        genai.configure(api_key=api_key)
    
    @property
    def provider_type(self) -> LLMProviderType:
        return LLMProviderType.GEMINI
    
    @property
    def model(self) -> str:
        return self._model_name
    
    def _get_model(self, tools: Optional[List[Dict[str, Any]]] = None):
        """Get or create the Gemini model instance."""
        # Safety settings - allow all for pentesting context
        safety_settings = {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        }
        
        kwargs = {
            "model_name": self._model_name,
            "safety_settings": safety_settings,
        }
        
        if tools:
            kwargs["tools"] = tools
        
        return genai.GenerativeModel(**kwargs)
    
    async def validate_config(self) -> bool:
        """
        Validate the API key by making a minimal API call.
        
        Returns:
            True if configuration is valid
            
        Raises:
            ConfigurationError: If API key is invalid
        """
        try:
            model = self._get_model()
            # Make a minimal request to validate
            response = model.generate_content("hi", stream=False)
            return True
        except Exception as e:
            error_str = str(e).lower()
            if "api key" in error_str or "invalid" in error_str:
                raise ConfigurationError(f"Invalid API key: {e}")
            if "quota" in error_str or "rate" in error_str:
                # Rate limit means the key is valid
                return True
            raise ConfigurationError(f"Failed to validate configuration: {e}")
    
    def get_tools_schema(self, tools: List[ToolSchema]) -> List[Dict[str, Any]]:
        """
        Convert tool schemas to Gemini's function calling format.
        
        Gemini uses a specific format for function declarations.
        """
        gemini_tools = []
        
        for tool in tools:
            # Convert parameters to Gemini format
            properties = {}
            for param_name, param_info in tool.parameters.items():
                param_type = param_info.get("type", "string")
                # Map types to Gemini types
                type_mapping = {
                    "string": "STRING",
                    "number": "NUMBER",
                    "integer": "INTEGER",
                    "boolean": "BOOLEAN",
                    "array": "ARRAY",
                    "object": "OBJECT",
                }
                properties[param_name] = {
                    "type": type_mapping.get(param_type, "STRING"),
                    "description": param_info.get("description", ""),
                }
            
            function_declaration = {
                "name": tool.name,
                "description": tool.description,
                "parameters": {
                    "type": "OBJECT",
                    "properties": properties,
                    "required": tool.required,
                }
            }
            gemini_tools.append(function_declaration)
        
        return [{"function_declarations": gemini_tools}]
    
    def _convert_messages(self, messages: List[ChatMessage]) -> List[Dict[str, Any]]:
        """Convert ChatMessage objects to Gemini's content format."""
        gemini_contents = []
        
        for msg in messages:
            if msg.role == "system":
                # Gemini handles system prompts differently - prepend to first user message
                continue
            elif msg.role == "user":
                gemini_contents.append({
                    "role": "user",
                    "parts": [{"text": msg.content}]
                })
            elif msg.role == "assistant":
                parts = []
                if msg.content:
                    parts.append({"text": msg.content})
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        parts.append({
                            "function_call": {
                                "name": tc.name,
                                "args": tc.parameters
                            }
                        })
                gemini_contents.append({
                    "role": "model",
                    "parts": parts
                })
            elif msg.role == "tool":
                gemini_contents.append({
                    "role": "function",
                    "parts": [{
                        "function_response": {
                            "name": msg.name,
                            "response": {"result": msg.content}
                        }
                    }]
                })
        
        return gemini_contents
    
    def _get_system_instruction(self, messages: List[ChatMessage]) -> Optional[str]:
        """Extract system instruction from messages."""
        for msg in messages:
            if msg.role == "system":
                return msg.content
        return None

    async def chat(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolSchema]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = True
    ) -> AsyncIterator[StreamEvent]:
        """
        Send a chat request to Gemini and stream the response.
        
        Handles both text responses and tool calls.
        """
        try:
            # Get tools schema if provided
            gemini_tools = self.get_tools_schema(tools) if tools else None
            
            # Create model with tools
            model = self._get_model(gemini_tools)
            
            # Get system instruction
            system_instruction = self._get_system_instruction(messages)
            
            # Convert messages
            contents = self._convert_messages(messages)
            
            # Create generation config
            generation_config = genai.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            )
            
            # Start chat
            chat = model.start_chat(history=contents[:-1] if len(contents) > 1 else [])
            
            # Get the last user message
            last_message = contents[-1] if contents else {"parts": [{"text": ""}]}
            last_content = last_message.get("parts", [{}])[0].get("text", "")
            
            if stream:
                async for event in self._stream_response(chat, last_content, generation_config):
                    yield event
            else:
                async for event in self._non_stream_response(chat, last_content, generation_config):
                    yield event
                    
        except Exception as e:
            error_str = str(e).lower()
            if "quota" in error_str or "rate" in error_str:
                raise RateLimitError(f"Rate limit exceeded: {e}")
            yield StreamEvent(type="error", error=str(e))
    
    async def _stream_response(
        self,
        chat,
        content: str,
        generation_config
    ) -> AsyncIterator[StreamEvent]:
        """Handle streaming response from Gemini."""
        try:
            response = chat.send_message(
                content,
                generation_config=generation_config,
                stream=True
            )
            
            for chunk in response:
                if chunk.text:
                    yield StreamEvent(type="text", content=chunk.text)
                
                # Check for function calls
                if hasattr(chunk, 'candidates') and chunk.candidates:
                    for candidate in chunk.candidates:
                        if hasattr(candidate, 'content') and candidate.content.parts:
                            for part in candidate.content.parts:
                                if hasattr(part, 'function_call'):
                                    fc = part.function_call
                                    tool_call = ToolCall(
                                        id=f"call_{fc.name}_{hash(str(fc.args))}",
                                        name=fc.name,
                                        parameters=dict(fc.args) if fc.args else {}
                                    )
                                    yield StreamEvent(type="tool_call", tool_call=tool_call)
            
            yield StreamEvent(type="done")
            
        except Exception as e:
            yield StreamEvent(type="error", error=str(e))
    
    async def _non_stream_response(
        self,
        chat,
        content: str,
        generation_config
    ) -> AsyncIterator[StreamEvent]:
        """Handle non-streaming response from Gemini."""
        try:
            response = chat.send_message(
                content,
                generation_config=generation_config,
                stream=False
            )
            
            # Emit text content
            if response.text:
                yield StreamEvent(type="text", content=response.text)
            
            # Check for function calls
            if response.candidates:
                for candidate in response.candidates:
                    if candidate.content.parts:
                        for part in candidate.content.parts:
                            if hasattr(part, 'function_call'):
                                fc = part.function_call
                                tool_call = ToolCall(
                                    id=f"call_{fc.name}_{hash(str(fc.args))}",
                                    name=fc.name,
                                    parameters=dict(fc.args) if fc.args else {}
                                )
                                yield StreamEvent(type="tool_call", tool_call=tool_call)
            
            yield StreamEvent(type="done")
            
        except Exception as e:
            yield StreamEvent(type="error", error=str(e))


__all__ = ["GeminiProvider"]

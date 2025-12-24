"""
Chat Session Data Models for AI Chat Integration.

Defines the data models for chat sessions, messages, and tool executions
that are persisted and restored across user interactions.

Requirements:
- 5.1: Create new Chat_Session with unique identifier
- 5.2: Restore previous conversation history
- 5.3: Display messages with timestamps
- 5.5: Preserve tool execution output in history
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class MessageRole(str, Enum):
    """Role of a message in the conversation."""
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    TOOL = "tool"


class ToolExecutionStatus(str, Enum):
    """Status of a tool execution."""
    PENDING = "pending"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELLED = "cancelled"


class FindingSeverity(str, Enum):
    """Severity level for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    """Type of finding."""
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    SHELL = "shell"
    INFO = "info"


class Finding(BaseModel):
    """
    A finding from tool execution.
    
    Represents discovered information like open ports, vulnerabilities,
    or credentials found during security assessments.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: FindingType
    value: Any
    severity: FindingSeverity
    source: str  # Tool that produced this finding
    target: str  # Target that was scanned
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    """
    A tool call request from the LLM.
    
    Represents the LLM's request to execute a specific tool
    with given parameters.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ToolExecution(BaseModel):
    """
    Record of a tool execution within a chat session.
    
    Tracks the full lifecycle of a tool execution including
    status, output, findings, and timing information.
    
    Requirements: 5.5 - Preserve tool execution output in history
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    status: ToolExecutionStatus = ToolExecutionStatus.PENDING
    requires_confirmation: bool = False
    output: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    summary: Optional[str] = None

    class Config:
        use_enum_values = True


class ChatMessage(BaseModel):
    """
    A message in the chat conversation.
    
    Represents a single message from user, assistant, system, or tool.
    Messages may include tool calls and their execution results.
    
    Requirements:
    - 5.3: Display messages with timestamps
    - 5.5: Preserve tool execution output in history
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: MessageRole
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tool_calls: Optional[List[ToolCall]] = None
    tool_execution: Optional[ToolExecution] = None
    
    # For tool response messages
    tool_call_id: Optional[str] = None
    tool_name: Optional[str] = None

    class Config:
        use_enum_values = True


class ChatSession(BaseModel):
    """
    A chat session containing conversation history.
    
    Represents a complete conversation between user and AI,
    including all messages, tool executions, and metadata.
    
    Requirements:
    - 5.1: Create new Chat_Session with unique identifier
    - 5.2: Restore previous conversation history
    - 5.3: Display messages with timestamps
    - 5.5: Preserve tool execution output in history
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    messages: List[ChatMessage] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Optional title for the session (can be auto-generated)
    title: Optional[str] = None
    
    # Track active targets during this session
    active_targets: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True

    def add_message(
        self,
        role: MessageRole,
        content: str,
        tool_calls: Optional[List[ToolCall]] = None,
        tool_execution: Optional[ToolExecution] = None,
        tool_call_id: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> ChatMessage:
        """
        Add a new message to the session.
        
        Args:
            role: The role of the message sender
            content: The message content
            tool_calls: Optional list of tool calls
            tool_execution: Optional tool execution record
            tool_call_id: Optional tool call ID for tool responses
            tool_name: Optional tool name for tool responses
            
        Returns:
            The created ChatMessage
        """
        message = ChatMessage(
            role=role,
            content=content,
            tool_calls=tool_calls,
            tool_execution=tool_execution,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
        )
        self.messages.append(message)
        self.updated_at = datetime.utcnow()
        return message

    def get_conversation_history(
        self,
        limit: Optional[int] = None,
        include_system: bool = True,
    ) -> List[ChatMessage]:
        """
        Get conversation history for context.
        
        Args:
            limit: Optional limit on number of messages
            include_system: Whether to include system messages
            
        Returns:
            List of messages in chronological order
        """
        messages = self.messages
        
        if not include_system:
            messages = [m for m in messages if m.role != MessageRole.SYSTEM]
        
        if limit:
            messages = messages[-limit:]
        
        return messages

    def get_tool_executions(self) -> List[ToolExecution]:
        """
        Get all tool executions from this session.
        
        Returns:
            List of ToolExecution objects
        """
        executions = []
        for message in self.messages:
            if message.tool_execution:
                executions.append(message.tool_execution)
        return executions

    def get_findings(self) -> List[Finding]:
        """
        Get all findings from tool executions in this session.
        
        Returns:
            List of Finding objects
        """
        findings = []
        for execution in self.get_tool_executions():
            findings.extend(execution.findings)
        return findings


class ChatSessionSummary(BaseModel):
    """
    Summary of a chat session for listing.
    
    Provides a lightweight view of a session without full message history.
    """
    id: str
    title: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    message_count: int
    tool_execution_count: int
    finding_count: int
    active_targets: List[str] = Field(default_factory=list)

    @classmethod
    def from_session(cls, session: ChatSession) -> "ChatSessionSummary":
        """Create a summary from a full session."""
        tool_executions = session.get_tool_executions()
        findings = session.get_findings()
        
        return cls(
            id=session.id,
            title=session.title,
            created_at=session.created_at,
            updated_at=session.updated_at,
            message_count=len(session.messages),
            tool_execution_count=len(tool_executions),
            finding_count=len(findings),
            active_targets=session.active_targets,
        )


# API Request/Response Models

class ChatMessageRequest(BaseModel):
    """Request to send a chat message."""
    content: str
    session_id: Optional[str] = None


class ChatConfigUpdate(BaseModel):
    """Request to update chat configuration."""
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    ollama_url: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None


class ChatConfig(BaseModel):
    """Chat configuration response."""
    provider: str
    model: str
    ollama_url: Optional[str] = "http://localhost:11434"
    temperature: float = 0.7
    max_tokens: int = 4096
    # Note: api_key is never returned in responses


class ConfirmationResponse(BaseModel):
    """Response for confirmation actions."""
    execution_id: str
    confirmed: bool
    message: str


__all__ = [
    # Enums
    "MessageRole",
    "ToolExecutionStatus",
    "FindingSeverity",
    "FindingType",
    # Core Models
    "Finding",
    "ToolCall",
    "ToolExecution",
    "ChatMessage",
    "ChatSession",
    "ChatSessionSummary",
    # API Models
    "ChatMessageRequest",
    "ChatConfigUpdate",
    "ChatConfig",
    "ConfirmationResponse",
]

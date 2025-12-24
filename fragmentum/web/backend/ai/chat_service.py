"""
Chat Service for AI Chat Integration.

Orchestrates chat interactions between users and the LLM, handling
message processing, tool execution, and safety confirmations.

Requirements:
- 1.1: Interpret user intent and respond appropriately
- 1.2: Identify appropriate tools and execute them
- 1.3: Display real-time output in chat interface
- 1.4: Summarize results in natural language
- 4.1, 4.2, 4.3, 4.4: Tool execution lifecycle
- 8.1, 8.2, 8.3, 8.5: Safety confirmations for dangerous operations
"""

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional, Set

from fragmentum.tools.registry import get_tool_registry, ToolCategory, Tool
from fragmentum.tools.executor import execute_command, smart_execute
from fragmentum.web.backend.jobs.manager import get_job_manager
from fragmentum.web.backend.ai.providers import (
    LLMProvider,
    LLMProviderType,
    ChatMessage,
    StreamEvent,
    ToolCall,
    ToolSchema,
    get_provider,
)
from fragmentum.web.backend.ai.context import (
    ContextBuilder,
    get_context_builder,
    DANGEROUS_TOOL_PATTERNS,
    DANGEROUS_CATEGORIES,
)
from fragmentum.web.backend.ai.attack_planner import (
    AttackPlanner,
    AttackPlan,
    PlanStep,
    PlanStatus,
    StepStatus,
    AttackPhase,
    get_attack_planner,
)


class ChatEventType(str, Enum):
    """Types of events emitted during chat processing."""
    TEXT = "text"
    TOOL_START = "tool_start"
    TOOL_OUTPUT = "tool_output"
    TOOL_COMPLETE = "tool_complete"
    TOOL_ERROR = "tool_error"
    FINDING = "finding"
    # Multi-step attack planning events
    PLAN_CREATED = "plan_created"
    PLAN_STEP_START = "plan_step_start"
    PLAN_STEP_COMPLETE = "plan_step_complete"
    PLAN_STEP_ERROR = "plan_step_error"
    PLAN_ADAPTED = "plan_adapted"
    PLAN_PAUSED = "plan_paused"
    PLAN_COMPLETE = "plan_complete"
    PLAN_ERROR = "plan_error"
    CONFIRMATION_REQUIRED = "confirmation_required"
    ERROR = "error"
    DONE = "done"


class ToolExecutionStatus(str, Enum):
    """Status of a tool execution."""
    PENDING = "pending"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELLED = "cancelled"


@dataclass
class ChatEvent:
    """Event emitted during chat processing."""
    type: ChatEventType
    content: Optional[str] = None
    tool_name: Optional[str] = None
    execution_id: Optional[str] = None
    output: Optional[str] = None
    finding: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    summary: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ToolExecution:
    """Represents a tool execution request."""
    id: str
    tool_name: str
    parameters: Dict[str, Any]
    status: ToolExecutionStatus
    requires_confirmation: bool = False
    output_lines: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    summary: Optional[str] = None


@dataclass
class PendingConfirmation:
    """A pending confirmation request for dangerous operations."""
    execution_id: str
    tool_name: str
    parameters: Dict[str, Any]
    warning_message: str
    created_at: datetime = field(default_factory=datetime.utcnow)


# Tool categories and patterns that require safety confirmations
EXPLOIT_TOOLS = {
    "searchsploit", "nuclei", "msfvenom_linux", "msfvenom_windows", "msfvenom_php",
    "impacket_secretsdump", "impacket_psexec", "impacket_wmiexec", "impacket_smbexec",
    "impacket_dcomexec", "impacket_atexec", "evil_winrm", "rubeus", "mimikatz",
    "linpeas", "linenum", "pspy", "kubectl_exec",
}

PASSWORD_TOOLS = {
    "hydra_ssh", "hydra_ftp", "hydra_http", "hydra_smb", "hydra_rdp",
    "hydra_mysql", "hydra_postgres", "medusa", "crackmapexec_smb",
    "crackmapexec_winrm", "john", "hashcat",
}

AGGRESSIVE_TOOLS = {
    "masscan", "nmap_full", "unicornscan", "zmap", "responder",
    "bettercap", "ettercap", "arpspoof", "dnsspoof", "sslstrip",
}

# Destructive operations that require double confirmation
DESTRUCTIVE_TOOLS = {
    "mimikatz", "impacket_secretsdump", "rubeus",
}


class SafetyLevel(str, Enum):
    """Safety level for tool operations."""
    SAFE = "safe"
    CAUTION = "caution"  # Single confirmation
    DANGEROUS = "dangerous"  # Double confirmation for destructive ops


@dataclass
class SafetyCheck:
    """Result of a safety check on a tool."""
    level: SafetyLevel
    requires_confirmation: bool
    warning_message: str
    risk_factors: List[str] = field(default_factory=list)


class ChatService:
    """
    Main service for AI chat interactions.
    
    Orchestrates:
    - Message processing through LLM provider
    - Tool call parsing and execution
    - Safety confirmations for dangerous operations
    - Result summarization
    
    Requirements:
    - 1.1: Interpret user intent and respond appropriately
    - 1.2: Identify appropriate tools and execute them
    - 1.3: Display real-time output in chat interface
    - 1.4: Summarize results in natural language
    """
    
    def __init__(
        self,
        provider: LLMProvider,
        context_builder: Optional[ContextBuilder] = None,
    ):
        """
        Initialize the chat service.
        
        Args:
            provider: LLM provider for chat interactions
            context_builder: Optional context builder (uses global if None)
        """
        self._provider = provider
        self._context_builder = context_builder or get_context_builder()
        self._pending_confirmations: Dict[str, PendingConfirmation] = {}
        self._active_executions: Dict[str, ToolExecution] = {}
    
    @property
    def provider(self) -> LLMProvider:
        """Get the LLM provider."""
        return self._provider
    
    @property
    def context_builder(self) -> ContextBuilder:
        """Get the context builder."""
        return self._context_builder
    
    async def process_message(
        self,
        message: str,
        conversation_history: Optional[List[ChatMessage]] = None,
        session_id: Optional[str] = None,
    ) -> AsyncIterator[ChatEvent]:
        """
        Process a user message and yield response events.
        
        This is the main entry point for chat interactions. It:
        1. Builds context with system prompt and tools
        2. Sends message to LLM provider
        3. Handles text responses and tool calls
        4. Executes tools with safety checks
        5. Summarizes results
        
        Args:
            message: User's message text
            conversation_history: Optional previous messages
            session_id: Optional session ID for context
            
        Yields:
            ChatEvent objects for each response element
            
        Requirements: 1.1, 1.2
        """
        # Build conversation with system prompt
        messages = self._build_messages(message, conversation_history)
        
        # Get tool schemas for function calling
        tools = self._context_builder.build_tools_schema()
        
        # Track tool calls from this response
        pending_tool_calls: List[ToolCall] = []
        accumulated_text = ""
        
        try:
            # Stream response from LLM
            async for event in self._provider.chat(
                messages=messages,
                tools=tools,
                stream=True
            ):
                if event.type == "text":
                    accumulated_text += event.content or ""
                    yield ChatEvent(
                        type=ChatEventType.TEXT,
                        content=event.content
                    )
                
                elif event.type == "tool_call":
                    if event.tool_call:
                        pending_tool_calls.append(event.tool_call)
                
                elif event.type == "error":
                    yield ChatEvent(
                        type=ChatEventType.ERROR,
                        message=event.error
                    )
                
                elif event.type == "done":
                    # Process any pending tool calls
                    for tool_call in pending_tool_calls:
                        async for tool_event in self._handle_tool_call(tool_call):
                            yield tool_event
                    
                    yield ChatEvent(type=ChatEventType.DONE)
        
        except Exception as e:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"Error processing message: {str(e)}"
            )
    
    def _build_messages(
        self,
        user_message: str,
        history: Optional[List[ChatMessage]] = None
    ) -> List[ChatMessage]:
        """
        Build the message list for the LLM.
        
        Args:
            user_message: Current user message
            history: Optional conversation history
            
        Returns:
            List of ChatMessage objects
        """
        messages = []
        
        # Add system prompt
        system_prompt = self._context_builder.build_system_prompt()
        messages.append(ChatMessage(role="system", content=system_prompt))
        
        # Add conversation history
        if history:
            messages.extend(history)
        
        # Add current user message
        messages.append(ChatMessage(role="user", content=user_message))
        
        return messages
    
    async def _handle_tool_call(
        self,
        tool_call: ToolCall
    ) -> AsyncIterator[ChatEvent]:
        """
        Handle a tool call from the LLM.
        
        ALL tool calls now require confirmation before execution,
        similar to Claude Desktop's behavior.
        
        Args:
            tool_call: The tool call to handle
            
        Yields:
            ChatEvent objects for the tool execution
            
        Requirements: 1.2, 8.1, 8.2, 8.3
        """
        execution_id = str(uuid.uuid4())
        tool_name = tool_call.name
        parameters = tool_call.parameters
        
        # Check if tool is dangerous (for warning level)
        is_dangerous = self._requires_confirmation(tool_name)
        
        # Create execution record - ALL tools require confirmation now
        execution = ToolExecution(
            id=execution_id,
            tool_name=tool_name,
            parameters=parameters,
            status=ToolExecutionStatus.AWAITING_CONFIRMATION,
            requires_confirmation=True,  # Always require confirmation
        )
        self._active_executions[execution_id] = execution
        
        # Generate confirmation message
        if is_dangerous:
            warning = self._get_safety_warning(tool_name, parameters)
        else:
            warning = self._get_tool_confirmation_message(tool_name, parameters)
        
        # Create pending confirmation
        confirmation = PendingConfirmation(
            execution_id=execution_id,
            tool_name=tool_name,
            parameters=parameters,
            warning_message=warning,
        )
        self._pending_confirmations[execution_id] = confirmation
        
        yield ChatEvent(
            type=ChatEventType.CONFIRMATION_REQUIRED,
            execution_id=execution_id,
            tool_name=tool_name,
            message=warning,
        )
    
    def _get_tool_confirmation_message(
        self,
        tool_name: str,
        parameters: Dict[str, Any]
    ) -> str:
        """
        Generate a confirmation message for a tool call (non-dangerous).
        
        Similar to Claude Desktop's "Claude wants to use X" message.
        
        Args:
            tool_name: Name of the tool
            parameters: Tool parameters
            
        Returns:
            Confirmation message string
        """
        # Format parameters nicely
        params_str = json.dumps(parameters, indent=2, ensure_ascii=False)
        
        # Get tool description from registry
        registry = get_tool_registry()
        tool = registry.get(tool_name)
        tool_desc = tool.description if tool else "Execute tool"
        
        return (
            f"🔧 **FRAGMENTUM wants to use {tool_name}**\n\n"
            f"*{tool_desc}*\n\n"
            f"```json\n{params_str}\n```\n\n"
            f"Allow this tool to run?"
        )
    
    def _requires_confirmation(self, tool_name: str) -> bool:
        """
        Check if a tool requires safety confirmation.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            True if confirmation is required
            
        Requirements: 8.1, 8.2, 8.3
        """
        # Check explicit tool sets
        if tool_name in EXPLOIT_TOOLS:
            return True
        if tool_name in PASSWORD_TOOLS:
            return True
        if tool_name in AGGRESSIVE_TOOLS:
            return True
        
        # Check dangerous patterns
        tool_lower = tool_name.lower()
        for pattern in DANGEROUS_TOOL_PATTERNS:
            if pattern in tool_lower:
                return True
        
        # Check tool category
        registry = get_tool_registry()
        tool = registry.get(tool_name)
        if tool and tool.category in DANGEROUS_CATEGORIES:
            return True
        
        return False
    
    def _get_safety_warning(
        self,
        tool_name: str,
        parameters: Dict[str, Any]
    ) -> str:
        """
        Generate a safety warning message for a dangerous tool.
        
        Args:
            tool_name: Name of the tool
            parameters: Tool parameters
            
        Returns:
            Warning message string
            
        Requirements: 8.1, 8.2, 8.3
        """
        target = parameters.get("target", "unknown target")
        
        if tool_name in EXPLOIT_TOOLS:
            return (
                f"⚠️ **Exploitation Tool Requested**\n\n"
                f"Tool: `{tool_name}`\n"
                f"Target: `{target}`\n\n"
                f"This tool may attempt to exploit vulnerabilities on the target system. "
                f"Ensure you have proper authorization before proceeding.\n\n"
                f"Do you want to continue?"
            )
        
        if tool_name in PASSWORD_TOOLS:
            return (
                f"⚠️ **Password Attack Requested**\n\n"
                f"Tool: `{tool_name}`\n"
                f"Target: `{target}`\n\n"
                f"This tool will attempt to brute-force credentials. "
                f"**Warning**: This may cause account lockouts on the target system.\n\n"
                f"Do you want to continue?"
            )
        
        if tool_name in AGGRESSIVE_TOOLS:
            return (
                f"⚠️ **Aggressive Scanning Requested**\n\n"
                f"Tool: `{tool_name}`\n"
                f"Target: `{target}`\n\n"
                f"This tool performs aggressive network operations that may:\n"
                f"- Be detected by security systems\n"
                f"- Cause network disruption\n"
                f"- Trigger alerts\n\n"
                f"Do you want to continue?"
            )
        
        # Generic warning
        return (
            f"⚠️ **Potentially Dangerous Operation**\n\n"
            f"Tool: `{tool_name}`\n"
            f"Target: `{target}`\n\n"
            f"This operation requires confirmation. Do you want to continue?"
        )
    
    async def confirm_execution(
        self,
        execution_id: str,
        confirmed: bool
    ) -> AsyncIterator[ChatEvent]:
        """
        Handle confirmation response for a pending execution.
        
        Args:
            execution_id: The execution ID to confirm/cancel
            confirmed: Whether the user confirmed the operation
            
        Yields:
            ChatEvent objects for the result
            
        Requirements: 8.1
        """
        if execution_id not in self._pending_confirmations:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"No pending confirmation found for execution {execution_id}"
            )
            return
        
        confirmation = self._pending_confirmations.pop(execution_id)
        execution = self._active_executions.get(execution_id)
        
        if not execution:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"Execution not found: {execution_id}"
            )
            return
        
        if confirmed:
            # Execute the tool
            async for event in self.execute_tool(execution_id):
                yield event
        else:
            # Cancel the execution
            execution.status = ToolExecutionStatus.CANCELLED
            yield ChatEvent(
                type=ChatEventType.TEXT,
                content=f"Operation cancelled: {confirmation.tool_name}"
            )
            yield ChatEvent(type=ChatEventType.DONE)
    
    async def execute_tool(
        self,
        execution_id: str
    ) -> AsyncIterator[ChatEvent]:
        """
        Execute a tool and stream results.
        
        Args:
            execution_id: The execution ID
            
        Yields:
            ChatEvent objects for the execution lifecycle
            
        Requirements: 1.3, 4.1, 4.2, 4.3, 4.4
        """
        execution = self._active_executions.get(execution_id)
        if not execution:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"Execution not found: {execution_id}"
            )
            return
        
        tool_name = execution.tool_name
        parameters = execution.parameters
        
        # Get tool from registry
        registry = get_tool_registry()
        tool = registry.get(tool_name)
        
        if not tool:
            execution.status = ToolExecutionStatus.ERROR
            execution.error = f"Tool not found: {tool_name}"
            yield ChatEvent(
                type=ChatEventType.TOOL_ERROR,
                execution_id=execution_id,
                tool_name=tool_name,
                message=f"Tool not found: {tool_name}"
            )
            return
        
        # Emit tool start event - Requirements 4.1
        execution.status = ToolExecutionStatus.RUNNING
        execution.started_at = datetime.utcnow()
        
        # Get tool explanation with target context - Requirements 3.4
        target = parameters.get("target", "")
        explanation = self._context_builder.get_tool_explanation(tool_name, target=target)
        
        yield ChatEvent(
            type=ChatEventType.TOOL_START,
            execution_id=execution_id,
            tool_name=tool_name,
            message=explanation,
        )
        
        # Build and execute command
        options = {k: v for k, v in parameters.items() if k != "target"}
        command = tool.build_command(target=target, options=options)
        
        try:
            # Execute with streaming - Requirements 4.2
            async for output_event in self._execute_with_streaming(
                execution_id, command, tool.timeout
            ):
                yield output_event
            
            # Mark as completed
            execution.status = ToolExecutionStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            
            # Parse findings from output
            full_output = "\n".join(execution.output_lines)
            findings = self._parse_findings(full_output, tool_name, target)
            execution.findings = findings
            
            # Emit findings - Requirements 4.3
            for finding in findings:
                yield ChatEvent(
                    type=ChatEventType.FINDING,
                    execution_id=execution_id,
                    finding=finding,
                )
            
            # Generate summary - Requirements 1.4, 4.4
            summary = await self._generate_summary(
                tool_name, target, full_output, findings
            )
            execution.summary = summary
            
            yield ChatEvent(
                type=ChatEventType.TOOL_COMPLETE,
                execution_id=execution_id,
                tool_name=tool_name,
                summary=summary,
            )
        
        except Exception as e:
            execution.status = ToolExecutionStatus.ERROR
            execution.error = str(e)
            execution.completed_at = datetime.utcnow()
            
            yield ChatEvent(
                type=ChatEventType.TOOL_ERROR,
                execution_id=execution_id,
                tool_name=tool_name,
                message=f"Execution error: {str(e)}"
            )
    
    async def _execute_with_streaming(
        self,
        execution_id: str,
        command: str,
        timeout: int
    ) -> AsyncIterator[ChatEvent]:
        """
        Execute a command and stream output.
        
        Args:
            execution_id: The execution ID
            command: Command to execute
            timeout: Timeout in seconds
            
        Yields:
            ChatEvent objects for output lines
            
        Requirements: 1.3, 4.2
        """
        execution = self._active_executions.get(execution_id)
        if not execution:
            return
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            
            while True:
                try:
                    line = await asyncio.wait_for(
                        process.stdout.readline(),
                        timeout=timeout
                    )
                    
                    if not line:
                        break
                    
                    decoded_line = line.decode('utf-8', errors='replace').rstrip()
                    execution.output_lines.append(decoded_line)
                    
                    yield ChatEvent(
                        type=ChatEventType.TOOL_OUTPUT,
                        execution_id=execution_id,
                        output=decoded_line,
                    )
                
                except asyncio.TimeoutError:
                    process.kill()
                    timeout_msg = f"[Timeout: Command exceeded {timeout}s limit]"
                    execution.output_lines.append(timeout_msg)
                    yield ChatEvent(
                        type=ChatEventType.TOOL_OUTPUT,
                        execution_id=execution_id,
                        output=timeout_msg,
                    )
                    break
            
            await process.wait()
        
        except Exception as e:
            error_msg = f"[Error: {str(e)}]"
            execution.output_lines.append(error_msg)
            yield ChatEvent(
                type=ChatEventType.TOOL_OUTPUT,
                execution_id=execution_id,
                output=error_msg,
            )
    
    def _parse_findings(
        self,
        output: str,
        tool_name: str,
        target: str
    ) -> List[Dict[str, Any]]:
        """
        Parse tool output to extract findings.
        
        Args:
            output: Tool output text
            tool_name: Name of the tool
            target: Target that was scanned
            
        Returns:
            List of finding dictionaries
        """
        import re
        findings = []
        
        # Nmap port findings
        if tool_name.startswith("nmap"):
            port_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)"
            for match in re.finditer(port_pattern, output, re.IGNORECASE):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "type": "port",
                    "value": {
                        "port": int(match.group(1)),
                        "protocol": match.group(2),
                        "service": match.group(3),
                        "version": match.group(4).strip() if match.group(4) else ""
                    },
                    "severity": "info",
                    "source": tool_name,
                    "target": target,
                })
        
        # Hydra credential findings
        elif tool_name.startswith("hydra"):
            cred_pattern = r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
            for match in re.finditer(cred_pattern, output, re.IGNORECASE):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "type": "credential",
                    "value": {
                        "username": match.group(4),
                        "password": match.group(5),
                        "service": match.group(2),
                        "port": int(match.group(1))
                    },
                    "severity": "critical",
                    "source": tool_name,
                    "target": match.group(3),
                })
        
        # Directory findings
        elif tool_name in ["gobuster", "dirb", "ffuf", "feroxbuster"]:
            # Match status codes and paths
            dir_pattern = r"(/\S+)\s+\(Status:\s*(\d+)\)"
            for match in re.finditer(dir_pattern, output):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "type": "info",
                    "value": {
                        "path": match.group(1),
                        "status_code": int(match.group(2))
                    },
                    "severity": "low",
                    "source": tool_name,
                    "target": target,
                })
        
        # Nikto vulnerability findings
        elif tool_name == "nikto":
            vuln_pattern = r"\+\s+OSVDB-(\d+):\s+(.+)"
            for match in re.finditer(vuln_pattern, output):
                findings.append({
                    "id": str(uuid.uuid4()),
                    "type": "vulnerability",
                    "value": {
                        "osvdb_id": match.group(1),
                        "description": match.group(2).strip()
                    },
                    "severity": "medium",
                    "source": tool_name,
                    "target": target,
                })
        
        return findings
    
    async def _generate_summary(
        self,
        tool_name: str,
        target: str,
        output: str,
        findings: List[Dict[str, Any]]
    ) -> str:
        """
        Generate a natural language summary of tool results.
        
        Args:
            tool_name: Name of the tool
            target: Target that was scanned
            output: Full tool output
            findings: Parsed findings
            
        Returns:
            Summary string
            
        Requirements: 1.4, 4.4
        """
        # Build summary based on findings
        if not findings:
            return f"✅ `{tool_name}` completed on `{target}`. No significant findings detected."
        
        # Count findings by type
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        
        for finding in findings:
            f_type = finding.get("type", "unknown")
            f_severity = finding.get("severity", "info")
            by_type[f_type] = by_type.get(f_type, 0) + 1
            by_severity[f_severity] = by_severity.get(f_severity, 0) + 1
        
        # Build summary parts
        parts = [f"📊 **{tool_name}** completed on `{target}`\n"]
        
        # Add finding counts
        parts.append(f"**Findings**: {len(findings)} total")
        
        if by_type:
            type_str = ", ".join(f"{count} {t}" for t, count in by_type.items())
            parts.append(f"  - By type: {type_str}")
        
        if by_severity:
            sev_str = ", ".join(f"{count} {s}" for s, count in by_severity.items())
            parts.append(f"  - By severity: {sev_str}")
        
        # Highlight critical/high findings
        critical_high = [
            f for f in findings
            if f.get("severity") in ("critical", "high")
        ]
        
        if critical_high:
            parts.append("\n⚠️ **Notable findings**:")
            for finding in critical_high[:5]:  # Limit to 5
                f_type = finding.get("type", "unknown")
                f_value = finding.get("value", {})
                if f_type == "credential":
                    parts.append(
                        f"  - 🔑 Credential found: `{f_value.get('username')}` "
                        f"on {f_value.get('service', 'unknown')}"
                    )
                elif f_type == "vulnerability":
                    parts.append(
                        f"  - 🔴 Vulnerability: {f_value.get('description', 'Unknown')[:100]}"
                    )
                elif f_type == "port":
                    parts.append(
                        f"  - 🔓 Open port: {f_value.get('port')}/{f_value.get('protocol')} "
                        f"({f_value.get('service', 'unknown')})"
                    )
        
        return "\n".join(parts)
    
    def get_pending_confirmations(self) -> List[PendingConfirmation]:
        """Get all pending confirmations."""
        return list(self._pending_confirmations.values())
    
    def get_execution(self, execution_id: str) -> Optional[ToolExecution]:
        """Get an execution by ID."""
        return self._active_executions.get(execution_id)
    
    def clear_execution(self, execution_id: str) -> None:
        """Clear an execution from tracking."""
        self._active_executions.pop(execution_id, None)
        self._pending_confirmations.pop(execution_id, None)
    
    async def execute_tool_via_job_manager(
        self,
        execution_id: str
    ) -> AsyncIterator[ChatEvent]:
        """
        Execute a tool using the job manager for better integration.
        
        This method uses the existing job infrastructure for execution
        while still providing chat-specific events.
        
        Args:
            execution_id: The execution ID
            
        Yields:
            ChatEvent objects for the execution lifecycle
            
        Requirements: 1.3, 4.1, 4.2, 4.3, 4.4
        """
        execution = self._active_executions.get(execution_id)
        if not execution:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"Execution not found: {execution_id}"
            )
            return
        
        tool_name = execution.tool_name
        parameters = execution.parameters
        target = parameters.get("target", "")
        
        # Get tool from registry
        registry = get_tool_registry()
        tool = registry.get(tool_name)
        
        if not tool:
            execution.status = ToolExecutionStatus.ERROR
            execution.error = f"Tool not found: {tool_name}"
            yield ChatEvent(
                type=ChatEventType.TOOL_ERROR,
                execution_id=execution_id,
                tool_name=tool_name,
                message=f"Tool not found: {tool_name}"
            )
            return
        
        # Emit tool start event with explanation
        execution.status = ToolExecutionStatus.RUNNING
        execution.started_at = datetime.utcnow()
        
        # Get tool explanation with target context - Requirements 3.4
        explanation = self._context_builder.get_tool_explanation(tool_name, target=target)
        
        yield ChatEvent(
            type=ChatEventType.TOOL_START,
            execution_id=execution_id,
            tool_name=tool_name,
            message=explanation,
        )
        
        # Create job via job manager
        job_manager = get_job_manager()
        job = job_manager.create_job(
            tool_name=tool_name,
            parameters=parameters,
            target_id=None  # Could be linked to a target if available
        )
        
        # Execute and stream output
        try:
            options = {k: v for k, v in parameters.items() if k != "target"}
            command = tool.build_command(target=target, options=options)
            
            async for output_event in self._execute_with_streaming(
                execution_id, command, tool.timeout
            ):
                yield output_event
            
            # Mark as completed
            execution.status = ToolExecutionStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            
            # Parse findings
            full_output = "\n".join(execution.output_lines)
            findings = self._parse_findings(full_output, tool_name, target)
            execution.findings = findings
            
            # Emit findings
            for finding in findings:
                yield ChatEvent(
                    type=ChatEventType.FINDING,
                    execution_id=execution_id,
                    finding=finding,
                )
            
            # Generate and emit summary
            summary = await self._generate_summary(
                tool_name, target, full_output, findings
            )
            execution.summary = summary
            
            yield ChatEvent(
                type=ChatEventType.TOOL_COMPLETE,
                execution_id=execution_id,
                tool_name=tool_name,
                summary=summary,
            )
        
        except Exception as e:
            execution.status = ToolExecutionStatus.ERROR
            execution.error = str(e)
            execution.completed_at = datetime.utcnow()
            
            yield ChatEvent(
                type=ChatEventType.TOOL_ERROR,
                execution_id=execution_id,
                tool_name=tool_name,
                message=f"Execution error: {str(e)}"
            )
    
    def get_tool_output(self, execution_id: str) -> str:
        """
        Get the full output of a tool execution.
        
        Args:
            execution_id: The execution ID
            
        Returns:
            Full output string
        """
        execution = self._active_executions.get(execution_id)
        if not execution:
            return ""
        return "\n".join(execution.output_lines)
    
    def get_tool_findings(self, execution_id: str) -> List[Dict[str, Any]]:
        """
        Get findings from a tool execution.
        
        Args:
            execution_id: The execution ID
            
        Returns:
            List of finding dictionaries
        """
        execution = self._active_executions.get(execution_id)
        if not execution:
            return []
        return execution.findings
    
    def check_tool_safety(
        self,
        tool_name: str,
        parameters: Dict[str, Any]
    ) -> SafetyCheck:
        """
        Perform a comprehensive safety check on a tool.
        
        Args:
            tool_name: Name of the tool
            parameters: Tool parameters
            
        Returns:
            SafetyCheck with level, confirmation requirement, and warnings
            
        Requirements: 8.1, 8.2, 8.3, 8.5
        """
        risk_factors = []
        target = parameters.get("target", "unknown")
        
        # Check for destructive tools (double confirmation)
        if tool_name in DESTRUCTIVE_TOOLS:
            risk_factors.append("Destructive operation - may cause permanent changes")
            return SafetyCheck(
                level=SafetyLevel.DANGEROUS,
                requires_confirmation=True,
                warning_message=self._get_destructive_warning(tool_name, parameters),
                risk_factors=risk_factors,
            )
        
        # Check for exploit tools
        if tool_name in EXPLOIT_TOOLS:
            risk_factors.append("Exploitation tool - may compromise target system")
            return SafetyCheck(
                level=SafetyLevel.CAUTION,
                requires_confirmation=True,
                warning_message=self._get_safety_warning(tool_name, parameters),
                risk_factors=risk_factors,
            )
        
        # Check for password tools
        if tool_name in PASSWORD_TOOLS:
            risk_factors.append("Password attack - may cause account lockouts")
            return SafetyCheck(
                level=SafetyLevel.CAUTION,
                requires_confirmation=True,
                warning_message=self._get_safety_warning(tool_name, parameters),
                risk_factors=risk_factors,
            )
        
        # Check for aggressive tools
        if tool_name in AGGRESSIVE_TOOLS:
            risk_factors.append("Aggressive scanning - may trigger security alerts")
            return SafetyCheck(
                level=SafetyLevel.CAUTION,
                requires_confirmation=True,
                warning_message=self._get_safety_warning(tool_name, parameters),
                risk_factors=risk_factors,
            )
        
        # Check dangerous patterns
        tool_lower = tool_name.lower()
        for pattern in DANGEROUS_TOOL_PATTERNS:
            if pattern in tool_lower:
                risk_factors.append(f"Tool matches dangerous pattern: {pattern}")
                return SafetyCheck(
                    level=SafetyLevel.CAUTION,
                    requires_confirmation=True,
                    warning_message=self._get_safety_warning(tool_name, parameters),
                    risk_factors=risk_factors,
                )
        
        # Check tool category
        registry = get_tool_registry()
        tool = registry.get(tool_name)
        if tool and tool.category in DANGEROUS_CATEGORIES:
            risk_factors.append(f"Tool category is dangerous: {tool.category.value}")
            return SafetyCheck(
                level=SafetyLevel.CAUTION,
                requires_confirmation=True,
                warning_message=self._get_safety_warning(tool_name, parameters),
                risk_factors=risk_factors,
            )
        
        # Safe tool
        return SafetyCheck(
            level=SafetyLevel.SAFE,
            requires_confirmation=False,
            warning_message="",
            risk_factors=[],
        )
    
    def _get_destructive_warning(
        self,
        tool_name: str,
        parameters: Dict[str, Any]
    ) -> str:
        """
        Generate a warning for destructive operations.
        
        Args:
            tool_name: Name of the tool
            parameters: Tool parameters
            
        Returns:
            Warning message requiring double confirmation
            
        Requirements: 8.5
        """
        target = parameters.get("target", "unknown target")
        
        return (
            f"🚨 **DESTRUCTIVE OPERATION REQUESTED**\n\n"
            f"Tool: `{tool_name}`\n"
            f"Target: `{target}`\n\n"
            f"⚠️ **This operation may cause permanent changes:**\n"
            f"- Credential extraction\n"
            f"- System modification\n"
            f"- Data exfiltration\n\n"
            f"**This requires double confirmation.**\n"
            f"Type 'CONFIRM' to proceed or 'cancel' to abort."
        )
    
    async def handle_double_confirmation(
        self,
        execution_id: str,
        confirmation_text: str
    ) -> AsyncIterator[ChatEvent]:
        """
        Handle double confirmation for destructive operations.
        
        Args:
            execution_id: The execution ID
            confirmation_text: User's confirmation text
            
        Yields:
            ChatEvent objects for the result
            
        Requirements: 8.5
        """
        if execution_id not in self._pending_confirmations:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"No pending confirmation found for execution {execution_id}"
            )
            return
        
        confirmation = self._pending_confirmations.get(execution_id)
        execution = self._active_executions.get(execution_id)
        
        if not execution or not confirmation:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"Execution not found: {execution_id}"
            )
            return
        
        # Check for explicit CONFIRM text for destructive operations
        if confirmation_text.strip().upper() == "CONFIRM":
            self._pending_confirmations.pop(execution_id)
            async for event in self.execute_tool(execution_id):
                yield event
        elif confirmation_text.strip().lower() == "cancel":
            self._pending_confirmations.pop(execution_id)
            execution.status = ToolExecutionStatus.CANCELLED
            yield ChatEvent(
                type=ChatEventType.TEXT,
                content=f"Operation cancelled: {confirmation.tool_name}"
            )
            yield ChatEvent(type=ChatEventType.DONE)
        else:
            yield ChatEvent(
                type=ChatEventType.TEXT,
                content=(
                    "Invalid confirmation. Please type 'CONFIRM' (in uppercase) "
                    "to proceed or 'cancel' to abort."
                )
            )
    
    def is_target_in_scope(self, target: str) -> bool:
        """
        Check if a target appears to be within authorized scope.
        
        This is a basic check - in production, this should be
        configured with actual authorized ranges.
        
        Args:
            target: Target IP, domain, or CIDR
            
        Returns:
            True if target appears to be in scope
            
        Requirements: 8.4
        """
        # Check for obviously external targets
        external_patterns = [
            "google.com", "facebook.com", "amazon.com", "microsoft.com",
            "apple.com", "twitter.com", "linkedin.com", "github.com",
        ]
        
        target_lower = target.lower()
        for pattern in external_patterns:
            if pattern in target_lower:
                return False
        
        # Check for private IP ranges (likely in scope)
        import re
        private_patterns = [
            r"^10\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^192\.168\.",
            r"^127\.",
        ]
        
        for pattern in private_patterns:
            if re.match(pattern, target):
                return True
        
        # Default to in-scope for other targets
        # In production, this should check against configured scope
        return True
    
    # =========================================================================
    # Multi-Step Attack Planning Methods
    # Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
    # =========================================================================
    
    async def process_full_assessment(
        self,
        message: str,
        conversation_history: Optional[List[ChatMessage]] = None,
    ) -> AsyncIterator[ChatEvent]:
        """
        Process a full assessment request and execute multi-step attack plan.
        
        This method:
        1. Detects if the message is a full assessment request
        2. Creates an attack plan with multiple phases
        3. Executes each step sequentially
        4. Adapts the plan based on findings
        5. Handles errors and confirmations
        
        Args:
            message: User's message text
            conversation_history: Optional previous messages
            
        Yields:
            ChatEvent objects for each step of the assessment
            
        Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
        """
        planner = get_attack_planner()
        
        # Check if this is a full assessment request
        if not planner.is_full_assessment_request(message):
            # Not a full assessment, process normally
            async for event in self.process_message(message, conversation_history):
                yield event
            return
        
        # Extract target from message
        target = planner.extract_target(message)
        if not target:
            yield ChatEvent(
                type=ChatEventType.TEXT,
                content="I detected a full assessment request, but couldn't identify the target. "
                        "Please specify the target IP, domain, or CIDR range."
            )
            yield ChatEvent(type=ChatEventType.DONE)
            return
        
        # Check scope warning
        scope_warning = self.get_scope_warning(target)
        if scope_warning:
            yield ChatEvent(
                type=ChatEventType.TEXT,
                content=scope_warning
            )
        
        # Check if exploitation is requested
        include_exploitation = any(
            word in message.lower()
            for word in ["exploit", "pwn", "hack", "explorar", "comprometer"]
        )
        
        # Create the attack plan
        plan = planner.create_plan(
            target=target,
            include_exploitation=include_exploitation,
        )
        
        # Emit plan created event
        yield ChatEvent(
            type=ChatEventType.PLAN_CREATED,
            content=planner.get_plan_summary(plan),
            message=f"Created attack plan with {len(plan.steps)} steps for {target}",
        )
        
        # Execute the plan
        async for event in self._execute_attack_plan(plan.id):
            yield event
    
    async def _execute_attack_plan(
        self,
        plan_id: str,
    ) -> AsyncIterator[ChatEvent]:
        """
        Execute an attack plan step by step.
        
        Args:
            plan_id: ID of the plan to execute
            
        Yields:
            ChatEvent objects for each step
            
        Requirements: 7.2, 7.3, 7.5
        """
        planner = get_attack_planner()
        plan = planner.get_plan(plan_id)
        
        if not plan:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"Plan not found: {plan_id}"
            )
            return
        
        plan.status = PlanStatus.IN_PROGRESS
        
        while plan.current_step_index < len(plan.steps):
            step = plan.current_step
            if not step:
                break
            
            # Skip already completed steps
            if step.status in (StepStatus.COMPLETED, StepStatus.SKIPPED):
                planner.advance_plan(plan_id)
                continue
            
            # Check if step requires confirmation (exploitation phase)
            if step.requires_confirmation or step.phase == AttackPhase.EXPLOITATION:
                yield ChatEvent(
                    type=ChatEventType.CONFIRMATION_REQUIRED,
                    execution_id=step.id,
                    tool_name=step.tool_name,
                    message=self._get_exploitation_confirmation_message(step),
                )
                
                # Store pending confirmation and pause
                confirmation = PendingConfirmation(
                    execution_id=step.id,
                    tool_name=step.tool_name,
                    parameters=step.parameters,
                    warning_message=self._get_exploitation_confirmation_message(step),
                )
                self._pending_confirmations[step.id] = confirmation
                plan.status = PlanStatus.AWAITING_CONFIRMATION
                
                # Return and wait for confirmation
                return
            
            # Execute the step
            async for event in self._execute_plan_step(plan_id, step):
                yield event
                
                # Check if we need to pause due to error
                if event.type == ChatEventType.PLAN_STEP_ERROR:
                    plan.status = PlanStatus.PAUSED
                    yield ChatEvent(
                        type=ChatEventType.PLAN_PAUSED,
                        message=f"Plan paused due to error in step: {step.description}\n\n"
                                f"Error: {step.error}\n\n"
                                f"Would you like to:\n"
                                f"1. Skip this step and continue\n"
                                f"2. Retry this step\n"
                                f"3. Cancel the assessment",
                    )
                    return
            
            # Advance to next step
            planner.advance_plan(plan_id)
        
        # Plan completed
        plan.status = PlanStatus.COMPLETED
        yield ChatEvent(
            type=ChatEventType.PLAN_COMPLETE,
            content=self._generate_plan_completion_summary(plan),
            message=f"Assessment of {plan.target} completed",
        )
        yield ChatEvent(type=ChatEventType.DONE)
    
    async def _execute_plan_step(
        self,
        plan_id: str,
        step: PlanStep,
    ) -> AsyncIterator[ChatEvent]:
        """
        Execute a single step in the attack plan.
        
        Args:
            plan_id: ID of the plan
            step: Step to execute
            
        Yields:
            ChatEvent objects for the step execution
            
        Requirements: 7.2, 7.3
        """
        planner = get_attack_planner()
        plan = planner.get_plan(plan_id)
        
        if not plan:
            return
        
        # Emit step start with explanation - Requirements 7.2
        step.status = StepStatus.RUNNING
        step.started_at = datetime.utcnow()
        
        explanation = planner.get_step_explanation(step)
        yield ChatEvent(
            type=ChatEventType.PLAN_STEP_START,
            content=explanation,
            tool_name=step.tool_name,
            execution_id=step.id,
            message=step.description,
        )
        
        # Create tool execution
        execution_id = str(uuid.uuid4())
        execution = ToolExecution(
            id=execution_id,
            tool_name=step.tool_name,
            parameters=step.parameters,
            status=ToolExecutionStatus.RUNNING,
        )
        self._active_executions[execution_id] = execution
        
        # Get tool from registry
        registry = get_tool_registry()
        tool = registry.get(step.tool_name)
        
        if not tool:
            step.status = StepStatus.ERROR
            step.error = f"Tool not found: {step.tool_name}"
            yield ChatEvent(
                type=ChatEventType.PLAN_STEP_ERROR,
                execution_id=step.id,
                tool_name=step.tool_name,
                message=f"Tool not found: {step.tool_name}",
            )
            return
        
        # Build and execute command
        target = step.parameters.get("target", "")
        options = {k: v for k, v in step.parameters.items() if k != "target"}
        command = tool.build_command(target=target, options=options)
        
        try:
            # Execute with streaming
            async for output_event in self._execute_with_streaming(
                execution_id, command, tool.timeout
            ):
                yield output_event
            
            # Mark execution as completed
            execution.status = ToolExecutionStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            
            # Parse findings
            full_output = "\n".join(execution.output_lines)
            findings = self._parse_findings(full_output, step.tool_name, target)
            execution.findings = findings
            
            # Emit findings
            for finding in findings:
                yield ChatEvent(
                    type=ChatEventType.FINDING,
                    execution_id=execution_id,
                    finding=finding,
                )
            
            # Mark step as completed
            step.status = StepStatus.COMPLETED
            step.output = execution.output_lines
            step.findings = findings
            step.completed_at = datetime.utcnow()
            
            # Generate summary
            summary = await self._generate_summary(
                step.tool_name, target, full_output, findings
            )
            
            yield ChatEvent(
                type=ChatEventType.PLAN_STEP_COMPLETE,
                execution_id=step.id,
                tool_name=step.tool_name,
                summary=summary,
            )
            
            # Adapt plan based on findings - Requirements 7.3
            if findings:
                new_steps = planner.adapt_plan(plan_id, findings)
                if new_steps:
                    yield ChatEvent(
                        type=ChatEventType.PLAN_ADAPTED,
                        content=f"Based on findings, added {len(new_steps)} new steps to the plan:\n" +
                                "\n".join(f"  - {s.description}" for s in new_steps),
                        message=f"Plan adapted with {len(new_steps)} new steps",
                    )
        
        except Exception as e:
            step.status = StepStatus.ERROR
            step.error = str(e)
            step.completed_at = datetime.utcnow()
            
            planner.mark_step_error(plan_id, step.id, str(e))
            
            yield ChatEvent(
                type=ChatEventType.PLAN_STEP_ERROR,
                execution_id=step.id,
                tool_name=step.tool_name,
                message=f"Error executing step: {str(e)}",
            )
    
    def _get_exploitation_confirmation_message(self, step: PlanStep) -> str:
        """
        Generate confirmation message for exploitation steps.
        
        Args:
            step: The exploitation step
            
        Returns:
            Confirmation message
            
        Requirements: 7.4
        """
        target = step.parameters.get("target", "unknown")
        
        return (
            f"⚠️ **Exploitation Step Requires Confirmation**\n\n"
            f"**Step:** {step.description}\n"
            f"**Tool:** `{step.tool_name}`\n"
            f"**Target:** `{target}`\n\n"
            f"**Rationale:** {step.rationale}\n\n"
            f"This step may attempt to exploit vulnerabilities on the target system. "
            f"Ensure you have proper authorization before proceeding.\n\n"
            f"Do you want to continue with this step?"
        )
    
    def _generate_plan_completion_summary(self, plan: AttackPlan) -> str:
        """
        Generate a summary when the plan completes.
        
        Args:
            plan: The completed plan
            
        Returns:
            Summary string
        """
        summary_parts = [
            f"✅ **Assessment Complete: {plan.target}**",
            f"",
            f"**Duration:** {self._format_duration(plan.created_at, datetime.utcnow())}",
            f"**Steps Completed:** {len(plan.completed_steps)}/{len(plan.steps)}",
            f"",
        ]
        
        # Findings summary
        if plan.all_findings:
            summary_parts.append(f"**Total Findings:** {len(plan.all_findings)}")
            
            # Group by severity
            by_severity: Dict[str, int] = {}
            for finding in plan.all_findings:
                severity = finding.get("severity", "info")
                by_severity[severity] = by_severity.get(severity, 0) + 1
            
            if by_severity:
                severity_str = ", ".join(
                    f"{count} {sev}" for sev, count in sorted(by_severity.items())
                )
                summary_parts.append(f"  - By severity: {severity_str}")
        
        # Discovered services
        if plan.discovered_services:
            summary_parts.append(f"")
            summary_parts.append(f"**Discovered Services:**")
            for port, service in sorted(plan.discovered_services.items()):
                summary_parts.append(f"  - Port {port}: {service}")
        
        # Discovered vulnerabilities
        if plan.discovered_vulnerabilities:
            summary_parts.append(f"")
            summary_parts.append(f"**Potential Vulnerabilities:**")
            for vuln in plan.discovered_vulnerabilities[:10]:
                summary_parts.append(f"  - {vuln}")
        
        # Recommendations
        summary_parts.extend([
            "",
            "**Recommended Next Steps:**",
        ])
        
        if plan.discovered_vulnerabilities:
            summary_parts.append("  - Review and validate discovered vulnerabilities")
            summary_parts.append("  - Search for exploits using `searchsploit`")
        
        if plan.discovered_services:
            summary_parts.append("  - Perform deeper enumeration on discovered services")
        
        summary_parts.append("  - Document findings and prepare report")
        
        return "\n".join(summary_parts)
    
    def _format_duration(self, start: datetime, end: datetime) -> str:
        """Format duration between two timestamps."""
        delta = end - start
        total_seconds = int(delta.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds} seconds"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes}m {seconds}s"
        else:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    async def handle_plan_confirmation(
        self,
        step_id: str,
        confirmed: bool,
    ) -> AsyncIterator[ChatEvent]:
        """
        Handle confirmation response for a plan step.
        
        Args:
            step_id: The step ID to confirm/skip
            confirmed: Whether the user confirmed
            
        Yields:
            ChatEvent objects for the result
            
        Requirements: 7.4
        """
        # Find the plan containing this step
        planner = get_attack_planner()
        plan = None
        step = None
        
        for p in planner._active_plans.values():
            for s in p.steps:
                if s.id == step_id:
                    plan = p
                    step = s
                    break
            if plan:
                break
        
        if not plan or not step:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"Step not found: {step_id}"
            )
            return
        
        # Remove from pending confirmations
        self._pending_confirmations.pop(step_id, None)
        
        if confirmed:
            # Continue with the step
            plan.status = PlanStatus.IN_PROGRESS
            
            async for event in self._execute_plan_step(plan.id, step):
                yield event
            
            # Continue with remaining steps
            planner.advance_plan(plan.id)
            async for event in self._execute_attack_plan(plan.id):
                yield event
        else:
            # Skip this step
            step.status = StepStatus.SKIPPED
            yield ChatEvent(
                type=ChatEventType.TEXT,
                content=f"Skipped step: {step.description}"
            )
            
            # Continue with remaining steps
            planner.advance_plan(plan.id)
            async for event in self._execute_attack_plan(plan.id):
                yield event
    
    async def handle_plan_error_response(
        self,
        plan_id: str,
        action: str,
    ) -> AsyncIterator[ChatEvent]:
        """
        Handle user response to a plan error.
        
        Args:
            plan_id: The plan ID
            action: User's chosen action ("skip", "retry", "cancel")
            
        Yields:
            ChatEvent objects for the result
            
        Requirements: 7.5
        """
        planner = get_attack_planner()
        plan = planner.get_plan(plan_id)
        
        if not plan:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"Plan not found: {plan_id}"
            )
            return
        
        current_step = plan.current_step
        
        if action == "skip":
            # Skip the errored step and continue
            if current_step:
                current_step.status = StepStatus.SKIPPED
            
            yield ChatEvent(
                type=ChatEventType.TEXT,
                content=f"Skipping step and continuing with assessment..."
            )
            
            planner.advance_plan(plan_id)
            async for event in self._execute_attack_plan(plan_id):
                yield event
        
        elif action == "retry":
            # Reset step status and retry
            if current_step:
                current_step.status = StepStatus.PENDING
                current_step.error = None
            
            plan.status = PlanStatus.IN_PROGRESS
            
            yield ChatEvent(
                type=ChatEventType.TEXT,
                content=f"Retrying step: {current_step.description if current_step else 'unknown'}"
            )
            
            async for event in self._execute_attack_plan(plan_id):
                yield event
        
        elif action == "cancel":
            # Cancel the entire plan
            planner.cancel_plan(plan_id)
            
            yield ChatEvent(
                type=ChatEventType.TEXT,
                content=f"Assessment cancelled. Completed {len(plan.completed_steps)} of {len(plan.steps)} steps."
            )
            yield ChatEvent(type=ChatEventType.DONE)
        
        else:
            yield ChatEvent(
                type=ChatEventType.ERROR,
                message=f"Unknown action: {action}. Please choose 'skip', 'retry', or 'cancel'."
            )
    
    def get_active_plan(self, target: Optional[str] = None) -> Optional[AttackPlan]:
        """
        Get an active plan, optionally filtered by target.
        
        Args:
            target: Optional target to filter by
            
        Returns:
            Active plan if found, None otherwise
        """
        planner = get_attack_planner()
        
        for plan in planner._active_plans.values():
            if plan.status in (PlanStatus.IN_PROGRESS, PlanStatus.PAUSED, PlanStatus.AWAITING_CONFIRMATION):
                if target is None or plan.target == target:
                    return plan
        
        return None

    def get_scope_warning(self, target: str) -> Optional[str]:
        """
        Get a warning if target appears out of scope.
        
        Args:
            target: Target to check
            
        Returns:
            Warning message if out of scope, None otherwise
            
        Requirements: 8.4
        """
        if not self.is_target_in_scope(target):
            return (
                f"⚠️ **Potential Scope Warning**\n\n"
                f"Target `{target}` appears to be outside typical authorized scope.\n\n"
                f"Please verify you have proper authorization before proceeding."
            )
        return None


# Factory function for creating chat service
def create_chat_service(
    provider_type: LLMProviderType,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    ollama_url: Optional[str] = None,
    context_builder: Optional[ContextBuilder] = None,
) -> ChatService:
    """
    Create a ChatService with the specified provider.
    
    Args:
        provider_type: Type of LLM provider
        api_key: API key for cloud providers
        model: Model name (uses provider default if None)
        ollama_url: URL for Ollama provider
        context_builder: Optional context builder
        
    Returns:
        Configured ChatService instance
    """
    # Build provider kwargs
    kwargs: Dict[str, Any] = {}
    
    if provider_type == LLMProviderType.OLLAMA:
        if ollama_url:
            kwargs["base_url"] = ollama_url
        if model:
            kwargs["model"] = model
    else:
        if api_key:
            kwargs["api_key"] = api_key
        if model:
            kwargs["model"] = model
    
    provider = get_provider(provider_type, **kwargs)
    return ChatService(provider=provider, context_builder=context_builder)


__all__ = [
    "ChatService",
    "ChatEvent",
    "ChatEventType",
    "ToolExecution",
    "ToolExecutionStatus",
    "PendingConfirmation",
    "SafetyCheck",
    "SafetyLevel",
    "create_chat_service",
    "EXPLOIT_TOOLS",
    "PASSWORD_TOOLS",
    "AGGRESSIVE_TOOLS",
    "DESTRUCTIVE_TOOLS",
    # Attack planning exports
    "AttackPlanner",
    "AttackPlan",
    "PlanStep",
    "PlanStatus",
    "StepStatus",
    "AttackPhase",
    "get_attack_planner",
]

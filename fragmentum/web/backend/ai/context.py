"""
Context Builder for AI Chat Integration.

Builds system prompts and tool schemas for LLM providers, including
dynamic context from active targets and session findings.

Requirements:
- 3.1: Load complete tool registry with descriptions and parameters
- 3.2: Include target information in context
- 3.3: Reference findings when suggesting next steps
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime

from fragmentum.tools.registry import ToolRegistry, Tool, ToolCategory
from fragmentum.web.backend.ai.providers import ToolSchema


# Tool categories that require safety confirmations
DANGEROUS_CATEGORIES = {
    ToolCategory.EXPLOIT,
    ToolCategory.PASSWORD,
}

# Tool name patterns that require safety confirmations
DANGEROUS_TOOL_PATTERNS = [
    "exploit",
    "hydra",
    "medusa",
    "crackmapexec",
    "msfvenom",
    "mimikatz",
    "secretsdump",
    "psexec",
    "wmiexec",
    "evil_winrm",
]


@dataclass
class TargetContext:
    """Context information about a target."""
    id: str
    value: str
    type: str
    session_count: int = 0
    recent_findings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SessionContext:
    """Context information about a session."""
    id: str
    target_id: str
    status: str
    started_at: datetime
    finding_count: int = 0
    findings_summary: Dict[str, int] = field(default_factory=dict)


class ContextBuilder:
    """
    Builds context for LLM interactions.
    
    Responsible for:
    - Building system prompts with FRAGMENTUM capabilities
    - Generating function calling schemas from tool registry
    - Including dynamic context from targets and sessions
    
    Requirements:
    - 3.1: Load complete tool registry with descriptions and parameters
    - 3.2: Include target information in context
    - 3.3: Reference findings when suggesting next steps
    """
    
    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
    ):
        """
        Initialize the context builder.
        
        Args:
            tool_registry: Tool registry instance (creates default if None)
        """
        self._tool_registry = tool_registry or ToolRegistry()
        self._active_targets: List[TargetContext] = []
        self._recent_sessions: List[SessionContext] = []
    
    @property
    def tool_registry(self) -> ToolRegistry:
        """Get the tool registry."""
        return self._tool_registry
    
    def build_system_prompt(self) -> str:
        """
        Build the system prompt with FRAGMENTUM capabilities.
        
        Returns:
            Complete system prompt for the LLM
            
        Requirements: 3.1, 3.2
        """
        prompt_parts = [
            self._build_base_prompt(),
            self._build_tools_description(),
            self._build_targets_context(),
            self._build_findings_context(),
            self._build_safety_guidelines(),
        ]
        
        return "\n\n".join(filter(None, prompt_parts))
    
    def _build_base_prompt(self) -> str:
        """Build the base system prompt."""
        return """You are FRAGMENTUM AI, an intelligent assistant for penetration testing and security assessments.

Your role is to help security professionals execute reconnaissance, scanning, enumeration, and exploitation tasks using natural language commands.

You can understand commands in both Portuguese and English.

Key capabilities:
- Execute security tools based on natural language requests
- Analyze scan results and suggest next steps
- Plan and execute multi-step security assessments
- Explain tool selections and findings

CRITICAL RULES FOR TOOL USAGE:
1. ONLY call tools when the user EXPLICITLY requests a scan, attack, or test
2. When user says "sim", "yes", "ok", "proceed" - this is confirmation to run the tool you mentioned
3. For simple confirmations like "sim" or "yes", call the appropriate tool with the target discussed
4. NEVER call execute_command with user's text as the command
5. For general questions, respond with TEXT ONLY - no tool calls

Example interactions:
- User: "scan 172.20.0.6" -> Call nmap tool with target=172.20.0.6
- User: "sim" (after you asked about scanning) -> Call the scan tool you mentioned
- User: "what tools do you have?" -> Respond with text, NO tool call
- User: "hello" -> Respond with text, NO tool call

When you need to run a scan:
1. Call the appropriate tool (nmap, gobuster, nikto, etc.)
2. Use the target IP/domain discussed in conversation
3. The system will show a confirmation dialog to the user

Response format:
- Use Markdown for formatting
- Use **bold** for important terms
- Use `code` for IPs, ports, commands
- Use bullet points for lists

Be concise but informative. Focus on actionable insights."""
    
    def _build_tools_description(self) -> str:
        """Build description of available tools by category."""
        tools = self._tool_registry.list_all()
        
        if not tools:
            return ""
        
        # Group tools by category
        by_category: Dict[str, List[Tool]] = {}
        for tool in tools:
            cat_name = tool.category.value
            if cat_name not in by_category:
                by_category[cat_name] = []
            by_category[cat_name].append(tool)
        
        lines = ["## Available Tools"]
        
        for category, cat_tools in sorted(by_category.items()):
            lines.append(f"\n### {category.title()}")
            for tool in cat_tools[:10]:  # Limit to avoid context overflow
                lines.append(f"- **{tool.name}**: {tool.description}")
        
        lines.append(f"\nTotal: {len(tools)} tools available across {len(by_category)} categories.")
        
        return "\n".join(lines)
    
    def _build_targets_context(self) -> str:
        """Build context about active targets."""
        if not self._active_targets:
            return ""
        
        lines = ["## Active Targets"]
        
        for target in self._active_targets:
            lines.append(f"- **{target.value}** ({target.type})")
            if target.session_count > 0:
                lines.append(f"  - {target.session_count} previous sessions")
            if target.recent_findings:
                findings_str = ", ".join(
                    f"{f.get('severity', 'info')}: {f.get('type', 'unknown')}"
                    for f in target.recent_findings[:3]
                )
                lines.append(f"  - Recent findings: {findings_str}")
        
        return "\n".join(lines)
    
    def _build_findings_context(self) -> str:
        """Build context about recent findings."""
        if not self._recent_sessions:
            return ""
        
        # Aggregate findings across sessions
        total_findings = 0
        severity_counts: Dict[str, int] = {}
        
        for session in self._recent_sessions:
            total_findings += session.finding_count
            for severity, count in session.findings_summary.items():
                severity_counts[severity] = severity_counts.get(severity, 0) + count
        
        if total_findings == 0:
            return ""
        
        lines = ["## Recent Findings Summary"]
        lines.append(f"Total findings from recent sessions: {total_findings}")
        
        if severity_counts:
            severity_str = ", ".join(
                f"{sev}: {count}"
                for sev, count in sorted(severity_counts.items())
            )
            lines.append(f"By severity: {severity_str}")
        
        lines.append("\nConsider these findings when suggesting next steps.")
        
        return "\n".join(lines)
    
    def _build_safety_guidelines(self) -> str:
        """Build safety guidelines for dangerous operations."""
        return """## Safety Guidelines

Before executing potentially dangerous operations, you MUST:
1. **Exploitation tools**: Request explicit user confirmation
2. **Password attacks**: Warn about potential account lockouts
3. **Aggressive scanning**: Inform about detection risks

Always verify the target is within authorized scope before proceeding."""

    # Priority categories for tool selection (most important first)
    PRIORITY_CATEGORIES = [
        ToolCategory.SCANNING,
        ToolCategory.ENUMERATION,
        ToolCategory.WEB,
        ToolCategory.EXPLOIT,
        ToolCategory.PASSWORD,
        ToolCategory.NETWORK,
        ToolCategory.CLOUD,
        ToolCategory.BINARY,
        ToolCategory.OSINT,
    ]
    
    # Core tools that should always be included (simplified - one version per tool)
    CORE_TOOLS = {
        # Scanning
        "nmap", "masscan",
        # Web
        "gobuster", "nikto", "wpscan", "sqlmap", "whatweb", "nuclei",
        # Enumeration
        "enum4linux", "smbmap", "showmount", "nbtscan", "dnsrecon",
        # Password
        "hydra", "crackmapexec", "john",
        # Exploitation
        "searchsploit", "msfvenom", "linpeas",
        # Network
        "impacket_psexec", "impacket_secretsdump", "evil_winrm",
        # OSINT
        "subfinder", "theharvester", "whois",
        # Cloud
        "trivy", "kube_hunter",
        # Misc
        "execute_command",
    }
    
    def build_tools_schema(self, max_tools: int = 50) -> List[ToolSchema]:
        """
        Build function calling schema from tool registry.
        
        Args:
            max_tools: Maximum number of tools to include (default 50 for Groq compatibility)
        
        Returns:
            List of ToolSchema objects for LLM function calling
            
        Requirements: 3.1
        """
        tools = self._tool_registry.list_all()
        schemas = []
        
        # First, add all core tools
        core_tools = []
        other_tools = []
        
        for tool in tools:
            if tool.name in self.CORE_TOOLS:
                core_tools.append(tool)
            else:
                other_tools.append(tool)
        
        # Sort other tools by category priority
        def get_category_priority(tool: Tool) -> int:
            try:
                return self.PRIORITY_CATEGORIES.index(tool.category)
            except (ValueError, AttributeError):
                return len(self.PRIORITY_CATEGORIES)
        
        other_tools.sort(key=get_category_priority)
        
        # Add core tools first
        for tool in core_tools:
            schema = self._tool_to_schema(tool)
            schemas.append(schema)
        
        # Add other tools up to the limit
        remaining_slots = max_tools - len(schemas)
        for tool in other_tools[:remaining_slots]:
            schema = self._tool_to_schema(tool)
            schemas.append(schema)
        
        return schemas
    
    def _tool_to_schema(self, tool: Tool) -> ToolSchema:
        """
        Convert a Tool to a ToolSchema for function calling.
        
        Args:
            tool: Tool instance from registry
            
        Returns:
            ToolSchema for LLM function calling
        """
        # Build parameter schema
        parameters: Dict[str, Any] = {
            "type": "object",
            "properties": {},
        }
        required: List[str] = []
        
        # Add target parameter (most tools need it)
        if "{target}" in tool.command or "{TARGET}" in tool.command:
            parameters["properties"]["target"] = {
                "type": "string",
                "description": "Target IP, hostname, or URL"
            }
            required.append("target")
        
        # Add parameters from default_options
        for opt_name, opt_default in tool.default_options.items():
            param_type = "string"
            if isinstance(opt_default, bool):
                param_type = "boolean"
            elif isinstance(opt_default, int):
                param_type = "integer"
            elif isinstance(opt_default, float):
                param_type = "number"
            
            parameters["properties"][opt_name] = {
                "type": param_type,
                "description": f"Option: {opt_name}",
                "default": opt_default
            }
        
        return ToolSchema(
            name=tool.name,
            description=f"{tool.description} (Category: {tool.category.value})",
            parameters=parameters,
            required=required
        )
    
    def set_active_targets(self, targets: List[TargetContext]) -> None:
        """
        Set the active targets for context.
        
        Args:
            targets: List of target contexts
            
        Requirements: 3.2
        """
        self._active_targets = targets
    
    def set_recent_sessions(self, sessions: List[SessionContext]) -> None:
        """
        Set recent sessions for context.
        
        Args:
            sessions: List of session contexts
            
        Requirements: 3.3
        """
        self._recent_sessions = sessions
    
    def update_from_api_data(
        self,
        targets: Optional[List[Dict[str, Any]]] = None,
        sessions: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """
        Update context from API response data.
        
        Args:
            targets: List of target dicts from API
            sessions: List of session dicts from API
            
        Requirements: 3.2, 3.3
        """
        if targets:
            self._active_targets = [
                TargetContext(
                    id=t.get("id", ""),
                    value=t.get("value", ""),
                    type=t.get("type", "unknown"),
                    session_count=t.get("session_count", 0),
                    recent_findings=t.get("recent_findings", [])
                )
                for t in targets
            ]
        
        if sessions:
            self._recent_sessions = [
                SessionContext(
                    id=s.get("id", ""),
                    target_id=s.get("target_id", ""),
                    status=s.get("status", "unknown"),
                    started_at=s.get("started_at", datetime.utcnow()),
                    finding_count=s.get("finding_count", 0),
                    findings_summary=s.get("findings_summary", {})
                )
                for s in sessions
            ]
    
    def is_dangerous_tool(self, tool_name: str) -> bool:
        """
        Check if a tool requires safety confirmation.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            True if tool requires confirmation
            
        Requirements: 8.1, 8.2, 8.3
        """
        # Check by name pattern
        tool_lower = tool_name.lower()
        for pattern in DANGEROUS_TOOL_PATTERNS:
            if pattern in tool_lower:
                return True
        
        # Check by category
        tool = self._tool_registry.get(tool_name)
        if tool and tool.category in DANGEROUS_CATEGORIES:
            return True
        
        return False
    
    def get_tool_explanation(self, tool_name: str, target: str = "", context: str = "") -> str:
        """
        Get an explanation for why a tool was selected.
        
        Args:
            tool_name: Name of the tool
            target: Optional target being scanned
            context: Optional context about why the tool was selected
            
        Returns:
            Explanation string with reasoning
            
        Requirements: 3.4
        """
        tool = self._tool_registry.get(tool_name)
        if not tool:
            return f"Tool '{tool_name}' not found in registry."
        
        explanation_parts = [
            f"**{tool.name}** - {tool.description}",
            f"Category: {tool.category.value}",
        ]
        
        # Add reasoning for tool selection based on category and tool type
        reasoning = self._generate_tool_reasoning(tool, target, context)
        if reasoning:
            explanation_parts.append(f"\n**Why this tool:** {reasoning}")
        
        if tool.timeout > 180:
            explanation_parts.append(f"Note: This tool may take up to {tool.timeout}s to complete.")
        
        if tool.requires_root:
            explanation_parts.append("Note: This tool requires root privileges.")
        
        if self.is_dangerous_tool(tool_name):
            explanation_parts.append("⚠️ This is a potentially dangerous operation that requires confirmation.")
        
        return "\n".join(explanation_parts)
    
    def _generate_tool_reasoning(self, tool: Tool, target: str = "", context: str = "") -> str:
        """
        Generate reasoning for why a specific tool was selected.
        
        Args:
            tool: Tool instance
            target: Target being scanned
            context: Additional context
            
        Returns:
            Reasoning string explaining the tool selection
            
        Requirements: 3.4
        """
        tool_name = tool.name.lower()
        category = tool.category.value.lower()
        
        # Tool-specific reasoning based on common use cases
        reasoning_map = {
            # Port scanning tools
            "nmap": "Nmap is the industry-standard port scanner, providing comprehensive service detection and version enumeration. It's the best starting point for network reconnaissance.",
            "masscan": "Masscan is optimized for high-speed port scanning across large IP ranges. Ideal when you need to quickly identify open ports before deeper analysis.",
            "rustscan": "RustScan provides extremely fast port discovery, then hands off to nmap for detailed service detection. Best for quick initial reconnaissance.",
            
            # Web scanning tools
            "nikto": "Nikto performs comprehensive web server vulnerability scanning, checking for dangerous files, outdated software, and common misconfigurations.",
            "gobuster": "Gobuster excels at directory and file brute-forcing, helping discover hidden content and admin panels on web servers.",
            "dirb": "DIRB is a reliable directory scanner that systematically tests for common web paths and hidden resources.",
            "ffuf": "FFUF is a fast web fuzzer that can discover hidden directories, files, and parameters through brute-force testing.",
            "feroxbuster": "Feroxbuster is a modern, recursive content discovery tool that efficiently maps web application structure.",
            "wpscan": "WPScan is specifically designed for WordPress security assessment, detecting vulnerable plugins, themes, and user enumeration.",
            "whatweb": "WhatWeb identifies web technologies, CMS platforms, and server configurations to help plan targeted attacks.",
            
            # Enumeration tools
            "enum4linux": "Enum4linux extracts valuable information from Windows/Samba systems including users, shares, and policies via SMB.",
            "smbmap": "SMBMap provides detailed SMB share enumeration with permission checking, helping identify accessible resources.",
            "smbclient": "SMBClient allows interactive access to SMB shares for file browsing and data extraction.",
            "ldapsearch": "LDAP search queries Active Directory for user accounts, groups, and organizational structure.",
            "snmpwalk": "SNMP walk extracts system information, network configuration, and potentially sensitive data via SNMP.",
            
            # DNS tools
            "dnsrecon": "DNSRecon performs comprehensive DNS enumeration including zone transfers, subdomain discovery, and record analysis.",
            "dnsenum": "DNSenum gathers DNS information through multiple techniques including brute-force subdomain enumeration.",
            "subfinder": "Subfinder discovers subdomains using passive sources, minimizing detection while maximizing coverage.",
            "amass": "Amass performs in-depth subdomain enumeration using both passive and active techniques.",
            
            # Vulnerability scanning
            "nuclei": "Nuclei uses community-maintained templates to detect known vulnerabilities, misconfigurations, and security issues.",
            "nmap_vuln": "Nmap's vulnerability scripts check for common CVEs and security issues on discovered services.",
            
            # Password attacks
            "hydra": "Hydra is a versatile online password cracker supporting numerous protocols for credential testing.",
            "medusa": "Medusa provides parallel password testing across multiple services simultaneously.",
            "john": "John the Ripper cracks password hashes using various attack modes including dictionary and brute-force.",
            "hashcat": "Hashcat leverages GPU acceleration for high-speed hash cracking with extensive algorithm support.",
            
            # Exploitation tools
            "searchsploit": "SearchSploit queries the Exploit-DB database to find known exploits for identified services and versions.",
            "msfvenom": "MSFVenom generates custom payloads for exploitation, supporting various platforms and encoding options.",
            
            # OSINT tools
            "theharvester": "TheHarvester gathers emails, subdomains, and other intelligence from public sources.",
            "whois": "WHOIS lookup reveals domain registration details, ownership, and contact information.",
            "sherlock": "Sherlock searches for usernames across social media platforms for OSINT gathering.",
        }
        
        # Check for exact match first
        for key, reasoning in reasoning_map.items():
            if key in tool_name:
                return reasoning
        
        # Category-based fallback reasoning
        category_reasoning = {
            "recon": "This reconnaissance tool helps gather initial information about the target to plan further assessment.",
            "scan": "This scanning tool identifies potential entry points and services running on the target.",
            "enum": "This enumeration tool extracts detailed information from discovered services.",
            "vuln": "This vulnerability scanner checks for known security issues that could be exploited.",
            "exploit": "This exploitation tool attempts to leverage discovered vulnerabilities for access.",
            "password": "This password tool tests credential strength and attempts to recover valid credentials.",
            "web": "This web tool analyzes web applications for security issues and hidden content.",
            "network": "This network tool examines network services and configurations.",
            "osint": "This OSINT tool gathers publicly available information about the target.",
        }
        
        for cat_key, reasoning in category_reasoning.items():
            if cat_key in category:
                return reasoning
        
        # Generic fallback
        return f"This {category} tool is appropriate for the current phase of the assessment."
    
    def generate_tool_selection_explanation(
        self,
        tool_name: str,
        target: str,
        user_request: str,
        alternatives: list[str] | None = None
    ) -> str:
        """
        Generate a comprehensive explanation for tool selection.
        
        This method creates a detailed explanation that includes:
        - What the tool does
        - Why it was selected for this specific request
        - What to expect from the results
        - Alternative tools that could be used
        
        Args:
            tool_name: Name of the selected tool
            target: Target being assessed
            user_request: Original user request
            alternatives: Optional list of alternative tools considered
            
        Returns:
            Comprehensive explanation string
            
        Requirements: 3.4
        """
        tool = self._tool_registry.get(tool_name)
        if not tool:
            return f"Tool '{tool_name}' not found in registry."
        
        parts = []
        
        # Tool header
        parts.append(f"🔧 **Executing: {tool.name}**")
        parts.append(f"*{tool.description}*")
        parts.append("")
        
        # Reasoning section
        reasoning = self._generate_tool_reasoning(tool, target, user_request)
        parts.append(f"**Selection Reasoning:** {reasoning}")
        parts.append("")
        
        # Target info
        if target:
            parts.append(f"**Target:** `{target}`")
        
        # Expected output
        expected = self._get_expected_output_description(tool)
        if expected:
            parts.append(f"**Expected Output:** {expected}")
        
        # Alternatives considered
        if alternatives and len(alternatives) > 0:
            alt_str = ", ".join(f"`{a}`" for a in alternatives[:3])
            parts.append(f"**Alternatives Considered:** {alt_str}")
        
        # Warnings
        if self.is_dangerous_tool(tool_name):
            parts.append("")
            parts.append("⚠️ **Warning:** This operation may be detected by security systems or cause service disruption.")
        
        return "\n".join(parts)
    
    def _get_expected_output_description(self, tool: Tool) -> str:
        """
        Get a description of expected output for a tool.
        
        Args:
            tool: Tool instance
            
        Returns:
            Description of expected output
        """
        tool_name = tool.name.lower()
        
        output_descriptions = {
            "nmap": "Open ports, service versions, and OS detection results",
            "masscan": "List of open ports discovered at high speed",
            "nikto": "Web server vulnerabilities, misconfigurations, and outdated software",
            "gobuster": "Discovered directories, files, and hidden paths",
            "dirb": "Found directories and files with HTTP status codes",
            "ffuf": "Fuzzing results showing discovered content",
            "wpscan": "WordPress vulnerabilities, plugins, themes, and users",
            "enum4linux": "SMB shares, users, groups, and policies",
            "smbmap": "Share permissions and accessible resources",
            "hydra": "Valid credentials if found",
            "nuclei": "Detected vulnerabilities with severity ratings",
            "searchsploit": "Matching exploits from Exploit-DB",
            "subfinder": "Discovered subdomains",
            "theharvester": "Emails, subdomains, and hosts found",
            "whois": "Domain registration and ownership details",
        }
        
        for key, desc in output_descriptions.items():
            if key in tool_name:
                return desc
        
        return "Tool-specific output based on target analysis"
    
    def get_relevant_context(self, query: str) -> str:
        """
        Get context relevant to a specific query.
        
        Args:
            query: User's query or request
            
        Returns:
            Relevant context string
            
        Requirements: 3.2, 3.3
        """
        context_parts = []
        
        # Add target context if query mentions targets
        if self._active_targets:
            target_values = [t.value for t in self._active_targets]
            for target in self._active_targets:
                if target.value in query:
                    context_parts.append(
                        f"Target {target.value} has {target.session_count} previous sessions."
                    )
                    if target.recent_findings:
                        context_parts.append(
                            f"Recent findings: {len(target.recent_findings)} items"
                        )
        
        # Add findings context if relevant
        if self._recent_sessions and any(
            word in query.lower()
            for word in ["finding", "vulnerability", "result", "discovered", "found"]
        ):
            total = sum(s.finding_count for s in self._recent_sessions)
            if total > 0:
                context_parts.append(
                    f"There are {total} findings from recent sessions to consider."
                )
        
        return "\n".join(context_parts) if context_parts else ""


# Singleton instance
_context_builder: Optional[ContextBuilder] = None


def get_context_builder() -> ContextBuilder:
    """
    Get the global context builder instance.
    
    Returns:
        ContextBuilder singleton
    """
    global _context_builder
    if _context_builder is None:
        _context_builder = ContextBuilder()
    return _context_builder


def reset_context_builder() -> None:
    """Reset the global context builder (for testing)."""
    global _context_builder
    _context_builder = None


async def load_dynamic_context(context_builder: Optional[ContextBuilder] = None) -> ContextBuilder:
    """
    Load dynamic context from API data stores.
    
    Fetches active targets and recent sessions to provide
    relevant context for AI interactions.
    
    Args:
        context_builder: Optional context builder instance (uses global if None)
        
    Returns:
        ContextBuilder with updated context
        
    Requirements: 3.2, 3.3
    """
    from fragmentum.web.backend.api.targets import get_target_storage, get_target_session_mapping
    from fragmentum.web.backend.api.sessions import get_session_storage
    
    ctx = context_builder or get_context_builder()
    
    # Load active targets
    targets_storage = get_target_storage()
    target_sessions = get_target_session_mapping()
    sessions_storage = get_session_storage()
    
    target_contexts = []
    for target_id, target in targets_storage.items():
        session_ids = target_sessions.get(target_id, [])
        
        # Get recent findings for this target
        recent_findings = []
        for session_id in session_ids[-5:]:  # Last 5 sessions
            session = sessions_storage.get(session_id)
            if session and session.findings:
                for finding in session.findings[-3:]:  # Last 3 findings per session
                    recent_findings.append({
                        "type": finding.type.value if hasattr(finding.type, 'value') else str(finding.type),
                        "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                        "value": finding.value,
                    })
        
        target_contexts.append(TargetContext(
            id=target_id,
            value=target.value,
            type=target.type.value if hasattr(target.type, 'value') else str(target.type),
            session_count=len(session_ids),
            recent_findings=recent_findings[:10]  # Limit to 10 findings
        ))
    
    ctx.set_active_targets(target_contexts)
    
    # Load recent sessions
    session_contexts = []
    sessions_list = list(sessions_storage.values())
    # Sort by started_at descending and take last 10
    sessions_list.sort(key=lambda s: s.started_at, reverse=True)
    
    for session in sessions_list[:10]:
        # Build findings summary by severity
        findings_summary: Dict[str, int] = {}
        for finding in session.findings:
            severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            findings_summary[severity] = findings_summary.get(severity, 0) + 1
        
        session_contexts.append(SessionContext(
            id=session.id,
            target_id=session.target_id,
            status=session.status.value if hasattr(session.status, 'value') else str(session.status),
            started_at=session.started_at,
            finding_count=len(session.findings),
            findings_summary=findings_summary
        ))
    
    ctx.set_recent_sessions(session_contexts)
    
    return ctx


def build_chat_context(
    context_builder: Optional[ContextBuilder] = None,
    include_tools: bool = True,
    include_targets: bool = True,
    include_findings: bool = True,
) -> Dict[str, Any]:
    """
    Build a complete context dictionary for chat interactions.
    
    Args:
        context_builder: Optional context builder instance
        include_tools: Whether to include tool schemas
        include_targets: Whether to include target context
        include_findings: Whether to include findings context
        
    Returns:
        Dictionary with system_prompt, tools, and metadata
        
    Requirements: 3.1, 3.2, 3.3
    """
    ctx = context_builder or get_context_builder()
    
    result: Dict[str, Any] = {
        "system_prompt": ctx.build_system_prompt(),
        "metadata": {
            "active_targets": len(ctx._active_targets),
            "recent_sessions": len(ctx._recent_sessions),
        }
    }
    
    if include_tools:
        result["tools"] = ctx.build_tools_schema()
        result["metadata"]["tool_count"] = len(result["tools"])
    
    if include_targets and ctx._active_targets:
        result["targets"] = [
            {
                "id": t.id,
                "value": t.value,
                "type": t.type,
                "session_count": t.session_count,
            }
            for t in ctx._active_targets
        ]
    
    if include_findings and ctx._recent_sessions:
        total_findings = sum(s.finding_count for s in ctx._recent_sessions)
        result["findings_summary"] = {
            "total": total_findings,
            "sessions": len(ctx._recent_sessions),
        }
    
    return result


class DynamicContextInjector:
    """
    Handles dynamic context injection for chat sessions.
    
    Provides methods to inject relevant context based on
    the current conversation and user requests.
    
    Requirements: 3.2, 3.3
    """
    
    def __init__(self, context_builder: Optional[ContextBuilder] = None):
        """
        Initialize the context injector.
        
        Args:
            context_builder: Optional context builder instance
        """
        self._context_builder = context_builder or get_context_builder()
        self._conversation_targets: List[str] = []
        self._mentioned_tools: List[str] = []
    
    def extract_targets_from_message(self, message: str) -> List[str]:
        """
        Extract potential targets from a user message.
        
        Args:
            message: User message text
            
        Returns:
            List of potential target strings (IPs, domains)
        """
        import re
        
        targets = []
        
        # IPv4 pattern
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        targets.extend(re.findall(ipv4_pattern, message))
        
        # CIDR pattern
        cidr_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b'
        targets.extend(re.findall(cidr_pattern, message))
        
        # Domain pattern (simplified)
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, message)
        # Filter out common non-target domains
        excluded = {'example.com', 'test.com', 'localhost.localdomain'}
        targets.extend([d for d in domains if d.lower() not in excluded])
        
        return list(set(targets))
    
    def extract_tools_from_message(self, message: str) -> List[str]:
        """
        Extract mentioned tools from a user message.
        
        Args:
            message: User message text
            
        Returns:
            List of tool names mentioned
        """
        message_lower = message.lower()
        mentioned = []
        
        # Check against all tools in registry
        for tool in self._context_builder.tool_registry.list_all():
            if tool.name.lower() in message_lower:
                mentioned.append(tool.name)
        
        # Also check common tool aliases
        aliases = {
            "port scan": ["nmap", "masscan", "rustscan"],
            "directory scan": ["gobuster", "dirb", "ffuf", "feroxbuster"],
            "vulnerability scan": ["nikto", "nuclei", "nmap_vuln"],
            "brute force": ["hydra_ssh", "hydra_ftp", "medusa"],
            "smb": ["enum4linux", "smbmap", "smbclient"],
            "web scan": ["nikto", "whatweb", "wpscan"],
            "subdomain": ["subfinder", "amass", "theharvester"],
        }
        
        for alias, tools in aliases.items():
            if alias in message_lower:
                mentioned.extend(tools)
        
        return list(set(mentioned))
    
    def get_context_for_message(self, message: str) -> str:
        """
        Get relevant context for a specific message.
        
        Args:
            message: User message text
            
        Returns:
            Context string to inject into the conversation
            
        Requirements: 3.2, 3.3
        """
        context_parts = []
        
        # Extract and track targets
        targets = self.extract_targets_from_message(message)
        if targets:
            self._conversation_targets.extend(targets)
            self._conversation_targets = list(set(self._conversation_targets))
        
        # Get context for known targets
        for target_value in targets:
            for target_ctx in self._context_builder._active_targets:
                if target_ctx.value == target_value:
                    context_parts.append(
                        f"Target {target_value}: {target_ctx.session_count} previous sessions"
                    )
                    if target_ctx.recent_findings:
                        severities = [f.get('severity', 'info') for f in target_ctx.recent_findings]
                        context_parts.append(
                            f"  Previous findings: {len(target_ctx.recent_findings)} "
                            f"({', '.join(set(severities))})"
                        )
        
        # Extract and provide tool context
        tools = self.extract_tools_from_message(message)
        if tools:
            self._mentioned_tools.extend(tools)
            self._mentioned_tools = list(set(self._mentioned_tools))
            
            for tool_name in tools[:3]:  # Limit to 3 tools
                explanation = self._context_builder.get_tool_explanation(tool_name)
                if explanation:
                    context_parts.append(f"\n{explanation}")
        
        # Add general context from recent findings
        base_context = self._context_builder.get_relevant_context(message)
        if base_context:
            context_parts.append(base_context)
        
        return "\n".join(context_parts) if context_parts else ""
    
    def get_suggested_tools(self, message: str) -> List[str]:
        """
        Get suggested tools based on the message content.
        
        Args:
            message: User message text
            
        Returns:
            List of suggested tool names
        """
        message_lower = message.lower()
        suggestions = []
        
        # Keyword to tool mapping
        keyword_tools = {
            # Scanning keywords
            "scan": ["nmap", "masscan"],
            "port": ["nmap", "masscan", "rustscan"],
            "escaneie": ["nmap"],  # Portuguese
            "escanear": ["nmap"],  # Portuguese
            
            # Web keywords
            "web": ["nikto", "gobuster", "whatweb"],
            "directory": ["gobuster", "dirb", "ffuf"],
            "diretório": ["gobuster", "dirb"],  # Portuguese
            "wordpress": ["wpscan"],
            "sql": ["sqlmap"],
            "xss": ["xsstrike"],
            
            # Enumeration keywords
            "enumerate": ["enum4linux", "smbmap"],
            "enumerar": ["enum4linux", "smbmap"],  # Portuguese
            "smb": ["enum4linux", "smbmap", "smbclient"],
            "ldap": ["ldapsearch"],
            "snmp": ["snmpwalk"],
            "dns": ["dnsrecon", "dnsenum"],
            
            # Password keywords
            "password": ["hydra_ssh", "john"],
            "senha": ["hydra_ssh", "john"],  # Portuguese
            "brute": ["hydra_ssh", "medusa"],
            "crack": ["john", "hashcat"],
            
            # Exploit keywords
            "exploit": ["searchsploit", "nuclei"],
            "vulnerability": ["nmap_vuln", "nikto", "nuclei"],
            "vulnerabilidade": ["nmap_vuln", "nikto"],  # Portuguese
            
            # OSINT keywords
            "subdomain": ["subfinder", "amass"],
            "subdomínio": ["subfinder", "amass"],  # Portuguese
            "email": ["theharvester"],
            "whois": ["whois"],
            
            # Full assessment
            "pentest": ["nmap", "nikto", "gobuster", "enum4linux"],
            "assessment": ["nmap", "nikto", "gobuster"],
            "completo": ["nmap", "nikto", "gobuster", "enum4linux"],  # Portuguese
        }
        
        for keyword, tools in keyword_tools.items():
            if keyword in message_lower:
                suggestions.extend(tools)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_suggestions = []
        for tool in suggestions:
            if tool not in seen:
                seen.add(tool)
                unique_suggestions.append(tool)
        
        return unique_suggestions[:5]  # Limit to 5 suggestions
    
    def reset_conversation_context(self) -> None:
        """Reset the conversation-specific context."""
        self._conversation_targets = []
        self._mentioned_tools = []

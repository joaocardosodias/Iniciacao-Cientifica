"""
Attack Planner for Multi-Step Security Assessments.

Provides functionality to detect full assessment requests, generate
multi-tool execution plans, and execute them step-by-step with
adaptive behavior based on findings.

Requirements:
- 7.1: Plan and execute multiple tools in sequence for full assessments
- 7.2: Explain each step before executing
- 7.3: Adapt subsequent steps based on discoveries
- 7.4: Confirm with user before exploitation
- 7.5: Pause on errors and ask how to proceed
"""

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional, Set, Tuple

from fragmentum.tools.registry import get_tool_registry, ToolCategory, Tool


class AttackPhase(str, Enum):
    """Phases of a penetration test."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


class PlanStatus(str, Enum):
    """Status of an attack plan."""
    CREATED = "created"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


class StepStatus(str, Enum):
    """Status of a plan step."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    ERROR = "error"
    AWAITING_CONFIRMATION = "awaiting_confirmation"


@dataclass
class PlanStep:
    """A single step in an attack plan."""
    id: str
    phase: AttackPhase
    tool_name: str
    parameters: Dict[str, Any]
    description: str
    rationale: str
    status: StepStatus = StepStatus.PENDING
    requires_confirmation: bool = False
    depends_on: List[str] = field(default_factory=list)
    output: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class AttackPlan:
    """A multi-step attack plan."""
    id: str
    target: str
    description: str
    status: PlanStatus = PlanStatus.CREATED
    steps: List[PlanStep] = field(default_factory=list)
    current_step_index: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    all_findings: List[Dict[str, Any]] = field(default_factory=list)
    discovered_services: Dict[int, str] = field(default_factory=dict)
    discovered_vulnerabilities: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

    @property
    def current_step(self) -> Optional[PlanStep]:
        """Get the current step."""
        if 0 <= self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    @property
    def completed_steps(self) -> List[PlanStep]:
        """Get completed steps."""
        return [s for s in self.steps if s.status == StepStatus.COMPLETED]

    @property
    def pending_steps(self) -> List[PlanStep]:
        """Get pending steps."""
        return [s for s in self.steps if s.status == StepStatus.PENDING]

    @property
    def progress_percentage(self) -> float:
        """Get progress as percentage."""
        if not self.steps:
            return 0.0
        completed = len([s for s in self.steps if s.status in (StepStatus.COMPLETED, StepStatus.SKIPPED)])
        return (completed / len(self.steps)) * 100


# Keywords that indicate a full assessment request
FULL_ASSESSMENT_KEYWORDS = {
    # English
    "full assessment", "full pentest", "full scan", "complete assessment",
    "complete pentest", "complete scan", "comprehensive scan", "full test",
    "penetration test", "security assessment", "security audit",
    "assess everything", "scan everything", "test everything",
    # Portuguese
    "pentest completo", "teste completo", "avaliação completa",
    "escaneamento completo", "análise completa", "auditoria completa",
    "teste de penetração", "avaliação de segurança", "auditoria de segurança",
    "testar tudo", "escanear tudo", "avaliar tudo",
}

# Keywords for specific phases
PHASE_KEYWORDS = {
    AttackPhase.RECONNAISSANCE: [
        "recon", "reconnaissance", "osint", "information gathering",
        "reconhecimento", "coleta de informações",
    ],
    AttackPhase.SCANNING: [
        "scan", "port scan", "network scan", "service scan",
        "escaneamento", "varredura", "scan de portas",
    ],
    AttackPhase.ENUMERATION: [
        "enumerate", "enumeration", "enum", "list services",
        "enumerar", "enumeração", "listar serviços",
    ],
    AttackPhase.VULNERABILITY_ANALYSIS: [
        "vulnerability", "vuln scan", "vulnerability assessment",
        "vulnerabilidade", "análise de vulnerabilidade",
    ],
    AttackPhase.EXPLOITATION: [
        "exploit", "exploitation", "pwn", "hack", "compromise",
        "explorar", "exploração", "comprometer",
    ],
}


class AttackPlanner:
    """
    Plans and manages multi-step security assessments.
    
    Responsible for:
    - Detecting full assessment requests
    - Generating multi-tool execution plans
    - Adapting plans based on findings
    - Managing plan execution state
    
    Requirements:
    - 7.1: Plan and execute multiple tools in sequence
    - 7.2: Explain each step before executing
    - 7.3: Adapt subsequent steps based on discoveries
    """
    
    def __init__(self):
        """Initialize the attack planner."""
        self._active_plans: Dict[str, AttackPlan] = {}
        self._tool_registry = get_tool_registry()
    
    def is_full_assessment_request(self, message: str) -> bool:
        """
        Detect if a message is requesting a full assessment.
        
        Args:
            message: User message text
            
        Returns:
            True if this is a full assessment request
            
        Requirements: 7.1
        """
        message_lower = message.lower()
        
        # Check for full assessment keywords
        for keyword in FULL_ASSESSMENT_KEYWORDS:
            if keyword in message_lower:
                return True
        
        # Check for combination patterns
        has_target = bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message))
        has_action = any(word in message_lower for word in [
            "pentest", "test", "scan", "assess", "audit",
            "testar", "escanear", "avaliar", "auditar"
        ])
        has_scope = any(word in message_lower for word in [
            "full", "complete", "comprehensive", "everything", "all",
            "completo", "tudo", "todo", "inteiro"
        ])
        
        return has_target and has_action and has_scope
    
    def extract_target(self, message: str) -> Optional[str]:
        """
        Extract target from a message.
        
        Args:
            message: User message text
            
        Returns:
            Target string if found, None otherwise
        """
        # IPv4 pattern
        ipv4_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        if ipv4_match:
            return ipv4_match.group()
        
        # CIDR pattern
        cidr_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', message)
        if cidr_match:
            return cidr_match.group()
        
        # Domain pattern
        domain_match = re.search(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            message
        )
        if domain_match:
            domain = domain_match.group()
            # Filter out common non-target domains
            excluded = {'example.com', 'test.com', 'localhost.localdomain'}
            if domain.lower() not in excluded:
                return domain
        
        return None
    
    def create_plan(
        self,
        target: str,
        include_exploitation: bool = False,
        custom_phases: Optional[List[AttackPhase]] = None,
    ) -> AttackPlan:
        """
        Create a multi-step attack plan for a target.
        
        Args:
            target: Target IP, domain, or CIDR
            include_exploitation: Whether to include exploitation phase
            custom_phases: Optional list of specific phases to include
            
        Returns:
            AttackPlan with steps
            
        Requirements: 7.1
        """
        plan_id = str(uuid.uuid4())
        
        # Determine phases to include
        if custom_phases:
            phases = custom_phases
        else:
            phases = [
                AttackPhase.RECONNAISSANCE,
                AttackPhase.SCANNING,
                AttackPhase.ENUMERATION,
                AttackPhase.VULNERABILITY_ANALYSIS,
            ]
            if include_exploitation:
                phases.append(AttackPhase.EXPLOITATION)
        
        # Generate steps for each phase
        steps = []
        for phase in phases:
            phase_steps = self._generate_phase_steps(target, phase)
            steps.extend(phase_steps)
        
        plan = AttackPlan(
            id=plan_id,
            target=target,
            description=f"Full security assessment of {target}",
            steps=steps,
        )
        
        self._active_plans[plan_id] = plan
        return plan
    
    def _generate_phase_steps(
        self,
        target: str,
        phase: AttackPhase,
    ) -> List[PlanStep]:
        """
        Generate steps for a specific phase.
        
        Args:
            target: Target for the assessment
            phase: Phase to generate steps for
            
        Returns:
            List of PlanStep objects
        """
        steps = []
        
        if phase == AttackPhase.RECONNAISSANCE:
            steps.extend(self._generate_recon_steps(target))
        elif phase == AttackPhase.SCANNING:
            steps.extend(self._generate_scanning_steps(target))
        elif phase == AttackPhase.ENUMERATION:
            steps.extend(self._generate_enumeration_steps(target))
        elif phase == AttackPhase.VULNERABILITY_ANALYSIS:
            steps.extend(self._generate_vuln_steps(target))
        elif phase == AttackPhase.EXPLOITATION:
            steps.extend(self._generate_exploitation_steps(target))
        
        return steps
    
    def _generate_recon_steps(self, target: str) -> List[PlanStep]:
        """Generate reconnaissance steps."""
        steps = []
        
        # Check if target is a domain (for OSINT)
        is_domain = not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}', target)
        
        if is_domain:
            steps.append(PlanStep(
                id=str(uuid.uuid4()),
                phase=AttackPhase.RECONNAISSANCE,
                tool_name="whois",
                parameters={"target": target},
                description=f"WHOIS lookup for {target}",
                rationale="Gather domain registration information and identify potential contacts",
            ))
            
            steps.append(PlanStep(
                id=str(uuid.uuid4()),
                phase=AttackPhase.RECONNAISSANCE,
                tool_name="subfinder",
                parameters={"target": target},
                description=f"Subdomain enumeration for {target}",
                rationale="Discover subdomains that may expose additional attack surface",
            ))
        
        return steps
    
    def _generate_scanning_steps(self, target: str) -> List[PlanStep]:
        """Generate scanning steps."""
        steps = []
        
        # Initial port scan
        steps.append(PlanStep(
            id=str(uuid.uuid4()),
            phase=AttackPhase.SCANNING,
            tool_name="nmap",
            parameters={"target": target, "options": "-sV -sC -T4"},
            description=f"Service version scan of {target}",
            rationale="Identify open ports and running services with version detection",
        ))
        
        return steps
    
    def _generate_enumeration_steps(self, target: str) -> List[PlanStep]:
        """Generate enumeration steps (will be adapted based on scan results)."""
        steps = []
        
        # These are placeholder steps that will be adapted based on findings
        # The actual enumeration tools depend on discovered services
        
        # SMB enumeration (common on Windows targets)
        steps.append(PlanStep(
            id=str(uuid.uuid4()),
            phase=AttackPhase.ENUMERATION,
            tool_name="enum4linux",
            parameters={"target": target},
            description=f"SMB/Samba enumeration of {target}",
            rationale="Enumerate SMB shares, users, and groups if SMB is available",
        ))
        
        return steps
    
    def _generate_vuln_steps(self, target: str) -> List[PlanStep]:
        """Generate vulnerability analysis steps."""
        steps = []
        
        # Nmap vulnerability scripts
        steps.append(PlanStep(
            id=str(uuid.uuid4()),
            phase=AttackPhase.VULNERABILITY_ANALYSIS,
            tool_name="nmap_vuln",
            parameters={"target": target},
            description=f"Vulnerability scan of {target}",
            rationale="Run NSE vulnerability scripts to identify known vulnerabilities",
        ))
        
        return steps
    
    def _generate_exploitation_steps(self, target: str) -> List[PlanStep]:
        """Generate exploitation steps (requires confirmation)."""
        steps = []
        
        # Search for exploits based on discovered services
        steps.append(PlanStep(
            id=str(uuid.uuid4()),
            phase=AttackPhase.EXPLOITATION,
            tool_name="searchsploit",
            parameters={"query": target},
            description=f"Search for exploits related to {target}",
            rationale="Find potential exploits for discovered services and versions",
            requires_confirmation=True,
        ))
        
        return steps
    
    def adapt_plan(
        self,
        plan_id: str,
        findings: List[Dict[str, Any]],
    ) -> List[PlanStep]:
        """
        Adapt plan based on findings from completed steps.
        
        Args:
            plan_id: ID of the plan to adapt
            findings: New findings to consider
            
        Returns:
            List of new steps added to the plan
            
        Requirements: 7.3
        """
        plan = self._active_plans.get(plan_id)
        if not plan:
            return []
        
        new_steps = []
        
        # Process findings and add relevant steps
        for finding in findings:
            finding_type = finding.get("type", "")
            value = finding.get("value", {})
            
            if finding_type == "port":
                port = value.get("port")
                service = value.get("service", "").lower()
                
                # Add service-specific enumeration
                new_step = self._get_service_enumeration_step(
                    plan.target, port, service
                )
                if new_step and not self._step_exists(plan, new_step.tool_name, new_step.parameters):
                    new_steps.append(new_step)
                    plan.discovered_services[port] = service
            
            elif finding_type == "vulnerability":
                vuln_id = value.get("osvdb_id") or value.get("cve_id", "")
                if vuln_id:
                    plan.discovered_vulnerabilities.append(vuln_id)
        
        # Add new steps to plan
        if new_steps:
            # Insert after current step
            insert_index = plan.current_step_index + 1
            for i, step in enumerate(new_steps):
                plan.steps.insert(insert_index + i, step)
        
        plan.all_findings.extend(findings)
        plan.updated_at = datetime.utcnow()
        
        return new_steps
    
    def _get_service_enumeration_step(
        self,
        target: str,
        port: int,
        service: str,
    ) -> Optional[PlanStep]:
        """Get enumeration step for a specific service."""
        
        # HTTP/HTTPS services
        if service in ("http", "https") or port in (80, 443, 8080, 8443):
            return PlanStep(
                id=str(uuid.uuid4()),
                phase=AttackPhase.ENUMERATION,
                tool_name="nikto",
                parameters={"target": f"{target}:{port}"},
                description=f"Web vulnerability scan on port {port}",
                rationale=f"HTTP service detected on port {port}, scanning for web vulnerabilities",
            )
        
        # SMB service
        if service in ("smb", "microsoft-ds", "netbios-ssn") or port in (139, 445):
            return PlanStep(
                id=str(uuid.uuid4()),
                phase=AttackPhase.ENUMERATION,
                tool_name="smbmap",
                parameters={"target": target},
                description=f"SMB share mapping",
                rationale=f"SMB service detected, mapping accessible shares",
            )
        
        # SSH service
        if service == "ssh" or port == 22:
            return PlanStep(
                id=str(uuid.uuid4()),
                phase=AttackPhase.ENUMERATION,
                tool_name="nmap",
                parameters={"target": target, "options": f"-p {port} --script ssh-auth-methods,ssh-hostkey"},
                description=f"SSH enumeration on port {port}",
                rationale=f"SSH service detected, enumerating authentication methods",
            )
        
        # FTP service
        if service == "ftp" or port == 21:
            return PlanStep(
                id=str(uuid.uuid4()),
                phase=AttackPhase.ENUMERATION,
                tool_name="nmap",
                parameters={"target": target, "options": f"-p {port} --script ftp-anon,ftp-bounce,ftp-syst"},
                description=f"FTP enumeration on port {port}",
                rationale=f"FTP service detected, checking for anonymous access and vulnerabilities",
            )
        
        # MySQL service
        if service == "mysql" or port == 3306:
            return PlanStep(
                id=str(uuid.uuid4()),
                phase=AttackPhase.ENUMERATION,
                tool_name="nmap",
                parameters={"target": target, "options": f"-p {port} --script mysql-info,mysql-enum"},
                description=f"MySQL enumeration on port {port}",
                rationale=f"MySQL service detected, gathering database information",
            )
        
        # SNMP service
        if service == "snmp" or port in (161, 162):
            return PlanStep(
                id=str(uuid.uuid4()),
                phase=AttackPhase.ENUMERATION,
                tool_name="snmpwalk",
                parameters={"target": target},
                description=f"SNMP enumeration",
                rationale=f"SNMP service detected, attempting to enumerate system information",
            )
        
        return None
    
    def _step_exists(
        self,
        plan: AttackPlan,
        tool_name: str,
        parameters: Dict[str, Any],
    ) -> bool:
        """Check if a similar step already exists in the plan."""
        for step in plan.steps:
            if step.tool_name == tool_name:
                # Check if parameters are similar
                if step.parameters.get("target") == parameters.get("target"):
                    return True
        return False
    
    def get_plan(self, plan_id: str) -> Optional[AttackPlan]:
        """Get a plan by ID."""
        return self._active_plans.get(plan_id)
    
    def get_step_explanation(self, step: PlanStep) -> str:
        """
        Get a detailed explanation for a step.
        
        Args:
            step: The step to explain
            
        Returns:
            Explanation string
            
        Requirements: 7.2
        """
        explanation_parts = [
            f"**Step: {step.description}**",
            f"",
            f"**Tool:** `{step.tool_name}`",
            f"**Phase:** {step.phase.value.replace('_', ' ').title()}",
            f"",
            f"**Why this step?**",
            f"{step.rationale}",
        ]
        
        if step.requires_confirmation:
            explanation_parts.extend([
                "",
                "⚠️ **This step requires your confirmation before proceeding.**",
            ])
        
        return "\n".join(explanation_parts)
    
    def get_plan_summary(self, plan: AttackPlan) -> str:
        """
        Get a summary of the plan.
        
        Args:
            plan: The plan to summarize
            
        Returns:
            Summary string
        """
        summary_parts = [
            f"📋 **Attack Plan for {plan.target}**",
            f"",
            f"**Status:** {plan.status.value.replace('_', ' ').title()}",
            f"**Progress:** {plan.progress_percentage:.0f}% ({len(plan.completed_steps)}/{len(plan.steps)} steps)",
            f"",
            f"**Phases:**",
        ]
        
        # Group steps by phase
        phases_seen: Set[AttackPhase] = set()
        for step in plan.steps:
            if step.phase not in phases_seen:
                phases_seen.add(step.phase)
                phase_steps = [s for s in plan.steps if s.phase == step.phase]
                completed = len([s for s in phase_steps if s.status == StepStatus.COMPLETED])
                summary_parts.append(
                    f"  - {step.phase.value.replace('_', ' ').title()}: {completed}/{len(phase_steps)} steps"
                )
        
        if plan.all_findings:
            summary_parts.extend([
                "",
                f"**Findings:** {len(plan.all_findings)} total",
            ])
        
        if plan.discovered_services:
            services_str = ", ".join(
                f"{port}/{svc}" for port, svc in plan.discovered_services.items()
            )
            summary_parts.append(f"**Discovered Services:** {services_str}")
        
        return "\n".join(summary_parts)
    
    def mark_step_complete(
        self,
        plan_id: str,
        step_id: str,
        output: List[str],
        findings: List[Dict[str, Any]],
    ) -> None:
        """Mark a step as complete."""
        plan = self._active_plans.get(plan_id)
        if not plan:
            return
        
        for step in plan.steps:
            if step.id == step_id:
                step.status = StepStatus.COMPLETED
                step.output = output
                step.findings = findings
                step.completed_at = datetime.utcnow()
                break
        
        plan.updated_at = datetime.utcnow()
    
    def mark_step_error(
        self,
        plan_id: str,
        step_id: str,
        error: str,
    ) -> None:
        """Mark a step as errored."""
        plan = self._active_plans.get(plan_id)
        if not plan:
            return
        
        for step in plan.steps:
            if step.id == step_id:
                step.status = StepStatus.ERROR
                step.error = error
                step.completed_at = datetime.utcnow()
                break
        
        plan.status = PlanStatus.ERROR
        plan.error_message = error
        plan.updated_at = datetime.utcnow()
    
    def advance_plan(self, plan_id: str) -> Optional[PlanStep]:
        """
        Advance to the next step in the plan.
        
        Args:
            plan_id: ID of the plan
            
        Returns:
            Next step if available, None if plan is complete
        """
        plan = self._active_plans.get(plan_id)
        if not plan:
            return None
        
        plan.current_step_index += 1
        
        if plan.current_step_index >= len(plan.steps):
            plan.status = PlanStatus.COMPLETED
            return None
        
        plan.status = PlanStatus.IN_PROGRESS
        return plan.current_step
    
    def pause_plan(self, plan_id: str, reason: str) -> None:
        """Pause a plan execution."""
        plan = self._active_plans.get(plan_id)
        if plan:
            plan.status = PlanStatus.PAUSED
            plan.error_message = reason
            plan.updated_at = datetime.utcnow()
    
    def resume_plan(self, plan_id: str) -> Optional[PlanStep]:
        """Resume a paused plan."""
        plan = self._active_plans.get(plan_id)
        if plan and plan.status == PlanStatus.PAUSED:
            plan.status = PlanStatus.IN_PROGRESS
            plan.error_message = None
            plan.updated_at = datetime.utcnow()
            return plan.current_step
        return None
    
    def cancel_plan(self, plan_id: str) -> None:
        """Cancel a plan."""
        plan = self._active_plans.get(plan_id)
        if plan:
            plan.status = PlanStatus.CANCELLED
            plan.updated_at = datetime.utcnow()
    
    def delete_plan(self, plan_id: str) -> None:
        """Delete a plan from active plans."""
        self._active_plans.pop(plan_id, None)


# Singleton instance
_attack_planner: Optional[AttackPlanner] = None


def get_attack_planner() -> AttackPlanner:
    """Get the global attack planner instance."""
    global _attack_planner
    if _attack_planner is None:
        _attack_planner = AttackPlanner()
    return _attack_planner


def reset_attack_planner() -> None:
    """Reset the global attack planner (for testing)."""
    global _attack_planner
    _attack_planner = None


__all__ = [
    "AttackPhase",
    "PlanStatus",
    "StepStatus",
    "PlanStep",
    "AttackPlan",
    "AttackPlanner",
    "get_attack_planner",
    "reset_attack_planner",
    "FULL_ASSESSMENT_KEYWORDS",
    "PHASE_KEYWORDS",
]

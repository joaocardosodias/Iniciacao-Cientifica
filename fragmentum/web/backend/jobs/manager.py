"""
Job Manager for async tool execution.

Requirements:
- 8.2: Return job ID for status tracking
- 2.4: Return job status, output, and findings
- 2.3: Display real-time output via WebSocket streaming
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, Optional, List, Any, Callable
from dataclasses import dataclass, field
import re

from fragmentum.web.backend.models.schemas import (
    Job,
    JobStatus,
    Finding,
    FindingType,
    Severity,
)
from fragmentum.tools.registry import get_tool_registry, Tool as RegistryTool
from fragmentum.tools.executor import execute_command


@dataclass
class JobEntry:
    """Internal job entry with execution state."""
    job: Job
    task: Optional[asyncio.Task] = None
    callbacks: List[Callable] = field(default_factory=list)


class JobManager:
    """
    Manages job creation, execution, and status tracking.
    
    Requirements:
    - 8.2: Return job ID for status tracking
    - 2.4: Return job status, output, and findings
    - 2.3: Display real-time output via WebSocket streaming
    """
    
    def __init__(self):
        self._jobs: Dict[str, JobEntry] = {}
        self._output_callbacks: Dict[str, List[Callable]] = {}
        self._websocket_hub = None
        self._notification_manager = None
    
    def set_websocket_hub(self, hub) -> None:
        """Set the WebSocket hub for real-time streaming."""
        self._websocket_hub = hub
    
    def set_notification_manager(self, manager) -> None:
        """Set the notification manager for alerts."""
        self._notification_manager = manager
    
    def create_job(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        target_id: Optional[str] = None,
        custom_command: Optional[str] = None
    ) -> Job:
        """
        Create a new job for tool execution.
        
        Requirements 8.2: Return job ID for status tracking.
        
        Args:
            tool_name: Name of the tool to execute
            parameters: Tool parameters
            target_id: Optional target ID for session tracking
            custom_command: Optional custom command to execute instead of tool default
            
        Returns:
            Created Job with unique ID
        """
        job_id = str(uuid.uuid4())
        
        # Store custom_command in parameters if provided
        if custom_command:
            parameters = {**parameters, "_custom_command": custom_command}
        
        job = Job(
            id=job_id,
            tool=tool_name,
            parameters=parameters,
            status=JobStatus.PENDING,
            output="",
            started_at=datetime.utcnow(),
            completed_at=None,
            findings=[]
        )
        
        self._jobs[job_id] = JobEntry(job=job)
        return job
    
    def get_job(self, job_id: str) -> Optional[Job]:
        """
        Get job by ID.
        
        Requirements 2.4: Return job status, output, and findings.
        
        Args:
            job_id: The job ID
            
        Returns:
            Job if found, None otherwise
        """
        entry = self._jobs.get(job_id)
        return entry.job if entry else None
    
    def list_jobs(
        self,
        status: Optional[JobStatus] = None,
        limit: int = 100
    ) -> List[Job]:
        """List jobs with optional status filter."""
        jobs = [entry.job for entry in self._jobs.values()]
        
        if status:
            jobs = [j for j in jobs if j.status == status]
        
        # Sort by started_at descending
        jobs.sort(key=lambda j: j.started_at, reverse=True)
        
        return jobs[:limit]
    
    async def execute_job(self, job_id: str) -> None:
        """
        Execute a job asynchronously.
        
        Requirements 2.3: Display real-time output via WebSocket streaming.
        
        Args:
            job_id: The job ID to execute
        """
        entry = self._jobs.get(job_id)
        if not entry:
            return
        
        job = entry.job
        job.status = JobStatus.RUNNING
        
        # Broadcast status change
        if self._websocket_hub:
            await self._websocket_hub.broadcast_job_status(job_id, job.status.value)
        
        try:
            # Get tool from registry
            registry = get_tool_registry()
            tool = registry.get(job.tool)
            
            if not tool:
                job.status = JobStatus.ERROR
                job.output = f"Tool not found: {job.tool}"
                job.completed_at = datetime.utcnow()
                
                # Broadcast error
                if self._websocket_hub:
                    await self._websocket_hub.broadcast_error(job_id, job.output)
                    await self._websocket_hub.broadcast_job_status(
                        job_id, job.status.value, job.completed_at
                    )
                
                # Send error notification
                if self._notification_manager:
                    target = job.parameters.get("target", "unknown")
                    await self._notification_manager.notify_execution_error(
                        job_id, job.tool, job.output, target
                    )
                return
            
            # Build command with parameters
            target = job.parameters.get("target", "")
            custom_command = job.parameters.get("_custom_command")
            options = {k: v for k, v in job.parameters.items() if k not in ["target", "_custom_command"]}
            
            # Use custom command if provided, otherwise build from tool
            if custom_command:
                command = custom_command
            else:
                command = tool.build_command(target=target, options=options)
            
            # Execute command with streaming
            output, success = await self._execute_with_streaming(
                job_id, command, tool.timeout
            )
            
            job.output = output
            job.status = JobStatus.COMPLETED if success else JobStatus.ERROR
            job.completed_at = datetime.utcnow()
            
            # Parse findings from output
            job.findings = self._parse_findings(output, job.tool, target)
            
            # Broadcast findings and check for notifications
            for finding in job.findings:
                if self._websocket_hub:
                    await self._websocket_hub.broadcast_finding(job_id, {
                        "id": finding.id,
                        "type": finding.type.value,
                        "value": finding.value,
                        "severity": finding.severity.value,
                        "source": finding.source,
                        "target": finding.target,
                    })
                
                # Send notification for critical/high findings
                if self._notification_manager:
                    await self._notification_manager.notify_finding(
                        {
                            "id": finding.id,
                            "type": finding.type.value,
                            "value": finding.value,
                            "severity": finding.severity.value,
                        },
                        finding.target,
                        finding.source
                    )
            
            # Broadcast final status
            if self._websocket_hub:
                await self._websocket_hub.broadcast_job_status(
                    job_id, job.status.value, job.completed_at
                )
            
            # Send error notification if failed
            if not success and self._notification_manager:
                await self._notification_manager.notify_execution_error(
                    job_id, job.tool, output[:200], target
                )
            
        except Exception as e:
            job.status = JobStatus.ERROR
            job.output = f"Execution error: {str(e)}"
            job.completed_at = datetime.utcnow()
            
            # Broadcast error
            if self._websocket_hub:
                await self._websocket_hub.broadcast_error(job_id, str(e))
                await self._websocket_hub.broadcast_job_status(
                    job_id, job.status.value, job.completed_at
                )
            
            # Send error notification
            if self._notification_manager:
                target = job.parameters.get("target", "unknown")
                await self._notification_manager.notify_execution_error(
                    job_id, job.tool, str(e), target
                )
    
    async def execute_shell_job(self, job_id: str, command: str, timeout: int = 180) -> None:
        """
        Execute a shell command job asynchronously.
        
        Args:
            job_id: The job ID to execute
            command: The shell command to execute
            timeout: Timeout in seconds
        """
        entry = self._jobs.get(job_id)
        if not entry:
            return
        
        job = entry.job
        job.status = JobStatus.RUNNING
        
        # Broadcast status change
        if self._websocket_hub:
            await self._websocket_hub.broadcast_job_status(job_id, job.status.value)
        
        try:
            # Execute command with streaming
            output, success = await self._execute_with_streaming(
                job_id, command, timeout
            )
            
            job.output = output
            job.status = JobStatus.COMPLETED if success else JobStatus.ERROR
            job.completed_at = datetime.utcnow()
            
            # Broadcast final status
            if self._websocket_hub:
                await self._websocket_hub.broadcast_job_status(
                    job_id, job.status.value, job.completed_at
                )
            
        except Exception as e:
            job.status = JobStatus.ERROR
            job.output = f"Execution error: {str(e)}"
            job.completed_at = datetime.utcnow()
            
            # Broadcast error
            if self._websocket_hub:
                await self._websocket_hub.broadcast_error(job_id, str(e))
                await self._websocket_hub.broadcast_job_status(
                    job_id, job.status.value, job.completed_at
                )
    
    async def _execute_with_streaming(
        self,
        job_id: str,
        command: str,
        timeout: int
    ) -> tuple[str, bool]:
        """
        Execute command with real-time output streaming.
        
        Requirements 2.3: Display real-time output via WebSocket streaming.
        
        Args:
            job_id: The job ID for streaming
            command: The command to execute
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (output, success)
        """
        full_output = ""
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            
            # Stream output line by line
            while True:
                try:
                    line = await asyncio.wait_for(
                        process.stdout.readline(),
                        timeout=timeout
                    )
                    
                    if not line:
                        break
                    
                    decoded_line = line.decode('utf-8', errors='replace')
                    full_output += decoded_line
                    
                    # Stream to WebSocket
                    if self._websocket_hub:
                        await self._websocket_hub.broadcast_job_output(
                            job_id, decoded_line, append=True
                        )
                        
                except asyncio.TimeoutError:
                    process.kill()
                    full_output += "\n[Timeout: Command exceeded time limit]"
                    if self._websocket_hub:
                        await self._websocket_hub.broadcast_job_output(
                            job_id, "\n[Timeout: Command exceeded time limit]", append=True
                        )
                    return full_output, False
            
            await process.wait()
            success = process.returncode == 0
            return full_output, success
            
        except Exception as e:
            error_msg = f"\n[Error: {str(e)}]"
            full_output += error_msg
            if self._websocket_hub:
                await self._websocket_hub.broadcast_job_output(job_id, error_msg, append=True)
            return full_output, False
    
    def start_job(self, job_id: str) -> Optional[asyncio.Task]:
        """
        Start job execution in background.
        
        Args:
            job_id: The job ID to start
            
        Returns:
            The asyncio Task if started, None if job not found
        """
        entry = self._jobs.get(job_id)
        if not entry:
            return None
        
        task = asyncio.create_task(self.execute_job(job_id))
        entry.task = task
        return task
    
    def _parse_findings(
        self,
        output: str,
        tool_name: str,
        target: str
    ) -> List[Finding]:
        """
        Parse tool output to extract findings.
        
        Args:
            output: Tool output text
            tool_name: Name of the tool
            target: Target that was scanned
            
        Returns:
            List of parsed findings
        """
        findings = []
        output_lower = output.lower()
        
        # Nmap port findings
        if tool_name.startswith("nmap"):
            findings.extend(self._parse_nmap_output(output, target))
        
        # Gobuster/directory findings
        elif tool_name in ["gobuster", "dirb", "ffuf", "feroxbuster"]:
            findings.extend(self._parse_directory_output(output, target, tool_name))
        
        # Nikto vulnerability findings
        elif tool_name == "nikto":
            findings.extend(self._parse_nikto_output(output, target))
        
        # Hydra credential findings
        elif tool_name.startswith("hydra"):
            findings.extend(self._parse_hydra_output(output, target))
        
        # SQLMap findings
        elif tool_name == "sqlmap":
            findings.extend(self._parse_sqlmap_output(output, target))
        
        # Generic info finding if no specific parser
        if not findings and output.strip():
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.INFO,
                value={"output_preview": output[:500]},
                severity=Severity.INFO,
                source=tool_name,
                target=target,
                timestamp=datetime.utcnow(),
                details={"full_output_length": len(output)}
            ))
        
        return findings
    
    def _parse_nmap_output(self, output: str, target: str) -> List[Finding]:
        """Parse nmap output for port/service findings."""
        findings = []
        
        # Match port lines: "22/tcp   open  ssh     OpenSSH 7.9"
        port_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)"
        
        for match in re.finditer(port_pattern, output, re.IGNORECASE):
            port = match.group(1)
            protocol = match.group(2)
            service = match.group(3)
            version = match.group(4).strip() if match.group(4) else ""
            
            # Determine severity based on service
            severity = Severity.INFO
            if service in ["ftp", "telnet", "rsh", "rlogin"]:
                severity = Severity.MEDIUM
            elif "anonymous" in output.lower() and service == "ftp":
                severity = Severity.HIGH
            
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.PORT,
                value={
                    "port": int(port),
                    "protocol": protocol,
                    "service": service,
                    "version": version
                },
                severity=severity,
                source="nmap",
                target=target,
                timestamp=datetime.utcnow(),
                details={"raw_line": match.group(0)}
            ))
            
            # Add service finding
            if version:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    type=FindingType.SERVICE,
                    value={
                        "service": service,
                        "version": version,
                        "port": int(port)
                    },
                    severity=Severity.INFO,
                    source="nmap",
                    target=target,
                    timestamp=datetime.utcnow(),
                    details={}
                ))
        
        return findings
    
    def _parse_directory_output(
        self,
        output: str,
        target: str,
        tool_name: str
    ) -> List[Finding]:
        """Parse directory brute-force output."""
        findings = []
        
        # Match status codes and paths
        patterns = [
            r"(/\S+)\s+\(Status:\s*(\d+)\)",  # gobuster
            r"\+\s+http[s]?://[^/]+(/\S+)",    # dirb
            r"(\d{3})\s+\d+L\s+\d+W\s+\d+Ch\s+\"([^\"]+)\"",  # ffuf
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, output):
                path = match.group(1) if len(match.groups()) == 1 else match.group(2)
                status = match.group(2) if len(match.groups()) > 1 else "200"
                
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    type=FindingType.INFO,
                    value={
                        "path": path,
                        "status_code": int(status) if status.isdigit() else 200
                    },
                    severity=Severity.LOW,
                    source=tool_name,
                    target=target,
                    timestamp=datetime.utcnow(),
                    details={}
                ))
        
        return findings
    
    def _parse_nikto_output(self, output: str, target: str) -> List[Finding]:
        """Parse nikto vulnerability output."""
        findings = []
        
        # Match vulnerability lines
        vuln_pattern = r"\+\s+OSVDB-(\d+):\s+(.+)"
        
        for match in re.finditer(vuln_pattern, output):
            osvdb_id = match.group(1)
            description = match.group(2).strip()
            
            # Determine severity based on keywords
            severity = Severity.MEDIUM
            desc_lower = description.lower()
            if any(w in desc_lower for w in ["critical", "rce", "remote code"]):
                severity = Severity.CRITICAL
            elif any(w in desc_lower for w in ["xss", "injection", "bypass"]):
                severity = Severity.HIGH
            elif any(w in desc_lower for w in ["disclosure", "information"]):
                severity = Severity.LOW
            
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.VULNERABILITY,
                value={
                    "osvdb_id": osvdb_id,
                    "description": description
                },
                severity=severity,
                source="nikto",
                target=target,
                timestamp=datetime.utcnow(),
                details={"raw_line": match.group(0)}
            ))
        
        return findings
    
    def _parse_hydra_output(self, output: str, target: str) -> List[Finding]:
        """Parse hydra credential findings."""
        findings = []
        
        # Match credential lines
        cred_pattern = r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
        
        for match in re.finditer(cred_pattern, output, re.IGNORECASE):
            port = match.group(1)
            service = match.group(2)
            host = match.group(3)
            username = match.group(4)
            password = match.group(5)
            
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.CREDENTIAL,
                value={
                    "username": username,
                    "password": password,
                    "service": service,
                    "port": int(port)
                },
                severity=Severity.CRITICAL,
                source="hydra",
                target=host,
                timestamp=datetime.utcnow(),
                details={}
            ))
        
        return findings
    
    def _parse_sqlmap_output(self, output: str, target: str) -> List[Finding]:
        """Parse sqlmap SQL injection findings."""
        findings = []
        
        # Check for injection confirmation
        if "is vulnerable" in output.lower() or "injectable" in output.lower():
            # Extract parameter name if possible
            param_match = re.search(r"Parameter:\s+(\S+)", output)
            param = param_match.group(1) if param_match else "unknown"
            
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.VULNERABILITY,
                value={
                    "type": "SQL Injection",
                    "parameter": param
                },
                severity=Severity.CRITICAL,
                source="sqlmap",
                target=target,
                timestamp=datetime.utcnow(),
                details={"confirmed": True}
            ))
        
        # Extract database info if found
        db_match = re.search(r"back-end DBMS:\s+(.+)", output)
        if db_match:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.INFO,
                value={
                    "database_type": db_match.group(1).strip()
                },
                severity=Severity.INFO,
                source="sqlmap",
                target=target,
                timestamp=datetime.utcnow(),
                details={}
            ))
        
        return findings
    
    def register_output_callback(
        self,
        job_id: str,
        callback: Callable[[str], None]
    ) -> None:
        """Register a callback for job output updates."""
        if job_id not in self._output_callbacks:
            self._output_callbacks[job_id] = []
        self._output_callbacks[job_id].append(callback)
    
    def unregister_output_callback(
        self,
        job_id: str,
        callback: Callable[[str], None]
    ) -> None:
        """Unregister an output callback."""
        if job_id in self._output_callbacks:
            try:
                self._output_callbacks[job_id].remove(callback)
            except ValueError:
                pass


# Global job manager instance
_job_manager: Optional[JobManager] = None


def get_job_manager() -> JobManager:
    """Get the global job manager instance."""
    global _job_manager
    if _job_manager is None:
        _job_manager = JobManager()
    return _job_manager

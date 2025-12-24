"""
Pydantic models for API request/response schemas.

Based on the design document data models.
Requirements: 8.5 - Tool definitions with parameter schemas
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator
import re


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    """Types of findings."""
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    SHELL = "shell"
    INFO = "info"


class TargetType(str, Enum):
    """Target types."""
    IP = "ip"
    DOMAIN = "domain"
    CIDR = "cidr"


class JobStatus(str, Enum):
    """Job execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"


class SessionStatus(str, Enum):
    """Session status."""
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"


# Parameter Schema
class ParameterSchema(BaseModel):
    """Schema for tool parameters."""
    name: str
    type: str = Field(description="Parameter type: string, number, boolean, object")
    description: str
    required: bool = False
    default: Optional[Any] = None


# Tool Models
class ToolBase(BaseModel):
    """Base tool definition."""
    name: str
    description: str
    category: str


class Tool(ToolBase):
    """Tool definition with parameters."""
    parameters: Dict[str, ParameterSchema] = Field(default_factory=dict)
    timeout: int = 180
    requires_root: bool = False
    command: Optional[str] = None


class ToolResponse(ToolBase):
    """Response for tool listing - Requirements 8.5."""
    parameters: Dict[str, ParameterSchema]
    
    model_config = {"from_attributes": True}


class ToolListResponse(BaseModel):
    """Response for listing all tools."""
    tools: List[ToolResponse]
    total: int
    categories: List[str]


# Target Models
class TargetInput(BaseModel):
    """Input for creating a target."""
    value: str = Field(description="IP, domain, or CIDR range")
    
    @field_validator('value')
    @classmethod
    def validate_target_format(cls, v: str) -> str:
        """Validate target format - Requirements 3.1."""
        v = v.strip()
        if not v:
            raise ValueError("Target value cannot be empty")
        
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # CIDR pattern
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        # Domain pattern (simplified)
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        if re.match(ipv4_pattern, v):
            # Validate IP octets
            octets = v.split('.')
            for octet in octets:
                if int(octet) > 255:
                    raise ValueError(f"Invalid IP address: {v}")
            return v
        elif re.match(cidr_pattern, v):
            # Validate CIDR
            ip_part, prefix = v.rsplit('/', 1)
            octets = ip_part.split('.')
            for octet in octets:
                if int(octet) > 255:
                    raise ValueError(f"Invalid CIDR range: {v}")
            if int(prefix) > 32:
                raise ValueError(f"Invalid CIDR prefix: {v}")
            return v
        elif re.match(domain_pattern, v) and '.' in v:
            return v
        else:
            raise ValueError(f"Invalid target format: {v}. Must be IP, domain, or CIDR range")


def detect_target_type(value: str) -> TargetType:
    """Detect target type from value."""
    if '/' in value:
        return TargetType.CIDR
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
        return TargetType.IP
    return TargetType.DOMAIN


class Target(BaseModel):
    """Target model."""
    id: str
    value: str
    type: TargetType
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TargetResponse(BaseModel):
    """Response for target operations."""
    id: str
    value: str
    type: TargetType
    created_at: datetime
    session_count: int = 0


# Finding Models
class Finding(BaseModel):
    """Finding model."""
    id: str
    type: FindingType
    value: Any
    severity: Severity
    source: str
    target: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = Field(default_factory=dict)


class FindingResponse(BaseModel):
    """Response for finding operations."""
    id: str
    type: FindingType
    value: Any
    severity: Severity
    source: str
    target: str
    timestamp: datetime
    details: Dict[str, Any]


# Session Models
class Session(BaseModel):
    """Session model."""
    id: str
    target_id: str
    status: SessionStatus
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None
    findings: List[Finding] = Field(default_factory=list)


class SessionResponse(BaseModel):
    """Response for session operations."""
    id: str
    target_id: str
    status: SessionStatus
    started_at: datetime
    ended_at: Optional[datetime]
    finding_count: int = 0


# Job Models
class Job(BaseModel):
    """Job model for tool execution."""
    id: str
    tool: str
    parameters: Dict[str, Any]
    status: JobStatus
    output: str = ""
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    findings: List[Finding] = Field(default_factory=list)


# Execute Request/Response
class ExecuteRequest(BaseModel):
    """Request for tool execution."""
    tool: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    target_id: Optional[str] = None
    custom_command: Optional[str] = Field(default=None, description="Custom command to execute instead of tool default")


class ExecuteResponse(BaseModel):
    """Response for tool execution."""
    job_id: str
    status: JobStatus
    started_at: datetime


class JobStatusResponse(BaseModel):
    """Response for job status check."""
    job_id: str
    status: JobStatus
    output: str
    started_at: datetime
    completed_at: Optional[datetime]
    findings: List[FindingResponse] = Field(default_factory=list)


# Error Response
class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    details: Optional[str] = None

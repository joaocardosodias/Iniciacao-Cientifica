"""
Swarm attack API endpoints.

Requirements:
- 3.3: Create a new session and start the multi-agent attack
"""

from typing import Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field
import uuid

from fragmentum.web.backend.models.schemas import (
    SessionStatus,
    ErrorResponse,
    Finding,
    FindingType,
    Severity,
)
from fragmentum.web.backend.api.auth import get_api_key
from fragmentum.web.backend.api.sessions import (
    create_session,
    add_finding_to_session,
    complete_session,
    get_session_by_id,
)
from fragmentum.web.backend.api.targets import (
    add_session_to_target,
    get_target_storage,
)
from fragmentum.web.backend.websocket.notifications import get_notification_manager

router = APIRouter(prefix="/swarm", tags=["swarm"])


class SwarmAttackRequest(BaseModel):
    """Request for starting a Swarm attack."""
    target: str = Field(description="Target IP or domain")
    target_id: Optional[str] = Field(default=None, description="Optional target ID to associate")
    enable_exploitation: bool = Field(default=True, description="Enable exploitation phase")
    enable_password_attacks: bool = Field(default=True, description="Enable password attacks")
    aggressive_mode: bool = Field(default=False, description="Aggressive mode (faster, noisier)")


class SwarmAttackResponse(BaseModel):
    """Response for Swarm attack initiation."""
    session_id: str
    target: str
    status: str
    started_at: datetime


class SwarmStatusResponse(BaseModel):
    """Response for Swarm attack status."""
    session_id: str
    target: str
    status: str
    started_at: datetime
    ended_at: Optional[datetime]
    finding_count: int
    summary: Dict[str, Any]


# Track active swarm attacks
_active_swarms: Dict[str, Dict[str, Any]] = {}


@router.post(
    "/attack",
    response_model=SwarmAttackResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Start a Swarm attack",
    description="Initiate a multi-agent Swarm attack - Requirements 3.3"
)
async def start_swarm_attack(
    request: SwarmAttackRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(get_api_key)
) -> SwarmAttackResponse:
    """
    Start a Swarm attack against a target.
    
    Requirements 3.3: Create a new session and start the multi-agent attack.
    
    Args:
        request: Swarm attack configuration
        background_tasks: FastAPI background tasks
        
    Returns:
        SwarmAttackResponse with session ID
    """
    # Validate target_id if provided
    if request.target_id:
        targets = get_target_storage()
        if request.target_id not in targets:
            raise HTTPException(
                status_code=404,
                detail=f"Target not found: {request.target_id}"
            )
    
    # Create session
    session_id = f"swarm-{uuid.uuid4().hex[:8]}"
    session = create_session(
        target_id=request.target_id or request.target,
        session_id=session_id
    )
    
    # Associate session with target if target_id provided
    if request.target_id:
        add_session_to_target(request.target_id, session_id)
    
    # Track swarm attack
    _active_swarms[session_id] = {
        "target": request.target,
        "config": {
            "enable_exploitation": request.enable_exploitation,
            "enable_password_attacks": request.enable_password_attacks,
            "aggressive_mode": request.aggressive_mode,
        },
        "started_at": datetime.utcnow(),
        "status": "running"
    }
    
    # Start swarm attack in background
    background_tasks.add_task(
        run_swarm_attack,
        session_id,
        request.target,
        request.enable_exploitation,
        request.enable_password_attacks,
        request.aggressive_mode
    )
    
    return SwarmAttackResponse(
        session_id=session_id,
        target=request.target,
        status="running",
        started_at=session.started_at
    )


async def run_swarm_attack(
    session_id: str,
    target: str,
    enable_exploitation: bool,
    enable_password_attacks: bool,
    aggressive_mode: bool
):
    """
    Execute the Swarm attack in background.
    
    Args:
        session_id: Session ID for tracking
        target: Target IP or domain
        enable_exploitation: Enable exploitation phase
        enable_password_attacks: Enable password attacks
        aggressive_mode: Aggressive mode flag
    """
    try:
        # Import here to avoid circular imports
        from fragmentum.swarm.swarm import SwarmController, SwarmConfig
        from fragmentum.swarm.shared_memory import Finding as SwarmFinding, Severity as SwarmSeverity
        
        # Create swarm config
        config = SwarmConfig(
            enable_exploitation=enable_exploitation,
            enable_password_attacks=enable_password_attacks,
            aggressive_mode=aggressive_mode
        )
        
        # Create controller and run attack
        controller = SwarmController(config)
        swarm_session = await controller.attack(target)
        
        # Convert swarm findings to API findings
        for swarm_finding in swarm_session.memory.get_all_findings():
            finding = convert_swarm_finding(swarm_finding, session_id)
            add_finding_to_session(session_id, finding)
            
            # Send notification for critical/high findings
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                notification_manager = get_notification_manager()
                await notification_manager.notify_finding(finding)
        
        # Mark session as completed
        final_status = SessionStatus.COMPLETED if swarm_session.status == "completed" else SessionStatus.ERROR
        complete_session(session_id, final_status)
        
        # Update swarm tracking
        if session_id in _active_swarms:
            _active_swarms[session_id]["status"] = swarm_session.status
            _active_swarms[session_id]["ended_at"] = datetime.utcnow()
            _active_swarms[session_id]["summary"] = swarm_session.memory.get_summary()
        
        # Send completion notification
        notification_manager = get_notification_manager()
        session = get_session_by_id(session_id)
        if session:
            await notification_manager.notify_session_complete(
                session_id,
                target,
                len(session.findings)
            )
        
    except Exception as e:
        # Mark session as error
        complete_session(session_id, SessionStatus.ERROR)
        
        if session_id in _active_swarms:
            _active_swarms[session_id]["status"] = f"error: {str(e)}"
            _active_swarms[session_id]["ended_at"] = datetime.utcnow()


def convert_swarm_finding(swarm_finding, session_id: str) -> Finding:
    """
    Convert a Swarm finding to API Finding model.
    
    Args:
        swarm_finding: Finding from Swarm shared memory
        session_id: Session ID for reference
        
    Returns:
        API Finding model
    """
    from fragmentum.swarm.shared_memory import FindingType as SwarmFindingType, Severity as SwarmSeverity
    
    # Map swarm finding type to API finding type
    type_mapping = {
        SwarmFindingType.PORT: FindingType.PORT,
        SwarmFindingType.SERVICE: FindingType.SERVICE,
        SwarmFindingType.VULNERABILITY: FindingType.VULNERABILITY,
        SwarmFindingType.CREDENTIAL: FindingType.CREDENTIAL,
        SwarmFindingType.SHELL: FindingType.SHELL,
        SwarmFindingType.INFO: FindingType.INFO,
    }
    
    # Map swarm severity to API severity
    severity_mapping = {
        SwarmSeverity.CRITICAL: Severity.CRITICAL,
        SwarmSeverity.HIGH: Severity.HIGH,
        SwarmSeverity.MEDIUM: Severity.MEDIUM,
        SwarmSeverity.LOW: Severity.LOW,
        SwarmSeverity.INFO: Severity.INFO,
    }
    
    finding_type = type_mapping.get(swarm_finding.type, FindingType.INFO)
    severity = severity_mapping.get(swarm_finding.severity, Severity.INFO)
    
    return Finding(
        id=str(uuid.uuid4()),
        type=finding_type,
        value=swarm_finding.value,
        severity=severity,
        source=swarm_finding.source,  # Agent name - Requirements 5.4
        target=swarm_finding.target,
        timestamp=swarm_finding.timestamp,
        details=swarm_finding.details
    )


@router.get(
    "/{session_id}",
    response_model=SwarmStatusResponse,
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Get Swarm attack status",
    description="Get status of a Swarm attack"
)
async def get_swarm_status(
    session_id: str,
    api_key: str = Depends(get_api_key)
) -> SwarmStatusResponse:
    """
    Get Swarm attack status.
    
    Args:
        session_id: Session ID
        
    Returns:
        SwarmStatusResponse with attack status
    """
    swarm_info = _active_swarms.get(session_id)
    session = get_session_by_id(session_id)
    
    if not swarm_info and not session:
        raise HTTPException(
            status_code=404,
            detail=f"Swarm session not found: {session_id}"
        )
    
    if swarm_info:
        return SwarmStatusResponse(
            session_id=session_id,
            target=swarm_info["target"],
            status=swarm_info["status"],
            started_at=swarm_info["started_at"],
            ended_at=swarm_info.get("ended_at"),
            finding_count=len(session.findings) if session else 0,
            summary=swarm_info.get("summary", {})
        )
    
    # Fallback to session data
    return SwarmStatusResponse(
        session_id=session_id,
        target=session.target_id,
        status=session.status.value,
        started_at=session.started_at,
        ended_at=session.ended_at,
        finding_count=len(session.findings),
        summary={}
    )

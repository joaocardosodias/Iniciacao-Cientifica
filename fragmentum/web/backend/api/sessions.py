"""
Session management API endpoints.

Requirements:
- 5.1: Display a timeline of events and findings
- 5.3: Generate a JSON file with all session data
- 5.4: Show which agents discovered each finding
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
import uuid
import json

from fragmentum.web.backend.models.schemas import (
    Session,
    SessionResponse,
    SessionStatus,
    Finding,
    FindingResponse,
    ErrorResponse,
    Severity,
    FindingType,
)
from fragmentum.web.backend.api.auth import get_api_key

router = APIRouter(prefix="/sessions", tags=["sessions"])

# In-memory storage for sessions (in production, use a database)
_sessions: Dict[str, Session] = {}


def get_session_storage() -> Dict[str, Session]:
    """Get the session storage (for testing/dependency injection)."""
    return _sessions


class SessionExport:
    """Session export data structure for JSON export."""
    
    def __init__(self, session: Session):
        self.id = session.id
        self.target_id = session.target_id
        self.status = session.status.value
        self.started_at = session.started_at.isoformat()
        self.ended_at = session.ended_at.isoformat() if session.ended_at else None
        self.findings = [
            {
                "id": f.id,
                "type": f.type.value,
                "value": f.value,
                "severity": f.severity.value,
                "source": f.source,
                "target": f.target,
                "timestamp": f.timestamp.isoformat(),
                "details": f.details
            }
            for f in session.findings
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "findings": self.findings
        }


@router.get(
    "",
    response_model=List[SessionResponse],
    responses={401: {"model": ErrorResponse}},
    summary="List all sessions",
    description="Returns all sessions sorted by date - Requirements 5.1"
)
async def list_sessions(
    target_id: Optional[str] = None,
    status: Optional[SessionStatus] = None,
    api_key: str = Depends(get_api_key)
) -> List[SessionResponse]:
    """
    List all sessions with optional filtering.
    
    Requirements 5.1: Display a timeline of events and findings.
    
    Args:
        target_id: Optional filter by target
        status: Optional filter by status
        
    Returns:
        List of sessions sorted by start date (most recent first)
    """
    sessions = list(_sessions.values())
    
    # Filter by target_id if specified
    if target_id:
        sessions = [s for s in sessions if s.target_id == target_id]
    
    # Filter by status if specified
    if status:
        sessions = [s for s in sessions if s.status == status]
    
    # Sort by started_at descending (most recent first) - Requirements 3.4
    sessions.sort(key=lambda s: s.started_at, reverse=True)
    
    return [
        SessionResponse(
            id=s.id,
            target_id=s.target_id,
            status=s.status,
            started_at=s.started_at,
            ended_at=s.ended_at,
            finding_count=len(s.findings)
        )
        for s in sessions
    ]


@router.get(
    "/{session_id}",
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Get session details",
    description="Get full session details with findings - Requirements 5.1, 5.4"
)
async def get_session(
    session_id: str,
    finding_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    api_key: str = Depends(get_api_key)
) -> Dict[str, Any]:
    """
    Get session details with findings.
    
    Requirements:
    - 5.1: Display a timeline of events and findings
    - 5.2: Allow filtering by type, severity, and source agent
    - 5.4: Show which agents discovered each finding
    
    Args:
        session_id: Session ID
        finding_type: Optional filter by finding type
        severity: Optional filter by severity
        source: Optional filter by source agent
        
    Returns:
        Session details with filtered findings
    """
    session = _sessions.get(session_id)
    
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session not found: {session_id}"
        )
    
    # Filter findings - Requirements 5.2
    findings = session.findings
    
    if finding_type:
        findings = [f for f in findings if f.type.value == finding_type]
    
    if severity:
        findings = [f for f in findings if f.severity.value == severity]
    
    if source:
        findings = [f for f in findings if f.source == source]
    
    # Sort findings by timestamp (timeline) - Requirements 5.1
    findings.sort(key=lambda f: f.timestamp)
    
    return {
        "id": session.id,
        "target_id": session.target_id,
        "status": session.status.value,
        "started_at": session.started_at.isoformat(),
        "ended_at": session.ended_at.isoformat() if session.ended_at else None,
        "finding_count": len(session.findings),
        "filtered_count": len(findings),
        "findings": [
            {
                "id": f.id,
                "type": f.type.value,
                "value": f.value,
                "severity": f.severity.value,
                "source": f.source,  # Requirements 5.4: Agent attribution
                "target": f.target,
                "timestamp": f.timestamp.isoformat(),
                "details": f.details
            }
            for f in findings
        ]
    }


@router.post(
    "/{session_id}/export",
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Export session to JSON",
    description="Export session data as JSON - Requirements 5.3"
)
async def export_session(
    session_id: str,
    api_key: str = Depends(get_api_key)
) -> JSONResponse:
    """
    Export session to JSON.
    
    Requirements 5.3: Generate a JSON file with all session data.
    
    Args:
        session_id: Session ID to export
        
    Returns:
        JSON response with session data
    """
    session = _sessions.get(session_id)
    
    if not session:
        raise HTTPException(
            status_code=404,
            detail=f"Session not found: {session_id}"
        )
    
    export = SessionExport(session)
    
    return JSONResponse(
        content=export.to_dict(),
        headers={
            "Content-Disposition": f'attachment; filename="session-{session_id}.json"'
        }
    )


@router.delete(
    "/{session_id}",
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Delete a session",
    description="Delete a session and its findings"
)
async def delete_session(
    session_id: str,
    api_key: str = Depends(get_api_key)
) -> dict:
    """
    Delete a session.
    
    Args:
        session_id: Session ID to delete
        
    Returns:
        Confirmation message
    """
    if session_id not in _sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Session not found: {session_id}"
        )
    
    del _sessions[session_id]
    
    return {"message": f"Session {session_id} deleted"}


def create_session(target_id: str, session_id: Optional[str] = None) -> Session:
    """
    Create a new session.
    
    Args:
        target_id: Target ID for the session
        session_id: Optional custom session ID
        
    Returns:
        Created session
    """
    if not session_id:
        session_id = str(uuid.uuid4())
    
    session = Session(
        id=session_id,
        target_id=target_id,
        status=SessionStatus.RUNNING,
        started_at=datetime.utcnow(),
        findings=[]
    )
    
    _sessions[session_id] = session
    return session


def add_finding_to_session(session_id: str, finding: Finding) -> bool:
    """
    Add a finding to a session.
    
    Args:
        session_id: Session ID
        finding: Finding to add
        
    Returns:
        True if successful, False if session not found
    """
    session = _sessions.get(session_id)
    if not session:
        return False
    
    session.findings.append(finding)
    return True


def complete_session(session_id: str, status: SessionStatus = SessionStatus.COMPLETED) -> bool:
    """
    Mark a session as completed.
    
    Args:
        session_id: Session ID
        status: Final status
        
    Returns:
        True if successful, False if session not found
    """
    session = _sessions.get(session_id)
    if not session:
        return False
    
    session.status = status
    session.ended_at = datetime.utcnow()
    return True


def get_session_by_id(session_id: str) -> Optional[Session]:
    """
    Get a session by ID.
    
    Args:
        session_id: Session ID
        
    Returns:
        Session or None
    """
    return _sessions.get(session_id)

"""
Dashboard API endpoints.

Requirements:
- 1.1: Display active sessions with their current status
- 1.3: Categorize findings by severity
"""

from typing import Dict, List, Any
from fastapi import APIRouter, Depends

from fragmentum.web.backend.api.auth import get_api_key
from fragmentum.web.backend.api.sessions import get_session_storage
from fragmentum.web.backend.api.targets import get_target_storage
from fragmentum.web.backend.models.schemas import (
    SessionStatus,
    Severity,
    ErrorResponse,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get(
    "/stats",
    responses={401: {"model": ErrorResponse}},
    summary="Get dashboard statistics",
    description="Returns aggregated stats for the dashboard - Requirements 1.1, 1.3"
)
async def get_dashboard_stats(
    api_key: str = Depends(get_api_key)
) -> Dict[str, Any]:
    """
    Get dashboard statistics.
    
    Requirements:
    - 1.1: Display active sessions with their current status
    - 1.3: Categorize findings by severity
    
    Returns:
        Dashboard statistics including targets, sessions, and findings counts
    """
    targets = get_target_storage()
    sessions = get_session_storage()
    
    # Count sessions by status
    active_sessions = sum(1 for s in sessions.values() if s.status == SessionStatus.RUNNING)
    completed_sessions = sum(1 for s in sessions.values() if s.status == SessionStatus.COMPLETED)
    error_sessions = sum(1 for s in sessions.values() if s.status == SessionStatus.ERROR)
    
    # Collect all findings and count by severity
    all_findings = []
    for session in sessions.values():
        all_findings.extend(session.findings)
    
    findings_by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for finding in all_findings:
        severity_key = finding.severity.value
        if severity_key in findings_by_severity:
            findings_by_severity[severity_key] += 1
    
    return {
        "total_targets": len(targets),
        "total_sessions": len(sessions),
        "active_sessions": active_sessions,
        "completed_sessions": completed_sessions,
        "error_sessions": error_sessions,
        "total_findings": len(all_findings),
        "findings_by_severity": findings_by_severity
    }


@router.get(
    "/recent-findings",
    responses={401: {"model": ErrorResponse}},
    summary="Get recent findings",
    description="Returns recent findings grouped by severity - Requirements 1.3"
)
async def get_recent_findings(
    limit: int = 20,
    api_key: str = Depends(get_api_key)
) -> Dict[str, Any]:
    """
    Get recent findings grouped by severity.
    
    Requirements 1.3: Categorize findings by severity.
    
    Args:
        limit: Maximum number of findings to return
        
    Returns:
        Recent findings grouped by severity
    """
    sessions = get_session_storage()
    
    # Collect all findings with session info
    all_findings = []
    for session in sessions.values():
        for finding in session.findings:
            all_findings.append({
                "id": finding.id,
                "type": finding.type.value,
                "value": finding.value,
                "severity": finding.severity.value,
                "source": finding.source,
                "target": finding.target,
                "timestamp": finding.timestamp.isoformat(),
                "details": finding.details,
                "session_id": session.id
            })
    
    # Sort by timestamp descending (most recent first)
    all_findings.sort(key=lambda f: f["timestamp"], reverse=True)
    
    # Limit results
    recent_findings = all_findings[:limit]
    
    # Group by severity
    grouped = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }
    
    for finding in recent_findings:
        severity = finding["severity"]
        if severity in grouped:
            grouped[severity].append(finding)
    
    return {
        "findings": recent_findings,
        "grouped": grouped,
        "total": len(recent_findings)
    }


@router.get(
    "/active-sessions",
    responses={401: {"model": ErrorResponse}},
    summary="Get active sessions",
    description="Returns currently running sessions - Requirements 1.1"
)
async def get_active_sessions(
    api_key: str = Depends(get_api_key)
) -> List[Dict[str, Any]]:
    """
    Get active (running) sessions.
    
    Requirements 1.1: Display active sessions with their current status.
    
    Returns:
        List of active sessions with their details
    """
    sessions = get_session_storage()
    
    active = []
    for session in sessions.values():
        if session.status == SessionStatus.RUNNING:
            active.append({
                "id": session.id,
                "target_id": session.target_id,
                "status": session.status.value,
                "started_at": session.started_at.isoformat(),
                "finding_count": len(session.findings)
            })
    
    # Sort by started_at descending
    active.sort(key=lambda s: s["started_at"], reverse=True)
    
    return active

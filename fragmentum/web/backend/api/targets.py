"""
Target management API endpoints.

Requirements:
- 3.1: Validate target format (IP, domain, or CIDR range)
- 3.2: Display all associated sessions and findings
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
import uuid

from fragmentum.web.backend.models.schemas import (
    TargetInput,
    Target,
    TargetResponse,
    TargetType,
    ErrorResponse,
    detect_target_type,
)
from fragmentum.web.backend.api.auth import get_api_key

router = APIRouter(prefix="/targets", tags=["targets"])

# In-memory storage for targets (in production, use a database)
_targets: Dict[str, Target] = {}
_target_sessions: Dict[str, List[str]] = {}  # target_id -> session_ids


def get_target_storage() -> Dict[str, Target]:
    """Get the target storage (for testing/dependency injection)."""
    return _targets


def get_target_session_mapping() -> Dict[str, List[str]]:
    """Get the target-session mapping."""
    return _target_sessions


@router.get(
    "",
    response_model=List[TargetResponse],
    responses={401: {"model": ErrorResponse}},
    summary="List all targets",
    description="Returns all registered targets - Requirements 3.2"
)
async def list_targets(
    api_key: str = Depends(get_api_key)
) -> List[TargetResponse]:
    """
    List all registered targets.
    
    Requirements 3.2: Display all associated sessions and findings.
    
    Returns:
        List of targets with session counts
    """
    responses = []
    for target in _targets.values():
        session_count = len(_target_sessions.get(target.id, []))
        responses.append(TargetResponse(
            id=target.id,
            value=target.value,
            type=target.type,
            created_at=target.created_at,
            session_count=session_count
        ))
    
    # Sort by created_at descending (most recent first)
    responses.sort(key=lambda t: t.created_at, reverse=True)
    return responses


@router.post(
    "",
    response_model=TargetResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
    },
    summary="Add a new target",
    description="Add a new target with validation - Requirements 3.1"
)
async def create_target(
    target_input: TargetInput,
    api_key: str = Depends(get_api_key)
) -> TargetResponse:
    """
    Create a new target.
    
    Requirements 3.1: Validate target format (IP, domain, or CIDR range).
    
    Args:
        target_input: Target value to add
        
    Returns:
        Created target with ID
    """
    # Check for duplicate
    for existing in _targets.values():
        if existing.value == target_input.value:
            raise HTTPException(
                status_code=400,
                detail=f"Target already exists: {target_input.value}"
            )
    
    # Detect target type
    target_type = detect_target_type(target_input.value)
    
    # Create target
    target_id = str(uuid.uuid4())
    target = Target(
        id=target_id,
        value=target_input.value,
        type=target_type,
        created_at=datetime.utcnow()
    )
    
    _targets[target_id] = target
    _target_sessions[target_id] = []
    
    return TargetResponse(
        id=target.id,
        value=target.value,
        type=target.type,
        created_at=target.created_at,
        session_count=0
    )


@router.get(
    "/{target_id}",
    response_model=TargetResponse,
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Get target details",
    description="Get details for a specific target - Requirements 3.2"
)
async def get_target(
    target_id: str,
    api_key: str = Depends(get_api_key)
) -> TargetResponse:
    """
    Get target details.
    
    Requirements 3.2: Display all associated sessions and findings.
    
    Args:
        target_id: Target ID
        
    Returns:
        Target details with session count
    """
    target = _targets.get(target_id)
    
    if not target:
        raise HTTPException(
            status_code=404,
            detail=f"Target not found: {target_id}"
        )
    
    session_count = len(_target_sessions.get(target_id, []))
    
    return TargetResponse(
        id=target.id,
        value=target.value,
        type=target.type,
        created_at=target.created_at,
        session_count=session_count
    )


@router.delete(
    "/{target_id}",
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Delete a target",
    description="Delete a target and its associations"
)
async def delete_target(
    target_id: str,
    api_key: str = Depends(get_api_key)
) -> dict:
    """
    Delete a target.
    
    Args:
        target_id: Target ID to delete
        
    Returns:
        Confirmation message
    """
    if target_id not in _targets:
        raise HTTPException(
            status_code=404,
            detail=f"Target not found: {target_id}"
        )
    
    # Remove target
    del _targets[target_id]
    
    # Remove session associations
    if target_id in _target_sessions:
        del _target_sessions[target_id]
    
    return {"message": f"Target {target_id} deleted"}


def add_session_to_target(target_id: str, session_id: str) -> bool:
    """
    Associate a session with a target.
    
    Args:
        target_id: Target ID
        session_id: Session ID to associate
        
    Returns:
        True if successful, False if target not found
    """
    if target_id not in _targets:
        return False
    
    if target_id not in _target_sessions:
        _target_sessions[target_id] = []
    
    if session_id not in _target_sessions[target_id]:
        _target_sessions[target_id].append(session_id)
    
    return True


def get_sessions_for_target(target_id: str) -> List[str]:
    """
    Get all session IDs for a target.
    
    Args:
        target_id: Target ID
        
    Returns:
        List of session IDs
    """
    return _target_sessions.get(target_id, [])

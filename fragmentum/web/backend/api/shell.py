"""
Interactive Shell API endpoints.

Provides endpoints for executing arbitrary shell commands.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel

from fragmentum.web.backend.api.auth import get_api_key
from fragmentum.web.backend.jobs.manager import get_job_manager
from fragmentum.web.backend.models.schemas import JobStatus

router = APIRouter(prefix="/shell", tags=["shell"])


class ShellExecuteRequest(BaseModel):
    """Request for shell command execution."""
    command: str
    timeout: int = 180


class ShellExecuteResponse(BaseModel):
    """Response for shell command execution."""
    job_id: str
    status: str


@router.post(
    "/execute",
    response_model=ShellExecuteResponse,
    summary="Execute shell command",
    description="Execute an arbitrary shell command and return job ID for tracking"
)
async def execute_shell_command(
    request: ShellExecuteRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(get_api_key)
) -> ShellExecuteResponse:
    """
    Execute a shell command asynchronously.
    
    Args:
        request: Shell execution request with command
        background_tasks: FastAPI background tasks
        api_key: Validated API key
        
    Returns:
        ShellExecuteResponse with job_id for tracking
    """
    if not request.command.strip():
        raise HTTPException(
            status_code=400,
            detail="Command cannot be empty"
        )
    
    # Create job using the shell tool
    job_manager = get_job_manager()
    job = job_manager.create_job(
        tool_name="shell",
        parameters={"timeout": request.timeout},
        custom_command=request.command
    )
    
    # Start execution in background
    background_tasks.add_task(job_manager.execute_shell_job, job.id, request.command, request.timeout)
    
    return ShellExecuteResponse(
        job_id=job.id,
        status=job.status.value
    )

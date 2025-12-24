"""
Tool execution API endpoints.

Requirements:
- 2.2: Validate required parameters before sending
- 2.4: Display final result and parsed findings
- 8.2: Return job ID for status tracking
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks

from fragmentum.web.backend.models.schemas import (
    ExecuteRequest,
    ExecuteResponse,
    JobStatusResponse,
    FindingResponse,
    JobStatus,
    ErrorResponse,
    ParameterSchema,
)
from fragmentum.web.backend.jobs.manager import get_job_manager
from fragmentum.web.backend.api.auth import get_api_key
from fragmentum.tools.registry import get_tool_registry

router = APIRouter(prefix="/execute", tags=["execute"])


def validate_tool_parameters(
    tool_name: str,
    parameters: dict
) -> tuple[bool, Optional[str]]:
    """
    Validate tool parameters against schema.
    
    Requirements 2.2: Validate required parameters before sending.
    
    Args:
        tool_name: Name of the tool
        parameters: Parameters to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    registry = get_tool_registry()
    tool = registry.get(tool_name)
    
    if not tool:
        return False, f"Tool not found: {tool_name}"
    
    # Check if target is required and provided
    if "{target}" in tool.command or "{TARGET}" in tool.command:
        if "target" not in parameters or not parameters["target"]:
            return False, "Required parameter 'target' is missing"
    
    # Validate parameter types (basic validation)
    for param_name, param_value in parameters.items():
        if param_value is None:
            continue
        
        # Check for empty required strings
        if isinstance(param_value, str) and not param_value.strip():
            if param_name == "target":
                return False, f"Parameter '{param_name}' cannot be empty"
    
    return True, None


@router.post(
    "",
    response_model=ExecuteResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Execute a tool",
    description="Execute a tool and return job ID for tracking - Requirements 2.2, 8.2"
)
async def execute_tool(
    request: ExecuteRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(get_api_key)
) -> ExecuteResponse:
    """
    Execute a tool asynchronously.
    
    Requirements:
    - 2.2: Validate required parameters before sending
    - 8.2: Return job ID for status tracking
    
    Args:
        request: Execution request with tool name and parameters
        background_tasks: FastAPI background tasks
        api_key: Validated API key
        
    Returns:
        ExecuteResponse with job_id for tracking
    """
    # Validate tool exists
    registry = get_tool_registry()
    tool = registry.get(request.tool)
    
    if not tool:
        raise HTTPException(
            status_code=404,
            detail=f"Tool not found: {request.tool}"
        )
    
    # Validate parameters - Requirements 2.2
    is_valid, error_msg = validate_tool_parameters(
        request.tool,
        request.parameters
    )
    
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=error_msg
        )
    
    # Create job - Requirements 8.2
    job_manager = get_job_manager()
    job = job_manager.create_job(
        tool_name=request.tool,
        parameters=request.parameters,
        target_id=request.target_id,
        custom_command=request.custom_command
    )
    
    # Start execution in background
    background_tasks.add_task(job_manager.execute_job, job.id)
    
    return ExecuteResponse(
        job_id=job.id,
        status=job.status,
        started_at=job.started_at
    )


@router.get(
    "/{job_id}",
    response_model=JobStatusResponse,
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Get job status",
    description="Get execution status, output, and findings - Requirements 2.4"
)
async def get_job_status(
    job_id: str,
    api_key: str = Depends(get_api_key)
) -> JobStatusResponse:
    """
    Get job execution status.
    
    Requirements 2.4: Display final result and parsed findings.
    
    Args:
        job_id: The job ID to check
        api_key: Validated API key
        
    Returns:
        JobStatusResponse with status, output, and findings
    """
    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)
    
    if not job:
        raise HTTPException(
            status_code=404,
            detail=f"Job not found: {job_id}"
        )
    
    # Convert findings to response format
    finding_responses = [
        FindingResponse(
            id=f.id,
            type=f.type,
            value=f.value,
            severity=f.severity,
            source=f.source,
            target=f.target,
            timestamp=f.timestamp,
            details=f.details
        )
        for f in job.findings
    ]
    
    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        output=job.output,
        started_at=job.started_at,
        completed_at=job.completed_at,
        findings=finding_responses
    )


@router.delete(
    "/{job_id}",
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Cancel a job",
    description="Cancel a running job"
)
async def cancel_job(
    job_id: str,
    api_key: str = Depends(get_api_key)
) -> dict:
    """
    Cancel a running job.
    
    Args:
        job_id: The job ID to cancel
        api_key: Validated API key
        
    Returns:
        Confirmation message
    """
    job_manager = get_job_manager()
    job = job_manager.get_job(job_id)
    
    if not job:
        raise HTTPException(
            status_code=404,
            detail=f"Job not found: {job_id}"
        )
    
    if job.status not in [JobStatus.PENDING, JobStatus.RUNNING]:
        raise HTTPException(
            status_code=400,
            detail=f"Job cannot be cancelled: status is {job.status}"
        )
    
    # Mark as error (cancelled)
    job.status = JobStatus.ERROR
    job.output = "Job cancelled by user"
    
    return {"message": f"Job {job_id} cancelled"}

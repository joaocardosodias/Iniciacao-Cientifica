"""
WebSocket route handlers.

Requirements:
- 2.1: Open web-based terminal interface
- 2.2: Send commands to remote shell via WebSocket
- 2.3: Display real-time output via WebSocket streaming
- 2.4: Transmit appropriate escape sequences for special keys
- 4.4: Support terminal resize events
- 7.1: Display toast notification for critical/high findings
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import Optional

from fragmentum.web.backend.websocket.hub import get_websocket_hub
from fragmentum.web.backend.websocket.shell_handler import get_shell_connection_manager
from fragmentum.web.backend.jobs.manager import get_job_manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/stream/{job_id}")
async def websocket_job_stream(
    websocket: WebSocket,
    job_id: str,
    token: Optional[str] = Query(None)
) -> None:
    """
    WebSocket endpoint for streaming job output.
    
    Requirements 2.3: Display real-time output via WebSocket streaming.
    
    Args:
        websocket: The WebSocket connection
        job_id: The job ID to stream
        token: Optional API token for authentication
    """
    hub = get_websocket_hub()
    job_manager = get_job_manager()
    
    # Verify job exists
    job = job_manager.get_job(job_id)
    if not job:
        await websocket.close(code=4004, reason="Job not found")
        return
    
    try:
        # Connect to job stream
        await hub.connect_job_stream(websocket, job_id)
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages (ping/pong, close, etc.)
                data = await websocket.receive_text()
                
                # Handle ping messages
                if data == "ping":
                    await websocket.send_text('{"type": "pong"}')
                    
            except WebSocketDisconnect:
                break
                
    finally:
        await hub.disconnect_job_stream(websocket, job_id)


@router.websocket("/ws/notifications")
async def websocket_notifications(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
) -> None:
    """
    WebSocket endpoint for global notifications.
    
    Requirements 7.1: Display toast notification for critical/high findings.
    
    Args:
        websocket: The WebSocket connection
        token: Optional API token for authentication
    """
    hub = get_websocket_hub()
    
    try:
        # Connect to notifications
        await hub.connect_notifications(websocket)
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Wait for messages (ping/pong, close, etc.)
                data = await websocket.receive_text()
                
                # Handle ping messages
                if data == "ping":
                    await websocket.send_text('{"type": "pong"}')
                    
            except WebSocketDisconnect:
                break
                
    finally:
        await hub.disconnect_notifications(websocket)


@router.websocket("/ws/shell/{shell_id}")
async def websocket_shell_terminal(
    websocket: WebSocket,
    shell_id: str,
    token: Optional[str] = Query(None)
) -> None:
    """
    WebSocket endpoint for shell terminal interaction.
    
    Requirements 2.1: Open web-based terminal interface.
    Requirements 2.2: Send commands to remote shell via WebSocket.
    Requirements 2.3: Display output in terminal in real-time.
    Requirements 2.4: Transmit appropriate escape sequences for special keys.
    Requirements 4.4: Support terminal resize events.
    
    Message format (JSON):
    - Input: {"type": "input", "data": "command text"}
    - Special key: {"type": "special_key", "data": "ctrl+c"}
    - Resize: {"type": "resize", "data": {"cols": 80, "rows": 24}}
    
    Response format (JSON):
    - Output: {"type": "output", "data": {"output": "..."}, "shell_id": "..."}
    - Status: {"type": "status", "data": {"status": "connected", "is_pty": false}}
    - Error: {"type": "error", "data": {"error": "..."}}
    
    Args:
        websocket: The WebSocket connection
        shell_id: The shell ID to connect to
        token: Optional API token for authentication
    """
    connection_manager = get_shell_connection_manager()
    
    # Try to establish connection
    handler = await connection_manager.connect(websocket, shell_id)
    
    if not handler:
        # Connection failed (shell not found or disconnected)
        # The handler already closed the websocket with appropriate code
        return
    
    try:
        # Handle the connection lifecycle
        await handler.handle_connection()
    finally:
        # Clean up
        await connection_manager.disconnect(shell_id)

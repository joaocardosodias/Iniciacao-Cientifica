"""
WebSocket Hub for real-time streaming and updates.

Requirements:
- 2.3: Display real-time output via WebSocket streaming
- 7.1: Display toast notification for critical/high findings
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Set, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from fastapi import WebSocket, WebSocketDisconnect


class MessageType(str, Enum):
    """WebSocket message types."""
    OUTPUT = "output"
    STATUS = "status"
    FINDING = "finding"
    ERROR = "error"
    CONNECTED = "connected"
    HEARTBEAT = "heartbeat"


@dataclass
class WebSocketMessage:
    """WebSocket message structure."""
    type: MessageType
    data: Any
    timestamp: datetime = field(default_factory=datetime.utcnow)
    job_id: Optional[str] = None
    
    def to_json(self) -> str:
        """Convert message to JSON string."""
        return json.dumps({
            "type": self.type.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "job_id": self.job_id,
        })


class WebSocketHub:
    """
    Central hub for managing WebSocket connections and broadcasting.
    
    Requirements:
    - 2.3: Display real-time output via WebSocket streaming
    - 7.1: Display toast notification for critical/high findings
    
    Implements:
    - /ws/stream/{job_id} for tool output streaming
    - /ws/notifications for global notifications
    """
    
    def __init__(self):
        # Job-specific connections: job_id -> set of websockets
        self._job_connections: Dict[str, Set[WebSocket]] = {}
        # Global notification connections
        self._notification_connections: Set[WebSocket] = set()
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()
        # Output buffers for jobs (for late joiners)
        self._output_buffers: Dict[str, str] = {}
        # Heartbeat interval in seconds
        self._heartbeat_interval = 30

    async def connect_job_stream(
        self,
        websocket: WebSocket,
        job_id: str
    ) -> None:
        """
        Connect a WebSocket to a job's output stream.
        
        Requirements 2.3: Display real-time output via WebSocket streaming.
        
        Args:
            websocket: The WebSocket connection
            job_id: The job ID to stream
        """
        await websocket.accept()
        
        async with self._lock:
            if job_id not in self._job_connections:
                self._job_connections[job_id] = set()
            self._job_connections[job_id].add(websocket)
        
        # Send connection confirmation
        await self._send_message(
            websocket,
            WebSocketMessage(
                type=MessageType.CONNECTED,
                data={"job_id": job_id, "message": "Connected to job stream"},
                job_id=job_id
            )
        )
        
        # Send buffered output if available
        if job_id in self._output_buffers:
            await self._send_message(
                websocket,
                WebSocketMessage(
                    type=MessageType.OUTPUT,
                    data={"output": self._output_buffers[job_id]},
                    job_id=job_id
                )
            )
    
    async def disconnect_job_stream(
        self,
        websocket: WebSocket,
        job_id: str
    ) -> None:
        """
        Disconnect a WebSocket from a job's output stream.
        
        Args:
            websocket: The WebSocket connection
            job_id: The job ID
        """
        async with self._lock:
            if job_id in self._job_connections:
                self._job_connections[job_id].discard(websocket)
                if not self._job_connections[job_id]:
                    del self._job_connections[job_id]
    
    async def connect_notifications(self, websocket: WebSocket) -> None:
        """
        Connect a WebSocket to global notifications.
        
        Requirements 7.1: Display toast notification for critical/high findings.
        
        Args:
            websocket: The WebSocket connection
        """
        await websocket.accept()
        
        async with self._lock:
            self._notification_connections.add(websocket)
        
        # Send connection confirmation
        await self._send_message(
            websocket,
            WebSocketMessage(
                type=MessageType.CONNECTED,
                data={"message": "Connected to notifications"}
            )
        )
    
    async def disconnect_notifications(self, websocket: WebSocket) -> None:
        """
        Disconnect a WebSocket from global notifications.
        
        Args:
            websocket: The WebSocket connection
        """
        async with self._lock:
            self._notification_connections.discard(websocket)

    async def broadcast_job_output(
        self,
        job_id: str,
        output: str,
        append: bool = True
    ) -> None:
        """
        Broadcast output to all connections watching a job.
        
        Requirements 2.3: Display real-time output via WebSocket streaming.
        
        Args:
            job_id: The job ID
            output: The output text
            append: Whether to append to buffer or replace
        """
        # Update buffer
        if append:
            if job_id not in self._output_buffers:
                self._output_buffers[job_id] = ""
            self._output_buffers[job_id] += output
        else:
            self._output_buffers[job_id] = output
        
        # Broadcast to connected clients
        message = WebSocketMessage(
            type=MessageType.OUTPUT,
            data={"output": output, "append": append},
            job_id=job_id
        )
        
        await self._broadcast_to_job(job_id, message)
    
    async def broadcast_job_status(
        self,
        job_id: str,
        status: str,
        completed_at: Optional[datetime] = None
    ) -> None:
        """
        Broadcast job status change.
        
        Args:
            job_id: The job ID
            status: The new status
            completed_at: Completion timestamp if applicable
        """
        message = WebSocketMessage(
            type=MessageType.STATUS,
            data={
                "status": status,
                "completed_at": completed_at.isoformat() if completed_at else None
            },
            job_id=job_id
        )
        
        await self._broadcast_to_job(job_id, message)
    
    async def broadcast_finding(
        self,
        job_id: str,
        finding: Dict[str, Any]
    ) -> None:
        """
        Broadcast a new finding to job watchers.
        
        Args:
            job_id: The job ID
            finding: The finding data
        """
        message = WebSocketMessage(
            type=MessageType.FINDING,
            data=finding,
            job_id=job_id
        )
        
        await self._broadcast_to_job(job_id, message)
    
    async def broadcast_notification(
        self,
        notification: Dict[str, Any]
    ) -> None:
        """
        Broadcast a notification to all notification subscribers.
        
        Requirements 7.1: Display toast notification for critical/high findings.
        
        Args:
            notification: The notification data
        """
        message = WebSocketMessage(
            type=MessageType.FINDING,
            data=notification
        )
        
        await self._broadcast_to_notifications(message)

    async def broadcast_error(
        self,
        job_id: str,
        error: str
    ) -> None:
        """
        Broadcast an error to job watchers.
        
        Args:
            job_id: The job ID
            error: The error message
        """
        message = WebSocketMessage(
            type=MessageType.ERROR,
            data={"error": error},
            job_id=job_id
        )
        
        await self._broadcast_to_job(job_id, message)
    
    async def _broadcast_to_job(
        self,
        job_id: str,
        message: WebSocketMessage
    ) -> None:
        """
        Broadcast a message to all connections watching a job.
        
        Args:
            job_id: The job ID
            message: The message to broadcast
        """
        async with self._lock:
            connections = self._job_connections.get(job_id, set()).copy()
        
        disconnected = []
        for websocket in connections:
            try:
                await self._send_message(websocket, message)
            except Exception:
                disconnected.append(websocket)
        
        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    if job_id in self._job_connections:
                        self._job_connections[job_id].discard(ws)
    
    async def _broadcast_to_notifications(
        self,
        message: WebSocketMessage
    ) -> None:
        """
        Broadcast a message to all notification subscribers.
        
        Args:
            message: The message to broadcast
        """
        async with self._lock:
            connections = self._notification_connections.copy()
        
        disconnected = []
        for websocket in connections:
            try:
                await self._send_message(websocket, message)
            except Exception:
                disconnected.append(websocket)
        
        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    self._notification_connections.discard(ws)
    
    async def _send_message(
        self,
        websocket: WebSocket,
        message: WebSocketMessage
    ) -> None:
        """
        Send a message to a WebSocket.
        
        Args:
            websocket: The WebSocket connection
            message: The message to send
        """
        await websocket.send_text(message.to_json())
    
    def clear_job_buffer(self, job_id: str) -> None:
        """
        Clear the output buffer for a job.
        
        Args:
            job_id: The job ID
        """
        if job_id in self._output_buffers:
            del self._output_buffers[job_id]
    
    def get_job_connection_count(self, job_id: str) -> int:
        """Get the number of connections watching a job."""
        return len(self._job_connections.get(job_id, set()))
    
    def get_notification_connection_count(self) -> int:
        """Get the number of notification subscribers."""
        return len(self._notification_connections)


# Global WebSocket hub instance
_websocket_hub: Optional[WebSocketHub] = None


def get_websocket_hub() -> WebSocketHub:
    """Get the global WebSocket hub instance."""
    global _websocket_hub
    if _websocket_hub is None:
        _websocket_hub = WebSocketHub()
    return _websocket_hub

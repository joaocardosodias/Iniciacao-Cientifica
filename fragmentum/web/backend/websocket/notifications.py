"""
Notification system for real-time alerts.

Requirements:
- 7.1: Display toast notification for critical/high findings
- 7.2: Notify user when Swarm attack completes with summary
- 7.3: Display error notification when tool execution fails
"""

import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum


class NotificationType(str, Enum):
    """Types of notifications."""
    FINDING_CRITICAL = "finding_critical"
    FINDING_HIGH = "finding_high"
    SESSION_COMPLETE = "session_complete"
    SWARM_COMPLETE = "swarm_complete"
    EXECUTION_ERROR = "execution_error"
    INFO = "info"


@dataclass
class NotificationEvent:
    """
    Notification event structure.
    
    Requirements:
    - 7.1: Display toast notification for critical/high findings
    - 7.2: Notify user when Swarm attack completes with summary
    - 7.3: Display error notification when tool execution fails
    """
    type: NotificationType
    title: str
    message: str
    severity: str = "info"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert notification to dictionary."""
        return {
            "type": self.type.value,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


class NotificationManager:
    """
    Manages notification creation and broadcasting.
    
    Requirements:
    - 7.1: Display toast notification for critical/high findings
    - 7.2: Notify user when Swarm attack completes with summary
    - 7.3: Display error notification when tool execution fails
    """
    
    def __init__(self):
        self._websocket_hub = None
        self._notification_history: List[NotificationEvent] = []
        self._max_history = 100

    def set_websocket_hub(self, hub) -> None:
        """Set the WebSocket hub for broadcasting."""
        self._websocket_hub = hub
    
    async def notify_critical_finding(
        self,
        finding: Dict[str, Any],
        target: str,
        source: str
    ) -> NotificationEvent:
        """
        Create and broadcast notification for critical finding.
        
        Requirements 7.1: Display toast notification for critical/high findings.
        
        Args:
            finding: The finding data
            target: The target that was scanned
            source: The tool that found it
            
        Returns:
            The created notification event
        """
        notification = NotificationEvent(
            type=NotificationType.FINDING_CRITICAL,
            title="Critical Finding Discovered",
            message=f"Critical vulnerability found on {target} by {source}",
            severity="critical",
            data={
                "finding": finding,
                "target": target,
                "source": source,
            }
        )
        
        await self._broadcast_and_store(notification)
        return notification
    
    async def notify_high_finding(
        self,
        finding: Dict[str, Any],
        target: str,
        source: str
    ) -> NotificationEvent:
        """
        Create and broadcast notification for high severity finding.
        
        Requirements 7.1: Display toast notification for critical/high findings.
        
        Args:
            finding: The finding data
            target: The target that was scanned
            source: The tool that found it
            
        Returns:
            The created notification event
        """
        notification = NotificationEvent(
            type=NotificationType.FINDING_HIGH,
            title="High Severity Finding",
            message=f"High severity issue found on {target} by {source}",
            severity="high",
            data={
                "finding": finding,
                "target": target,
                "source": source,
            }
        )
        
        await self._broadcast_and_store(notification)
        return notification
    
    async def notify_session_complete(
        self,
        session_id: str,
        target: str,
        finding_count: int,
        duration_seconds: float
    ) -> NotificationEvent:
        """
        Create and broadcast notification for session completion.
        
        Requirements 7.2: Notify user when Swarm attack completes with summary.
        
        Args:
            session_id: The session ID
            target: The target that was scanned
            finding_count: Number of findings discovered
            duration_seconds: Session duration
            
        Returns:
            The created notification event
        """
        notification = NotificationEvent(
            type=NotificationType.SESSION_COMPLETE,
            title="Session Complete",
            message=f"Scan of {target} completed with {finding_count} findings",
            severity="info",
            data={
                "session_id": session_id,
                "target": target,
                "finding_count": finding_count,
                "duration_seconds": duration_seconds,
            }
        )
        
        await self._broadcast_and_store(notification)
        return notification

    async def notify_swarm_complete(
        self,
        session_id: str,
        target: str,
        agents_completed: int,
        total_findings: int,
        findings_by_severity: Dict[str, int],
        duration_seconds: float
    ) -> NotificationEvent:
        """
        Create and broadcast notification for Swarm attack completion.
        
        Requirements 7.2: Notify user when Swarm attack completes with summary.
        
        Args:
            session_id: The session ID
            target: The target that was attacked
            agents_completed: Number of agents that completed
            total_findings: Total findings discovered
            findings_by_severity: Findings grouped by severity
            duration_seconds: Attack duration
            
        Returns:
            The created notification event
        """
        # Build summary message
        summary_parts = []
        if findings_by_severity.get("critical", 0) > 0:
            summary_parts.append(f"{findings_by_severity['critical']} critical")
        if findings_by_severity.get("high", 0) > 0:
            summary_parts.append(f"{findings_by_severity['high']} high")
        
        severity_summary = ", ".join(summary_parts) if summary_parts else "no critical issues"
        
        notification = NotificationEvent(
            type=NotificationType.SWARM_COMPLETE,
            title="Swarm Attack Complete",
            message=f"Attack on {target} finished: {total_findings} findings ({severity_summary})",
            severity="info" if not summary_parts else "warning",
            data={
                "session_id": session_id,
                "target": target,
                "agents_completed": agents_completed,
                "total_findings": total_findings,
                "findings_by_severity": findings_by_severity,
                "duration_seconds": duration_seconds,
            }
        )
        
        await self._broadcast_and_store(notification)
        return notification
    
    async def notify_execution_error(
        self,
        job_id: str,
        tool_name: str,
        error_message: str,
        target: Optional[str] = None
    ) -> NotificationEvent:
        """
        Create and broadcast notification for execution error.
        
        Requirements 7.3: Display error notification when tool execution fails.
        
        Args:
            job_id: The job ID that failed
            tool_name: The tool that failed
            error_message: The error message
            target: Optional target that was being scanned
            
        Returns:
            The created notification event
        """
        notification = NotificationEvent(
            type=NotificationType.EXECUTION_ERROR,
            title="Execution Failed",
            message=f"{tool_name} failed: {error_message[:100]}",
            severity="error",
            data={
                "job_id": job_id,
                "tool_name": tool_name,
                "error_message": error_message,
                "target": target,
            }
        )
        
        await self._broadcast_and_store(notification)
        return notification
    
    async def notify_finding(
        self,
        finding: Dict[str, Any],
        target: str,
        source: str
    ) -> Optional[NotificationEvent]:
        """
        Create notification for a finding based on its severity.
        
        Requirements 7.1: Display toast notification for critical/high findings.
        
        Only creates notifications for critical and high severity findings.
        
        Args:
            finding: The finding data
            target: The target that was scanned
            source: The tool that found it
            
        Returns:
            The created notification event, or None if severity doesn't warrant notification
        """
        severity = finding.get("severity", "info").lower()
        
        if severity == "critical":
            return await self.notify_critical_finding(finding, target, source)
        elif severity == "high":
            return await self.notify_high_finding(finding, target, source)
        
        # No notification for medium, low, info severities
        return None

    async def _broadcast_and_store(
        self,
        notification: NotificationEvent
    ) -> None:
        """
        Broadcast notification and store in history.
        
        Args:
            notification: The notification to broadcast
        """
        # Store in history
        self._notification_history.append(notification)
        
        # Trim history if needed
        if len(self._notification_history) > self._max_history:
            self._notification_history = self._notification_history[-self._max_history:]
        
        # Broadcast via WebSocket hub
        if self._websocket_hub:
            await self._websocket_hub.broadcast_notification(notification.to_dict())
    
    def get_recent_notifications(
        self,
        limit: int = 20,
        notification_type: Optional[NotificationType] = None
    ) -> List[NotificationEvent]:
        """
        Get recent notifications from history.
        
        Args:
            limit: Maximum number of notifications to return
            notification_type: Optional filter by type
            
        Returns:
            List of recent notifications
        """
        notifications = self._notification_history
        
        if notification_type:
            notifications = [n for n in notifications if n.type == notification_type]
        
        # Return most recent first
        return list(reversed(notifications[-limit:]))
    
    def clear_history(self) -> None:
        """Clear notification history."""
        self._notification_history.clear()


# Global notification manager instance
_notification_manager: Optional[NotificationManager] = None


def get_notification_manager() -> NotificationManager:
    """Get the global notification manager instance."""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager

"""
Notification API endpoints.

Requirements:
- 7.1: Display toast notification for critical/high findings
- 7.2: Notify user when Swarm attack completes with summary
- 7.3: Display error notification when tool execution fails
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, Query

from fragmentum.web.backend.websocket.notifications import (
    get_notification_manager,
    NotificationType,
    NotificationEvent,
)
from fragmentum.web.backend.api.auth import get_api_key
from pydantic import BaseModel
from datetime import datetime
from typing import Dict, Any


class NotificationResponse(BaseModel):
    """Response model for notifications."""
    type: str
    title: str
    message: str
    severity: str
    timestamp: datetime
    data: Dict[str, Any]


class NotificationListResponse(BaseModel):
    """Response model for notification list."""
    notifications: List[NotificationResponse]
    total: int


router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get(
    "",
    response_model=NotificationListResponse,
    summary="Get recent notifications",
    description="Get recent notifications from history - Requirements 7.1, 7.2, 7.3"
)
async def get_notifications(
    limit: int = Query(default=20, ge=1, le=100),
    notification_type: Optional[str] = Query(default=None),
    api_key: str = Depends(get_api_key)
) -> NotificationListResponse:
    """
    Get recent notifications.
    
    Args:
        limit: Maximum number of notifications to return
        notification_type: Optional filter by notification type
        api_key: Validated API key
        
    Returns:
        List of recent notifications
    """
    manager = get_notification_manager()
    
    # Convert string type to enum if provided
    type_filter = None
    if notification_type:
        try:
            type_filter = NotificationType(notification_type)
        except ValueError:
            pass
    
    notifications = manager.get_recent_notifications(
        limit=limit,
        notification_type=type_filter
    )
    
    return NotificationListResponse(
        notifications=[
            NotificationResponse(
                type=n.type.value,
                title=n.title,
                message=n.message,
                severity=n.severity,
                timestamp=n.timestamp,
                data=n.data
            )
            for n in notifications
        ],
        total=len(notifications)
    )


@router.delete(
    "",
    summary="Clear notification history",
    description="Clear all notifications from history"
)
async def clear_notifications(
    api_key: str = Depends(get_api_key)
) -> dict:
    """
    Clear notification history.
    
    Args:
        api_key: Validated API key
        
    Returns:
        Confirmation message
    """
    manager = get_notification_manager()
    manager.clear_history()
    
    return {"message": "Notification history cleared"}

"""API routes package."""

from fastapi import APIRouter, Depends

from fragmentum.web.backend.api.tools import router as tools_router
from fragmentum.web.backend.api.execute import router as execute_router
from fragmentum.web.backend.api.notifications import router as notifications_router
from fragmentum.web.backend.api.targets import router as targets_router
from fragmentum.web.backend.api.sessions import router as sessions_router
from fragmentum.web.backend.api.swarm import router as swarm_router
from fragmentum.web.backend.api.dashboard import router as dashboard_router
from fragmentum.web.backend.api.chat import router as chat_router
from fragmentum.web.backend.api.shell import router as shell_router
from fragmentum.web.backend.api.shells import router as shells_router
from fragmentum.web.backend.api.auth import get_api_key, optional_api_key

router = APIRouter()


@router.get("/")
async def api_root():
    """API root endpoint."""
    return {
        "name": "FRAGMENTUM Web API",
        "version": "2.0.0",
        "endpoints": {
            "tools": "/api/tools",
            "targets": "/api/targets",
            "sessions": "/api/sessions",
            "execute": "/api/execute",
            "notifications": "/api/notifications",
            "swarm": "/api/swarm",
            "dashboard": "/api/dashboard",
            "chat": "/api/chat",
            "shell": "/api/shell",
            "shells": "/api/shells"
        }
    }


# Include sub-routers
router.include_router(tools_router)
router.include_router(execute_router)
router.include_router(notifications_router)
router.include_router(targets_router)
router.include_router(sessions_router)
router.include_router(swarm_router)
router.include_router(dashboard_router)
router.include_router(chat_router)
router.include_router(shell_router)
router.include_router(shells_router)

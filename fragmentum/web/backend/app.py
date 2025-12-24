"""
FRAGMENTUM Web Backend - FastAPI Application

Main application entry point with CORS and middleware configuration.

Requirements:
- 2.3: Display real-time output via WebSocket streaming
- 7.1: Display toast notification for critical/high findings
- 8.4: Return appropriate HTTP status codes and error messages
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).resolve().parents[3] / ".env"
if env_path.exists():
    load_dotenv(env_path)

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
from typing import Callable

from fragmentum.web.backend.api import router as api_router
from fragmentum.web.backend.websocket.routes import router as ws_router
from fragmentum.web.backend.websocket.hub import get_websocket_hub
from fragmentum.web.backend.websocket.notifications import get_notification_manager
from fragmentum.web.backend.jobs.manager import get_job_manager
from fragmentum.web.backend.middleware import setup_error_handlers


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="FRAGMENTUM Web API",
        description="REST API for FRAGMENTUM pentesting framework",
        version="2.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json"
    )
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next: Callable):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response
    
    # Include API routes
    app.include_router(api_router, prefix="/api")
    
    # Include WebSocket routes
    app.include_router(ws_router)
    
    # Setup global error handlers - Requirements 8.4
    setup_error_handlers(app)
    
    # Wire up notification manager with WebSocket hub
    notification_manager = get_notification_manager()
    websocket_hub = get_websocket_hub()
    notification_manager.set_websocket_hub(websocket_hub)
    
    # Wire up job manager with WebSocket hub and notification manager
    job_manager = get_job_manager()
    job_manager.set_websocket_hub(websocket_hub)
    job_manager.set_notification_manager(notification_manager)
    
    # Health check endpoint
    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "service": "fragmentum-web",
            "websocket_connections": {
                "notifications": websocket_hub.get_notification_connection_count()
            }
        }
    
    return app


# Create the application instance
app = create_app()

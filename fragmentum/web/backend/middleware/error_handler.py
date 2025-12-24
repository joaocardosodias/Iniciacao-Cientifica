"""
Global error handling middleware for FRAGMENTUM Web API.

Requirements:
- 8.4: Return appropriate HTTP status codes and error messages

This module implements a centralized error handling system that:
1. Catches all unhandled exceptions
2. Returns consistent JSON error responses
3. Maps exceptions to appropriate HTTP status codes
"""

import logging
import traceback
from typing import Optional, Union, Callable
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError as PydanticValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class FragmentumAPIError(Exception):
    """Base exception for FRAGMENTUM API errors.
    
    All custom API exceptions should inherit from this class.
    """
    
    def __init__(
        self,
        message: str,
        status_code: int = 500,
        details: Optional[str] = None
    ):
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(self.message)


class ValidationError(FragmentumAPIError):
    """Raised when request validation fails.
    
    HTTP Status: 400 Bad Request
    """
    
    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(message, status_code=400, details=details)


class NotFoundError(FragmentumAPIError):
    """Raised when a requested resource is not found.
    
    HTTP Status: 404 Not Found
    """
    
    def __init__(self, resource: str, identifier: str):
        message = f"{resource} not found: {identifier}"
        super().__init__(message, status_code=404)


class AuthenticationError(FragmentumAPIError):
    """Raised when authentication fails.
    
    HTTP Status: 401 Unauthorized
    """
    
    def __init__(self, message: str = "Invalid or missing API token"):
        super().__init__(message, status_code=401)


class ExecutionError(FragmentumAPIError):
    """Raised when tool execution fails.
    
    HTTP Status: 500 Internal Server Error
    """
    
    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(
            f"Execution failed: {message}",
            status_code=500,
            details=details
        )


class TimeoutError(FragmentumAPIError):
    """Raised when an operation times out.
    
    HTTP Status: 504 Gateway Timeout
    """
    
    def __init__(self, seconds: int):
        super().__init__(
            f"Execution timeout after {seconds}s",
            status_code=504
        )


def create_error_response(
    status_code: int,
    error: str,
    details: Optional[str] = None
) -> JSONResponse:
    """Create a standardized JSON error response.
    
    Requirements 8.4: Return appropriate HTTP status codes and error messages.
    
    Args:
        status_code: HTTP status code
        error: Error message
        details: Optional additional details
        
    Returns:
        JSONResponse with error information
    """
    content = {"error": error}
    if details:
        content["details"] = details
    
    return JSONResponse(
        status_code=status_code,
        content=content
    )


async def fragmentum_exception_handler(
    request: Request,
    exc: FragmentumAPIError
) -> JSONResponse:
    """Handle FragmentumAPIError exceptions.
    
    Args:
        request: The incoming request
        exc: The FragmentumAPIError exception
        
    Returns:
        JSONResponse with error details
    """
    logger.warning(
        f"API Error: {exc.message} (status={exc.status_code}, path={request.url.path})"
    )
    return create_error_response(
        status_code=exc.status_code,
        error=exc.message,
        details=exc.details
    )


async def http_exception_handler(
    request: Request,
    exc: Union[HTTPException, StarletteHTTPException]
) -> JSONResponse:
    """Handle FastAPI/Starlette HTTPException.
    
    Args:
        request: The incoming request
        exc: The HTTPException
        
    Returns:
        JSONResponse with error details
    """
    logger.warning(
        f"HTTP Exception: {exc.detail} (status={exc.status_code}, path={request.url.path})"
    )
    return create_error_response(
        status_code=exc.status_code,
        error=str(exc.detail)
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
) -> JSONResponse:
    """Handle Pydantic validation errors from request parsing.
    
    Args:
        request: The incoming request
        exc: The RequestValidationError
        
    Returns:
        JSONResponse with validation error details
    """
    errors = exc.errors()
    
    # Format validation errors into a readable message
    error_messages = []
    for error in errors:
        loc = " -> ".join(str(l) for l in error.get("loc", []))
        msg = error.get("msg", "Invalid value")
        error_messages.append(f"{loc}: {msg}")
    
    details = "; ".join(error_messages)
    
    logger.warning(
        f"Validation Error: {details} (path={request.url.path})"
    )
    
    return create_error_response(
        status_code=400,
        error="Invalid request parameters",
        details=details
    )


async def pydantic_validation_handler(
    request: Request,
    exc: PydanticValidationError
) -> JSONResponse:
    """Handle Pydantic ValidationError.
    
    Args:
        request: The incoming request
        exc: The PydanticValidationError
        
    Returns:
        JSONResponse with validation error details
    """
    errors = exc.errors()
    
    error_messages = []
    for error in errors:
        loc = " -> ".join(str(l) for l in error.get("loc", []))
        msg = error.get("msg", "Invalid value")
        error_messages.append(f"{loc}: {msg}")
    
    details = "; ".join(error_messages)
    
    logger.warning(
        f"Pydantic Validation Error: {details} (path={request.url.path})"
    )
    
    return create_error_response(
        status_code=400,
        error="Data validation failed",
        details=details
    )


async def generic_exception_handler(
    request: Request,
    exc: Exception
) -> JSONResponse:
    """Handle any unhandled exceptions.
    
    This is the catch-all handler for unexpected errors.
    
    Args:
        request: The incoming request
        exc: The unhandled exception
        
    Returns:
        JSONResponse with generic error message
    """
    # Log the full traceback for debugging
    logger.error(
        f"Unhandled Exception: {type(exc).__name__}: {str(exc)} "
        f"(path={request.url.path})\n{traceback.format_exc()}"
    )
    
    # Return a generic error message (don't expose internal details)
    return create_error_response(
        status_code=500,
        error="Internal server error",
        details=str(exc) if logger.isEnabledFor(logging.DEBUG) else None
    )


def setup_error_handlers(app: FastAPI) -> None:
    """Register all error handlers with the FastAPI application.
    
    Requirements 8.4: Return appropriate HTTP status codes and error messages.
    
    This function sets up a comprehensive error handling system that ensures
    all errors are returned in a consistent JSON format with appropriate
    HTTP status codes.
    
    Error Response Format:
    {
        "error": "Error message",
        "details": "Optional additional details"
    }
    
    Status Code Mapping:
    - 400: Invalid parameters, validation errors
    - 401: Unauthorized (invalid/missing API token)
    - 404: Resource not found
    - 500: Execution failed, internal errors
    - 504: Execution timeout
    
    Args:
        app: The FastAPI application instance
    """
    # Register custom exception handlers
    app.add_exception_handler(FragmentumAPIError, fragmentum_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(PydanticValidationError, pydantic_validation_handler)
    
    # Catch-all for unhandled exceptions
    app.add_exception_handler(Exception, generic_exception_handler)
    
    logger.info("Error handlers registered successfully")

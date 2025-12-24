"""Middleware package for FRAGMENTUM Web Backend."""

from fragmentum.web.backend.middleware.error_handler import (
    setup_error_handlers,
    FragmentumAPIError,
    ValidationError,
    NotFoundError,
    AuthenticationError,
    ExecutionError,
    TimeoutError,
)

__all__ = [
    "setup_error_handlers",
    "FragmentumAPIError",
    "ValidationError",
    "NotFoundError",
    "AuthenticationError",
    "ExecutionError",
    "TimeoutError",
]

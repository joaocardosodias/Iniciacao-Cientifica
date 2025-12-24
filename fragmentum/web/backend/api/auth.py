"""
Authentication middleware and utilities.

Requirements:
- 8.1: API token authentication
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel


# API Key header configuration
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# In-memory token storage (in production, use a database)
_tokens: Dict[str, Dict[str, Any]] = {}

# Default development token (should be configured via environment in production)
DEFAULT_DEV_TOKEN = "fragmentum-dev-token-2024"


class TokenInfo(BaseModel):
    """Token information."""
    token: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    description: str = ""


class TokenResponse(BaseModel):
    """Response for token generation."""
    token: str
    expires_at: Optional[datetime] = None


def generate_token(description: str = "", expires_in_days: Optional[int] = None) -> TokenInfo:
    """Generate a new API token.
    
    Args:
        description: Optional description for the token
        expires_in_days: Optional expiration in days
        
    Returns:
        TokenInfo with the generated token
    """
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    expires_at = None
    
    if expires_in_days:
        expires_at = now + timedelta(days=expires_in_days)
    
    token_info = TokenInfo(
        token=token,
        created_at=now,
        expires_at=expires_at,
        description=description
    )
    
    # Store token hash for validation
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    _tokens[token_hash] = {
        "created_at": now,
        "expires_at": expires_at,
        "description": description
    }
    
    return token_info


def validate_token(token: str) -> bool:
    """Validate an API token.
    
    Args:
        token: The token to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not token:
        return False
    
    # Allow default dev token
    if token == DEFAULT_DEV_TOKEN:
        return True
    
    # Check stored tokens
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    token_data = _tokens.get(token_hash)
    
    if not token_data:
        return False
    
    # Check expiration
    if token_data.get("expires_at"):
        if datetime.utcnow() > token_data["expires_at"]:
            return False
    
    return True


def revoke_token(token: str) -> bool:
    """Revoke an API token.
    
    Args:
        token: The token to revoke
        
    Returns:
        True if revoked, False if not found
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if token_hash in _tokens:
        del _tokens[token_hash]
        return True
    return False


async def get_api_key(
    api_key: Optional[str] = Security(API_KEY_HEADER)
) -> str:
    """Dependency to validate API key from header.
    
    Requirements 8.1: API token authentication.
    
    Raises:
        HTTPException: 401 if token is missing or invalid
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide X-API-Key header."
        )
    
    if not validate_token(api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key."
        )
    
    return api_key


async def optional_api_key(
    api_key: Optional[str] = Security(API_KEY_HEADER)
) -> Optional[str]:
    """Dependency for optional API key validation.
    
    Returns None if no key provided, validates if provided.
    """
    if not api_key:
        return None
    
    if not validate_token(api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key."
        )
    
    return api_key


# List of public endpoints that don't require authentication
PUBLIC_ENDPOINTS = {
    "/health",
    "/api/",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
}


def is_public_endpoint(path: str) -> bool:
    """Check if an endpoint is public (no auth required)."""
    return path in PUBLIC_ENDPOINTS or path.startswith("/api/docs")

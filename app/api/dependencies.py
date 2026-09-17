"""
VaultCore API Dependencies: rate limiter and API-key authentication.
"""

import hmac

from fastapi import Header, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings

# Shared storage (e.g. redis://) is required for correct limits with multiple workers.
limiter = Limiter(key_func=get_remote_address, storage_uri=settings.RATE_LIMIT_STORAGE_URI)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Protect management endpoints (upload, list, delete)."""
    if not settings.API_KEY:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "API key is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key, settings.API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")

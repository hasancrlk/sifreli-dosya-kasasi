"""
VaultCore API Dependencies.

Shared dependencies for route handlers including rate limiting configuration.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate limiter keyed by client IP address
limiter = Limiter(key_func=get_remote_address)

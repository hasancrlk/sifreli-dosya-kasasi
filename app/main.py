"""
VaultCore Application Entry Point.

FastAPI application factory with security middleware, rate limiting,
structured logging, and lifecycle management.
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.dependencies import limiter
from app.api.routes import router as vault_router
from app.config import settings
from app.database import close_db, init_db


# ─── Logging Configuration ───────────────────────────────────────────────────

def setup_logging() -> None:
    """Configure structured logging with security-aware formatting."""
    log_format = (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    logging.basicConfig(
        level=logging.DEBUG if settings.DEBUG else logging.INFO,
        format=log_format,
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Suppress noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.DEBUG else logging.WARNING
    )


setup_logging()
logger = logging.getLogger(__name__)


# ─── Application Lifecycle ───────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle manager: startup and shutdown hooks."""
    logger.info("VaultCore starting up...")
    logger.info("Environment: %s", settings.APP_ENV)
    logger.info("Encrypted files directory: %s", settings.encrypted_files_path)

    # Initialize database tables
    await init_db()
    logger.info("Database initialized")

    yield

    # Cleanup
    await close_db()
    logger.info("VaultCore shut down gracefully")


# ─── Application Factory ────────────────────────────────────────────────────


app = FastAPI(
    title="VaultCore",
    description=(
        "Zero-Knowledge Encrypted File Storage Service. "
        "Files are encrypted with AES-256-GCM using Argon2id-derived keys. "
        "Passwords are NEVER stored — only used transiently for key derivation."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)


# ─── Middleware ──────────────────────────────────────────────────────────────

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS (restrictive by default)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else [],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)

# Security headers middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# ─── Routes ──────────────────────────────────────────────────────────────────

app.include_router(vault_router)


@app.get("/health", tags=["system"])
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return {"status": "healthy", "service": "VaultCore", "version": "1.0.0"}


# ─── Global Exception Handler ────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all exception handler.

    Security: Never expose internal error details in production responses.
    """
    logger.exception("Unhandled exception: %s", type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ─── CLI Entry Point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )

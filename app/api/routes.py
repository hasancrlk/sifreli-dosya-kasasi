"""
VaultCore API Routes.

RESTful endpoints for the encrypted file vault.

Security Design:
    - All error responses use generic messages to prevent information leakage.
    - Rate limiting protects against brute-force password attacks.
    - Passwords are received via form data / JSON body (NOT URL parameters).
    - No sensitive data (passwords, keys, salts, nonces) appears in response bodies.
    - Timing-safe operations prevent side-channel attacks.
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import limiter
from app.config import settings
from app.database import get_db
from app.services.vault_service import (
    DecryptionError,
    FileExpiredError,
    FileNotFoundError,
    FileSizeExceededError,
    VaultService,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vault", tags=["vault"])


# ─── Pydantic Schemas ────────────────────────────────────────────────────────


class UploadResponse(BaseModel):
    """Response schema for successful file upload."""
    id: str = Field(..., description="Unique file identifier (UUID)")
    filename: str = Field(..., description="Original filename")
    encrypted_size: int = Field(..., description="Size of encrypted file in bytes")
    upload_date: str = Field(..., description="ISO 8601 upload timestamp")
    message: str = Field(default="File encrypted and stored successfully")
    max_downloads: Optional[int] = Field(None, description="Maximum allowed downloads")
    expires_at: Optional[str] = Field(None, description="Expiration timestamp (ISO 8601)")


class DownloadRequest(BaseModel):
    """Request schema for file download."""
    password: str = Field(
        ...,
        min_length=1,
        description="Passphrase used during encryption",
    )


class FileMetadata(BaseModel):
    """Public metadata for a stored file (no sensitive fields)."""
    id: str
    filename: str
    encrypted_size: int
    original_size: int
    content_type: str
    upload_date: str
    download_count: int
    max_downloads: Optional[int]
    expires_at: Optional[str]
    is_available: bool


class FileListResponse(BaseModel):
    """Response schema for file listing."""
    files: list[FileMetadata]
    total: int


class ErrorResponse(BaseModel):
    """Generic error response (no sensitive details)."""
    detail: str


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=201,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        413: {"model": ErrorResponse, "description": "File too large"},
    },
    summary="Upload and encrypt a file",
    description=(
        "Accepts a file and a passphrase via multipart form-data. "
        "The file is encrypted with AES-256-GCM using an Argon2id-derived key. "
        "The passphrase is NEVER stored — only used transiently for key derivation."
    ),
)
@limiter.limit(settings.RATE_LIMIT_UPLOAD)
async def upload_file(
    request: Request,
    file: UploadFile = File(..., description="File to encrypt and store"),
    password: str = Form(..., min_length=1, description="Encryption passphrase"),
    max_downloads: Optional[int] = Form(
        None, description="Maximum number of downloads (null = unlimited)", ge=1
    ),
    expires_in_hours: Optional[int] = Form(
        None, description="Hours until file expires (null = no expiry)", ge=1
    ),
    db: AsyncSession = Depends(get_db),
):
    """Upload, encrypt, and store a file in the vault."""
    try:
        # Read file content
        file_content = await file.read()

        if not file_content:
            raise HTTPException(status_code=400, detail="Empty file")

        # Calculate expiration time if specified
        expires_at = None
        if expires_in_hours:
            from datetime import timedelta
            expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

        # Process upload
        service = VaultService(db)
        file_record = await service.upload_file(
            file_content=file_content,
            filename=file.filename or "unnamed",
            password=password,
            content_type=file.content_type or "application/octet-stream",
            max_downloads=max_downloads,
            expires_at=expires_at,
        )

        return UploadResponse(
            id=str(file_record.id),
            filename=file_record.original_filename,
            encrypted_size=file_record.encrypted_size,
            upload_date=file_record.upload_date.isoformat(),
            max_downloads=file_record.max_downloads,
            expires_at=file_record.expires_at.isoformat() if file_record.expires_at else None,
        )

    except HTTPException:
        raise
    except FileSizeExceededError as e:
        raise HTTPException(status_code=413, detail=str(e))
    except Exception as e:
        logger.exception("Upload failed unexpectedly")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        # Best-effort password cleanup from local scope
        password = ""  # noqa: F841


@router.post(
    "/download/{file_id}",
    responses={
        200: {
            "description": "Decrypted file content",
            "content": {"application/octet-stream": {}},
        },
        401: {"model": ErrorResponse, "description": "Invalid credentials or corrupted data"},
        404: {"model": ErrorResponse, "description": "File not found"},
        410: {"model": ErrorResponse, "description": "File expired or download limit reached"},
    },
    summary="Download and decrypt a file",
    description=(
        "Accepts a file ID and passphrase. Re-derives the encryption key using "
        "Argon2id with the stored salt, then decrypts the file with AES-256-GCM. "
        "Returns the decrypted file as a streaming response."
    ),
)
@limiter.limit(settings.RATE_LIMIT_DOWNLOAD)
async def download_file(
    request: Request,
    file_id: UUID,
    body: DownloadRequest,
    db: AsyncSession = Depends(get_db),
):
    """Decrypt and download a file from the vault."""
    try:
        service = VaultService(db)
        plaintext, filename, content_type = await service.download_file(
            file_id=file_id,
            password=body.password,
        )

        # Stream the decrypted content
        return Response(
            content=plaintext,
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(plaintext)),
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
            },
        )

    except FileNotFoundError:
        # Generic 404 — do not reveal whether the ID exists
        raise HTTPException(status_code=404, detail="File not found")
    except FileExpiredError:
        raise HTTPException(
            status_code=410,
            detail="File is no longer available (expired or download limit reached)",
        )
    except DecryptionError:
        # CRITICAL: Generic 401 — do NOT differentiate between wrong password
        # and tampered ciphertext. This prevents oracle attacks.
        raise HTTPException(
            status_code=401,
            detail="Decryption failed: invalid credentials or corrupted data",
        )
    except Exception as e:
        logger.exception("Download failed unexpectedly")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        body.password = ""  # noqa: F841


@router.get(
    "/files",
    response_model=FileListResponse,
    summary="List encrypted files metadata",
    description=(
        "Returns metadata for all active encrypted files. "
        "NEVER returns file content, passwords, cryptographic material, "
        "or any other sensitive information."
    ),
)
async def list_files(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List metadata of all active encrypted files in the vault."""
    service = VaultService(db)
    files = await service.list_files()

    return FileListResponse(
        files=[FileMetadata(**f) for f in files],
        total=len(files),
    )

"""
VaultCore API Routes.

    - Upload / list / delete require the X-API-Key header.
    - Download requires only file ID + password (shareable link model),
      protected by IP rate limiting and a per-file lockout.
    - Error messages never distinguish wrong password from tampered data.
"""

import logging
from datetime import UTC, datetime, timedelta
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import limiter, require_api_key
from app.config import settings
from app.database import get_db
from app.services.vault_service import (
    DecryptionError,
    FileExpiredError,
    FileLockedError,
    FileSizeExceededError,
    VaultFileNotFoundError,
    VaultService,
    WeakPasswordError,
    ascii_filename,
    to_public_metadata,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vault", tags=["vault"])

READ_CHUNK = 1024 * 1024


# ─── Schemas ─────────────────────────────────────────────────────────────────


class UploadResponse(BaseModel):
    id: str
    filename: str
    encrypted_size: int
    upload_date: str
    message: str = "File encrypted and stored successfully"
    max_downloads: int | None = None
    expires_at: str | None = None


class DownloadRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=1024)


class FileMetadata(BaseModel):
    id: str
    filename: str
    encrypted_size: int
    original_size: int
    content_type: str
    upload_date: str
    download_count: int
    max_downloads: int | None
    expires_at: str | None
    is_available: bool


class FileListResponse(BaseModel):
    files: list[FileMetadata]
    total: int


class ErrorResponse(BaseModel):
    detail: str


# ─── Helpers ─────────────────────────────────────────────────────────────────


async def _read_limited(file: UploadFile, limit: int) -> bytes:
    """Read the upload in chunks and stop as soon as the limit is exceeded."""
    chunks, size = [], 0
    while chunk := await file.read(READ_CHUNK):
        size += len(chunk)
        if size > limit:
            raise FileSizeExceededError()
        chunks.append(chunk)
    return b"".join(chunks)


# ─── Endpoints ───────────────────────────────────────────────────────────────


@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=201,
    dependencies=[Depends(require_api_key)],
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 413: {"model": ErrorResponse}},
    summary="Upload and encrypt a file",
)
@limiter.limit(settings.RATE_LIMIT_UPLOAD)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    password: str = Form(..., min_length=1, max_length=1024),
    max_downloads: int | None = Form(None, ge=1),
    expires_in_hours: int | None = Form(None, ge=1, le=24 * 365),
    db: AsyncSession = Depends(get_db),
):
    try:
        content = await _read_limited(file, settings.max_file_size_bytes)
        if not content:
            raise HTTPException(400, "Empty file")

        expires_at = (
            datetime.now(UTC) + timedelta(hours=expires_in_hours)
            if expires_in_hours else None
        )
        record = await VaultService(db).upload_file(
            file_content=content,
            filename=file.filename,
            password=password,
            content_type=file.content_type,
            max_downloads=max_downloads,
            expires_at=expires_at,
        )
    except FileSizeExceededError:
        raise HTTPException(413, f"File exceeds {settings.MAX_FILE_SIZE_MB} MB")
    except WeakPasswordError as e:
        raise HTTPException(400, str(e))

    meta = to_public_metadata(record)
    return UploadResponse(
        id=meta["id"],
        filename=meta["filename"],
        encrypted_size=meta["encrypted_size"],
        upload_date=meta["upload_date"],
        max_downloads=meta["max_downloads"],
        expires_at=meta["expires_at"],
    )


@router.post(
    "/download/{file_id}",
    responses={
        200: {"content": {"application/octet-stream": {}}},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        410: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
    },
    summary="Download and decrypt a file",
)
@limiter.limit(settings.RATE_LIMIT_DOWNLOAD)
async def download_file(
    request: Request,
    file_id: UUID,
    body: DownloadRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        plaintext, filename = await VaultService(db).download_file(file_id, body.password)
    except VaultFileNotFoundError:
        raise HTTPException(404, "File not found")
    except FileExpiredError:
        raise HTTPException(410, "File is no longer available")
    except FileLockedError:
        raise HTTPException(429, "Too many failed attempts; try again later")
    except DecryptionError:
        raise HTTPException(401, "Decryption failed: invalid credentials or corrupted data")

    disposition = (
        f'attachment; filename="{ascii_filename(filename)}"; '
        f"filename*=UTF-8''{quote(filename, safe='')}"
    )
    return Response(
        content=plaintext,
        media_type="application/octet-stream",  # never echo user-supplied MIME types
        headers={
            "Content-Disposition": disposition,
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


@router.get(
    "/files",
    response_model=FileListResponse,
    dependencies=[Depends(require_api_key)],
    summary="List metadata of active files",
)
async def list_files(db: AsyncSession = Depends(get_db)):
    files = [to_public_metadata(f) for f in await VaultService(db).list_files()]
    return FileListResponse(files=[FileMetadata(**f) for f in files], total=len(files))


@router.delete(
    "/files/{file_id}",
    status_code=204,
    dependencies=[Depends(require_api_key)],
    summary="Delete a file (removes ciphertext)",
)
async def delete_file(file_id: UUID, db: AsyncSession = Depends(get_db)):
    if not await VaultService(db).delete_file(file_id):
        raise HTTPException(404, "File not found")
    return Response(status_code=204)

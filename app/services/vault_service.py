"""
VaultCore Vault Service.

Business logic for encrypted file operations.

Invariants:
    - Passwords are never stored or logged.
    - Plaintext is never written to disk.
    - CPU/memory-heavy KDF work runs in a thread pool behind a semaphore,
      so it neither blocks the event loop nor exhausts memory.
    - Download limits are enforced with an atomic UPDATE (race-free).
"""

import asyncio
import logging
import os
import re
import unicodedata
import uuid
from datetime import datetime, timedelta

import aiofiles
from anyio import to_thread
from cryptography.exceptions import InvalidTag
from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.crypto.engine import CryptoParams, decrypt, encrypt
from app.models.vault import EncryptedFile, as_utc, utcnow

logger = logging.getLogger(__name__)

_kdf_semaphore = asyncio.Semaphore(settings.KDF_MAX_CONCURRENCY)


class VaultServiceError(Exception):
    """Base exception for vault service errors."""


class VaultFileNotFoundError(VaultServiceError):
    """Requested file does not exist."""


class FileExpiredError(VaultServiceError):
    """File expired, deactivated or download limit reached."""


class FileLockedError(VaultServiceError):
    """Too many failed attempts; file temporarily locked."""


class DecryptionError(VaultServiceError):
    """Wrong password or tampered data."""


class FileSizeExceededError(VaultServiceError):
    """Uploaded file exceeds the size limit."""


class WeakPasswordError(VaultServiceError):
    """Password does not meet the policy."""


async def _run_kdf_bound(func, *args):
    async with _kdf_semaphore:
        return await to_thread.run_sync(func, *args)


def sanitize_filename(name: str | None) -> str:
    """Strip paths and control characters; keep a display-safe name."""
    name = os.path.basename((name or "").replace("\\", "/"))
    name = "".join(c for c in name if unicodedata.category(c)[0] != "C").strip()
    return name[:255] or "unnamed"


def ascii_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "download"


class VaultService:
    """Upload (encrypt + store), download (decrypt), list, delete and purge."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.storage_path = settings.encrypted_files_path

    async def upload_file(
        self,
        file_content: bytes,
        filename: str | None,
        password: str,
        content_type: str | None = None,
        max_downloads: int | None = None,
        expires_at: datetime | None = None,
    ) -> EncryptedFile:
        if len(file_content) > settings.max_file_size_bytes:
            raise FileSizeExceededError(
                f"File exceeds maximum allowed size ({settings.MAX_FILE_SIZE_MB} MB)"
            )
        if len(password) < settings.MIN_PASSWORD_LENGTH:
            raise WeakPasswordError(
                f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters"
            )

        file_id = uuid.uuid4()
        result = await _run_kdf_bound(encrypt, file_content, password, file_id.bytes)

        encrypted_filename = f"{file_id}.enc"
        final_path = self.storage_path / encrypted_filename
        tmp_path = final_path.with_suffix(".tmp")

        async with aiofiles.open(tmp_path, "wb") as f:
            await f.write(result.ciphertext)
        os.replace(tmp_path, final_path)  # atomic: no half-written .enc files

        record = EncryptedFile(
            id=file_id,
            original_filename=sanitize_filename(filename),
            encrypted_filename=encrypted_filename,
            original_size=len(file_content),
            encrypted_size=len(result.ciphertext),
            content_type=(content_type or "application/octet-stream")[:255],
            salt_hex=result.salt.hex(),
            nonce_hex=result.nonce.hex(),
            kdf_time_cost=result.params.time_cost,
            kdf_memory_cost=result.params.memory_cost,
            kdf_parallelism=result.params.parallelism,
            max_downloads=max_downloads,
            expires_at=expires_at,
        )
        try:
            self.db.add(record)
            await self.db.commit()
        except Exception:
            await self.db.rollback()
            final_path.unlink(missing_ok=True)  # never leave orphan ciphertext
            raise

        logger.info("File uploaded: id=%s size=%d", file_id, len(result.ciphertext))
        return record

    async def download_file(self, file_id: uuid.UUID, password: str) -> tuple[bytes, str]:
        record = await self.db.get(EncryptedFile, file_id)
        if record is None:
            raise VaultFileNotFoundError(file_id)
        if not record.is_available:
            raise FileExpiredError(file_id)
        if record.is_locked:
            raise FileLockedError(file_id)

        path = self.storage_path / record.encrypted_filename
        if not path.exists():
            logger.error("Encrypted file missing from disk: %s", record.encrypted_filename)
            raise VaultFileNotFoundError(file_id)

        async with aiofiles.open(path, "rb") as f:
            ciphertext = await f.read()

        params = CryptoParams(record.kdf_time_cost, record.kdf_memory_cost, record.kdf_parallelism)
        try:
            plaintext = await _run_kdf_bound(
                decrypt, ciphertext, password,
                bytes.fromhex(record.salt_hex), bytes.fromhex(record.nonce_hex),
                params, file_id.bytes,
            )
        except InvalidTag:
            await self._register_failed_attempt(file_id)
            raise DecryptionError(file_id)

        # Atomically claim one download; concurrent requests cannot exceed the limit.
        claimed = await self.db.execute(
            update(EncryptedFile)
            .where(
                EncryptedFile.id == file_id,
                EncryptedFile.is_active.is_(True),
                or_(
                    EncryptedFile.max_downloads.is_(None),
                    EncryptedFile.download_count < EncryptedFile.max_downloads,
                ),
            )
            .values(download_count=EncryptedFile.download_count + 1, failed_attempts=0)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            await self.db.rollback()
            raise FileExpiredError(file_id)

        # Deactivate once the limit is hit and shred the ciphertext.
        exhausted = await self.db.execute(
            update(EncryptedFile)
            .where(
                EncryptedFile.id == file_id,
                EncryptedFile.max_downloads.is_not(None),
                EncryptedFile.download_count >= EncryptedFile.max_downloads,
            )
            .values(is_active=False)
            .execution_options(synchronize_session=False)
        )
        await self.db.commit()
        if exhausted.rowcount:
            path.unlink(missing_ok=True)
            logger.info("File %s exhausted and removed from storage", file_id)

        return plaintext, record.original_filename

    async def _register_failed_attempt(self, file_id: uuid.UUID) -> None:
        await self.db.execute(
            update(EncryptedFile)
            .where(EncryptedFile.id == file_id)
            .values(failed_attempts=EncryptedFile.failed_attempts + 1)
            .execution_options(synchronize_session=False)
        )
        await self.db.execute(
            update(EncryptedFile)
            .where(
                EncryptedFile.id == file_id,
                EncryptedFile.failed_attempts >= settings.MAX_FAILED_ATTEMPTS,
            )
            .values(
                failed_attempts=0,
                locked_until=utcnow() + timedelta(minutes=settings.LOCKOUT_MINUTES),
            )
            .execution_options(synchronize_session=False)
        )
        await self.db.commit()

    async def list_files(self) -> list[EncryptedFile]:
        result = await self.db.execute(
            select(EncryptedFile)
            .where(EncryptedFile.is_active.is_(True))
            .order_by(EncryptedFile.upload_date.desc())
        )
        return list(result.scalars().all())

    async def delete_file(self, file_id: uuid.UUID) -> bool:
        """Deactivate the record and delete the ciphertext (crypto-shredding)."""
        record = await self.db.get(EncryptedFile, file_id)
        if record is None:
            return False
        record.is_active = False
        await self.db.commit()
        (self.storage_path / record.encrypted_filename).unlink(missing_ok=True)
        logger.info("File deleted: id=%s", file_id)
        return True

    async def purge_unavailable(self) -> int:
        """Remove ciphertext of expired/inactive/exhausted files and stray temp files."""
        now = utcnow()
        result = await self.db.execute(
            select(EncryptedFile).where(
                or_(
                    EncryptedFile.is_active.is_(False),
                    EncryptedFile.expires_at <= now,
                    and_(
                        EncryptedFile.max_downloads.is_not(None),
                        EncryptedFile.download_count >= EncryptedFile.max_downloads,
                    ),
                )
            )
        )
        purged = 0
        for record in result.scalars():
            record.is_active = False
            path = self.storage_path / record.encrypted_filename
            if path.exists():
                path.unlink()
                purged += 1
        await self.db.commit()

        known = set((await self.db.execute(select(EncryptedFile.encrypted_filename))).scalars())
        cutoff = now.timestamp() - 3600
        for path in self.storage_path.iterdir():
            orphan = path.suffix == ".tmp" or (path.suffix == ".enc" and path.name not in known)
            if orphan and path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)
                purged += 1

        if purged:
            logger.info("Purged %d stale encrypted files", purged)
        return purged


def to_public_metadata(f: EncryptedFile) -> dict:
    """Non-sensitive metadata only (no salt, nonce, KDF params)."""
    expires = as_utc(f.expires_at)
    return {
        "id": str(f.id),
        "filename": f.original_filename,
        "encrypted_size": f.encrypted_size,
        "original_size": f.original_size,
        "content_type": f.content_type,
        "upload_date": as_utc(f.upload_date).isoformat(),
        "download_count": f.download_count,
        "max_downloads": f.max_downloads,
        "expires_at": expires.isoformat() if expires else None,
        "is_available": f.is_available,
    }

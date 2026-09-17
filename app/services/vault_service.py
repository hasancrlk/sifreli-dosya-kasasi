"""
VaultCore Vault Service.

Business logic layer for encrypted file operations.
Orchestrates cryptographic operations, file I/O, and database persistence.

Security Invariants:
    - Passwords exist in memory only during the encrypt/decrypt call.
    - All file I/O uses the encrypted form; plaintext is never written to disk.
    - Cryptographic failures produce generic error messages (no info leakage).
"""

import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiofiles
from cryptography.exceptions import InvalidTag
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.crypto.engine import encrypt, decrypt
from app.models.vault import EncryptedFile

logger = logging.getLogger(__name__)


class VaultServiceError(Exception):
    """Base exception for vault service errors."""
    pass


class FileNotFoundError(VaultServiceError):
    """Raised when a requested file does not exist."""
    pass


class FileExpiredError(VaultServiceError):
    """Raised when a file has expired or reached download limits."""
    pass


class DecryptionError(VaultServiceError):
    """Raised when decryption fails (wrong password or tampered data)."""
    pass


class FileSizeExceededError(VaultServiceError):
    """Raised when uploaded file exceeds the size limit."""
    pass


class VaultService:
    """
    Service class for vault operations.

    Handles the complete lifecycle of encrypted files:
    upload (encrypt + store) and download (retrieve + decrypt).
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.storage_path = settings.encrypted_files_path

    async def upload_file(
        self,
        file_content: bytes,
        filename: str,
        password: str,
        content_type: str = "application/octet-stream",
        max_downloads: Optional[int] = None,
        expires_at: Optional[datetime] = None,
    ) -> EncryptedFile:
        """
        Encrypt and store a file in the vault.

        Process:
            1. Validate file size.
            2. Encrypt file content with AES-256-GCM (Argon2id-derived key).
            3. Write encrypted data to disk as .enc file.
            4. Store metadata (NOT the password) in PostgreSQL.

        Args:
            file_content: Raw file bytes to encrypt.
            filename: Original filename for metadata.
            password: Passphrase for encryption (NOT stored).
            content_type: MIME type of the original file.
            max_downloads: Optional limit on download count (None = unlimited).
            expires_at: Optional expiration datetime (None = no expiry).

        Returns:
            EncryptedFile metadata record.

        Raises:
            FileSizeExceededError: If file exceeds MAX_FILE_SIZE_MB.
        """
        # Validate file size
        if len(file_content) > settings.max_file_size_bytes:
            raise FileSizeExceededError(
                f"File size ({len(file_content)} bytes) exceeds "
                f"maximum allowed ({settings.max_file_size_bytes} bytes)"
            )

        # Encrypt the file content
        # Password is only used here and not stored anywhere
        encryption_result = encrypt(file_content, password)

        # Generate unique filename for encrypted file
        file_id = uuid.uuid4()
        encrypted_filename = f"{file_id}.enc"
        encrypted_filepath = self.storage_path / encrypted_filename

        # Write encrypted data to disk
        async with aiofiles.open(encrypted_filepath, "wb") as f:
            await f.write(encryption_result.ciphertext)

        # Create metadata record (NO password stored)
        file_record = EncryptedFile(
            id=file_id,
            original_filename=filename,
            encrypted_filename=encrypted_filename,
            original_size=len(file_content),
            encrypted_size=len(encryption_result.ciphertext),
            content_type=content_type,
            salt_hex=encryption_result.salt.hex(),
            nonce_hex=encryption_result.nonce.hex(),
            max_downloads=max_downloads,
            expires_at=expires_at,
        )

        self.db.add(file_record)
        await self.db.flush()

        logger.info(
            "File uploaded: id=%s, original_name='%s', encrypted_size=%d bytes",
            file_id,
            filename,
            len(encryption_result.ciphertext),
        )

        # Password variable goes out of scope here — Python GC will reclaim it.
        # We do NOT store it in any instance variable, log, or database field.
        return file_record

    async def download_file(
        self, file_id: uuid.UUID, password: str
    ) -> tuple[bytes, str, str]:
        """
        Retrieve and decrypt a file from the vault.

        Process:
            1. Fetch metadata from database.
            2. Verify file is available (active, not expired, within download limits).
            3. Read encrypted data from disk.
            4. Re-derive key from password + stored salt using Argon2id.
            5. Decrypt with AES-256-GCM using stored nonce.
            6. Increment download counter.

        Args:
            file_id: UUID of the file to download.
            password: Passphrase for decryption (NOT stored).

        Returns:
            Tuple of (decrypted_content, original_filename, content_type).

        Raises:
            FileNotFoundError: If file_id doesn't exist in database.
            FileExpiredError: If file is expired, deactivated, or download limit reached.
            DecryptionError: If password is wrong or ciphertext is tampered.
        """
        # Fetch file metadata
        result = await self.db.execute(
            select(EncryptedFile).where(EncryptedFile.id == file_id)
        )
        file_record = result.scalar_one_or_none()

        if file_record is None:
            raise FileNotFoundError(f"File not found: {file_id}")

        # Check availability (expiration, download limits, active status)
        if not file_record.is_available:
            if file_record.is_expired:
                raise FileExpiredError("File has expired and is no longer available")
            if file_record.is_download_limit_reached:
                raise FileExpiredError("File has reached its maximum download limit")
            raise FileExpiredError("File is no longer available")

        # Read encrypted data from disk
        encrypted_filepath = self.storage_path / file_record.encrypted_filename
        if not encrypted_filepath.exists():
            logger.error(
                "Encrypted file missing from disk: %s", file_record.encrypted_filename
            )
            raise FileNotFoundError("Encrypted file not found on storage")

        async with aiofiles.open(encrypted_filepath, "rb") as f:
            ciphertext = await f.read()

        # Reconstruct cryptographic parameters from stored hex values
        salt = bytes.fromhex(file_record.salt_hex)
        nonce = bytes.fromhex(file_record.nonce_hex)

        # Attempt decryption
        try:
            plaintext = decrypt(ciphertext, password, salt, nonce)
        except InvalidTag:
            # Generic error message — do NOT reveal whether password was wrong
            # or data was tampered with (prevents oracle attacks)
            raise DecryptionError(
                "Decryption failed: invalid credentials or corrupted data"
            )

        # Increment download counter
        file_record.download_count += 1

        # If max_downloads is reached after this download, deactivate the file
        if file_record.is_download_limit_reached:
            file_record.is_active = False
            logger.info(
                "File %s deactivated: download limit (%d) reached",
                file_id,
                file_record.max_downloads,
            )

        await self.db.flush()

        logger.info(
            "File downloaded: id=%s, download_count=%d",
            file_id,
            file_record.download_count,
        )

        return plaintext, file_record.original_filename, file_record.content_type

    async def list_files(self) -> list[dict]:
        """
        List metadata of all active encrypted files.

        Security Note:
            - Returns ONLY non-sensitive metadata.
            - Does NOT return: salt, nonce, file content, or any cryptographic material.
            - Expired/deactivated files are excluded from results.

        Returns:
            List of dictionaries containing file metadata.
        """
        result = await self.db.execute(
            select(EncryptedFile)
            .where(EncryptedFile.is_active == True)  # noqa: E712
            .order_by(EncryptedFile.upload_date.desc())
        )
        files = result.scalars().all()

        return [
            {
                "id": str(f.id),
                "filename": f.original_filename,
                "encrypted_size": f.encrypted_size,
                "original_size": f.original_size,
                "content_type": f.content_type,
                "upload_date": f.upload_date.isoformat(),
                "download_count": f.download_count,
                "max_downloads": f.max_downloads,
                "expires_at": f.expires_at.isoformat() if f.expires_at else None,
                "is_available": f.is_available,
            }
            for f in files
        ]

    async def delete_file(self, file_id: uuid.UUID) -> bool:
        """
        Soft-delete a file by deactivating it.

        The encrypted file remains on disk but is no longer available for download.
        A separate cleanup job can purge deactivated files.

        Args:
            file_id: UUID of the file to deactivate.

        Returns:
            True if file was found and deactivated, False if not found.
        """
        result = await self.db.execute(
            select(EncryptedFile).where(EncryptedFile.id == file_id)
        )
        file_record = result.scalar_one_or_none()

        if file_record is None:
            return False

        file_record.is_active = False
        await self.db.flush()

        logger.info("File deactivated: id=%s", file_id)
        return True

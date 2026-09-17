"""
VaultCore Database Models.

SQLAlchemy models for encrypted file metadata storage.

Security Note:
    - Only metadata is stored in the database (filenames, sizes, timestamps).
    - Cryptographic material (salt, nonce) is stored as hex strings.
    - Passwords and encryption keys are NEVER stored.
    - Original file content is NEVER stored unencrypted.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Integer, DateTime, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from app.database import Base


class EncryptedFile(Base):
    """
    Metadata record for an encrypted file stored in the vault.

    Attributes:
        id: Unique identifier (UUIDv4) for the encrypted file.
        original_filename: Original name of the uploaded file (for display only).
        encrypted_filename: Name of the .enc file on disk.
        original_size: Size of the original plaintext file in bytes.
        encrypted_size: Size of the encrypted file on disk in bytes.
        content_type: MIME type of the original file.
        salt_hex: Hex-encoded 16-byte salt used for key derivation.
        nonce_hex: Hex-encoded 12-byte nonce used for AES-GCM encryption.
        upload_date: UTC timestamp of when the file was uploaded.
        is_active: Whether the file is available for download.
        download_count: Number of times the file has been successfully downloaded.
        max_downloads: Maximum allowed downloads (None = unlimited).
        expires_at: Optional UTC expiration timestamp after which downloads are denied.
    """

    __tablename__ = "encrypted_files"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    encrypted_filename: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    original_size: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_size: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[str] = mapped_column(String(256), default="application/octet-stream")

    # Cryptographic parameters (NOT secrets — these are needed for decryption)
    salt_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce_hex: Mapped[str] = mapped_column(String(48), nullable=False)

    # Timestamps
    upload_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Access control
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    download_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_downloads: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, default=None)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

    # Optional description (never contains sensitive data)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)

    def __repr__(self) -> str:
        return (
            f"<EncryptedFile(id={self.id}, "
            f"filename='{self.original_filename}', "
            f"active={self.is_active})>"
        )

    @property
    def is_expired(self) -> bool:
        """Check if the file has passed its expiration time."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def is_download_limit_reached(self) -> bool:
        """Check if the file has reached its maximum download count."""
        if self.max_downloads is None:
            return False
        return self.download_count >= self.max_downloads

    @property
    def is_available(self) -> bool:
        """Check if the file is available for download."""
        return self.is_active and not self.is_expired and not self.is_download_limit_reached

"""
VaultCore Database Models.

Stores metadata and the public parameters needed for decryption
(salt, nonce, KDF params). Passwords and keys are never stored.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def as_utc(dt: datetime | None) -> datetime | None:
    """Treat naive datetimes (e.g. from SQLite) as UTC."""
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=UTC)


def utcnow() -> datetime:
    return datetime.now(UTC)


class EncryptedFile(Base):
    """Metadata record for an encrypted file stored in the vault."""

    __tablename__ = "encrypted_files"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_filename: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    original_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    encrypted_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), default="application/octet-stream")

    # Public cryptographic parameters (required for decryption, not secrets)
    salt_hex: Mapped[str] = mapped_column(String(32), nullable=False)
    nonce_hex: Mapped[str] = mapped_column(String(24), nullable=False)
    kdf_time_cost: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_memory_cost: Mapped[int] = mapped_column(Integer, nullable=False)
    kdf_parallelism: Mapped[int] = mapped_column(Integer, nullable=False)

    upload_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Access control
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    download_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_downloads: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Brute-force protection
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<EncryptedFile(id={self.id}, active={self.is_active})>"

    @property
    def is_expired(self) -> bool:
        expires = as_utc(self.expires_at)
        return expires is not None and utcnow() >= expires

    @property
    def is_download_limit_reached(self) -> bool:
        return self.max_downloads is not None and self.download_count >= self.max_downloads

    @property
    def is_locked(self) -> bool:
        locked = as_utc(self.locked_until)
        return locked is not None and utcnow() < locked

    @property
    def is_available(self) -> bool:
        return self.is_active and not self.is_expired and not self.is_download_limit_reached

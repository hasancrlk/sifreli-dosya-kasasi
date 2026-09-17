"""
VaultCore Application Configuration.

All sensitive values come from environment variables; nothing secret has a default.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database (required — no credentials baked into code)
    DATABASE_URL: str

    # Application
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_ENV: str = "production"
    DEBUG: bool = False

    # Authentication for management endpoints (upload/list/delete)
    API_KEY: str = ""

    # File Storage
    ENCRYPTED_FILES_DIR: str = "./encrypted_files"
    MAX_FILE_SIZE_MB: int = 100
    CLEANUP_INTERVAL_MINUTES: int = 60

    # Rate limiting — use redis:// when running more than one worker
    RATE_LIMIT_STORAGE_URI: str = "memory://"
    RATE_LIMIT_DOWNLOAD: str = "5/minute"
    RATE_LIMIT_UPLOAD: str = "10/minute"

    # Per-file brute-force lockout (enforced in the DB, works across workers)
    MAX_FAILED_ATTEMPTS: int = 5
    LOCKOUT_MINUTES: int = 15

    # Password policy
    MIN_PASSWORD_LENGTH: int = 12

    # Argon2id KDF parameters for NEW files (stored per file, so changing them is safe)
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536  # KiB = 64 MB
    ARGON2_PARALLELISM: int = 4
    KDF_MAX_CONCURRENCY: int = 4  # caps KDF memory use per worker

    @property
    def max_file_size_bytes(self) -> int:
        return self.MAX_FILE_SIZE_MB * 1024 * 1024

    @property
    def encrypted_files_path(self) -> Path:
        path = Path(self.ENCRYPTED_FILES_DIR)
        path.mkdir(parents=True, exist_ok=True)
        return path

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()

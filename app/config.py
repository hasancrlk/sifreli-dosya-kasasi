"""
VaultCore Application Configuration.

Centralized configuration management using pydantic-settings.
All sensitive values are loaded from environment variables.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://vaultcore:vaultcore_secret@localhost:5432/vaultcore_db"
    DATABASE_URL_SYNC: str = "postgresql://vaultcore:vaultcore_secret@localhost:5432/vaultcore_db"

    # Application
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_ENV: str = "production"
    DEBUG: bool = False

    # File Storage
    ENCRYPTED_FILES_DIR: str = "./encrypted_files"

    # Rate Limiting (per file_id for download endpoint)
    RATE_LIMIT_DOWNLOAD: str = "5/minute"
    RATE_LIMIT_UPLOAD: str = "10/minute"

    # Argon2id KDF Parameters (OWASP recommended)
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536  # 64 MB
    ARGON2_PARALLELISM: int = 4

    # File Limits
    MAX_FILE_SIZE_MB: int = 100

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
    )


settings = Settings()

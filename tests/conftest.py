"""
VaultCore Test Configuration.

Provides test fixtures for:
    - In-memory SQLite database (async)
    - FastAPI test client (httpx)
    - Temporary encrypted file storage
    - Fast KDF parameters (for test speed)
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base, get_db
from app.main import app


# ─── Test Database Setup ─────────────────────────────────────────────────────

TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_vault.db"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
)

test_session_factory = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    """Create and tear down test database for each test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    # Clean up test database file
    if os.path.exists("./test_vault.db"):
        os.remove("./test_vault.db")


@pytest_asyncio.fixture
async def db_session():
    """Provide a test database session."""
    async with test_session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def temp_storage(tmp_path):
    """Provide a temporary directory for encrypted files."""
    storage_dir = tmp_path / "encrypted_files"
    storage_dir.mkdir()
    return storage_dir


@pytest_asyncio.fixture
async def client(temp_storage):
    """
    Provide an async HTTP test client with overridden dependencies.

    Uses:
        - SQLite in-memory database instead of PostgreSQL
        - Temporary directory for encrypted files
        - Reduced Argon2 parameters for faster test execution
    """
    async def override_get_db():
        async with test_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db

    # Patch settings for test environment
    with patch("app.services.vault_service.settings") as mock_settings, \
         patch("app.crypto.engine.settings") as mock_crypto_settings, \
         patch("app.api.routes.settings") as mock_route_settings:

        mock_settings.encrypted_files_path = temp_storage
        mock_settings.max_file_size_bytes = 10 * 1024 * 1024  # 10 MB
        mock_settings.ENCRYPTED_FILES_DIR = str(temp_storage)

        # Use fast Argon2 params for testing (NOT for production!)
        mock_crypto_settings.ARGON2_TIME_COST = 1
        mock_crypto_settings.ARGON2_MEMORY_COST = 1024  # 1 MB (minimal)
        mock_crypto_settings.ARGON2_PARALLELISM = 1

        mock_route_settings.RATE_LIMIT_UPLOAD = "100/minute"
        from app.api.dependencies import limiter
        original_limiter_enabled = limiter.enabled
        limiter.enabled = False

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac

        limiter.enabled = original_limiter_enabled

    app.dependency_overrides.clear()

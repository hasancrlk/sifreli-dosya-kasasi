"""
VaultCore test configuration.

    - SQLite (aiosqlite) instead of PostgreSQL
    - Temporary encrypted-file storage
    - Fast Argon2 parameters (tests only!)
"""

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_vault.db")
os.environ.setdefault("API_KEY", "test-api-key")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.dependencies import limiter
from app.config import settings
from app.database import Base, get_db
from app.main import app

API_HEADERS = {"X-API-Key": "test-api-key"}
STRONG_PASSWORD = "correct-horse-battery-staple"

test_engine = create_async_engine(os.environ["DATABASE_URL"], echo=False)
test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(autouse=True)
def fast_settings(monkeypatch, tmp_path):
    storage = tmp_path / "encrypted_files"
    storage.mkdir()
    monkeypatch.setattr(settings, "ENCRYPTED_FILES_DIR", str(storage))
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_MB", 10)
    monkeypatch.setattr(settings, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(settings, "ARGON2_MEMORY_COST", 1024)
    monkeypatch.setattr(settings, "ARGON2_PARALLELISM", 1)
    monkeypatch.setattr(settings, "API_KEY", "test-api-key")
    monkeypatch.setattr(limiter, "enabled", False)
    return storage


@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()
    if os.path.exists("./test_vault.db"):
        os.remove("./test_vault.db")


@pytest_asyncio.fixture
async def db_session():
    async with test_session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client():
    async def override_get_db():
        async with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver", headers=API_HEADERS) as ac:
        yield ac
    app.dependency_overrides.clear()

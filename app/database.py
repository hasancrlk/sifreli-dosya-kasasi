"""
VaultCore Database Configuration.

Async SQLAlchemy engine and session management for PostgreSQL.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

_pool_kwargs = (
    {} if settings.DATABASE_URL.startswith("sqlite")
    else {"pool_pre_ping": True, "pool_size": 10, "max_overflow": 20}
)
engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG, **_pool_kwargs)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all models."""


async def get_db() -> AsyncSession:
    """Dependency injection for database sessions (services commit explicitly)."""
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all database tables on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose of the database engine on shutdown."""
    await engine.dispose()

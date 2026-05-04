"""
ShadowNet — Database Engine & Session Management
Supports SQLite (dev) and PostgreSQL (production) via async SQLAlchemy.
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event
from app.core.config import settings


# Detect if using SQLite
is_sqlite = settings.database_url.startswith("sqlite")

# Async engine — SQLite doesn't support pool_size
engine_kwargs: dict = {
    "echo": settings.debug,
}

if is_sqlite:
    # SQLite: disable check_same_thread, use NullPool to avoid lock contention
    engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
else:
    engine_kwargs.update({
        "pool_size": 20,
        "max_overflow": 10,
        "pool_pre_ping": True,
    })

engine = create_async_engine(settings.database_url, **engine_kwargs)

# Enable WAL mode for SQLite to allow concurrent reads + single writer without locking
if is_sqlite:
    from sqlalchemy import event as sa_event

    @sa_event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")   # Write-Ahead Logging
        cursor.execute("PRAGMA synchronous=NORMAL")  # Faster writes, still safe
        cursor.execute("PRAGMA cache_size=-64000")   # 64MB cache
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")  # 30s wait if locked
        cursor.close()


# Session factory
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields a database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables on startup (dev only)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

"""Database connection and session management."""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool, QueuePool
from typing import Generator

from ..config import get_settings

settings = get_settings()

# Configure engine based on database type
if settings.database_url.startswith("sqlite"):
    # SQLite configuration (for testing)
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    # PostgreSQL configuration with configurable connection pool
    # Pool settings are tuned per environment via config
    engine = create_engine(
        settings.database_url,
        poolclass=QueuePool,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_pool_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        pool_recycle=settings.db_pool_recycle,
        pool_pre_ping=settings.db_pool_pre_ping,
    )

    # Log pool events in debug mode for monitoring
    if settings.debug:
        @event.listens_for(engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            """Log when a connection is checked out from the pool."""
            pass  # Can be used for debugging connection issues

        @event.listens_for(engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            """Log when a connection is returned to the pool."""
            pass  # Can be used for debugging connection issues

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Get database session with automatic cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_pool_status() -> dict:
    """Get connection pool status for monitoring.

    Returns a dict with pool metrics. For SQLite (testing), returns minimal info.
    """
    pool = engine.pool
    if settings.database_url.startswith("sqlite"):
        return {
            "pool_type": "StaticPool",
            "note": "SQLite uses StaticPool for testing"
        }

    return {
        "pool_type": "QueuePool",
        "pool_size": pool.size(),
        "checked_in": pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow": pool.overflow(),
        "max_overflow": settings.db_pool_max_overflow,
        "pool_timeout": settings.db_pool_timeout,
        "pool_recycle": settings.db_pool_recycle,
    }

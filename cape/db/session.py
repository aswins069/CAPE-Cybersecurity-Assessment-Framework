"""SQLAlchemy session management for CAPE."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from cape.db.models import Base


_engine: Optional[Engine] = None
_SessionFactory: Optional[sessionmaker] = None  # type: ignore[type-arg]


def init_db(db_url: Optional[str] = None) -> Engine:
    """Initialize the database engine and create tables.

    Args:
        db_url: SQLAlchemy database URL. Defaults to config value.

    Returns:
        SQLAlchemy Engine.
    """
    global _engine, _SessionFactory

    if db_url is None:
        from cape.core.config import get_config
        db_url = get_config().db_url

    # Enable WAL mode for SQLite for better concurrency
    engine = create_engine(
        db_url,
        echo=False,
        pool_pre_ping=True,
    )

    if "sqlite" in db_url:
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    Base.metadata.create_all(engine)

    _engine = engine
    _SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)

    return engine


def get_engine() -> Engine:
    """Get or initialize the database engine."""
    global _engine
    if _engine is None:
        init_db()
    assert _engine is not None
    return _engine


def get_session() -> Session:
    """Get a new database session. Caller is responsible for closing."""
    if _SessionFactory is None:
        init_db()
    assert _SessionFactory is not None
    return _SessionFactory()


@contextmanager
def db_session() -> Generator[Session, None, None]:
    """Context manager that provides a database session with auto-commit/rollback.

    Usage:
        with db_session() as session:
            session.add(obj)
    """
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_memory_session() -> Session:
    """Create an in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    return factory()

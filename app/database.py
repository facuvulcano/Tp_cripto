"""Database configuration helpers."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import get_settings

settings = get_settings()
database_url = settings.database_url
url = make_url(database_url)
connect_args = {}
if url.drivername.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    if url.database:
        db_path = Path(url.database)
        if not db_path.is_absolute():
            db_path = Path.cwd() / db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)
Base = declarative_base()


def get_db() -> Generator:
    """Yield a database session for FastAPI dependencies."""

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Generator:
    """Provide transactional scope for scripts/tests."""

    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create tables if they do not exist."""

    import logging

    from . import models  # noqa: F401 - ensure models are imported

    logging.getLogger(__name__).info("Ensuring database schema is created")
    Base.metadata.create_all(bind=engine)

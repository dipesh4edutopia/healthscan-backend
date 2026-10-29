"""
Database Connection & Management Layer for Supabase PostgreSQL
Supports connection pooling with psycopg2 and dict-like row access.
"""

import logging
from contextlib import contextmanager
from typing import Generator, Any, Optional

try:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    RealDictCursor = None

from app.config import Config

logger = logging.getLogger(__name__)

# Global connection pool instance
_connection_pool: Optional[Any] = None
# Mock database for unit testing
_mock_db_instance: Optional[Any] = None


def init_db_pool(minconn: int = 1, maxconn: int = 20) -> None:
    """
    Initialize the threaded connection pool for Supabase PostgreSQL.
    """
    global _connection_pool
    if not PSYCOPG2_AVAILABLE:
        logger.warning("psycopg2 is not installed. Live database operations will fail.")
        return

    if _connection_pool is not None:
        return

    db_url = Config.DATABASE_URL
    try:
        if db_url and not db_url.startswith('mock://'):
            _connection_pool = pool.ThreadedConnectionPool(
                minconn=minconn,
                maxconn=maxconn,
                dsn=db_url,
                cursor_factory=RealDictCursor,
            )
            logger.info("Database connection pool initialized using DATABASE_URL.")
        elif Config.SUPABASE_DB_HOST:
            _connection_pool = pool.ThreadedConnectionPool(
                minconn=minconn,
                maxconn=maxconn,
                host=Config.SUPABASE_DB_HOST,
                database=Config.SUPABASE_DB_NAME,
                user=Config.SUPABASE_DB_USER,
                password=Config.SUPABASE_DB_PASSWORD,
                port=Config.SUPABASE_DB_PORT,
                cursor_factory=RealDictCursor,
            )
            logger.info("Database connection pool initialized using individual parameters.")
        else:
            logger.info("No live DATABASE_URL provided. Connection pool uninitialized.")
    except Exception as e:
        logger.error(f"Failed to initialize database connection pool: {e}")
        _connection_pool = None


def close_db_pool() -> None:
    """Close all connections in the pool."""
    global _connection_pool
    if _connection_pool is not None:
        try:
            _connection_pool.closeall()
            logger.info("Database connection pool closed.")
        except Exception as e:
            logger.error(f"Error closing connection pool: {e}")
        finally:
            _connection_pool = None


def set_mock_db(mock_instance: Any) -> None:
    """Set a mock database for unit testing."""
    global _mock_db_instance
    _mock_db_instance = mock_instance


def get_mock_db() -> Optional[Any]:
    """Retrieve current mock database if set."""
    return _mock_db_instance


@contextmanager
def get_db_cursor(commit: bool = False) -> Generator[Any, None, None]:
    """
    Context manager that checks out a database connection, yields a RealDictCursor,
    and commits or rolls back before returning the connection to the pool.
    """
    global _mock_db_instance, _connection_pool

    # If mock database is active (for tests), yield its cursor
    if _mock_db_instance is not None:
        with _mock_db_instance.get_cursor(commit=commit) as cursor:
            yield cursor
        return

    if _connection_pool is None:
        init_db_pool()

    if _connection_pool is None:
        raise RuntimeError(
            "Database connection pool is not initialized. Please configure DATABASE_URL in .env."
        )

    conn = None
    try:
        conn = _connection_pool.getconn()
        cursor = conn.cursor()
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
    finally:
        if conn is not None and _connection_pool is not None:
            _connection_pool.putconn(conn)

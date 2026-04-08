# =============================================================================
# DERIV TRADING BOT - Database Connection Pool Manager
# Version: 1.7 (FIXED: Parameter name mismatch for execute_insert_returning)
# Purpose: Handle concurrent database connections safely
# FIX: Renamed returning_column → returning_columns to match auth/routes.py calls
# =============================================================================

import os
import logging
import threading
from psycopg2 import connect, pool, OperationalError
from psycopg2.sql import Identifier, Placeholder, SQL
from psycopg2.extras import RealDictCursor
from config import Config

logger = logging.getLogger(__name__)


class DatabasePool:
    """Thread-safe PostgreSQL connection pool manager"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.min_connections = int(os.getenv('DB_MIN_CONNECTIONS', '2'))
        self.max_connections = int(os.getenv('DB_MAX_CONNECTIONS', '10'))

        try:
            self.connection_pool = pool.SimpleConnectionPool(
                self.min_connections,
                self.max_connections,
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                database=Config.DB_NAME,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
                cursor_factory=RealDictCursor
            )

            # Test initial connection
            test_conn = self.connection_pool.getconn()
            test_cursor = test_conn.cursor()
            test_cursor.execute("SELECT version()")
            test_cursor.fetchone()
            test_cursor.close()
            self.connection_pool.putconn(test_conn)

            logger.info(
                f"Database connection pool initialized successfully "
                f"(min={self.min_connections}, max={self.max_connections})"
            )
            self._initialized = True

        except OperationalError as e:
            logger.error(f"Failed to initialize database pool: {str(e)}")
            raise

    def getconn(self):
        """Get a connection from the pool"""
        try:
            conn = self.connection_pool.getconn()
            logger.debug("Connection acquired from pool")
            return conn
        except Exception as e:
            logger.error(f"Failed to acquire connection: {str(e)}")
            raise

    def putconn(self, conn):
        """Return a connection to the pool"""
        try:
            self.connection_pool.putconn(conn)
            logger.debug("Connection returned to pool")
        except Exception as e:
            logger.error(f"Failed to return connection: {str(e)}")
            raise

    def closeall(self):
        """Close all connections in the pool"""
        try:
            self.connection_pool.closeall()
            logger.info("All database connections closed")
        except Exception as e:
            logger.error(f"Error closing connections: {str(e)}")


# Global pool instance
db_pool = DatabasePool()


def get_db_connection():
    """
    Get a database connection from the pool.
    Must be explicitly returned after use via db_pool.putconn().
    """
    return db_pool.getconn()


def _get_safe_query_string(query, conn=None):
    """
    Safely extract a loggable string from a query object.
    Truncates to 120 chars to avoid log bloat.
    """
    try:
        if hasattr(query, 'as_string') and conn:
            raw = query.as_string(conn)
        else:
            raw = str(query)
        return raw[:120] + ("..." if len(raw) > 120 else "")
    except Exception:
        return "[unable to extract query string]"


def execute_query(query, params=None, fetch_one=False, fetch_all=False,
                  cursor_factory=RealDictCursor):
    """
    Execute a SQL query with automatic connection management.

    Args:
        query      : SQL string or psycopg2 Composable object
        params     : Query parameters (tuple/list/dict)
        fetch_one  : Return a single row dict  (use for SELECT ... LIMIT 1)
        fetch_all  : Return all rows as a list (use for SELECT)
        cursor_factory: Defaults to RealDictCursor (row dicts)

    Returns:
        - Single row dict   if fetch_one=True
        - List of row dicts if fetch_all=True
        - None              if neither fetch flag is set
                            (safe for UPDATE / INSERT / DELETE)
    """
    conn = None
    try:
        conn = get_db_connection()

        with conn.cursor(cursor_factory=cursor_factory) as cursor:
            cursor.execute(query, params)

            result = None
            if fetch_all:
                result = cursor.fetchall()
            elif fetch_one:
                result = cursor.fetchone()

            # Commit for write operations (INSERT, UPDATE, DELETE)
            # Also commit INSERT...RETURNING which uses fetch_one=True
            is_select = str(query).strip().upper().startswith('SELECT')
            if not is_select:
                conn.commit()

            logger.info(f"Query executed: {_get_safe_query_string(query, conn)}")
            return result

    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass

        safe_query = _get_safe_query_string(query, conn)
        logger.error(f"Query execution failed: {str(e)}")
        logger.error(f"Query details: {safe_query}")
        if params:
            logger.error(f"Query params count: {len(params)} items")
        raise

    finally:
        if conn:
            db_pool.putconn(conn)


def execute_query_one(query, params=None, cursor_factory=RealDictCursor):
    """Convenience wrapper – SELECT that returns exactly one row or None."""
    return execute_query(query, params, fetch_one=True, cursor_factory=cursor_factory)


def execute_query_all(query, params=None, cursor_factory=RealDictCursor):
    """Convenience wrapper – SELECT that returns all matching rows."""
    return execute_query(query, params, fetch_all=True, cursor_factory=cursor_factory)


def execute_non_query(query, params=None):
    """Convenience wrapper for UPDATE / INSERT / DELETE (no RETURNING)."""
    return execute_query(query, params, fetch_one=False, fetch_all=False)


def execute_insert_returning(table_name, columns, values, returning_columns='id'):
    """
    Safely insert a row and return the value of one column (default: 'id').

    ✅ FIX v1.7: Parameter renamed from 'returning_column' to 'returning_columns'
                to match calling code in auth/routes.py and prevent TypeError.

    Args:
        table_name       : Target table name (string)
        columns          : List/tuple of column name strings
        values           : List/tuple of values matching columns
        returning_columns: Single column name to return (default 'id')
                           Note: Despite plural name, currently supports single column

    Returns:
        RealDictRow with the returning column, e.g. {'id': 42}
    """
    # ── Validation ────────────────────────────────────────────────────────────
    if not table_name or not isinstance(table_name, str):
        raise ValueError(f"table_name must be a non-empty string, got {type(table_name)}")

    if not columns or not isinstance(columns, (list, tuple)):
        raise ValueError(f"columns must be a list or tuple, got {type(columns)}")

    if len(columns) != len(values):
        raise ValueError(
            f"columns/values length mismatch: {len(columns)} cols vs {len(values)} vals"
        )

    for i, col in enumerate(columns):
        if col is None:
            raise ValueError(f"columns[{i}] is None – all column names must be strings")
        if not isinstance(col, str):
            raise ValueError(f"columns[{i}] must be a string, got {type(col)}: {col!r}")

    if not returning_columns or not isinstance(returning_columns, str):
        raise ValueError(
            f"returning_columns must be a non-empty string, got {type(returning_columns)}"
        )

    # ── Build parameterised query ─────────────────────────────────────────────
    query = SQL(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING {}"
    ).format(
        Identifier(table_name),
        SQL(', ').join(map(Identifier, columns)),
        SQL(', ').join([Placeholder()] * len(columns)),
        Identifier(returning_columns)
    )

    try:
        # INSERT ... RETURNING behaves like SELECT – use fetch_one=True
        # Convert Composed query to string to avoid attribute errors
        query_str = str(query)
        result = execute_query(query_str, tuple(values), fetch_one=True)

        if result is None:
            logger.warning(f"Insert into '{table_name}' returned no row")
            return {returning_columns: None}

        logger.info(f"Insert successful into '{table_name}': {result}")
        return result

    except Exception as e:
        logger.error(f"Insert failed into '{table_name}': {str(e)}")
        raise


def batch_execute_queries(queries_with_params):
    """
    Execute multiple queries inside a single transaction.

    Each item in queries_with_params is a tuple:
        (query_string, params, fetch)   – fetch is optional bool, default False
    OR the legacy 2-tuple:
        (query_string, params)

    Returns a list of results (None for DML, rows for SELECT).
    """
    conn = None
    try:
        conn = get_db_connection()
        results = []

        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            for item in queries_with_params:
                if len(item) == 3:
                    query, params, do_fetch = item
                else:
                    query, params = item
                    do_fetch = False

                cursor.execute(query, params)

                if do_fetch and cursor.description:
                    results.append(cursor.fetchall())
                else:
                    results.append(None)

        conn.commit()
        logger.info(f"Batch execution completed: {len(queries_with_params)} queries")
        return results

    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        logger.error(f"Batch execution failed: {str(e)}")
        raise

    finally:
        if conn:
            db_pool.putconn(conn)


def check_database_connection():
    """Ping the database. Returns True if reachable, False otherwise."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        conn.commit()
        logger.info("Database connection check passed")
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {str(e)}")
        return False
    finally:
        if conn:
            db_pool.putconn(conn)


def cleanup_pool():
    """Gracefully close every connection in the pool (call on app shutdown)."""
    try:
        db_pool.closeall()
        logger.info("Database pool cleanup completed")
    except Exception as e:
        logger.error(f"Database pool cleanup error: {str(e)}")
        raise


# ── Public API ────────────────────────────────────────────────────────────────
__all__ = [
    'get_db_connection',
    'execute_query',
    'execute_query_one',
    'execute_query_all',
    'execute_non_query',
    'execute_insert_returning',
    'batch_execute_queries',
    'check_database_connection',
    'cleanup_pool',
    'db_pool',
]
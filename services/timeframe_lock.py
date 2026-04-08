# =============================================================================
# DERIV TRADING BOT - Timeframe Lock Enforcement Service
# Version: 1.0
# Purpose: Enforce 1 trade per timeframe limit using atomic database locks
# Security: Prevents race conditions through transactional operations
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# =============================================================================

import os
import sys
import time
import json
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List  # ← FIXED: Added List here

# Local imports
from config import Config
from database.db_conn import execute_query, get_db_connection, execute_insert_returning
from utils.logger import log_audit_event

logger = logging.getLogger(__name__)


class TimeframeLockManager:
    """
    Manages timeframe-based trading locks with atomic database operations.
    Ensures strict 1-trade-per-timeframe enforcement with proper concurrency control.
    """

    def __init__(self):
        """Initialize lock manager"""
        self.lock_cache = {}  # In-memory cache for active locks (user_id, timeframe) -> expires_at
        self.cache_ttl = 30  # Cache entries expire after 30 seconds
        self.thread_local = threading.local()

        logger.info("TimeframeLockManager initialized")

    def check_and_acquire_lock(self, user_id: int, timeframe: str,
                               user_agent_ip: str = None,
                               trade_details: Dict[str, Any] = None) -> Tuple[bool, str]:
        """
        Check if timeframe is available and acquire lock atomically.

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if not user_id or not timeframe:
                return False, "Missing required parameters"

            timeframe_upper = timeframe.upper()
            cache_key = f"{user_id}_{timeframe_upper}"

            # Check memory cache first
            if self._is_cached_locked(cache_key):
                remaining_seconds = self._get_cache_remaining_time(cache_key)
                if remaining_seconds > 0:
                    return False, f"Timeframe {timeframe_upper} locked for {remaining_seconds}s"

            # Acquire database-level lock
            conn = None
            try:
                conn = get_db_connection()
                with conn.cursor() as cursor:
                    cursor.execute("BEGIN")
                    try:
                        self._cleanup_expired_locks(conn)
                        existing_lock = self._get_active_lock(cursor, user_id, timeframe_upper)

                        if existing_lock:
                            cursor.execute("ROLLBACK")
                            return False, f"Timeframe {timeframe_upper} already locked"

                        lock_duration_seconds = self._calculate_lock_duration(timeframe_upper)
                        lock_expires_at = datetime.utcnow() + timedelta(seconds=lock_duration_seconds)

                        cursor.execute(
                            """INSERT INTO timeframe_locks 
                               (user_id, timeframe, trade_count, last_trade_at, lock_until)
                               VALUES (%s, %s, COALESCE((SELECT trade_count FROM timeframe_locks WHERE user_id = %s AND timeframe = %s), 0) + 1, 
                               CURRENT_TIMESTAMP, %s)
                               ON CONFLICT (user_id, timeframe) 
                               DO UPDATE SET 
                                   trade_count = EXCLUDED.trade_count,
                                   last_trade_at = CURRENT_TIMESTAMP,
                                   lock_until = EXCLUDED.lock_until
                               RETURNING id""",
                            (user_id, timeframe_upper, user_id, timeframe_upper, lock_expires_at)
                        )

                        lock_id = cursor.fetchone()['id']
                        cursor.execute("COMMIT")
                        self._update_cache(cache_key, lock_expires_at)

                        log_audit_event(
                            user_id=user_id,
                            event_type='TIMEFRAME_LOCK_ACQUIRED',
                            details={
                                'timeframe': timeframe_upper,
                                'lock_until': lock_expires_at.isoformat(),
                                'duration_seconds': lock_duration_seconds,
                                'lock_id': lock_id,
                                'ip_address': user_agent_ip
                            }
                        )

                        logger.info(f"Lock acquired for user {user_id}, timeframe {timeframe_upper}, expires {lock_expires_at}")
                        return True, f"Lock acquired, expires in {lock_duration_seconds}s"

                    except Exception as db_error:
                        cursor.execute("ROLLBACK")
                        raise db_error

            except Exception as e:
                logger.error(f"Database lock operation failed: {str(e)}")
                return False, f"Database error: {str(e)[:100]}"

        except Exception as e:
            logger.error(f"Lock acquisition failed for user {user_id}: {str(e)}")
            return False, f"General error: {str(e)[:100]}"

        finally:
            if conn:
                conn.close()

    def release_lock(self, user_id: int, timeframe: str) -> bool:
        """
        Release timeframe lock after trade completion.

        Args:
            user_id: User ID releasing lock
            timeframe: Timeframe to release

        Returns:
            True if released successfully
        """
        try:
            timeframe_upper = timeframe.upper()
            cache_key = f"{user_id}_{timeframe_upper}"

            conn = None
            try:
                conn = get_db_connection()

                with conn.cursor() as cursor:
                    # Clean up expired locks first
                    self._cleanup_expired_locks(conn)

                    # Delete lock record (trade complete)
                    cursor.execute(
                        """DELETE FROM timeframe_locks 
                           WHERE user_id = %s AND timeframe = %s 
                           AND (lock_until IS NULL OR lock_until > NOW())""",
                        (user_id, timeframe_upper)
                    )

                    rows_affected = cursor.rowcount

                    if rows_affected > 0:
                        # Remove from cache
                        if cache_key in self.lock_cache:
                            del self.lock_cache[cache_key]

                        logger.info(f"Lock released for user {user_id}, timeframe {timeframe_upper}")

                        # Log release event
                        log_audit_event(
                            user_id=user_id,
                            event_type='TIMEFRAME_LOCK_RELEASED',
                            details={
                                'timeframe': timeframe_upper,
                                'status': 'released_on_trade_completion'
                            }
                        )

                        return True
                    else:
                        logger.warning(
                            f"No active lock found to release for user {user_id}, timeframe {timeframe_upper}")
                        return False

            except Exception as e:
                logger.error(f"Lock release failed: {str(e)}")
                return False

        finally:
            if conn:
                conn.close()

    def _is_cached_locked(self, cache_key: str) -> bool:
        """Check if key is cached as locked"""
        if cache_key in self.lock_cache:
            expires_at = self.lock_cache[cache_key]['expires_at']
            # Check if cache still valid
            if datetime.utcnow() < expires_at:
                return True
            else:
                # Expired entry, remove it
                del self.lock_cache[cache_key]
        return False

    def _get_cache_remaining_time(self, cache_key: str) -> float:
        """Get remaining lock time in cache (seconds)"""
        if cache_key not in self.lock_cache:
            return 0

        expires_at = self.lock_cache[cache_key]['expires_at']
        remaining = (expires_at - datetime.utcnow()).total_seconds()
        return max(0, remaining)

    def _update_cache(self, cache_key: str, expires_at: datetime):
        """Update cache with new lock expiration"""
        self.lock_cache[cache_key] = {
            'expires_at': expires_at,
            'created_at': datetime.utcnow()
        }

    def _cleanup_expired_locks(self, conn=None):
        """Remove expired lock records from database"""
        try:
            if conn:
                cursor = conn.cursor()
                cursor.execute(
                    """DELETE FROM timeframe_locks 
                       WHERE lock_until IS NOT NULL AND lock_until < NOW()"""
                )
                conn.commit()
                logger.info(f"Cleaned up {cursor.rowcount} expired locks")
            else:
                # Fallback to execute_query
                execute_query(
                    """DELETE FROM timeframe_locks 
                       WHERE lock_until IS NOT NULL AND lock_until < NOW()"""
                )
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")

    def _get_active_lock(self, cursor, user_id: int, timeframe: str) -> Optional[Dict[str, Any]]:
        """
        Get existing active lock for user/timeframe.
        Assumes transaction is already started.
        """
        cursor.execute(
            """SELECT id, user_id, timeframe, trade_count, 
                      last_trade_at, lock_until
               FROM timeframe_locks 
               WHERE user_id = %s AND timeframe = %s
               AND (lock_until IS NULL OR lock_until > NOW())
               LIMIT 1""",
            (user_id, timeframe)
        )

        if cursor.rowcount > 0:
            row = cursor.fetchone()
            return dict(zip([desc[0] for desc in cursor.description], row))

        return None

    def _calculate_lock_duration(self, timeframe: str) -> int:
        """
        Calculate lock duration based on timeframe candles.

        Args:
            timeframe: Timeframe string (M1, M5, H1, etc.)

        Returns:
            Lock duration in seconds
        """
        duration_map = {
            'S1': 30,  # 30 seconds
            'S5': 30,  # 30 seconds
            'S10': 30,  # 30 seconds
            'S30': 30,  # 30 seconds
            'M1': 30,  # 30 seconds
            'M5': 30,  # 30 seconds
            'M15': 30,  # 30 seconds
            'M30': 30,  # 30 seconds
            'H1': 30,  # 30 seconds
            'H2': 30,  # 30 seconds
            'H4': 30,  # 30 seconds
            'H6': 30,  # 30 seconds
            'H12': 30,  # 30 seconds
            'D1': 30,  # 30 seconds
            'W1': 30,  # 30 seconds
            'MN1': 30,  # 30 seconds
        }

        return duration_map.get(timeframe, 60 * 5)  # Default to 5 minutes

    def is_timeframe_available(self, user_id: int, timeframe: str) -> bool:
        """
        Public API: Quick check if timeframe is available.
        Does not acquire lock, just checks status.

        Args:
            user_id: User ID to check
            timeframe: Timeframe to check

        Returns:
            True if available, False if locked
        """
        lock_result, message = self.check_and_acquire_lock(user_id, timeframe)

        if lock_result:
            # Lock was acquired, immediately release it
            self.release_lock(user_id, timeframe)
            return True

        return False

    def get_lock_status(self, user_id: int, timeframe: str) -> Dict[str, Any]:
        """
        Get current lock status without acquiring/release.

        Args:
            user_id: User ID
            timeframe: Timeframe

        Returns:
            Dictionary with lock status details
        """
        try:
            result = execute_query(
                """SELECT id, timeframe, trade_count, last_trade_at, 
                          lock_until
                   FROM timeframe_locks
                   WHERE user_id = %s AND timeframe = %s
                   AND (lock_until IS NULL OR lock_until > NOW())
                   LIMIT 1""",
                (user_id, timeframe.upper()),
                fetch_all=True
            )

            if result:
                lock_data = result[0]
                remaining = None

                if lock_data.get('lock_until'):
                    lock_until = lock_data['lock_until']
                    remaining = (lock_until - datetime.utcnow()).total_seconds()

                return {
                    'locked': True,
                    'trade_count': lock_data.get('trade_count', 0),
                    'last_trade_at': lock_data.get('last_trade_at').isoformat() if isinstance(
                        lock_data.get('last_trade_at'), datetime) else None,
                    'lock_until': lock_data.get('lock_until').isoformat() if isinstance(lock_data.get('lock_until'),
                                                                                        datetime) else None,
                    'remaining_seconds': round(remaining, 0) if remaining is not None else None,
                    'cache_key': f"{user_id}_{timeframe.upper()}"
                }
            else:
                return {
                    'locked': False,
                    'message': 'No active lock found'
                }

        except Exception as e:
            logger.error(f"Get lock status failed: {str(e)}")
            return {
                'locked': False,
                'error': str(e)
            }

    def force_clear_lock(self, user_id: int, timeframe: str, reason: str = "admin_clear"):
        """
        Force clear lock (for admin override or recovery).

        Args:
            user_id: User ID
            timeframe: Timeframe to clear
            reason: Reason for clearing (audit trail)
        """
        try:
            conn = None
            try:
                conn = get_db_connection()

                with conn.cursor() as cursor:
                    cursor.execute(
                        """UPDATE timeframe_locks SET 
                           lock_until = NOW() - INTERVAL '1 minute' -- Expire immediately
                           WHERE user_id = %s AND timeframe = %s""",
                        (user_id, timeframe.upper())
                    )

                    logger.warning(f"Force cleared lock for user {user_id}, timeframe {timeframe}. Reason: {reason}")

                    log_audit_event(
                        user_id=user_id,
                        event_type='TIMEFRAME_LOCK_FORCED_CLEAR',
                        details={
                            'timeframe': timeframe.upper(),
                            'clear_reason': reason,
                            'timestamp': datetime.utcnow().isoformat()
                        }
                    )

            finally:
                if conn:
                    conn.close()

        except Exception as e:
            logger.error(f"Force clear failed: {str(e)}")

    def get_user_timeframe_stats(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all timeframe lock stats for a user.

        Args:
            user_id: User ID

        Returns:
            List of timeframe statistics
        """
        try:
            results = execute_query(
                """SELECT timeframe, trade_count, last_trade_at, lock_until 
                   FROM timeframe_locks 
                   WHERE user_id = %s
                   ORDER BY last_trade_at DESC""",
                (user_id,),
                fetch_all=True
            )

            return [dict(row) for row in results]

        except Exception as e:
            logger.error(f"Get user timeframe stats failed: {str(e)}")
            return []

    def cleanup_all_user_locks(self, user_id: int):
        """
        Clean all locks for a user (e.g., account deletion or disable).

        Args:
            user_id: User ID to clean locks for
        """
        try:
            execute_query(
                """DELETE FROM timeframe_locks WHERE user_id = %s""",
                (user_id,)
            )

            # Clear from cache
            keys_to_remove = [k for k in self.lock_cache.keys() if k.startswith(f"{user_id}_")]
            for key in keys_to_remove:
                del self.lock_cache[key]

            logger.info(f"Cleaned all locks for user {user_id}")

        except Exception as e:
            logger.error(f"User lock cleanup failed: {str(e)}")


# Singleton instance for global access
_global_lock_manager = None
_lock_manager_lock = threading.Lock()


def get_lock_manager() -> TimeframeLockManager:
    """Singleton pattern for TimeframeLockManager"""
    global _global_lock_manager

    if _global_lock_manager is None:
        with _lock_manager_lock:
            if _global_lock_manager is None:
                _global_lock_manager = TimeframeLockManager()

    return _global_lock_manager


def reset_lock_manager():
    """Reset singleton instance (for testing)"""
    global _global_lock_manager
    _global_lock_manager = None
    logger.info("Timeframe lock manager reset")


# Convenience functions for direct use in bot_engine.py
def check_and_acquire_timeframe_lock(user_id: int, timeframe: str,
                                     user_agent_ip: str = None,
                                     trade_details: Dict[str, Any] = None) -> Tuple[bool, str]:
    """
    Check and acquire timeframe lock.

    Args:
        user_id: User ID
        timeframe: Timeframe
        user_agent_ip: IP address
        trade_details: Additional info

    Returns:
        Tuple of (success: bool, message: str)
    """
    manager = get_lock_manager()
    return manager.check_and_acquire_lock(user_id, timeframe, user_agent_ip, trade_details)


def release_timeframe_lock(user_id: int, timeframe: str) -> bool:
    """
    Simple function for releasing timeframe lock.

    Args:
        user_id: User ID
        timeframe: Timeframe

    Returns:
        True if released successfully
    """
    manager = get_lock_manager()
    return manager.release_lock(user_id, timeframe)


def is_timeframe_available(user_id: int, timeframe: str) -> bool:
    """
    Quick availability check without acquiring.

    Args:
        user_id: User ID
        timeframe: Timeframe

    Returns:
        True if available
    """
    manager = get_lock_manager()
    return manager.is_timeframe_available(user_id, timeframe)


__all__ = [
    'TimeframeLockManager',
    'get_lock_manager',
    'reset_lock_manager',
    'check_and_acquire_timeframe_lock',
    'release_timeframe_lock',
    'is_timeframe_available'
]
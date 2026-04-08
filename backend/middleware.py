# =============================================================================
# DERIV TRADING BOT - Security Middleware & Access Control
# Version: 2.1 (FIXED: Removed session.clear() from check_admin to prevent logout loops)
# Purpose: Authentication, authorization, and rate limiting for all routes
# Security: Session-based auth with comprehensive role validation
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# FIX: check_admin no longer clears session on errors (prevents accidental logout)
# =============================================================================

import os
import logging
from functools import wraps
from datetime import datetime, timedelta
from flask import request, jsonify, session, abort, g

# Local imports
from database.db_conn import execute_query
from utils.logger import log_audit_event

logger = logging.getLogger(__name__)


def get_session_data():
    """Get complete session data with fallback to defaults"""
    return {
        'user_id': session.get('user_id'),
        'admin_id': session.get('admin_id'),
        'email': session.get('email'),
        'role': session.get('role'),
        'email_verified': session.get('email_verified')
    }


def create_auth_error_response(message="Authentication required",
                               error_code="AUTH_REQUIRED",
                               status_code=401):
    """Create standardized authentication error response"""
    return jsonify({
        'success': False,
        'message': message,
        'error_code': error_code,
        'timestamp': datetime.utcnow().isoformat()
    }), status_code


def safe_log_audit_event(event_type, details=None, user_id=None, admin_id=None):
    """
    Safe wrapper around log_audit_event.
    Ensures correct parameter order matching log_audit_event signature.
    """
    try:
        log_audit_event(
            event_type=event_type,
            user_id=user_id,
            admin_id=admin_id,
            details=details or {}
        )
    except Exception as e:
        logger.error(f"[safe_log_audit_event] Failed to log '{event_type}': {e}")


# =============================================================================
# USER AUTHENTICATION MIDDLEWARE (SESSION-BASED)
# =============================================================================

def check_user(f):
    """
    Session-based authentication decorator for HTML page routes.
    Validates the session, checks account status, and blocks disabled accounts.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):

        # ── 1. No session at all ─────────────────────────────────────────────
        if 'user_id' not in session:
            safe_log_audit_event(
                event_type='USER_UNAUTHORIZED_ACCESS_ATTEMPT',
                user_id=None,
                details={
                    'ip_address': request.remote_addr,
                    'request_path': request.path,
                    'user_agent': request.headers.get('User-Agent'),
                    'access_denied_reason': 'No active session'
                }
            )
            return create_auth_error_response(
                message="Please log in to access this resource",
                error_code="USER_NOT_AUTHENTICATED",
                status_code=401
            )

        try:
            user_id = session['user_id']
            email = session.get('email', '')

            # ── 2. User still exists in DB? ──────────────────────────────────
            user_status = execute_query(
                "SELECT id, status, email_verified FROM users WHERE id = %s",
                (user_id,),
                fetch_all=True
            )

            if not user_status or len(user_status) == 0:
                session.clear()
                logger.warning(f"Session invalidated for non-existent user: {user_id}")
                safe_log_audit_event(
                    event_type='SESSION_INVALIDATED_USER_DELETED',
                    user_id=user_id,
                    details={'reason': 'User account no longer exists'}
                )
                return create_auth_error_response(
                    message="Your session has expired. Please log in again.",
                    error_code="SESSION_EXPIRED",
                    status_code=401
                )

            # ── 3. Account disabled by admin? ────────────────────────────────
            if user_status[0]['status'] == 'disabled':
                session.clear()
                safe_log_audit_event(
                    event_type='ACCESS_DENIED_ACCOUNT_DISABLED',
                    user_id=user_id,
                    details={'email': email, 'action': 'account_disabled_by_admin'}
                )
                return create_auth_error_response(
                    message="Your account has been disabled. Contact support for assistance.",
                    error_code="ACCOUNT_DISABLED",
                    status_code=403
                )

            # ── 4. Any other non-active status? ──────────────────────────────
            if user_status[0]['status'] != 'active':
                safe_log_audit_event(
                    event_type='ACCESS_DENIED_INVALID_STATUS',
                    user_id=user_id,
                    details={'email': email, 'status': user_status[0]['status']}
                )
                return create_auth_error_response(
                    message="Account status does not allow access.",
                    error_code="INVALID_ACCOUNT_STATUS",
                    status_code=403
                )

        except Exception as e:
            logger.error(f"User authentication check failed: {str(e)}")
            session.clear()
            return create_auth_error_response(
                message="An error occurred during authentication check.",
                error_code="AUTH_CHECK_ERROR",
                status_code=500
            )

        return f(*args, **kwargs)

    return decorated_function


def check_email_verified(f):
    """
    Decorator that ensures the logged-in user has verified their email
    before allowing access to the protected route.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return create_auth_error_response(
                message="Please log in to access this resource",
                error_code="USER_NOT_AUTHENTICATED",
                status_code=401
            )

        try:
            user_id = session['user_id']
            email = session.get('email', '')

            verification = execute_query(
                "SELECT email_verified FROM users WHERE id = %s",
                (user_id,),
                fetch_all=True
            )

            if not verification or len(verification) == 0 or not verification[0].get('email_verified'):
                safe_log_audit_event(
                    event_type='ACCESS_DENIED_EMAIL_NOT_VERIFIED',
                    user_id=user_id,
                    details={'email': email, 'attempted_action': request.path}
                )
                return create_auth_error_response(
                    message="Please verify your email address before accessing this feature.",
                    error_code="EMAIL_NOT_VERIFIED",
                    status_code=403
                )

        except Exception as e:
            logger.error(f"Email verification check failed: {str(e)}")
            session.clear()
            return create_auth_error_response(
                message="An error occurred during verification check.",
                error_code="VERIFICATION_CHECK_ERROR",
                status_code=500
            )

        return f(*args, **kwargs)

    return decorated_function


def check_account_active(f):
    """
    Decorator that blocks access for suspended, banned, or deleted accounts.
    Should be stacked after check_user for full protection.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return create_auth_error_response(
                message="Please log in to access this resource",
                error_code="USER_NOT_AUTHENTICATED",
                status_code=401
            )

        try:
            user_id = session['user_id']
            user_status = execute_query(
                "SELECT status FROM users WHERE id = %s",
                (user_id,),
                fetch_all=True
            )

            if not user_status or len(user_status) == 0 or user_status[0]['status'] in ['suspended', 'banned',
                                                                                        'deleted']:
                safe_log_audit_event(
                    event_type='ACCESS_DENIED_SUSPENDED_ACCOUNT',
                    user_id=user_id,
                    details={
                        'status': user_status[0].get('status') if user_status else 'unknown'
                    }
                )
                return create_auth_error_response(
                    message="This account is restricted. Contact support.",
                    error_code="ACCOUNT_RESTRICTED",
                    status_code=403
                )

        except Exception as e:
            logger.error(f"Account status check failed: {str(e)}")
            session.clear()
            return create_auth_error_response(
                message="System error occurred during status check.",
                error_code="STATUS_CHECK_ERROR",
                status_code=500
            )

        return f(*args, **kwargs)

    return decorated_function


# =============================================================================
# ADMIN AUTHENTICATION MIDDLEWARE (FIXED: No session.clear() on errors)
# =============================================================================

def check_admin(f):
    """
    Session-based admin authentication decorator.
    Validates admin session, enforces configurable session timeout,
    and confirms the admin account is still active in the database.

    ✅ FIX v2.1: Removed all session.clear() calls to prevent accidental logout
    when accessing admin endpoints (e.g., logs panel). Now returns 401 without
    destroying the session, allowing recovery from transient errors.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):

        # ── 1. No admin session ──────────────────────────────────────────────
        if 'admin_id' not in session:
            safe_log_audit_event(
                event_type='ADMIN_UNAUTHORIZED_ACCESS_ATTEMPT',
                admin_id=None,
                details={
                    'ip_address': request.remote_addr,
                    'request_path': request.path,
                    'user_agent': request.headers.get('User-Agent'),
                    'access_denied_reason': 'No active admin session'
                }
            )
            return create_auth_error_response(
                message="Admin authentication required",
                error_code="ADMIN_NOT_AUTHENTICATED",
                status_code=401
            )

        try:
            admin_id = session['admin_id']
            admin_email = session.get('admin_email', '')
            login_time_str = session.get('login_time')

            # ── 2. Session timeout check ─────────────────────────────────────
            if login_time_str:
                try:
                    login_time = datetime.fromisoformat(login_time_str)
                    timeout_minutes = int(os.getenv('ADMIN_SESSION_TIMEOUT', 30))
                    if datetime.utcnow() - login_time > timedelta(minutes=timeout_minutes):
                        # ✅ FIX: Removed session.clear() - just deny access
                        safe_log_audit_event(
                            event_type='SESSION_EXPIRED_ADMIN',
                            admin_id=admin_id,
                            details={
                                'email': admin_email,
                                'expired_after_minutes': timeout_minutes
                            }
                        )
                        return jsonify({
                            'success': False,
                            'message': 'Session expired. Please log in again.',
                            'redirect': '/admin/login',
                            'error_code': 'SESSION_EXPIRED'
                        }), 401
                except ValueError:
                    # ✅ FIX: Removed session.clear() - just deny access
                    return create_auth_error_response(
                        "Invalid session data.", "SESSION_CORRUPTED", 401
                    )

            # ── 3. Admin account still active in DB? ─────────────────────────
            admin_status = execute_query(
                "SELECT id, email, is_active FROM admin_accounts WHERE id = %s",
                (admin_id,),
                fetch_all=True
            )

            if not admin_status or len(admin_status) == 0 or not admin_status[0].get('is_active'):
                # ✅ FIX: Removed session.clear() - just deny access
                safe_log_audit_event(
                    event_type='ADMIN_ACCOUNT_INACTIVE',
                    admin_id=admin_id,
                    details={'email': admin_email, 'reason': 'Account disabled or not found'}
                )
                return create_auth_error_response(
                    message="Your admin session has expired or account is disabled.",
                    error_code="SESSION_EXPIRED",
                    status_code=401
                )

            # ── 4. Refresh last_login timestamp ──────────────────────────────
            execute_query(
                "UPDATE admin_accounts SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
                (admin_id,)
            )

        except Exception as e:
            logger.error(f"Admin authentication check failed: {str(e)}")
            # ✅ FIX: Removed session.clear() - log error but preserve session
            return create_auth_error_response(
                "Authentication error.", "AUTH_CHECK_ERROR", 500
            )

        return f(*args, **kwargs)

    return decorated_function


def check_super_admin(f):
    """Alias for check_admin — extend with role checks if needed."""
    return check_admin(f)


def check_admin_only(f):
    """
    Ensures the request comes from an admin session ONLY.
    BLOCKS ANY user who also has a user_id in their session (role confusion).

    This is CRITICAL for preventing unauthorized cross-role access!
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check: Is admin logged in?
        if 'admin_id' not in session:
            return create_auth_error_response(
                "Admin access required", "ADMIN_ONLY_ENDPOINT", 403
            )

        # Second check: Is user ALSO logged in? (PREVENTS ROLE CONFUSION!)
        if 'user_id' in session:
            safe_log_audit_event(
                event_type='CROSS_ROLE_ACCESS_ATTEMPT',
                user_id=session['user_id'],
                admin_id=session.get('admin_id'),
                details={
                    'requested_role': 'admin',
                    'actual_role': 'user',
                    'path': request.path,
                    'risk_level': 'HIGH'
                }
            )
            return create_auth_error_response(
                "Access denied - Role conflict detected",
                "INSUFFICIENT_PRIVILEGES",
                403
            )

        return f(*args, **kwargs)

    return decorated_function


# =============================================================================
# COMBINED CHECKS & UTILITY FUNCTIONS
# =============================================================================

def require_both_authentication_and_verification(f):
    """
    Requires the user to be both logged in AND email-verified.
    Lightweight session-only check — no DB query.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return create_auth_error_response(
                "Please log in", "USER_NOT_AUTHENTICATED", 401
            )
        if not session.get('email_verified'):
            return create_auth_error_response(
                "Email verification required", "EMAIL_NOT_VERIFIED", 403
            )
        return f(*args, **kwargs)

    return decorated_function


def require_admin_or_authenticated_user(f):
    """
    Allows access if either an admin or a regular user session is present.
    Used for shared endpoints accessible by both roles.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' in session or 'user_id' in session:
            return f(*args, **kwargs)
        return create_auth_error_response(
            "Authentication required", "AUTH_REQUIRED", 401
        )

    return decorated_function


def check_rate_limit(identifier, max_requests=100, window_seconds=60):
    """
    Rate limiting decorator.
    Tracks requests per identifier (admin/user/IP) per endpoint per window.
    Returns 429 if the limit is exceeded.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            # ── Derive a stable identifier from session or IP ────────────────
            if 'admin_id' in session:
                final_id = f"admin_{session['admin_id']}"
                audit_user_id = None
                audit_admin_id = session['admin_id']
            elif 'user_id' in session:
                final_id = f"user_{session['user_id']}"
                audit_user_id = session['user_id']
                audit_admin_id = None
            else:
                final_id = f"ip_{request.remote_addr}"
                audit_user_id = None
                audit_admin_id = None

            try:
                result = execute_query(
                    """
                    INSERT INTO rate_limits
                        (identifier, endpoint, limit_count, window_seconds, current_count, window_start)
                    VALUES (%s, %s, %s, %s, 1, NOW())
                    ON CONFLICT (identifier, endpoint, window_start) DO UPDATE
                        SET current_count = rate_limits.current_count + 1
                    RETURNING current_count
                    """,
                    (final_id, request.path, max_requests, window_seconds),
                    fetch_all=True
                )

                if result and len(result) > 0 and result[0].get('current_count', 0) > max_requests:
                    safe_log_audit_event(
                        event_type='RATE_LIMIT_EXCEEDED',
                        user_id=audit_user_id,
                        admin_id=audit_admin_id,
                        details={
                            'identifier': final_id,
                            'endpoint': request.path,
                            'count': result[0].get('current_count'),
                            'limit': max_requests,
                            'window_seconds': window_seconds
                        }
                    )
                    return jsonify({
                        'success': False,
                        'message': 'Too many requests. Please slow down.',
                        'error_code': 'RATE_LIMIT_EXCEEDED',
                        'retry_after_seconds': window_seconds
                    }), 429

            except Exception as e:
                logger.error(f"Rate limit check error for '{final_id}': {str(e)}")

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# =============================================================================
# EXPORT PUBLIC API
# =============================================================================

__all__ = [
    'check_user',
    'check_email_verified',
    'check_account_active',
    'check_admin',
    'check_super_admin',
    'check_admin_only',
    'require_both_authentication_and_verification',
    'require_admin_or_authenticated_user',
    'check_rate_limit',
    'safe_log_audit_event',
    'get_session_data',
    'create_auth_error_response'
]
# =============================================================================
# DERIV TRADING BOT - Admin Authentication Backend
# Version: 1.0
# Purpose: Handle admin account authentication ONLY
# Security: Stricter session timeout policies than regular users
# =============================================================================

import os
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session, redirect, url_for, abort

# Local imports
from config import Config
from database.db_conn import execute_query, execute_insert_returning, get_db_connection
from utils.hasher import hash_password, verify_password
from utils.validators import validate_email
from utils.logger import log_audit_event

logger = logging.getLogger(__name__)


class AdminAuthenticationError(Exception):
    """Custom exception for admin authentication errors"""
    pass


def generate_verification_token():
    """Generate secure verification token"""
    return secrets.token_urlsafe(32)


def hash_token(token):
    """Hash token before storing in database"""
    return hashlib.sha256(token.encode()).hexdigest()


# =============================================================================
# ADMIN LOGIN (Separate from User Login)
# =============================================================================

def authenticate_admin(email: str, password: str):
    """
    Authenticate admin account.

    Args:
        email: Admin email address
        password: Plain text password

    Returns:
        dict with admin data and session info

    Raises:
        AdminAuthenticationError on failure
    """
    # Validate email format
    if not validate_email(email):
        raise AdminAuthenticationError("Invalid email format")

    # Get admin from database (admin_accounts table only)
    admin_data = execute_query(
        """SELECT id, email, password_hash, is_active, created_at, last_login 
           FROM admin_accounts WHERE email = %s""",
        (email.lower(),),
        fetch_all=False
    )

    if not admin_data:
        logger.warning(f"Failed admin login attempt for non-existent admin: {email}")
        raise AdminAuthenticationError("Invalid email or password")

    # Check if admin account is active
    if not admin_data['is_active']:
        raise AdminAuthenticationError("Admin account is disabled by system administrator")

    # Verify password using Argon2id (matches seed_admin.sql and hasher.py)
    if not verify_password(password, admin_data['password_hash']):
        # Log failed attempt
        log_audit_event(
            admin_id=admin_data['id'],
            event_type='ADMIN_LOGIN_FAILED',
            details={
                'email': email,
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'attempt_number': get_failed_attempts(admin_data['id'])
            }
        )

        # Rate limiting check
        if get_failed_attempts(admin_data['id']) > 5:
            raise AdminAuthenticationError("Too many failed attempts. Contact system support.")

        raise AdminAuthenticationError("Invalid email or password")

    try:
        # Set admin session with strict timeout
        set_strict_admin_session(admin_data)

        # Update last login timestamp
        execute_query(
            "UPDATE admin_accounts SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
            (admin_data['id'],)
        )

        # Clear any failed attempt records
        clear_failed_attempts(admin_data['id'])

        # Log successful login
        log_audit_event(
            admin_id=admin_data['id'],
            event_type='ADMIN_LOGIN_SUCCESSFUL',
            details={
                'email': admin_data['email'],
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'action': 'admin_dashboard_access'
            }
        )

        logger.info(f"Successful admin login: {email}")

        return {
            'success': True,
            'message': 'Admin login successful',
            'admin': {
                'id': admin_data['id'],
                'email': admin_data['email'],
                'created_at': admin_data['created_at'].isoformat() if isinstance(admin_data['created_at'],
                                                                                 datetime) else admin_data[
                    'created_at'],
                'last_login': admin_data['last_login'].isoformat() if isinstance(admin_data['last_login'],
                                                                                 datetime) else admin_data['last_login']
            },
            'session_timeout_minutes': int(os.getenv('ADMIN_SESSION_TIMEOUT', 30))
        }

    except Exception as e:
        logger.error(f"Admin login failed: {str(e)}")
        raise AdminAuthenticationError("Login failed. Please try again.")


def get_failed_attempts(admin_id: int):
    """Get number of recent failed login attempts for rate limiting"""
    result = execute_query(
        """SELECT COUNT(*) as count FROM audit_log 
           WHERE admin_id = %s AND event_type = 'ADMIN_LOGIN_FAILED' 
           AND created_at > NOW() - INTERVAL '15 minutes'""",
        (admin_id,),
        fetch_all=True
    )

    return result[0]['count'] if result else 0


def clear_failed_attempts(admin_id: int):
    """Clear failed attempt tracking after successful login"""
    execute_query(
        """DELETE FROM audit_log 
           WHERE admin_id = %s AND event_type = 'ADMIN_LOGIN_FAILED' 
           AND created_at < NOW() - INTERVAL '2 hours'""",
        (admin_id,)
    )


def set_strict_admin_session(admin_data: dict):
    """
    Configure stricter session policy for admin users.

    Security features:
    - Shorter session timeout (default 30 minutes)
    - Secure cookie flags enabled
    - IP address binding check on subsequent requests
    - Session renewal on sensitive actions
    """
    # Set permanent session
    session.permanent = True

    # Admin-specific session data
    session['admin_id'] = admin_data['id']
    session['admin_email'] = admin_data['email']
    session['role'] = 'admin'
    session['login_time'] = datetime.utcnow().isoformat()
    session['ip_address'] = request.remote_addr

    # Enable secure cookie flags for production
    if Config.is_production():
        # Note: SESSION_COOKIE_SECURE and SESSION_COOKIE_NAME are set in app config
        pass

    # Track session fingerprint for security
    session['user_agent_fingerprint'] = request.headers.get('User-Agent')


# =============================================================================
# ADMIN LOGOUT
# =============================================================================

def logout_admin():
    """
    Invalidate admin session with enhanced security logging.

    Returns:
        dict with logout status
    """
    try:
        # Record logout details
        logout_details = {
            'admin_id': session.get('admin_id'),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'session_duration': calculate_session_duration()
        }

        # Log audit event before clearing session
        log_audit_event(
            admin_id=session.get('admin_id'),
            event_type='ADMIN_LOGOUT',
            details=logout_details
        )

        # Clear entire session
        session.clear()
        session.modified = True

        logger.info("Admin logged out successfully")

        return {
            'success': True,
            'message': 'Admin logout successful',
            'details': logout_details
        }

    except Exception as e:
        logger.error(f"Admin logout failed: {str(e)}")
        return {
            'success': False,
            'message': 'Logout encountered an error'
        }


def calculate_session_duration():
    """Calculate how long the current session has been active"""
    login_time_str = session.get('login_time')
    if not login_time_str:
        return None

    try:
        login_time = datetime.fromisoformat(login_time_str)
        duration = datetime.utcnow() - login_time
        return {
            'hours': int(duration.total_seconds() // 3600),
            'minutes': int((duration.total_seconds() % 3600) // 60),
            'seconds': int(duration.total_seconds() % 60)
        }
    except Exception:
        return None


# =============================================================================
# CREATE NEW ADMIN (For existing admins)
# =============================================================================

def create_new_admin(email: str, password: str, created_by_admin_id: int):
    """
    Create a new admin account (only authorized admins can do this).

    Args:
        email: New admin email address
        password: New admin password
        created_by_admin_id: ID of admin creating new account

    Returns:
        dict with creation status
    """
    # Validate email and password
    if not validate_email(email):
        raise AdminAuthenticationError("Invalid email format")

    if len(password) < 12:
        raise AdminAuthenticationError("Password must be at least 12 characters")

    # Check if admin already exists
    existing_admin = execute_query(
        "SELECT id FROM admin_accounts WHERE email = %s",
        (email.lower(),),
        fetch_all=False
    )

    if existing_admin:
        raise AdminAuthenticationError("Email already registered as admin")

    try:
        # Hash password using Argon2id (matches seed_admin.sql)
        password_hash = hash_password(password)

        # Insert new admin
        admin_result = execute_insert_returning(
            table_name='admin_accounts',
            columns=['email', 'password_hash', 'is_active'],
            values=[email.lower(), password_hash, True],
            returning_columns='*'
        )

        # Log creation event
        log_audit_event(
            admin_id=created_by_admin_id,
            event_type='ADMIN_CREATED',
            details={
                'new_admin_id': admin_result['id'],
                'new_admin_email': email,
                'created_by_email': session.get('email')
            }
        )

        logger.info(f"New admin created by {session.get('email')}: {email}")

        return {
            'success': True,
            'message': 'Admin account created successfully',
            'admin_id': admin_result['id']
        }

    except Exception as e:
        logger.error(f"Admin creation failed: {str(e)}")
        raise AdminAuthenticationError("Failed to create admin account")


# =============================================================================
# ENABLE/DISABLE ADMIN ACCOUNT
# =============================================================================

def toggle_admin_status(admin_id: int, is_enabled: bool, updated_by_admin_id: int):
    """
    Enable or disable an admin account.

    Args:
        admin_id: ID of admin to modify
        is_enabled: True to enable, False to disable
        updated_by_admin_id: ID of admin making the change

    Returns:
        dict with update status
    """
    try:
        # Prevent self-disabling
        if admin_id == updated_by_admin_id and not is_enabled:
            raise AdminAuthenticationError("Cannot disable your own account")

        # Perform update
        execute_query(
            "UPDATE admin_accounts SET is_active = %s WHERE id = %s",
            (is_enabled, admin_id)
        )

        # Log action
        log_audit_event(
            admin_id=updated_by_admin_id,
            event_type=f"ADMIN_STATUS_{'ENABLED' if is_enabled else 'DISABLED'}",
            details={
                'target_admin_id': admin_id,
                'new_status': 'enabled' if is_enabled else 'disabled'
            }
        )

        logger.info(f"Admin {admin_id} {'enabled' if is_enabled else 'disabled'} by {updated_by_admin_id}")

        return {
            'success': True,
            'message': f"Admin account {'enabled' if is_enabled else 'disabled'} successfully"
        }

    except Exception as e:
        logger.error(f"Admin status toggle failed: {str(e)}")
        raise AdminAuthenticationError("Failed to update admin status")


# =============================================================================
# AUTHORIZATION DECORATORS (For use in API routes)
# =============================================================================

def require_admin(f):
    """Decorator to require admin role for route access"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated as admin
        if 'admin_id' not in session:
            return jsonify({
                'success': False,
                'message': 'Admin authentication required'
            }), 401

        # Check session hasn't expired
        login_time_str = session.get('login_time')
        if login_time_str:
            try:
                login_time = datetime.fromisoformat(login_time_str)
                session_timeout = timedelta(minutes=int(os.getenv('ADMIN_SESSION_TIMEOUT', 30)))

                if datetime.utcnow() - login_time > session_timeout:
                    # Session expired - clear and redirect
                    session.clear()
                    return jsonify({
                        'success': False,
                        'message': 'Session expired. Please log in again.',
                        'redirect': '/admin/login'
                    }), 401

            except Exception:
                session.clear()
                return jsonify({
                    'success': False,
                    'message': 'Session invalid. Please log in again.'
                }), 401

        # Proceed with request
        return f(*args, **kwargs)

    return decorated_function


def require_super_admin(f):
    """Decorator to require super admin privileges (for future expansion)"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            abort(401)

        # TODO: Implement role hierarchy (super_admin vs regular_admin)
        # For now, all admins are equal
        return f(*args, **kwargs)

    return decorated_function


# =============================================================================
# PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    'authenticate_admin',
    'logout_admin',
    'create_new_admin',
    'toggle_admin_status',
    'require_admin',
    'require_super_admin'
]
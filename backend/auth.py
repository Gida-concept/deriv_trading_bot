# DERIV TRADING BOT - User & Admin Authentication Backend (FIXED v1.9)
# Version: 1.9 (FIXED: Registration redirect issue, Added system setting check)
# Purpose: Handle registration, login, logout, password reset, and email resending
# Security: Email verification required before login access
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# FIXES: 
#   1. Added get_system_setting() helper function.
#   2. Added allow_registration check to /register route.
#   3. Fixed boolean parsing for system settings.
#   4. Default allow_registration to True if setting is missing.
# =============================================================================

import os
import secrets
import hashlib
import hmac
import uuid
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify, session, redirect, url_for, abort, send_from_directory, flash

# Local imports
from config import Config
from database.db_conn import execute_query, execute_insert_returning, get_db_connection
from utils.hasher import hash_password, verify_password
from utils.email_sender import send_verification_email, send_reset_email
from utils.validators import validate_email_address, validate_password_strength
from utils.logger import log_audit_event

logger = logging.getLogger(__name__)

# =============================================================================
# BLUEPRINT DEFINITION
# =============================================================================

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    pass


def generate_verification_token():
    """Generate secure verification token"""
    return secrets.token_urlsafe(32)


def generate_reset_token():
    """Generate secure password reset token"""
    return secrets.token_urlsafe(32)


def hash_token(token):
    """Hash token before storing in database"""
    return hashlib.sha256(token.encode()).hexdigest()


# =============================================================================
# SYSTEM SETTINGS HELPER
# =============================================================================

def get_system_setting(key: str, default=None):
    """
    Fetch system setting from database. Returns default if not found.
    Handles boolean conversion for 'true'/'false'/'1'/'0' strings.
    """
    try:
        result = execute_query(
            "SELECT setting_value FROM system_settings WHERE setting_key = %s",
            (key,),
            fetch_one=True
        )
        if result and 'setting_value' in result:
            val = result['setting_value']
            # Handle boolean strings
            if isinstance(val, str):
                val_lower = val.lower().strip()
                if val_lower in ('true', '1', 'yes', 'enabled'):
                    return True
                elif val_lower in ('false', '0', 'no', 'disabled'):
                    return False
            return val
        return default
    except Exception as e:
        logger.error(f"Failed to fetch system setting '{key}': {str(e)}")
        return default


# =============================================================================
# RESEND VERIFICATION EMAIL
# =============================================================================

def resend_verification_email(email: str):
    """
    Resend email verification link to user who hasn't verified their account.
    """
    try:
        user_data = execute_query(
            """SELECT id, email, email_verified, status FROM users WHERE email = %s""",
            (email.lower(),),
            fetch_one=True
        )

        if not user_data:
            return {'success': True, 'message': 'If an account exists, a verification link has been sent.'}

        if user_data.get('email_verified'):
            return {'success': False, 'message': 'Email already verified. You can log in.'}

        if user_data.get('status') == 'disabled':
            return {'success': False, 'message': 'This account has been disabled. Please contact support.'}

        verification_token = generate_verification_token()
        verification_token_hash = hash_token(verification_token)
        token_expiry = datetime.utcnow() + timedelta(hours=24)

        execute_query(
            "UPDATE users SET verification_token = NULL, verification_token_hash = NULL WHERE id = %s",
            (user_data['id'],)
        )

        execute_query(
            "DELETE FROM auth_tokens WHERE user_id = %s AND token_type = 'email_verification' AND is_used = FALSE",
            (user_data['id'],)
        )

        execute_insert_returning(
            table_name='auth_tokens',
            columns=['user_id', 'token_type', 'token_hash', 'expires_at', 'created_at'],
            values=[
                user_data['id'],
                'email_verification',
                verification_token_hash,
                token_expiry,
                datetime.utcnow()
            ],
            returning_columns='id'
        )

        # Update user table with new hash for quick lookup
        execute_query(
            "UPDATE users SET verification_token_hash = %s WHERE id = %s",
            (verification_token_hash, user_data['id'])
        )

        verification_link = f"{Config.APP_URL}/verify-email?token={verification_token}&user_id={user_data['id']}"

        try:
            email_result = send_verification_email(
                user_email=email,
                verification_link=verification_link,
                user_name="User"
            )

            if email_result.get('success'):
                logger.info(f"Verification email resent to {email}")
                log_audit_event(
                    user_id=user_data['id'],
                    event_type='VERIFICATION_EMAIL_RESENT',
                    details={'email': email, 'ip_address': request.remote_addr}
                )
                return {'success': True, 'message': 'Verification email sent successfully!'}
            else:
                logger.warning(f"Resend verification email failed: {email_result.get('error')}")
                return {'success': False, 'message': 'Failed to send verification email.'}

        except Exception as email_error:
            logger.error(f"Failed to resend verification email: {str(email_error)}")
            return {'success': False, 'message': 'Email service temporarily unavailable.'}

    except Exception as e:
        logger.error(f"Resend verification failed: {str(e)}")
        return {'success': False, 'message': 'Request processing error. Please try again later.'}


# =============================================================================
# REGISTRATION
# =============================================================================

def register_user(email: str, password: str, confirm_password: str):
    """
    Register a new user account.
    """
    if not email or not password or not confirm_password:
        raise AuthenticationError("All fields are required")

    if not validate_email_address(email):
        raise AuthenticationError("Invalid email format")

    pwd_valid, pwd_msg = validate_password_strength(password)
    if not pwd_valid:
        raise AuthenticationError(pwd_msg)

    if password != confirm_password:
        raise AuthenticationError("Passwords do not match")

    existing_user = execute_query(
        "SELECT id FROM users WHERE email = %s",
        (email.lower(),),
        fetch_one=True
    )

    if existing_user:
        raise AuthenticationError("Email already registered")

    try:
        password_hash = hash_password(password)
        verification_token = generate_verification_token()
        verification_token_hash = hash_token(verification_token)
        token_expiry = datetime.utcnow() + timedelta(hours=24)

        user_result = execute_insert_returning(
            table_name='users',
            columns=['email', 'password_hash', 'email_verified', 'verification_token_hash', 'status'],
            values=[
                email.lower(),
                password_hash,
                False,
                verification_token_hash,
                'pending'
            ],
            returning_columns='id'
        )

        if not user_result or 'id' not in user_result:
            raise AuthenticationError("Failed to create user account")

        user_id = user_result['id']

        execute_insert_returning(
            table_name='auth_tokens',
            columns=['user_id', 'token_type', 'token_hash', 'expires_at', 'created_at'],
            values=[
                user_id,
                'email_verification',
                verification_token_hash,
                token_expiry,
                datetime.utcnow()
            ],
            returning_columns='id'
        )

        verification_link = f"{Config.APP_URL}/verify-email?token={verification_token}&user_id={user_id}"

        try:
            email_result = send_verification_email(
                user_email=email,
                verification_link=verification_link,
                user_name="User"
            )
            if not email_result.get('success'):
                logger.warning(f"Verification email failed for {email}: {email_result.get('error')}")
        except Exception as email_error:
            logger.error(f"Failed to send verification email: {str(email_error)}")

        log_audit_event(
            user_id=user_id,
            event_type='USER_REGISTRATION_INITIATED',
            details={'email': email, 'source_ip': request.remote_addr}
        )

        logger.info(f"New user registration initiated: {email}")

        return {
            'success': True,
            'message': 'Registration successful. Please check your email to verify your account.',
            'requires_verification': True,
            'user_id': user_id
        }

    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        raise AuthenticationError("Registration failed. Please try again.")


# =============================================================================
# USER LOGIN
# =============================================================================

def login_user(email: str, password: str):
    """
    Authenticate user and create session.
    """
    if not email or not password:
        raise AuthenticationError("Email and password are required")

    if not validate_email_address(email):
        raise AuthenticationError("Invalid email format")

    try:
        user_data = execute_query(
            """SELECT id, email, password_hash, email_verified, status, role 
               FROM users WHERE email = %s""",
            (email.lower(),),
            fetch_one=True
        )

        if not user_data:
            raise AuthenticationError("Invalid email or password")

        status = user_data.get('status', 'pending')
        if status == 'disabled':
            raise AuthenticationError("This account has been disabled. Please contact support.")

        if status != 'active':
            raise AuthenticationError("Account is not active. Please verify your email first.")

        # Check rate limit BEFORE password verification
        failed_attempts = execute_query(
            """SELECT COUNT(*) as count FROM auth_tokens 
               WHERE user_id = %s AND token_type = 'failed_login' 
               AND created_at > NOW() - INTERVAL '15 minutes'""",
            (user_data['id'],),
            fetch_one=True
        )

        if failed_attempts and failed_attempts.get('count', 0) > 5:
            raise AuthenticationError("Too many failed attempts. Please try again in 15 minutes.")

        if not verify_password(password, user_data['password_hash']):
            execute_query(
                """INSERT INTO auth_tokens (user_id, token_type, ip_address, user_agent, created_at)
                   VALUES (%s, 'failed_login', %s, %s, NOW())""",
                (user_data['id'], request.remote_addr, request.headers.get('User-Agent', 'unknown'))
            )
            raise AuthenticationError("Invalid email or password")

        if not verify_password(password, user_data['password_hash']):
            execute_query(
                """INSERT INTO auth_tokens (user_id, token_type, ip_address, user_agent, created_at)
                   VALUES (%s, 'failed_login', %s, %s, NOW())""",
                (user_data['id'], request.remote_addr, request.headers.get('User-Agent', 'unknown'))
            )
            raise AuthenticationError("Invalid email or password")

        session.permanent = True
        session['user_id'] = user_data['id']
        session['email'] = user_data['email']
        session['role'] = user_data['role']
        session['email_verified'] = user_data['email_verified']

        execute_query(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
            (user_data['id'],)
        )

        execute_query(
            "DELETE FROM auth_tokens WHERE user_id = %s AND token_type = 'failed_login'",
            (user_data['id'],)
        )

        log_audit_event(
            user_id=user_data['id'],
            event_type='USER_LOGIN_SUCCESSFUL',
            details={'email': user_data['email'], 'ip_address': request.remote_addr}
        )

        logger.info(f"Successful login for user: {email}")

        return {
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user_data['id'],
                'email': user_data['email'],
                'role': user_data['role'],
                'email_verified': user_data['email_verified']
            }
        }

    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"Login session creation failed: {str(e)}")
        raise AuthenticationError("Login failed. Please try again.")


# =============================================================================
# ADMIN LOGIN
# =============================================================================

def login_admin(email: str, password: str):
    """
    Authenticate admin and create admin session.
    """
    if not email or not password:
        raise AuthenticationError("Admin email and password are required")

    if not validate_email_address(email):
        raise AuthenticationError("Invalid admin email format")

    try:
        admin_data = execute_query(
            """SELECT id, email, password_hash, is_active, status, last_login 
               FROM admin_accounts WHERE email = %s""",
            (email.lower(),),
            fetch_one=True
        )

        if not admin_data:
            raise AuthenticationError("Invalid admin credentials")

        is_active = admin_data.get('is_active', True)
        if not is_active:
            raise AuthenticationError("This admin account is disabled. Contact super administrator.")

        if not verify_password(password, admin_data['password_hash']):
            # FIX: Do NOT update last_login on failed password attempt
            raise AuthenticationError("Invalid admin credentials")

        session.permanent = True
        session['admin_id'] = admin_data['id']
        session['admin_email'] = admin_data['email']
        session['is_admin'] = True
        session['login_time'] = datetime.utcnow().isoformat()

        # FIX: Update last_login only on success
        execute_query(
            "UPDATE admin_accounts SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
            (admin_data['id'],)
        )

        log_audit_event(
            admin_id=admin_data['id'],
            event_type='ADMIN_LOGIN_SUCCESSFUL',
            details={'email': admin_data['email'], 'ip_address': request.remote_addr, 'redirect': '/admin/panel'}
        )

        logger.info(f"Successful admin login: {admin_data['email']}")

        return {
            'success': True,
            'message': 'Admin authentication successful',
            'redirect_to': '/admin/panel'
        }

    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"Admin login session creation failed: {str(e)}")
        raise AuthenticationError("Admin authentication failed. Please try again.")


# =============================================================================
# LOGOUT
# =============================================================================

def logout_user():
    """
    Invalidate current session and clear user data.
    """
    try:
        user_id = session.get('user_id')
        admin_id = session.get('admin_id')

        if user_id:
            log_audit_event(
                user_id=user_id,
                event_type='USER_LOGOUT',
                details={'ip_address': request.remote_addr}
            )
        elif admin_id:
            log_audit_event(
                admin_id=admin_id,
                event_type='ADMIN_LOGOUT',
                details={'ip_address': request.remote_addr}
            )

        session.clear()
        session.modified = True

        logger.info(f"Session cleared (user: {user_id}, admin: {admin_id})")

        return {
            'success': True,
            'message': 'Logout successful'
        }

    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        session.clear()
        return {
            'success': True,
            'message': 'Logged out'
        }


# =============================================================================
# EMAIL VERIFICATION
# =============================================================================

def verify_email(token: str, user_id: int):
    """
    Verify user email address using token.
    FIX: Check expiry in auth_tokens table.
    """
    if not token or not user_id:
        raise AuthenticationError("Invalid verification link")

    try:
        user_data = execute_query(
            """SELECT id, email, verification_token_hash, email_verified 
               FROM users WHERE id = %s""",
            (user_id,),
            fetch_one=True
        )

        if not user_data:
            raise AuthenticationError("User not found")

        if user_data.get('email_verified'):
            return {
                'success': True,
                'message': 'Email already verified. You can log in.'
            }

        provided_token_hash = hash_token(token)

        # FIX: Validate token against auth_tokens for expiry and usage
        token_record = execute_query(
            """SELECT id, token_hash, expires_at, is_used 
               FROM auth_tokens 
               WHERE user_id = %s 
               AND token_type = 'email_verification' 
               AND token_hash = %s
               ORDER BY created_at DESC LIMIT 1""",
            (user_id, provided_token_hash),
            fetch_one=True
        )

        if not token_record:
            raise AuthenticationError("Invalid verification token")

        if token_record.get('is_used'):
            raise AuthenticationError("Verification token has already been used")

        if token_record.get('expires_at') < datetime.utcnow():
            raise AuthenticationError("Verification token has expired")

        # Activate user
        execute_query(
            """UPDATE users 
               SET email_verified = TRUE, 
                   verification_token_hash = NULL,
                   status = 'active'
               WHERE id = %s""",
            (user_id,)
        )

        # Mark token as used
        execute_query(
            "UPDATE auth_tokens SET is_used = TRUE WHERE id = %s",
            (token_record['id'],)
        )

        log_audit_event(
            user_id=user_id,
            event_type='EMAIL_VERIFIED',
            details={'email': user_data['email']}
        )

        logger.info(f"Email verified for user: {user_data['email']}")

        return {
            'success': True,
            'message': 'Email verified successfully. You can now log in.'
        }

    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"Email verification failed: {str(e)}")
        raise AuthenticationError("Email verification failed. Please try again.")


# =============================================================================
# PASSWORD RESET
# =============================================================================

def request_password_reset(email: str):
    """
    Initiate password reset flow.
    """
    success_message = "If an account exists with that email, a reset link has been sent."

    if not validate_email_address(email):
        return {'success': True, 'message': success_message}

    try:
        user_data = execute_query(
            "SELECT id, email FROM users WHERE email = %s",
            (email.lower(),),
            fetch_one=True
        )

        if user_data:
            reset_token = generate_reset_token()
            reset_token_hash = hash_token(reset_token)
            reset_expiry = datetime.utcnow() + timedelta(hours=1)

            execute_query(
                """UPDATE auth_tokens SET is_used = TRUE 
                   WHERE user_id = %s AND token_type = 'password_reset' 
                   AND is_used = FALSE""",
                (user_data['id'],)
            )

            execute_insert_returning(
                table_name='auth_tokens',
                columns=['user_id', 'token_type', 'token_hash', 'expires_at', 'ip_address', 'user_agent', 'created_at'],
                values=[
                    user_data['id'],
                    'password_reset',
                    reset_token_hash,
                    reset_expiry,
                    request.remote_addr,
                    request.headers.get('User-Agent', 'unknown'),
                    datetime.utcnow()
                ],
                returning_columns='id'
            )

            reset_link = f"{Config.APP_URL}/reset-password?token={reset_token}&user_id={user_data['id']}"

            try:
                # FIX: Align expiry_hours with token expiry (1 hour)
                email_result = send_reset_email(
                    user_email=email,
                    reset_link=reset_link,
                    expiry_hours=1,
                    expiry_minutes=0,
                    user_name="User"
                )

                if email_result.get('success'):
                    logger.info(f"Password reset email sent to: {email}")
                else:
                    logger.warning(f"Reset email delivery failed: {email_result.get('error')}")

            except Exception as email_error:
                logger.error(f"Failed to send reset email: {str(email_error)}")

            log_audit_event(
                user_id=user_data['id'],
                event_type='PASSWORD_RESET_REQUESTED',
                details={'email': email, 'ip_address': request.remote_addr}
            )

    except Exception as e:
        logger.error(f"Password reset request failed: {str(e)}")

    return {'success': True, 'message': success_message}


def reset_password(user_id: int, token: str, new_password: str, confirm_password: str):
    """
    Complete password reset using token.
    """
    if not all([user_id, token, new_password, confirm_password]):
        raise AuthenticationError("All fields are required")

    if new_password != confirm_password:
        raise AuthenticationError("Passwords do not match")

    pwd_valid, pwd_msg = validate_password_strength(new_password)
    if not pwd_valid:
        raise AuthenticationError(pwd_msg)

    try:
        user_data = execute_query(
            "SELECT id, email FROM users WHERE id = %s",
            (user_id,),
            fetch_one=True
        )

        if not user_data:
            raise AuthenticationError("User not found")

        token_records = execute_query(
            """SELECT id, token_hash FROM auth_tokens 
               WHERE user_id = %s 
               AND token_type = 'password_reset' 
               AND is_used = FALSE 
               AND expires_at > NOW()
               ORDER BY created_at DESC LIMIT 1""",
            (user_id,),
            fetch_all=True
        )

        if not token_records:
            raise AuthenticationError("Invalid or expired reset token")

        provided_token_hash = hash_token(token)
        valid_token = next((r for r in token_records if hmac.compare_digest(r['token_hash'], provided_token_hash)), None)

        if not valid_token:
            raise AuthenticationError("Invalid reset token")

        execute_query(
            "UPDATE auth_tokens SET is_used = TRUE WHERE id = %s",
            (valid_token['id'],)
        )

        new_password_hash = hash_password(new_password)
        execute_query(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (new_password_hash, user_id)
        )

        log_audit_event(
            user_id=user_id,
            event_type='PASSWORD_RESET_COMPLETED',
            details={'email': user_data['email']}
        )

        logger.info(f"Password reset completed for user: {user_data['email']}")

        return {
            'success': True,
            'message': 'Password reset successful. You can now log in with your new password.'
        }

    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"Password reset failed: {str(e)}")
        raise AuthenticationError("Password reset failed. Please try again.")


# =============================================================================
# BLUEPRINT ROUTES
# =============================================================================

@auth_bp.route('/register', methods=['GET', 'POST'])
def register_route():
    # ✅ FIX: Check if registration is allowed via system setting
    allow_registration = get_system_setting('allow_registration', default=True)

    if not allow_registration:
        if request.method == 'GET':
            # Redirect to login if registration is disabled
            flash('Registration is currently disabled by the administrator.', 'warning')
            return redirect(url_for('auth.login'))
        else:
            return jsonify({
                'success': False,
                'message': 'Registration is currently disabled by the administrator.'
            }), 403

    # FIX: Handle GET request to serve registration form
    if request.method == 'GET':
        from flask import send_from_directory
        import os
        frontend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'frontend', 'user')
        return send_from_directory(frontend_path, 'register.html')

    try:
        data = request.get_json(silent=True) or request.form
        email = (data.get('email') or '').strip().lower()
        password = (data.get('password') or '').strip()
        confirm_password = (data.get('confirm_password') or '').strip()

        if not email or not password or not confirm_password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        result = register_user(email, password, confirm_password)
        return jsonify(result), 201

    except AuthenticationError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Registration route error: {str(e)}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500


@auth_bp.route('/login', methods=['POST'])
def login_route():
    try:
        data = request.get_json(silent=True) or request.form
        email = (data.get('email') or '').strip().lower()
        password = (data.get('password') or '').strip()

        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400

        result = login_user(email, password)
        return jsonify(result), 200

    except AuthenticationError as e:
        return jsonify({'success': False, 'message': str(e)}), 401
    except Exception as e:
        logger.error(f"Login route error: {str(e)}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred'}), 500


@auth_bp.route('/admin_login', methods=['POST'])
def admin_login_route():
    try:
        data = request.get_json(silent=True) or request.form
        email = (data.get('email') or '').strip().lower()
        password = (data.get('password') or '').strip()

        if not email or not password:
            return jsonify({'success': False, 'message': 'Admin email and password are required'}), 400

        result = login_admin(email, password)

        return jsonify({
            'success': result['success'],
            'message': result['message'],
            'redirect': result.get('redirect_to', '/admin/panel')
        }), 200

    except AuthenticationError as e:
        return jsonify({'success': False, 'message': str(e)}), 401
    except Exception as e:
        logger.error(f"Admin login route error: {str(e)}")
        return jsonify({'success': False, 'message': 'Admin authentication failed'}), 500


@auth_bp.route('/logout', methods=['POST'])
def logout_route():
    try:
        result = logout_user()
        status = 200 if result['success'] else 500
        return jsonify(result), status
    except Exception as e:
        logger.error(f"Logout route error: {str(e)}")
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out'}), 200


@auth_bp.route('/resend_verification', methods=['POST'])
def resend_verification_route():
    try:
        data = request.get_json(silent=True) or request.form
        email = (data.get('email') or '').strip().lower()

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400

        if not validate_email_address(email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400

        result = resend_verification_email(email)
        status_code = 200 if result.get('success') else 400

        return jsonify(result), status_code

    except Exception as e:
        logger.error(f"Resend verification route error: {str(e)}")
        return jsonify({'success': False, 'message': 'Request processing error'}), 500


@auth_bp.route('/verify-email', methods=['GET'])
def verify_email_route():
    try:
        token = request.args.get('token', '').strip()
        user_id = request.args.get('user_id', '').strip()

        if not token or not user_id:
            return jsonify({
                'success': False,
                'message': 'Invalid verification link — missing token or user ID'
            }), 400

        try:
            user_id = int(user_id)
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid user ID'}), 400

        result = verify_email(token, user_id)
        return jsonify(result), 200

    except AuthenticationError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Email verification route error: {str(e)}")
        return jsonify({'success': False, 'message': 'Verification failed'}), 500


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password_route():
    try:
        data = request.get_json(silent=True) or request.form
        email = (data.get('email') or '').strip().lower()

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400

        result = request_password_reset(email)
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Forgot password route error: {str(e)}")
        return jsonify({
            'success': True,
            'message': 'If an account exists with that email, a reset link has been sent.'
        }), 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password_route():
    try:
        data = request.get_json(silent=True) or request.form
        user_id = data.get('user_id')
        token = (data.get('token') or '').strip()
        new_password = (data.get('new_password') or '').strip()
        confirm_password = (data.get('confirm_password') or '').strip()

        if not all([user_id, token, new_password, confirm_password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid user ID'}), 400

        result = reset_password(user_id, token, new_password, confirm_password)
        return jsonify(result), 200

    except AuthenticationError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        logger.error(f"Reset password route error: {str(e)}")
        return jsonify({'success': False, 'message': 'Password reset failed'}), 500


@auth_bp.route('/status', methods=['GET'])
def auth_status_route():
    if 'user_id' in session:
        return jsonify({
            'success': True,
            'authenticated': True,
            'type': 'user',
            'user_id': session.get('user_id'),
            'email': session.get('email'),
            'role': session.get('role'),
            'email_verified': session.get('email_verified')
        }), 200
    elif 'admin_id' in session:
        return jsonify({
            'success': True,
            'authenticated': True,
            'type': 'admin',
            'admin_id': session.get('admin_id'),
            'email': session.get('admin_email'),
            'is_admin': session.get('is_admin')
        }), 200
    return jsonify({'success': True, 'authenticated': False}), 200


# =============================================================================
# AUTHORIZATION DECORATORS
# =============================================================================

def require_email_verification(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('email_verified'):
            return jsonify({
                'success': False,
                'message': 'Email verification required'
            }), 403
        return f(*args, **kwargs)

    return decorated_function


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({
                'success': False,
                'message': 'Admin authentication required',
                'error_code': 'ADMIN_NOT_AUTHENTICATED'
            }), 401
        if 'user_id' in session:
            return jsonify({
                'success': False,
                'message': 'Insufficient privileges - user cannot access admin routes'
            }), 403
        return f(*args, **kwargs)

    return decorated_function


# =============================================================================
# PUBLIC EXPORTS
# =============================================================================

__all__ = [
    'auth_bp',
    'register_user',
    'login_user',
    'login_admin',
    'logout_user',
    'verify_email',
    'request_password_reset',
    'reset_password',
    'resend_verification_email',
    'require_email_verification',
    'require_admin',
    'get_system_setting'
]

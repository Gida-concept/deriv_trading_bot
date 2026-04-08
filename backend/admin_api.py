# =============================================================================
# DERIV TRADING BOT - Admin API Backend
# Version: 1.3 (FIXED: Added /logs endpoint, verified no session.clear())
# Purpose: Handle admin-specific endpoints for system management
# Security: All endpoints require admin authentication via check_admin
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# =============================================================================

import os
import json
import logging
from datetime import datetime
from flask import request, jsonify, session, abort, Blueprint

# FIX: Create Blueprint for admin API routes
admin_bp = Blueprint('admin_api', __name__)

# Local imports
from config import Config
# ✅ FIX: Import new safe wrappers from db_conn v1.6
from database.db_conn import (
    execute_query_one,  # SELECT → single row
    execute_query_all,  # SELECT → list of rows
    execute_non_query,  # UPDATE/INSERT/DELETE → no fetch
    execute_insert_returning
)
from utils.hasher import hash_password, verify_password
from utils.logger import log_audit_event
from backend.middleware import check_admin
from services.signal_engine import get_signal_engine

logger = logging.getLogger(__name__)


def get_current_admin_id():
    """Get current authenticated admin ID from session"""
    if 'admin_id' not in session:
        abort(401)
    return session['admin_id']


# =============================================================================
# ADMIN AUTHENTICATION & SESSION
# =============================================================================

@admin_bp.route('/login', methods=['POST'])
def admin_login():
    """
    Admin login endpoint with brute-force protection.

    POST /api/admin/login
    Body: { "email": "...", "password": "..." }
    """
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON body'}), 400
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password required'}), 400

        # Rate limiting: check failed attempts before DB lookup
        rate_result = execute_query_one(
            """SELECT COUNT(*) as count FROM audit_log 
               WHERE event_type = 'ADMIN_LOGIN_FAILED' 
               AND ip_address = %s 
               AND created_at > NOW() - INTERVAL '15 minutes'""",
            (request.remote_addr,)
        )
        if rate_result and rate_result['count'] >= 5:
            log_audit_event(admin_id=None, event_type='ADMIN_LOGIN_FAILED',
                            details={'email': email, 'reason': 'rate_limited', 'ip': request.remote_addr})
            return jsonify({'success': False, 'message': 'Too many failed attempts. Try again in 15 minutes.'}), 429

        admin = execute_query_one(
            """SELECT id, email, password_hash, status, is_active, last_login
               FROM admin_accounts WHERE email = %s""",
            (email,)
        )

        if not admin:
            log_audit_event(admin_id=None, event_type='ADMIN_LOGIN_FAILED',
                            details={'email': email, 'reason': 'not_found', 'ip': request.remote_addr})
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        # Check account status
        if admin['status'] != 'active' or not admin['is_active']:
            return jsonify({'success': False, 'message': 'Admin account is disabled'}), 403

        # Verify password
        if not verify_password(password, admin['password_hash']):
            log_audit_event(admin_id=None, event_type='ADMIN_LOGIN_FAILED',
                            details={'email': email, 'reason': 'wrong_password', 'ip': request.remote_addr})
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        execute_non_query(
            "UPDATE admin_accounts SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
            (admin['id'],)
        )

        # Clear previous failed attempts on success
        execute_non_query(
            """DELETE FROM audit_log 
               WHERE event_type = 'ADMIN_LOGIN_FAILED' AND ip_address = %s""",
            (request.remote_addr,)
        )

        session['admin_id'] = admin['id']
        session['admin_email'] = admin['email']
        session['role'] = 'admin'
        session.permanent = True

        log_audit_event(admin_id=admin['id'], event_type='ADMIN_LOGIN_SUCCESS', details={'email': email})

        return jsonify({
            'success': True,
            'message': 'Admin login successful',
            'admin': {
                'id': admin['id'],
                'email': admin['email'],
                'last_login': admin['last_login'].isoformat() if admin['last_login'] else None
            }
        })

    except Exception as e:
        logger.error(f"Admin login failed: {str(e)}")
        return jsonify({'success': False, 'message': 'Login error'}), 500


@admin_bp.route('/logout', methods=['POST'])
@check_admin
def admin_logout():
    """Admin logout endpoint"""
    try:
        admin_id = get_current_admin_id()
        log_audit_event(admin_id=admin_id, event_type='ADMIN_LOGOUT')
        session.clear()
        return jsonify({'success': True, 'message': 'Admin logged out successfully'})
    except Exception as e:
        logger.error(f"Admin logout error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# =============================================================================
# USER MANAGEMENT (Admin Functions)
# =============================================================================

@admin_bp.route('/users/list', methods=['GET'])
@check_admin
def list_all_users():
    """
    List all registered users with pagination.

    GET /api/admin/users/list?page=1&limit=50
    """
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 50))
        offset = (page - 1) * limit

        # ✅ FIX: Use execute_query_one for COUNT
        total = execute_query_one("SELECT COUNT(*) as count FROM users")
        total_count = total['count'] if total else 0

        # ✅ FIX: Use execute_query_all for multiple rows
        users = execute_query_all(
            """SELECT id, email, status, role, email_verified, created_at, last_login
               FROM users ORDER BY created_at DESC LIMIT %s OFFSET %s""",
            (limit, offset)
        )

        return jsonify({
            'success': True,
            'users': users if users else [],
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_count,
                'pages': (total_count + limit - 1) // limit
            }
        })

    except Exception as e:
        logger.error(f"List users failed: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/users/toggle_status', methods=['POST'])
@check_admin
def toggle_user_status():
    """
    Enable/disable a user account.

    POST /api/admin/users/toggle_status
    Body: { "user_id": 123, "status": "active" | "disabled" }
    """
    try:
        admin_id = get_current_admin_id()
        data = request.get_json()
        user_id = data.get('user_id')
        new_status = data.get('status')

        if not user_id or new_status not in ['active', 'disabled', 'deleted']:
            return jsonify({'success': False, 'message': 'user_id and valid status required'}), 400

        # ✅ FIX: Use execute_non_query for UPDATE
        execute_non_query(
            "UPDATE users SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (new_status, user_id)
        )

        log_audit_event(admin_id=admin_id, event_type='USER_STATUS_CHANGED',
                        details={'target_user_id': user_id, 'new_status': new_status})

        return jsonify({'success': True, 'message': f'User {user_id} status updated to {new_status}'})

    except Exception as e:
        logger.error(f"Toggle user status failed: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# =============================================================================
# SYSTEM SETTINGS MANAGEMENT
# =============================================================================

@admin_bp.route('/settings', methods=['GET'])
@check_admin
def get_system_settings():
    """
    Get all system-wide settings.

    GET /api/admin/settings
    """
    try:
        # ✅ FIX: Use execute_query_all
        settings = execute_query_all(
            "SELECT setting_key, setting_value, setting_type, description FROM system_settings"
        )

        # Convert to dict for easier frontend use
        settings_dict = {}
        if settings:
            for s in settings:
                key = s['setting_key']
                value = s['setting_value']
                stype = s['setting_type']

                # Parse value based on type
                if stype == 'int':
                    settings_dict[key] = int(value)
                elif stype == 'decimal':
                    settings_dict[key] = float(value)
                elif stype == 'boolean':
                    settings_dict[key] = value.lower() == 'true'
                elif stype == 'json':
                    settings_dict[key] = json.loads(value)
                else:
                    settings_dict[key] = value

        return jsonify({'success': True, 'settings': settings_dict})

    except Exception as e:
        logger.error(f"Get settings failed: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/settings/update', methods=['POST'])
@check_admin
def update_system_settings():
    """
    Update one or more system settings.

    POST /api/admin/settings/update
    Body: { "setting_updates": { "key1": "value1", "key2": "value2" } }
    """
    try:
        admin_id = get_current_admin_id()
        data = request.get_json()
        updates = data.get('setting_updates', {})

        if not updates:
            return jsonify({'success': False, 'message': 'No settings provided to update'}), 400

        updated_keys = []
        for key, value in updates.items():
            # Determine type and format value
            if isinstance(value, bool):
                setting_type = 'boolean'
                formatted_value = str(value).lower()
            elif isinstance(value, int):
                setting_type = 'int'
                formatted_value = str(value)
            elif isinstance(value, float):
                setting_type = 'decimal'
                formatted_value = str(value)
            elif isinstance(value, (dict, list)):
                setting_type = 'json'
                formatted_value = json.dumps(value)
            else:
                setting_type = 'string'
                formatted_value = str(value)

            # ✅ FIX: Use execute_non_query for UPSERT
            execute_non_query(
                """INSERT INTO system_settings (setting_key, setting_value, setting_type, updated_by, updated_at)
                   VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                   ON CONFLICT (setting_key) DO UPDATE
                   SET setting_value = EXCLUDED.setting_value,
                       setting_type = EXCLUDED.setting_type,
                       updated_by = EXCLUDED.updated_by,
                       updated_at = CURRENT_TIMESTAMP""",
                (key, formatted_value, setting_type, admin_id)
            )
            updated_keys.append(key)

        log_audit_event(admin_id=admin_id, event_type='SETTINGS_UPDATED', details={'updated_keys': updated_keys})

        return jsonify({'success': True, 'message': f'Updated {len(updated_keys)} settings', 'keys': updated_keys})

    except Exception as e:
        logger.error(f"Update settings failed: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# =============================================================================
# GLOBAL STATISTICS (Admin Dashboard)
# =============================================================================

@admin_bp.route('/stats/global', methods=['GET'])
@check_admin
def get_global_statistics():
    """
    Get system-wide statistics for admin dashboard.

    GET /api/admin/stats/global
    """
    try:
        # ✅ FIX: Use execute_query_one for all single-row aggregates
        total_users = execute_query_one("SELECT COUNT(*) as count FROM users")
        total_users_count = total_users['count'] if total_users else 0

        active_bots = execute_query_one(
            "SELECT COUNT(*) as count FROM bot_sessions WHERE bot_state = 'active'"
        )
        active_bots_count = active_bots['count'] if active_bots else 0

        recent_24h = execute_query_one(
            """SELECT 
                COUNT(*) as trades,
                SUM(CASE WHEN status = 'won' THEN 1 ELSE 0 END) as wins,
                SUM(CASE WHEN status = 'lost' THEN 1 ELSE 0 END) as losses,
                COALESCE(SUM(profit_loss), 0) as pnl
               FROM trades WHERE opened_at > NOW() - INTERVAL '24 hours'"""
        )

        if recent_24h:
            wins = recent_24h['wins'] or 0
            losses = recent_24h['losses'] or 0
            completed = wins + losses
            win_rate = (wins / completed * 100) if completed > 0 else 0
            pnl = float(recent_24h['pnl'])
        else:
            wins = losses = 0
            win_rate = 0.0
            pnl = 0.0

        return jsonify({
            'success': True,
            'global_statistics': {
                'total_registered_users': total_users_count,
                'active_bots': active_bots_count,
                'recent_24h': {
                    'trades': recent_24h['trades'] if recent_24h else 0,
                    'wins': wins,
                    'losses': losses,
                    'pnl': pnl,
                    'win_rate_percent': round(win_rate, 2)
                }
            }
        })

    except Exception as e:
        logger.error(f"Get global stats failed: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/stats/activity', methods=['GET'])
@check_admin
def get_recent_activity():
    """
    Get recent system activity for audit trail.

    GET /api/admin/stats/activity?days=7
    """
    try:
        days = int(request.args.get('days', 7))
    except (ValueError, TypeError):
        days = 7

    activity = execute_query_all(
        """SELECT al.id, al.event_type, al.details, al.created_at, 
                  COALESCE(u.email, 'System') as user_email,
                  COALESCE(a.email, 'System') as admin_email
           FROM audit_log al
           LEFT JOIN users u ON al.user_id = u.id
           LEFT JOIN admin_accounts a ON al.admin_id = a.id
           WHERE al.created_at > NOW() - %s * INTERVAL '1 day'
           ORDER BY al.created_at DESC LIMIT 100""",
        (days,)
    )

    return jsonify({'success': True, 'reports': activity if activity else []})


@admin_bp.route('/stats/trades', methods=['GET'])
@check_admin
def get_all_trades():
    """
    Get all trades across all users for admin panel.

    GET /api/admin/stats/trades?limit=50&status=all
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 200)
        status_filter = request.args.get('status', 'all')

        if status_filter and status_filter != 'all':
            rows = execute_query_all(
                """SELECT t.id, t.user_id, u.email, t.symbol, t.contract_type,
                          t.stake_amount, t.profit_loss, t.status, t.timeframe,
                          t.opened_at, t.closed_at
                   FROM trades t
                   LEFT JOIN users u ON t.user_id = u.id
                   WHERE t.status = %s
                   ORDER BY t.opened_at DESC
                   LIMIT %s""",
                (status_filter, limit)
            )
        else:
            rows = execute_query_all(
                """SELECT t.id, t.user_id, u.email, t.symbol, t.contract_type,
                          t.stake_amount, t.profit_loss, t.status, t.timeframe,
                          t.opened_at, t.closed_at
                   FROM trades t
                   LEFT JOIN users u ON t.user_id = u.id
                   ORDER BY t.opened_at DESC
                   LIMIT %s""",
                (limit,)
            )

        return jsonify({'success': True, 'trades': rows if rows else []})

    except Exception as e:
        logger.error(f"Get all trades failed: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# =============================================================================
# SYSTEM LOGS (NEW ENDPOINT)
# =============================================================================

@admin_bp.route('/logs', methods=['GET'])
@check_admin
def get_logs():
    """
    Get application logs.

    GET /api/admin/logs?lines=100

    ✅ VERIFIED: This endpoint does NOT clear session.
    It only reads the log file and returns JSON.
    Any errors are caught and returned without affecting the session.
    """
    try:
        # Get number of lines to return (default 100, max 1000)
        lines_count = min(int(request.args.get('lines', 100)), 1000)
        log_file_path = 'logs/app.log'

        logs = []

        if os.path.exists(log_file_path):
            try:
                with open(log_file_path, 'r', encoding='utf-8') as f:
                    all_lines = f.readlines()
                    # Get last N lines
                    logs = all_lines[-lines_count:]
                    # Strip newlines and clean up
                    logs = [line.strip() for line in logs if line.strip()]
            except PermissionError:
                return jsonify({
                    'success': False,
                    'message': 'Permission denied reading log file',
                    'logs': []
                }), 403
            except Exception as read_error:
                logger.error(f"Failed to read log file: {str(read_error)}")
                return jsonify({
                    'success': False,
                    'message': f'Error reading logs: {str(read_error)}',
                    'logs': []
                }), 500
        else:
            # Log file doesn't exist yet
            logs = ['[No log file found]']

        # ✅ SUCCESS: Return logs WITHOUT touching session
        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs),
            'file': log_file_path
        })

    except ValueError:
        # Invalid lines parameter
        return jsonify({
            'success': False,
            'message': 'Invalid lines parameter. Must be an integer.',
            'logs': []
        }), 400

    except Exception as e:
        # ✅ CRITICAL: Catch all errors WITHOUT clearing session
        logger.error(f"Get logs endpoint failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Failed to retrieve logs: {str(e)}',
            'logs': []
        }), 500


# =============================================================================
# SIGNAL ENGINE CONTROLS
# =============================================================================

@admin_bp.route('/signal/status', methods=['GET'])
@check_admin
def signal_engine_status():
    """Get master signal engine status."""
    try:
        engine = get_signal_engine()
        status = engine.get_status()
        return jsonify({
            'success': True,
            'status': status
        })
    except Exception as e:
        logger.error(f"Signal status failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@admin_bp.route('/signal/start', methods=['POST'])
@check_admin
def signal_engine_start():
    """Start the master signal engine."""
    try:
        engine = get_signal_engine()
        if engine.running:
            return jsonify({
                'success': False,
                'message': 'Signal engine already running'
            }), 400
        engine.start()
        return jsonify({
            'success': True,
            'message': 'Signal engine started'
        })
    except Exception as e:
        logger.error(f"Signal start failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@admin_bp.route('/signal/stop', methods=['POST'])
@check_admin
def signal_engine_stop():
    """Stop the master signal engine."""
    try:
        engine = get_signal_engine()
        if not engine.running:
            return jsonify({
                'success': False,
                'message': 'Signal engine not running'
            }), 400
        engine.stop()
        return jsonify({
            'success': True,
            'message': 'Signal engine stopped'
        })
    except Exception as e:
        logger.error(f"Signal stop failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'admin_bp',
    'admin_login',
    'admin_logout',
    'list_all_users',
    'toggle_user_status',
    'get_system_settings',
    'update_system_settings',
    'get_global_statistics',
    'get_recent_activity',
    'get_logs'  # ✅ Added new endpoint
]
# =============================================================================
# BINANCE FUTURES TRADING BOT - User API Backend
# Version: 1.4
# Purpose: Handle user-specific data endpoints ONLY per specification
# Security: All endpoints require authenticated user session
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# FIX: Proper Blueprint route registration for all endpoints
# =============================================================================

import os
import json
import hashlib
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session, g, abort, Blueprint

# Local imports
from config import Config
from database.db_conn import execute_query, execute_insert_returning
from utils.encryptor import encrypt_api_key, decrypt_api_key, encrypt_sensitive_data
from utils.hasher import verify_password, hash_password
from utils.logger import log_audit_event
from services.process_manager import get_process_manager
from backend.middleware import check_user

logger = logging.getLogger(__name__)

# =============================================================================
# FIX: Create Blueprint for user API routes FIRST
# =============================================================================

user_bp = Blueprint('user_api', __name__)


# =============================================================================
# PROFILE MANAGEMENT (PROPERLY REGISTERED)
# =============================================================================

@user_bp.route('/profile', methods=['GET'])
@check_user
def user_get_profile():
    """
    Get current user profile information.

    GET /api/user/profile
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        # Get user profile from database
        user = execute_query(
            """SELECT id, email, status, email_verified, 
                      created_at, last_login, role
               FROM users WHERE id = %s""",
            (user_id,),
            fetch_all=True
        )

        if not user:
            return jsonify({
                'success': False,
                'message': 'User profile not found'
            }), 404

        return jsonify({
            'success': True,
            'profile': {
                'id': user[0]['id'],
                'email': user[0]['email'],
                'status': user[0]['status'],
                'email_verified': bool(user[0]['email_verified']),
                'role': user[0]['role'],
                'created_at': user[0]['created_at'].isoformat() if user[0]['created_at'] else None,
                'last_login': user[0]['last_login'].isoformat() if user[0]['last_login'] else None
            }
        })

    except Exception as e:
        logger.error(f"Get profile failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to retrieve profile'
        }), 500


@user_bp.route('/profile/password', methods=['POST'])
@check_user
def user_update_profile_password():
    """
    Change user password.

    POST /api/user/profile/password
    Body: { "current_password": "...", "new_password": "..." }
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        # Get request data
        current_password = request.json.get('current_password')
        new_password = request.json.get('new_password')

        # Validate inputs
        if not current_password or not new_password:
            return jsonify({
                'success': False,
                'message': 'Current password and new password required'
            }), 400

        # Verify user credentials first
        user = execute_query(
            """SELECT id, password_hash, email, status FROM users WHERE id = %s""",
            (user_id,),
            fetch_all=True
        )

        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404

        # Check account status
        if user[0]['status'] != 'active':
            return jsonify({
                'success': False,
                'message': 'Account is disabled. Cannot update password.'
            }), 403

        # Verify current password
        if not verify_password(current_password, user[0]['password_hash']):
            return jsonify({
                'success': False,
                'message': 'Current password is incorrect'
            }), 401

        # Validate new password strength
        if len(new_password) < 8:
            return jsonify({
                'success': False,
                'message': 'New password must be at least 8 characters long'
            }), 400

        # Check if new password matches current password
        if new_password == current_password:
            return jsonify({
                'success': False,
                'message': 'New password must be different from current password'
            }), 400

        # Hash new password
        new_password_hash = hash_password(new_password)

        # Update password in database
        execute_query(
            "UPDATE users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (new_password_hash, user_id)
        )

        # Log audit event
        log_audit_event(
            user_id=user_id,
            event_type='PASSWORD_CHANGED',
            details={
                'timestamp': datetime.utcnow().isoformat()
            }
        )

        logger.info(f"Password updated for user {user_id}")

        return jsonify({
            'success': True,
            'message': 'Password updated successfully'
        })

    except Exception as e:
        logger.error(f"Update password failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to update password'
        }), 500


@user_bp.route('/profile/delete', methods=['POST'])
@check_user
def user_delete_account():
    """
    Delete user account permanently.

    POST /api/user/profile/delete
    Body: { "confirm_password": "..." }
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        # Get request data
        confirm_password = request.json.get('confirm_password')

        # Validate input
        if not confirm_password:
            return jsonify({
                'success': False,
                'message': 'Confirmation password required'
            }), 400

        # Verify user exists and get their data
        user = execute_query(
            """SELECT id, email, password_hash, status, role FROM users WHERE id = %s""",
            (user_id,),
            fetch_all=True
        )

        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 404

        # Check account status
        if user[0]['status'] != 'active':
            return jsonify({
                'success': False,
                'message': 'Account is already disabled. Deletion will proceed upon re-verification.'
            }), 403

        # Verify password before proceeding
        if not verify_password(confirm_password, user[0]['password_hash']):
            return jsonify({
                'success': False,
                'message': 'Confirmation password is incorrect. Account deletion cancelled.'
            }), 401

        # Step 1: Disable account instead of hard delete (for safety)
        execute_query(
            """UPDATE users SET 
               status = 'deleted', 
               deleted_at = CURRENT_TIMESTAMP,
               updated_at = CURRENT_TIMESTAMP 
               WHERE id = %s AND status = 'active'""",
            (user_id,)
        )

        # Step 2: Soft delete user API keys
        execute_query(
            """UPDATE user_api_keys SET is_active = FALSE, deleted_at = CURRENT_TIMESTAMP WHERE user_id = %s""",
            (user_id,)
        )

        # Step 3: Stop and deactivate all bot sessions
        execute_query(
            """UPDATE bot_sessions SET 
               bot_state = 'stopped', 
               stopped_at = CURRENT_TIMESTAMP, 
               error_message = 'Account deleted by user' 
               WHERE user_id = %s""",
            (user_id,)
        )

        # Step 4: Mark all trades as void (optional - keep history for audit)
        execute_query(
            """UPDATE trades SET status = 'void', closed_at = CURRENT_TIMESTAMP 
               WHERE user_id = %s AND status IN ('open', 'pending')""",
            (user_id,)
        )

        # Step 5: Clear user session
        session.clear()

        # Step 6: Log deletion event
        log_audit_event(
            user_id=user_id,
            event_type='ACCOUNT_DELETED',
            details={
                'email': user[0]['email'],
                'timestamp': datetime.utcnow().isoformat()
            }
        )

        logger.warning(f"Account deleted for user {user_id} ({user[0]['email']})")

        return jsonify({
            'success': True,
            'message': 'Account deleted successfully. Redirecting to login...',
            'redirect': '/login'
        })

    except Exception as e:
        logger.error(f"Delete account failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to delete account'
        }), 500


# =============================================================================
# API KEY MANAGEMENT (Encrypted Storage)
# =============================================================================

@user_bp.route('/api/save', methods=['POST'])
@check_user
def user_save_api_credentials():
    """
    Save or update Binance Futures API credentials for trading.

    POST /api/user/api/save
    Body: { "binance_api_key": "...", "binance_api_secret": "..." }
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        # Get request data
        api_key = request.json.get('binance_api_key')
        api_secret = request.json.get('binance_api_secret')

        # Validate inputs
        if not api_key or not api_secret:
            return jsonify({
                'success': False,
                'message': 'Both API key and API secret are required'
            }), 400

        # Encrypt credentials before storage
        key_encrypted = encrypt_api_key(api_key)
        secret_encrypted = encrypt_api_key(api_secret)

        # Check if credentials exist
        existing = execute_query(
            """SELECT id FROM user_api_keys WHERE user_id = %s""",
            (user_id,),
            fetch_one=True
        )

        if existing:
            execute_query(
                """UPDATE user_api_keys SET 
                   api_key_encrypted = %s,
                   api_secret_encrypted = %s,
                   last_used_at = CURRENT_TIMESTAMP,
                   is_active = TRUE
                   WHERE user_id = %s""",
                (key_encrypted, secret_encrypted, user_id)
            )
            logger.info(f"API credentials updated for user {user_id}")
        else:
            execute_insert_returning(
                table_name='user_api_keys',
                columns=['user_id', 'api_key_encrypted', 'api_secret_encrypted'],
                values=[user_id, key_encrypted, secret_encrypted],
                returning_columns='id'
            )
            logger.info(f"New API credentials saved for user {user_id}")

        log_audit_event(
            user_id=user_id,
            event_type='API_CREDENTIALS_UPDATED',
            details={
                'action': 'update',
                'timestamp': datetime.utcnow().isoformat()
            }
        )

        return jsonify({
            'success': True,
            'message': 'Binance API credentials saved successfully',
            'encrypted': True
        })

    except Exception as e:
        logger.error(f"Save API credentials failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to save credentials'
        }), 500


@user_bp.route('/api/status', methods=['GET'])
@check_user
def user_get_api_status():
    """
    Get status of saved API credentials (not actual key).

    GET /api/user/api/status

    Returns: Whether API credentials are saved and active
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        result = execute_query(
            """SELECT is_active, last_used_at, created_at 
               FROM user_api_keys WHERE user_id = %s""",
            (user_id,),
            fetch_all=True
        )

        if not result:
            return jsonify({
                'success': True,
                'has_credentials': False,
                'message': 'No API credentials configured'
            })

        return jsonify({
            'success': True,
            'has_credentials': True,
            'is_active': result[0]['is_active'],
            'last_used': result[0]['last_used_at'].isoformat() if result[0]['last_used_at'] else None,
            'created_at': result[0]['created_at'].isoformat() if result[0]['created_at'] else None
        })

    except Exception as e:
        logger.error(f"Get API status failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to retrieve bot status'
        }), 500


@user_bp.route('/api/delete', methods=['DELETE'])
@check_user
def user_delete_api_credentials():
    """
    Delete saved API credentials.

    DELETE /api/user/api/delete
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        # First verify credentials exist
        existing = execute_query(
            """SELECT id FROM user_api_keys WHERE user_id = %s""",
            (user_id,),
            fetch_one=True
        )

        if not existing:
            return jsonify({
                'success': False,
                'message': 'No API credentials found to delete'
            }), 404

        # Soft delete credentials (mark inactive)
        execute_query(
            """UPDATE user_api_keys SET is_active = FALSE, deleted_at = CURRENT_TIMESTAMP WHERE user_id = %s""",
            (user_id,)
        )

        # Also deactivate bot sessions tied to this user
        execute_query(
            """UPDATE bot_sessions SET bot_state = 'stopped', stopped_at = CURRENT_TIMESTAMP, error_message = 'API credentials removed' WHERE user_id = %s AND bot_state = 'active'""",
            (user_id,)
        )

        # Log audit event
        log_audit_event(
            user_id=user_id,
            event_type='API_CREDENTIALS_DELETED',
            details={
                'action': 'delete'
            }
        )

        logger.info(f"API credentials deleted for user {user_id}")

        return jsonify({
            'success': True,
            'message': 'API credentials deleted successfully'
        })

    except Exception as e:
        logger.error(f"Delete API credentials failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to delete account'
        }), 500


# =============================================================================
# DASHBOARD STATISTICS (PnL, Trades)
# =============================================================================

@user_bp.route('/stats/dashboard', methods=['GET'])
@check_user
def user_get_dashboard_stats():
    """
    Get dashboard statistics for current user.

    ✅ FIX v1.5: Handle None values from SUM() when no trades exist.
    PostgreSQL returns NULL for SUM() on empty sets, which caused float(None) error.
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        # Helper function to safely extract float values
        def safe_float(row, key, default=0.0):
            if not row:
                return default
            val = row.get(key)
            return float(val) if val is not None else default

        # Helper function to safely extract int values
        def safe_int(row, key, default=0):
            if not row:
                return default
            val = row.get(key)
            return int(val) if val is not None else default

        # Get total trade count
        trade_count = execute_query(
            """SELECT COUNT(*) as count FROM trades WHERE user_id = %s""",
            (user_id,),
            fetch_all=True
        )
        total_trades = safe_int(trade_count[0] if trade_count else None, 'count', 0)

        # Get wins/losses
        # ✅ FIX: SUM() returns NULL when no rows match, handle None values
        win_loss = execute_query(
            """SELECT 
                SUM(CASE WHEN status = 'won' THEN profit_loss ELSE 0 END) as won_pnl,
                SUM(CASE WHEN status = 'lost' THEN profit_loss ELSE 0 END) as lost_pnl
               FROM trades WHERE user_id = %s""",
            (user_id,),
            fetch_all=True
        )

        win_loss_row = win_loss[0] if win_loss else {}
        pnl_won = safe_float(win_loss_row, 'won_pnl', 0.0)
        pnl_lost = abs(safe_float(win_loss_row, 'lost_pnl', 0.0))

        # Get current day stats (last 24 hours)
        recent_day = execute_query(
            """SELECT 
                COUNT(*) as daily_trades,
                SUM(CASE WHEN status = 'won' THEN 1 ELSE 0 END) as daily_wins,
                SUM(CASE WHEN status = 'lost' THEN 1 ELSE 0 END) as daily_losses,
                COALESCE(SUM(profit_loss), 0) as daily_pnl
               FROM trades WHERE user_id = %s AND opened_at > NOW() - INTERVAL '24 hours'""",
            (user_id,),
            fetch_all=True
        )

        recent_row = recent_day[0] if recent_day else {}
        daily_trades = safe_int(recent_row, 'daily_trades', 0)
        daily_wins = safe_int(recent_row, 'daily_wins', 0)
        daily_losses = safe_int(recent_row, 'daily_losses', 0)
        daily_pnl = safe_float(recent_row, 'daily_pnl', 0.0)

        # Get active bot status
        active_bots = execute_query(
            """SELECT bot_state, timeframe, started_at 
               FROM bot_sessions 
               WHERE user_id = %s AND bot_state = 'active'""",
            (user_id,),
            fetch_all=True
        )
        active_bot_count = len(active_bots) if active_bots else 0

        # Calculate overall win rate
        completed_trades = execute_query(
            """SELECT COUNT(*) as count FROM trades 
               WHERE user_id = %s AND status IN ('won', 'lost')""",
            (user_id,),
            fetch_all=True
        )
        total_completed = safe_int(completed_trades[0] if completed_trades else None, 'count', 0)

        won_count = execute_query(
            """SELECT COUNT(*) as count FROM trades 
               WHERE user_id = %s AND status = 'won'""",
            (user_id,),
            fetch_all=True
        )
        won_total = safe_int(won_count[0] if won_count else None, 'count', 0)

        win_rate = round((won_total / total_completed * 100), 2) if total_completed > 0 else 0.0

        # Total net PnL
        net_pnl_result = execute_query(
            """SELECT COALESCE(SUM(profit_loss), 0) as net_pnl FROM trades WHERE user_id = %s""",
            (user_id,),
            fetch_all=True
        )
        net_pnl = safe_float(net_pnl_result[0] if net_pnl_result else None, 'net_pnl', 0.0)

        return jsonify({
            'success': True,
            'statistics': {
                'total_trades': total_trades,
                'pnl_won': round(pnl_won, 2),
                'pnl_lost': round(pnl_lost, 2),
                'net_pnl': round(net_pnl, 2),
                'win_rate_percent': win_rate,
                'daily_summary': {
                    'trades': daily_trades,
                    'wins': daily_wins,
                    'losses': daily_losses,
                    'pnl': round(daily_pnl, 2)
                },
                'active_bots': {
                    'count': active_bot_count,
                    'sessions': [
                        {
                            'timeframe': bot['timeframe'],
                            'started_at': bot['started_at'].isoformat() if bot.get('started_at') else None
                        }
                        for bot in (active_bots or [])
                    ]
                }
            }
        })

    except Exception as e:
        logger.error(f"Get dashboard stats failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to delete credentials'
        }), 500


@user_bp.route('/stats/signals', methods=['GET'])
@check_user
def user_get_signals():
    """
    Get shared AI trading signals for all users.

    GET /api/user/stats/signals?limit=20
    """
    try:
        limit = request.args.get('limit', 20, type=int)

        signals = execute_query(
            """SELECT id, symbol, signal, confidence, entry_price, stop_loss, take_profit, timeframe, reasoning, created_at
               FROM signals
               WHERE expires_at > NOW()
               ORDER BY created_at DESC
               LIMIT %s""",
            (limit,),
            fetch_all=True
        )

        return jsonify({
            'success': True,
            'signals': signals
        })

    except Exception as e:
        logger.error(f"Get signals failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to retrieve signals'
        }), 500


@user_bp.route('/stats/trades', methods=['GET'])
@check_user
def user_get_trade_history():
    """
    Get paginated trade history for current user.

    GET /api/user/stats/trades?limit=50&offset=0&page=1
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        # Parse pagination params
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        timeframe = request.args.get('timeframe', None)
        status = request.args.get('status', None)

        # Build dynamic query filter
        filters = ["user_id = %s"]
        filter_params = [user_id]

        if timeframe:
            filters.append("timeframe = %s")
            filter_params.append(timeframe)

        if status:
            filters.append("status = %s")
            filter_params.append(status)

        where_clause = " AND ".join(filters)

        # Get total count
        total_count = execute_query(
            f"""SELECT COUNT(*) as count FROM trades WHERE {where_clause}""",
            tuple(filter_params),
            fetch_all=True
        )

        total_results = total_count[0]['count'] if total_count else 0

        # Get paginated trades
        trades = execute_query(
            f"""SELECT * FROM trades 
               WHERE {where_clause}
               ORDER BY opened_at DESC
               LIMIT %s OFFSET %s""",
            (*filter_params, limit, offset),
            fetch_all=True
        )

        return jsonify({
            'success': True,
            'trades': trades,
            'pagination': {
                'total': total_results,
                'limit': limit,
                'offset': offset,
                'pages': max(1, int(total_results / limit))
            }
        })

    except Exception as e:
        logger.error(f"Get trade history failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to retrieve profile'
        }), 500


# =============================================================================
# BOT CONTROL (Start/Stop/Demo-Live Toggle)
# =============================================================================

@user_bp.route('/bot/status', methods=['GET'])
@check_user
def user_get_bot_status():
    """
    Get current bot session status for user.

    GET /api/user/bot/status
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        bots = execute_query(
            """SELECT id, bot_state, timeframe, demo_live, risk_percentage, 
                      current_stake, started_at, stopped_at
               FROM bot_sessions WHERE user_id = %s""",
            (user_id,),
            fetch_all=True
        )

        return jsonify({
            'success': True,
            'bots': bots,
            'has_active_bot': any(b['bot_state'] == 'active' for b in bots) if bots else False
        })

    except Exception as e:
        logger.error(f"Get bot status failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to retrieve API status'
        }), 500


@user_bp.route('/bot/start', methods=['POST'])
@check_user
def user_start_bot():
    """
    Start Binance Futures trading bot.

    POST /api/user/bot/start
    Body: { "timeframe": "15m", "demo_live": "demo", "stake": 10.0, "risk": 5.0 }
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        # Get request parameters
        timeframe = request.json.get('timeframe', '15m')
        demo_live = request.json.get('demo_live', 'demo')
        stake = request.json.get('stake', 10.0)
        risk = request.json.get('risk', 5.0)
        strategy = request.json.get('strategy', 'default')

        # Validate timeframe
        allowed_tf = ['1m', '3m', '5m', '15m', '30m', '1h', '2h', '4h', '6h', '12h', '1d']
        if timeframe not in allowed_tf:
            return jsonify({
                'success': False,
                'message': f'Invalid timeframe. Allowed: {allowed_tf}'
            }), 400

        # Check if bot already active in process manager (not just DB)
        existing = execute_query(
            """SELECT id, bot_state FROM bot_sessions 
               WHERE user_id = %s AND timeframe = %s""",
            (user_id, timeframe),
            fetch_all=True
        )

        process_manager = get_process_manager()
        bot_in_memory = (user_id, timeframe) in process_manager.active_bots

        if existing and existing[0]['bot_state'] == 'active' and bot_in_memory:
            return jsonify({
                'success': False,
                'message': f'Bot already running for timeframe {timeframe}'
            }), 400

        # Reuse existing row (whether active/stopped/error)
        if existing:
            execute_query(
                """UPDATE bot_sessions SET 
                   bot_state = 'active',
                   demo_live = %s,
                   risk_percentage = %s,
                   current_stake = %s,
                   strategy_type = %s,
                   started_at = CURRENT_TIMESTAMP
                   WHERE id = %s""",
                (demo_live, risk, stake, strategy, existing[0]['id'])
            )

            process_manager.spawn_bot_thread(user_id, timeframe, strategy)

        else:
            result = execute_insert_returning(
                table_name='bot_sessions',
                columns=['user_id', 'timeframe', 'demo_live', 'risk_percentage', 'current_stake', 'strategy_type',
                         'bot_state'],
                values=[user_id, timeframe, demo_live, risk, stake, strategy, 'active'],
                returning_columns='id'
            )

            # Notify worker thread to start bot
            process_manager = get_process_manager()
            process_manager.spawn_bot_thread(user_id, timeframe, strategy)

        # Log audit event
        log_audit_event(
            user_id=user_id,
            event_type='BOT_STARTED',
            details={
                'timeframe': timeframe,
                'mode': demo_live
            }
        )

        return jsonify({
            'success': True,
            'message': f'Bot started for timeframe {timeframe} in {demo_live} mode'
        })

    except Exception as e:
        logger.error(f"Start bot failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Failed to start bot: {str(e)}'
        }), 500


@user_bp.route('/bot/stop', methods=['POST'])
@check_user
def user_stop_bot():
    """
    Stop trading bot for specific timeframe.

    POST /api/user/bot/stop
    Body: { "timeframe": "M5" }
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        timeframe = request.json.get('timeframe')

        if not timeframe:
            return jsonify({
                'success': False,
                'message': 'Timeframe required'
            }), 400

        # Stop bot in session
        execute_query(
            """UPDATE bot_sessions SET 
               bot_state = 'stopped',
               stopped_at = CURRENT_TIMESTAMP
               WHERE user_id = %s AND timeframe = %s""",
            (user_id, timeframe)
        )

        # Cancel any active trades for this timeframe
        execute_query(
            """UPDATE trades SET status = 'void', closed_at = CURRENT_TIMESTAMP 
               WHERE user_id = %s AND timeframe = %s AND status = 'open'""",
            (user_id, timeframe)
        )

        # Clear timeframe lock
        execute_query(
            """DELETE FROM timeframe_locks 
               WHERE user_id = %s AND timeframe = %s""",
            (user_id, timeframe)
        )

        # Notify worker thread to stop bot
        process_manager = get_process_manager()
        process_manager.stop_bot_thread(user_id, timeframe)

        # Log audit event
        log_audit_event(
            user_id=user_id,
            event_type='BOT_STOPPED',
            details={
                'timeframe': timeframe
            }
        )

        return jsonify({
            'success': True,
            'message': f'Bot stopped for timeframe {timeframe}'
        })

    except Exception as e:
        logger.error(f"Stop bot failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to switch mode'
        }), 500


@user_bp.route('/bot/toggle_mode', methods=['POST'])
@check_user
def user_toggle_demo_live():
    """
    Toggle between Demo and Live trading mode.

    POST /api/user/bot/toggle_mode
    Body: { "timeframe": "M5", "mode": "live" }
    """
    try:
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({
                'success': False,
                'message': 'User not authenticated'
            }), 401

        timeframe = request.json.get('timeframe')
        mode = request.json.get('mode', 'live')

        if mode not in ['demo', 'live']:
            return jsonify({
                'success': False,
                'message': 'Mode must be either demo or live'
            }), 400

        # Verify bot exists and is running
        bot_exists = execute_query(
            """SELECT id, bot_state FROM bot_sessions 
               WHERE user_id = %s AND timeframe = %s""",
            (user_id, timeframe),
            fetch_all=True
        )

        if not bot_exists:
            return jsonify({
                'success': False,
                'message': 'No active bot session found for this timeframe'
            }), 404

        if bot_exists[0]['bot_state'] != 'active':
            return jsonify({
                'success': False,
                'message': 'Cannot switch modes on stopped bot'
            }), 400

        # Update the demo_live mode in the database
        execute_query(
            """UPDATE bot_sessions SET demo_live = %s WHERE id = %s""",
            (mode, bot_exists[0]['id'])
        )

        # Restart the bot to apply the new mode
        from services.process_manager import get_process_manager
        process_manager = get_process_manager()
        
        # Stop the existing bot
        process_manager.stop_bot(user_id, timeframe)
        
        # Small delay to ensure clean shutdown
        import time
        time.sleep(2)
        
        # Restart the bot with the new mode
        strategy = bot_exists[0].get('strategy_type', 'default')
        process_manager.spawn_bot_thread(user_id, timeframe, strategy)

        # Log audit event
        log_audit_event(
            user_id=user_id,
            event_type='MODE_SWITCHED',
            details={
                'timeframe': timeframe,
                'old_mode': bot_exists[0]['demo_live'],
                'new_mode': mode
            }
        )

        return jsonify({
            'success': True,
            'message': f'Mode switched to {mode} for timeframe {timeframe}. Bot restarted.',
            'warnings': 'Live trading involves real financial risk. Ensure proper risk management.'
        })

    except Exception as e:
        logger.error(f"Toggle demo/live failed: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Failed to switch mode'
        }), 500


# =============================================================================
# EXPORTS & INITIALIZATION
# =============================================================================

__all__ = [
    'user_bp',
    'user_get_profile',
    'user_update_profile_password',
    'user_delete_account',
    'user_save_api_credentials',
    'user_get_api_status',
    'user_delete_api_credentials',
    'user_get_dashboard_stats',
    'user_get_trade_history',
    'user_get_bot_status',
    'user_start_bot',
    'user_stop_bot',
    'user_toggle_demo_live'
]
# =============================================================================
# BINANCE FUTURES TRADING BOT - Flask Application Entry Point
# Version: 3.0
# Purpose: Main application entry point with all routes registered
# Security: Session-based authentication for users AND admins
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# =============================================================================

import os
import sys
import atexit
import logging
from datetime import datetime
from flask import Flask, send_from_directory, jsonify, request, redirect, session

# =============================================================================
# Stop Flask access log spam
# =============================================================================
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# =============================================================================
# Initialize Flask App
# =============================================================================
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.config.from_object('config.Config')

secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is required. "
        "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
    )
app.secret_key = secret_key

# Create logs folder + file
os.makedirs('logs', exist_ok=True)
log_path = 'logs/app.log'
if not os.path.exists(log_path):
    open(log_path, 'w').close()


def log_request(message):
    """Log request information to app.log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] {message}\n")


# =============================================================================
# Import Middleware First
# =============================================================================
try:
    from backend.middleware import check_user, check_admin
except ImportError as e:
    raise ImportError(f"Critical: 'check_user' or 'check_admin' could not be imported: {e}") from e

# =============================================================================
# Register Blueprints BEFORE frontend routes (Prevents Conflicts)
# =============================================================================
try:
    from backend.user_api import user_bp

    app.register_blueprint(user_bp, url_prefix='/api/user')
    print("Success: user_bp imported and registered at /api/user")
except ImportError as e:
    raise ImportError(f"Critical: 'user_bp' could not be imported. Check backend/user_api.py: {e}") from e

admin_bp = None
try:
    from backend.admin_api import admin_bp

    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    print("Success: admin_bp imported successfully")
    print("Admin API routes registered at /api/admin")
except ImportError as e:
    print(f"Warning: admin_bp not found – Admin routes disabled. Error: {e}")

auth_bp = None
try:
    from backend.auth import auth_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    print("Auth API routes registered at /auth - Registration enabled!")
    print("[OK] Resend Verification Endpoint: /auth/resend_verification")
    print("[OK] Verify Email Endpoint: /auth/verify-email")
except ImportError as e:
    print("\n" + "=" * 70)
    print("ERROR: FAILED TO IMPORT auth_bp - Registration will NOT work!")
    print("Error:", e)
    print("=" * 70 + "\n")


# =============================================================================
# User Login/Logout Handlers (Specific Before General)
# =============================================================================
@app.route('/login', methods=['GET'])
def serve_login():
    """Serve user login page"""
    if 'user_id' in session and 'user_email' in session:
        return redirect('/dashboard')
    return send_from_directory(os.path.join(app.root_path, 'frontend/user'), 'login.html')


@app.route('/logout', methods=['POST'])
def logout():
    """Handle user logout"""
    try:
        session.clear()
        return redirect('/login')
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500


# =============================================================================
# User Frontend Routes (After Blueprints)
# =============================================================================
frontend_user_path = os.path.join(app.root_path, 'frontend', 'user')

PROTECTED_PAGES = ['dashboard', 'api_config', 'settings', 'profile']

# ✅ FIX: Added 'verify-email' to PUBLIC_PAGES
PUBLIC_PAGES = ['login', 'register', 'verify-email', 'reset_request', 'forgot_password', 'reset_confirm']


def is_user_logged_in():
    """Check if user has active session"""
    return 'user_id' in session and session.get('user_id') is not None


@app.route('/')
@app.route('/dashboard')
@app.route('/register')
@app.route('/verify-email')          # ✅ FIX: Added verify-email route
@app.route('/reset_request')
@app.route('/reset_confirm')
@app.route('/api_config')
@app.route('/settings')
@app.route('/profile')
def serve_user_frontend(token=None):
    """Serve user-facing HTML pages"""
    page = request.path.lstrip('/')

    # Handle root path redirect
    if not page or page.endswith('/'):
        if is_user_logged_in():
            return redirect('/dashboard')
        else:
            return redirect('/login')

    # Remove query/hash parameters
    base_page = page.split('?')[0].split('#')[0]
    if '.' in base_page:
        base_page = base_page.rsplit('.', 1)[0]

    logged_in = is_user_logged_in()

    # Redirect protected pages to login if not authenticated
    if base_page in PROTECTED_PAGES and not logged_in:
        return redirect('/login')

    # Redirect public pages to dashboard if already authenticated
    if base_page in PUBLIC_PAGES and logged_in:
        return redirect('/dashboard')

    html_file = f"{base_page}.html" if base_page else 'dashboard.html'
    filepath = os.path.join(frontend_user_path, html_file)

    if os.path.exists(filepath):
        return send_from_directory(frontend_user_path, html_file)
    else:
        if logged_in:
            return send_from_directory(frontend_user_path, 'dashboard.html')
        else:
            return redirect('/login')


# =============================================================================
# Admin Frontend Routes - FIXED FILE NAMES & DECORATORS
# =============================================================================
frontend_admin_path = os.path.join(app.root_path, 'frontend', 'admin')


@app.route('/admin/login')
def serve_admin_login():
    """Serve admin login page - NO SESSION CHECK REQUIRED"""
    html_file = 'login.html'
    filepath = os.path.join(frontend_admin_path, html_file)

    if os.path.exists(filepath):
        return send_from_directory(frontend_admin_path, html_file)
    else:
        return jsonify({
            'success': False,
            'message': 'Admin login page not found'
        }), 404


@app.route('/admin/panel')
@app.route('/admin/users')
@app.route('/admin/settings')
@app.route('/admin/logs')
@check_admin
def serve_admin_pages():
    """Serve admin-only HTML pages - Requires admin session"""
    page_map = {
        '/admin/panel': 'panel.html',
        '/admin/users': 'users.html',
        '/admin/settings': 'settings.html',
        '/admin/logs': 'logs.html'
    }
    filename = page_map.get(request.path, 'panel.html')
    filepath = os.path.join(frontend_admin_path, filename)

    if os.path.exists(filepath):
        return send_from_directory(frontend_admin_path, filename)
    else:
        return redirect('/admin/login')


# =============================================================================
# Static Files
# =============================================================================
@app.route('/static/<path:filepath>')
def serve_static(filepath):
    """Serve static assets (CSS, JS, images)"""
    return send_from_directory(app.static_folder, filepath)


def cleanup_on_shutdown():
    """Gracefully close database connections and stop signal engines on shutdown."""
    try:
        from services.signal_engine import get_signal_engine
        get_signal_engine().stop()
    except Exception:
        pass
    try:
        from database.db_conn import cleanup_pool
        cleanup_pool()
        print("Database pool cleaned up successfully")
    except Exception as e:
        print(f"Error during cleanup: {e}")

atexit.register(cleanup_on_shutdown)


# =============================================================================
# Start Signal Engines (Master AI + Social Copy Trading)
# =============================================================================
try:
    from services.pretrain_xgboost import pretrain_model
    from services.signal_engine import get_signal_engine

    print("Pretraining XGBoost model on historical data...")
    pretrain_model()

    signal_engine = get_signal_engine()
    signal_engine.start()
    print("Master signal engine started (AI signals)")
except Exception as e:
    print(f"Warning: Signal engine failed to start: {e}")


# =============================================================================
# Custom Error Handlers
# =============================================================================
@app.errorhandler(404)
def handle_404(error):
    """Handle 404 errors"""
    log_request(f"404 Not Found: {request.method} {request.path}")

    if request.path.startswith('/api') or request.path.startswith('/auth'):
        return jsonify({"error": "Not Found", "success": False}), 404

    if 'admin_id' in session:
        return redirect('/admin/panel')
    elif 'user_id' in session:
        return redirect('/dashboard')
    else:
        return redirect('/login')


@app.errorhandler(401)
def handle_unauthorized(error):
    """Handle 401 Unauthorized errors"""
    log_request(f"401 Unauthorized: {request.method} {request.path}")

    if request.is_json or request.path.startswith('/api'):
        return jsonify({
            'success': False,
            'message': 'Unauthorized',
            'error_code': 'UNAUTHORIZED'
        }), 401

    if 'admin_id' in session:
        return redirect('/admin/panel')
    else:
        return redirect('/login')


@app.errorhandler(500)
def handle_500(error):
    """Handle 500 Internal Server Error"""
    log_request(f"500 Internal Error: {str(error)} on {request.path}")
    return jsonify({"error": "Internal Server Error"}), 500


# =============================================================================
# Run Server
# =============================================================================
if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))

    print(f"\n{'=' * 60}")
    print("Deriv Trading Bot started successfully!")
    print(f"→ http://localhost:{port}")
    print(f"→ http://127.0.0.1:{port}")
    print(f"→ Registration: http://localhost:{port}/register")
    print(f"→ Login: http://localhost:{port}/login")
    print(f"→ Verify Email: http://localhost:{port}/verify-email")
    print(f"→ Admin Login: http://localhost:{port}/admin/login")
    print(f"→ Resend Verification: http://localhost:{port}/auth/resend_verification")
    print(f"{'=' * 60}\n")

    app.run(host=host, port=port, debug=False, threaded=True)
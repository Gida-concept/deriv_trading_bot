# =============================================================================
# DERIV TRADING BOT - System Logging Utility Module
# Version: 1.2 (FIXED - Added admin_id support)
# Purpose: Centralized logging with rotation, multiple handlers, security masking
# Security: Sanitizes sensitive data (passwords, tokens, API keys)
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# FIX: Added admin_id parameter to log_audit_event() function
# =============================================================================

import os
import sys
import json
import logging
import re
import datetime
from typing import Optional, Any, Union, Dict
from logging.handlers import RotatingFileHandler
import os

# Local imports
from config import Config

# Configuration Constants
LOG_DIR = 'logs'
APP_LOG_FILE = 'app.log'
BOT_LOG_FILE = 'bot.log'
ERROR_LOG_FILE = 'error.log'
MAX_BYTES = 10 * 1024 * 1024  # 10 MB per file
BACKUP_COUNT = 5  # Keep 5 backup files

# Supported Log Levels
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

# Sensitive Data Patterns for Redaction
SENSITIVE_PATTERNS = [
    r'password\s*=\s*["\'][^"\']+["\']',
    r'api_key\s*:\s*["\'][^"\']+["\']',
    r'token\s*:\s*["\'][^"\']+["\']',
    r'secret\s*:\s*["\'][^"\']+["\']',
    r'"access_token"\s*:\s*"[^"]+"',
    r'"refresh_token"\s*:\s*"[^"]+"',
]


class SensitiveDataFilter(logging.Filter):
    """Custom filter to redact sensitive information from log messages."""

    def __init__(self):
        super().__init__()
        self.patterns = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_PATTERNS]

    def filter(self, record):
        try:
            msg = record.getMessage()
            for pattern in self.patterns:
                msg = pattern.sub('<REDACTED>', msg)
            record.msg = msg
            record.args = None
            return True
        except Exception:
            return True
        except Exception:
            return True


class ColoredFormatter(logging.Formatter):
    """Custom formatter for console output with colors."""

    COLORS = {
        'DEBUG': '\033[92m',
        'INFO': '\033[94m',
        'WARNING': '\033[93m',
        'ERROR': '\033[91m',
        'CRITICAL': '\033[95m',
    }
    RESET = '\033[0m'
    FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.RESET)
        formatted_msg = super().format(record)
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            formatted_msg = f"{log_color}{formatted_msg}{self.RESET}"
        return formatted_msg


def _create_file_handler(filename: str, level: int, encoding: str = 'utf-8') -> RotatingFileHandler:
    """Create a rotating file handler."""
    os.makedirs(LOG_DIR, exist_ok=True)
    filepath = os.path.join(LOG_DIR, filename)
    handler = RotatingFileHandler(filepath, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding=encoding)
    handler.setLevel(level)
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(fmt)
    return handler


def configure_logging(log_level: str = 'INFO'):
    """Configure global logging for the application."""
    if log_level.upper() not in LOG_LEVELS:
        log_level = 'INFO'
        print(f"Invalid log level '{log_level}'. Defaulting to INFO.")

    effective_level = LOG_LEVELS[log_level.upper()]
    root_logger = logging.getLogger()

    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    app_handler = _create_file_handler(APP_LOG_FILE, effective_level)
    app_handler.addFilter(SensitiveDataFilter())

    bot_handler = _create_file_handler(BOT_LOG_FILE, effective_level)
    bot_handler.addFilter(SensitiveDataFilter())

    error_handler = _create_file_handler(ERROR_LOG_FILE, logging.ERROR)
    error_handler.addFilter(SensitiveDataFilter())

    root_logger.addHandler(app_handler)
    root_logger.addHandler(bot_handler)
    root_logger.addHandler(error_handler)

    root_logger.setLevel(effective_level)
    root_logger.propagate = False
    root_logger.info(f"Logging system configured. Log level: {log_level}")


def get_logger(name: str) -> logging.Logger:
    """Get a named logger instance."""
    return logging.getLogger(name)


def log_audit_event(event_type: str, details: Dict[str, Any], user_id: Optional[int] = None,
                    admin_id: Optional[int] = None):
    """
    Log a structured audit event to both file and database.
    Supports logging from both users (user_id) and admins (admin_id).
    """
    try:
        logger = get_logger('audit')

        # Build audit data - only include ID fields that are present
        audit_data = {
            'event_type': event_type,
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'details': details
        }

        # Add user_id if provided
        if user_id is not None:
            audit_data['user_id'] = user_id

        # Add admin_id if provided
        if admin_id is not None:
            audit_data['admin_id'] = admin_id

        # Format as JSON for easier parsing by SIEM systems
        message = json.dumps(audit_data)

        # Log to Audit Logger (sub-logger)
        logger.info(message)

        # Also write to database audit_log table
        try:
            from database.db_conn import execute_non_query
            # Skip DB write for system calls (user_id=0 means signal engine, not a real user)
            if user_id == 0:
                return
            execute_non_query(
                """INSERT INTO audit_log (user_id, admin_id, event_type, details, ip_address, user_agent)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    user_id,
                    admin_id,
                    event_type,
                    json.dumps(details),
                    details.get('ip_address') if isinstance(details, dict) else None,
                    details.get('user_agent') if isinstance(details, dict) else None
                )
            )
        except Exception:
            pass  # Don't fail audit logging if DB write fails

    except Exception as e:
        logging.error(f"Audit logging failed: {str(e)}")


def log_error_with_traceback(logger_instance, error: Exception, message: str = None):
    """Helper function to log exceptions with full traceback."""
    import traceback

    exc_string = f"{message}: {error.__class__.__name__} - {str(error)}" if message else f"{error}"
    logger_instance.error(exc_string, exc_info=True)


# Initialize logging on import
try:
    env_log_level = os.getenv('LOG_LEVEL', 'INFO').strip().upper()
    configure_logging(env_log_level)
except Exception as e:
    print(f"Warning: Failed to initialize logger: {str(e)}. Continuing without logging setup.")
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
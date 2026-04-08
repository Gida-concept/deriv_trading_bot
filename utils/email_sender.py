# =============================================================================
# DERIV TRADING BOT - Email Sending Utility Module
# Version: 3.1 (FIXED: Argument mismatch with auth/routes.py)
# Purpose: SMTP email delivery with template rendering
# Security: TLS encrypted connections, graceful error handling
# FIXES:
#   1. Updated send_verification_email to accept user_email, verification_link, user_name
#   2. Updated send_reset_email to accept user_email, reset_link, expiry params, user_name
#   3. Aligned signatures with auth/routes.py calls to prevent TypeError
#   4. Preserved link construction logic in auth module (includes user_id)
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# =============================================================================

import os
import sys
import smtplib
import logging
import threading
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional

# Jinja2
try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("CRITICAL: pip install jinja2")
    raise

from config import Config
from utils.logger import log_audit_event
from utils.validators import validate_email_address

logging.basicConfig(filename='logs/bot.log', level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailSenderException(Exception):
    """Custom exception for email operations"""
    pass


class EmailTemplateManager:
    """Manages email templates with Jinja2 rendering."""

    def __init__(self, template_dir: str = 'email_templates'):
        self.template_dir = template_dir

        full_template_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            template_dir
        )

        logger.info(f"Template directory loaded from: {full_template_path}")

        self.jinja_env = Environment(
            loader=FileSystemLoader(full_template_path),
            autoescape=True
        )

    def render(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render template with provided context variables."""
        try:
            template = self.jinja_env.get_template(f'{template_name}.html')
            return template.render(**context)
        except FileNotFoundError as e:
            logger.error(f"Template file not found: {e.filename}")
            return f"""<!DOCTYPE html>
<html><body>
<h1>{template_name} Template Missing</h1>
<p>Please verify template file exists: email_templates/{template_name}.html</p>
</body></html>"""
        except Exception as e:
            logger.error(f"Template error {template_name}: {e}")
            raise EmailSenderException(f"Failed to render email template: {e}")


class EmailSender:
    """Handles SMTP email sending operations."""

    MAX_EMAILS_PER_HOUR = 50

    def __init__(self):
        """Initialize email sender with configuration."""
        self.config = {
            'host': Config.SMTP_HOST,
            'port': Config.SMTP_PORT,
            'username': Config.SMTP_USERNAME,
            'password': Config.SMTP_PASSWORD,
            'use_tls': getattr(Config, 'SMTP_USE_TLS', True),
            'use_ssl': getattr(Config, 'SMTP_USE_SSL', False),
            'from_email': Config.EMAIL_FROM,
            'from_name': getattr(Config, 'FROM_NAME', 'Deriv Trading Bot'),
        }
        self.template_manager = EmailTemplateManager()
        self.sent_tracker = []
        self._tracker_lock = threading.Lock()

    def _rate_limit_ok(self) -> bool:
        """Check if we've exceeded hourly email sending limit."""
        with self._tracker_lock:
            now = datetime.utcnow()
            self.sent_tracker = [t for t in self.sent_tracker if now - t < timedelta(hours=1)]
            return len(self.sent_tracker) < self.MAX_EMAILS_PER_HOUR

    def send_email(self, to_email: str, subject: str, html: str, text: str = None) -> bool:
        """Send an HTML email via SMTP."""
        if not validate_email_address(to_email):
            logger.error(f"Invalid recipient email: {to_email}")
            return False

        if not self._rate_limit_ok():
            logger.warning("Email sending rate limit exceeded")
            return False

        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.config['from_name']} <{self.config['from_email']}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

            msg.attach(MIMEText(html, 'html'))

            if text:
                msg.attach(MIMEText(text, 'plain'))

            if self.config['use_ssl']:
                server = smtplib.SMTP_SSL(self.config['host'], self.config['port'])
            else:
                server = smtplib.SMTP(self.config['host'], self.config['port'])
                if self.config['use_tls']:
                    server.starttls()

            server.login(self.config['username'], self.config['password'])
            server.sendmail(self.config['from_email'], to_email, msg.as_string())
            server.quit()

            self.sent_tracker.append(datetime.utcnow())
            logger.info(f"Email sent successfully to {to_email}")
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP Authentication failed - check credentials")
            return False
        except smtplib.SMTPConnectError:
            logger.error("Failed to connect to SMTP server")
            return False
        except Exception as e:
            logger.error(f"Email sending error to {to_email}: {str(e)}")
            return False


# Singleton instance
_email_sender = None
_lock = threading.Lock()


def get_sender() -> EmailSender:
    """Get singleton instance of email sender."""
    global _email_sender

    if _email_sender is None:
        with _lock:
            if _email_sender is None:
                try:
                    _email_sender = EmailSender()
                except Exception as e:
                    logger.error(f"Email sender initialization failed: {str(e)}")
                    raise

    return _email_sender


# =============================================================================
# PUBLIC FUNCTIONS - ALIGNED WITH auth/routes.py CALLS
# =============================================================================

def send_verification_email(user_email: str, verification_link: str, user_name: str = "User") -> dict:
    """
    Send email verification link.

    ✅ FIX v3.1: Updated signature to match auth/routes.py calls.
    Now accepts user_email, verification_link, and user_name.
    The auth module builds the full link including user_id, which is required.

    Args:
        user_email: Recipient email address
        verification_link: Full verification URL (built by auth module with token & user_id)
        user_name: User's name for personalization

    Returns:
        dict: {'success': bool, 'error': str (optional)}
    """
    try:
        sender = get_sender()

        # Render template with context from auth module
        html = sender.template_manager.render('verify_user', {
            'user_name': user_name,
            'verification_link': verification_link,
            'app_url': Config.APP_URL,
            'unsubscribe_link': f"{Config.APP_URL}/unverify",
            'privacy_link': f"{Config.APP_URL}/privacy",
            'terms_link': f"{Config.APP_URL}/terms"
        })

        success = sender.send_email(
            to_email=user_email,
            subject="Verify Your Deriv Trading Bot Account",
            html=html
        )

        return {"success": success}

    except Exception as e:
        logger.error(f"Verification email failed: {e}")
        return {"success": False, "error": str(e)}


def send_reset_email(user_email: str, reset_link: str, expiry_hours: int = 24, expiry_minutes: int = 0,
                     user_name: str = "User") -> dict:
    """
    Send password reset request email.

    ✅ FIX v3.1: Updated signature to match auth/routes.py calls.
    Now accepts user_email, reset_link, expiry params, and user_name.

    Args:
        user_email: Recipient email address
        reset_link: Full reset URL (built by auth module)
        expiry_hours: Token expiry in hours
        expiry_minutes: Token expiry in minutes
        user_name: User's name for personalization

    Returns:
        dict: {'success': bool, 'error': str (optional)}
    """
    try:
        sender = get_sender()

        html = sender.template_manager.render('reset_password', {
            'user_name': user_name,
            'reset_link': reset_link,
            'expiry_hours': expiry_hours,
            'expiry_minutes': expiry_minutes,
            'app_url': Config.APP_URL,
            'unsubscribe_link': f"{Config.APP_URL}/unsub",
            'privacy_link': f"{Config.APP_URL}/privacy",
            'terms_link': f"{Config.APP_URL}/terms",
            'support_link': f"{Config.APP_URL}/contact"
        })

        success = sender.send_email(
            to_email=user_email,
            subject=f"Password Reset Request - Deriv Trading Bot ({expiry_hours}h expiry)",
            html=html
        )

        return {"success": success}

    except Exception as e:
        logger.error(f"Reset email failed: {e}")
        return {"success": False, "error": str(e)}


def send_resend_verification_email(user_email: str, verification_link: str, user_name: str = "User") -> dict:
    """
    Resend email verification link.

    ✅ FIX v3.1: Updated to call send_verification_email with correct signature.

    Args:
        user_email: Recipient email address
        verification_link: Full verification URL
        user_name: User's name for personalization

    Returns:
        dict: {'success': bool, 'error': str (optional)}
    """
    try:
        result = send_verification_email(user_email, verification_link, user_name)

        if result['success']:
            logger.info(f"Resent verification email to {user_email}")
            return {"success": True, "message": "Verification email resent"}
        else:
            logger.warning(f"Failed to resend verification email to {user_email}: {result.get('error')}")
            return {"success": False, "error": result.get('error', 'Unknown error')}

    except Exception as e:
        logger.error(f"Resend verification email failed: {e}")
        return {"success": False, "error": str(e)}


def send_generic_email(recipient: str, subject: str, html_content: str) -> dict:
    """Send generic HTML email without template rendering."""
    try:
        sender = get_sender()

        success = sender.send_email(
            to_email=recipient,
            subject=subject,
            html=html_content
        )

        return {"success": success}

    except Exception as e:
        logger.error(f"Generic email failed: {e}")
        return {"success": False, "error": str(e)}


# Keep old names for backward compatibility
send_password_reset = send_reset_email

# =============================================================================
# TEST FUNCTION
# =============================================================================

if __name__ == '__main__':
    """Test the email sender module."""
    print("=" * 60)
    print("EMAIL SENDER MODULE TEST")
    print("=" * 60)

    test_email = os.getenv('TEST_EMAIL', 'test@example.com')

    if test_email == 'test@example.com':
        print("\n⚠️ WARNING: Configure TEST_EMAIL in .env for testing!")
    else:
        print(f"\n📧 Testing email to: {test_email}")

        try:
            print("\n1. Testing verification email...")
            result = send_verification_email(
                user_email=test_email,
                verification_link=f"{Config.APP_URL}/verify-email?token=test_token&user_id=999",
                user_name="Test User"
            )
            print(f"   Result: {result}")

            print("\n2. Testing password reset email...")
            result = send_reset_email(
                user_email=test_email,
                reset_link=f"{Config.APP_URL}/reset-password?token=reset_token",
                expiry_hours=1,
                expiry_minutes=0,
                user_name="Test User"
            )
            print(f"   Result: {result}")

        except Exception as e:
            print(f"\n❌ Email test failed: {str(e)}")

    print("\n" + "=" * 60)
    print("Email Sender Module Ready")
    print("=" * 60)
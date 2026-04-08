# =============================================================================
# DERIV TRADING BOT - Password Hashing Utility Module
# Version: 1.3 (FIXED: Argon2 decoding exceptions)
# Purpose: Secure password hashing and verification using Argon2id
# Security: Industry-standard KDF (Key Derivation Function)
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# =============================================================================

import os
import sys
import logging
import threading
from typing import Optional, Tuple

# Argon2-CFFI library installation requirement
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHashError
except ImportError as e:
    print("CRITICAL: argon2-cffi package required!")
    print("Install with: pip install argon2-cffi")
    raise ValueError(f"Import failed: {str(e)}")

# Local imports
from utils.logger import get_logger

# Setup Logging (Avoid duplicate configuration)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(handler)


class PasswordHasherManager:
    """
    Manager for password hashing operations.
    Uses Argon2id for maximum security against hardware attacks.
    """

    def __init__(self):
        """Initialize Argon2 CFFI hasher with secure defaults."""

        self.hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32
        )

        # Maximum password length to prevent DoS attacks
        self.max_password_length = 1024

        logger.info("PasswordHasherManager initialized with Argon2id")

    def verify_input_length(self, input_str: str) -> bool:
        """Validate string length to prevent Denial of Service."""
        if len(input_str) > self.max_password_length:
            return False
        return True

    def sanitize_input(self, input_str: str) -> str:
        """Clean input string (remove null bytes, trim whitespace)."""
        if not isinstance(input_str, str):
            return ""
        return input_str.strip('\x00').strip().replace('\n', '').replace('\r', '')

    def hash_password(self, password: str) -> str:
        """Hash a plaintext password using Argon2id."""
        if not isinstance(password, str):
            raise TypeError("Password must be a string")

        password = self.sanitize_input(password)

        if len(password) == 0:
            raise ValueError("Password cannot be empty")

        if not self.verify_input_length(password):
            logger.warning(f"Password attempt exceeds maximum length: {len(password)}")
            raise ValueError(f"Password too long (max {self.max_password_length} chars)")

        try:
            # Generate hash with auto salt
            return self.hasher.hash(password)
        except Exception as e:
            logger.error(f"Password hashing failed: {str(e)}")
            raise RuntimeError("Password hashing operation failed")

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        if not isinstance(password, str):
            raise TypeError("Password must be a string")
        if not isinstance(hashed, str):
            raise TypeError("Hash must be a string")

        password = self.sanitize_input(password)
        hashed = self.sanitize_input(hashed)

        if len(password) == 0:
            logger.warning("Empty password verification attempt")
            return False

        # Quick check for obvious failure without full compute
        if not hashed.startswith('$argon'):
            logger.debug(f"Invalid hash format. Expected $argon prefix, got: {hashed[:20]}...")
            return False

        try:
            # Constant-time comparison prevents timing attacks
            return self.hasher.verify(hashed, password)
        except VerifyMismatchError:
            logger.warning("Password verification failed")
            return False
        except InvalidHashError as e:
            logger.error(f"Invalid hash format encountered: {str(e)}")
            logger.error(f"Hash value: {hashed[:50]}...")
            return False
        except Exception as e:
            logger.error(f"Password verification exception: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def needs_rehash(self, hashed: str) -> bool:
        """Check if a hash needs re-hashing due to parameter updates."""
        try:
            return self.hasher.check_needs_rehash(hashed)
        except Exception:
            return False


# Global Singleton Instance
_global_hash_manager = None
_lock = threading.Lock()


def get_hash_manager() -> PasswordHasherManager:
    """Get singleton instance of hasher manager."""
    global _global_hash_manager

    if _global_hash_manager is None:
        with _lock:
            if _global_hash_manager is None:
                _global_hash_manager = PasswordHasherManager()

    return _global_hash_manager


# Convenience functions
def hash_password(password: str) -> str:
    """Convenience function to hash a password."""
    manager = get_hash_manager()
    return manager.hash_password(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    manager = get_hash_manager()
    return manager.verify_password(password, hashed)


def needs_rehash(hashed: str) -> bool:
    """Check if a stored hash should be updated."""
    manager = get_hash_manager()
    return manager.needs_rehash(hashed)


# Password validation helper
def is_weak_password(password: str) -> bool:
    """Basic strength check before hashing."""
    if not password or len(password) < 8:
        return True

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    score = sum([has_upper, has_lower, has_digit, has_special])
    return score < 3


# Admin reset functionality
def reset_admin_password(admin_email: str, new_password: str) -> bool:
    """Helper function to reset admin password via script."""
    from database.db_conn import execute_query

    try:
        admin_result = execute_query(
            """SELECT id FROM admin_accounts WHERE email = %s""",
            (admin_email,),
            fetch_all=True
        )

        if not admin_result:
            logger.error(f"Admin account not found: {admin_email}")
            return False

        admin_id = admin_result[0]['id']
        new_hash = hash_password(new_password)

        execute_query(
            """UPDATE admin_accounts SET password_hash = %s, updated_at = CURRENT_TIMESTAMP 
               WHERE id = %s""",
            (new_hash, admin_id)
        )

        logger.info(f"Admin password reset successful for: {admin_email}")
        return True

    except Exception as e:
        logger.error(f"Admin password reset failed: {str(e)}")
        return False


if __name__ == '__main__':
    print("=" * 60)
    print("PASSWORD HASHING SYSTEM TEST")
    print("=" * 60)

    test_password = "SecurePass123!"

    try:
        manager = get_hash_manager()

        # 1. Hash Test
        print(f"\nOriginal Password: {test_password}")
        hashed = manager.hash_password(test_password)
        print(f"Generated Hash:    {hashed[:50]}...")
        assert hashed.startswith("$argon"), "Hash format incorrect"

        # 2. Verify Test
        is_valid = manager.verify_password(test_password, hashed)
        print(f"Verification:      {'✅ PASS' if is_valid else '❌ FAIL'}")
        assert is_valid, "Verified same password failed"

        # 3. Wrong Password Test
        is_invalid = manager.verify_password("WrongPassword", hashed)
        print(f"Wrong Password:    {'✅ REJECTED' if not is_invalid else '❌ ACCEPTED'}")
        assert not is_invalid, "Wrong password was accepted"

        # 4. Weak Password Check
        print(f"\nWeak Password Check:")
        print(f"  Short 'Pass1':   {is_weak_password('Pass1')}")
        print(f"  Complex 'P@ss1': {is_weak_password('P@ss1!')}")

        print("\n" + "=" * 60)
        print("✅ ALL HASHING TESTS PASSED")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ TEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
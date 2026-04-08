# =============================================================================
# DERIV TRADING BOT - Encryption Utility Module
# Version: 1.4 (FIXED - decrypt_sensitive_data return type)
# Purpose: Secure encryption/decryption for sensitive user data
# Security: Fernet symmetric encryption with key stored in environment
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# FIX: Changed decrypt_sensitive_data to return str instead of dict
# =============================================================================

import os
import sys
import base64
import json
import threading
import logging
from datetime import datetime, timedelta
from typing import Optional, Any, Union

# FIX: Add project root to path so 'config' can be imported from utils folder
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Fernet from cryptography library
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError as e:
    print("CRITICAL: cryptography package required!")
    print("Install with: pip install cryptography")
    raise

# Local imports
from config import Config
from utils.logger import log_audit_event

# Setup Logging (Safe fallback if logger module fails)
try:
    logging.basicConfig(filename='logs/bot.log', level=logging.INFO)
    logger = logging.getLogger(__name__)
except Exception as e:
    # If file logging fails, create a basic console logger instead
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class EncryptedDataManager:
    """
    Centralized encryption/decryption manager for sensitive data.
    Uses Fernet symmetric encryption algorithm.
    """

    def __init__(self):
        """Initialize encryption with key from environment."""

        # Get encryption key from environment
        encryption_key = self._get_encryption_key()

        if not encryption_key:
            raise ValueError(
                "ENCRYPTION_KEY not found in environment variables. "
                "Please set it in your .env file or generate one."
            )

        # Initialize Fernet instance
        self.cipher_suite = Fernet(encryption_key.encode())

        logger.info("EncryptedDataManager initialized successfully")

    def _get_encryption_key(self) -> str:
        """
        Retrieve encryption key from environment or generate new one.

        Returns:
            str: Valid Fernet encryption key

        Raises:
            ValueError: If key cannot be retrieved or generated
        """
        key = os.getenv('ENCRYPTION_KEY')

        if key:
            # Validate existing key
            try:
                Fernet(key.encode())
                logger.debug("Using existing encryption key from environment")
                return key
            except Exception as e:
                logger.warning(f"Existing encryption key invalid: {str(e)}")

        # Generate new key for first-time setup
        logger.warning("Generating new encryption key")
        new_key = Fernet.generate_key().decode()

        logger.info("New encryption key generated")
        print("\n" + "=" * 60)
        print("IMPORTANT: Save this key! Lost keys mean lost data")
        print(f"ENCRYPTION_KEY={new_key}")
        print("=" * 60 + "\n")

        return new_key

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext string using Fernet.

        Args:
            plaintext: String data to encrypt

        Returns:
            str: Base64-encoded encrypted bytes

        Raises:
            TypeError: If input is not a string
            ValueError: If encryption fails
        """
        if not isinstance(plaintext, str):
            raise TypeError("Input must be a string")

        try:
            # Encode to bytes
            plaintext_bytes = plaintext.encode('utf-8')

            # Encrypt
            encrypted_bytes = self.cipher_suite.encrypt(plaintext_bytes)

            # Return as string (base64 encoded)
            encrypted_string = encrypted_bytes.decode('utf-8')

            return encrypted_string

        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext string using Fernet.

        Args:
            ciphertext: Base64-encoded encrypted bytes

        Returns:
            str: Decrypted plaintext string

        Raises:
            TypeError: If input is not a string
            ValueError: If decryption fails (invalid key/tampered data)
        """
        if not isinstance(ciphertext, str):
            raise TypeError("Input must be a string")

        try:
            # Decode from base64
            ciphertext_bytes = ciphertext.encode('utf-8')

            # Decrypt
            decrypted_bytes = self.cipher_suite.decrypt(ciphertext_bytes)

            # Decode from UTF-8
            decrypted_string = decrypted_bytes.decode('utf-8')

            return decrypted_string

        except InvalidToken:
            logger.error("Invalid token - possible tampering or wrong key")
            raise ValueError("Decryption failed: Invalid token")
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise ValueError(f"Decryption failed: {str(e)}")

    def encrypt_json(self, data: dict) -> str:
        """
        Encrypt JSON dictionary object.

        Args:
            data: Dictionary to encrypt

        Returns:
            str: JSON string representation of encrypted data
        """
        try:
            # Serialize to JSON string
            json_string = json.dumps(data)

            # Encrypt the JSON string
            encrypted = self.encrypt(json_string)

            return encrypted

        except Exception as e:
            logger.error(f"JSON encryption failed: {str(e)}")
            raise

    def decrypt_json(self, encrypted_data: str) -> dict:
        """
        Decrypt JSON dictionary object.

        Args:
            encrypted_data: Encrypted JSON string

        Returns:
            dict: Decrypted dictionary
        """
        try:
            # Decrypt the data
            decrypted_string = self.decrypt(encrypted_data)

            # Parse JSON
            data_dict = json.loads(decrypted_string)

            return data_dict

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing failed after decryption: {str(e)}")
            raise ValueError(f"Invalid JSON data")
        except Exception as e:
            logger.error(f"JSON decryption failed: {str(e)}")
            raise

    def encrypt_sensitive_data(self, data_type: str, data_value: str) -> str:
        """
        Encrypt specific type of sensitive data with metadata.

        Args:
            data_type: Type of data ('api_key', 'password_hash', 'token')
            data_value: The actual value to encrypt

        Returns:
            str: Encrypted data with metadata
        """
        # Add metadata for tracking
        metadata = {
            'type': data_type,
            'created_at': datetime.utcnow().isoformat(),
            'version': '1.0'
        }

        # Combine with original data
        full_data = {
            'metadata': metadata,
            'data': data_value
        }

        # Encrypt
        return self.encrypt_json(full_data)

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """
        Decrypt and validate sensitive data with metadata verification.

        Args:
            encrypted_data: Encrypted data with metadata

        Returns:
            str: Decrypted data value (NOT dict - FIXED)

        Raises:
            ValueError: If metadata validation fails
        """
        try:
            # Decrypt the data
            decrypted = self.decrypt_json(encrypted_data)

            # Verify structure
            if 'metadata' not in decrypted or 'data' not in decrypted:
                raise ValueError("Invalid encrypted data structure")

            # Verify version compatibility
            version = decrypted.get('metadata', {}).get('version', '1.0')
            if version != '1.0':
                logger.warning(f"Unknown encryption version: {version}")

            # Return data portion only as STRING
            return str(decrypted['data'])

        except Exception as e:
            logger.error(f"Sensitive data decryption failed: {str(e)}")
            raise


# Global instance
_global_encryptor = None
_lock = threading.Lock()


def get_encryptor() -> EncryptedDataManager:
    """Get singleton instance of encryption manager."""
    global _global_encryptor

    if _global_encryptor is None:
        with _lock:
            if _global_encryptor is None:
                try:
                    _global_encryptor = EncryptedDataManager()
                except ValueError as e:
                    logger.error(f"Encryption setup failed: {str(e)}")
                    raise

    return _global_encryptor


# =============================================================================
# CONVENIENCE FUNCTIONS FOR COMMON USES
# =============================================================================

def encrypt_api_key(api_key: str) -> str:
    """Encrypt Deriv API key for database storage."""
    try:
        encryptor = get_encryptor()
        return encryptor.encrypt_sensitive_data('api_key', api_key)
    except Exception as e:
        logger.error(f"API key encryption failed: {str(e)}")
        raise


def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt Deriv API key from database storage."""
    try:
        encryptor = get_encryptor()
        return encryptor.decrypt_sensitive_data(encrypted_key)
    except Exception as e:
        logger.error(f"API key decryption failed: {str(e)}")
        raise


def encrypt_password(password: str) -> str:
    """Encrypt password for storage."""
    try:
        encryptor = get_encryptor()
        return encryptor.encrypt_sensitive_data('password', password)
    except Exception as e:
        logger.error(f"Password encryption failed: {str(e)}")
        raise


def decrypt_password(encrypted_password: str) -> str:
    """Decrypt password for comparison."""
    try:
        encryptor = get_encryptor()
        return encryptor.decrypt_sensitive_data(encrypted_password)
    except Exception as e:
        logger.error(f"Password decryption failed: {str(e)}")
        raise


def encrypt_token(token: str) -> str:
    """Encrypt authentication token."""
    try:
        encryptor = get_encryptor()
        return encryptor.encrypt_sensitive_data('token', token)
    except Exception as e:
        logger.error(f"Token encryption failed: {str(e)}")
        raise


def decrypt_token(encrypted_token: str) -> str:
    """Decrypt authentication token."""
    try:
        encryptor = get_encryptor()
        return encryptor.decrypt_sensitive_data(encrypted_token)
    except Exception as e:
        logger.error(f"Token decryption failed: {str(e)}")
        raise


def encrypt_sensitive_data(data: str) -> str:
    """Encrypt any sensitive data (generic wrapper)."""
    try:
        encryptor = get_encryptor()
        return encryptor.encrypt_sensitive_data('generic', data)
    except Exception as e:
        logger.error(f"Sensitive data encryption failed: {str(e)}")
        raise


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """Decrypt any sensitive data (generic wrapper)."""
    try:
        encryptor = get_encryptor()
        return encryptor.decrypt_sensitive_data(encrypted_data)
    except Exception as e:
        logger.error(f"Sensitive data decryption failed: {str(e)}")
        raise


# =============================================================================
# KEY GENERATION HELPER
# =============================================================================

def generate_new_key():
    """Generate and display new Fernet encryption key for configuration."""
    try:
        from cryptography.fernet import Fernet

        new_key = Fernet.generate_key()

        print("=" * 60)
        print("NEW ENCRYPTION KEY GENERATED")
        print("=" * 60)
        print(f"Encryption Key: {new_key.decode()}")
        print("=" * 60)
        print("IMPORTANT: Add this to your .env file:")
        print(f"ENCRYPTION_KEY={new_key.decode()}")
        print("=" * 60)
        print("\n⚠️ WARNING: Once generated, old keys cannot decrypt existing data!")
        print("=" * 60)

        return new_key.decode()

    except Exception as e:
        print(f"Failed to generate encryption key: {str(e)}")
        raise


if __name__ == '__main__':
    # Test encryption functionality
    print("Testing Encryption System...")
    print("=" * 60)

    # Generate test key if not exists
    test_data = "This is test data for encryption system"

    try:
        # Get or create encryptor
        encryptor = get_encryptor()

        # Test basic encryption/decryption
        print(f"Original Data: {test_data}")

        encrypted = encryptor.encrypt(test_data)
        print(f"Encrypted:     {encrypted}")

        decrypted = encryptor.decrypt(encrypted)
        print(f"Decrypted:     {decrypted}")

        # Test JSON encryption
        test_json = {"key": "value", "number": 123}
        print(f"\nOriginal JSON: {test_json}")

        encrypted_json = encryptor.encrypt_json(test_json)
        print(f"Encrypted JSON: {encrypted_json}")

        decrypted_json = encryptor.decrypt_json(encrypted_json)
        print(f"Decrypted JSON: {decrypted_json}")

        # Test sensitive data encryption
        sensitive_encrypted = encryptor.encrypt_sensitive_data('api_key', test_data)
        print(f"\nSensitive Encrypted: {sensitive_encrypted}")

        sensitive_decrypted = encryptor.decrypt_sensitive_data(sensitive_encrypted)
        print(f"Sensitive Decrypted: {sensitive_decrypted}")
        print(f"Type: {type(sensitive_decrypted)}")  # Should be <class 'str'>

        print("\n✅ All encryption tests passed!")

    except Exception as e:
        print(f"\n❌ Encryption test failed: {str(e)}")
        print("\nTo fix this issue:")
        print("1. Generate a new encryption key using utils/encryptor.py")
        print("2. Add it to your .env file as ENCRYPTION_KEY")
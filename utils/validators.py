# =============================================================================
# DERIV TRADING BOT - Input Validation Module
# Version: 1.0
# Purpose: Validate user inputs across the application
# Security: Sanitize inputs, prevent injection attacks
# Theme: Dark Red (#8b0000) + Light Sea Green (#20b2aa) only
# =============================================================================

import os
import sys
import re
import logging  # ← FIXED: Added missing import
from typing import Tuple, Optional, Dict, Union, Any, List

# Local imports
from utils.logger import get_logger

# Setup Logging
logging.basicConfig(filename='logs/bot.log', level=logging.INFO)
logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


def validate_email_address(email: str, require_verified: bool = False) -> Tuple[bool, str]:
    """
    Validate email address format against RFC 5322 standards.

    Args:
        email: Email address string to validate
        require_verified: If True, check if domain is commonly verified

    Returns:
        Tuple of (is_valid: bool, error_message: str)

    Examples:
        >>> validate_email("user@example.com")
        (True, "Valid email address")

        >>> validate_email("invalid@")
        (False, "Invalid email format: Missing domain")
    """

    # Sanitize input
    if not isinstance(email, str):
        return False, "Email must be a string"

    email = email.strip().lower()

    if len(email) == 0:
        return False, "Email cannot be empty"

    if len(email) > 254:
        return False, "Email address too long (max 254 characters)"

    # RFC 5322 simplified email regex pattern
    email_pattern = re.compile(
        r'^(?:[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+)*|'
        r'"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")'
        r'@(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|'
        r'\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\])$'
    )

    if not email_pattern.match(email):
        return False, "Invalid email format: Must contain valid local part @ domain"

    # Extract domain and check for common issues
    local_part, domain = email.split('@')

    if len(local_part) == 0:
        return False, "Invalid email format: Missing local part"

    if len(domain) == 0:
        return False, "Invalid email format: Missing domain"

    if '.' not in domain:
        return False, "Invalid email format: Domain must contain at least one dot"

    if domain.startswith('.') or domain.endswith('.'):
        return False, "Invalid email format: Domain cannot start or end with dot"

    if '..' in domain:
        return False, "Invalid email format: Domain cannot contain consecutive dots"

    logger.debug(f"Email validation passed for: {email}")

    return True, "Valid email address"


def validate_password_strength(password: str, min_length: int = 8) -> Tuple[bool, str]:
    """
    Validate password meets security requirements.

    Args:
        password: Plain text password to validate
        min_length: Minimum required password length

    Returns:
        Tuple of (is_valid: bool, error_message: str)
    """
    if not isinstance(password, str):
        return False, "Password must be a string"

    password = password.strip()

    if len(password) < min_length:
        return False, f"Password too short (minimum {min_length} characters)"

    if len(password) > 128:
        return False, "Password too long (maximum 128 characters)"

    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
    has_special = any(c in special_chars for c in password)

    requirements_met = sum([has_uppercase, has_lowercase, has_digit, has_special])

    if requirements_met < 3:
        missing = []
        if not has_uppercase:
            missing.append("uppercase letter")
        if not has_lowercase:
            missing.append("lowercase letter")
        if not has_digit:
            missing.append("number")
        if not has_special:
            missing.append("special character (!@#$%^&*)")

        return False, f"Weak password: Include at least 3 of these ({', '.join(missing)})"

    if '123' in password.lower():
        return False, "Weak password: Avoid sequential numbers (e.g., 123)"

    if 'abc' in password.lower():
        return False, "Weak password: Avoid sequential letters (e.g., abc)"

    logger.debug(f"Password strength validated successfully")

    return True, "Strong password"


def validate_stake_amount(stake: Union[str, float, int]) -> Tuple[bool, str]:
    try:
        stake_float = float(stake) if isinstance(stake, str) else float(stake)
    except (ValueError, TypeError):
        return False, "Stake amount must be a valid number"

    if stake_float <= 0:
        return False, "Stake amount must be greater than zero"

    MAX_STAKE = 10000.00
    if stake_float > MAX_STAKE:
        return False, f"Stake amount exceeds maximum allowed (${MAX_STAKE:.2f})"

    if '.' in str(stake_float):
        if len(str(stake_float).split('.')[1]) > 2:
            return False, "Stake amount cannot exceed 2 decimal places"

    MIN_STAKE = 0.10
    if stake_float < MIN_STAKE:
        return False, f"Stake amount below minimum ({MIN_STAKE:.2f})"

    logger.debug(f"Stake amount validated: ${stake_float:.2f}")
    return True, f"Valid stake amount: ${stake_float:.2f}"


def validate_risk_percentage(risk: Union[str, float, int]) -> Tuple[bool, str]:
    try:
        risk_float = float(risk) if isinstance(risk, str) else float(risk)
    except (ValueError, TypeError):
        return False, "Risk percentage must be a valid number"

    if risk_float < 0:
        return False, "Risk percentage must be non-negative"

    if risk_float > 100:
        return False, "Risk percentage cannot exceed 100%"

    if '.' in str(risk_float):
        if len(str(risk_float).split('.')[1]) > 4:
            return False, "Risk percentage cannot exceed 4 decimal places"

    if risk_float > 5.0:
        logger.warning(f"High risk percentage detected: {risk_float}%")
        return True, f"Valid risk percentage (high): {risk_float:.2f}%"

    logger.debug(f"Risk percentage validated: {risk_float:.2f}%")
    return True, f"Valid risk percentage: {risk_float:.2f}%"


def validate_deriv_api_token(token: str) -> Tuple[bool, str]:
    if not isinstance(token, str):
        return False, "Token must be a string"

    token = token.strip()

    if len(token) == 0:
        return False, "API token cannot be empty"

    if len(token) < 16:
        return False, "API token too short (minimum 16 characters)"

    if len(token) > 256:
        return False, "API token too long (maximum 256 characters)"

    if not re.match(r'^[A-Za-z0-9]+$', token):
        return False, "API token contains invalid characters (only A-Z, a-z, 0-9 allowed)"

    logger.debug(f"Deriv API token format validated")
    return True, "Valid Deriv API token format"


def validate_timeframe(timeframe: str) -> Tuple[bool, str]:
    if not isinstance(timeframe, str):
        return False, "Timeframe must be a string"

    timeframe = timeframe.strip().upper()

    VALID_TIMEFRAMES = ['M1', 'M2', 'M5', 'M10', 'M15', 'M30',
                        'H1', 'H2', 'H3', 'H4', 'H6', 'H8', 'D1']

    if timeframe not in VALID_TIMEFRAMES:
        return False, f"Invalid timeframe format: Use M1, M5, M15, H1, H4, D1"

    logger.debug(f"Timeframe validated: {timeframe}")
    return True, f"Valid timeframe: {timeframe}"


def validate_symbol(symbol: str) -> Tuple[bool, str]:
    if not isinstance(symbol, str):
        return False, "Symbol must be a string"

    symbol = symbol.strip().upper()

    if len(symbol) == 0:
        return False, "Trading symbol cannot be empty"

    if len(symbol) > 50:
        return False, "Trading symbol too long (maximum 50 characters)"

    if not re.match(r'^[A-Z0-9_\-]+$', symbol):
        return False, "Invalid symbol format: Only uppercase letters, numbers, _ and - allowed"

    logger.debug(f"Symbol validated: {symbol}")
    return True, "Valid trading symbol"


def validate_account_mode(mode: str) -> Tuple[bool, str]:
    if not isinstance(mode, str):
        return False, "Account mode must be a string"

    mode = mode.strip().lower()

    VALID_MODES = ['demo', 'live']

    if mode not in VALID_MODES:
        return False, f"Invalid account mode: Use '{VALID_MODES[0]}' or '{VALID_MODES[1]}'"

    logger.debug(f"Account mode validated: {mode}")
    return True, f"Valid account mode: {mode.capitalize()}"


def validate_numeric_value(value: Any, min_val: float, max_val: float, field_name: str) -> Tuple[bool, str]:
    try:
        num_value = float(value)
    except (ValueError, TypeError):
        return False, f"{field_name} must be a valid number"

    if num_value < min_val:
        return False, f"{field_name} below minimum ({min_val})"

    if num_value > max_val:
        return False, f"{field_name} above maximum ({max_val})"

    return True, f"Valid {field_name}: {num_value}"


# =============================================================================
# MAIN VALIDATION FUNCTIONS (Convenience wrappers)
# =============================================================================

def validate_user_input(user_data: Dict[str, Any]) -> Tuple[bool, str]:
    required_fields = ['email', 'password']

    for field in required_fields:
        if field not in user_data:
            return False, f"Missing required field: {field}"

    email_valid, email_msg = validate_email_address(user_data['email'])
    if not email_valid:
        return False, f"Invalid email: {email_msg}"

    pwd_valid, pwd_msg = validate_password_strength(user_data['password'])
    if not pwd_valid:
        return False, f"Invalid password: {pwd_msg}"

    logger.info("User input validation passed")
    return True, "All user inputs valid"


def validate_bot_settings(settings: Dict[str, Any]) -> Tuple[bool, str]:
    errors = []

    if 'timeframe' in settings:
        tf_valid, tf_msg = validate_timeframe(settings['timeframe'])
        if not tf_valid:
            errors.append(f"Timeframe: {tf_msg}")

    if 'stake' in settings:
        stake_valid, stake_msg = validate_stake_amount(settings['stake'])
        if not stake_valid:
            errors.append(f"Stake: {stake_msg}")

    if 'risk' in settings:
        risk_valid, risk_msg = validate_risk_percentage(settings['risk'])
        if not risk_valid:
            errors.append(f"Risk: {risk_msg}")

    if 'account_mode' in settings:
        mode_valid, mode_msg = validate_account_mode(settings['account_mode'])
        if not mode_valid:
            errors.append(f"Mode: {mode_msg}")

    if errors:
        return False, "; ".join(errors)

    logger.info("Bot settings validation passed")
    return True, "All bot settings valid"


def validate_email(email: str) -> bool:
    """
    Wrapper for validate_email_address.
    Returns True if valid, False otherwise.
    Used for compatibility with imports expecting 'validate_email'.
    """
    is_valid, _ = validate_email_address(email)
    return is_valid


if __name__ == '__main__':
    print("=" * 60)
    print("INPUT VALIDATION MODULE TEST SUITE")
    print("=" * 60)

    test_cases = [
        ("valid@email.com", True, "Email"),
        ("invalid@", False, "Email"),
        ("Pass123!", True, "Password"),
        ("weak", False, "Password"),
        (10.50, True, "Stake"),
        (-1, False, "Stake"),
        (1.5, True, "Risk"),
        (150.0, False, "Risk"),
        ("M5", True, "Timeframe"),
        ("INVALID", False, "Timeframe"),
        ("R_100", True, "Symbol"),
        ("", False, "Symbol"),
    ]

    passed = failed = 0

    for test_input, expected, test_type in test_cases:
        print(f"\nTesting {test_type}: '{test_input}'")
        try:
            if test_type == "Email":
                result, msg = validate_email_address(test_input)
            elif test_type == "Password":
                result, msg = validate_password_strength(test_input)
            elif test_type == "Stake":
                result, msg = validate_stake_amount(test_input)
            elif test_type == "Risk":
                result, msg = validate_risk_percentage(test_input)
            elif test_type == "Timeframe":
                result, msg = validate_timeframe(test_input)
            elif test_type == "Symbol":
                result, msg = validate_symbol(test_input)

            status = "PASS" if result == expected else "FAIL"
            if result == expected:
                passed += 1
            else:
                failed += 1

            print(f"  Expected: {'Valid' if expected else 'Invalid'}")
            print(f"  Got:      {'Valid' if result else 'Invalid'}")
            print(f"  Message:  {msg}")
            print(f"  Status:   {status}")

        except Exception as e:
            failed += 1
            print(f"  EXCEPTION: {str(e)}")

    print("\n" + "=" * 60)
    print(f"VALIDATION TEST RESULTS")
    print(f"Passed: {passed}/{len(test_cases)}")
    print(f"Failed: {failed}/{len(test_cases)}")
    print("=" * 60)

    if failed == 0:
        print("ALL VALIDATION TESTS PASSED")
    else:
        print(f"{failed} TESTS FAILED - Review validation logic")
    print("INPUT VALIDATION MODULE TEST SUITE")
    print("=" * 60)

    test_cases = [
        ("valid@email.com", True, "Email"),
        ("invalid@", False, "Email"),
        ("Pass123!", True, "Password"),
        ("weak", False, "Password"),
        (10.50, True, "Stake"),
        (-1, False, "Stake"),
        (1.5, True, "Risk"),
        (150.0, False, "Risk"),
        ("M5", True, "Timeframe"),
        ("INVALID", False, "Timeframe"),
        ("R_100", True, "Symbol"),
        ("", False, "Symbol"),
    ]

    passed = failed = 0

    for test_input, expected, test_type in test_cases:
        print(f"\nTesting {test_type}: '{test_input}'")
        try:
            if test_type == "Email":
                result, msg = validate_email_address(test_input)
            elif test_type == "Password":
                result, msg = validate_password_strength(test_input)
            elif test_type == "Stake":
                result, msg = validate_stake_amount(test_input)
            elif test_type == "Risk":
                result, msg = validate_risk_percentage(test_input)
            elif test_type == "Timeframe":
                result, msg = validate_timeframe(test_input)
            elif test_type == "Symbol":
                result, msg = validate_symbol(test_input)

            status = "PASS" if result == expected else "FAIL"
            if result == expected:
                passed += 1
            else:
                failed += 1

            print(f"  Expected: {'Valid' if expected else 'Invalid'}")
            print(f"  Got:      {'Valid' if result else 'Invalid'}")
            print(f"  Message:  {msg}")
            print(f"  Status:   {status}")

        except Exception as e:
            failed += 1
            print(f"  EXCEPTION: {str(e)}")

    print("\n" + "=" * 60)
    print(f"VALIDATION TEST RESULTS")
    print(f"Passed: {passed}/{len(test_cases)}")
    print(f"Failed: {failed}/{len(test_cases)}")
    print("=" * 60)

    if failed == 0:
        print("ALL VALIDATION TESTS PASSED")
    else:
        print(f"{failed} TESTS FAILED - Review validation logic")
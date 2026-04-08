import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    # =========================================================================
    # Application URL Configuration
    # =========================================================================
    # ✅ FIX: Added APP_URL for email verification links
    APP_URL = os.getenv('APP_URL', 'http://localhost:5000')

    # =========================================================================
    # Database Configuration
    # =========================================================================
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 5432))
    DB_NAME = os.getenv('DB_NAME', 'trading_db')
    DB_USER = os.getenv('DB_USER', 'postgres')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')

    # =========================================================================
    # Flask Configuration
    # =========================================================================
    SECRET_KEY = os.getenv('SECRET_KEY', '')
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour default

    # =========================================================================
    # Email/SMTP Configuration
    # =========================================================================
    SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
    EMAIL_FROM = os.getenv('EMAIL_FROM', 'no-reply@tradingbot.com')

    # =========================================================================
    # Groq AI Configuration
    # =========================================================================
    GROQ_API_KEY = os.getenv('GROQ_API_KEY', '')
    GROQ_MODEL = os.getenv('GROQ_MODEL', 'llama-3.3-70b-versatile')

    # =========================================================================
    # Encryption Configuration
    # =========================================================================
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', '')

    # =========================================================================
    # System Constants
    # =========================================================================
    DEFAULT_RISK_PERCENTAGE = float(os.getenv('DEFAULT_RISK_PERCENTAGE', '1.0'))
    MAX_TRADES_PER_DAY = int(os.getenv('MAX_TRADES_PER_DAY', '20'))
    MAX_TRADES_PER_TIMEFRAME = int(os.getenv('MAX_TRADES_PER_TIMEFRAME', '1'))

    # =========================================================================
    # Server Configuration
    # =========================================================================
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))

    # =========================================================================
    # Theme Configuration
    # =========================================================================
    THEME_PRIMARY_COLOR = '#8b0000'  # Dark Red
    THEME_SECONDARY_COLOR = '#20b2aa'  # Light Sea Green

    # =========================================================================
    # Helper Methods
    # =========================================================================
    @classmethod
    def get_database_connection_string(cls):
        return f"postgresql://{cls.DB_USER}:{cls.DB_PASSWORD}@{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"

    @classmethod
    def is_production(cls):
        return os.getenv('ENVIRONMENT', 'development') == 'production'
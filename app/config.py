"""
Application Configuration Module
Loads configuration from environment variables with safe defaults.
"""

import os
import json
import logging
from datetime import timedelta
from dotenv import load_dotenv

# Load .env file from the backend root directory if present
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
dotenv_path = os.path.join(backend_root, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)


def _json_env(name: str, default):
    """Parse a JSON object from an environment variable, falling back to default."""
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else default
    except json.JSONDecodeError:
        logging.getLogger(__name__).warning("Environment variable %s is not valid JSON; ignoring.", name)
        return default


class Config:
    """Base Configuration"""
    ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() in ('true', '1', 't')
    PORT = int(os.getenv('PORT', 5000))
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

    # JWT Settings
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES_MINUTES', 15))
    )
    REFRESH_TOKEN_EXPIRES_DAYS = int(os.getenv('REFRESH_TOKEN_EXPIRES_DAYS', 30))

    # Google OAuth settings
    _raw_client_ids = os.getenv('GOOGLE_CLIENT_IDS', '')
    GOOGLE_CLIENT_IDS = [
        cid.strip() for cid in _raw_client_ids.split(',') if cid.strip()
    ]
    # Also support single GOOGLE_CLIENT_ID env var
    _single_cid = os.getenv('GOOGLE_CLIENT_ID', '').strip()
    if _single_cid and _single_cid not in GOOGLE_CLIENT_IDS:
        GOOGLE_CLIENT_IDS.append(_single_cid)

    # Supabase PostgreSQL Database Settings
    DATABASE_URL = os.getenv('DATABASE_URL', '')
    SUPABASE_DB_HOST = os.getenv('SUPABASE_DB_HOST', '')
    SUPABASE_DB_NAME = os.getenv('SUPABASE_DB_NAME', 'postgres')
    SUPABASE_DB_USER = os.getenv('SUPABASE_DB_USER', 'postgres')
    SUPABASE_DB_PASSWORD = os.getenv('SUPABASE_DB_PASSWORD', '')
    SUPABASE_DB_PORT = int(os.getenv('SUPABASE_DB_PORT', 5432))

    # Multi-App Settings
    DEFAULT_APP_KEY = os.getenv('DEFAULT_APP_KEY', 'main_app')
    AUTO_PROVISION_USER_APP_ACCESS = os.getenv(
        'AUTO_PROVISION_USER_APP_ACCESS', 'True'
    ).lower() in ('true', '1', 't')

    # CORS Settings
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv('CORS_ORIGINS', '*').split(',')
        if origin.strip()
    ]

    # ------------------------------------------------------------------
    # Payments: Google Play Billing
    # ------------------------------------------------------------------
    # JSON map of app_key -> Android package name, e.g.
    #   {"main_app": "com.healthscanapp.mobile", "learnboard_app": "com.learnboard"}
    GOOGLE_PLAY_PACKAGES = _json_env('GOOGLE_PLAY_PACKAGES', {})
    # Service account credentials with access to the Play Console (Android Publisher API).
    # Provide EITHER the raw JSON content (recommended on Render) OR a file path.
    GOOGLE_PLAY_SERVICE_ACCOUNT_JSON = os.getenv('GOOGLE_PLAY_SERVICE_ACCOUNT_JSON', '').strip()
    GOOGLE_PLAY_SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_PLAY_SERVICE_ACCOUNT_FILE', '').strip()

    # ------------------------------------------------------------------
    # Payments: Apple In-App Purchase (App Store Server API)
    # ------------------------------------------------------------------
    # JSON map of app_key -> iOS bundle id, e.g. {"main_app": "com.healthscanapp.mobile"}
    APPLE_BUNDLE_IDS = _json_env('APPLE_BUNDLE_IDS', {})
    APPLE_IAP_KEY_ID = os.getenv('APPLE_IAP_KEY_ID', '').strip()
    APPLE_IAP_ISSUER_ID = os.getenv('APPLE_IAP_ISSUER_ID', '').strip()
    # Contents of the .p8 private key. Literal "\n" sequences are converted to newlines.
    APPLE_IAP_PRIVATE_KEY = os.getenv('APPLE_IAP_PRIVATE_KEY', '').replace('\\n', '\n').strip()

    # How often (minutes) an expired-looking subscription may be re-checked with the store
    # when the user asks for their status. Covers renewals until webhooks are added.
    PAYMENTS_REVERIFY_INTERVAL_MINUTES = int(os.getenv('PAYMENTS_REVERIFY_INTERVAL_MINUTES', 60))

    # Optional shared secrets for verifying incoming store webhook calls
    GOOGLE_RTDN_WEBHOOK_SECRET = os.getenv('GOOGLE_RTDN_WEBHOOK_SECRET', '').strip()
    APPLE_WEBHOOK_SECRET = os.getenv('APPLE_WEBHOOK_SECRET', '').strip()

    # ------------------------------------------------------------------
    # Email & Password Auth / Transactional Email Settings
    # ------------------------------------------------------------------
    REQUIRE_EMAIL_VERIFICATION = os.getenv('REQUIRE_EMAIL_VERIFICATION', 'False').lower() in ('true', '1', 't')
    MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv('MAX_FAILED_LOGIN_ATTEMPTS', 5))
    ACCOUNT_LOCKOUT_MINUTES = int(os.getenv('ACCOUNT_LOCKOUT_MINUTES', 15))
    PASSWORD_RESET_OTP_MINUTES = int(os.getenv('PASSWORD_RESET_OTP_MINUTES', 15))
    PASSWORD_RESET_MAX_ATTEMPTS = int(os.getenv('PASSWORD_RESET_MAX_ATTEMPTS', 5))

    # Email delivery: 'resend' | 'smtp' | 'console' (auto-detected if blank)
    EMAIL_PROVIDER = os.getenv('EMAIL_PROVIDER', '').strip()
    EMAIL_FROM = os.getenv('EMAIL_FROM', 'Auth <onboarding@resend.dev>').strip()
    RESEND_API_KEY = os.getenv('RESEND_API_KEY', '').strip()
    SMTP_HOST = os.getenv('SMTP_HOST', '').strip()
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USER = os.getenv('SMTP_USER', '').strip()
    SMTP_PASS = os.getenv('SMTP_PASS', '').strip()


class TestConfig(Config):
    """Testing Configuration"""
    ENV = 'testing'
    TESTING = True
    DEBUG = False
    JWT_SECRET_KEY = 'test-jwt-secret-key'
    GOOGLE_CLIENT_IDS = ['test-web-client-id.apps.googleusercontent.com']
    DATABASE_URL = 'mock://testing'
    GOOGLE_PLAY_PACKAGES = {'main_app': 'com.healthscanapp.mobile'}
    APPLE_BUNDLE_IDS = {}

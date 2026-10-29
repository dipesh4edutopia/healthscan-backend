"""
Application Configuration Module
Loads configuration from environment variables with safe defaults.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load .env file from the backend root directory if present
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
dotenv_path = os.path.join(backend_root, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)


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


class TestConfig(Config):
    """Testing Configuration"""
    ENV = 'testing'
    TESTING = True
    DEBUG = False
    JWT_SECRET_KEY = 'test-jwt-secret-key'
    GOOGLE_CLIENT_IDS = ['test-web-client-id.apps.googleusercontent.com']
    DATABASE_URL = 'mock://testing'

"""
Token and Session Management Service
Handles JWT access token generation/validation and cryptographic hashing of refresh tokens.
"""

import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple
import jwt
from app.config import Config


class TokenError(Exception):
    """Base exception for token errors."""
    pass


class TokenExpiredError(TokenError):
    """Access token has expired."""
    pass


class InvalidAccessTokenError(TokenError):
    """Access token is invalid or tampered with."""
    pass


def generate_access_token(
    user_id: str,
    email: str,
    app_id: str,
    app_key: str,
    role: str = 'user',
    expires_delta: timedelta = None,
) -> Tuple[str, int]:
    """
    Generates a cryptographically signed JWT access token.

    Payload claims:
      - sub: user_id (UUID)
      - email: user email
      - app_id: app UUID
      - app_key: unique app key string
      - role: user's role in this app
      - type: 'access'
      - iat: issued-at timestamp
      - exp: expiration timestamp

    Returns:
      (token_str, expires_in_seconds)
    """
    now = datetime.now(timezone.utc)
    delta = expires_delta or Config.JWT_ACCESS_TOKEN_EXPIRES
    expires_at = now + delta
    expires_in = int(delta.total_seconds())

    payload = {
        'sub': str(user_id),
        'email': str(email),
        'app_id': str(app_id),
        'app_key': str(app_key),
        'role': str(role),
        'type': 'access',
        'iat': int(now.timestamp()),
        'exp': int(expires_at.timestamp()),
    }

    token = jwt.encode(
        payload,
        Config.JWT_SECRET_KEY,
        algorithm=Config.JWT_ALGORITHM,
    )
    # PyJWT 2.x returns str directly
    return token, expires_in


def decode_access_token(token_str: str) -> Dict[str, Any]:
    """
    Decodes and validates a JWT access token.
    Raises TokenExpiredError or InvalidAccessTokenError.
    """
    try:
        payload = jwt.decode(
            token_str,
            Config.JWT_SECRET_KEY,
            algorithms=[Config.JWT_ALGORITHM],
            options={'require': ['exp', 'iat', 'sub', 'app_id', 'role']},
        )
        if payload.get('type') != 'access':
            raise InvalidAccessTokenError("Invalid token type. Expected access token.")
        return payload
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError("Access token has expired. Please refresh your session.")
    except jwt.InvalidTokenError as ite:
        raise InvalidAccessTokenError(f"Invalid access token: {ite}")


def generate_raw_refresh_token() -> str:
    """
    Generates a high-entropy, cryptographically secure random token string.
    This raw token is delivered to the client and NEVER stored in the database.
    """
    # 48 bytes urlsafe produces a 64-character token with ~384 bits of entropy
    return secrets.token_urlsafe(48)


def hash_refresh_token(raw_token: str) -> str:
    """
    Computes the SHA-256 cryptographic hex digest of a raw refresh token.
    ONLY this hash is stored and queried in the database.
    """
    if not raw_token or not isinstance(raw_token, str):
        raise ValueError("Invalid refresh token provided for hashing.")
    return hashlib.sha256(raw_token.strip().encode('utf-8')).hexdigest()

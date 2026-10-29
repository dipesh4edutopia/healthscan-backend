"""
Google ID Token Verification Service
Validates issuer, audience, expiry, signature, and extracts verified claims.
"""

import logging
from typing import Dict, Any, List, Optional
from app.config import Config

logger = logging.getLogger(__name__)

# Valid Google token issuers per OpenID Connect specifications
VALID_ISSUERS = {
    'accounts.google.com',
    'https://accounts.google.com',
}


class GoogleAuthError(Exception):
    """Base exception for Google authentication errors."""
    pass


class InvalidTokenError(GoogleAuthError):
    """Token is malformed or signature verification failed."""
    pass


class ExpiredTokenError(GoogleAuthError):
    """Google ID token has expired."""
    pass


class InvalidAudienceError(GoogleAuthError):
    """Token audience does not match any configured Google client IDs."""
    pass


class UnverifiedEmailError(GoogleAuthError):
    """The Google user's email address has not been verified."""
    pass


def verify_google_id_token(
    token_str: str,
    allowed_client_ids: Optional[List[str]] = None,
    clock_skew_seconds: int = 10,
    request_adapter: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Verifies a Google ID token server-side using Google's public certs.

    Validates:
      1. Cryptographic signature against Google public keys
      2. Expiry (exp claim)
      3. Issuer (iss claim) in {'accounts.google.com', 'https://accounts.google.com'}
      4. Audience (aud claim) matches one of allowed_client_ids
      5. sub claim exists (unique Google subject identifier)
      6. email_verified is True

    Returns:
      Normalized user payload:
        {
          "google_sub": str,
          "email": str,
          "email_verified": bool,
          "full_name": str,
          "avatar_url": str,
          "raw_claims": dict
        }
    """
    if not token_str or not isinstance(token_str, str):
        raise InvalidTokenError("ID token string is missing or empty.")

    target_audiences = allowed_client_ids if allowed_client_ids is not None else Config.GOOGLE_CLIENT_IDS

    try:
        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests

        req = request_adapter if request_adapter is not None else google_requests.Request()

        # id_token.verify_oauth2_token verifies signature, exp, and optionally audience.
        # When audience=None, we perform explicit multi-client-id audience validation below.
        claims = id_token.verify_oauth2_token(
            token_str,
            req,
            audience=None,
            clock_skew_in_seconds=clock_skew_seconds,
        )
    except ValueError as ve:
        err_msg = str(ve).lower()
        if "token has expired" in err_msg or "token expired" in err_msg:
            raise ExpiredTokenError(f"Google ID token has expired: {ve}")
        raise InvalidTokenError(f"Invalid Google ID token: {ve}")
    except Exception as e:
        logger.error(f"Unexpected error verifying Google ID token: {e}")
        raise InvalidTokenError(f"Failed to verify Google ID token: {e}")

    # 1. Validate Issuer
    issuer = claims.get('iss')
    if issuer not in VALID_ISSUERS:
        raise InvalidTokenError(f"Invalid token issuer '{issuer}'. Expected one of {VALID_ISSUERS}.")

    # 2. Validate Audience
    aud = claims.get('aud')
    if target_audiences:
        if aud not in target_audiences:
            raise InvalidAudienceError(
                f"Token audience '{aud}' does not match configured Google client IDs."
            )
    else:
        logger.warning(
            "GOOGLE_CLIENT_IDS is not configured in environment! "
            "Audience validation skipped in development mode."
        )

    # 3. Validate Google Subject Identifier
    google_sub = claims.get('sub')
    if not google_sub or not str(google_sub).strip():
        raise InvalidTokenError("Google ID token is missing a valid 'sub' identifier.")

    # 4. Validate Email & Verification Status
    email = claims.get('email')
    if not email:
        raise InvalidTokenError("Google ID token does not contain an email address.")

    email_verified = claims.get('email_verified')
    # Some providers return string 'true', handle both boolean and string
    is_verified = (email_verified is True) or (str(email_verified).lower() == 'true')
    if not is_verified:
        raise UnverifiedEmailError(
            f"Google account email '{email}' is not verified. Access is prohibited."
        )

    # 5. Extract user profile information
    full_name = claims.get('name') or claims.get('given_name', '')
    avatar_url = claims.get('picture')

    return {
        'google_sub': str(google_sub).strip(),
        'email': str(email).strip().lower(),
        'email_verified': True,
        'full_name': full_name.strip() if full_name else None,
        'avatar_url': str(avatar_url).strip() if avatar_url else None,
        'raw_claims': claims,
    }

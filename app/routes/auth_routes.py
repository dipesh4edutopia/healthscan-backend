"""
Authentication Blueprint Routes
Endpoints for Google Sign-In, token refresh, session revocation, and user context.
"""

import logging
from flask import Blueprint, request, jsonify, g

from app.services.auth_service import (
    AuthService,
    AppNotFoundError,
    AppInactiveError,
    UserDeactivatedError,
    AppAccessDeniedError,
    InvalidSessionError,
    SessionRevokedError,
    SessionExpiredError,
)
from app.services.google_auth import (
    GoogleAuthError,
    InvalidTokenError,
    ExpiredTokenError,
    InvalidAudienceError,
    UnverifiedEmailError,
)
from app.middleware import require_auth

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')


@auth_bp.route('/google', methods=['POST'])
def google_sign_in():
    """
    Authenticate or Register via Google ID Token.

    Request Body (JSON):
      {
        "id_token": "<google_id_token_jwt>",
        "app_key": "main_app",                 // Optional, fallback to X-App-Key header or DEFAULT_APP_KEY
        "device_label": "Alex's Pixel 8"       // Optional
      }

    Headers:
      X-App-Key: "main_app"                    // Optional header

    Returns 200 OK:
      {
        "access_token": "...",
        "refresh_token": "...",
        "token_type": "Bearer",
        "expires_in": 900,
        "user": { ... },
        "app": { ... }
      }
    """
    data = request.get_json(silent=True) or {}
    id_token_str = data.get('id_token')

    if not id_token_str:
        return jsonify({
            'error': 'BadRequest',
            'message': 'Missing required parameter: "id_token".',
        }), 400

    # Resolve app key from body, custom header, or default
    app_key = data.get('app_key') or request.headers.get('X-App-Key')
    device_label = data.get('device_label')
    user_agent = request.headers.get('User-Agent')

    try:
        result = AuthService.authenticate_with_google(
            id_token_str=id_token_str,
            app_key=app_key,
            user_agent=user_agent,
            device_label=device_label,
        )
        return jsonify(result), 200

    # Google verification errors -> 401 Unauthorized
    except ExpiredTokenError as ete:
        return jsonify({'error': 'TokenExpired', 'message': str(ete)}), 401
    except InvalidAudienceError as iae:
        return jsonify({'error': 'InvalidAudience', 'message': str(iae)}), 401
    except UnverifiedEmailError as uee:
        return jsonify({'error': 'UnverifiedEmail', 'message': str(uee)}), 401
    except (InvalidTokenError, GoogleAuthError) as gae:
        return jsonify({'error': 'InvalidToken', 'message': str(gae)}), 401

    # App resolution errors -> 404 Not Found / 403 Forbidden
    except AppNotFoundError as ane:
        return jsonify({'error': 'AppNotFound', 'message': str(ane)}), 404
    except AppInactiveError as aie:
        return jsonify({'error': 'AppInactive', 'message': str(aie)}), 403

    # Authorization and user status errors -> 403 Forbidden
    except UserDeactivatedError as ude:
        return jsonify({'error': 'UserDeactivated', 'message': str(ude)}), 403
    except AppAccessDeniedError as aade:
        return jsonify({'error': 'AppAccessDenied', 'message': str(aade)}), 403

    except Exception as e:
        logger.exception("Unexpected error during Google authentication")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'An unexpected authentication error occurred on the server.',
        }), 500


@auth_bp.route('/refresh', methods=['POST'])
def refresh_session():
    """
    Refresh Session & Rotate Refresh Token.

    Request Body (JSON):
      {
        "refresh_token": "<raw_refresh_token>",
        "device_label": "Optional device label"
      }

    Returns 200 OK:
      {
        "access_token": "...",
        "refresh_token": "<new_rotated_refresh_token>",
        "token_type": "Bearer",
        "expires_in": 900,
        "user": { ... },
        "app": { ... }
      }
    """
    data = request.get_json(silent=True) or {}
    raw_refresh_token = data.get('refresh_token')

    if not raw_refresh_token:
        return jsonify({
            'error': 'BadRequest',
            'message': 'Missing required parameter: "refresh_token".',
        }), 400

    device_label = data.get('device_label')
    user_agent = request.headers.get('User-Agent')

    try:
        result = AuthService.refresh_session(
            raw_refresh_token=raw_refresh_token,
            user_agent=user_agent,
            device_label=device_label,
        )
        return jsonify(result), 200

    except SessionRevokedError as sre:
        return jsonify({'error': 'SessionRevoked', 'message': str(sre)}), 401
    except SessionExpiredError as see:
        return jsonify({'error': 'SessionExpired', 'message': str(see)}), 401
    except InvalidSessionError as ise:
        return jsonify({'error': 'InvalidSession', 'message': str(ise)}), 401
    except UserDeactivatedError as ude:
        return jsonify({'error': 'UserDeactivated', 'message': str(ude)}), 403
    except (AppInactiveError, AppAccessDeniedError) as ae:
        return jsonify({'error': 'AccessDenied', 'message': str(ae)}), 403
    except Exception as e:
        logger.exception("Unexpected error during session refresh")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'An unexpected error occurred while refreshing your session.',
        }), 500


@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    Revoke a single refresh token session.

    Request Body (JSON):
      {
        "refresh_token": "<raw_refresh_token>"
      }
    """
    data = request.get_json(silent=True) or {}
    raw_refresh_token = data.get('refresh_token')

    if not raw_refresh_token:
        return jsonify({
            'error': 'BadRequest',
            'message': 'Missing required parameter: "refresh_token".',
        }), 400

    try:
        revoked = AuthService.logout_session(raw_refresh_token)
        return jsonify({
            'success': True,
            'message': 'Session revoked successfully.' if revoked else 'Session was already inactive.',
        }), 200
    except Exception as e:
        logger.exception("Error during session logout")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'Failed to process logout.',
        }), 500


@auth_bp.route('/logout-all', methods=['POST'])
@require_auth
def logout_all():
    """
    Revoke all active sessions for the current authenticated user on this app.
    Requires Authorization: Bearer <access_token>.
    """
    try:
        count = AuthService.logout_all_sessions(
            user_id=g.current_user_id,
            app_id=g.current_app_id,
        )
        return jsonify({
            'success': True,
            'revoked_count': count,
            'message': f"Successfully revoked {count} active session(s) on application '{g.current_app_key}'.",
        }), 200
    except Exception as e:
        logger.exception("Error during logout-all")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'Failed to revoke sessions.',
        }), 500


@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_current_user_profile():
    """
    Get Current Authenticated User Profile & App Authorization.
    Requires Authorization: Bearer <access_token>.
    """
    try:
        profile = AuthService.get_user_profile(
            user_id=g.current_user_id,
            app_id=g.current_app_id,
        )
        return jsonify({
            'user': {
                'id': str(profile['id']),
                'email': profile['email'],
                'email_verified': profile['email_verified'],
                'full_name': profile['full_name'],
                'avatar_url': profile['avatar_url'],
                'is_active': profile['is_active'],
                'created_at': profile['created_at'].isoformat() if profile.get('created_at') else None,
            },
            'app': {
                'id': str(g.current_app_id),
                'app_key': profile['app_key'],
                'display_name': profile['app_display_name'],
                'role': profile['role'],
                'is_active': profile['app_access_active'],
            },
        }), 200
    except Exception as e:
        logger.exception("Error fetching user profile")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'Could not retrieve profile.',
        }), 500

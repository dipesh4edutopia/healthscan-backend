"""
Reusable Authentication & Authorization Middleware
Provides decorators to protect Flask endpoints using backend-issued JWTs.
"""

from functools import wraps
from typing import Sequence
from flask import request, jsonify, g

from app.services.token_service import (
    decode_access_token,
    TokenExpiredError,
    InvalidAccessTokenError,
)


def require_auth(f):
    """
    Decorator to protect routes requiring an authenticated user.
    Extracts Bearer JWT from Authorization header, validates signature & expiry,
    and attaches identity context to Flask's request-scoped `g` object:
      - g.current_user_id (UUID string)
      - g.current_email (str)
      - g.current_app_id (UUID string)
      - g.current_app_key (str)
      - g.current_role (str e.g. 'user', 'admin')
      - g.token_payload (dict)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Missing Authorization header. Expected Bearer token.',
            }), 401

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid Authorization header format. Expected "Bearer <token>".',
            }), 401

        token_str = parts[1]

        try:
            payload = decode_access_token(token_str)
        except TokenExpiredError as tee:
            return jsonify({
                'error': 'TokenExpired',
                'message': str(tee),
            }), 401
        except InvalidAccessTokenError as ite:
            return jsonify({
                'error': 'Unauthorized',
                'message': str(ite),
            }), 401
        except Exception as e:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Authentication verification failed.',
            }), 401

        # Populate Flask request context
        g.current_user_id = payload.get('sub')
        g.current_email = payload.get('email')
        g.current_app_id = payload.get('app_id')
        g.current_app_key = payload.get('app_key')
        g.current_role = payload.get('role', 'user')
        g.token_payload = payload

        return f(*args, **kwargs)

    return decorated_function


def require_role(*allowed_roles: str):
    """
    Decorator to enforce role-based access control (RBAC) per app.
    Must be placed AFTER @require_auth.

    Example:
      @app.route('/api/admin/metrics')
      @require_auth
      @require_role('admin')
      def admin_metrics():
          ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_role = getattr(g, 'current_role', None)
            if not current_role:
                return jsonify({
                    'error': 'Unauthorized',
                    'message': 'User role context not established. Ensure @require_auth is applied.',
                }), 401

            if current_role not in allowed_roles:
                return jsonify({
                    'error': 'Forbidden',
                    'message': f"Access denied. Requires one of roles: {list(allowed_roles)}. Your role is '{current_role}'.",
                }), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_app(*allowed_app_keys: str):
    """
    Decorator to restrict an endpoint to specific registered application(s).
    Must be placed AFTER @require_auth.

    Example:
      @app.route('/api/healthscan/results')
      @require_auth
      @require_app('main_app', 'healthscan_app')
      def healthscan_results():
          ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_app_key = getattr(g, 'current_app_key', None)
            if not current_app_key:
                return jsonify({
                    'error': 'Unauthorized',
                    'message': 'Application context not established.',
                }), 401

            if current_app_key not in allowed_app_keys:
                return jsonify({
                    'error': 'Forbidden',
                    'message': f"This endpoint is not available for application '{current_app_key}'.",
                }), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator

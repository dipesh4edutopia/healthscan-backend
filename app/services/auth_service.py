"""
Core Authentication & Multi-App Authorization Service
Orchestrates Google verification, idempotent user creation, app resolution,
per-app authorization, and backend session lifecycles.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple

from app.config import Config
from app.database import get_db_cursor
from app.services.google_auth import verify_google_id_token
from app.services.token_service import (
    generate_access_token,
    generate_raw_refresh_token,
    hash_refresh_token,
)

logger = logging.getLogger(__name__)


class AuthServiceError(Exception):
    """Base exception for authentication service errors."""
    pass


class AppNotFoundError(AuthServiceError):
    """The requested application is not registered in public.apps."""
    pass


class AppInactiveError(AuthServiceError):
    """The application is disabled in public.apps."""
    pass


class UserDeactivatedError(AuthServiceError):
    """The user account is marked as is_active = False."""
    pass


class AppAccessDeniedError(AuthServiceError):
    """The user does not have permission or access is deactivated for this app."""
    pass


class InvalidSessionError(AuthServiceError):
    """Refresh token session not found or invalid."""
    pass


class SessionRevokedError(AuthServiceError):
    """Refresh token session was already revoked (possible replay attack)."""
    pass


class SessionExpiredError(AuthServiceError):
    """Refresh token session has expired."""
    pass


class AuthService:
    """Authentication and multi-app authorization manager."""

    @staticmethod
    def resolve_app(app_key: str, cursor=None) -> Dict[str, Any]:
        """
        Resolves an application by its unique app_key from public.apps.
        Enforces that the app exists and is_active = True.
        """
        if not app_key or not isinstance(app_key, str):
            raise AppNotFoundError("An 'app_key' is required to identify the client application.")

        normalized_key = app_key.strip()

        def _query(cur):
            cur.execute(
                """
                SELECT id, app_key, display_name, is_active, created_at
                FROM public.apps
                WHERE app_key = %s
                LIMIT 1;
                """,
                (normalized_key,),
            )
            return cur.fetchone()

        if cursor:
            row = _query(cursor)
        else:
            with get_db_cursor(commit=False) as cur:
                row = _query(cur)

        if not row:
            raise AppNotFoundError(f"Application with key '{normalized_key}' is not registered.")

        if not row['is_active']:
            raise AppInactiveError(f"Application '{normalized_key}' is currently disabled.")

        return dict(row)

    @staticmethod
    def find_or_create_user(verified_google: Dict[str, Any], cursor) -> Dict[str, Any]:
        """
        Idempotently creates or updates a global user account in public.users.
        - First tries matching by unique verified google_sub.
        - Second tries matching by verified LOWER(email) and links google_sub.
        - Otherwise inserts a new user record.
        - Updates full_name and avatar_url if provided.
        - Verifies is_active is True.
        """
        google_sub = verified_google['google_sub']
        email = verified_google['email'].strip().lower()
        full_name = verified_google.get('full_name')
        avatar_url = verified_google.get('avatar_url')
        email_verified = verified_google.get('email_verified', True)

        # 1. Query by unique Google subject identifier
        cursor.execute(
            """
            SELECT id, google_sub, email, email_verified, full_name, avatar_url, is_active, created_at, updated_at
            FROM public.users
            WHERE google_sub = %s
            LIMIT 1;
            """,
            (google_sub,),
        )
        user = cursor.fetchone()

        if user:
            if not user['is_active']:
                raise UserDeactivatedError("User account has been deactivated. Please contact support.")

            # Update profile info and email verification status
            cursor.execute(
                """
                UPDATE public.users
                SET email = %s,
                    email_verified = %s,
                    full_name = COALESCE(%s, full_name),
                    avatar_url = COALESCE(%s, avatar_url),
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id, google_sub, email, email_verified, full_name, avatar_url, is_active, created_at, updated_at;
                """,
                (email, email_verified, full_name, avatar_url, user['id']),
            )
            updated_user = cursor.fetchone()
            return dict(updated_user)

        # 2. Query by LOWER(email) in case user existed prior to linking google_sub
        cursor.execute(
            """
            SELECT id, google_sub, email, email_verified, full_name, avatar_url, is_active, created_at, updated_at
            FROM public.users
            WHERE LOWER(email) = LOWER(%s)
            LIMIT 1;
            """,
            (email,),
        )
        user_by_email = cursor.fetchone()

        if user_by_email:
            if not user_by_email['is_active']:
                raise UserDeactivatedError("User account has been deactivated. Please contact support.")

            # Link Google sub and update profile
            cursor.execute(
                """
                UPDATE public.users
                SET google_sub = %s,
                    email_verified = %s,
                    full_name = COALESCE(%s, full_name),
                    avatar_url = COALESCE(%s, avatar_url),
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id, google_sub, email, email_verified, full_name, avatar_url, is_active, created_at, updated_at;
                """,
                (google_sub, email_verified, full_name, avatar_url, user_by_email['id']),
            )
            linked_user = cursor.fetchone()
            return dict(linked_user)

        # 3. Create new user record
        cursor.execute(
            """
            INSERT INTO public.users (
                google_sub,
                email,
                email_verified,
                full_name,
                avatar_url,
                is_active
            ) VALUES (
                %s, %s, %s, %s, %s, TRUE
            )
            RETURNING id, google_sub, email, email_verified, full_name, avatar_url, is_active, created_at, updated_at;
            """,
            (google_sub, email, email_verified, full_name, avatar_url),
        )
        new_user = cursor.fetchone()
        return dict(new_user)

    @staticmethod
    def resolve_user_app_access(
        user_id: str,
        app_id: str,
        cursor,
        auto_provision: bool = True,
    ) -> Dict[str, Any]:
        """
        Enforces and checks authorization in public.user_app_access.
        - If access record exists, ensures is_active = True and returns role.
        - If no record exists and auto_provision=True, creates a record with role='user'.
        - If auto_provision=False, raises AppAccessDeniedError.
        """
        cursor.execute(
            """
            SELECT user_id, app_id, role, is_active, created_at
            FROM public.user_app_access
            WHERE user_id = %s AND app_id = %s
            LIMIT 1;
            """,
            (str(user_id), str(app_id)),
        )
        access = cursor.fetchone()

        if access:
            if not access['is_active']:
                raise AppAccessDeniedError(
                    "Your access to this application has been disabled. Please contact an administrator."
                )
            return dict(access)

        # Record does not exist: auto-provision if enabled
        if auto_provision:
            cursor.execute(
                """
                INSERT INTO public.user_app_access (
                    user_id,
                    app_id,
                    role,
                    is_active
                ) VALUES (
                    %s, %s, 'user', TRUE
                )
                ON CONFLICT (user_id, app_id) DO UPDATE
                SET is_active = public.user_app_access.is_active
                RETURNING user_id, app_id, role, is_active, created_at;
                """,
                (str(user_id), str(app_id)),
            )
            new_access = cursor.fetchone()
            return dict(new_access)

        raise AppAccessDeniedError("You do not have access privileges for this application.")

    @staticmethod
    def create_refresh_session(
        user_id: str,
        app_id: str,
        cursor,
        user_agent: Optional[str] = None,
        device_label: Optional[str] = None,
    ) -> Tuple[str, datetime]:
        """
        Creates a new session in public.refresh_tokens.
        Generates a high-entropy raw token, calculates its SHA-256 hash,
        and saves ONLY the hash in the database.
        Returns: (raw_refresh_token, expires_at)
        """
        raw_token = generate_raw_refresh_token()
        token_hash = hash_refresh_token(raw_token)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=Config.REFRESH_TOKEN_EXPIRES_DAYS)

        cursor.execute(
            """
            INSERT INTO public.refresh_tokens (
                user_id,
                app_id,
                token_hash,
                expires_at,
                user_agent,
                device_label
            ) VALUES (
                %s, %s, %s, %s, %s, %s
            )
            RETURNING id, expires_at;
            """,
            (
                str(user_id),
                str(app_id),
                token_hash,
                expires_at,
                user_agent[:255] if user_agent else None,
                device_label[:120] if device_label else None,
            ),
        )
        return raw_token, expires_at

    @classmethod
    def authenticate_with_google(
        cls,
        id_token_str: str,
        app_key: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Complete Google Sign-In Flow:
          1. Verify Google ID token (iss, aud, exp, signature, sub, email).
          2. Resolve registered application from public.apps.
          3. Find or create user idempotently in public.users.
          4. Check and provision user authorization in public.user_app_access.
          5. Issue backend session (hashed refresh token) and signed JWT access token.
        """
        # Step 1: Verify Google ID token
        verified_google = verify_google_id_token(id_token_str)

        effective_app_key = app_key or Config.DEFAULT_APP_KEY

        with get_db_cursor(commit=True) as cursor:
            # Step 2: Resolve app
            app = cls.resolve_app(effective_app_key, cursor=cursor)

            # Step 3: Find or create user
            user = cls.find_or_create_user(verified_google, cursor=cursor)

            # Step 4: Resolve per-app access & role
            access = cls.resolve_user_app_access(
                user_id=user['id'],
                app_id=app['id'],
                cursor=cursor,
                auto_provision=Config.AUTO_PROVISION_USER_APP_ACCESS,
            )
            user_role = access['role']

            # Step 5: Create backend-managed refresh session
            raw_refresh_token, refresh_expires_at = cls.create_refresh_session(
                user_id=user['id'],
                app_id=app['id'],
                cursor=cursor,
                user_agent=user_agent,
                device_label=device_label,
            )

        # Step 6: Generate short-lived signed JWT access token
        access_token, expires_in = generate_access_token(
            user_id=user['id'],
            email=user['email'],
            app_id=app['id'],
            app_key=app['app_key'],
            role=user_role,
        )

        return {
            'access_token': access_token,
            'refresh_token': raw_refresh_token,
            'token_type': 'Bearer',
            'expires_in': expires_in,
            'user': {
                'id': str(user['id']),
                'email': user['email'],
                'full_name': user['full_name'],
                'avatar_url': user['avatar_url'],
            },
            'app': {
                'id': str(app['id']),
                'app_key': app['app_key'],
                'display_name': app['display_name'],
                'role': user_role,
            },
        }

    @classmethod
    def refresh_session(
        cls,
        raw_refresh_token: str,
        user_agent: Optional[str] = None,
        device_label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Exchanges a valid raw refresh token for a new access token and
        performs REFRESH TOKEN ROTATION for anti-replay security.
        """
        if not raw_refresh_token or not isinstance(raw_refresh_token, str):
            raise InvalidSessionError("A valid refresh_token is required.")

        token_hash = hash_refresh_token(raw_refresh_token)
        now = datetime.now(timezone.utc)

        with get_db_cursor(commit=True) as cursor:
            # Query session join with users, apps, and user_app_access
            cursor.execute(
                """
                SELECT
                    rt.id AS session_id,
                    rt.user_id,
                    rt.app_id,
                    rt.expires_at,
                    rt.revoked_at,
                    u.email,
                    u.full_name,
                    u.avatar_url,
                    u.is_active AS user_active,
                    a.app_key,
                    a.display_name AS app_display_name,
                    a.is_active AS app_active,
                    uaa.role AS user_role,
                    uaa.is_active AS access_active
                FROM public.refresh_tokens rt
                JOIN public.users u ON rt.user_id = u.id
                JOIN public.apps a ON rt.app_id = a.id
                LEFT JOIN public.user_app_access uaa ON (rt.user_id = uaa.user_id AND rt.app_id = uaa.app_id)
                WHERE rt.token_hash = %s
                LIMIT 1;
                """,
                (token_hash,),
            )
            session = cursor.fetchone()

            if not session:
                raise InvalidSessionError("Invalid refresh token session.")

            # Replay protection: if already revoked, alert and block
            if session['revoked_at'] is not None:
                raise SessionRevokedError(
                    "Refresh token has been revoked or already used. Please re-authenticate."
                )

            # Check expiration
            expires_at = session['expires_at']
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if expires_at < now:
                raise SessionExpiredError("Session has expired. Please log in again.")

            if not session['user_active']:
                raise UserDeactivatedError("User account is inactive.")

            if not session['app_active']:
                raise AppInactiveError("Application is currently disabled.")

            if not session.get('access_active', False):
                raise AppAccessDeniedError("Access to this application has been disabled.")

            # ROTATION: Revoke current refresh token
            cursor.execute(
                """
                UPDATE public.refresh_tokens
                SET revoked_at = NOW(),
                    last_used_at = NOW()
                WHERE id = %s;
                """,
                (session['session_id'],),
            )

            # Issue brand new rotated refresh token
            new_raw_refresh, new_expires_at = cls.create_refresh_session(
                user_id=session['user_id'],
                app_id=session['app_id'],
                cursor=cursor,
                user_agent=user_agent,
                device_label=device_label,
            )

        # Issue new JWT access token
        access_token, expires_in = generate_access_token(
            user_id=session['user_id'],
            email=session['email'],
            app_id=session['app_id'],
            app_key=session['app_key'],
            role=session['user_role'] or 'user',
        )

        return {
            'access_token': access_token,
            'refresh_token': new_raw_refresh,
            'token_type': 'Bearer',
            'expires_in': expires_in,
            'user': {
                'id': str(session['user_id']),
                'email': session['email'],
                'full_name': session['full_name'],
                'avatar_url': session['avatar_url'],
            },
            'app': {
                'id': str(session['app_id']),
                'app_key': session['app_key'],
                'display_name': session['app_display_name'],
                'role': session['user_role'] or 'user',
            },
        }

    @staticmethod
    def logout_session(raw_refresh_token: str) -> bool:
        """
        Revokes a single active refresh token session.
        """
        if not raw_refresh_token or not isinstance(raw_refresh_token, str):
            return False

        token_hash = hash_refresh_token(raw_refresh_token)

        with get_db_cursor(commit=True) as cursor:
            cursor.execute(
                """
                UPDATE public.refresh_tokens
                SET revoked_at = NOW(),
                    last_used_at = NOW()
                WHERE token_hash = %s AND revoked_at IS NULL
                RETURNING id;
                """,
                (token_hash,),
            )
            row = cursor.fetchone()
            return row is not None

    @staticmethod
    def logout_all_sessions(user_id: str, app_id: Optional[str] = None) -> int:
        """
        Revokes all active sessions for a user, optionally scoped to a single app.
        """
        with get_db_cursor(commit=True) as cursor:
            if app_id:
                cursor.execute(
                    """
                    UPDATE public.refresh_tokens
                    SET revoked_at = NOW(),
                        last_used_at = NOW()
                    WHERE user_id = %s AND app_id = %s AND revoked_at IS NULL
                    RETURNING id;
                    """,
                    (str(user_id), str(app_id)),
                )
            else:
                cursor.execute(
                    """
                    UPDATE public.refresh_tokens
                    SET revoked_at = NOW(),
                        last_used_at = NOW()
                    WHERE user_id = %s AND revoked_at IS NULL
                    RETURNING id;
                    """,
                    (str(user_id),),
                )
            rows = cursor.fetchall()
            return len(rows)

    @staticmethod
    def get_user_profile(user_id: str, app_id: str) -> Dict[str, Any]:
        """
        Retrieves user profile and current app authorization data.
        """
        with get_db_cursor(commit=False) as cursor:
            cursor.execute(
                """
                SELECT
                    u.id,
                    u.email,
                    u.email_verified,
                    u.full_name,
                    u.avatar_url,
                    u.is_active,
                    u.created_at,
                    uaa.role,
                    uaa.is_active AS app_access_active,
                    a.app_key,
                    a.display_name AS app_display_name
                FROM public.users u
                JOIN public.apps a ON a.id = %s
                LEFT JOIN public.user_app_access uaa ON (u.id = uaa.user_id AND a.id = uaa.app_id)
                WHERE u.id = %s
                LIMIT 1;
                """,
                (str(app_id), str(user_id)),
            )
            row = cursor.fetchone()
            if not row:
                raise AuthServiceError("User profile not found.")
            return dict(row)

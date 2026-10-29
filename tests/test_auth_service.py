"""
Unit Tests for AuthService & Multi-App Authorization Logic
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

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
from app.services.token_service import hash_refresh_token


def test_resolve_app_success(mock_db):
    app = AuthService.resolve_app('main_app')
    assert app['app_key'] == 'main_app'
    assert app['is_active'] is True

    app2 = AuthService.resolve_app('healthscan_app')
    assert app2['app_key'] == 'healthscan_app'
    assert app2['display_name'] == 'HealthScan App'


def test_resolve_app_not_found(mock_db):
    with pytest.raises(AppNotFoundError) as exc_info:
        AuthService.resolve_app('non_existent_app')
    assert "not registered" in str(exc_info.value).lower()


def test_resolve_app_inactive(mock_db):
    with pytest.raises(AppInactiveError) as exc_info:
        AuthService.resolve_app('inactive_app')
    assert "disabled" in str(exc_info.value).lower()


def test_find_or_create_user_idempotent(mock_db):
    verified_info = {
        'google_sub': 'sub-1001',
        'email': 'patient@example.com',
        'email_verified': True,
        'full_name': 'Jane Doe',
        'avatar_url': 'https://photo.example.com/jane.jpg',
    }

    # 1. First creation
    with mock_db.get_cursor() as cursor:
        user1 = AuthService.find_or_create_user(verified_info, cursor)

    assert user1['email'] == 'patient@example.com'
    assert user1['google_sub'] == 'sub-1001'
    assert user1['full_name'] == 'Jane Doe'
    assert user1['is_active'] is True

    # 2. Second invocation with updated name should update existing record
    verified_info['full_name'] = 'Jane Doe-Smith'
    with mock_db.get_cursor() as cursor:
        user2 = AuthService.find_or_create_user(verified_info, cursor)

    assert user2['id'] == user1['id']
    assert user2['full_name'] == 'Jane Doe-Smith'
    # Only 1 user should exist in DB
    assert len(mock_db.users) == 1


def test_find_or_create_user_links_by_email(mock_db):
    # Pre-existing user with email but no google_sub
    existing_id = "user-legacy-uuid"
    mock_db.users[existing_id] = {
        'id': existing_id,
        'google_sub': 'old-dummy-sub',
        'email': 'existing@healthscan.io',
        'email_verified': True,
        'full_name': 'Existing User',
        'avatar_url': None,
        'is_active': True,
        'created_at': datetime.now(timezone.utc),
        'updated_at': datetime.now(timezone.utc),
    }

    google_data = {
        'google_sub': 'new-google-sub-777',
        'email': 'EXISTING@HEALTHSCAN.IO',  # case-insensitive check
        'email_verified': True,
        'full_name': 'Existing User Linked',
        'avatar_url': 'https://avatar.url',
    }

    with mock_db.get_cursor() as cursor:
        linked = AuthService.find_or_create_user(google_data, cursor)

    assert linked['id'] == existing_id
    assert linked['google_sub'] == 'new-google-sub-777'
    assert linked['full_name'] == 'Existing User Linked'


def test_user_deactivated_fails(mock_db):
    banned_id = "banned-uuid"
    mock_db.users[banned_id] = {
        'id': banned_id,
        'google_sub': 'banned-sub',
        'email': 'banned@example.com',
        'email_verified': True,
        'full_name': 'Banned User',
        'avatar_url': None,
        'is_active': False,  # DEACTIVATED
        'created_at': datetime.now(timezone.utc),
        'updated_at': datetime.now(timezone.utc),
    }

    google_data = {
        'google_sub': 'banned-sub',
        'email': 'banned@example.com',
        'email_verified': True,
        'full_name': 'Banned User',
        'avatar_url': None,
    }

    with pytest.raises(UserDeactivatedError):
        with mock_db.get_cursor() as cursor:
            AuthService.find_or_create_user(google_data, cursor)


def test_user_app_access_auto_provision(mock_db):
    user_id = "user-abc"
    app_id = list(mock_db.apps.keys())[0]

    with mock_db.get_cursor() as cursor:
        access = AuthService.resolve_user_app_access(
            user_id=user_id,
            app_id=app_id,
            cursor=cursor,
            auto_provision=True,
        )

    assert access['role'] == 'user'
    assert access['is_active'] is True
    assert (user_id, app_id) in mock_db.user_app_access


def test_user_app_access_revoked_fails(mock_db):
    user_id = "user-revoked"
    app_id = list(mock_db.apps.keys())[0]

    # Explicitly revoked for this app
    mock_db.user_app_access[(user_id, app_id)] = {
        'user_id': user_id,
        'app_id': app_id,
        'role': 'user',
        'is_active': False,
        'created_at': datetime.now(timezone.utc),
    }

    with pytest.raises(AppAccessDeniedError) as exc_info:
        with mock_db.get_cursor() as cursor:
            AuthService.resolve_user_app_access(
                user_id=user_id,
                app_id=app_id,
                cursor=cursor,
            )

    assert "disabled" in str(exc_info.value).lower()


def test_full_google_auth_flow_and_session_refresh_rotation(mock_db):
    mock_google_info = {
        'google_sub': 'google-flow-sub-1',
        'email': 'flow.user@example.com',
        'email_verified': True,
        'full_name': 'Flow User',
        'avatar_url': 'https://photo.jpg',
        'raw_claims': {},
    }

    with patch('app.services.auth_service.verify_google_id_token', return_value=mock_google_info):
        # 1. Sign in
        auth_res = AuthService.authenticate_with_google(
            id_token_str='dummy-google-jwt',
            app_key='healthscan_app',
            user_agent='HealthScan-Expo/1.0',
            device_label='iPhone 15 Pro',
        )

        assert 'access_token' in auth_res
        assert 'refresh_token' in auth_res
        raw_refresh_1 = auth_res['refresh_token']
        assert auth_res['user']['email'] == 'flow.user@example.com'
        assert auth_res['app']['app_key'] == 'healthscan_app'

        # Verify raw refresh token is NEVER in DB, only its SHA-256 hash is
        assert raw_refresh_1 not in mock_db.refresh_tokens
        hash_1 = hash_refresh_token(raw_refresh_1)
        assert hash_1 in mock_db.refresh_tokens

        # 2. Refresh session (Token Rotation)
        refreshed = AuthService.refresh_session(
            raw_refresh_token=raw_refresh_1,
            user_agent='HealthScan-Expo/1.0',
        )

        assert 'access_token' in refreshed
        assert 'refresh_token' in refreshed
        raw_refresh_2 = refreshed['refresh_token']
        # Rotated refresh token must be different from previous
        assert raw_refresh_2 != raw_refresh_1

        # Old token must now be marked revoked
        old_session = mock_db.refresh_tokens[hash_1]
        assert old_session['revoked_at'] is not None

        # 3. Replay attack test: Trying to use old refresh_1 must fail!
        with pytest.raises(SessionRevokedError):
            AuthService.refresh_session(raw_refresh_token=raw_refresh_1)

        # 4. Logout with new token
        logged_out = AuthService.logout_session(raw_refresh_2)
        assert logged_out is True

        # Second logout should return False (already revoked)
        logged_out_again = AuthService.logout_session(raw_refresh_2)
        assert logged_out_again is False

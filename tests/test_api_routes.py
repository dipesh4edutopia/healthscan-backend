"""
Integration Tests for Flask API Endpoints & Middleware
"""

import json
from unittest.mock import patch
from app.services.token_service import generate_access_token


def test_health_check_endpoint(client):
    res = client.get('/api/v1/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'healthy'
    assert 'Shared Multi-App' in data['service']


def test_google_sign_in_missing_id_token(client):
    res = client.post('/api/v1/auth/google', json={})
    assert res.status_code == 400
    data = res.get_json()
    assert data['error'] == 'BadRequest'


def test_google_sign_in_success(client, mock_db):
    mock_claims = {
        'google_sub': 'api-test-sub-123',
        'email': 'api.user@healthscan.io',
        'email_verified': True,
        'full_name': 'API Test User',
        'avatar_url': 'https://photo.url',
        'raw_claims': {},
    }

    with patch('app.services.auth_service.verify_google_id_token', return_value=mock_claims):
        res = client.post(
            '/api/v1/auth/google',
            headers={'X-App-Key': 'healthscan_app'},
            json={
                'id_token': 'mock.google.id.token',
                'device_label': 'Pixel 8',
            },
        )

        assert res.status_code == 200
        data = res.get_json()
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['token_type'] == 'Bearer'
        assert data['user']['email'] == 'api.user@healthscan.io'
        assert data['app']['app_key'] == 'healthscan_app'
        assert data['app']['role'] == 'user'


def test_protected_route_without_token(client):
    res = client.get('/api/v1/auth/me')
    assert res.status_code == 401
    data = res.get_json()
    assert data['error'] == 'Unauthorized'


def test_protected_route_with_valid_token(client, mock_db):
    app_id = list(mock_db.apps.keys())[0]
    token, _ = generate_access_token(
        user_id='test-user-id',
        email='user@test.com',
        app_id=app_id,
        app_key='main_app',
        role='user',
    )

    res = client.get(
        '/api/v1/test/protected',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data['authenticated_user']['user_id'] == 'test-user-id'
    assert data['authenticated_user']['role'] == 'user'


def test_admin_route_forbidden_for_standard_user(client, mock_db):
    app_id = list(mock_db.apps.keys())[0]
    user_token, _ = generate_access_token(
        user_id='regular-user-id',
        email='user@test.com',
        app_id=app_id,
        app_key='main_app',
        role='user',  # Not admin
    )

    res = client.get(
        '/api/v1/test/admin',
        headers={'Authorization': f'Bearer {user_token}'},
    )
    assert res.status_code == 403
    data = res.get_json()
    assert data['error'] == 'Forbidden'
    assert 'Insufficient' in data['message'] or 'Access denied' in data['message']


def test_admin_route_allowed_for_admin_role(client, mock_db):
    app_id = list(mock_db.apps.keys())[0]
    admin_token, _ = generate_access_token(
        user_id='admin-user-id',
        email='admin@test.com',
        app_id=app_id,
        app_key='main_app',
        role='admin',  # Admin role
    )

    res = client.get(
        '/api/v1/test/admin',
        headers={'Authorization': f'Bearer {admin_token}'},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert 'Welcome' in data['message']
    assert data['role'] == 'admin'


def test_session_refresh_and_logout_api(client, mock_db):
    mock_claims = {
        'google_sub': 'refresh-sub-999',
        'email': 'refresh@test.com',
        'email_verified': True,
        'full_name': 'Refresh User',
        'avatar_url': None,
        'raw_claims': {},
    }

    # 1. Login to get tokens
    with patch('app.services.auth_service.verify_google_id_token', return_value=mock_claims):
        login_res = client.post(
            '/api/v1/auth/google',
            json={'id_token': 'dummy', 'app_key': 'healthscan_app'},
        )
        assert login_res.status_code == 200
        raw_refresh = login_res.get_json()['refresh_token']

    # 2. Call /refresh
    refresh_res = client.post(
        '/api/v1/auth/refresh',
        json={'refresh_token': raw_refresh},
    )
    assert refresh_res.status_code == 200
    refreshed_data = refresh_res.get_json()
    new_raw_refresh = refreshed_data['refresh_token']
    assert new_raw_refresh != raw_refresh

    # 3. Call /logout
    logout_res = client.post(
        '/api/v1/auth/logout',
        json={'refresh_token': new_raw_refresh},
    )
    assert logout_res.status_code == 200
    assert logout_res.get_json()['success'] is True


def test_get_current_user_profile_endpoint(client, mock_db):
    mock_claims = {
        'google_sub': 'me-sub-123',
        'email': 'me@healthscan.io',
        'email_verified': True,
        'full_name': 'Me Profile',
        'avatar_url': 'https://me.png',
        'raw_claims': {},
    }

    with patch('app.services.auth_service.verify_google_id_token', return_value=mock_claims):
        login_res = client.post(
            '/api/v1/auth/google',
            json={'id_token': 'dummy', 'app_key': 'main_app'},
        )
        access_token = login_res.get_json()['access_token']

    # Call /api/v1/auth/me
    me_res = client.get(
        '/api/v1/auth/me',
        headers={'Authorization': f'Bearer {access_token}'},
    )
    assert me_res.status_code == 200
    me_data = me_res.get_json()
    assert me_data['user']['email'] == 'me@healthscan.io'
    assert me_data['app']['role'] == 'user'

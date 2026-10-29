"""
Unit Tests for Google ID Token Verification Service
"""

import pytest
from unittest.mock import patch, MagicMock

from app.services.google_auth import (
    verify_google_id_token,
    InvalidTokenError,
    ExpiredTokenError,
    InvalidAudienceError,
    UnverifiedEmailError,
)


def test_verify_google_id_token_success():
    mock_claims = {
        'iss': 'https://accounts.google.com',
        'aud': 'test-web-client-id.apps.googleusercontent.com',
        'sub': 'google-uid-987654321',
        'email': 'Alex.Johnson@healthscan.io',
        'email_verified': True,
        'name': 'Alex Johnson',
        'picture': 'https://lh3.googleusercontent.com/a/photo.jpg',
        'exp': 9999999999,
    }

    with patch('google.oauth2.id_token.verify_oauth2_token', return_value=mock_claims):
        res = verify_google_id_token(
            'fake.valid.jwt',
            allowed_client_ids=['test-web-client-id.apps.googleusercontent.com'],
        )

        assert res['google_sub'] == 'google-uid-987654321'
        assert res['email'] == 'alex.johnson@healthscan.io'  # lowercased
        assert res['email_verified'] is True
        assert res['full_name'] == 'Alex Johnson'
        assert res['avatar_url'] == 'https://lh3.googleusercontent.com/a/photo.jpg'


def test_verify_google_id_token_expired():
    with patch(
        'google.oauth2.id_token.verify_oauth2_token',
        side_effect=ValueError('Token expired'),
    ):
        with pytest.raises(ExpiredTokenError):
            verify_google_id_token('fake.expired.jwt')


def test_verify_google_id_token_invalid_issuer():
    mock_claims = {
        'iss': 'https://evil-issuer.com',
        'aud': 'test-web-client-id.apps.googleusercontent.com',
        'sub': 'google-uid-123',
        'email': 'alex@example.com',
        'email_verified': True,
    }

    with patch('google.oauth2.id_token.verify_oauth2_token', return_value=mock_claims):
        with pytest.raises(InvalidTokenError) as exc_info:
            verify_google_id_token(
                'fake.jwt',
                allowed_client_ids=['test-web-client-id.apps.googleusercontent.com'],
            )
        assert "issuer" in str(exc_info.value).lower()


def test_verify_google_id_token_invalid_audience():
    mock_claims = {
        'iss': 'https://accounts.google.com',
        'aud': 'malicious-attacker-client-id.apps.googleusercontent.com',
        'sub': 'google-uid-123',
        'email': 'alex@example.com',
        'email_verified': True,
    }

    with patch('google.oauth2.id_token.verify_oauth2_token', return_value=mock_claims):
        with pytest.raises(InvalidAudienceError) as exc_info:
            verify_google_id_token(
                'fake.jwt',
                allowed_client_ids=['test-web-client-id.apps.googleusercontent.com'],
            )
        assert "audience" in str(exc_info.value).lower()


def test_verify_google_id_token_unverified_email():
    mock_claims = {
        'iss': 'https://accounts.google.com',
        'aud': 'test-web-client-id.apps.googleusercontent.com',
        'sub': 'google-uid-123',
        'email': 'unverified@example.com',
        'email_verified': False,
    }

    with patch('google.oauth2.id_token.verify_oauth2_token', return_value=mock_claims):
        with pytest.raises(UnverifiedEmailError):
            verify_google_id_token(
                'fake.jwt',
                allowed_client_ids=['test-web-client-id.apps.googleusercontent.com'],
            )


def test_verify_google_id_token_missing_sub():
    mock_claims = {
        'iss': 'https://accounts.google.com',
        'aud': 'test-web-client-id.apps.googleusercontent.com',
        'sub': '',
        'email': 'alex@example.com',
        'email_verified': True,
    }

    with patch('google.oauth2.id_token.verify_oauth2_token', return_value=mock_claims):
        with pytest.raises(InvalidTokenError) as exc_info:
            verify_google_id_token(
                'fake.jwt',
                allowed_client_ids=['test-web-client-id.apps.googleusercontent.com'],
            )
        assert "sub" in str(exc_info.value).lower()

"""
Unit Tests for Token & Session Cryptographic Service
"""

import time
from datetime import timedelta
import pytest

from app.services.token_service import (
    generate_access_token,
    decode_access_token,
    generate_raw_refresh_token,
    hash_refresh_token,
    TokenExpiredError,
    InvalidAccessTokenError,
)


def test_generate_and_decode_access_token():
    user_id = "11111111-2222-3333-4444-555555555555"
    email = "test@example.com"
    app_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    app_key = "healthscan_app"
    role = "admin"

    token, expires_in = generate_access_token(
        user_id=user_id,
        email=email,
        app_id=app_id,
        app_key=app_key,
        role=role,
    )

    assert isinstance(token, str)
    assert len(token) > 20
    assert expires_in == 900  # 15 minutes default

    payload = decode_access_token(token)
    assert payload['sub'] == user_id
    assert payload['email'] == email
    assert payload['app_id'] == app_id
    assert payload['app_key'] == app_key
    assert payload['role'] == role
    assert payload['type'] == 'access'


def test_access_token_expired():
    token, _ = generate_access_token(
        user_id="user-123",
        email="test@example.com",
        app_id="app-456",
        app_key="main_app",
        role="user",
        expires_delta=timedelta(seconds=-1),  # already expired
    )

    with pytest.raises(TokenExpiredError) as exc_info:
        decode_access_token(token)

    assert "expired" in str(exc_info.value).lower()


def test_access_token_tampered():
    token, _ = generate_access_token(
        user_id="user-123",
        email="test@example.com",
        app_id="app-456",
        app_key="main_app",
        role="user",
    )

    # Tamper with signature by modifying the last characters
    tampered = token[:-5] + ("abcde" if token[-5:] != "abcde" else "12345")

    with pytest.raises(InvalidAccessTokenError):
        decode_access_token(tampered)


def test_refresh_token_generation_and_hashing():
    raw1 = generate_raw_refresh_token()
    raw2 = generate_raw_refresh_token()

    assert isinstance(raw1, str)
    assert len(raw1) >= 48
    # High entropy check: successive tokens must differ
    assert raw1 != raw2

    # Hashing is deterministic
    hash1 = hash_refresh_token(raw1)
    hash1_repeat = hash_refresh_token(raw1)
    assert hash1 == hash1_repeat
    assert len(hash1) == 64  # SHA-256 produces 64 hex characters

    # Raw token and hash are never identical
    assert raw1 != hash1

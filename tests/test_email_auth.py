"""
Tests for Multi-App Email & Password Auth and Conflict-Free Google Account Linking.
"""

from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from app.services.store_verifier import LIFETIME_EXPIRY


def _mock_google(monkeypatch, email="user@example.com", sub="google-sub-1", name="Google User"):
    monkeypatch.setattr(
        "app.services.auth_service.verify_google_id_token",
        lambda token_str: {
            "google_sub": sub,
            "email": email,
            "email_verified": True,
            "full_name": name,
            "avatar_url": "https://example.com/pic.png",
        },
    )


class TestEmailRegisterAndLogin:
    def test_register_and_login_and_me(self, client):
        reg = client.post(
            "/api/v1/auth/register",
            json={
                "email": "Alice@Example.com",
                "password": "Password123",
                "full_name": "Alice Doe",
                "app_key": "main_app",
            },
        )
        assert reg.status_code == 201
        body = reg.get_json()
        assert body["access_token"]
        assert body["refresh_token"]
        assert body["user"]["email"] == "alice@example.com"
        assert body["user"]["has_password"] is True
        assert body["user"]["has_google"] is False

        # Login with same credentials works across another app too
        login_other = client.post(
            "/api/v1/auth/login",
            json={
                "email": "alice@example.com",
                "password": "Password123",
                "app_key": "healthscan_app",
            },
        )
        assert login_other.status_code == 200
        other_body = login_other.get_json()
        assert other_body["user"]["id"] == body["user"]["id"]
        assert other_body["app"]["app_key"] == "healthscan_app"

        # /me exposes has_google & has_password
        me = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {body['access_token']}"},
        )
        assert me.status_code == 200
        assert me.get_json()["user"]["has_password"] is True
        assert me.get_json()["user"]["has_google"] is False

    def test_weak_password_and_duplicate_email_rejected(self, client):
        weak = client.post(
            "/api/v1/auth/register",
            json={"email": "bob@example.com", "password": "short"},
        )
        assert weak.status_code == 400
        assert weak.get_json()["error"] == "WeakPassword"

        ok = client.post(
            "/api/v1/auth/register",
            json={"email": "bob@example.com", "password": "Password1"},
        )
        assert ok.status_code == 201

        dup = client.post(
            "/api/v1/auth/register",
            json={"email": "BOB@example.com", "password": "Password2"},
        )
        assert dup.status_code == 409
        assert dup.get_json()["error"] == "EmailAlreadyRegistered"

    def test_brute_force_lockout_after_5_failures(self, client):
        client.post(
            "/api/v1/auth/register",
            json={"email": "lock@example.com", "password": "Password1"},
        )
        for _ in range(4):
            r = client.post(
                "/api/v1/auth/login",
                json={"email": "lock@example.com", "password": "Wrong123"},
            )
            assert r.status_code == 401
        r5 = client.post(
            "/api/v1/auth/login",
            json={"email": "lock@example.com", "password": "Wrong123"},
        )
        assert r5.status_code == 429
        assert r5.get_json()["error"] == "AccountLocked"

        # Even correct password is blocked while locked
        r6 = client.post(
            "/api/v1/auth/login",
            json={"email": "lock@example.com", "password": "Password1"},
        )
        assert r6.status_code == 429


class TestGoogleAndPasswordInterop:
    def test_google_user_buys_pro_then_adds_password_and_keeps_pro(self, client, monkeypatch):
        _mock_google(monkeypatch, email="rahul@gmail.com", sub="sub-rahul", name="Rahul")
        g_login = client.post(
            "/api/v1/auth/google",
            json={"id_token": "tok", "app_key": "main_app"},
        ).get_json()
        assert g_login["user"]["has_google"] is True
        assert g_login["user"]["has_password"] is False

        # Buy Pro via Google account
        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mv:
            mv.return_value = {
                "provider_subscription_id": "tok-rahul",
                "provider_transaction_id": "GPA.RAHUL",
                "status": "active",
                "starts_at": datetime.now(timezone.utc),
                "expires_at": LIFETIME_EXPIRY,
                "auto_renew": False,
                "raw_data": {},
            }
            buy = client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {g_login['access_token']}"},
                json={"provider": "google_play", "product_id": "healthscan_pro_lifetime", "purchase_token": "tok-rahul"},
            )
            assert buy.status_code == 200

        # Trying password login before setting password gives friendly PasswordNotSet
        pw_before = client.post(
            "/api/v1/auth/login",
            json={"email": "rahul@gmail.com", "password": "Password1", "app_key": "main_app"},
        )
        assert pw_before.status_code == 400
        assert pw_before.get_json()["error"] == "PasswordNotSet"

        # Add a password while signed in with Google (no current_password required)
        add_pw = client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {g_login['access_token']}"},
            json={"new_password": "NewPassword1"},
        )
        assert add_pw.status_code == 200

        # Now login with email + password -> SAME user_id and Pro is already active!
        pw_login = client.post(
            "/api/v1/auth/login",
            json={"email": "rahul@gmail.com", "password": "NewPassword1", "app_key": "main_app"},
        )
        assert pw_login.status_code == 200
        pw_body = pw_login.get_json()
        assert pw_body["user"]["id"] == g_login["user"]["id"]
        assert pw_body["user"]["has_google"] is True
        assert pw_body["user"]["has_password"] is True

        status = client.get(
            "/api/v1/payments/status",
            headers={"Authorization": f"Bearer {pw_body['access_token']}"},
        ).get_json()
        assert status["is_pro"] is True

    def test_unverified_password_signup_cleared_when_real_owner_claims_via_google(self, client, monkeypatch):
        reg = client.post(
            "/api/v1/auth/register",
            json={"email": "victim@gmail.com", "password": "Attacker1", "app_key": "main_app"},
        )
        assert reg.status_code == 201
        attacker_refresh = reg.get_json()["refresh_token"]

        # Real owner signs in with Google
        _mock_google(monkeypatch, email="victim@gmail.com", sub="sub-victim", name="Real Owner")
        g_resp = client.post(
            "/api/v1/auth/google",
            json={"id_token": "tok", "app_key": "main_app"},
        )
        assert g_resp.status_code == 200
        assert g_resp.get_json()["user"]["has_password"] is False

        # Attacker's password no longer works and attacker's refresh token is revoked
        att_login = client.post(
            "/api/v1/auth/login",
            json={"email": "victim@gmail.com", "password": "Attacker1"},
        )
        assert att_login.status_code == 400
        assert att_login.get_json()["error"] == "PasswordNotSet"

        att_ref = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": attacker_refresh},
        )
        assert att_ref.status_code == 401

    def test_forgot_and_reset_password_otp_flow(self, client, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            "app.services.auth_service.send_password_reset_otp",
            lambda to_email, otp_code, app_name="Our App": captured.update(
                {"email": to_email, "otp": otp_code}
            ) or "console",
        )

        reg = client.post(
            "/api/v1/auth/register",
            json={"email": "reset@example.com", "password": "OldPassword1"},
        ).get_json()
        old_refresh = reg["refresh_token"]

        req = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "reset@example.com", "app_key": "main_app"},
        )
        assert req.status_code == 200
        assert len(captured["otp"]) == 6

        # Wrong OTP rejected
        bad = client.post(
            "/api/v1/auth/reset-password",
            json={"email": "reset@example.com", "otp": "000000", "new_password": "NewPassword2"},
        )
        assert bad.status_code == 400

        # Correct OTP resets password & revokes old refresh token
        ok = client.post(
            "/api/v1/auth/reset-password",
            json={"email": "reset@example.com", "otp": captured["otp"], "new_password": "NewPassword2"},
        )
        assert ok.status_code == 200

        assert client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh}).status_code == 401

        login = client.post(
            "/api/v1/auth/login",
            json={"email": "reset@example.com", "password": "NewPassword2"},
        )
        assert login.status_code == 200
        assert login.get_json()["user"]["email_verified"] is True

"""
Unit & Integration Tests for Multi-App Payments & Subscriptions.
Mocks external Google Play / Apple Store APIs so tests run offline deterministically.
"""

from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from app.services.store_verifier import (
    LIFETIME_EXPIRY,
    InvalidReceiptError,
    StoreConfigurationError,
)


def _login_user(client, monkeypatch, email="pro@example.com", sub="google-sub-1", app_key="main_app"):
    """Helper to sign in a user via /api/v1/auth/google and return access token + user."""
    monkeypatch.setattr(
        "app.services.auth_service.verify_google_id_token",
        lambda token_str: {
            "google_sub": sub,
            "email": email,
            "email_verified": True,
            "full_name": "Test User",
            "avatar_url": "https://example.com/avatar.png",
        },
    )
    resp = client.post(
        "/api/v1/auth/google",
        json={"id_token": "fake-google-token", "app_key": app_key},
    )
    assert resp.status_code == 200
    return resp.get_json()


class TestPaymentPlansEndpoint:
    def test_list_plans_for_main_app(self, client):
        resp = client.get("/api/v1/payments/plans?app_key=main_app")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["app_key"] == "main_app"
        assert len(body["plans"]) == 2
        assert body["plans"][0]["plan_key"] == "yearly_pro"
        assert body["plans"][0]["price"] == 150.0
        assert body["plans"][1]["plan_key"] == "lifetime_pro"
        assert body["plans"][1]["price"] == 300.0

    def test_list_plans_uses_x_app_key_header(self, client):
        resp = client.get("/api/v1/payments/plans", headers={"X-App-Key": "healthscan_app"})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["app_key"] == "healthscan_app"
        assert body["plans"] == []

    def test_list_plans_unknown_app_returns_404(self, client):
        resp = client.get("/api/v1/payments/plans?app_key=unknown_app")
        assert resp.status_code == 404
        assert resp.get_json()["error"] == "AppNotFound"

    def test_list_plans_inactive_app_returns_403(self, client):
        resp = client.get("/api/v1/payments/plans?app_key=inactive_app")
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "AppInactive"


class TestVerifyPurchaseAndStatus:
    def test_status_requires_auth(self, client):
        resp = client.get("/api/v1/payments/status")
        assert resp.status_code == 401

    def test_free_user_status(self, client, monkeypatch):
        auth = _login_user(client, monkeypatch)
        resp = client.get(
            "/api/v1/payments/status",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["is_pro"] is False
        assert body["status"] == "free"
        assert body["features"] == {}

    def test_verify_purchase_missing_fields_returns_400(self, client, monkeypatch):
        auth = _login_user(client, monkeypatch)
        resp = client.post(
            "/api/v1/payments/verify-purchase",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
            json={"provider": "google_play"},
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "BadRequest"

    def test_verify_purchase_invalid_provider_returns_400(self, client, monkeypatch):
        auth = _login_user(client, monkeypatch)
        resp = client.post(
            "/api/v1/payments/verify-purchase",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
            json={
                "provider": "crypto",
                "product_id": "healthscan_pro_yearly",
                "purchase_token": "tok-123",
            },
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "InvalidProvider"

    def test_verify_purchase_unknown_product_returns_404(self, client, monkeypatch):
        auth = _login_user(client, monkeypatch)
        resp = client.post(
            "/api/v1/payments/verify-purchase",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
            json={
                "provider": "google_play",
                "product_id": "non_existent_sku",
                "purchase_token": "tok-123",
            },
        )
        assert resp.status_code == 404
        assert resp.get_json()["error"] == "PlanNotFound"

    def test_verify_google_yearly_subscription_activates_pro(self, client, monkeypatch, mock_db):
        auth = _login_user(client, monkeypatch)
        future_expiry = datetime.now(timezone.utc) + timedelta(days=365)

        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mock_verify:
            mock_verify.return_value = {
                "provider_subscription_id": "google-tok-yearly-1",
                "provider_transaction_id": "GPA.1111-2222-3333",
                "status": "active",
                "starts_at": datetime.now(timezone.utc),
                "expires_at": future_expiry,
                "auto_renew": True,
                "raw_data": {"subscriptionState": "SUBSCRIPTION_STATE_ACTIVE"},
            }

            resp = client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
                json={
                    "provider": "google_play",
                    "product_id": "healthscan_pro_yearly",
                    "purchase_token": "google-tok-yearly-1",
                },
            )

        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        assert body["subscription"]["is_pro"] is True
        assert body["subscription"]["plan_key"] == "yearly_pro"
        assert body["subscription"]["billing_period"] == "yearly"
        assert body["subscription"]["features"] == {"premium": True}
        assert len(mock_db.payment_transactions) == 1

        # Status endpoint now returns is_pro=True
        status_resp = client.get(
            "/api/v1/payments/status",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
        )
        assert status_resp.status_code == 200
        assert status_resp.get_json()["is_pro"] is True

    def test_verify_google_lifetime_purchase_and_idempotent_retry(self, client, monkeypatch, mock_db):
        auth = _login_user(client, monkeypatch)

        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mock_verify:
            mock_verify.return_value = {
                "provider_subscription_id": "google-tok-life-1",
                "provider_transaction_id": "GPA.9999-8888-7777",
                "status": "active",
                "starts_at": datetime.now(timezone.utc),
                "expires_at": LIFETIME_EXPIRY,
                "auto_renew": False,
                "raw_data": {"purchaseState": 0},
            }

            payload = {
                "provider": "google_play",
                "product_id": "healthscan_pro_lifetime",
                "purchase_token": "google-tok-life-1",
            }
            resp1 = client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
                json=payload,
            )
            resp2 = client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
                json=payload,
            )

        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp1.get_json()["subscription"]["plan_key"] == "lifetime_pro"
        assert resp1.get_json()["subscription"]["auto_renew"] is False
        # Duplicate retry must not create a second transaction row
        assert len(mock_db.payment_transactions) == 1

    def test_verify_apple_purchase(self, client, monkeypatch):
        auth = _login_user(client, monkeypatch)
        future_expiry = datetime.now(timezone.utc) + timedelta(days=365)

        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mock_verify:
            mock_verify.return_value = {
                "provider_subscription_id": "apple-orig-tx-1",
                "provider_transaction_id": "apple-tx-1",
                "status": "active",
                "starts_at": datetime.now(timezone.utc),
                "expires_at": future_expiry,
                "auto_renew": True,
                "raw_data": {"productId": "healthscan_pro_yearly"},
            }
            resp = client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
                json={
                    "provider": "apple",
                    "product_id": "healthscan_pro_yearly",
                    "purchase_token": "apple-tx-1",
                },
            )

        assert resp.status_code == 200
        assert resp.get_json()["subscription"]["provider"] == "apple"
        assert resp.get_json()["subscription"]["is_pro"] is True

    def test_invalid_receipt_returns_400(self, client, monkeypatch):
        auth = _login_user(client, monkeypatch)
        with patch(
            "app.services.payment_service.StoreVerifier.verify_purchase",
            side_effect=InvalidReceiptError("Token expired or invalid"),
        ):
            resp = client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
                json={
                    "provider": "google_play",
                    "product_id": "healthscan_pro_yearly",
                    "purchase_token": "bad-token",
                },
            )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "InvalidReceipt"

    def test_unconfigured_store_returns_503(self, client, monkeypatch):
        auth = _login_user(client, monkeypatch)
        with patch(
            "app.services.payment_service.StoreVerifier.verify_purchase",
            side_effect=StoreConfigurationError("Missing service account"),
        ):
            resp = client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
                json={
                    "provider": "google_play",
                    "product_id": "healthscan_pro_yearly",
                    "purchase_token": "tok-123",
                },
            )
        assert resp.status_code == 503
        assert resp.get_json()["error"] == "StoreNotConfigured"

    def test_multi_app_isolation(self, client, monkeypatch):
        """A user who is Pro on main_app must still be Free on healthscan_app."""
        auth_main = _login_user(client, monkeypatch, email="multi@example.com", sub="sub-multi", app_key="main_app")
        auth_other = _login_user(client, monkeypatch, email="multi@example.com", sub="sub-multi", app_key="healthscan_app")

        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mock_verify:
            mock_verify.return_value = {
                "provider_subscription_id": "tok-multi",
                "provider_transaction_id": "GPA.MULTI",
                "status": "active",
                "starts_at": datetime.now(timezone.utc),
                "expires_at": LIFETIME_EXPIRY,
                "auto_renew": False,
                "raw_data": {},
            }
            client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth_main['access_token']}"},
                json={
                    "provider": "google_play",
                    "product_id": "healthscan_pro_lifetime",
                    "purchase_token": "tok-multi",
                },
            )

        main_status = client.get(
            "/api/v1/payments/status",
            headers={"Authorization": f"Bearer {auth_main['access_token']}"},
        ).get_json()
        other_status = client.get(
            "/api/v1/payments/status",
            headers={"Authorization": f"Bearer {auth_other['access_token']}"},
        ).get_json()

        assert main_status["is_pro"] is True
        assert other_status["is_pro"] is False


class TestRequireSubscriptionMiddleware:
    def test_blocks_free_user_with_403(self, client, monkeypatch):
        auth = _login_user(client, monkeypatch)
        resp = client.get(
            "/api/v1/test/pro-feature",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
        )
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "SubscriptionRequired"

    def test_allows_active_pro_user_and_checks_feature_flag(self, client, monkeypatch):
        auth = _login_user(client, monkeypatch)
        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mock_verify:
            mock_verify.return_value = {
                "provider_subscription_id": "tok-mw",
                "provider_transaction_id": "GPA.MW",
                "status": "active",
                "starts_at": datetime.now(timezone.utc),
                "expires_at": LIFETIME_EXPIRY,
                "auto_renew": False,
                "raw_data": {},
            }
            client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
                json={
                    "provider": "google_play",
                    "product_id": "healthscan_pro_lifetime",
                    "purchase_token": "tok-mw",
                },
            )

        ok_resp = client.get(
            "/api/v1/test/pro-feature",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
        )
        assert ok_resp.status_code == 200
        assert ok_resp.get_json()["plan_key"] == "lifetime_pro"

        missing_feat_resp = client.get(
            "/api/v1/test/vip-only",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
        )
        assert missing_feat_resp.status_code == 403
        assert missing_feat_resp.get_json()["error"] == "UpgradeRequired"


class TestStoreWebhooks:
    def test_google_rtdn_test_notification(self, client):
        import base64
        import json

        data_b64 = base64.b64encode(json.dumps({"testNotification": {"version": "1.0"}}).encode()).decode()
        resp = client.post(
            "/api/v1/payments/webhook/google",
            json={"message": {"data": data_b64, "messageId": "m-1"}},
        )
        assert resp.status_code == 200
        assert resp.get_json()["type"] == "testNotification"

    def test_google_rtdn_renewal_and_revocation(self, client, monkeypatch, mock_db):
        import base64
        import json

        auth = _login_user(client, monkeypatch)
        initial_expiry = datetime.now(timezone.utc) + timedelta(days=30)
        renewed_expiry = datetime.now(timezone.utc) + timedelta(days=395)

        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mock_verify:
            mock_verify.return_value = {
                "provider_subscription_id": "tok-rtdn-1",
                "provider_transaction_id": "GPA.INIT",
                "status": "active",
                "starts_at": datetime.now(timezone.utc),
                "expires_at": initial_expiry,
                "auto_renew": True,
                "raw_data": {},
            }
            client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
                json={
                    "provider": "google_play",
                    "product_id": "healthscan_pro_yearly",
                    "purchase_token": "tok-rtdn-1",
                },
            )

        # 1. Renewal notification (notificationType=2)
        renew_payload = {
            "packageName": "com.healthscanapp.mobile",
            "subscriptionNotification": {
                "notificationType": 2,
                "purchaseToken": "tok-rtdn-1",
                "subscriptionId": "healthscan_pro_yearly",
            },
        }
        renew_b64 = base64.b64encode(json.dumps(renew_payload).encode()).decode()

        with patch("app.services.payment_service.StoreVerifier.verify_google_play") as mock_reverify:
            mock_reverify.return_value = {
                "provider_subscription_id": "tok-rtdn-1",
                "provider_transaction_id": "GPA.RENEW.1",
                "status": "active",
                "starts_at": datetime.now(timezone.utc),
                "expires_at": renewed_expiry,
                "auto_renew": True,
                "raw_data": {"subscriptionState": "SUBSCRIPTION_STATE_ACTIVE"},
            }
            resp = client.post(
                "/api/v1/payments/webhook/google",
                json={"message": {"data": renew_b64}},
            )

        assert resp.status_code == 200
        assert resp.get_json()["status"] == "active"
        assert len(mock_db.payment_transactions) == 2

        # 2. Revocation / Refund notification (notificationType=12)
        revoke_payload = {
            "packageName": "com.healthscanapp.mobile",
            "subscriptionNotification": {
                "notificationType": 12,
                "purchaseToken": "tok-rtdn-1",
                "subscriptionId": "healthscan_pro_yearly",
            },
        }
        revoke_b64 = base64.b64encode(json.dumps(revoke_payload).encode()).decode()
        revoke_resp = client.post(
            "/api/v1/payments/webhook/google",
            json={"message": {"data": revoke_b64}},
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.get_json()["status"] == "expired"

        status_resp = client.get(
            "/api/v1/payments/status",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
        ).get_json()
        assert status_resp["is_pro"] is False
        assert status_resp["status"] == "expired"

    def test_google_webhook_rejects_bad_secret(self, client, monkeypatch):
        monkeypatch.setattr("app.config.Config.GOOGLE_RTDN_WEBHOOK_SECRET", "super-secret")
        resp = client.post(
            "/api/v1/payments/webhook/google?token=wrong",
            json={"message": {"data": "e30="}},
        )
        assert resp.status_code == 401

    def test_apple_webhook_renewal_and_refund(self, client, monkeypatch, mock_db):
        import jwt as pyjwt

        auth = _login_user(client, monkeypatch)
        initial_expiry = datetime.now(timezone.utc) + timedelta(days=30)
        renewed_ms = int((datetime.now(timezone.utc) + timedelta(days=395)).timestamp() * 1000)

        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mock_verify:
            mock_verify.return_value = {
                "provider_subscription_id": "orig-apple-1",
                "provider_transaction_id": "tx-apple-1",
                "status": "active",
                "starts_at": datetime.now(timezone.utc),
                "expires_at": initial_expiry,
                "auto_renew": True,
                "raw_data": {},
            }
            client.post(
                "/api/v1/payments/verify-purchase",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
                json={
                    "provider": "apple",
                    "product_id": "healthscan_pro_yearly",
                    "purchase_token": "tx-apple-1",
                },
            )

        signed_tx = pyjwt.encode(
            {
                "originalTransactionId": "orig-apple-1",
                "transactionId": "tx-apple-2",
                "expiresDate": renewed_ms,
            },
            "unused",
            algorithm="HS256",
        )
        signed_payload = pyjwt.encode(
            {
                "notificationType": "DID_RENEW",
                "data": {"signedTransactionInfo": signed_tx},
            },
            "unused",
            algorithm="HS256",
        )

        resp = client.post(
            "/api/v1/payments/webhook/apple",
            json={"signedPayload": signed_payload},
        )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "active"
        assert len(mock_db.payment_transactions) == 2

        refund_payload = pyjwt.encode(
            {
                "notificationType": "REFUND",
                "data": {"signedTransactionInfo": signed_tx},
            },
            "unused",
            algorithm="HS256",
        )
        refund_resp = client.post(
            "/api/v1/payments/webhook/apple",
            json={"signedPayload": refund_payload},
        )
        assert refund_resp.status_code == 200
        assert refund_resp.get_json()["status"] == "expired"

        status_resp = client.get(
            "/api/v1/payments/status",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
        ).get_json()
        assert status_resp["is_pro"] is False

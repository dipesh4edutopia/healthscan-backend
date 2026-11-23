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

        # Signature verification is covered separately in TestAppleJwsVerification;
        # here we only exercise the notification business logic with unsigned test JWTs.
        monkeypatch.setattr(
            "app.services.payment_service.StoreVerifier.decode_apple_jws",
            lambda s: pyjwt.decode(s, options={"verify_signature": False}),
        )

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


class TestPurchaseOwnership:
    def _verified(self, token):
        return {
            "provider_subscription_id": token,
            "provider_transaction_id": f"GPA.{token}",
            "status": "active",
            "starts_at": datetime.now(timezone.utc),
            "expires_at": LIFETIME_EXPIRY,
            "auto_renew": False,
            "raw_data": {},
        }

    def _verify(self, client, auth, token):
        return client.post(
            "/api/v1/payments/verify-purchase",
            headers={"Authorization": f"Bearer {auth['access_token']}"},
            json={
                "provider": "google_play",
                "product_id": "healthscan_pro_lifetime",
                "purchase_token": token,
            },
        )

    def test_same_token_cannot_unlock_a_second_account(self, client, monkeypatch, mock_db):
        owner = _login_user(client, monkeypatch, email="owner@example.com", sub="sub-owner")
        thief = _login_user(client, monkeypatch, email="thief@example.com", sub="sub-thief")

        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mock_verify:
            mock_verify.return_value = self._verified("shared-token")

            assert self._verify(client, owner, "shared-token").status_code == 200

            resp = self._verify(client, thief, "shared-token")
            assert resp.status_code == 409
            assert resp.get_json()["error"] == "PurchaseAlreadyLinked"

        thief_status = client.get(
            "/api/v1/payments/status",
            headers={"Authorization": f"Bearer {thief['access_token']}"},
        ).get_json()
        owner_status = client.get(
            "/api/v1/payments/status",
            headers={"Authorization": f"Bearer {owner['access_token']}"},
        ).get_json()
        assert thief_status["is_pro"] is False
        assert owner_status["is_pro"] is True

    def test_owner_can_reverify_same_token(self, client, monkeypatch, mock_db):
        owner = _login_user(client, monkeypatch, email="again@example.com", sub="sub-again")
        with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mock_verify:
            mock_verify.return_value = self._verified("my-token")
            assert self._verify(client, owner, "my-token").status_code == 200
            assert self._verify(client, owner, "my-token").status_code == 200


class TestWebhookFailClosed:
    def test_google_webhook_disabled_without_secret_outside_tests(self, client, app, monkeypatch):
        monkeypatch.setattr("app.config.Config.GOOGLE_RTDN_WEBHOOK_SECRET", "")
        monkeypatch.setitem(app.config, "TESTING", False)
        resp = client.post("/api/v1/payments/webhook/google", json={"message": {"data": "e30="}})
        assert resp.status_code == 503
        assert resp.get_json()["error"] == "WebhookNotConfigured"

    def test_apple_webhook_disabled_without_secret_outside_tests(self, client, app, monkeypatch):
        monkeypatch.setattr("app.config.Config.APPLE_WEBHOOK_SECRET", "")
        monkeypatch.setitem(app.config, "TESTING", False)
        resp = client.post("/api/v1/payments/webhook/apple", json={"signedPayload": "x"})
        assert resp.status_code == 503

    def test_webhook_accepts_correct_secret(self, client, monkeypatch):
        import base64, json as _json

        monkeypatch.setattr("app.config.Config.GOOGLE_RTDN_WEBHOOK_SECRET", "s3cret")
        data = base64.b64encode(_json.dumps({"testNotification": {}}).encode()).decode()
        ok = client.post(
            "/api/v1/payments/webhook/google?token=s3cret",
            json={"message": {"data": data}},
        )
        assert ok.status_code == 200
        header_ok = client.post(
            "/api/v1/payments/webhook/google",
            headers={"X-Webhook-Token": "s3cret"},
            json={"message": {"data": data}},
        )
        assert header_ok.status_code == 200


class TestAppleJwsVerification:
    """Builds a throw-away Apple-style cert chain and checks decode_apple_jws end-to-end."""

    @staticmethod
    def _make_chain(marker_oids=True):
        import datetime as dt
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        from app.services import store_verifier as sv

        def name(cn):
            return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

        def build(subject_cn, subject_key, issuer_cn, issuer_key, marker=None, ca=False):
            now = dt.datetime.now(dt.timezone.utc)
            builder = (
                x509.CertificateBuilder()
                .subject_name(name(subject_cn))
                .issuer_name(name(issuer_cn))
                .public_key(subject_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1))
                .not_valid_after(now + dt.timedelta(days=30))
            )
            if marker is not None:
                builder = builder.add_extension(x509.UnrecognizedExtension(marker, b"\x05\x00"), critical=False)
            return builder.sign(issuer_key, hashes.SHA384())

        root_key = ec.generate_private_key(ec.SECP384R1())
        inter_key = ec.generate_private_key(ec.SECP384R1())
        leaf_key = ec.generate_private_key(ec.SECP256R1())  # ES256 signing key

        root = build("Test Apple Root", root_key, "Test Apple Root", root_key)
        inter = build(
            "Test WWDR", inter_key, "Test Apple Root", root_key,
            marker=sv.APPLE_INTERMEDIATE_MARKER_OID if marker_oids else None,
        )
        leaf = build(
            "Test Leaf", leaf_key, "Test WWDR", inter_key,
            marker=sv.APPLE_LEAF_MARKER_OID if marker_oids else None,
        )
        return root, inter, leaf, leaf_key

    @staticmethod
    def _sign(payload, leaf_key, chain):
        import base64
        import jwt as pyjwt
        from cryptography.hazmat.primitives.serialization import Encoding

        x5c = [base64.b64encode(c.public_bytes(Encoding.DER)).decode() for c in chain]
        return pyjwt.encode(payload, leaf_key, algorithm="ES256", headers={"x5c": x5c})

    def test_valid_chain_is_accepted(self, monkeypatch):
        from cryptography.hazmat.primitives import hashes
        from app.services import store_verifier as sv

        root, inter, leaf, leaf_key = self._make_chain()
        monkeypatch.setattr(sv, "APPLE_ROOT_CA_G3_SHA256", root.fingerprint(hashes.SHA256()).hex())

        token = self._sign({"transactionId": "t1", "productId": "p"}, leaf_key, [leaf, inter, root])
        assert sv.decode_apple_jws(token)["transactionId"] == "t1"

    def test_untrusted_root_is_rejected(self):
        from app.services import store_verifier as sv

        root, inter, leaf, leaf_key = self._make_chain()  # fingerprint NOT pinned
        token = self._sign({"transactionId": "t1"}, leaf_key, [leaf, inter, root])
        try:
            sv.decode_apple_jws(token)
            assert False, "expected InvalidReceiptError"
        except InvalidReceiptError:
            pass

    def test_tampered_payload_is_rejected(self, monkeypatch):
        import base64, json as _json
        from cryptography.hazmat.primitives import hashes
        from app.services import store_verifier as sv

        root, inter, leaf, leaf_key = self._make_chain()
        monkeypatch.setattr(sv, "APPLE_ROOT_CA_G3_SHA256", root.fingerprint(hashes.SHA256()).hex())
        token = self._sign({"transactionId": "t1"}, leaf_key, [leaf, inter, root])

        header, payload, signature = token.split(".")
        forged = base64.urlsafe_b64encode(_json.dumps({"transactionId": "forged"}).encode()).rstrip(b"=").decode()
        try:
            sv.decode_apple_jws(f"{header}.{forged}.{signature}")
            assert False, "expected InvalidReceiptError"
        except InvalidReceiptError:
            pass

    def test_hs256_forgery_and_missing_chain_are_rejected(self):
        import jwt as pyjwt
        from app.services import store_verifier as sv

        for forged in (
            pyjwt.encode({"transactionId": "x"}, "k" * 32, algorithm="HS256"),
            "not-a-jwt",
            "",
        ):
            try:
                sv.decode_apple_jws(forged)
                assert False, "expected InvalidReceiptError"
            except InvalidReceiptError:
                pass

    def test_missing_apple_marker_extensions_are_rejected(self, monkeypatch):
        from cryptography.hazmat.primitives import hashes
        from app.services import store_verifier as sv

        root, inter, leaf, leaf_key = self._make_chain(marker_oids=False)
        monkeypatch.setattr(sv, "APPLE_ROOT_CA_G3_SHA256", root.fingerprint(hashes.SHA256()).hex())
        token = self._sign({"transactionId": "t1"}, leaf_key, [leaf, inter, root])
        try:
            sv.decode_apple_jws(token)
            assert False, "expected InvalidReceiptError"
        except InvalidReceiptError:
            pass


class TestSameUserMultipleApps:
    def test_one_account_can_hold_independent_subscriptions_in_two_apps(self, client, monkeypatch, mock_db):
        """Same Google account, two apps: each app has its own subscription row & entitlement."""
        # Give the second app its own plan so it can be purchased
        second_app = next(a for a in mock_db.apps.values() if a["app_key"] == "healthscan_app")
        mock_db.subscription_plans["plan-second-yearly"] = {
            "id": "plan-second-yearly",
            "app_id": second_app["id"],
            "plan_key": "yearly_pro",
            "name": "Second App Pro Yearly",
            "description": None,
            "google_product_id": "second_pro_yearly",
            "apple_product_id": None,
            "price": 99,
            "currency": "INR",
            "billing_period": "yearly",
            "trial_days": 0,
            "features": {"premium": True},
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        }

        auth_a = _login_user(client, monkeypatch, email="both@example.com", sub="sub-both", app_key="main_app")
        auth_b = _login_user(client, monkeypatch, email="both@example.com", sub="sub-both", app_key="healthscan_app")
        assert auth_a["user"]["id"] == auth_b["user"]["id"]  # one global user
        assert auth_a["app"]["app_key"] != auth_b["app"]["app_key"]

        def buy(auth, product_id, token):
            with patch("app.services.payment_service.StoreVerifier.verify_purchase") as mv:
                mv.return_value = {
                    "provider_subscription_id": token,
                    "provider_transaction_id": f"GPA.{token}",
                    "status": "active",
                    "starts_at": datetime.now(timezone.utc),
                    "expires_at": datetime.now(timezone.utc) + timedelta(days=365),
                    "auto_renew": True,
                    "raw_data": {},
                }
                return client.post(
                    "/api/v1/payments/verify-purchase",
                    headers={"Authorization": f"Bearer {auth['access_token']}"},
                    json={"provider": "google_play", "product_id": product_id, "purchase_token": token},
                )

        def status(auth):
            return client.get(
                "/api/v1/payments/status",
                headers={"Authorization": f"Bearer {auth['access_token']}"},
            ).get_json()

        # Buy only in app A -> B stays free
        assert buy(auth_a, "healthscan_pro_yearly", "tok-app-a").status_code == 200
        assert status(auth_a)["is_pro"] is True
        assert status(auth_b)["is_pro"] is False

        # Buy in app B with the SAME account -> both Pro, two separate rows
        assert buy(auth_b, "second_pro_yearly", "tok-app-b").status_code == 200
        assert status(auth_a)["is_pro"] is True
        assert status(auth_b)["is_pro"] is True
        assert status(auth_a)["plan_name"] != status(auth_b)["plan_name"]
        assert status(auth_b)["plan_name"] == "Second App Pro Yearly"
        assert len(mock_db.user_subscriptions) == 2

        # Cancelling/expiring one app does not touch the other
        key_a = next(k for k, v in mock_db.user_subscriptions.items() if v["provider_subscription_id"] == "tok-app-a")
        mock_db.user_subscriptions[key_a]["expires_at"] = datetime.now(timezone.utc) - timedelta(days=1)
        assert status(auth_a)["is_pro"] is False
        assert status(auth_b)["is_pro"] is True

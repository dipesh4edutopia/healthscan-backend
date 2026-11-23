"""
Store Receipt & Purchase Token Verification Clients
Verifies purchases server-to-server with:
  - Google Play Developer API v3 (Subscriptions v2 + One-time In-App Products)
  - Apple App Store Server API v1 (Signed JWS transactions)
"""

import base64
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GoogleAuthRequest

from app.config import Config

logger = logging.getLogger(__name__)

# Distant future timestamp for lifetime / non-expiring purchases
LIFETIME_EXPIRY = datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

GOOGLE_ANDROID_PUBLISHER_SCOPE = "https://www.googleapis.com/auth/androidpublisher"

# SHA-256 fingerprint (hex, lowercase) of "Apple Root CA - G3".
# Every genuine App Store signed JWS (transactions + server notifications) carries an
# x5c certificate chain that must end in this root.
# Source: https://www.apple.com/certificateauthority/AppleRootCA-G3.cer
APPLE_ROOT_CA_G3_SHA256 = "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"
# Marker extensions Apple puts on the leaf ("Mac App Store Receipt Signing") and the
# intermediate ("Worldwide Developer Relations") certificates.
APPLE_LEAF_MARKER_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.11.1")
APPLE_INTERMEDIATE_MARKER_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.2.1")


class StoreVerificationError(Exception):
    """Base error for store verification failures."""
    pass


class StoreConfigurationError(StoreVerificationError):
    """Missing or invalid store credentials/package configuration on the server."""
    pass


class InvalidReceiptError(StoreVerificationError):
    """Purchase token or transaction receipt is invalid, expired, or canceled."""
    pass


def _parse_iso_datetime(iso_str: str) -> datetime:
    """Parse RFC3339 / ISO-8601 timestamps returned by Google Play (e.g. '2026-11-17T12:00:00.123Z')."""
    if not iso_str:
        raise InvalidReceiptError("Missing expiry timestamp in store response.")
    cleaned = iso_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _cert_validity(cert: x509.Certificate):
    """(not_before, not_after) as aware UTC datetimes across cryptography versions."""
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    return nb, na


def decode_apple_jws(signed_jws: str) -> Dict[str, Any]:
    """
    Cryptographically verifies an Apple-signed JWS (signedTransactionInfo, signedPayload, ...)
    and returns its payload.

    Verification steps (same as Apple's official server library):
      1. JWS header must contain an x5c chain (leaf, intermediate, root).
      2. The chain root must match the pinned Apple Root CA - G3 SHA-256 fingerprint.
      3. Every certificate must be within its validity period and be signed by the next one.
      4. Leaf / intermediate must carry Apple's marker extensions.
      5. The JWS signature (ES256) must verify with the leaf certificate's public key.

    Raises InvalidReceiptError on any failure. Never returns unverified data.
    """
    if not signed_jws or not isinstance(signed_jws, str):
        raise InvalidReceiptError("Apple signed payload is missing.")

    try:
        header = jwt.get_unverified_header(signed_jws)
        if header.get("alg") != "ES256":
            raise InvalidReceiptError("Apple JWS must use ES256.")
        x5c = header.get("x5c") or []
        if len(x5c) != 3:
            raise InvalidReceiptError("Apple JWS certificate chain is missing or malformed.")

        certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in x5c]
        leaf, intermediate, root = certs

        if root.fingerprint(hashes.SHA256()).hex() != APPLE_ROOT_CA_G3_SHA256:
            raise InvalidReceiptError("Apple JWS chain does not end in the trusted Apple Root CA.")

        now = datetime.now(timezone.utc)
        for cert in certs:
            not_before, not_after = _cert_validity(cert)
            if not (not_before <= now <= not_after):
                raise InvalidReceiptError("Apple JWS certificate is expired or not yet valid.")

        # Each cert must be signed by its issuer in the chain (root is self-signed).
        for cert, issuer in ((leaf, intermediate), (intermediate, root), (root, root)):
            issuer_key = issuer.public_key()
            if not isinstance(issuer_key, ec.EllipticCurvePublicKey):
                raise InvalidReceiptError("Unsupported Apple certificate key type.")
            issuer_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )

        try:
            leaf.extensions.get_extension_for_oid(APPLE_LEAF_MARKER_OID)
            intermediate.extensions.get_extension_for_oid(APPLE_INTERMEDIATE_MARKER_OID)
        except x509.ExtensionNotFound as exc:
            raise InvalidReceiptError("Apple certificate chain is missing marker extensions.") from exc

        return jwt.decode(
            signed_jws,
            leaf.public_key(),
            algorithms=["ES256"],
            options={"verify_aud": False},
        )
    except InvalidReceiptError:
        raise
    except Exception as exc:
        logger.warning("Apple JWS verification failed: %s", exc)
        raise InvalidReceiptError("Apple signed data failed signature verification.") from exc


class StoreVerifier:
    """Unified server-side receipt verifier for Google Play and Apple App Store."""

    decode_apple_jws = staticmethod(decode_apple_jws)

    @staticmethod
    def verify_purchase(
        provider: str,
        app_key: str,
        product_id: str,
        purchase_token: str,
        billing_period: str,
    ) -> Dict[str, Any]:
        """
        Dispatches verification to Google Play or Apple App Store.

        Returns normalized dict:
          {
            "provider_subscription_id": str,
            "provider_transaction_id": str,
            "status": "active" | "trialing" | "in_grace_period" | "on_hold" | "canceled" | "expired",
            "starts_at": datetime,
            "expires_at": datetime,
            "auto_renew": bool,
            "raw_data": dict,
          }
        """
        if provider == "google_play":
            return StoreVerifier.verify_google_play(
                app_key=app_key,
                product_id=product_id,
                purchase_token=purchase_token,
                billing_period=billing_period,
            )
        elif provider == "apple":
            return StoreVerifier.verify_apple_store(
                app_key=app_key,
                product_id=product_id,
                transaction_id=purchase_token,
                billing_period=billing_period,
            )
        else:
            raise StoreVerificationError(f"Unsupported payment provider: '{provider}'.")

    # ------------------------------------------------------------------
    # Google Play Verification
    # ------------------------------------------------------------------
    @staticmethod
    def _get_google_credentials():
        """Loads Google Play service account credentials from env JSON or file."""
        info = None
        if Config.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON:
            try:
                info = json.loads(Config.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON)
            except json.JSONDecodeError as exc:
                raise StoreConfigurationError(
                    "GOOGLE_PLAY_SERVICE_ACCOUNT_JSON is not valid JSON."
                ) from exc
            creds = service_account.Credentials.from_service_account_info(
                info, scopes=[GOOGLE_ANDROID_PUBLISHER_SCOPE]
            )
        elif Config.GOOGLE_PLAY_SERVICE_ACCOUNT_FILE:
            try:
                creds = service_account.Credentials.from_service_account_file(
                    Config.GOOGLE_PLAY_SERVICE_ACCOUNT_FILE,
                    scopes=[GOOGLE_ANDROID_PUBLISHER_SCOPE],
                )
            except Exception as exc:
                raise StoreConfigurationError(
                    f"Failed to load Google service account file: {exc}"
                ) from exc
        else:
            raise StoreConfigurationError(
                "Google Play Service Account is not configured on the server."
            )

        creds.refresh(GoogleAuthRequest())
        return creds.token

    @staticmethod
    def verify_google_play(
        app_key: str,
        product_id: str,
        purchase_token: str,
        billing_period: str,
    ) -> Dict[str, Any]:
        package_name = Config.GOOGLE_PLAY_PACKAGES.get(app_key)
        if not package_name:
            raise StoreConfigurationError(
                f"Android package name is not configured in GOOGLE_PLAY_PACKAGES for app '{app_key}'."
            )

        access_token = StoreVerifier._get_google_credentials()
        headers = {"Authorization": f"Bearer {access_token}"}

        if billing_period == "lifetime":
            return StoreVerifier._verify_google_one_time_product(
                package_name=package_name,
                product_id=product_id,
                purchase_token=purchase_token,
                headers=headers,
            )
        return StoreVerifier._verify_google_subscription_v2(
            package_name=package_name,
            purchase_token=purchase_token,
            headers=headers,
        )

    @staticmethod
    def _verify_google_subscription_v2(
        package_name: str,
        purchase_token: str,
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        url = (
            f"https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"
            f"{package_name}/purchases/subscriptionsv2/tokens/{purchase_token}"
        )
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            raise InvalidReceiptError("Google subscription purchase token not found.")
        if not resp.ok:
            logger.error("Google SubscriptionsV2 API error %s: %s", resp.status_code, resp.text)
            raise InvalidReceiptError(f"Google Play verification failed ({resp.status_code}).")

        data = resp.json()
        sub_state = data.get("subscriptionState", "")
        line_items = data.get("lineItems") or []
        if not line_items:
            raise InvalidReceiptError("Google subscription response missing lineItems.")

        item = line_items[0]
        expires_at = _parse_iso_datetime(item.get("expiryTime"))
        starts_at = _parse_iso_datetime(data.get("startTime")) if data.get("startTime") else datetime.now(timezone.utc)
        auto_renew = bool((item.get("autoRenewingPlan") or {}).get("autoRenewEnabled", False))
        order_id = data.get("latestOrderId") or purchase_token

        state_map = {
            "SUBSCRIPTION_STATE_ACTIVE": "active",
            "SUBSCRIPTION_STATE_IN_GRACE_PERIOD": "in_grace_period",
            "SUBSCRIPTION_STATE_ON_HOLD": "on_hold",
            "SUBSCRIPTION_STATE_CANCELED": "canceled",
            "SUBSCRIPTION_STATE_EXPIRED": "expired",
            "SUBSCRIPTION_STATE_PAUSED": "on_hold",
        }
        status = state_map.get(sub_state, "expired")

        if status not in ("active", "in_grace_period", "canceled", "trialing"):
            raise InvalidReceiptError(f"Subscription is not active (state: {sub_state}).")

        if expires_at <= datetime.now(timezone.utc):
            raise InvalidReceiptError("Google subscription has already expired.")

        return {
            "provider_subscription_id": purchase_token,
            "provider_transaction_id": order_id,
            "status": status,
            "starts_at": starts_at,
            "expires_at": expires_at,
            "auto_renew": auto_renew,
            "raw_data": data,
        }

    @staticmethod
    def _verify_google_one_time_product(
        package_name: str,
        product_id: str,
        purchase_token: str,
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        url = (
            f"https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"
            f"{package_name}/purchases/products/{product_id}/tokens/{purchase_token}"
        )
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            raise InvalidReceiptError("Google product purchase token not found.")
        if not resp.ok:
            logger.error("Google Products API error %s: %s", resp.status_code, resp.text)
            raise InvalidReceiptError(f"Google Play product verification failed ({resp.status_code}).")

        data = resp.json()
        # purchaseState: 0 = Purchased, 1 = Canceled, 2 = Pending
        purchase_state = data.get("purchaseState")
        if purchase_state != 0:
            raise InvalidReceiptError(
                f"One-time purchase is not completed (purchaseState={purchase_state})."
            )

        purchase_ms = data.get("purchaseTimeMillis")
        starts_at = (
            datetime.fromtimestamp(int(purchase_ms) / 1000.0, tz=timezone.utc)
            if purchase_ms
            else datetime.now(timezone.utc)
        )
        order_id = data.get("orderId") or purchase_token

        return {
            "provider_subscription_id": purchase_token,
            "provider_transaction_id": order_id,
            "status": "active",
            "starts_at": starts_at,
            "expires_at": LIFETIME_EXPIRY,
            "auto_renew": False,
            "raw_data": data,
        }

    # ------------------------------------------------------------------
    # Apple App Store Server API v1 Verification
    # ------------------------------------------------------------------
    @staticmethod
    def _generate_apple_jwt(bundle_id: str) -> str:
        if not (Config.APPLE_IAP_KEY_ID and Config.APPLE_IAP_ISSUER_ID and Config.APPLE_IAP_PRIVATE_KEY):
            raise StoreConfigurationError(
                "Apple App Store Server API credentials are not configured on the server."
            )

        now = datetime.now(timezone.utc)
        payload = {
            "iss": Config.APPLE_IAP_ISSUER_ID,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=15)).timestamp()),
            "aud": "appstoreconnect-v1",
            "bid": bundle_id,
        }
        headers = {
            "alg": "ES256",
            "kid": Config.APPLE_IAP_KEY_ID,
            "typ": "JWT",
        }
        return jwt.encode(payload, Config.APPLE_IAP_PRIVATE_KEY, algorithm="ES256", headers=headers)

    @staticmethod
    def verify_apple_store(
        app_key: str,
        product_id: str,
        transaction_id: str,
        billing_period: str,
    ) -> Dict[str, Any]:
        bundle_id = Config.APPLE_BUNDLE_IDS.get(app_key)
        if not bundle_id:
            raise StoreConfigurationError(
                f"Apple bundle ID is not configured in APPLE_BUNDLE_IDS for app '{app_key}'."
            )

        token = StoreVerifier._generate_apple_jwt(bundle_id)
        headers = {"Authorization": f"Bearer {token}"}

        # Try production first, fallback to sandbox on 404 (standard Apple practice for TestFlight/review)
        prod_url = f"https://api.storekit.itunes.apple.com/inApps/v1/transactions/{transaction_id}"
        resp = requests.get(prod_url, headers=headers, timeout=15)
        if resp.status_code == 404:
            sandbox_url = f"https://api.storekit-sandbox.itunes.apple.com/inApps/v1/transactions/{transaction_id}"
            resp = requests.get(sandbox_url, headers=headers, timeout=15)

        if not resp.ok:
            logger.error("Apple StoreKit API error %s: %s", resp.status_code, resp.text)
            raise InvalidReceiptError(f"Apple App Store verification failed ({resp.status_code}).")

        data = resp.json()
        signed_tx = data.get("signedTransactionInfo")
        if not signed_tx:
            raise InvalidReceiptError("Apple response missing signedTransactionInfo.")

        # Verify the Apple signature chain and decode the transaction payload
        tx_info = StoreVerifier.decode_apple_jws(signed_tx)

        if tx_info.get("bundleId") != bundle_id:
            raise InvalidReceiptError("Apple transaction bundleId mismatch.")
        if tx_info.get("productId") != product_id:
            raise InvalidReceiptError("Apple transaction productId mismatch.")
        if tx_info.get("revocationDate"):
            raise InvalidReceiptError("Apple transaction has been revoked/refunded.")

        purchase_ms = tx_info.get("purchaseDate")
        starts_at = (
            datetime.fromtimestamp(int(purchase_ms) / 1000.0, tz=timezone.utc)
            if purchase_ms
            else datetime.now(timezone.utc)
        )

        if billing_period == "lifetime" or not tx_info.get("expiresDate"):
            expires_at = LIFETIME_EXPIRY
            auto_renew = False
        else:
            expires_at = datetime.fromtimestamp(int(tx_info["expiresDate"]) / 1000.0, tz=timezone.utc)
            if expires_at <= datetime.now(timezone.utc):
                raise InvalidReceiptError("Apple subscription has already expired.")
            auto_renew = True

        original_tx_id = str(tx_info.get("originalTransactionId") or transaction_id)
        tx_id = str(tx_info.get("transactionId") or transaction_id)

        return {
            "provider_subscription_id": original_tx_id,
            "provider_transaction_id": tx_id,
            "status": "active",
            "starts_at": starts_at,
            "expires_at": expires_at,
            "auto_renew": auto_renew,
            "raw_data": tx_info,
        }

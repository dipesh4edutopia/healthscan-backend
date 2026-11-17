"""
Multi-App Payments & Subscription Service
Handles per-app plan retrieval, store receipt verification, entitlement status checks,
and transaction ledger recording across multiple registered applications.
"""

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import jwt

from app.config import Config
from app.database import get_db_cursor
from app.services.auth_service import AuthService
from app.services.store_verifier import (
    StoreVerifier,
    StoreVerificationError,
    StoreConfigurationError,
    InvalidReceiptError,
)

logger = logging.getLogger(__name__)

ENTITLED_STATUSES = {"active", "trialing", "in_grace_period", "canceled"}


class PaymentServiceError(Exception):
    """Base exception for payment service errors."""
    pass


class PlanNotFoundError(PaymentServiceError):
    """No matching active plan found for the app and product_id."""
    pass


class InvalidProviderError(PaymentServiceError):
    """Unsupported or missing payment provider."""
    pass


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _format_plan(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "plan_key": row["plan_key"],
        "name": row["name"],
        "description": row.get("description"),
        "google_product_id": row.get("google_product_id"),
        "apple_product_id": row.get("apple_product_id"),
        "price": float(row["price"]) if row.get("price") is not None else 0.0,
        "currency": row.get("currency", "INR"),
        "billing_period": row["billing_period"],
        "trial_days": int(row.get("trial_days") or 0),
        "features": row.get("features") or {},
    }


class PaymentService:
    """Multi-app subscription & payment manager."""

    @staticmethod
    def get_active_plans(app_key: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Resolves the app by app_key and returns all active subscription plans for it.
        """
        with get_db_cursor(commit=False) as cursor:
            app_record = AuthService.resolve_app(app_key, cursor=cursor)
            cursor.execute(
                """
                SELECT id, app_id, plan_key, name, description,
                       google_product_id, apple_product_id,
                       price, currency, billing_period, trial_days, features, is_active
                FROM public.subscription_plans
                WHERE app_id = %s AND is_active = TRUE
                ORDER BY price ASC, created_at ASC;
                """,
                (app_record["id"],),
            )
            rows = cursor.fetchall() or []

        plans = [_format_plan(dict(r)) for r in rows]
        return app_record, plans

    @staticmethod
    def _find_plan_for_product(
        app_id: str, provider: str, product_id: str, cursor
    ) -> Dict[str, Any]:
        """
        Finds an active plan in subscription_plans matching the store product_id (or plan_key).
        """
        if provider == "google_play":
            col = "google_product_id"
        elif provider == "apple":
            col = "apple_product_id"
        else:
            raise InvalidProviderError(
                f"Unsupported provider '{provider}'. Expected 'google_play' or 'apple'."
            )

        cursor.execute(
            f"""
            SELECT id, app_id, plan_key, name, description,
                   google_product_id, apple_product_id,
                   price, currency, billing_period, trial_days, features, is_active
            FROM public.subscription_plans
            WHERE app_id = %s
              AND is_active = TRUE
              AND ({col} = %s OR plan_key = %s)
            LIMIT 1;
            """,
            (app_id, product_id, product_id),
        )
        row = cursor.fetchone()
        if not row:
            raise PlanNotFoundError(
                f"No active plan found for product '{product_id}' on this application."
            )
        return dict(row)

    @staticmethod
    def verify_and_activate_purchase(
        user_id: str,
        app_id: str,
        app_key: str,
        provider: str,
        product_id: str,
        purchase_token: str,
    ) -> Dict[str, Any]:
        """
        Verifies a purchase token/transaction ID with Google Play or Apple App Store,
        upserts public.user_subscriptions, and records the transaction in public.payment_transactions.
        """
        if provider not in ("google_play", "apple"):
            raise InvalidProviderError(
                f"Unsupported provider '{provider}'. Expected 'google_play' or 'apple'."
            )

        with get_db_cursor(commit=False) as cursor:
            plan = PaymentService._find_plan_for_product(
                app_id=app_id,
                provider=provider,
                product_id=product_id,
                cursor=cursor,
            )

        # Call external store API (outside DB transaction so locks aren't held during HTTP)
        verified = StoreVerifier.verify_purchase(
            provider=provider,
            app_key=app_key,
            product_id=product_id,
            purchase_token=purchase_token,
            billing_period=plan["billing_period"],
        )

        raw_json = json.dumps(verified.get("raw_data") or {}, default=str)

        with get_db_cursor(commit=True) as cursor:
            # 1. Upsert user_subscriptions (1 active/latest record per user + app)
            cursor.execute(
                """
                INSERT INTO public.user_subscriptions (
                    user_id, app_id, plan_id, provider, provider_subscription_id,
                    status, starts_at, expires_at, auto_renew, canceled_at,
                    last_verified_at, raw_receipt_data
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    NOW(), %s::jsonb
                )
                ON CONFLICT (user_id, app_id) DO UPDATE SET
                    plan_id = EXCLUDED.plan_id,
                    provider = EXCLUDED.provider,
                    provider_subscription_id = EXCLUDED.provider_subscription_id,
                    status = EXCLUDED.status,
                    starts_at = EXCLUDED.starts_at,
                    expires_at = EXCLUDED.expires_at,
                    auto_renew = EXCLUDED.auto_renew,
                    canceled_at = EXCLUDED.canceled_at,
                    last_verified_at = NOW(),
                    raw_receipt_data = EXCLUDED.raw_receipt_data
                RETURNING id, status, starts_at, expires_at, auto_renew;
                """,
                (
                    user_id,
                    app_id,
                    plan["id"],
                    provider,
                    verified["provider_subscription_id"],
                    verified["status"],
                    verified["starts_at"],
                    verified["expires_at"],
                    verified["auto_renew"],
                    datetime.now(timezone.utc) if verified["status"] == "canceled" else None,
                    raw_json,
                ),
            )
            sub_row = dict(cursor.fetchone())

            # 2. Record immutable transaction ledger (idempotent on duplicate retries)
            cursor.execute(
                """
                INSERT INTO public.payment_transactions (
                    user_id, app_id, subscription_id, plan_id,
                    provider, provider_transaction_id,
                    amount, currency, status, raw_response
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s,
                    %s, %s, 'success', %s::jsonb
                )
                ON CONFLICT (provider, provider_transaction_id) DO NOTHING
                RETURNING id;
                """,
                (
                    user_id,
                    app_id,
                    sub_row["id"],
                    plan["id"],
                    provider,
                    verified["provider_transaction_id"],
                    plan["price"],
                    plan["currency"],
                    raw_json,
                ),
            )

        logger.info(
            "Activated %s subscription for user=%s app=%s plan=%s expires=%s",
            provider,
            user_id,
            app_key,
            plan["plan_key"],
            sub_row["expires_at"],
        )

        expires_at = _ensure_utc(sub_row["expires_at"])
        return {
            "is_pro": True,
            "subscription_id": str(sub_row["id"]),
            "status": sub_row["status"],
            "provider": provider,
            "plan_key": plan["plan_key"],
            "plan_name": plan["name"],
            "billing_period": plan["billing_period"],
            "expires_at": expires_at.isoformat() if expires_at else None,
            "auto_renew": bool(sub_row["auto_renew"]),
            "features": plan.get("features") or {},
        }

    @staticmethod
    def get_user_subscription_status(user_id: str, app_id: str) -> Dict[str, Any]:
        """
        Returns the current subscription status and entitlements for (user_id, app_id).
        """
        with get_db_cursor(commit=False) as cursor:
            cursor.execute(
                """
                SELECT us.id, us.status, us.provider, us.starts_at, us.expires_at,
                       us.auto_renew, us.last_verified_at,
                       sp.plan_key, sp.name AS plan_name, sp.billing_period, sp.features
                FROM public.user_subscriptions us
                JOIN public.subscription_plans sp ON sp.id = us.plan_id
                WHERE us.user_id = %s AND us.app_id = %s
                LIMIT 1;
                """,
                (user_id, app_id),
            )
            row = cursor.fetchone()

        if not row:
            return {
                "is_pro": False,
                "status": "free",
                "plan_key": None,
                "plan_name": None,
                "billing_period": None,
                "expires_at": None,
                "auto_renew": False,
                "features": {},
            }

        data = dict(row)
        now = datetime.now(timezone.utc)
        expires_at = _ensure_utc(data.get("expires_at"))
        status = data["status"]

        is_entitled = (
            status in ENTITLED_STATUSES
            and expires_at is not None
            and expires_at > now
        )
        effective_status = status if is_entitled else ("expired" if status in ENTITLED_STATUSES else status)

        return {
            "is_pro": is_entitled,
            "subscription_id": str(data["id"]),
            "status": effective_status,
            "provider": data.get("provider"),
            "plan_key": data["plan_key"],
            "plan_name": data["plan_name"],
            "billing_period": data["billing_period"],
            "expires_at": expires_at.isoformat() if expires_at else None,
            "auto_renew": bool(data.get("auto_renew", False)),
            "features": (data.get("features") or {}) if is_entitled else {},
        }

    # ------------------------------------------------------------------
    # Store Webhooks (RTDN & App Store Server Notifications v2)
    # ------------------------------------------------------------------
    @staticmethod
    def _find_subscription_by_provider_id(
        provider: str, provider_sub_id: str, cursor
    ) -> Optional[Dict[str, Any]]:
        cursor.execute(
            """
            SELECT us.id, us.user_id, us.app_id, us.plan_id, us.status,
                   us.expires_at, us.auto_renew,
                   sp.billing_period, sp.price, sp.currency,
                   a.app_key
            FROM public.user_subscriptions us
            JOIN public.subscription_plans sp ON sp.id = us.plan_id
            JOIN public.apps a ON a.id = us.app_id
            WHERE us.provider = %s AND us.provider_subscription_id = %s
            LIMIT 1;
            """,
            (provider, provider_sub_id),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    @staticmethod
    def _update_subscription_from_webhook(
        sub: Dict[str, Any],
        status: str,
        expires_at: Optional[datetime],
        auto_renew: bool,
        raw_data: Dict[str, Any],
        tx_id: Optional[str] = None,
        tx_status: str = "success",
    ) -> None:
        raw_json = json.dumps(raw_data or {}, default=str)
        effective_expires = expires_at or _ensure_utc(sub["expires_at"])
        canceled_at = datetime.now(timezone.utc) if status in ("canceled", "expired") else None

        with get_db_cursor(commit=True) as cursor:
            cursor.execute(
                """
                UPDATE public.user_subscriptions
                SET status = %s,
                    expires_at = %s,
                    auto_renew = %s,
                    canceled_at = COALESCE(%s, canceled_at),
                    last_verified_at = NOW(),
                    raw_receipt_data = %s::jsonb
                WHERE id = %s;
                """,
                (
                    status,
                    effective_expires,
                    auto_renew,
                    canceled_at,
                    raw_json,
                    sub["id"],
                ),
            )

            if tx_id:
                cursor.execute(
                    """
                    INSERT INTO public.payment_transactions (
                        user_id, app_id, subscription_id, plan_id,
                        provider, provider_transaction_id,
                        amount, currency, status, raw_response
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        %s, %s,
                        %s, %s, %s, %s::jsonb
                    )
                    ON CONFLICT (provider, provider_transaction_id) DO NOTHING;
                    """,
                    (
                        sub["user_id"],
                        sub["app_id"],
                        sub["id"],
                        sub["plan_id"],
                        "google_play" if sub.get("provider") == "google_play" else sub.get("provider", "apple"),
                        tx_id,
                        sub.get("price", 0),
                        sub.get("currency", "INR"),
                        tx_status,
                        raw_json,
                    ),
                )

    @staticmethod
    def handle_google_rtdn(pubsub_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a Google Cloud Pub/Sub Real-Time Developer Notification (RTDN).
        """
        message = (pubsub_payload or {}).get("message") or {}
        encoded_data = message.get("data")
        if not encoded_data:
            raise PaymentServiceError("Missing Pub/Sub message.data in Google webhook.")

        try:
            decoded_bytes = base64.b64decode(encoded_data)
            notification = json.loads(decoded_bytes.decode("utf-8"))
        except Exception as exc:
            raise PaymentServiceError(f"Invalid base64 JSON in Pub/Sub message: {exc}") from exc

        if "testNotification" in notification:
            return {"handled": True, "type": "testNotification"}

        package_name = notification.get("packageName", "")
        sub_notif = notification.get("subscriptionNotification")
        one_time_notif = notification.get("oneTimeProductNotification")

        if sub_notif:
            notif_type = sub_notif.get("notificationType")
            purchase_token = sub_notif.get("purchaseToken")
            product_id = sub_notif.get("subscriptionId", "")

            with get_db_cursor(commit=False) as cursor:
                sub = PaymentService._find_subscription_by_provider_id(
                    "google_play", purchase_token, cursor
                )

            if not sub:
                logger.info("Google RTDN ignored: unknown purchaseToken for %s", package_name)
                return {"handled": False, "reason": "subscription_not_found"}

            sub["provider"] = "google_play"
            # Notification types: 12=REVOKED, 13=EXPIRED
            if notif_type in (12, 13):
                new_status = "expired"
                new_expiry = datetime.now(timezone.utc) if notif_type == 12 else _ensure_utc(sub["expires_at"])
                PaymentService._update_subscription_from_webhook(
                    sub=sub,
                    status=new_status,
                    expires_at=new_expiry,
                    auto_renew=False,
                    raw_data=notification,
                    tx_id=f"revoke_{purchase_token}" if notif_type == 12 else None,
                    tx_status="refunded" if notif_type == 12 else "success",
                )
                return {"handled": True, "status": new_status, "notification_type": notif_type}

            # For renewals, cancellations, grace periods, recovery -> re-verify with Google Play API
            try:
                verified = StoreVerifier.verify_google_play(
                    app_key=sub["app_key"],
                    product_id=product_id,
                    purchase_token=purchase_token,
                    billing_period=sub["billing_period"],
                )
                PaymentService._update_subscription_from_webhook(
                    sub=sub,
                    status=verified["status"],
                    expires_at=verified["expires_at"],
                    auto_renew=verified["auto_renew"],
                    raw_data=verified["raw_data"],
                    tx_id=verified["provider_transaction_id"] if notif_type in (1, 2, 4, 7) else None,
                )
                return {"handled": True, "status": verified["status"], "notification_type": notif_type}
            except InvalidReceiptError:
                PaymentService._update_subscription_from_webhook(
                    sub=sub,
                    status="expired",
                    expires_at=_ensure_utc(sub["expires_at"]),
                    auto_renew=False,
                    raw_data=notification,
                )
                return {"handled": True, "status": "expired", "notification_type": notif_type}

        if one_time_notif:
            notif_type = one_time_notif.get("notificationType")
            purchase_token = one_time_notif.get("purchaseToken")
            if notif_type == 2:  # ONE_TIME_PRODUCT_CANCELED
                with get_db_cursor(commit=False) as cursor:
                    sub = PaymentService._find_subscription_by_provider_id(
                        "google_play", purchase_token, cursor
                    )
                if sub:
                    sub["provider"] = "google_play"
                    PaymentService._update_subscription_from_webhook(
                        sub=sub,
                        status="expired",
                        expires_at=datetime.now(timezone.utc),
                        auto_renew=False,
                        raw_data=notification,
                        tx_id=f"refund_{purchase_token}",
                        tx_status="refunded",
                    )
                    return {"handled": True, "status": "expired", "notification_type": notif_type}

        return {"handled": False, "reason": "unhandled_notification_type"}

    @staticmethod
    def handle_apple_notification(payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes an Apple App Store Server Notification v2 signedPayload.
        """
        signed_payload = (payload or {}).get("signedPayload")
        if not signed_payload:
            raise PaymentServiceError("Missing signedPayload in Apple webhook.")

        try:
            outer = jwt.decode(signed_payload, options={"verify_signature": False})
        except Exception as exc:
            raise PaymentServiceError(f"Invalid Apple signedPayload JWT: {exc}") from exc

        notif_type = outer.get("notificationType", "")
        if notif_type == "TEST":
            return {"handled": True, "type": "TEST"}

        data = outer.get("data") or {}
        signed_tx = data.get("signedTransactionInfo")
        if not signed_tx:
            return {"handled": False, "reason": "missing_signedTransactionInfo"}

        tx_info = jwt.decode(signed_tx, options={"verify_signature": False})
        original_tx_id = str(tx_info.get("originalTransactionId") or "")
        tx_id = str(tx_info.get("transactionId") or "")

        with get_db_cursor(commit=False) as cursor:
            sub = PaymentService._find_subscription_by_provider_id(
                "apple", original_tx_id, cursor
            )

        if not sub:
            return {"handled": False, "reason": "subscription_not_found"}

        sub["provider"] = "apple"
        expires_ms = tx_info.get("expiresDate")
        expires_at = (
            datetime.fromtimestamp(int(expires_ms) / 1000.0, tz=timezone.utc)
            if expires_ms
            else _ensure_utc(sub["expires_at"])
        )

        if notif_type in ("EXPIRED", "REVOKE", "REFUND"):
            new_status = "expired"
            auto_renew = False
            if notif_type in ("REVOKE", "REFUND"):
                expires_at = datetime.now(timezone.utc)
            PaymentService._update_subscription_from_webhook(
                sub=sub,
                status=new_status,
                expires_at=expires_at,
                auto_renew=auto_renew,
                raw_data=outer,
                tx_id=f"refund_{tx_id}" if notif_type in ("REVOKE", "REFUND") and tx_id else None,
                tx_status="refunded" if notif_type in ("REVOKE", "REFUND") else "success",
            )
            return {"handled": True, "status": new_status, "notification_type": notif_type}

        if notif_type in ("DID_RENEW", "SUBSCRIBED", "DID_RECOVER"):
            PaymentService._update_subscription_from_webhook(
                sub=sub,
                status="active",
                expires_at=expires_at,
                auto_renew=True,
                raw_data=outer,
                tx_id=tx_id or None,
                tx_status="success",
            )
            return {"handled": True, "status": "active", "notification_type": notif_type}

        if notif_type == "DID_CHANGE_RENEWAL_STATUS":
            subtype = outer.get("subtype", "")
            auto_renew = subtype == "AUTO_RENEW_ENABLED"
            new_status = "active" if auto_renew else "canceled"
            PaymentService._update_subscription_from_webhook(
                sub=sub,
                status=new_status,
                expires_at=expires_at,
                auto_renew=auto_renew,
                raw_data=outer,
            )
            return {"handled": True, "status": new_status, "notification_type": notif_type}

        if notif_type == "GRACE_PERIOD_EXPIRED":
            PaymentService._update_subscription_from_webhook(
                sub=sub,
                status="expired",
                expires_at=expires_at,
                auto_renew=False,
                raw_data=outer,
            )
            return {"handled": True, "status": "expired", "notification_type": notif_type}

        return {"handled": False, "reason": f"unhandled_{notif_type}"}

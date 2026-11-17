"""
Payments & Subscription Blueprint Routes
Multi-app endpoints for listing plans, verifying Google Play / Apple IAP receipts,
and checking active user entitlements.
"""

import hmac
import logging
from flask import Blueprint, request, jsonify, g

from app.config import Config
from app.middleware import require_auth
from app.services.auth_service import AppNotFoundError, AppInactiveError
from app.services.payment_service import (
    PaymentService,
    PaymentServiceError,
    PlanNotFoundError,
    InvalidProviderError,
)
from app.services.store_verifier import (
    StoreVerificationError,
    StoreConfigurationError,
    InvalidReceiptError,
)

logger = logging.getLogger(__name__)

payment_bp = Blueprint('payments', __name__, url_prefix='/api/v1/payments')


@payment_bp.route('/plans', methods=['GET'])
def list_plans():
    """
    List active subscription plans for a specific application.
    App key is resolved from query param `app_key`, header `X-App-Key`, or DEFAULT_APP_KEY.
    """
    app_key = (
        request.args.get('app_key')
        or request.headers.get('X-App-Key')
        or Config.DEFAULT_APP_KEY
    )

    try:
        app_record, plans = PaymentService.get_active_plans(app_key)
        return jsonify({
            'app_key': app_record['app_key'],
            'app_display_name': app_record['display_name'],
            'plans': plans,
        }), 200
    except AppNotFoundError as ane:
        return jsonify({'error': 'AppNotFound', 'message': str(ane)}), 404
    except AppInactiveError as aie:
        return jsonify({'error': 'AppInactive', 'message': str(aie)}), 403
    except Exception:
        logger.exception("Unexpected error fetching subscription plans")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'Could not retrieve subscription plans.',
        }), 500


@payment_bp.route('/verify-purchase', methods=['POST'])
@require_auth
def verify_purchase():
    """
    Verify a Google Play or Apple App Store purchase server-side and activate subscription.
    Requires Authorization: Bearer <access_token>.

    Request Body (JSON):
      {
        "provider": "google_play",        // "google_play" or "apple"
        "product_id": "healthscan_pro_yearly",
        "purchase_token": "<token_or_transaction_id>"
      }
    """
    data = request.get_json(silent=True) or {}
    provider = (data.get('provider') or '').strip().lower()
    product_id = (data.get('product_id') or '').strip()
    purchase_token = (data.get('purchase_token') or '').strip()

    missing = [
        name for name, val in (
            ('provider', provider),
            ('product_id', product_id),
            ('purchase_token', purchase_token),
        ) if not val
    ]
    if missing:
        return jsonify({
            'error': 'BadRequest',
            'message': f"Missing required parameter(s): {', '.join(missing)}.",
        }), 400

    try:
        subscription = PaymentService.verify_and_activate_purchase(
            user_id=g.current_user_id,
            app_id=g.current_app_id,
            app_key=g.current_app_key,
            provider=provider,
            product_id=product_id,
            purchase_token=purchase_token,
        )
        return jsonify({
            'success': True,
            'subscription': subscription,
        }), 200

    except InvalidProviderError as ipe:
        return jsonify({'error': 'InvalidProvider', 'message': str(ipe)}), 400
    except PlanNotFoundError as pnfe:
        return jsonify({'error': 'PlanNotFound', 'message': str(pnfe)}), 404
    except InvalidReceiptError as ire:
        return jsonify({'error': 'InvalidReceipt', 'message': str(ire)}), 400
    except StoreConfigurationError as sce:
        logger.error("Store configuration error: %s", sce)
        return jsonify({'error': 'StoreNotConfigured', 'message': str(sce)}), 503
    except StoreVerificationError as sve:
        return jsonify({'error': 'StoreVerificationError', 'message': str(sve)}), 502
    except Exception:
        logger.exception("Unexpected error during purchase verification")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'An unexpected error occurred while verifying your purchase.',
        }), 500


@payment_bp.route('/status', methods=['GET'])
@require_auth
def get_subscription_status():
    """
    Get the authenticated user's current subscription status and entitlements
    for the current app (resolved from JWT).
    """
    try:
        status = PaymentService.get_user_subscription_status(
            user_id=g.current_user_id,
            app_id=g.current_app_id,
        )
        return jsonify({
            'app_key': g.current_app_key,
            **status,
        }), 200
    except Exception:
        logger.exception("Unexpected error retrieving subscription status")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'Could not retrieve subscription status.',
        }), 500


def _verify_webhook_secret(expected_secret: str) -> bool:
    """Validates optional ?token=... query param or X-Webhook-Token header."""
    if not expected_secret:
        return True
    provided = request.args.get('token') or request.headers.get('X-Webhook-Token') or ''
    return hmac.compare_digest(provided, expected_secret)


@payment_bp.route('/webhook/google', methods=['POST'])
def google_rtdn_webhook():
    """
    Google Play Real-Time Developer Notifications (Cloud Pub/Sub Push endpoint).
    """
    if not _verify_webhook_secret(Config.GOOGLE_RTDN_WEBHOOK_SECRET):
        return jsonify({'error': 'Unauthorized', 'message': 'Invalid webhook token.'}), 401

    payload = request.get_json(silent=True) or {}
    try:
        result = PaymentService.handle_google_rtdn(payload)
        return jsonify({'success': True, **result}), 200
    except PaymentServiceError as pse:
        return jsonify({'error': 'BadRequest', 'message': str(pse)}), 400
    except Exception:
        logger.exception("Unexpected error handling Google RTDN webhook")
        return jsonify({'error': 'InternalServerError', 'message': 'Webhook processing failed.'}), 500


@payment_bp.route('/webhook/apple', methods=['POST'])
def apple_server_webhook():
    """
    Apple App Store Server Notifications v2 endpoint.
    """
    if not _verify_webhook_secret(Config.APPLE_WEBHOOK_SECRET):
        return jsonify({'error': 'Unauthorized', 'message': 'Invalid webhook token.'}), 401

    payload = request.get_json(silent=True) or {}
    try:
        result = PaymentService.handle_apple_notification(payload)
        return jsonify({'success': True, **result}), 200
    except PaymentServiceError as pse:
        return jsonify({'error': 'BadRequest', 'message': str(pse)}), 400
    except Exception:
        logger.exception("Unexpected error handling Apple webhook")
        return jsonify({'error': 'InternalServerError', 'message': 'Webhook processing failed.'}), 500

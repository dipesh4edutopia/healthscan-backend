"""
Pytest Fixtures & In-Memory Supabase Mock Database
Allows running the complete test suite without needing a live external database or network.
"""

import sys
import os
import uuid
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from contextlib import contextmanager
import pytest

# Ensure backend root is on sys.path
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app import create_app
from app.config import TestConfig
from app.database import set_mock_db, close_db_pool


class MockCursor:
    """
    In-memory cursor simulating PostgreSQL queries on the Supabase schema:
      - public.users
      - public.apps
      - public.user_app_access
      - public.refresh_tokens
    """
    def __init__(self, db: 'MockDatabase'):
        self.db = db
        self.last_result: List[Dict[str, Any]] = []

    def execute(self, query: str, params: Optional[tuple] = None):
        params = params or ()
        normalized = " ".join(query.strip().split())

        # -------------------------------------------------------------
        # 1. SELECT 1 AS alive (health check)
        # -------------------------------------------------------------
        if "SELECT 1 AS alive" in normalized:
            self.last_result = [{'alive': 1}]
            return

        # -------------------------------------------------------------
        # 2. SELECT FROM public.apps WHERE app_key = %s
        # -------------------------------------------------------------
        if "FROM public.apps" in normalized and "WHERE app_key = %s" in normalized:
            app_key = params[0]
            matched = [
                dict(a) for a in self.db.apps.values()
                if a['app_key'] == app_key
            ]
            self.last_result = matched
            return

        # -------------------------------------------------------------
        # 3. SELECT FROM public.users WHERE google_sub = %s
        # -------------------------------------------------------------
        if "FROM public.users" in normalized and "WHERE google_sub = %s" in normalized:
            google_sub = params[0]
            matched = [
                dict(u) for u in self.db.users.values()
                if u.get('google_sub') == google_sub
            ]
            self.last_result = matched
            return

        # -------------------------------------------------------------
        # 4. SELECT FROM public.users WHERE LOWER(email) = LOWER(%s)
        # -------------------------------------------------------------
        if "FROM public.users" in normalized and "LOWER(email) = LOWER(%s)" in normalized:
            email = params[0].lower()
            matched = [
                dict(u) for u in self.db.users.values()
                if u.get('email', '').lower() == email
            ]
            self.last_result = matched
            return

        # -------------------------------------------------------------
        # 4b. SELECT FROM public.users WHERE id = %s
        # -------------------------------------------------------------
        if "FROM public.users" in normalized and "WHERE id = %s" in normalized:
            uid = str(params[0])
            u = self.db.users.get(uid)
            self.last_result = [dict(u)] if u else []
            return

        # -------------------------------------------------------------
        # 5. INSERT INTO public.users
        # -------------------------------------------------------------
        if "INSERT INTO public.users" in normalized:
            user_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            if "password_hash" in normalized:
                email, full_name, pw_hash = params
                user_record = {
                    'id': user_id,
                    'google_sub': None,
                    'email': email.lower(),
                    'email_verified': False,
                    'full_name': full_name,
                    'avatar_url': None,
                    'password_hash': pw_hash,
                    'password_updated_at': now,
                    'failed_login_attempts': 0,
                    'locked_until': None,
                    'is_active': True,
                    'created_at': now,
                    'updated_at': now,
                }
            else:
                # (google_sub, email, email_verified, full_name, avatar_url)
                google_sub, email, email_verified, full_name, avatar_url = params
                user_record = {
                    'id': user_id,
                    'google_sub': google_sub,
                    'email': email.lower(),
                    'email_verified': email_verified,
                    'full_name': full_name,
                    'avatar_url': avatar_url,
                    'password_hash': None,
                    'password_updated_at': None,
                    'failed_login_attempts': 0,
                    'locked_until': None,
                    'is_active': True,
                    'created_at': now,
                    'updated_at': now,
                }
            self.db.users[user_id] = user_record
            self.last_result = [dict(user_record)]
            return

        # -------------------------------------------------------------
        # 6. UPDATE public.users
        # -------------------------------------------------------------
        if "UPDATE public.users" in normalized:
            now = datetime.now(timezone.utc)
            if "SET email = %s" in normalized:
                email, email_verified, full_name, avatar_url, uid = params
                uid_str = str(uid)
                if uid_str in self.db.users:
                    u = self.db.users[uid_str]
                    u['email'] = email.lower()
                    u['email_verified'] = email_verified
                    if full_name:
                        u['full_name'] = full_name
                    if avatar_url:
                        u['avatar_url'] = avatar_url
                    u['updated_at'] = now
                    self.last_result = [dict(u)]
                    return
            elif "SET google_sub = %s" in normalized:
                google_sub, email_verified, full_name, avatar_url, uid = params
                uid_str = str(uid)
                if uid_str in self.db.users:
                    u = self.db.users[uid_str]
                    u['google_sub'] = google_sub
                    u['email_verified'] = email_verified
                    if full_name:
                        u['full_name'] = full_name
                    if avatar_url:
                        u['avatar_url'] = avatar_url
                    if "password_hash = NULL" in normalized:
                        u['password_hash'] = None
                        u['failed_login_attempts'] = 0
                        u['locked_until'] = None
                    u['updated_at'] = now
                    self.last_result = [dict(u)]
                    return
            elif "SET password_hash = %s" in normalized:
                pw_hash, uid = params
                uid_str = str(uid)
                if uid_str in self.db.users:
                    u = self.db.users[uid_str]
                    u['password_hash'] = pw_hash
                    u['password_updated_at'] = now
                    if "email_verified = TRUE" in normalized:
                        u['email_verified'] = True
                    u['failed_login_attempts'] = 0
                    u['locked_until'] = None
                    u['updated_at'] = now
                    self.last_result = [dict(u)]
                    return
            elif "SET failed_login_attempts = %s" in normalized:
                attempts, locked_until, uid = params
                uid_str = str(uid)
                if uid_str in self.db.users:
                    u = self.db.users[uid_str]
                    u['failed_login_attempts'] = attempts
                    u['locked_until'] = locked_until
                    u['updated_at'] = now
                    self.last_result = [dict(u)]
                    return
            elif "SET failed_login_attempts = 0" in normalized:
                uid_str = str(params[0])
                if uid_str in self.db.users:
                    u = self.db.users[uid_str]
                    u['failed_login_attempts'] = 0
                    u['locked_until'] = None
                    u['updated_at'] = now
                    self.last_result = [dict(u)]
                    return

            self.last_result = []
            return

        # -------------------------------------------------------------
        # 6b. public.auth_verification_tokens (OTP reset / verify)
        # -------------------------------------------------------------
        if "INSERT INTO public.auth_verification_tokens" in normalized:
            uid, token_hash, expires_at = params
            tid = str(uuid.uuid4())
            rec = {
                'id': tid,
                'user_id': str(uid),
                'purpose': 'password_reset',
                'token_hash': token_hash,
                'attempts': 0,
                'expires_at': expires_at,
                'used_at': None,
                'created_at': datetime.now(timezone.utc),
            }
            self.db.auth_tokens.append(rec)
            self.last_result = [{'id': tid}]
            return

        if "FROM public.auth_verification_tokens" in normalized:
            uid = str(params[0])
            matches = [
                dict(t) for t in self.db.auth_tokens
                if t['user_id'] == uid and t['purpose'] == 'password_reset' and t['used_at'] is None
            ]
            matches.sort(key=lambda t: t['created_at'], reverse=True)
            self.last_result = matches[:1]
            return

        if "UPDATE public.auth_verification_tokens" in normalized:
            now = datetime.now(timezone.utc)
            if "WHERE user_id = %s" in normalized:
                uid = str(params[0])
                for t in self.db.auth_tokens:
                    if t['user_id'] == uid and t['purpose'] == 'password_reset' and t['used_at'] is None:
                        t['used_at'] = now
            elif "SET attempts = attempts + 1" in normalized:
                tid = str(params[0])
                for t in self.db.auth_tokens:
                    if t['id'] == tid:
                        t['attempts'] += 1
            elif "SET used_at = NOW()" in normalized and "WHERE id = %s" in normalized:
                tid = str(params[0])
                for t in self.db.auth_tokens:
                    if t['id'] == tid:
                        t['used_at'] = now
            self.last_result = []
            return

        # -------------------------------------------------------------
        # 7. SELECT FROM public.user_app_access WHERE user_id = %s AND app_id = %s
        # -------------------------------------------------------------
        if "FROM public.user_app_access" in normalized and "WHERE user_id = %s AND app_id = %s" in normalized:
            uid, aid = str(params[0]), str(params[1])
            key = (uid, aid)
            if key in self.db.user_app_access:
                self.last_result = [dict(self.db.user_app_access[key])]
            else:
                self.last_result = []
            return

        # -------------------------------------------------------------
        # 8. INSERT INTO public.user_app_access
        # -------------------------------------------------------------
        if "INSERT INTO public.user_app_access" in normalized:
            uid, aid = str(params[0]), str(params[1])
            now = datetime.now(timezone.utc)
            key = (uid, aid)
            access = {
                'user_id': uid,
                'app_id': aid,
                'role': 'user',
                'is_active': True,
                'created_at': now,
            }
            self.db.user_app_access[key] = access
            self.last_result = [dict(access)]
            return

        # -------------------------------------------------------------
        # 9. INSERT INTO public.refresh_tokens
        # -------------------------------------------------------------
        if "INSERT INTO public.refresh_tokens" in normalized:
            uid, aid, token_hash, expires_at, user_agent, device_label = params
            sid = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            token_record = {
                'id': sid,
                'user_id': str(uid),
                'app_id': str(aid),
                'token_hash': token_hash,
                'expires_at': expires_at,
                'revoked_at': None,
                'created_at': now,
                'last_used_at': None,
                'user_agent': user_agent,
                'device_label': device_label,
            }
            self.db.refresh_tokens[token_hash] = token_record
            self.last_result = [{'id': sid, 'expires_at': expires_at}]
            return

        # -------------------------------------------------------------
        # 10. SELECT FROM public.refresh_tokens (refresh query)
        # -------------------------------------------------------------
        if "FROM public.refresh_tokens" in normalized and "WHERE rt.token_hash = %s" in normalized:
            thash = params[0]
            rt = self.db.refresh_tokens.get(thash)
            if not rt:
                self.last_result = []
                return
            u = self.db.users.get(rt['user_id'], {})
            a = self.db.apps.get(rt['app_id'], {})
            uaa = self.db.user_app_access.get((rt['user_id'], rt['app_id']), {})

            row = {
                'session_id': rt['id'],
                'user_id': rt['user_id'],
                'app_id': rt['app_id'],
                'expires_at': rt['expires_at'],
                'revoked_at': rt['revoked_at'],
                'email': u.get('email'),
                'full_name': u.get('full_name'),
                'avatar_url': u.get('avatar_url'),
                'user_active': u.get('is_active', False),
                'app_key': a.get('app_key'),
                'app_display_name': a.get('display_name'),
                'app_active': a.get('is_active', False),
                'user_role': uaa.get('role', 'user'),
                'access_active': uaa.get('is_active', False),
            }
            self.last_result = [row]
            return

        # -------------------------------------------------------------
        # 11. UPDATE public.refresh_tokens (Revoke session by ID or hash)
        # -------------------------------------------------------------
        if "UPDATE public.refresh_tokens" in normalized:
            now = datetime.now(timezone.utc)
            if "WHERE id = %s" in normalized:
                sid = str(params[0])
                for rt in self.db.refresh_tokens.values():
                    if rt['id'] == sid:
                        rt['revoked_at'] = now
                        rt['last_used_at'] = now
                        self.last_result = [{'id': sid}]
                        return
            elif "WHERE token_hash = %s" in normalized:
                thash = params[0]
                rt = self.db.refresh_tokens.get(thash)
                if rt and rt['revoked_at'] is None:
                    rt['revoked_at'] = now
                    rt['last_used_at'] = now
                    self.last_result = [{'id': rt['id']}]
                    return
            elif "WHERE user_id = %s" in normalized:
                uid = str(params[0])
                aid = str(params[1]) if len(params) > 1 else None
                revoked = []
                for rt in self.db.refresh_tokens.values():
                    if rt['user_id'] == uid and rt['revoked_at'] is None:
                        if aid is None or rt['app_id'] == aid:
                            rt['revoked_at'] = now
                            rt['last_used_at'] = now
                            revoked.append({'id': rt['id']})
                self.last_result = revoked
                return

            self.last_result = []
            return

        # -------------------------------------------------------------
        # 12. SELECT user profile for /me
        # -------------------------------------------------------------
        if "FROM public.users u" in normalized and "JOIN public.apps a" in normalized:
            aid, uid = str(params[0]), str(params[1])
            u = self.db.users.get(uid)
            a = self.db.apps.get(aid)
            uaa = self.db.user_app_access.get((uid, aid), {})
            if u and a:
                self.last_result = [{
                    'id': u['id'],
                    'google_sub': u.get('google_sub'),
                    'password_hash': u.get('password_hash'),
                    'email': u['email'],
                    'email_verified': u['email_verified'],
                    'full_name': u['full_name'],
                    'avatar_url': u['avatar_url'],
                    'is_active': u['is_active'],
                    'created_at': u['created_at'],
                    'role': uaa.get('role', 'user'),
                    'app_access_active': uaa.get('is_active', True),
                    'app_key': a['app_key'],
                    'app_display_name': a['display_name'],
                }]
            else:
                self.last_result = []
            return

        # -------------------------------------------------------------
        # 13. SELECT FROM public.subscription_plans
        # -------------------------------------------------------------
        if "FROM public.subscription_plans" in normalized:
            if "WHERE app_id = %s AND is_active = TRUE AND" in normalized:
                aid, prod_id, plan_key = str(params[0]), params[1], params[2]
                matched = [
                    dict(p) for p in self.db.subscription_plans.values()
                    if p['app_id'] == aid
                    and p['is_active']
                    and (
                        p.get('google_product_id') == prod_id
                        or p.get('apple_product_id') == prod_id
                        or p.get('plan_key') == plan_key
                    )
                ]
                self.last_result = matched[:1]
                return
            elif "WHERE app_id = %s AND is_active = TRUE" in normalized:
                aid = str(params[0])
                matched = sorted(
                    [
                        dict(p) for p in self.db.subscription_plans.values()
                        if p['app_id'] == aid and p['is_active']
                    ],
                    key=lambda p: p['price'],
                )
                self.last_result = matched
                return

        # -------------------------------------------------------------
        # 14. INSERT / UPSERT INTO public.user_subscriptions
        # -------------------------------------------------------------
        if "INSERT INTO public.user_subscriptions" in normalized:
            import json as _json
            uid, aid, pid, provider, provider_sub_id, status, starts_at, expires_at, auto_renew, canceled_at, raw_json = params
            key = (str(uid), str(aid))
            now = datetime.now(timezone.utc)
            existing = self.db.user_subscriptions.get(key)
            sub_id = existing['id'] if existing else str(uuid.uuid4())
            record = {
                'id': sub_id,
                'user_id': str(uid),
                'app_id': str(aid),
                'plan_id': str(pid),
                'provider': provider,
                'provider_subscription_id': provider_sub_id,
                'status': status,
                'starts_at': starts_at,
                'expires_at': expires_at,
                'auto_renew': auto_renew,
                'canceled_at': canceled_at,
                'last_verified_at': now,
                'raw_receipt_data': _json.loads(raw_json) if isinstance(raw_json, str) else raw_json,
                'created_at': existing['created_at'] if existing else now,
                'updated_at': now,
            }
            self.db.user_subscriptions[key] = record
            self.last_result = [{
                'id': sub_id,
                'status': status,
                'starts_at': starts_at,
                'expires_at': expires_at,
                'auto_renew': auto_renew,
            }]
            return

        # -------------------------------------------------------------
        # 15. INSERT INTO public.payment_transactions
        # -------------------------------------------------------------
        if "INSERT INTO public.payment_transactions" in normalized:
            import json as _json
            if len(params) == 10:
                uid, aid, sid, pid, provider, tx_id, amount, currency, tx_status, raw_json = params
            else:
                uid, aid, sid, pid, provider, tx_id, amount, currency, raw_json = params
                tx_status = 'success'
            tx_key = (provider, tx_id)
            if tx_key in self.db.payment_transactions:
                self.last_result = []
                return
            record_id = str(uuid.uuid4())
            self.db.payment_transactions[tx_key] = {
                'id': record_id,
                'user_id': str(uid),
                'app_id': str(aid),
                'subscription_id': str(sid),
                'plan_id': str(pid),
                'provider': provider,
                'provider_transaction_id': tx_id,
                'amount': amount,
                'currency': currency,
                'status': tx_status,
                'raw_response': _json.loads(raw_json) if isinstance(raw_json, str) else raw_json,
                'created_at': datetime.now(timezone.utc),
            }
            self.last_result = [{'id': record_id}]
            return

        # -------------------------------------------------------------
        # 16. SELECT FROM public.user_subscriptions (status or webhook lookup)
        # -------------------------------------------------------------
        if "FROM public.user_subscriptions us" in normalized:
            if "WHERE us.provider = %s AND us.provider_subscription_id = %s" in normalized:
                provider, provider_sub_id = params[0], params[1]
                matched = None
                for sub in self.db.user_subscriptions.values():
                    if sub['provider'] == provider and sub.get('provider_subscription_id') == provider_sub_id:
                        matched = sub
                        break
                if not matched:
                    self.last_result = []
                    return
                plan = self.db.subscription_plans.get(matched['plan_id'], {})
                app_rec = self.db.apps.get(matched['app_id'], {})
                self.last_result = [{
                    'id': matched['id'],
                    'user_id': matched['user_id'],
                    'app_id': matched['app_id'],
                    'plan_id': matched['plan_id'],
                    'status': matched['status'],
                    'expires_at': matched['expires_at'],
                    'auto_renew': matched['auto_renew'],
                    'billing_period': plan.get('billing_period'),
                    'price': plan.get('price', 0),
                    'currency': plan.get('currency', 'INR'),
                    'app_key': app_rec.get('app_key'),
                }]
                return

            uid, aid = str(params[0]), str(params[1])
            sub = self.db.user_subscriptions.get((uid, aid))
            if not sub:
                self.last_result = []
                return
            plan = self.db.subscription_plans.get(sub['plan_id'], {})
            self.last_result = [{
                'id': sub['id'],
                'status': sub['status'],
                'provider': sub['provider'],
                'starts_at': sub['starts_at'],
                'expires_at': sub['expires_at'],
                'auto_renew': sub['auto_renew'],
                'last_verified_at': sub['last_verified_at'],
                'plan_key': plan.get('plan_key'),
                'plan_name': plan.get('name'),
                'billing_period': plan.get('billing_period'),
                'features': plan.get('features') or {},
            }]
            return

        # -------------------------------------------------------------
        # 17. UPDATE public.user_subscriptions (webhook update)
        # -------------------------------------------------------------
        if "UPDATE public.user_subscriptions" in normalized:
            import json as _json
            status, expires_at, auto_renew, canceled_at, raw_json, sid = params
            for sub in self.db.user_subscriptions.values():
                if sub['id'] == str(sid):
                    sub['status'] = status
                    sub['expires_at'] = expires_at
                    sub['auto_renew'] = auto_renew
                    if canceled_at is not None:
                        sub['canceled_at'] = canceled_at
                    sub['last_verified_at'] = datetime.now(timezone.utc)
                    sub['raw_receipt_data'] = _json.loads(raw_json) if isinstance(raw_json, str) else raw_json
                    break
            self.last_result = []
            return

        # Fallback empty
        self.last_result = []

    def fetchone(self) -> Optional[Dict[str, Any]]:
        if self.last_result:
            return self.last_result[0]
        return None

    def fetchall(self) -> List[Dict[str, Any]]:
        return list(self.last_result)

    def close(self):
        pass


class MockDatabase:
    """Mock Database container holding dictionaries for auth and payment schema tables."""
    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}
        self.apps: Dict[str, Dict[str, Any]] = {}
        self.user_app_access: Dict[tuple, Dict[str, Any]] = {}
        self.refresh_tokens: Dict[str, Dict[str, Any]] = {}
        self.subscription_plans: Dict[str, Dict[str, Any]] = {}
        self.user_subscriptions: Dict[tuple, Dict[str, Any]] = {}
        self.payment_transactions: Dict[tuple, Dict[str, Any]] = {}
        self.auth_tokens: List[Dict[str, Any]] = []

        # Pre-seed applications & plans
        self._seed_default_apps()

    def _seed_default_apps(self):
        main_app_id = str(uuid.uuid4())
        self.apps[main_app_id] = {
            'id': main_app_id,
            'app_key': 'main_app',
            'display_name': 'Main App',
            'is_active': True,
            'created_at': datetime.now(timezone.utc),
        }

        healthscan_id = str(uuid.uuid4())
        self.apps[healthscan_id] = {
            'id': healthscan_id,
            'app_key': 'healthscan_app',
            'display_name': 'HealthScan App',
            'is_active': True,
            'created_at': datetime.now(timezone.utc),
        }

        inactive_app_id = str(uuid.uuid4())
        self.apps[inactive_app_id] = {
            'id': inactive_app_id,
            'app_key': 'inactive_app',
            'display_name': 'Inactive App',
            'is_active': False,
            'created_at': datetime.now(timezone.utc),
        }

        # Seed plans for main_app (₹150 yearly + ₹300 lifetime)
        yearly_id = str(uuid.uuid4())
        self.subscription_plans[yearly_id] = {
            'id': yearly_id,
            'app_id': main_app_id,
            'plan_key': 'yearly_pro',
            'name': 'HealthScan Pro Yearly',
            'description': '1 year unlimited access',
            'google_product_id': 'healthscan_pro_yearly',
            'apple_product_id': 'healthscan_pro_yearly',
            'price': 150.00,
            'currency': 'INR',
            'billing_period': 'yearly',
            'trial_days': 0,
            'features': {'premium': True},
            'is_active': True,
        }

        lifetime_id = str(uuid.uuid4())
        self.subscription_plans[lifetime_id] = {
            'id': lifetime_id,
            'app_id': main_app_id,
            'plan_key': 'lifetime_pro',
            'name': 'HealthScan Pro Lifetime',
            'description': 'Lifetime access',
            'google_product_id': 'healthscan_pro_lifetime',
            'apple_product_id': 'healthscan_pro_lifetime',
            'price': 300.00,
            'currency': 'INR',
            'billing_period': 'lifetime',
            'trial_days': 0,
            'features': {'premium': True},
            'is_active': True,
        }

    @contextmanager
    def get_cursor(self, commit: bool = False):
        yield MockCursor(self)


@pytest.fixture(scope='session')
def app():
    """Create Flask test application."""
    test_app = create_app(TestConfig)

    # Register test-only routes to verify reusable auth, RBAC, and subscription middleware decorators
    from flask import jsonify, g
    from app.middleware import require_auth, require_role, require_subscription

    @test_app.route('/api/v1/test/protected', methods=['GET'])
    @require_auth
    def _test_protected():
        return jsonify({
            'authenticated_user': {
                'user_id': g.current_user_id,
                'email': g.current_email,
                'role': g.current_role,
                'app_key': g.current_app_key,
            },
        }), 200

    @test_app.route('/api/v1/test/admin', methods=['GET'])
    @require_auth
    @require_role('admin')
    def _test_admin():
        return jsonify({
            'message': 'Welcome to the Administrator Dashboard.',
            'app_key': g.current_app_key,
            'admin_user_id': g.current_user_id,
            'role': g.current_role,
        }), 200

    @test_app.route('/api/v1/test/pro-feature', methods=['GET'])
    @require_auth
    @require_subscription('premium')
    def _test_pro_feature():
        return jsonify({
            'message': 'Pro feature unlocked!',
            'plan_key': g.current_subscription['plan_key'],
        }), 200

    @test_app.route('/api/v1/test/vip-only', methods=['GET'])
    @require_auth
    @require_subscription('vip_only_flag')
    def _test_vip_only():
        return jsonify({'message': 'VIP unlocked!'}), 200

    return test_app


@pytest.fixture
def mock_db():
    """Provides a fresh MockDatabase instance for each test."""
    db = MockDatabase()
    set_mock_db(db)
    yield db
    set_mock_db(None)


@pytest.fixture
def client(app, mock_db):
    """Flask test client with mock database enabled."""
    with app.test_client() as test_client:
        yield test_client

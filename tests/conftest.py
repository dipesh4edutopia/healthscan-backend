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
        # 5. INSERT INTO public.users
        # -------------------------------------------------------------
        if "INSERT INTO public.users" in normalized:
            # (google_sub, email, email_verified, full_name, avatar_url)
            google_sub, email, email_verified, full_name, avatar_url = params
            user_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            user_record = {
                'id': user_id,
                'google_sub': google_sub,
                'email': email.lower(),
                'email_verified': email_verified,
                'full_name': full_name,
                'avatar_url': avatar_url,
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
            # Check which update query it is
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
                    u['updated_at'] = now
                    self.last_result = [dict(u)]
                    return

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
    """Mock Database container holding dictionaries for the 4 schema tables."""
    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}
        self.apps: Dict[str, Dict[str, Any]] = {}
        self.user_app_access: Dict[tuple, Dict[str, Any]] = {}
        self.refresh_tokens: Dict[str, Dict[str, Any]] = {}

        # Pre-seed applications
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

    @contextmanager
    def get_cursor(self, commit: bool = False):
        yield MockCursor(self)


@pytest.fixture(scope='session')
def app():
    """Create Flask test application."""
    test_app = create_app(TestConfig)

    # Register test-only routes to verify reusable auth & RBAC middleware decorators
    from flask import jsonify, g
    from app.middleware import require_auth, require_role

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

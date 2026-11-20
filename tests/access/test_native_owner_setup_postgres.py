"""Owner activation through real auth audit on an isolated migrated PostgreSQL clone."""
import os
from types import SimpleNamespace

import pytest

from server.api.routes import auth as routes
from server.sli.access import auth

pytestmark = pytest.mark.postgres_integration


@pytest.mark.parametrize('valid_code', [True, False])
def test_owner_activation_commits_real_audit(monkeypatch, valid_code):
    dsn = (os.environ.get('ADLOG_TEST_PG_DSN') or '').strip()
    if not dsn:
        pytest.skip('Disposable migrated PostgreSQL required')
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row

    code = 'synthetic-onetime-code'
    password = 'synthetic-new-owner-password-' + 'x' * 20
    encoded = auth.PASSWORD_HASHER.hash(code)
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        conn.execute("delete from access_platform_owners where owner_key='primary'")
        user_id = conn.execute(
            """insert into auth_users(username,password_hash,role,is_active,last_login_at,updated_at)
               values ('platform-owner',%s,'admin',true,null,clock_timestamp())
               on conflict (lower(username)) do update set password_hash=excluded.password_hash,
               role='admin',is_active=true,last_login_at=null,updated_at=clock_timestamp() returning id""",
            (encoded,),
        ).fetchone()['id']
        conn.execute(
            "insert into access_platform_owners(user_id,owner_key,business_reason) values (%s,'primary','synthetic')",
            (user_id,),
        )
        before = conn.execute('select coalesce(max(id),0) as id from auth_audit').fetchone()['id']

    def runtime_connection():
        conn = psycopg.connect(dsn, row_factory=dict_row)
        conn.execute('set role adlog_user')
        return conn

    monkeypatch.setattr(auth, '_connect', runtime_connection)
    monkeypatch.setenv('SLI_OWNER_SETUP', '1')
    monkeypatch.setenv('ADLOG_AUTH_REQUIRED', '1')
    responses = []
    handler = SimpleNamespace(
        client_address=('192.0.2.1', 1), server=SimpleNamespace(login_allowed=lambda ip: (True, 0)),
        _secure_transport=lambda: True, _check_request_origin=lambda: True,
        _read_json_body=lambda **kwargs: {'code': code if valid_code else 'synthetic-wrong-code', 'password': password},
        _public_principal=lambda principal: principal,
        _send_json=lambda body, status=200, **kwargs: responses.append((body, status)),
        _send_json_with_cookie=lambda body, cookie: responses.append((body, 200)),
    )
    # No replacement of claim, _audit, record_auth_audit, mirror or AUTH_ACTIONS.
    routes._handle_owner_setup(handler)
    assert responses[-1][1] == (200 if valid_code else 401)
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        audits = conn.execute(
            'select actor_type,actor_id,action,outcome from auth_audit where id>%s order by id', (before,),
        ).fetchall()
        assert audits == [{
            'actor_type': 'session' if valid_code else 'anonymous',
            'actor_id': user_id if valid_code else None,
            'action': 'initial_owner_claimed', 'outcome': 'ok' if valid_code else 'failed',
        }]
        user = conn.execute('select password_hash,last_login_at from auth_users where id=%s', (user_id,)).fetchone()
        assert auth.PASSWORD_HASHER.verify(user['password_hash'], password if valid_code else code)
        assert (user['last_login_at'] is not None) is valid_code
    if valid_code:
        assert auth.claim_initial_owner(code, password) is None

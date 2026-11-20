"""One-time owner activation without new schema or privileged API credentials."""
import threading
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from server.api import http_server
from server.api.routes import auth as routes
from server.sli.access import auth
from tests.unit.test_login_self_protection import Ledger


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setenv('SLI_OWNER_SETUP', '1')
    state = {'id': 7, 'username': 'platform-owner', 'password_hash': auth.PASSWORD_HASHER.hash('synthetic-onetime-code'),
             'role': 'admin', 'is_active': True, 'last_login_at': None, 'updated_at': datetime(2026, 10, 30, tzinfo=UTC),
             'checked_at': datetime(2026, 10, 30, tzinfo=UTC), 'audits': []}
    class Cursor(Ledger):
        def execute(self, sql, params=()):
            if 'auth_login_throttle' in sql or 'pg_try_advisory' in sql or sql.startswith('select clock_timestamp'):
                self.auth_query = False
                return super().execute(sql, params)
            self.auth_query = True
            self.audit = sql.startswith('insert into auth_audit')
            if self.audit:
                state['audits'].append(dict(zip(
                    ('actor_type', 'actor_id', 'action', 'outcome', 'remote_address'), params, strict=True)))
            if sql.startswith('update auth_users set password_hash'):
                state['password_hash'] = params[0]
                state['last_login_at'] = 'claimed'
        def fetchone(self):
            if not self.auth_query:
                return super().fetchone()
            if self.audit:
                return {'id': len(state['audits']), 'created_at': state['checked_at']}
            return dict(state)
    monkeypatch.setattr(auth, '_connect', lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(Cursor()))))
    return state


def test_one_time_code_activates_owner_and_cannot_be_reused(owner):
    result = auth.claim_initial_owner('synthetic-onetime-code', 'a-new-password-12345')
    assert result['id'] == 7
    assert owner['audits'][0]['action'] == 'initial_owner_claimed'
    assert owner['audits'][0]['outcome'] == 'ok'
    assert auth.PASSWORD_HASHER.verify(owner['password_hash'], 'a-new-password-12345')
    assert auth.claim_initial_owner('synthetic-onetime-code', 'another-password-123') is None


@pytest.mark.parametrize('failure', [None, 'slow', 'session', 'response', 'broken_pipe', 'timeout'])
def test_bootstrap_returns_complete_response_over_real_tls(owner, monkeypatch, tmp_path, capsys, failure):
    import json
    import ssl
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    from deploy.linux.sli_secrets import _tls_bundle
    from server.sli.core.app_config import AdLogConfig
    from server.sli.ops import logging_config

    monkeypatch.setattr(logging_config, 'LOG_PATH', tmp_path / 'monitor.log')
    monkeypatch.setenv('ADLOG_LOG_DIR', str(tmp_path))
    material = _tls_bundle(['127.0.0.1'])
    certificate, key = tmp_path / 'certificate', tmp_path / 'key'
    certificate.write_bytes(material['tls_certificate'])
    key.write_bytes(material['tls_key'])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    client_context = ssl.create_default_context(cadata=material['tls_ca'].decode('ascii'))
    monkeypatch.setattr(routes, 'auth_required', lambda: True)
    monkeypatch.setattr(routes, 'issue_session', lambda principal: 'synthetic-session')
    monkeypatch.setattr(auth, 'ensure_auth_schema', lambda: None)
    response_failure = failure in {'response', 'broken_pipe', 'timeout'}
    if failure == 'slow':
        import time
        hasher = auth.PASSWORD_HASHER
        def slow_verify(*args):
            time.sleep(0.05)
            return hasher.verify(*args)
        def slow_hash(*args):
            time.sleep(0.05)
            return hasher.hash(*args)
        monkeypatch.setattr(auth, 'PASSWORD_HASHER', SimpleNamespace(verify=slow_verify, hash=slow_hash))
        monkeypatch.setattr(http_server.RequestHandler, 'header_timeout_seconds', 0.02)
    if failure == 'session':
        def fail_session(principal):
            raise RuntimeError('synthetic-private-code-and-password')
        monkeypatch.setattr(routes, 'issue_session', fail_session)
    elif response_failure:
        original = http_server.RequestHandler.end_headers
        def fail_response(handler):
            original(handler)
            error_type = {'response': RuntimeError, 'broken_pipe': BrokenPipeError, 'timeout': TimeoutError}[failure]
            raise error_type('synthetic-private-code-and-password')
        monkeypatch.setattr(http_server.RequestHandler, 'end_headers', fail_response)
    server = http_server.ProtectedHTTPServer(('127.0.0.1', 0), http_server.RequestHandler,
                                             config=AdLogConfig(reports_dir='', log_dir=''))
    # server_close must join the request before stderr capture is inspected.
    server.daemon_threads = False
    server.adlog_tls_context = context
    server.adlog_tls_enabled = True
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
    thread.start()
    try:
        data = json.dumps({'code': 'synthetic-onetime-code', 'password': 'p' * 48}).encode()
        request = Request(f'https://127.0.0.1:{server.server_port}/api/auth/bootstrap', data,
                          {'Content-Type': 'application/json'})
        if response_failure:
            import http.client
            with pytest.raises((OSError, http.client.HTTPException)), \
                    urlopen(request, context=client_context, timeout=10) as response:
                response.read()
        else:
            try:
                response = urlopen(request, context=client_context, timeout=10)
            except HTTPError as error:
                response = error
            with response:
                body = response.read()
                assert response.status == (500 if failure == 'session' else 200)
                assert len(body) == int(response.headers['Content-Length'])
                if failure != 'session':
                    assert json.loads(body)['authenticated'] is True
                    assert 'synthetic-session' in response.headers['Set-Cookie']
        assert owner['last_login_at'] == 'claimed'
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    if failure == 'session' or response_failure:
        journal = capsys.readouterr().err
        assert ('initial_owner_setup_failed' if failure == 'session' else 'http_request_failed') in journal
        assert 'synthetic-private-code-and-password' not in journal
        assert 'synthetic-onetime-code' not in journal
        assert 'synthetic-session' not in journal
        assert 'p' * 48 not in journal


@pytest.mark.parametrize('change', [{'last_login_at': 'already-used'}, {'is_active': False}, {'role': 'viewer'}, {'id': None}])
def test_claim_refuses_used_disabled_or_foreign_account(owner, change):
    owner.update(change)
    assert auth.claim_initial_owner('synthetic-onetime-code', 'a-new-password-12345') is None


def test_claim_refuses_wrong_code_and_does_not_change_password(owner):
    before = owner['password_hash']
    assert auth.claim_initial_owner('wrong-code', 'a-new-password-12345') is None
    assert owner['password_hash'] == before


def test_claim_is_disabled_outside_explicit_native_setup(owner, monkeypatch):
    monkeypatch.delenv('SLI_OWNER_SETUP')
    assert auth.claim_initial_owner('synthetic-onetime-code', 'a-new-password-12345') is None


def test_bootstrap_code_cannot_be_used_as_normal_login(owner, monkeypatch):
    from unittest.mock import Mock

    attempt = Mock()
    monkeypatch.setattr(auth, 'AccountAttempt', Mock(return_value=attempt))
    assert auth.authenticate_password('platform-owner', 'synthetic-onetime-code') is None
    attempt.failed.assert_called_once()
    attempt.succeeded.assert_not_called()


@pytest.mark.parametrize('password', ['short', 'synthetic-onetime-code', 'x' * 4097])
def test_claim_validates_password_before_database(owner, password):
    with pytest.raises(ValueError):
        auth.claim_initial_owner('synthetic-onetime-code', password)


@pytest.mark.parametrize('secure,origin,allowed', [(False, True, True), (True, False, True), (True, True, False)])
def test_claim_route_checks_tls_origin_and_rate_limit_before_reading_body(monkeypatch, secure, origin, allowed):
    monkeypatch.setenv('SLI_OWNER_SETUP', '1')
    responses = []
    handler = SimpleNamespace(
        _secure_transport=lambda: secure, _check_request_origin=lambda: origin,
        client_address=('192.0.2.1', 1), server=SimpleNamespace(login_allowed=lambda ip: (allowed, 30)),
        _send_json=lambda *args, **kwargs: responses.append(args),
        _read_json_body=lambda **kwargs: pytest.fail('must guard before reading credentials'))
    assert routes.try_handle_post(handler, '/api/auth/bootstrap')


def test_bootstrap_form_does_not_embed_credentials_or_external_resources(owner, monkeypatch):
    monkeypatch.setenv('SLI_OWNER_SETUP', '1')
    html = []
    handler = SimpleNamespace(_send_html=html.append)
    assert routes.try_handle_account_get(handler, '/api/auth/bootstrap')
    assert 'fetch("/api/auth/bootstrap"' in html[0]
    assert 'https://' not in html[0]


@pytest.fixture
def setup_handler(owner, monkeypatch):
    server = object.__new__(http_server.ProtectedHTTPServer)
    server.login_lock = threading.Lock()
    server.login_failure_window_seconds = 60
    server.max_login_failures = 3
    server.login_attempts = {}
    monkeypatch.setattr(http_server.time, 'monotonic', lambda: 100)
    monkeypatch.setattr(routes, 'auth_required', lambda: True)
    monkeypatch.setattr(routes, 'issue_session', lambda principal: 'synthetic-session')
    monkeypatch.setattr(auth, 'ensure_auth_schema', lambda: None)
    responses = []
    payload = {'code': 'wrong-synthetic-code', 'password': 'a-new-password-12345'}
    return SimpleNamespace(
        server=server, client_address=('192.0.2.1', 1), payload=payload,
        responses=responses, audits=owner['audits'],
        _secure_transport=lambda: True, _check_request_origin=lambda: True,
        _read_json_body=lambda **kwargs: dict(payload),
        _public_principal=lambda principal: principal,
        _send_json=lambda body, status=200, **kwargs: responses.append((body, status, kwargs)),
        _send_json_with_cookie=lambda body, cookie: responses.append((body, 200, {'cookie': cookie})),
    )


@pytest.mark.parametrize('used', [False, True])
def test_failed_owner_codes_exhaust_budget_and_are_audited(setup_handler, owner, used):
    handler = setup_handler
    if used:
        owner['last_login_at'] = 'already-used'
        handler.payload['code'] = 'synthetic-onetime-code'
    for _ in range(3):
        routes._handle_owner_setup(handler)
        assert handler.responses[-1][1] == 401
    assert handler.audits == [{
        'actor_type': 'anonymous', 'actor_id': None, 'action': 'initial_owner_claimed',
        'outcome': 'failed', 'remote_address': '192.0.2.1',
    }] * 3
    handler._read_json_body = lambda **kwargs: pytest.fail('locked request must not read credentials')
    routes._handle_owner_setup(handler)
    assert handler.responses[-1] == (
        {'error': 'login_temporarily_locked'}, 429, {'headers': {'Retry-After': '60'}},
    )


def test_owner_activation_succeeds_after_failures_within_budget(setup_handler, owner):
    handler = setup_handler
    for _ in range(2):
        routes._handle_owner_setup(handler)
        assert handler.responses[-1][1] == 401
    handler.payload['code'] = 'synthetic-onetime-code'
    routes._handle_owner_setup(handler)
    assert handler.responses[-1][1] == 200
    assert handler.responses[-1][0]['authenticated'] is True
    assert handler.responses[-1][0]['principal']['id'] == 7
    assert 'HttpOnly' in handler.responses[-1][2]['cookie']
    assert owner['last_login_at'] == 'claimed'
    assert auth.PASSWORD_HASHER.verify(owner['password_hash'], 'a-new-password-12345')


def test_expired_code_cannot_activate_owner(owner):
    owner['updated_at'] = owner['checked_at'] - timedelta(hours=24)
    before = dict(owner)
    assert auth.claim_initial_owner('synthetic-onetime-code', 'a-new-password-12345') is None
    assert owner == before


@pytest.mark.parametrize('activated', [False, True])
def test_bootstrap_form_checks_database_even_with_setup_flag(owner, activated):
    owner['last_login_at'] = 'claimed' if activated else None
    html, responses = [], []
    handler = SimpleNamespace(_send_html=html.append, _send_json=lambda *args: responses.append(args))
    assert routes.try_handle_account_get(handler, '/api/auth/bootstrap')
    assert bool(html) is not activated
    if activated:
        assert responses == [({'error': 'not_found'}, 404)]


@pytest.mark.parametrize('change', [{'id': None}, {'role': 'viewer'}, {'is_active': False}, {'username': 'foreign'}])
def test_bootstrap_form_refuses_ineligible_owner(owner, change):
    owner.update(change)
    responses = []
    handler = SimpleNamespace(_send_html=lambda html: pytest.fail('must hide form'),
                              _send_json=lambda *args: responses.append(args))
    assert routes.try_handle_account_get(handler, '/api/auth/bootstrap')
    assert responses == [({'error': 'not_found'}, 404)]


def test_bootstrap_form_disabled_without_querying_database(monkeypatch):
    monkeypatch.delenv('SLI_OWNER_SETUP', raising=False)
    monkeypatch.setattr(auth, '_connect', lambda: pytest.fail('disabled setup must not query DB'))
    responses = []
    handler = SimpleNamespace(_send_json=lambda *args: responses.append(args))
    assert routes.try_handle_account_get(handler, '/api/auth/bootstrap')
    assert responses == [({'error': 'not_found'}, 404)]


def test_expired_code_consumes_attempt_budget_and_records_failure(setup_handler, owner):
    handler = setup_handler
    handler.payload['code'] = 'synthetic-onetime-code'
    owner['updated_at'] = owner['checked_at'] - timedelta(hours=24)
    routes._handle_owner_setup(handler)
    assert handler.responses[-1][1] == 401
    assert handler.audits[-1]['outcome'] == 'failed'
    assert owner['last_login_at'] is None


@pytest.mark.parametrize('age,valid', [(-1, False), (0, True), (86399, True), (86400, False), (86401, False)])
def test_owner_code_lifetime_boundaries(age, valid):
    checked = datetime(2026, 10, 30, tzinfo=UTC)
    assert auth.owner_code_current(checked - timedelta(seconds=age), checked) is valid


def test_missing_owner_code_issuance_time_is_invalid():
    assert not auth.owner_code_current(None, datetime(2026, 10, 30, tzinfo=UTC))


@pytest.mark.parametrize('password', [None, 123, 'short', 'synthetic-onetime-code', 'x\x00' * 12, 'x' * 4097])
def test_route_reports_only_invalid_password_as_bad_request(setup_handler, password):
    setup_handler.payload.update(code='synthetic-onetime-code', password=password)
    routes._handle_owner_setup(setup_handler)
    assert setup_handler.responses[-1][:2] == ({'error': 'new_password_required'}, 400)


@pytest.mark.parametrize('stage', ['claim', 'failed_audit', 'session'])
@pytest.mark.parametrize('error_type', [ValueError, RuntimeError])
def test_owner_setup_internal_errors_are_safe_500_and_logged(setup_handler, monkeypatch, tmp_path, stage, error_type):
    from server.sli.ops import logging_config

    service_log = tmp_path / 'service.log'
    monkeypatch.setattr(logging_config, 'LOG_PATH', service_log)
    def fail(*args, **kwargs):
        raise error_type('synthetic-private-code-and-password')

    if stage == 'claim':
        monkeypatch.setattr(routes, 'claim_initial_owner', fail)
    elif stage == 'failed_audit':
        monkeypatch.setattr(routes, 'record_auth_audit', fail)
    else:
        setup_handler.payload['code'] = 'synthetic-onetime-code'
        monkeypatch.setattr(routes, 'issue_session', fail)
    routes._handle_owner_setup(setup_handler)
    assert setup_handler.responses[-1][:2] == ({'error': 'internal_server_error'}, 500)
    logged = service_log.read_text(encoding='utf-8')
    assert 'initial_owner_setup_failed' in logged
    assert 'synthetic-private-code-and-password' not in logged
    assert 'synthetic-private-code-and-password' not in str(setup_handler.responses)

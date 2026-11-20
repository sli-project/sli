from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from types import SimpleNamespace

import pytest

from server.api import http_server
from server.api.routes import auth


def _server():
    server = object.__new__(http_server.ProtectedHTTPServer)
    server.login_lock = threading.Lock()
    server.login_failure_window_seconds = 60
    server.max_login_failures = 3
    server.login_attempts = {}
    return server


def _handler(server):
    responses = []
    return SimpleNamespace(
        server=server, client_address=("198.51.100.1", 1234), responses=responses,
        _check_request_origin=lambda: True, _secure_transport=lambda: True,
        _read_json_body=lambda: {"username": "synthetic-account", "password": "synthetic-password"},
        _send_json=lambda payload, status=200, **kwargs: responses.append((payload, status)),
    )


def _patch_auth(monkeypatch):
    monkeypatch.setattr(auth, "auth_required", lambda: True)
    monkeypatch.setattr(auth, "record_auth_audit", lambda **_: None)
    monkeypatch.setattr(auth, "issue_session", lambda *_, **kwargs: "synthetic-session")
    monkeypatch.setattr(auth, "_send_login_success", lambda *_, **kwargs: None)


def test_known_password_cannot_clear_failures_or_other_clients(monkeypatch):
    _patch_auth(monkeypatch)
    server = _server()
    assert server.login_allowed("198.51.100.2")[0]
    handler = _handler(server)
    outcomes = iter([None, {"id": 1}, None])
    verified = []
    monkeypatch.setattr(auth, "authenticate_password", lambda *_: verified.append(True) or next(outcomes))
    for _ in range(4):
        auth._handle_login(handler)
    assert len(verified) == 3
    assert [status for _, status in handler.responses] == [HTTPStatus.UNAUTHORIZED, HTTPStatus.UNAUTHORIZED, HTTPStatus.TOO_MANY_REQUESTS]
    assert len(server.login_attempts["198.51.100.1"]) == 3
    assert len(server.login_attempts["198.51.100.2"]) == 1


def test_all_successes_consume_the_same_attempt_budget(monkeypatch):
    _patch_auth(monkeypatch)
    handler = _handler(_server())
    verified = []
    monkeypatch.setattr(auth, "authenticate_password", lambda *_: verified.append(True) or {"id": 1})
    for _ in range(4):
        auth._handle_login(handler)
    assert len(verified) == 3
    assert handler.responses[-1][1] == HTTPStatus.TOO_MANY_REQUESTS


def test_inflight_password_checks_reserve_budget_atomically(monkeypatch):
    _patch_auth(monkeypatch)
    server = _server()
    entered = threading.Barrier(4)
    release = threading.Event()

    def verify(*_):
        entered.wait(timeout=5)
        assert release.wait(timeout=5)
        return None

    monkeypatch.setattr(auth, "authenticate_password", verify)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(auth._handle_login, _handler(server)) for _ in range(3)]
        try:
            entered.wait(timeout=5)
            rejected = _handler(server)
            auth._handle_login(rejected)
            assert rejected.responses[-1][1] == HTTPStatus.TOO_MANY_REQUESTS
        finally:
            release.set()
        for future in futures:
            future.result(timeout=5)
    assert len(server.login_attempts["198.51.100.1"]) == 3


def test_expired_buckets_are_removed_and_requests_can_resume(monkeypatch):
    server = _server()
    monkeypatch.setattr(http_server.time, "monotonic", lambda: 100)
    for _ in range(3):
        assert server.login_allowed("198.51.100.1") == (True, 0)
    assert server.login_allowed("198.51.100.1") == (False, 60)
    server.login_allowed("198.51.100.2")
    monkeypatch.setattr(http_server.time, "monotonic", lambda: 160)
    assert server.login_allowed("198.51.100.3") == (True, 0)
    assert set(server.login_attempts) == {"198.51.100.3"}
    assert server.login_allowed("198.51.100.1") == (True, 0)


def test_verification_error_still_consumes_attempt(monkeypatch):
    _patch_auth(monkeypatch)
    server = _server()

    def broken(*_):
        raise RuntimeError("synthetic-verification-error")

    monkeypatch.setattr(auth, "authenticate_password", broken)
    with pytest.raises(RuntimeError):
        auth._handle_login(_handler(server))
    assert len(server.login_attempts["198.51.100.1"]) == 1


def test_password_spray_across_accounts_hits_source_budget(monkeypatch):
    _patch_auth(monkeypatch)
    handler = _handler(_server())
    verified = []
    monkeypatch.setattr(auth, "authenticate_password", lambda username, _: verified.append(username))
    for index in range(10):
        handler._read_json_body = lambda index=index: {"username": f"fixture-{index}", "password": "synthetic"}
        auth._handle_login(handler)
    assert verified == ["fixture-0", "fixture-1", "fixture-2"]
    assert [status for _, status in handler.responses[3:]] == [HTTPStatus.TOO_MANY_REQUESTS] * 7

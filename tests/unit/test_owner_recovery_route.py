"""HTTP recovery contracts without importing unrelated server renderers."""
from http import HTTPStatus
from types import SimpleNamespace

import pytest

from server.api.routes import auth


def test_recovery_keeps_source_gate_and_never_echoes_code(monkeypatch):
    code = "synthetic-console-code"
    # The unmodified server owns the budget. This route contract checks that
    # recovery still obeys its denial before reading/validating credentials.
    admission = iter([(True, 0), (True, 0), (True, 0), (False, 60)])
    responses, checked, audits = [], [], []
    handler = SimpleNamespace(
        server=SimpleNamespace(login_allowed=lambda _: next(admission)),
        client_address=("198.51.100.1", 1234),
        _check_request_origin=lambda: True, _secure_transport=lambda: True,
        _read_json_body=lambda: {"username": "owner", "password": "synthetic", "recovery_code": code},
        _send_json=lambda payload, status=200, **kwargs: responses.append((payload, status)),
    )

    def verify(username, password, **kwargs):
        checked.append(kwargs)
        return None

    monkeypatch.setattr(auth, "auth_required", lambda: True)
    monkeypatch.setattr(auth, "authenticate_password", verify)
    monkeypatch.setattr(auth, "record_auth_audit", lambda **kwargs: audits.append(kwargs))
    for _ in range(4):
        auth._handle_login(handler)
    assert len(checked) == 3
    assert all(item == {"recovery_code": code, "remote_address": "198.51.100.1"} for item in checked)
    assert [status for _, status in responses] == [HTTPStatus.UNAUTHORIZED] * 3 + [HTTPStatus.TOO_MANY_REQUESTS]
    assert code not in str(responses) + str(audits)


@pytest.mark.parametrize("path", ["/api/auth/owner-recovery", "/api/auth/recovery", "/api/auth/owner-recovery/issue"])
def test_no_web_route_can_issue_recovery(path):
    assert not auth.try_handle_post(SimpleNamespace(), path)


@pytest.fixture
def recovery_route(monkeypatch):
    from server.sli.access import auth as service_auth
    from server.sli.access import owner_recovery
    from tests.unit.test_owner_recovery import RecoveryDatabase, install_code
    from contextlib import nullcontext

    db = RecoveryDatabase()
    clock = [0.0]
    # Use a fresh process-local budget for each HTTP contract.
    import time
    monkeypatch.setattr(owner_recovery, "recovery_budget", owner_recovery.RecoveryBudget())
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(service_auth, "_connect", lambda: nullcontext(db))
    monkeypatch.setattr(auth, "auth_required", lambda: True)
    from server.sli.sources import administrative_activity_producer
    monkeypatch.setattr(administrative_activity_producer, "mirror_auth_audit_if_enabled", lambda **_: None)
    monkeypatch.setattr(auth, "record_auth_audit", lambda **kw: service_auth._audit(db, **kw))
    monkeypatch.setattr(auth, "issue_session", lambda *_, **__: "synthetic-session")
    monkeypatch.setattr(auth, "_send_login_success", lambda h, *_, **__: h.responses.append(({}, 200, {})))
    admissions = []

    def request(code, address="198.51.100.1", username="owner", password="synthetic-owner-password"):
        def allowed(client):
            admissions.append(client)
            return True, 0
        h = SimpleNamespace(
            server=SimpleNamespace(login_allowed=allowed), client_address=(address, 1234),
            _check_request_origin=lambda: True, _secure_transport=lambda: True,
            _read_json_body=lambda: {"username": username, "password": password, "recovery_code": code},
            responses=[],
        )
        h._send_json = lambda payload, status=200, **kw: h.responses.append((payload, status, kw))
        auth._handle_login(h)
        return h.responses[-1]

    return db, clock, request, install_code, admissions


def test_recovery_five_failures_block_even_valid_code_without_consuming_or_leaking(recovery_route):
    db, clock, request, install, _ = recovery_route
    code = install(db)
    for _ in range(5):
        assert request("wrong-code")[1] == 401
    calls = len(db.calls)
    for candidate in [code, "another-wrong-code"]:
        payload, status, kwargs = request(candidate)
        assert status == 429
        assert payload == {"error": "login_temporarily_locked", "retry_after_seconds": 900}
        assert kwargs == {"headers": {"Retry-After": "900"}}
        assert db.audits[-1][2:4] == ("owner_recovery_login", "throttled")
    assert all("auth_owner_recovery" not in sql for sql, _ in db.calls[calls:])
    assert 1 in db.codes
    assert code not in str(db.calls) + str(db.audits)
    assert "synthetic-owner-password" not in str(db.calls) + str(db.audits)
    clock[0] = 899
    assert request(code)[1] == 429


def test_recovery_unblocks_at_deadline_without_extending_code_expiry(recovery_route):
    from datetime import timedelta
    db, clock, request, install, _ = recovery_route
    old_code = install(db)
    expiry = db.codes[1]["expires_at"]
    for _ in range(5):
        request("wrong")
    clock[0] = 899
    db.now += timedelta(seconds=899)
    assert request(old_code)[1] == 429
    assert db.codes[1]["expires_at"] == expiry
    clock[0] = 900
    db.now += timedelta(seconds=1)
    assert request(old_code)[1] == 401
    fresh_code = install(db)
    assert request(fresh_code)[1] == 200
    assert not db.codes


@pytest.mark.parametrize("trusted", [False, True])
def test_recovery_address_budget_uses_same_proxy_identity_as_login(recovery_route, trusted):
    import ipaddress
    from server.api.proxy import request_context
    db, _, request, install, admissions = recovery_route
    code = install(db)
    peer = "192.0.2.2"
    networks = (ipaddress.ip_network(peer),) if trusted else ()
    def address(xff):
        return request_context(peer, {"X-Forwarded-For": xff}, tls=True, trusted_proxies=networks).client_ip
    for _ in range(5):
        assert request("wrong", address("198.51.100.1"))[1] == 401
    assert request(code, address("198.51.100.1"))[1] == 429
    assert request(code, address("198.51.100.2"))[1] == (200 if trusted else 429)
    assert admissions == (["198.51.100.1"] * 6 + ["198.51.100.2"] if trusted else [peer] * 7)


def test_recovery_failures_across_usernames_and_passwords_share_address_budget(recovery_route):
    db, _, request, install, _ = recovery_route
    code = install(db)
    for i in range(5):
        assert request(code, username="owner" if i % 2 else "missing", password="wrong")[1] == 401
    assert request(code)[1] == 429
    assert request(code, "198.51.100.2")[1] == 200


def test_recovery_parallel_checks_reserve_budget_without_blocking_other_addresses():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, Event
    from server.sli.access.owner_recovery import RecoveryBudget
    from server.sli.access.login_throttle import LoginThrottled

    budget = RecoveryBudget()
    started, release = Barrier(6), Event()
    def invalid():
        started.wait(timeout=5)
        assert release.wait(timeout=5)
        return None
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(budget.verify, "same", invalid) for _ in range(5)]
        try:
            started.wait(timeout=5)
            with pytest.raises(LoginThrottled):
                budget.verify("same", lambda: pytest.fail("sixth verifier must not run"))
            assert budget.verify("different", lambda: {"id": 1}) == {"id": 1}
        finally:
            release.set()
        assert [future.result(timeout=5) for future in futures] == [None] * 5
    with pytest.raises(LoginThrottled) as caught:
        budget.verify("same", lambda: {"id": 1})
    assert 899 <= caught.value.retry_after <= 900


def test_recovery_successes_and_service_errors_do_not_spend_failure_budget():
    from server.sli.access.owner_recovery import RecoveryBudget
    budget = RecoveryBudget()
    for _ in range(10):
        assert budget.verify("same", lambda: {"id": 1}) == {"id": 1}
        def broken():
            raise RuntimeError("synthetic-service-error")
        with pytest.raises(RuntimeError):
            budget.verify("same", broken)
    assert budget.verify("same", lambda: {"id": 1}) == {"id": 1}
    assert not budget.addresses


def test_recovery_block_lasts_full_window_from_fifth_failure(monkeypatch):
    from server.sli.access import owner_recovery
    from server.sli.access.login_throttle import LoginThrottled
    clock = [0.0]
    monkeypatch.setattr(owner_recovery.time, "monotonic", lambda: clock[0])
    budget = owner_recovery.RecoveryBudget()
    for _ in range(4):
        budget.verify("same", lambda: None)
    clock[0] = 899
    budget.verify("same", lambda: None)
    clock[0] = 900
    with pytest.raises(LoginThrottled) as caught:
        budget.verify("same", lambda: {"id": 1})
    assert caught.value.retry_after == 899
    clock[0] = 1799
    assert budget.verify("same", lambda: {"id": 1}) == {"id": 1}


def test_recovery_address_table_is_bounded_without_evicting_active_limits(monkeypatch):
    from server.sli.access import owner_recovery
    from server.sli.access.login_throttle import LoginThrottled
    clock = [0.0]
    monkeypatch.setattr(owner_recovery.time, "monotonic", lambda: clock[0])
    budget = owner_recovery.RecoveryBudget()
    for _ in range(5):
        budget.verify("blocked", lambda: None)
    for i in range(4095):
        budget.verify(str(i), lambda: None)
    with pytest.raises(LoginThrottled):
        budget.verify("overflow", lambda: pytest.fail("full table must fail closed"))
    with pytest.raises(LoginThrottled):
        budget.verify("blocked", lambda: {"id": 1})
    assert len(budget.addresses) == 4096
    clock[0] = 900
    assert budget.verify("overflow", lambda: {"id": 1}) == {"id": 1}

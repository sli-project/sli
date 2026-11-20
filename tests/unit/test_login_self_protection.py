"""Hermetic budget/cache/proxy tests; no database, installed service or network."""
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.api import proxy
from server.sli.access.login_throttle import AccountAttempt, LoginThrottled
from server.sli.core.messages import response_messages
from server.sli.sigma import cache_policy


class Ledger:
    """Transaction boundary double; PostgreSQL SQL is exercised separately."""

    def __init__(self):
        self.rows = {}
        self.now = datetime(2026, 10, 29, tzinfo=timezone.utc)
        self.acquired = True
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "pg_try_advisory" in sql:
            self.result = {"acquired": self.acquired}
        elif "clock_timestamp" in sql:
            self.result = {"now": self.now}
        elif sql.startswith("select failures"):
            self.result = self.rows.get(params[0])
        elif "insert into auth_login_throttle" in sql:
            key, failures, started, blocked = params
            self.rows[key] = {"failures": failures, "window_started_at": started, "blocked_until": blocked}
        elif sql == "delete from auth_login_throttle where account_key=%s":
            self.rows.pop(params[0], None)

    def fetchone(self):
        return self.result


def test_account_budget_survives_new_attempts_and_source_rotation():
    ledger = Ledger()
    # Each AccountAttempt models another request/process. IP is deliberately
    # absent from the key, including case/whitespace variations of the name.
    for name in ["Admin", "ADMIN", " admin ", "Admin", "admin"]:
        AccountAttempt(ledger, name).failed(ledger)
    assert len(ledger.rows) == 1
    with pytest.raises(LoginThrottled) as caught:
        AccountAttempt(ledger, "ADMIN")
    assert caught.value.retry_after == 30
    ledger.now += timedelta(seconds=30)
    AccountAttempt(ledger, "admin").failed(ledger)
    with pytest.raises(LoginThrottled) as caught:
        AccountAttempt(ledger, "admin")
    assert caught.value.retry_after == 60
    assert all("admin" not in str(params).lower() for _, params in ledger.calls)


def test_success_resets_only_the_account_and_window_expires():
    ledger = Ledger()
    for name in ["admin"] * 4 + ["other"]:
        AccountAttempt(ledger, name).failed(ledger)
    AccountAttempt(ledger, "admin").succeeded(ledger)
    assert len(ledger.rows) == 1
    AccountAttempt(ledger, "admin").failed(ledger)
    assert sorted(row["failures"] for row in ledger.rows.values()) == [1, 1]
    ledger.now += timedelta(seconds=901)
    AccountAttempt(ledger, "admin").failed(ledger)
    assert all(row["failures"] == 1 for row in ledger.rows.values())


def test_delay_is_bounded_and_rejected_requests_do_not_extend_it():
    ledger = Ledger()
    for _ in range(15):
        attempt = AccountAttempt(ledger, "missing-account")
        attempt.failed(ledger)
        row = ledger.rows[attempt.key]
        if row["blocked_until"]:
            delay = (row["blocked_until"] - ledger.now).total_seconds()
            assert 30 <= delay <= 300
            frozen = dict(row)
            with pytest.raises(LoginThrottled):
                AccountAttempt(ledger, "missing-account")
            assert ledger.rows[attempt.key] == frozen
            ledger.now = row["blocked_until"]


def test_platform_owner_can_retry_at_expiry_and_success_clears_maximum_block():
    ledger = Ledger()
    delays = []
    for _ in range(9):
        attempt = AccountAttempt(ledger, "platform-owner")
        attempt.failed(ledger)
        row = ledger.rows[attempt.key]
        if row["blocked_until"]:
            delays.append((row["blocked_until"] - ledger.now).total_seconds())
            ledger.now = row["blocked_until"]
    assert delays == [30, 60, 120, 240, 300]
    blocked = dict(row)
    ledger.now -= timedelta(seconds=1)
    for _ in range(10):
        with pytest.raises(LoginThrottled) as caught:
            AccountAttempt(ledger, " PLATFORM-OWNER ")
        assert caught.value.retry_after == 1
        assert ledger.rows[attempt.key] == blocked
    ledger.now += timedelta(seconds=1)
    AccountAttempt(ledger, "platform-owner").succeeded(ledger)
    assert ledger.rows == {}
    assert AccountAttempt(ledger, "platform-owner").failures == 0


def test_inflight_account_check_cannot_queue_more_password_verifications():
    ledger = Ledger()
    ledger.acquired = False
    with pytest.raises(LoginThrottled) as caught:
        AccountAttempt(ledger, "admin")
    assert caught.value.retry_after == 1
    assert len(ledger.calls) == 1


@pytest.mark.parametrize("state", ["active", "unknown", "inactive", "owner_setup"])
def test_password_entry_point_counts_failures_and_resets_after_success(monkeypatch, state):
    pytest.importorskip("argon2", reason="argon2 is required by the real password entry point")
    from server.sli.access import auth

    monkeypatch.setenv("SLI_OWNER_SETUP", "1" if state == "owner_setup" else "0")
    username = "platform-owner" if state == "owner_setup" else "admin"

    class PasswordLedger(Ledger):
        def execute(self, sql, params=()):
            if sql.startswith("select id, username, password_hash"):
                self.result = {"id": 1, "username": username, "password_hash": "synthetic",
                               "is_active": state != "inactive", "role": "admin", "last_login_at": None} if state != "unknown" else None
            else:
                super().execute(sql, params)

    ledger = PasswordLedger()
    monkeypatch.setattr(auth, "_connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(ledger))))
    monkeypatch.setattr(auth, "PASSWORD_HASHER", SimpleNamespace(verify=lambda *_: False, check_needs_rehash=lambda *_: False))
    for _ in range(5):
        assert auth.authenticate_password(username, "synthetic") is None
    with pytest.raises(LoginThrottled):
        auth.authenticate_password(username.upper(), "synthetic")
    ledger.now += timedelta(seconds=30)
    if state == "active":
        monkeypatch.setattr(auth.PASSWORD_HASHER, "verify", lambda *_: True)
        assert auth.authenticate_password(username, "synthetic")["id"] == 1
        assert ledger.rows == {}
    else:
        monkeypatch.setattr(auth.PASSWORD_HASHER, "verify", lambda *_: pytest.fail("ineligible account must not verify a password"))
        assert auth.authenticate_password(username, "synthetic") is None
        with pytest.raises(LoginThrottled) as caught:
            auth.authenticate_password(username, "synthetic")
        assert caught.value.retry_after == 60


@pytest.mark.parametrize("peer,trusted", [("203.0.113.5", ()), ("203.0.113.5", ("192.0.2.2",))])
@pytest.mark.parametrize("header", ["X-Forwarded-For", "X-Real-IP"])
def test_untrusted_address_spoof_is_ignored(monkeypatch, peer, trusted, header):
    monkeypatch.setenv("ADLOG_TRUSTED_PROXIES", ",".join(trusted))
    ctx = proxy.request_context(peer, {header: "198.51.100.9"}, tls=True, trusted_proxies=proxy.load_trusted_proxies())
    assert ctx.client_ip == peer


def test_no_proxy_is_trusted_by_default(monkeypatch):
    monkeypatch.delenv("ADLOG_TRUSTED_PROXIES", raising=False)
    assert proxy.load_trusted_proxies() == ()


@pytest.mark.parametrize("xff,expected", [(None, "198.51.100.9"), ("198.51.100.8", "198.51.100.8"), ("invalid", "192.0.2.2")])
def test_real_ip_is_trusted_fallback_only(monkeypatch, xff, expected):
    monkeypatch.setenv("ADLOG_TRUSTED_PROXIES", "192.0.2.2")
    headers = {"X-Real-IP": "198.51.100.9"}
    if xff is not None:
        headers["X-Forwarded-For"] = xff
    ctx = proxy.request_context("192.0.2.2", headers, tls=True, trusted_proxies=proxy.load_trusted_proxies())
    assert ctx.client_ip == expected


def test_duplicate_forwarding_headers_cannot_select_address(monkeypatch):
    monkeypatch.setenv("ADLOG_TRUSTED_PROXIES", "192.0.2.2")
    headers = Message()
    for name in ["X-Forwarded-For", "X-Real-IP"]:
        headers[name] = "198.51.100.9"
        headers[name] = "198.51.100.8"
    assert proxy.request_context("192.0.2.2", headers, tls=True, trusted_proxies=proxy.load_trusted_proxies()).client_ip == "192.0.2.2"


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_generic_account_lock_message_uses_existing_ru_en_catalog(locale):
    payload = response_messages({"error": "login_temporarily_locked", "retry_after_seconds": 30}, locale, login=True)
    assert payload["message"]["code"] == "login.error.retryAfter"
    assert payload["message"]["params"] == {"seconds": 30}
    assert "30" in payload["message"]["text"]
    assert payload["message"]["text"].startswith("Слишком много" if locale == "ru" else "Too many")


def test_windows_sigma_cache_never_opens_old_pickle_directory(monkeypatch):
    modules = [SimpleNamespace(__name__="sigma.data." + name, _cache=None, _get_cache=lambda: pytest.fail("unsafe cache opened"),
                               set_cache_dir=lambda _: pytest.fail("disk cache opened")) for name in ("mitre_attack", "mitre_d3fend")]
    monkeypatch.setattr(cache_policy, "_prepared", False)
    monkeypatch.setattr(cache_policy, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(cache_policy.importlib, "import_module", lambda name: next(module for module in modules if module.__name__ == name))
    cache_policy.prepare_sigma_caches()
    cache = modules[0]._get_cache()
    assert cache.get("old") is None
    assert cache.set("data", {"tactics": ["example"]})
    value = cache.get("data")
    value["tactics"].clear()
    assert cache.get("data") == {"tactics": ["example"]}
    with pytest.raises(TypeError):
        cache.set("code", object())
    cache.clear()
    assert cache.get("data") is None


@pytest.mark.skipif(cache_policy.os.name != "posix", reason="POSIX service permissions")
def test_sigma_cache_directories_are_exclusive_and_private():
    import os
    import stat

    with cache_policy._private_directory() as first, cache_policy._private_directory() as second:
        assert first != second
        info = os.lstat(first)
        assert info.st_uid == os.geteuid()
        assert stat.S_IMODE(info.st_mode) == 0o700
        assert not Path(first).is_symlink()


@pytest.mark.parametrize("mode,uid", [(0o120777, 0), (0o40777, 0), (0o41777, 1001)])
def test_sigma_refuses_symlink_or_attacker_controlled_temp_parent(monkeypatch, mode, uid):
    monkeypatch.setattr(cache_policy.os, "lstat", lambda _: SimpleNamespace(st_mode=mode, st_uid=uid))
    monkeypatch.setattr(cache_policy.tempfile, "TemporaryDirectory", lambda **_: pytest.fail("unsafe parent used"))
    with pytest.raises(RuntimeError, match="unsafe_sigma_cache_parent"):
        cache_policy._private_directory()


def test_pinned_sigma_data_cache_hooks_when_dependency_is_installed():
    # Imports only: do not access lazy dataset attributes or open an old cache.
    pytest.importorskip("sigma.data.mitre_attack", reason="Optional pinned pySigma not installed")
    import importlib

    for name in ("mitre_attack", "mitre_d3fend"):
        module = importlib.import_module("sigma.data." + name)
        assert callable(vars(module).get("_get_cache"))
        assert callable(vars(module).get("set_cache_dir"))


def test_migration_299_is_isolated_and_runtime_schema_is_guarded():
    sql = Path("config/postgres_migrations/299_login_account_throttle.sql").read_text("utf-8")
    assert "values(299,'login_account_throttle')" in sql
    assert "version=280 and name='service_account_origin'" in sql
    assert "version>=299" in sql
    assert "pg_advisory_xact_lock" in sql and sql.rstrip().endswith("commit;")
    assert "grant select, insert, update, delete" in sql
    assert "from public" in sql
    assert "password" not in sql and "username" not in sql
    guard = Path("server/sli/access/auth.py").read_text("utf-8")
    assert 'require_table_columns("auth_login_throttle"' in guard
    assert "minimum_schema_version=299" in guard

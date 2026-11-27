"""Hermetic budget/cache/proxy tests; no database, installed service or network."""
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest



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


def test_pinned_sigma_data_cache_hooks_when_dependency_is_installed():
    # Imports only: do not access lazy dataset attributes or open an old cache.
    pytest.importorskip("sigma.data.mitre_attack", reason="Optional pinned pySigma not installed")
    import importlib

    for name in ("mitre_attack", "mitre_d3fend"):
        module = importlib.import_module("sigma.data." + name)
        assert callable(vars(module).get("_get_cache"))
        assert callable(vars(module).get("set_cache_dir"))

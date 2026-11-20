"""Durable account login budget; names and passwords are never persisted here."""
from __future__ import annotations

import hashlib
import math
from datetime import timedelta

FAILURE_LIMIT = 5
WINDOW_SECONDS = 900
MAX_DELAY_SECONDS = 300


class LoginThrottled(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = max(1, retry_after)
        super().__init__("login_temporarily_locked")


class AccountAttempt:
    """Hold a PostgreSQL transaction lock through verification and accounting.

    Contenders fail immediately instead of queuing expensive password checks.
    The caller must commit failures too; never raise for an invalid password.
    """

    def __init__(self, cur, username: str):
        self.key = hashlib.sha256(username.strip().lower().encode("utf-8")).hexdigest()
        # Domain-separated 64-bit advisory key, shared by all server processes.
        lock = int.from_bytes(hashlib.sha256(("login:" + self.key).encode()).digest()[:8], "big", signed=True)
        cur.execute("select pg_try_advisory_xact_lock(%s) as acquired", (lock,))
        if not cur.fetchone()["acquired"]:
            raise LoginThrottled(1)
        cur.execute("select clock_timestamp() as now")
        self.now = cur.fetchone()["now"]
        cur.execute("select failures, window_started_at, blocked_until from auth_login_throttle where account_key=%s for update", (self.key,))
        row = cur.fetchone()
        self.failures = 0
        self.started = self.now
        if row:
            if row["blocked_until"] and row["blocked_until"] > self.now:
                raise LoginThrottled(math.ceil((row["blocked_until"] - self.now).total_seconds()))
            if row["window_started_at"] > self.now - timedelta(seconds=WINDOW_SECONDS):
                self.failures = row["failures"]
                self.started = row["window_started_at"]

    def failed(self, cur):
        failures = min(self.failures + 1, FAILURE_LIMIT + 4)
        delay = min(MAX_DELAY_SECONDS, 30 * 2 ** (failures - FAILURE_LIMIT)) if failures >= FAILURE_LIMIT else 0
        cur.execute("""
            insert into auth_login_throttle(account_key, failures, window_started_at, blocked_until)
            values (%s,%s,%s,%s)
            on conflict(account_key) do update set failures=excluded.failures,
                window_started_at=excluded.window_started_at, blocked_until=excluded.blocked_until
        """, (self.key, failures, self.started, self.now + timedelta(seconds=delay) if delay else None))
        # Bound cleanup work. Never delete a row another login is using.
        cur.execute("""
            delete from auth_login_throttle where account_key in (
                select account_key from auth_login_throttle
                where window_started_at < %s and (blocked_until is null or blocked_until <= %s)
                order by window_started_at limit 64 for update skip locked
            )
        """, (self.now - timedelta(seconds=WINDOW_SECONDS), self.now))

    def succeeded(self, cur):
        cur.execute("delete from auth_login_throttle where account_key=%s", (self.key,))

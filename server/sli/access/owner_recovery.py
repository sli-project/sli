"""Host-console owner recovery. No HTTP issuance path; never persist the code."""
from __future__ import annotations

import os
import secrets
import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from server.sli.access.login_throttle import LoginThrottled


@dataclass
class _AddressBudget:
    failures: list[float] = field(default_factory=list)
    pending: int = 0
    blocked_until: float = 0


class RecoveryBudget:
    """Bounded process-local recovery budget, using the resolved login address.

    Reserve in-flight checks too; perform DB/crypto outside the shared lock.
    Only completed credential failures count towards the 15-minute block.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.addresses: OrderedDict[str, _AddressBudget] = OrderedDict()

    def verify(self, address: str, authenticate):
        with self.lock:
            now = time.monotonic()
            for _ in range(64):
                if not self.addresses:
                    break
                oldest = next(iter(self.addresses.values()))
                if oldest.pending or oldest.blocked_until > now or (oldest.failures and oldest.failures[-1] > now - 900):
                    break
                self.addresses.popitem(last=False)
            state = self.addresses.get(address)
            if state is None:
                if len(self.addresses) >= 4096:
                    raise LoginThrottled(900)
                state = self.addresses[address] = _AddressBudget()
            if state.blocked_until > now:
                raise LoginThrottled(math.ceil(state.blocked_until - now))
            state.failures = [stamp for stamp in state.failures if stamp > now - 900]
            if len(state.failures) + state.pending >= 5:
                raise LoginThrottled(1)
            state.pending += 1
            self.addresses.move_to_end(address)
        completed = False
        principal = None
        try:
            principal = authenticate()
            completed = True
            return principal
        finally:
            with self.lock:
                state.pending -= 1
                now = time.monotonic()
                state.failures = [stamp for stamp in state.failures if stamp > now - 900]
                if completed and not principal:
                    state.failures.append(now)
                    if len(state.failures) >= 5:
                        state.blocked_until = now + 900
                self.addresses.move_to_end(address)
                if not state.failures and not state.pending:
                    del self.addresses[address]


recovery_budget = RecoveryBudget()


def require_host_root() -> None:
    if getattr(os, "geteuid", lambda: -1)() != 0:
        raise PermissionError("host_root_required")


def issue_owner_recovery_code(username: str) -> str:
    from server.sli.access import auth

    require_host_root()
    auth.ensure_auth_schema()
    code = None
    with auth._connect() as conn, conn.cursor() as cur:
        cur.execute("""
            select u.id from auth_users u
            where lower(u.username)=lower(%s) and u.is_active=true
              and exists(select 1 from access_platform_owners o where o.user_id=u.id)
        """, (str(username or "").strip(),))
        user = cur.fetchone()
        if user:
            code = secrets.token_urlsafe(32)
            cur.execute("""
                insert into auth_owner_recovery(user_id, code_hash, expires_at)
                values (%s,%s,clock_timestamp()+interval '10 minutes')
                on conflict(user_id) do update set code_hash=excluded.code_hash,
                    expires_at=excluded.expires_at
            """, (user["id"], auth._digest(code)))
        auth._audit(cur, actor_type="local_operator", actor_id=None,
                    action=f"owner_recovery_issued:{user['id']}" if user else "owner_recovery_issued",
                    outcome="ok" if user else "failed")
    # Commit the failed issuance audit before raising.
    if code is None:
        raise ValueError("active_platform_owner_required")
    return code


def authenticate_owner(cur, username: str, password: str, code: str,
                       remote_address: str | None = None) -> dict | None:
    from argon2.exceptions import InvalidHashError, VerificationError

    from server.sli.access import auth

    cur.execute("""
        select u.id, u.username, u.password_hash, u.role from auth_users u
        where lower(u.username)=lower(%s) and u.is_active=true
          and exists(select 1 from access_platform_owners o where o.user_id=u.id)
    """, (str(username or "").strip(),))
    user = cur.fetchone()
    principal = None
    if user and code and len(code) <= 128:
        digest = auth._digest(code)
        cur.execute("""
            select user_id from auth_owner_recovery
            where user_id=%s and code_hash=%s and expires_at>clock_timestamp()
        """, (user["id"], digest))
        if cur.fetchone():
            try:
                valid = auth.PASSWORD_HASHER.verify(str(user["password_hash"]), password or "")
            except (VerificationError, InvalidHashError):
                valid = False
            if valid:
                # Conditional DELETE is the single-use arbitration across HTTP
                # processes. Recheck wall-clock expiry after Argon2; concurrent
                # consumers/reissuance cannot consume the same code twice.
                cur.execute("""
                    delete from auth_owner_recovery
                    where user_id=%s and code_hash=%s and expires_at>clock_timestamp()
                    returning user_id
                """, (user["id"], digest))
                if cur.fetchone():
                    cur.execute("update auth_users set previous_login_at=last_login_at, last_login_at=now() where id=%s", (user["id"],))
                    principal = {"type": "session", "id": int(user["id"]),
                                 "username": str(user["username"]), "role": str(user["role"])}
    auth._audit(cur, actor_type="session" if principal else "anonymous",
                actor_id=principal["id"] if principal else None,
                action="owner_recovery_login", outcome="ok" if principal else "failed",
                remote_address=remote_address)
    return principal

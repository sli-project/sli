"""Local authentication for the web UI and external API.

Secrets never reach the database in plaintext: passwords use Argon2id and
sessions/API keys are persisted only as SHA-256 digests. Authentication is
enabled by default; unauthenticated operation requires an explicit startup
opt-out for isolated diagnostics.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from server.sli.access.login_throttle import AccountAttempt

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}
ROLE_LABELS = {
    "viewer": "ИБ",
    "operator": "ИТ",
    "admin": "Администратор",
}
SESSION_COOKIE = "adlog_session"
SESSION_HOURS = 12
REMEMBER_SESSION_HOURS = 24 * 14
PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)


def auth_required() -> bool:
    value = os.getenv("ADLOG_AUTH_REQUIRED", "1").strip().lower()
    if value in {"", "1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError("invalid ADLOG_AUTH_REQUIRED setting")


def auth_opt_out() -> bool:
    return os.getenv("ADLOG_ALLOW_UNAUTHENTICATED", "0").strip().lower() in {"1", "true", "yes", "on"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_username(username: str) -> str:
    cleaned = str(username or "").strip()
    if not USERNAME_RE.fullmatch(cleaned):
        raise ValueError("username_must_be_3_to_64_characters")
    return cleaned


def _valid_role(role: str) -> str:
    cleaned = str(role or "").strip().lower()
    if cleaned not in ROLE_RANK:
        raise ValueError("invalid_role")
    return cleaned


def _connect():
    from server.sli.core.postgres_runtime_pipeline import connect
    return connect()


def ensure_auth_schema() -> None:
    """Verify the versioned local-auth schema without executing runtime DDL."""
    from server.sli.ops.postgres_schema_guard import require_table_columns

    contracts = {
        "auth_users": ("id", "username", "password_hash", "role", "is_active", "created_at", "updated_at", "last_login_at"),
        "auth_sessions": ("id", "user_id", "token_hash", "expires_at", "revoked_at", "created_at", "last_used_at"),
        "auth_api_keys": ("id", "key_prefix", "key_hash", "label", "role", "is_active", "expires_at", "created_at", "last_used_at", "revoked_at"),
        "auth_audit": ("id", "actor_type", "actor_id", "action", "outcome", "remote_address", "created_at"),
    }
    for table, columns in contracts.items():
        require_table_columns(table, columns, minimum_schema_version=14)
    require_table_columns("auth_users", ("previous_login_at",), minimum_schema_version=223)
    require_table_columns("auth_users", ("is_service",), minimum_schema_version=280)
    require_table_columns("auth_login_throttle", ("account_key", "failures", "window_started_at", "blocked_until"), minimum_schema_version=299)
    require_table_columns("auth_owner_recovery", ("user_id", "code_hash", "expires_at"), minimum_schema_version=300)


def _audit(cur: Any, *, actor_type: str, actor_id: int | None, action: str, outcome: str = "ok",
           remote_address: str | None = None) -> None:
    cur.execute(
        "insert into auth_audit(actor_type, actor_id, action, outcome, remote_address) "
        "values (%s,%s,%s,%s,%s) returning id,created_at",
        (actor_type, actor_id, action[:200], outcome[:40], remote_address),
    )
    audit_row = dict(cur.fetchone() or {})
    from server.sli.sources.administrative_activity_producer import (
        mirror_auth_audit_if_enabled,
    )

    mirror_auth_audit_if_enabled(
        cursor=cur,
        audit_id=int(audit_row.get("id") or 0),
        created_at=audit_row.get("created_at"),
        actor_type=actor_type,
        actor_id=actor_id,
        action=action[:200],
        outcome=outcome[:40],
        remote_address=remote_address,
    )


def record_auth_audit(*, actor_type: str, actor_id: int | None, action: str, outcome: str = "ok",
                      remote_address: str | None = None) -> None:
    """Append a safe authentication/audit entry without carrying secrets."""
    ensure_auth_schema()
    with _connect() as conn, conn.cursor() as cur:
        _audit(cur, actor_type=actor_type, actor_id=actor_id, action=action, outcome=outcome,
               remote_address=remote_address)


def create_user(*, username: str, password: str, role: str = "admin", actor_id: int | None = None,
                actor_type: str = "session",
                remote_address: str | None = None, is_service: bool = False) -> dict[str, Any]:
    # Origin metadata only: never used to grant or deny authentication/access.
    if type(is_service) is not bool:
        raise ValueError("invalid_service_account_marker")
    username = _valid_username(username)
    role = _valid_role(role)
    if len(password or "") < 12:
        raise ValueError("password_must_be_at_least_12_characters")
    ensure_auth_schema()
    password_hash = PASSWORD_HASHER.hash(password)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """insert into auth_users(username, password_hash, role, is_service) values (%s,%s,%s,%s)
                   returning id, username, role, is_active, created_at""",
            (username, password_hash, role, is_service),
        )
        result = dict(cur.fetchone() or {})
        _audit(cur, actor_type=actor_type, actor_id=actor_id, action=f"user_created:{result['id']}:{result['username']}", remote_address=remote_address)
        return result


def list_users() -> list[dict[str, Any]]:
    """Return safe user-management data; password hashes are never selected."""
    ensure_auth_schema()
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("""
                select u.id, u.username, u.role, u.is_active, u.created_at, u.updated_at, u.last_login_at,
                       (u.is_service or exists (select 1 from auth_api_keys k where k.report_subject_id = u.id)) as is_service
                from auth_users u
                order by lower(u.username), u.id
            """)
        return [dict(row) for row in cur.fetchall()]


def update_user(*, user_id: int, role: str | None = None, is_active: bool | None = None,
                actor_id: int | None = None, actor_type: str = "session",
                remote_address: str | None = None) -> dict[str, Any]:
    """Change only a role and/or active flag, preserving the last active admin."""
    if role is None and is_active is None:
        raise ValueError("user_update_required")
    clean_role = _valid_role(role) if role is not None else None
    ensure_auth_schema()
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("select id, username, role, is_active from auth_users where id=%s", (int(user_id),))
        current = dict(cur.fetchone() or {})
        if not current:
            raise ValueError("user_not_found")
        next_role = clean_role or str(current["role"])
        next_active = bool(current["is_active"]) if is_active is None else bool(is_active)
        if actor_type == "session" and actor_id is not None and int(user_id) == int(actor_id) and not next_active:
            raise ValueError("cannot_disable_current_user")
        if current["role"] == "admin" and current["is_active"] and (next_role != "admin" or not next_active):
            # Lock all active administrator rows before deciding.  Without
            # this, two concurrent demotions could each observe the other
            # admin and leave the system with no administrator at all.
            cur.execute("select id from auth_users where role='admin' and is_active=true order by id for update")
            remaining_admins = {int(row["id"]) for row in cur.fetchall()} - {int(user_id)}
            if not remaining_admins:
                raise ValueError("last_active_admin_required")
        cur.execute("""
                update auth_users set role=%s, is_active=%s, updated_at=now()
                where id=%s
                returning id, username, role, is_active, created_at, updated_at, last_login_at
            """, (next_role, next_active, int(user_id)))
        result = dict(cur.fetchone() or {})
        if not next_active:
            cur.execute("update auth_sessions set revoked_at=now() where user_id=%s and revoked_at is null", (int(user_id),))
        _audit(cur, actor_type=actor_type, actor_id=actor_id, action=f"user_updated:{result['id']}:{result['username']}", remote_address=remote_address)
        from server.sli.access.session_access_cache import invalidate_session

        invalidate_session(user_id=int(user_id))
        return result


def reset_user_password(*, user_id: int, password: str, actor_id: int | None = None,
                        actor_type: str = "session", remote_address: str | None = None) -> dict[str, Any]:
    if len(password or "") < 12:
        raise ValueError("password_must_be_at_least_12_characters")
    ensure_auth_schema()
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("select id, username, is_active from auth_users where id=%s for update", (int(user_id),))
        user = dict(cur.fetchone() or {})
        if not user:
            raise ValueError("user_not_found")
        if not user["is_active"]:
            raise ValueError("cannot_reset_password_for_disabled_user")
        cur.execute("update auth_users set password_hash=%s, updated_at=now() where id=%s", (PASSWORD_HASHER.hash(password), int(user_id)))
        cur.execute("update auth_sessions set revoked_at=now() where user_id=%s and revoked_at is null", (int(user_id),))
        _audit(cur, actor_type=actor_type, actor_id=actor_id, action=f"user_password_reset:{user['id']}:{user['username']}", remote_address=remote_address)
        return {"id": int(user["id"]), "username": str(user["username"]), "sessions_revoked": True}


def issue_api_key(*, label: str, role: str = "viewer", expires_at: datetime | None = None,
                  actor_id: int | None = None, actor_type: str = "session",
                  remote_address: str | None = None) -> tuple[dict[str, Any], str]:
    role = _valid_role(role)
    cleaned_label = str(label or "").strip()
    if not cleaned_label or len(cleaned_label) > 120:
        raise ValueError("api_key_label_required")
    ensure_auth_schema()
    token = f"adl_{secrets.token_urlsafe(32)}"
    prefix = token[:12]
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """insert into auth_api_keys(key_prefix, key_hash, label, role, expires_at)
                   values (%s,%s,%s,%s,%s)
                   returning id, key_prefix, label, role, expires_at, created_at""",
            (prefix, _digest(token), cleaned_label, role, expires_at),
        )
        result = dict(cur.fetchone() or {})
        _audit(cur, actor_type=actor_type, actor_id=actor_id, action=f"api_key_issued:{result['id']}:{result['key_prefix']}", remote_address=remote_address)
        return result, token


def list_api_keys() -> list[dict[str, Any]]:
    ensure_auth_schema()
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("""
                select id, key_prefix, label, role, is_active, expires_at, created_at, last_used_at, revoked_at
                from auth_api_keys order by id desc
            """)
        return [dict(row) for row in cur.fetchall()]


def revoke_api_key(key_id: int, *, actor_id: int | None = None, actor_type: str = "session",
                   remote_address: str | None = None) -> bool:
    ensure_auth_schema()
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("update auth_api_keys set revoked_at=now(), is_active=false where id=%s and revoked_at is null returning key_prefix", (key_id,))
        row = dict(cur.fetchone() or {})
        if row:
            _audit(cur, actor_type=actor_type, actor_id=actor_id, action=f"api_key_revoked:{key_id}:{row['key_prefix']}", remote_address=remote_address)
        return bool(row)


def authenticate_password(username: str, password: str, *, recovery_code: str | None = None,
                          remote_address: str | None = None) -> dict[str, Any] | None:
    with _connect() as conn, conn.cursor() as cur:
        if recovery_code is not None:
            from server.sli.access.owner_recovery import authenticate_owner

            return authenticate_owner(cur, username, password, recovery_code, remote_address)
        attempt = AccountAttempt(cur, username)
        cur.execute("select id, username, password_hash, role, is_active, last_login_at from auth_users where lower(username)=lower(%s)", (str(username or "").strip(),))
        row = dict(cur.fetchone() or {})
        if not row or not row.get("is_active"):
            attempt.failed(cur)
            return None
        if (os.getenv("SLI_OWNER_SETUP") == "1" and row.get("username") == "platform-owner"
                and row.get("last_login_at") is None):
            attempt.failed(cur)
            return None  # The bootstrap code can only set a new password.
        try:
            valid = PASSWORD_HASHER.verify(str(row["password_hash"]), password or "")
        except (VerificationError, InvalidHashError):
            valid = False
        if not valid:
            attempt.failed(cur)
            return None
        if PASSWORD_HASHER.check_needs_rehash(str(row["password_hash"])):
            cur.execute("update auth_users set password_hash=%s, updated_at=now() where id=%s", (PASSWORD_HASHER.hash(password), row["id"]))
        cur.execute("update auth_users set previous_login_at=last_login_at, last_login_at=now() where id=%s", (row["id"],))
        attempt.succeeded(cur)
        return {"type": "session", "id": int(row["id"]), "username": str(row["username"]), "role": str(row["role"])}


def owner_code_current(issued_at: datetime | None, checked_at: datetime) -> bool:
    """Both timestamps come from PostgreSQL; null or future issuance fails closed."""
    return issued_at is not None and checked_at - timedelta(hours=24) < issued_at <= checked_at


def initial_owner_setup_pending() -> bool:
    """A stale process flag cannot reopen activation after the owner is claimed."""
    if os.getenv("SLI_OWNER_SETUP") != "1":
        return False
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("""select u.id, u.username, u.role, u.is_active, u.last_login_at
            from auth_users u join access_platform_owners o on o.user_id=u.id
            where u.username='platform-owner' and o.owner_key='primary'""")
        row = dict(cur.fetchone() or {})
        return bool(row.get('id') and row.get('is_active') and row.get('role') == 'admin'
                    and row.get('username') == 'platform-owner' and row.get('last_login_at') is None)


class InitialOwnerPasswordError(ValueError):
    """The supplied owner password fails the activation policy."""


def claim_initial_owner(code: str, password: str, *, remote_address: str | None = None) -> dict[str, Any] | None:
    """Consume the fresh native owner's bootstrap credential in one transaction.

    Row locking serializes simultaneous claims. Changing its hash consumes the
    code; last_login_at closes activation permanently, including after a reset.
    No admin DB credential or secret file is delivered to the API process.
    """
    if os.getenv("SLI_OWNER_SETUP") != "1":
        return None
    if not isinstance(password, str) or not 12 <= len(password) <= 4096 or '\x00' in password or password == code:
        raise InitialOwnerPasswordError("password_must_be_new_and_12_to_4096_characters")
    if not isinstance(code, str) or not 12 <= len(code) <= 4096:
        return None
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("""select u.id, u.username, u.password_hash, u.role, u.is_active, u.last_login_at,
                u.updated_at, clock_timestamp() as checked_at
                from auth_users u join access_platform_owners o on o.user_id=u.id
                where u.username='platform-owner' and o.owner_key='primary' for update of u""")
        row = dict(cur.fetchone() or {})
        if (not row.get('id') or not row.get('is_active') or row.get('role') != 'admin'
                or row.get('username') != 'platform-owner' or row.get('last_login_at') is not None
                or not owner_code_current(row.get('updated_at'), row['checked_at'])):
            return None
        try:
            PASSWORD_HASHER.verify(str(row['password_hash']), code)
        except (VerificationError, InvalidHashError):
            return None
        cur.execute("update auth_users set password_hash=%s, updated_at=now(), last_login_at=now() where id=%s",
                    (PASSWORD_HASHER.hash(password), row['id']))
        _audit(cur, actor_type='session', actor_id=int(row['id']), action='initial_owner_claimed',
               remote_address=remote_address)
        return {'type': 'session', 'id': int(row['id']), 'username': 'platform-owner', 'role': 'admin'}


def previous_login(principal: Mapping[str, Any]) -> str | None:
    """A missing baseline (first login, local access or API key) is unknown."""
    if principal.get("type") != "session" or principal.get("id") is None:
        return None
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("select previous_login_at from auth_users where id=%s", (int(principal["id"]),))
        value = (cur.fetchone() or {}).get("previous_login_at")
        return value.isoformat() if value else None


def issue_session(principal: Mapping[str, Any], *, remember: bool = False) -> str:
    ensure_auth_schema()
    token = secrets.token_urlsafe(32)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            "insert into auth_sessions(user_id, token_hash, expires_at) values (%s,%s,%s)",
            (
                int(principal["id"]), _digest(token),
                _utc_now() + timedelta(hours=REMEMBER_SESSION_HOURS if remember else SESSION_HOURS),
            ),
        )
    return token


def revoke_session(token: str | None) -> None:
    if not token:
        return
    ensure_auth_schema()
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("update auth_sessions set revoked_at=now() where token_hash=%s and revoked_at is null", (_digest(token),))
    from server.sli.access.session_access_cache import invalidate_session

    invalidate_session(token)


def revoke_all_sessions() -> int:
    """Emergency global logout; normal server restarts preserve valid sessions."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("update auth_sessions set revoked_at=now() where revoked_at is null")
        from server.sli.access.session_access_cache import invalidate_session

        invalidate_session()
        return int(cur.rowcount)


def session_token_from_cookie(cookie_header: str | None) -> str | None:
    cookie = SimpleCookie()
    cookie.load(cookie_header or "")
    item = cookie.get(SESSION_COOKIE)
    return item.value if item else None


def authenticate_session(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("""
                select u.id, u.username, u.role, s.id as session_id
                from auth_sessions s
                join auth_users u on u.id=s.user_id
                where s.token_hash=%s and s.revoked_at is null and s.expires_at > now() and u.is_active=true
            """, (_digest(token),))
        row = dict(cur.fetchone() or {})
        if row:
            cur.execute(
                """
                    update auth_sessions set last_used_at=now()
                    where id=%s
                      and (last_used_at is null or last_used_at < now()-interval '5 minutes')
                    """,
                (int(row["session_id"]),),
            )
            return {"type": "session", "id": int(row["id"]), "username": str(row["username"]), "role": str(row["role"])}
    return None


def authenticate_api_key(token: str | None) -> dict[str, Any] | None:
    if not token or not token.startswith("adl_"):
        return None
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("""
                select id, key_prefix, label, role, report_subject_id from auth_api_keys k
                where key_hash=%s and is_active=true and revoked_at is null
                  and (expires_at is null or expires_at > now())
                  and (report_subject_id is null or exists(select 1 from auth_users u where u.id=k.report_subject_id and u.is_active))
            """, (_digest(token),))
        row = dict(cur.fetchone() or {})
        if row:
            cur.execute(
                """
                    update auth_api_keys set last_used_at=now()
                    where id=%s
                      and (last_used_at is null or last_used_at < now()-interval '5 minutes')
                    """,
                (int(row["id"]),),
            )
            return {"type": "api_key", "id": int(row["id"]), "label": str(row["label"]), "role": str(row["role"]), **({"report_subject_id": int(row["report_subject_id"])} if row.get("report_subject_id") is not None else {})}
    return None


def principal_from_headers(headers: Mapping[str, str]) -> dict[str, Any] | None:
    authorization = str(headers.get("Authorization") or "")
    if authorization.lower().startswith("bearer "):
        principal = authenticate_api_key(authorization[7:].strip())
        if principal:
            return principal
    principal = authenticate_api_key(headers.get("X-ADLog-API-Key"))
    return principal or authenticate_session(session_token_from_cookie(headers.get("Cookie")))


def allows(principal: Mapping[str, Any] | None, required_role: str) -> bool:
    return bool(principal) and ROLE_RANK.get(str(principal.get("role")), 0) >= ROLE_RANK[required_role]

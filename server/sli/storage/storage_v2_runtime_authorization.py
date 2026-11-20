from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

from server.sli.storage.storage_v2_transition_controller import (
    CONTROLLER_AUTHORITY,
    is_controller_authorization,
)


_RUNTIME_AUTHORIZATION_SEAL = object()
_ALLOWED_ROUTES = frozenset({"v2_primary_compat", "v2"})
FRESH_BOOTSTRAP_AUTHORITY = "storage-v2-fresh-bootstrap/v1"
FRESH_EVENT_TABLES = (
    "events_v2_core", "event_facts_v2", "event_entity_link_blocks_v2",
    "storage_v2_event_identity_allocations", "raw_log_files", "storage_v2_outbox",
    "storage_v2_archive_blocks", "storage_v2_archive_sets",
)
FRESH_REQUIRED_MIGRATIONS = {
    91: "storage_v2_runtime_authorization",
    93: "storage_v2_runtime_authorization_reader",
    94: "storage_v2_runtime_authorization_owner",
    96: "storage_v2_direct_ingest_worker_grants",
    97: "storage_v2_drop_legacy_v1_relations",
    133: "runtime_collection_history_restoration",
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("runtime authorization timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _payload(
    *, route: str, authority: str, preflight_digest: str, archive_root: str,
    evidence: Mapping[str, Any], authorized_by: str,
    authorized_at: datetime, expires_at: datetime,
) -> dict[str, Any]:
    return {
        "route": route,
        "authority": authority,
        "preflight_digest": preflight_digest,
        "archive_root": archive_root,
        "evidence": dict(evidence),
        "authorized_by": authorized_by,
        "authorized_at": _utc(authorized_at).isoformat(),
        "expires_at": _utc(expires_at).isoformat(),
    }


def runtime_authorization_digest(**values: Any) -> str:
    payload = _payload(**values)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PersistedRuntimeAuthorization:
    route: str
    authority: str
    preflight_digest: str
    authorization_digest: str
    archive_root: str
    evidence: Mapping[str, Any]
    authorized_by: str
    authorized_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    _seal: object = field(default=None, repr=False, compare=False)

    def as_record(self) -> dict[str, Any]:
        return {
            "singleton": True,
            "route": self.route,
            "authority": self.authority,
            "preflight_digest": self.preflight_digest,
            "authorization_digest": self.authorization_digest,
            "archive_root": self.archive_root,
            "evidence": dict(self.evidence),
            "authorized_by": self.authorized_by,
            "authorized_at": self.authorized_at,
            "expires_at": self.expires_at,
            "revoked_at": self.revoked_at,
        }


def is_persisted_runtime_authorization(value: object) -> bool:
    return (
        isinstance(value, PersistedRuntimeAuthorization)
        and value._seal is _RUNTIME_AUTHORIZATION_SEAL
    )


def load_runtime_authorization_if_available(
    connect_factory,
) -> PersistedRuntimeAuthorization | None:
    """Load one active runtime capability without requiring migration 091."""
    with connect_factory() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select to_regclass('public.storage_v2_runtime_authorizations') "
                "is not null as available"
            )
            row = cur.fetchone()
            if isinstance(row, Mapping):
                available = bool(row.get("available"))
            else:
                available = bool(row and row[0])
            if not available:
                return None
            return load_runtime_authorization(cur)


def persist_runtime_authorization(
    cur,
    *,
    authorization: object,
    route: str,
    archive_root: str | Path,
    evidence: Mapping[str, Any],
    authorized_by: str,
    expires_at: datetime,
    issued_at: datetime | None = None,
) -> PersistedRuntimeAuthorization:
    if not is_controller_authorization(authorization):
        raise RuntimeError("controller-issued Storage V2 authorization is required")
    if route not in _ALLOWED_ROUTES:
        raise ValueError(f"unsupported Storage V2 runtime route: {route}")
    return _persist_record(
        cur, route=route, authority=str(authorization["authority"]),
        preflight_digest=str(authorization["preflight_digest"]), archive_root=archive_root,
        evidence=evidence, authorized_by=authorized_by, expires_at=expires_at,
        issued_at=issued_at, replace_existing=True,
    )


def _persist_record(
    cur, *, route, authority, preflight_digest, archive_root, evidence,
    authorized_by, expires_at, issued_at, replace_existing,
) -> PersistedRuntimeAuthorization:
    authorized_at = _utc(issued_at or datetime.now(timezone.utc))
    expires = _utc(expires_at)
    if expires <= authorized_at:
        raise ValueError("runtime authorization expiry must be after issuance")
    root = str(Path(archive_root).resolve())
    digest = runtime_authorization_digest(
        route=route,
        authority=authority,
        preflight_digest=preflight_digest,
        archive_root=root,
        evidence=evidence,
        authorized_by=str(authorized_by),
        authorized_at=authorized_at,
        expires_at=expires,
    )
    statement = """
        insert into storage_v2_runtime_authorizations(
            singleton,route,authority,preflight_digest,authorization_digest,
            archive_root,evidence,authorized_by,authorized_at,expires_at,revoked_at
        ) values (true,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,null)
        """
    if replace_existing:
        statement += """
        on conflict(singleton) do update set
            route=excluded.route,authority=excluded.authority,
            preflight_digest=excluded.preflight_digest,
            authorization_digest=excluded.authorization_digest,
            archive_root=excluded.archive_root,evidence=excluded.evidence,
            authorized_by=excluded.authorized_by,authorized_at=excluded.authorized_at,
            expires_at=excluded.expires_at,revoked_at=null
        """
    cur.execute(
        statement,
        (
            route, authority, preflight_digest, digest, root,
            json.dumps(dict(evidence), ensure_ascii=False, sort_keys=True),
            str(authorized_by), authorized_at, expires,
        ),
    )
    return PersistedRuntimeAuthorization(
        route=route,
        authority=authority,
        preflight_digest=preflight_digest,
        authorization_digest=digest,
        archive_root=root,
        evidence=dict(evidence),
        authorized_by=str(authorized_by),
        authorized_at=authorized_at,
        expires_at=expires,
        _seal=_RUNTIME_AUTHORIZATION_SEAL,
    )


def load_runtime_authorization(
    cur, *, now: datetime | None = None
) -> PersistedRuntimeAuthorization | None:
    cur.execute(
        """
        select singleton,route,authority,preflight_digest,authorization_digest,
               archive_root,evidence,authorized_by,authorized_at,expires_at,revoked_at
        from storage_v2_runtime_authorizations
        where singleton=true
        """
    )
    row = cur.fetchone()
    if not row:
        return None
    revoked_at = row.get("revoked_at")
    if revoked_at is not None:
        raise RuntimeError("Storage V2 runtime authorization is revoked")
    current = _utc(now or datetime.now(timezone.utc))
    expires_at = _utc(row["expires_at"])
    if current >= expires_at:
        raise RuntimeError("Storage V2 runtime authorization is expired")
    route = str(row["route"])
    authority = str(row["authority"])
    if route not in _ALLOWED_ROUTES or authority not in {CONTROLLER_AUTHORITY, FRESH_BOOTSTRAP_AUTHORITY}:
        raise RuntimeError("Storage V2 runtime authorization authority or route is invalid")
    evidence_value = row.get("evidence") or {}
    evidence = json.loads(evidence_value) if isinstance(evidence_value, str) else dict(evidence_value)
    if authority == FRESH_BOOTSTRAP_AUTHORITY and (
        route != "v2" or evidence.get("kind") != "fresh-event-store"
        or evidence.get("version") != 1
    ):
        raise RuntimeError("Storage V2 fresh bootstrap authority or evidence is invalid")
    authorized_at = _utc(row["authorized_at"])
    expected = runtime_authorization_digest(
        route=route,
        authority=authority,
        preflight_digest=str(row["preflight_digest"]),
        archive_root=str(row["archive_root"]),
        evidence=evidence,
        authorized_by=str(row["authorized_by"]),
        authorized_at=authorized_at,
        expires_at=expires_at,
    )
    if str(row["authorization_digest"]).lower() != expected:
        raise RuntimeError("Storage V2 runtime authorization digest mismatch")
    return PersistedRuntimeAuthorization(
        route=route,
        authority=authority,
        preflight_digest=str(row["preflight_digest"]),
        authorization_digest=expected,
        archive_root=str(row["archive_root"]),
        evidence=evidence,
        authorized_by=str(row["authorized_by"]),
        authorized_at=authorized_at,
        expires_at=expires_at,
        _seal=_RUNTIME_AUTHORIZATION_SEAL,
    )


def inspect_fresh_storage(cur, *, archive_root: str | Path) -> dict[str, Any]:
    """Read-only prerequisites; apply repeats them under database locks."""
    from psycopg import sql
    # Retain the historical record field for digest/schema compatibility.
    root = str(Path(archive_root).resolve())
    cur.execute("SELECT version,name FROM public.schema_migrations WHERE version=ANY(%s)",
                (list(FRESH_REQUIRED_MIGRATIONS),))
    migrations = {row["version"]: row["name"] for row in cur.fetchall()}
    if migrations != FRESH_REQUIRED_MIGRATIONS:
        raise RuntimeError("fresh_storage_migrations_mismatch")
    cur.execute("SELECT EXISTS(SELECT 1 FROM public.storage_v2_runtime_authorizations) AS present")
    if cur.fetchone()["present"]:
        raise RuntimeError("fresh_storage_already_initialized")
    for name in ("events", "event_entity_links", "observed_entities"):
        cur.execute("SELECT to_regclass(%s) IS NOT NULL AS present", ("public." + name,))
        if cur.fetchone()["present"]:
            raise RuntimeError("fresh_storage_legacy_relations_present")
    for name in FRESH_EVENT_TABLES:
        cur.execute(sql.SQL("SELECT EXISTS(SELECT 1 FROM public.{}) AS present").format(sql.Identifier(name)))
        if cur.fetchone()["present"]:
            raise RuntimeError("fresh_storage_not_empty:" + name)
    cur.execute("SELECT current_database() AS database, session_user AS issuer")
    identity = dict(cur.fetchone())
    return {"kind": "fresh-event-store", "version": 1, "archive_root": root,
            "database": identity["database"], "issuer": identity["issuer"],
            "migrations": {str(k): v for k, v in migrations.items()},
            "empty_event_tables": list(FRESH_EVENT_TABLES),
            "legacy_relations_absent": True,
            "historical_cutover_performed": False}


def bootstrap_fresh_runtime_authorization(
    cur, *, archive_root: str | Path, authorized_by: str,
    expires_at: datetime, issued_at: datetime | None = None,
) -> PersistedRuntimeAuthorization:
    """Maintenance-only first initialization; caller owns the transaction.

    This never overwrites/revives an admission, creates schema or changes AD,
    VPN, entity identities, collection cursors or historical migration evidence.
    """
    from psycopg import sql
    if not authorized_by.strip():
        raise ValueError("fresh_storage_owner_required")
    issued = _utc(issued_at or datetime.now(timezone.utc))
    if not 0 < (_utc(expires_at) - issued).total_seconds() <= 366 * 86400:
        raise ValueError("fresh_storage_expiry_must_be_within_366_days")
    for lock in ("ad_log_reports_runtime_collection_process", "ad_log_reports_runtime_collection_worker"):
        cur.execute("SELECT pg_try_advisory_xact_lock(hashtext(%s)) AS acquired", (lock,))
        if not cur.fetchone()["acquired"]:
            raise RuntimeError("fresh_storage_collection_active")
    tables = ("storage_v2_runtime_authorizations", *FRESH_EVENT_TABLES)
    cur.execute(sql.SQL("LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE").format(
        sql.SQL(", ").join(sql.Identifier("public", name) for name in tables)))
    evidence = inspect_fresh_storage(cur, archive_root=archive_root)
    digest = sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return _persist_record(
        cur, route="v2", authority=FRESH_BOOTSTRAP_AUTHORITY,
        preflight_digest=digest, archive_root=evidence["archive_root"],
        evidence=evidence, authorized_by=authorized_by,
        expires_at=expires_at, issued_at=issued, replace_existing=False,
    )

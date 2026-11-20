"""Runtime-owned RADIUS plugin logic for the recurring plugin host.

`scripts/runtime/remote_access_plugin_host.py` previously imported its
recurring-cycle logic directly from `scripts/maintenance/*` (private helpers
`_connect_admin`/`_worker_dsn`/`_ephemeral_login` and `run_internal` from
`stage9_radius_manual_worker.py` and `stage9_radius_session_consumer_manual.py`,
plus `current_windows_account` from `ad_context_live_canary.py`). That made
production's recurring RADIUS cycle depend on maintenance/manual modules for
correctness; a change on that seam already caused one real production
failure (`getpass.getuser()` without `USERNAME` in a minimal Windows Job
child).

This module owns that logic instead. The plugin host imports only from here.
The maintenance CLIs (`stage9_radius_manual_worker.py`,
`stage9_radius_session_consumer_manual.py`, `ad_context_live_canary.py`) may
import back from this module to keep their own one-shot CLI behavior
unchanged -- the dependency direction is maintenance -> runtime, never the
reverse. This module must never import `scripts.maintenance.*`.
"""
from __future__ import annotations

import getpass
import json
import os
import re
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from server.sli.sources.plugin_runtime_admission import ACQUISITION, CONSUMER
from server.sli.sources.plugin_runtime_admission_executor import component_lease_scope
from server.sli.sources.windows_runtime_identity import verify_collection_identity
from server.sli.storage.acquisition_evidence_store import AcquisitionEvidenceStore
from server.source_packs.radius.accounting_evidence import (
    publish_radius_batch_evidence,
)
from server.source_packs.radius.accounting_identity import (
    resolve_radius_principal,
)
from server.source_packs.radius.accounting_manual_control import (
    RadiusManualLease,
    load_manual_control_contract,
)
from server.source_packs.radius.accounting_postgres import (
    commit_admitted_empty_radius_progress,
    commit_radius_batch,
    load_runtime_state,
)
from server.source_packs.radius.accounting_runtime_contract import plan_batch
from server.source_packs.radius.accounting_tail import read_bounded_tail
from server.source_packs.radius.collection_routes import (
    load_radius_collection_routes,
    require_accounting_source,
)
from server.source_packs.radius.session_consumer import (
    claim_radius_deliveries,
    fail_radius_delivery,
    process_radius_delivery,
)
from sli_collect.packets import validate_packet
from sli_collect.radius import collect_radius_packet
from sli_collect.radius_contract import RadiusFileCursor
from sli_collect.radius_tail import MAXIMUM_READ_BYTES, MAXIMUM_RECORDS, RadiusTailBatch

EVIDENCE_ROOT = Path(r"C:\SLI")
_EPHEMERAL_CONSUMER_ROLE = re.compile(r"^adlog_radius_consumer_[a-z0-9_]{1,32}$")


class RadiusAcquisitionRuntimeError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RadiusSessionConsumerRuntimeError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def current_windows_account() -> str:
    if os.name != "nt":
        return getpass.getuser()
    import ctypes
    from ctypes import wintypes

    name_sam_compatible = 2
    size = wintypes.ULONG(0)
    secur32 = ctypes.WinDLL("secur32", use_last_error=True)
    get_name = secur32.GetUserNameExW
    get_name.argtypes = (
        wintypes.ULONG,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.ULONG),
    )
    get_name.restype = wintypes.BOOL
    get_name(name_sam_compatible, None, ctypes.byref(size))
    if size.value < 2:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(size.value)
    if not get_name(name_sam_compatible, buffer, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    value = buffer.value.strip()
    if not value or "\\" not in value:
        raise RuntimeError("windows_sam_account_unavailable")
    return value


# --- radius-acquisition -----------------------------------------------


@dataclass(frozen=True)
class _LocalAcquisitionTail:
    """Internal witness from the identity-scoped local read, never wire input."""

    cursor: RadiusFileCursor
    batch: RadiusTailBatch


def acquisition_source_id() -> str:
    return str(load_radius_collection_routes()["source_instance_id"])


def acquisition_subscription_id() -> str:
    return str(load_manual_control_contract()["subscription_id"])


def acquisition_organization_fqdn() -> str:
    host = str(load_radius_collection_routes()["source_name"])
    return host.partition(".")[2]


def _acquisition_admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise RadiusAcquisitionRuntimeError(
            "protected_postgres_credentials_required"
        )
    values = conninfo_to_dict(source)
    values.update(user=user, password=password)
    return make_conninfo(**values)


def acquisition_worker_dsn(lease: RadiusManualLease) -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    values = conninfo_to_dict(os.environ["ADLOG_PG_DSN"])
    values.update(user=lease.login_role, password=lease.password)
    return make_conninfo(**values)


def connect_acquisition_admin():
    import psycopg

    return psycopg.connect(
        _acquisition_admin_dsn(),
        autocommit=True,
        connect_timeout=5,
        application_name="sli_stage9_radius_manual_control",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )


def connect_acquisition_worker():
    import psycopg

    dsn = os.environ.get("SLI_PLUGIN_PG_DSN", "").strip()
    if not dsn:
        raise RadiusAcquisitionRuntimeError("worker_dsn_required")
    return psycopg.connect(
        dsn,
        autocommit=False,
        connect_timeout=5,
        application_name="sli_stage9_radius_manual_worker",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )


def _resolve_acquisition_identity(cur: Any, distinguished_name: str) -> str | None:
    def exact_lookup(organization: str, candidate: str) -> str | None:
        cur.execute(
            "select sli_radius_resolve_principal_key(%s,%s)",
            (organization, candidate),
        )
        value = cur.fetchone()[0]
        return str(value) if value is not None else None

    return resolve_radius_principal(
        distinguished_name,
        expected_organization_fqdn=acquisition_organization_fqdn(),
        exact_lookup=exact_lookup,
    )


def run_acquisition_cycle() -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.vpn_source_auth import (
        VPN_SOURCE_CREDENTIAL_MODE_ENV,
        accounting_source_identity,
        validate_vpn_source_credential_mode,
    )
    source_mode = validate_vpn_source_credential_mode(
        os.environ.get(VPN_SOURCE_CREDENTIAL_MODE_ENV, "process")
    )
    if verify_collection_identity()["status"] != "ok":
        raise PermissionError("current_windows_account_is_not_approved_owner")
    with connect_acquisition_worker() as conn:
        holder_key = f"radius-acquisition:{os.getpid()}"
        with component_lease_scope(
            conn,
            component_id=ACQUISITION,
            holder_key=holder_key,
        ):
            directory, timezone_id, offset = require_accounting_source()
            state = load_runtime_state(
                conn,
                subscription_id=acquisition_subscription_id(),
            )
            local_tail = None

            def read_local_tail(*args, **kwargs):
                nonlocal local_tail
                tail = read_bounded_tail(*args, **kwargs)
                local_tail = _LocalAcquisitionTail(kwargs["cursor"], tail)
                return tail

            with accounting_source_identity(directory, mode=source_mode):
                packet = collect_radius_packet(
                    directory, cursor=state.cursor,
                    source_timezone_id=timezone_id,
                    source_utc_offset_minutes=offset,
                    read_tail=read_local_tail,
                    allow_exact_boundary_recovery=state.exact_boundary_recovery,
                )
            return import_acquisition_packet(
                conn, packet, state=state,
                local_tail=local_tail,
            )


def import_acquisition_packet(conn: Any, packet: dict[str, Any], *, state: Any,
                              subscription_id: str | None = None,
                              evidence_root: Path | None = None,
                              local_tail: _LocalAcquisitionTail | None = None) -> dict[str, Any]:
    """Apply the existing Accounting transaction to a source-free wire packet."""
    validate_packet(packet)
    header = packet["header"]
    bounds = header["cursor"]
    if (header["source"] != state.cursor.source_instance_id
            or header["channel"] != state.cursor.stream_id
            or bounds.get("before") != asdict(state.cursor)
            or any(record["format"] != "accounting_line" for record in packet["records"])):
        raise ValueError("collection_packet_radius_mismatch")
    records = tuple(record["payload"] for record in packet["records"])
    context = packet["context"]
    timezone_id = context["source_timezone_id"]
    offset = context["source_utc_offset_minutes"]
    stats = {name: context[name] for name in (
        "candidate_count", "bytes_read", "partial_trailing_bytes",
        "rotation_backlog_generations", "cursor_generation_recovered",
    )}
    if not records:
        revision_after = state.revision
        if local_tail is not None:
            _require_local_tail_packet(packet, state.cursor, local_tail)
            tail = local_tail.batch
            if tail.end_offset > tail.start_offset or tail.previous_generation_eof:
                commit_admitted_empty_radius_progress(
                    conn, subscription_id=subscription_id if subscription_id is not None else acquisition_subscription_id(),
                    cursor_epoch=state.cursor_epoch, expected_revision=state.revision,
                    current_cursor=state.cursor,
                    next_cursor=replace(state.cursor, file_generation=tail.file_generation,
                                        byte_offset=tail.end_offset),
                    skipped_bytes=tail.end_offset - tail.start_offset,
                    physical_lines=tail.physical_lines, maximum_physical_lines=MAXIMUM_RECORDS,
                )
                revision_after += 1
        return {
            "status": "committed" if revision_after != state.revision else "no_new_complete_records",
            "records": 0, **stats,
            "cursor_revision_before": state.revision, "cursor_revision_after": revision_after,
            "source_timezone_id": timezone_id, "source_utc_offset_minutes": offset,
            "evidence_rows": 0, "observation_rows": 0, "outbox_rows": 0,
        }
    observed = datetime.fromisoformat(header["observed_at_utc"].replace("Z", "+00:00"))
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_radius_accounting_worker")
        plan_value = plan_batch(
            cursor=state.cursor, class_cache=state.class_cache,
            file_generation=header["generation"], start_offset=bounds["start_offset"],
            end_offset=bounds["end_offset"], lines=records,
            identity_resolver=lambda dn: _resolve_acquisition_identity(cur, dn),
            batch_observed_at_utc=observed, source_timezone_id=timezone_id,
            source_utc_offset_minutes=offset,
            previous_generation_eof=packet["continuity"]["previous_generation_eof"],
        )
    evidence = publish_radius_batch_evidence(
        AcquisitionEvidenceStore(evidence_root if evidence_root is not None else EVIDENCE_ROOT), cursor_epoch=state.cursor_epoch,
        plan=plan_value, canonical_records=records,
    )
    receipt = commit_radius_batch(
        conn, subscription_id=subscription_id if subscription_id is not None else acquisition_subscription_id(), cursor_epoch=state.cursor_epoch,
        expected_revision=state.revision, plan=plan_value, evidence_objects=evidence,
    )
    return {
        "status": "committed",
        "records": int(plan_value.counters["records"]),
        **stats,
        "rotation_from_eof": plan_value.rotation_from_eof,
        "cursor_revision_before": state.revision,
        "cursor_revision_after": receipt.cursor_revision,
        "source_timezone_id": timezone_id,
        "source_utc_offset_minutes": offset,
        "counters": dict(plan_value.counters),
        "evidence_rows": receipt.evidence_rows,
        "observation_rows": receipt.observation_rows,
        "outbox_rows": receipt.outbox_rows,
        "class_cache_rows": receipt.class_cache_rows,
    }


def _require_local_tail_packet(packet: dict[str, Any], cursor: RadiusFileCursor,
                               witness: _LocalAcquisitionTail) -> None:
    """Bind the packet to the exact successful local read and before cursor.

    A wire summary alone must never opt legacy/agent callers into this path.
    Rebuilding only serializes the in-memory tail; it does not reread a source.
    """
    if (type(witness) is not _LocalAcquisitionTail or type(witness.cursor) is not RadiusFileCursor
            or json.dumps(asdict(witness.cursor), sort_keys=True) != json.dumps(asdict(cursor), sort_keys=True)
            or type(witness.batch) is not RadiusTailBatch):
        raise ValueError("collection_packet_local_tail_mismatch")
    tail = witness.batch
    rotation = tail.file_generation != cursor.file_generation
    if (any(type(getattr(tail, name)) is not int for name in (
            "start_offset", "end_offset", "physical_lines", "bytes_read", "partial_trailing_bytes"))
            or not 0 <= tail.start_offset <= tail.end_offset <= 2**63 - 1
            or tail.start_offset != (0 if rotation else cursor.byte_offset)
            or tail.previous_generation_eof is not rotation
            or not 0 <= tail.physical_lines <= MAXIMUM_RECORDS
            or not 0 <= tail.partial_trailing_bytes <= tail.bytes_read <= MAXIMUM_READ_BYTES
            or tail.end_offset - tail.start_offset > tail.bytes_read - tail.partial_trailing_bytes):
        raise ValueError("collection_packet_local_tail_mismatch")
    context = packet["context"]
    expected = collect_radius_packet(
        Path(), cursor=cursor, source_timezone_id=context["source_timezone_id"],
        source_utc_offset_minutes=context["source_utc_offset_minutes"],
        observed_at=datetime.fromisoformat(packet["header"]["observed_at_utc"].replace("Z", "+00:00")),
        read_tail=lambda *_args, **_kwargs: tail,
    )
    # JSON comparison also distinguishes bool from int in offsets and counts.
    if json.dumps(expected, sort_keys=True) != json.dumps(packet, sort_keys=True):
        raise ValueError("collection_packet_local_tail_mismatch")


# --- radius-session-observation (consumer) ------------------------------


def _consumer_admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise RadiusSessionConsumerRuntimeError(
            "protected_postgres_credentials_required"
        )
    values = conninfo_to_dict(source)
    values.update(user=user, password=password)
    return make_conninfo(**values)


def consumer_worker_dsn(role: str, password: str) -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    values = conninfo_to_dict(os.environ["ADLOG_PG_DSN"])
    values.update(user=role, password=password)
    return make_conninfo(**values)


def connect_consumer_admin():
    import psycopg

    return psycopg.connect(
        _consumer_admin_dsn(),
        autocommit=True,
        connect_timeout=5,
        application_name="sli_stage9_radius_session_consumer_control",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )


def connect_consumer_worker():
    import psycopg

    dsn = os.getenv("SLI_PLUGIN_PG_DSN", "").strip()
    if not dsn:
        raise RadiusSessionConsumerRuntimeError("consumer_worker_dsn_required")
    return psycopg.connect(
        dsn,
        autocommit=False,
        connect_timeout=5,
        application_name="sli_stage9_radius_session_consumer_worker",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )


@contextmanager
def consumer_ephemeral_login() -> Iterator[tuple[str, str]]:
    from psycopg import sql

    from server.source_packs.radius.accounting_manual_control import (
        lock_ephemeral_database_connect_acl,
    )

    role = f"adlog_radius_consumer_{uuid4().hex[:16]}"
    if _EPHEMERAL_CONSUMER_ROLE.fullmatch(role) is None:
        raise RadiusSessionConsumerRuntimeError("ephemeral_role_invalid")
    password = secrets.token_urlsafe(32)
    with connect_consumer_admin() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("select to_regrole(%s) is not null", (role,))
        if bool(cur.fetchone()[0]):
            raise RadiusSessionConsumerRuntimeError("ephemeral_role_conflict")
        database_name = str(cur.connection.info.dbname or "").strip()
        if not database_name:
            raise RadiusSessionConsumerRuntimeError(
                "consumer_database_identity_required"
            )
        lock_ephemeral_database_connect_acl(cur)
        cur.execute(
            sql.SQL(
                "create role {} noinherit login password {} "
                "nosuperuser nocreatedb nocreaterole "
                "nobypassrls noreplication"
            ).format(
                sql.Identifier(role),
                sql.Literal(password),
            )
        )
        cur.execute(
            sql.SQL(
                "grant adlog_radius_session_consumer to {}"
            ).format(sql.Identifier(role))
        )
        cur.execute(
            sql.SQL("grant connect on database {} to {}").format(
                sql.Identifier(database_name),
                sql.Identifier(role),
            )
        )
    try:
        yield role, password
    finally:
        with connect_consumer_admin() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(
                """
                select count(*) from pg_stat_activity
                where usename=%s and pid<>pg_backend_pid()
                """,
                (role,),
            )
            if int(cur.fetchone()[0]) != 0:
                raise RadiusSessionConsumerRuntimeError(
                    "ephemeral_role_still_active"
                )
            lock_ephemeral_database_connect_acl(cur)
            cur.execute(
                sql.SQL(
                    "revoke adlog_radius_session_consumer from {}"
                ).format(sql.Identifier(role))
            )
            database_name = str(cur.connection.info.dbname or "").strip()
            if not database_name:
                raise RadiusSessionConsumerRuntimeError(
                    "consumer_database_identity_required"
                )
            cur.execute(
                sql.SQL("revoke connect on database {} from {}").format(
                    sql.Identifier(database_name),
                    sql.Identifier(role),
                )
            )
            cur.execute(
                sql.SQL("drop role {}").format(sql.Identifier(role))
            )


def run_consumer_cycle() -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    started = time.monotonic()
    outcomes: dict[str, int] = {}
    processed = 0
    with connect_consumer_worker() as conn:
        holder_key = f"radius-session-observation:{os.getpid()}"
        with component_lease_scope(
            conn,
            component_id=CONSUMER,
            holder_key=holder_key,
        ):
            claimed = claim_radius_deliveries(conn, limit=50)
            for item in claimed:
                if time.monotonic() - started > 50:
                    raise TimeoutError("consumer_internal_deadline_exceeded")
                try:
                    receipt = process_radius_delivery(
                        conn,
                        delivery_id=item.delivery_id,
                        lease_token=item.lease_token,
                    )
                except Exception:
                    fail_radius_delivery(
                        conn,
                        delivery_id=item.delivery_id,
                        lease_token=item.lease_token,
                        error_code="consumer_processing_failed",
                        retry_delay_seconds=30,
                    )
                    raise
                outcomes[receipt.outcome] = (
                    outcomes.get(receipt.outcome, 0) + 1
                )
                processed += 1
    return {
        "status": "completed",
        "claimed": len(claimed),
        "processed": processed,
        "outcomes": outcomes,
    }

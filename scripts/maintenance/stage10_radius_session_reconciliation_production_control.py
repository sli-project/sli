#!/usr/bin/env python3
"""Plan/apply bounded, immutable RADIUS identity reconciliation.

The control reads only core-owned local evidence during planning.  Apply may
install the already-reviewed read boundaries and append reconciliation overlays,
then rebuilds only derived session rows.  It never contacts RADIUS/NPS, moves a
cursor, leases a queue item, or updates an original observation or receipt.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment  # noqa: E402
from server.source_packs.radius.session_consumer import (  # noqa: E402
    ReconciledRadiusProjection,
    rebuild_reconciled_radius_projections,
    load_consumer_contract,
)
from server.source_packs.radius.session_reconciliation import (  # noqa: E402
    build_reconciliation_attempts,
    load_reconciliation_contract,
)
from server.source_packs.radius.session_reconciliation_postgres import (  # noqa: E402
    write_reconciliation_attempts,
)
from server.source_packs.radius.session_reconciliation_production import (  # noqa: E402
    ImmutableTerminalObservation,
    VerifiedEvidenceRecord,
    build_exact_reconciliation_batch,
)
from server.source_packs.radius.accounting import (  # noqa: E402
    ACCESS_ACCEPT_PACKET_TYPE,
    parse_database_compatible_record,
)


CONFIRMATION = "APPLY-STAGE10-RADIUS-SESSION-RECONCILIATION"
RESOLVER_CONTRACT_ID = "sli.radius-session-reconciliation-production.v1"
EVIDENCE_ROOT = Path(r"C:\SLI")
AUTHORIZED_TERMINAL_RECEIPT_COUNT = 83
AUTHORIZED_BATCH_RECEIPT_COUNTS = (17, 50, 16)
RADIUS_ACCOUNTING_STREAM_ID = "radius-accounting"
RADIUS_ACCOUNTING_TRANSPORT_BINDING = "windows-rpc-smb-readonly-tail-v1"
MIGRATIONS = {
    62: ROOT / "config/postgres_migrations/062_vpn_session_report_read_boundary.sql",
    63: ROOT / "config/postgres_migrations/063_radius_vpn_operations_read_boundary.sql",
    64: ROOT / "config/postgres_migrations/064_vpn_session_canonical_identity_read_boundary.sql",
    65: ROOT / "config/postgres_migrations/065_radius_session_reconciliation_overlay.sql",
    80: ROOT / "config/postgres_migrations/080_radius_session_reconciliation_projection.sql",
}
RECONCILIATION_ROLLBACKS = {
    65: ROOT / "config/postgres_migrations/065_radius_session_reconciliation_overlay.rollback.sql",
    80: ROOT / "config/postgres_migrations/080_radius_session_reconciliation_projection.rollback.sql",
}
MIGRATION_NAMES = {
    61: "radius_session_consumer_projection",
    62: "vpn_session_report_read_boundary",
    63: "radius_vpn_operations_read_boundary",
    64: "vpn_session_canonical_identity_read_boundary",
    65: "radius_session_reconciliation_overlay",
    80: "radius_session_reconciliation_projection",
}
DEFAULT_DISPOSABLE_ACCEPTANCE = ROOT / (
    "artifacts/stage10/evidence/"
    "radius-session-reconciliation80-disposable-pg18.json"
)


class RadiusReconciliationProductionControlError(RuntimeError):
    pass


@dataclass(frozen=True)
class _Scope:
    source_instance_id: str
    organization_fqdn: str
    subscription_id: str


@dataclass(frozen=True)
class _EvidenceManifest:
    evidence_uid: str
    canonical_record_sha256: str
    object_sha256: str
    object_size_bytes: int
    cursor_start_byte_offset: int
    batch_record_ordinal: int = 0


@dataclass(frozen=True)
class _TerminalObservation:
    observation_id: str
    evidence_uid: str
    lifecycle_event: str
    timestamp_state: str
    observed_at_utc: datetime | str | None
    cursor_start_byte_offset: int


def _load_environment() -> None:
    if not (
        os.getenv("ADLOG_PG_DSN", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    ):
        load_supervisor_environment()


def _admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise RadiusReconciliationProductionControlError(
            "protected_postgres_credentials_required"
        )
    values = conninfo_to_dict(source)
    values.update(user=user, password=password)
    return make_conninfo(**values)


def _connect(*, autocommit: bool = False):
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(
        _admin_dsn(),
        autocommit=autocommit,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="sli_stage10_radius_reconciliation_control",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )


def _migration_markers(
    rows: list[Mapping[str, Any]],
) -> dict[int, bool]:
    """Return controlled migration state, rejecting a version-name collision."""
    for row in rows:
        version = int(row["version"])
        if (
            version in MIGRATION_NAMES
            and str(row["name"]) != MIGRATION_NAMES[version]
        ):
            raise RadiusReconciliationProductionControlError(
                "production_reconciliation_migration_version_conflict"
            )
    return {
        version: any(int(row["version"]) == version for row in rows)
        for version in MIGRATION_NAMES
    }


def _scope_and_baseline() -> tuple[_Scope, dict[str, Any], dict[int, bool]]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """
            select source_instance_id,organization_scope
            from acquisition_source_instances
            where source_kind='windows.nps.radius'
            order by source_instance_id
            """
        )
        sources = list(cur.fetchall())
        if len(sources) != 1:
            raise RadiusReconciliationProductionControlError(
                "production_reconciliation_exact_radius_source_required"
            )
        source = sources[0]
        cur.execute(
            """
            select subscription_id
            from acquisition_consumer_subscriptions
            where source_instance_id=%s
              and stream_id=%s
              and transport_binding=%s
            order by subscription_id
            """,
            (
                source["source_instance_id"],
                RADIUS_ACCOUNTING_STREAM_ID,
                RADIUS_ACCOUNTING_TRANSPORT_BINDING,
            ),
        )
        subscriptions = list(cur.fetchall())
        if len(subscriptions) != 1:
            raise RadiusReconciliationProductionControlError(
                "production_reconciliation_exact_subscription_required"
            )
        scope = _Scope(
            source_instance_id=str(source["source_instance_id"]),
            organization_fqdn=str(source["organization_scope"]),
            subscription_id=str(subscriptions[0]["subscription_id"]),
        )
        if scope.subscription_id != str(
            load_consumer_contract()["subscription_id"]
        ):
            raise RadiusReconciliationProductionControlError(
                "production_reconciliation_consumer_binding_required"
            )
        cur.execute(
            """
            select revision
            from acquisition_stream_cursors
            where source_instance_id=%s
              and stream_id=%s
              and transport_binding=%s
            """,
            (
                scope.source_instance_id,
                RADIUS_ACCOUNTING_STREAM_ID,
                RADIUS_ACCOUNTING_TRANSPORT_BINDING,
            ),
        )
        cursor = cur.fetchone()
        if cursor is None:
            raise RadiusReconciliationProductionControlError(
                "production_reconciliation_cursor_required"
            )
        cur.execute(
            """
            select
              (
                select count(*)::bigint
                from radius_accounting_session_observations observation
                join core_evidence_manifests evidence
                  on evidence.evidence_uid=observation.evidence_uid
                where evidence.source_instance_id=%s
                  and evidence.stream_id=%s
                  and evidence.transport_binding=%s
              ) as observations,
              (
                select count(*)::bigint
                from radius_session_projection_receipts receipt
                join radius_accounting_session_observations observation
                  on observation.observation_id=receipt.observation_id
                join core_evidence_manifests evidence
                  on evidence.evidence_uid=observation.evidence_uid
                where evidence.source_instance_id=%s
                  and evidence.stream_id=%s
                  and evidence.transport_binding=%s
                  and receipt.outcome='identity_unresolved'
              ) as terminal_unresolved_receipts,
              (
                select count(*)::bigint
                from acquisition_delivery_outbox delivery
                where delivery.subscription_id=%s
                  and delivery.delivery_state in ('queued','leased')
              ) as nonterminal_deliveries,
              to_regclass('radius_session_reconciliation_attempts') is not null as attempts_table,
              to_regclass('radius_session_identity_overlays') is not null as overlays_table,
              to_regrole('adlog_radius_session_reconciliation_writer') is not null as writer_role,
              (select rolcreaterole from pg_roles where rolname=current_user)
                as migration_role_can_create_role
            """,
            (
                scope.source_instance_id,
                RADIUS_ACCOUNTING_STREAM_ID,
                RADIUS_ACCOUNTING_TRANSPORT_BINDING,
                scope.source_instance_id,
                RADIUS_ACCOUNTING_STREAM_ID,
                RADIUS_ACCOUNTING_TRANSPORT_BINDING,
                scope.subscription_id,
            ),
        )
        row = dict(cur.fetchone())
        output_counts = {"attempt_count": 0, "overlay_count": 0}
        if bool(row["attempts_table"]) and bool(row["overlays_table"]):
            cur.execute(
                """
                select
                  (
                    select count(*)::bigint
                    from radius_session_reconciliation_attempts attempt
                    join radius_accounting_session_observations observation
                      on observation.observation_id=attempt.observation_id
                    join core_evidence_manifests evidence
                      on evidence.evidence_uid=observation.evidence_uid
                    where evidence.source_instance_id=%s
                      and evidence.stream_id=%s
                      and evidence.transport_binding=%s
                  ) as attempt_count,
                  (
                    select count(*)::bigint
                    from radius_session_identity_overlays overlay
                    join radius_accounting_session_observations observation
                      on observation.observation_id=overlay.observation_id
                    join core_evidence_manifests evidence
                      on evidence.evidence_uid=observation.evidence_uid
                    where evidence.source_instance_id=%s
                      and evidence.stream_id=%s
                      and evidence.transport_binding=%s
                  ) as overlay_count
                """,
                (
                    scope.source_instance_id,
                    RADIUS_ACCOUNTING_STREAM_ID,
                    RADIUS_ACCOUNTING_TRANSPORT_BINDING,
                    scope.source_instance_id,
                    RADIUS_ACCOUNTING_STREAM_ID,
                    RADIUS_ACCOUNTING_TRANSPORT_BINDING,
                ),
            )
            output_counts = {
                key: int(value) for key, value in dict(cur.fetchone()).items()
            }
        cur.execute(
            """
            select version,name
            from schema_migrations
            where version between 61 and 80
            order by version
            """
        )
        migration_rows = list(cur.fetchall())
        cur.execute("rollback")
    migrations = _migration_markers(migration_rows)
    if not migrations[61]:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_migration_061_required"
        )
    baseline = {
        "source_instance_sha256": sha256(
            scope.source_instance_id.encode("utf-8")
        ).hexdigest(),
        "cursor_revision": int(cursor["revision"]),
        "observations": int(row["observations"]),
        "terminal_unresolved_receipts": int(
            row["terminal_unresolved_receipts"]
        ),
        "nonterminal_deliveries": int(row["nonterminal_deliveries"]),
        "attempts_table": bool(row["attempts_table"]),
        "overlays_table": bool(row["overlays_table"]),
        "writer_role": bool(row["writer_role"]),
        "migration_role_can_create_role": bool(
            row["migration_role_can_create_role"]
        ),
        **output_counts,
    }
    return scope, baseline, migrations


def _select_terminal_inventory(
    cur: Any,
    scope: _Scope,
) -> tuple[dict[str, _EvidenceManifest], list[_TerminalObservation]]:
    cur.execute(
            """
            select observation.observation_id::text,observation.evidence_uid::text,
                   observation.lifecycle_event,observation.timestamp_state,
                   observation.observed_at_utc,evidence.cursor_start_byte_offset,
                   evidence.canonical_record_sha256,evidence.object_sha256,
                   evidence.object_size_bytes,evidence.batch_record_ordinal
            from radius_accounting_session_observations observation
            join core_evidence_manifests evidence
              on evidence.evidence_uid=observation.evidence_uid
            where evidence.source_instance_id=%s
              and evidence.stream_id=%s
              and evidence.transport_binding=%s
              and exists(
                select 1 from radius_session_projection_receipts receipt
                where receipt.observation_id=observation.observation_id
                  and receipt.outcome='identity_unresolved'
              )
            order by evidence.cursor_start_byte_offset,observation.observation_id
            """,
            (
                scope.source_instance_id,
                RADIUS_ACCOUNTING_STREAM_ID,
                RADIUS_ACCOUNTING_TRANSPORT_BINDING,
            ),
    )
    rows = list(cur.fetchall())
    terminal_evidence = {
        str(row["evidence_uid"]): _EvidenceManifest(
            evidence_uid=str(row["evidence_uid"]),
            canonical_record_sha256=str(row["canonical_record_sha256"]),
            object_sha256=str(row["object_sha256"]),
            object_size_bytes=int(row["object_size_bytes"]),
            cursor_start_byte_offset=int(row["cursor_start_byte_offset"]),
            batch_record_ordinal=int(row["batch_record_ordinal"]),
        )
        for row in rows
    }
    observations = [
        _TerminalObservation(
            observation_id=str(row["observation_id"]),
            evidence_uid=str(row["evidence_uid"]),
            lifecycle_event=str(row["lifecycle_event"]),
            timestamp_state=str(row["timestamp_state"]),
            observed_at_utc=row["observed_at_utc"],
            cursor_start_byte_offset=int(row["cursor_start_byte_offset"]),
        )
        for row in rows
    ]
    if len(terminal_evidence) != len(observations):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_terminal_evidence_duplicate"
        )
    return terminal_evidence, observations


def _read_terminal_inventory(
    scope: _Scope,
) -> tuple[dict[str, _EvidenceManifest], list[_TerminalObservation]]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        terminal_evidence, observations = _select_terminal_inventory(cur, scope)
        cur.execute("rollback")
    return terminal_evidence, observations


def _select_evidence_page(
    cur: Any,
    scope: _Scope,
    after: tuple[int, int, str] | None,
) -> list[_EvidenceManifest]:
    predicate = ""
    parameters: list[Any] = [
        scope.source_instance_id,
        RADIUS_ACCOUNTING_STREAM_ID,
        RADIUS_ACCOUNTING_TRANSPORT_BINDING,
    ]
    if after is not None:
        predicate = (
            "and (cursor_start_byte_offset,batch_record_ordinal,evidence_uid::text) "
            "> (%s,%s,%s)"
        )
        parameters.extend(after)
    page_size = int(load_reconciliation_contract()["identity_evidence_discovery"]["manifest_page_size"])
    parameters.append(page_size)
    cur.execute(
            f"""
            select evidence_uid::text,canonical_record_sha256,object_sha256,
                   object_size_bytes,cursor_start_byte_offset,batch_record_ordinal
            from core_evidence_manifests
            where source_instance_id=%s
              and stream_id=%s
              and transport_binding=%s
            {predicate}
            order by cursor_start_byte_offset,batch_record_ordinal,evidence_uid::text
            limit %s
            """,
            tuple(parameters),
    )
    rows = list(cur.fetchall())
    return [
        _EvidenceManifest(
            evidence_uid=str(row["evidence_uid"]),
            canonical_record_sha256=str(row["canonical_record_sha256"]),
            object_sha256=str(row["object_sha256"]),
            object_size_bytes=int(row["object_size_bytes"]),
            cursor_start_byte_offset=int(row["cursor_start_byte_offset"]),
            batch_record_ordinal=int(row["batch_record_ordinal"]),
        )
        for row in rows
    ]


def _read_evidence_page(
    scope: _Scope,
    after: tuple[int, int, str] | None,
) -> list[_EvidenceManifest]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        page = _select_evidence_page(cur, scope, after)
        cur.execute("rollback")
    return page


def _read_verified_record(item: _EvidenceManifest) -> VerifiedEvidenceRecord:
    uid = item.evidence_uid.replace("-", "").casefold()
    path = (
        EVIDENCE_ROOT
        / "published"
        / "acquisition-radius"
        / uid[:2]
        / f"{uid}.record"
    )
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_evidence_read_failed"
        ) from exc
    if len(payload) != item.object_size_bytes:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_evidence_size_mismatch"
        )
    digest = sha256(payload).hexdigest()
    if digest != item.object_sha256 or digest != item.canonical_record_sha256:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_evidence_hash_mismatch"
        )
    try:
        canonical_record = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_evidence_utf8_invalid"
        ) from exc
    return VerifiedEvidenceRecord(
        evidence_uid=item.evidence_uid,
        canonical_record=canonical_record,
    )


def _manifest_identity_sha256(manifests: list[_EvidenceManifest]) -> str:
    return sha256(
        "\n".join(
            "\0".join(
                (
                    item.evidence_uid,
                    item.canonical_record_sha256,
                    item.object_sha256,
                    str(item.object_size_bytes),
                    str(item.cursor_start_byte_offset),
                    str(item.batch_record_ordinal),
                )
            )
            for item in manifests
        ).encode("utf-8")
    ).hexdigest()


def _terminal_identity_sha256(
    observations: list[_TerminalObservation],
    terminal_evidence: Mapping[str, _EvidenceManifest],
) -> str:
    return sha256(
        "\n".join(
            "\0".join(
                (
                    item.observation_id,
                    item.evidence_uid,
                    terminal_evidence[item.evidence_uid].canonical_record_sha256,
                    item.lifecycle_event,
                    item.timestamp_state,
                    str(item.observed_at_utc),
                )
            )
            for item in sorted(observations, key=lambda value: value.observation_id)
        ).encode("utf-8")
    ).hexdigest()


def _resolution_identity_sha256(
    attempts: tuple[Any, ...],
    proposals: Mapping[str, Any],
) -> str:
    """Bind each candidate outcome and any exact resolution to the plan."""
    values: list[str] = []
    for attempt in sorted(attempts, key=lambda item: item.observation_id):
        proposal = proposals.get(attempt.observation_id)
        values.append(
            "\0".join(
                (
                    str(attempt.observation_id),
                    str(attempt.evidence_uid),
                    str(attempt.outcome),
                    str(attempt.resolution_input_sha256 or ""),
                    str(proposal.session_identity_key) if proposal is not None else "",
                    str(proposal.exact_principal_key) if proposal is not None else "",
                )
            )
        )
    return sha256("\n".join(values).encode("utf-8")).hexdigest()


def _scan_authorized_identity_evidence(
    scope: _Scope,
    terminal_evidence: Mapping[str, _EvidenceManifest],
    *,
    conn: Any | None = None,
) -> tuple[list[_EvidenceManifest], dict[str, VerifiedEvidenceRecord], dict[str, Any]]:
    contract = load_reconciliation_contract()
    discovery = dict(contract["identity_evidence_discovery"])
    maximum_manifests = int(discovery["maximum_manifests_per_run"])
    maximum_bytes = int(discovery["maximum_bytes_per_run"])
    manifests: list[_EvidenceManifest] = []
    verified_access_accepts: dict[str, VerifiedEvidenceRecord] = {}
    after: tuple[int, int, str] | None = None
    while True:
        if conn is None:
            page = _read_evidence_page(scope, after)
        else:
            with conn.cursor() as cur:
                page = _select_evidence_page(cur, scope, after)
        if not page:
            break
        manifests.extend(page)
        total_bytes = sum(item.object_size_bytes for item in manifests)
        if len(manifests) > maximum_manifests or total_bytes > maximum_bytes:
            raise RadiusReconciliationProductionControlError(
                "production_reconciliation_identity_scan_limit_exceeded"
            )
        for item in page:
            record = _read_verified_record(item)
            if (
                parse_database_compatible_record(record.canonical_record).packet_type
                == ACCESS_ACCEPT_PACKET_TYPE
            ):
                verified_access_accepts[item.evidence_uid] = record
        last = page[-1]
        after = (
            last.cursor_start_byte_offset,
            last.batch_record_ordinal,
            last.evidence_uid,
        )
    if not manifests:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_authorized_corpus_missing"
        )
    manifest_by_uid = {item.evidence_uid: item for item in manifests}
    if len(manifest_by_uid) != len(manifests):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_evidence_duplicate"
        )
    if set(terminal_evidence) - set(manifest_by_uid):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_observation_corpus_missing"
        )
    return manifests, verified_access_accepts, {
        "manifest_count": len(manifests),
        "manifest_bytes": sum(item.object_size_bytes for item in manifests),
        "manifest_identity_sha256": _manifest_identity_sha256(manifests),
        "selected_access_accept_count": len(verified_access_accepts),
        "selected_access_accept_sha256": _manifest_identity_sha256(
            [manifest_by_uid[uid] for uid in sorted(verified_access_accepts)]
        ),
    }


def _build_batches(
    scope: _Scope,
    *,
    conn: Any | None = None,
) -> tuple[list[dict[str, Any]], list[tuple[Any, tuple[Any, ...]]], dict[str, Any]]:
    if conn is None:
        with _connect() as local_conn:
            with local_conn.cursor() as cur:
                cur.execute("set transaction read only")
            result = _build_batches(scope, conn=local_conn)
            local_conn.rollback()
        return result
    with conn.cursor() as cur:
        terminal_evidence, observations = _select_terminal_inventory(cur, scope)
    manifests, verified_access_accepts, discovery = (
        _scan_authorized_identity_evidence(scope, terminal_evidence, conn=conn)
    )
    manifest_by_uid = {item.evidence_uid: item for item in manifests}
    contract = load_reconciliation_contract()
    observations_by_offset: dict[int, list[_TerminalObservation]] = defaultdict(list)
    for item in observations:
        observations_by_offset[item.cursor_start_byte_offset].append(item)
    built: list[dict[str, Any]] = []
    internal: list[tuple[Any, tuple[Any, ...]]] = []
    with conn.cursor() as cur:
        cur.execute("set local role adlog_radius_accounting_worker")

        def exact_lookup(organization: str, distinguished_name: str) -> str | None:
            cur.execute(
                "select sli_radius_resolve_principal_key(%s,%s) as exact_principal_key",
                (organization, distinguished_name),
            )
            row = cur.fetchone()
            return (
                str(row["exact_principal_key"])
                if row and row["exact_principal_key"] is not None
                else None
            )

        for offset in sorted(observations_by_offset):
            terminal_manifests = [
                terminal_evidence[item.evidence_uid]
                for item in observations_by_offset[offset]
            ]
            terminal_uids = {item.evidence_uid for item in terminal_manifests}
            verified_terminal = {
                item.evidence_uid: _read_verified_record(item)
                for item in terminal_manifests
            }
            identity_manifests = [
                *terminal_manifests,
                *(
                    manifest_by_uid[evidence_uid]
                    for evidence_uid in sorted(verified_access_accepts)
                    if evidence_uid not in terminal_uids
                ),
            ]
            if (
                len(identity_manifests)
                > int(contract["maximum_evidence_records_per_run"])
                or sum(item.object_size_bytes for item in identity_manifests)
                > int(contract["maximum_evidence_bytes_per_run"])
            ):
                raise RadiusReconciliationProductionControlError(
                    "production_reconciliation_evidence_batch_limit_exceeded"
                )
            batch = build_exact_reconciliation_batch(
                evidence_records=tuple(
                    verified_terminal.get(item.evidence_uid)
                    or verified_access_accepts[item.evidence_uid]
                    for item in identity_manifests
                ),
                terminal_observations=tuple(
                    ImmutableTerminalObservation(
                        observation_id=item.observation_id,
                        evidence_uid=item.evidence_uid,
                        lifecycle_event=item.lifecycle_event,
                        timestamp_state=item.timestamp_state,
                        observed_at_utc=item.observed_at_utc,
                    )
                    for item in observations_by_offset[offset]
                ),
                source_instance_id=scope.source_instance_id,
                organization_fqdn=scope.organization_fqdn,
                source_timezone_id="N. Central Asia Standard Time",
                source_utc_offset_minutes=420,
                exact_lookup=exact_lookup,
            )
            attempts = build_reconciliation_attempts(
                batch.candidates,
                batch.proposals,
                evidence_corpus_sha256=batch.evidence_corpus_sha256,
                resolver_contract_id=RESOLVER_CONTRACT_ID,
            )
            if len(attempts) != len(batch.candidates):
                raise RadiusReconciliationProductionControlError(
                    "production_reconciliation_attempt_count_mismatch"
                )
            projected_count = sum(item.outcome == "projected" for item in attempts)
            still_unresolved_count = sum(
                item.outcome == "still_unresolved" for item in attempts
            )
            built.append(
                {
                    "evidence_record_count": batch.evidence_record_count,
                    "terminal_receipt_count": len(batch.candidates),
                    "access_accept_count": batch.access_accept_count,
                    "unresolved_access_accept_count": batch.unresolved_access_accept_count,
                    "projected_count": projected_count,
                    "still_unresolved_count": still_unresolved_count,
                    "evidence_corpus_sha256": batch.evidence_corpus_sha256,
                    "attempt_set_sha256": sha256(
                        "\n".join(sorted(item.attempt_key for item in attempts)).encode("utf-8")
                    ).hexdigest(),
                    "resolution_identity_sha256": _resolution_identity_sha256(
                        attempts, batch.proposals
                    ),
                }
            )
            internal.append((batch, attempts))
        cur.execute("reset role")
    if sum(item["terminal_receipt_count"] for item in built) != len(observations):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_terminal_receipt_coverage_invalid"
        )
    return built, internal, {
        **discovery,
        "terminal_identity_sha256": _terminal_identity_sha256(
            observations, terminal_evidence
        ),
    }


def _migration_state(migrations: Mapping[int, bool], baseline: Mapping[str, Any]) -> str:
    core = (62, 63, 64, 65)
    applied_core = tuple(version for version in core if migrations[version])
    expected_prefix = core[: len(applied_core)]
    if applied_core != expected_prefix:
        return "inconsistent"
    components_absent = not any(
        bool(baseline[key])
        for key in ("attempts_table", "overlays_table", "writer_role")
    )
    components_present = all(
        bool(baseline[key])
        for key in ("attempts_table", "overlays_table", "writer_role")
    )
    if migrations[65] != components_present:
        return "inconsistent"
    if migrations[80] and not migrations[65]:
        return "inconsistent"
    if migrations[80] and components_present:
        return "applied"
    return "resumable"


def _authorized_reconciliation_blockers(
    batches: list[dict[str, Any]],
) -> list[str]:
    counts = tuple(int(item["terminal_receipt_count"]) for item in batches)
    if len(batches) != len(AUTHORIZED_BATCH_RECEIPT_COUNTS):
        return ["production_reconciliation_batch_scope_invalid"]
    if counts != AUTHORIZED_BATCH_RECEIPT_COUNTS:
        return ["production_reconciliation_batch_scope_invalid"]
    if sum(counts) != AUTHORIZED_TERMINAL_RECEIPT_COUNT:
        return ["production_reconciliation_terminal_scope_invalid"]
    if any(
        int(item["projected_count"]) < 0
        or int(item["still_unresolved_count"]) < 0
        or (
            int(item["projected_count"])
            + int(item["still_unresolved_count"])
            != int(item["terminal_receipt_count"])
        )
        for item in batches
    ):
        return ["production_reconciliation_partial_count_invalid"]
    if not any(int(item["projected_count"]) for item in batches):
        return ["production_reconciliation_no_exact_projection"]
    return []


def _validate_disposable_acceptance(path: Path) -> dict[str, str]:
    output = path.resolve()
    if not output.is_file():
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_disposable_acceptance_required"
        )
    try:
        value = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_disposable_acceptance_invalid"
        ) from exc
    acceptance = dict(value.get("acceptance") or {}) if isinstance(value, dict) else {}
    if not (
        isinstance(value, dict)
        and value.get("status") == "passed"
        and value.get("forward_sha256") == sha256(MIGRATIONS[65].read_bytes()).hexdigest()
        and value.get("rollback_sha256")
        == sha256(RECONCILIATION_ROLLBACKS[65].read_bytes()).hexdigest()
        and value.get("projection_forward_sha256")
        == sha256(MIGRATIONS[80].read_bytes()).hexdigest()
        and value.get("projection_rollback_sha256")
        == sha256(RECONCILIATION_ROLLBACKS[80].read_bytes()).hexdigest()
        and value.get("production_database_changed") is False
        and value.get("radius_source_contacted") is False
        and value.get("runtime_enabled") is False
        and value.get("autostart_enabled") is False
        and value.get("disposable_cluster_removed") is True
        and int(dict(value.get("database") or {}).get("server_version_num") or 0) // 10000 == 18
        and all(
            acceptance.get(key) is True
            for key in (
                "original_rows_unchanged",
                "writer_role_restricted_nologin",
                "original_observation_update_denied",
                "terminal_receipt_update_denied",
                "evidence_delete_denied",
                "append_only_output_update_denied",
                "consumer_overlay_update_denied",
                "outer_transaction_postcondition_readable",
                "conflicting_second_resolution_blocked",
                "reader_rollback_guarded_after_evidence",
                "rollback_guarded_after_evidence",
            )
        )
        and acceptance.get("attempt_counts_total_projected_unresolved") == [2, 1, 1]
        and int(acceptance.get("projected_session_count") or 0) == 1
    ):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_disposable_acceptance_invalid"
        )
    return {"evidence_sha256": sha256(output.read_bytes()).hexdigest()}


def build_plan(
    *,
    disposable_acceptance: Path = DEFAULT_DISPOSABLE_ACCEPTANCE,
) -> dict[str, Any]:
    disposable = _validate_disposable_acceptance(disposable_acceptance)
    scope, baseline, migrations = _scope_and_baseline()
    batches, _internal, discovery = _build_batches(scope)
    blockers: list[str] = []
    migration_state = _migration_state(migrations, baseline)
    if migration_state == "inconsistent":
        blockers.append("production_reconciliation_migration_state_inconsistent")
    if not migrations[65] and not baseline["migration_role_can_create_role"]:
        blockers.append(
            "production_reconciliation_migration_role_create_role_required"
        )
    blockers.extend(_authorized_reconciliation_blockers(batches))
    if baseline["nonterminal_deliveries"] != 0:
        blockers.append("production_reconciliation_nonterminal_delivery_present")
    if baseline["attempt_count"] != 0 or baseline["overlay_count"] != 0:
        blockers.append("production_reconciliation_existing_output_present")
    if baseline["terminal_unresolved_receipts"] != sum(
        item["terminal_receipt_count"] for item in batches
    ):
        blockers.append("production_reconciliation_terminal_receipt_count_mismatch")
    payload = {
        "plan_schema_version": 1,
        "status": "ready" if not blockers else "blocked",
        "baseline": baseline,
        "migration_state": migration_state,
        "migration_sha256": {
            str(version): sha256(path.read_bytes()).hexdigest()
            for version, path in MIGRATIONS.items()
        },
        "disposable_acceptance": disposable,
        "reconciliation": {
            "resolver_contract_id": RESOLVER_CONTRACT_ID,
            "batches": batches,
            "terminal_receipt_count": sum(
                item["terminal_receipt_count"] for item in batches
            ),
            "terminal_candidate_count": sum(
                item["terminal_receipt_count"] for item in batches
            ),
            "projected_count": sum(item["projected_count"] for item in batches),
            "still_unresolved_count": sum(
                item["still_unresolved_count"] for item in batches
            ),
            "unsupported_inferred_links": 0,
            "identity_evidence_discovery": discovery,
        },
        "blockers": blockers,
        "source_contacted": False,
        "production_database_changed": False,
        "cursor_changed": False,
        "queue_or_lease_changed": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
    }
    payload["plan_identity_sha256"] = _plan_identity(payload)
    return payload


def _plan_identity(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload.pop("plan_identity_sha256", None)
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_plan_binding(plan: Mapping[str, Any], current: Mapping[str, Any]) -> None:
    if int(plan.get("plan_schema_version") or 0) != 1:
        raise RadiusReconciliationProductionControlError(
            "production_apply_without_plan_binding"
        )
    baseline = dict(plan.get("baseline") or {})
    expected = {
        "source_instance_sha256",
        "cursor_revision",
        "observations",
        "terminal_unresolved_receipts",
        "nonterminal_deliveries",
        "attempts_table",
        "overlays_table",
        "writer_role",
        "migration_role_can_create_role",
        "attempt_count",
        "overlay_count",
    }
    if set(baseline) != expected or dict(current) != baseline:
        raise RadiusReconciliationProductionControlError(
            "production_apply_without_plan_binding"
        )


def _validate_plan(plan: Mapping[str, Any], fresh: Mapping[str, Any]) -> None:
    validate_plan_binding(plan, dict(fresh["baseline"]))
    if (
        plan.get("status") != "ready"
        or _plan_identity(plan) != plan.get("plan_identity_sha256")
        or fresh.get("plan_identity_sha256") != plan.get("plan_identity_sha256")
    ):
        raise RadiusReconciliationProductionControlError(
            "production_apply_without_plan_binding"
        )


def _validated_batches_after_migration(
    plan: Mapping[str, Any],
    scope: _Scope,
    *,
    conn: Any | None = None,
) -> list[tuple[Any, tuple[Any, ...]]]:
    summary, batches, discovery = _build_batches(scope, conn=conn)
    expected = dict(plan.get("reconciliation") or {})
    actual = {
        "resolver_contract_id": RESOLVER_CONTRACT_ID,
        "batches": summary,
        "terminal_receipt_count": sum(
            item["terminal_receipt_count"] for item in summary
        ),
        "terminal_candidate_count": sum(
            item["terminal_receipt_count"] for item in summary
        ),
        "projected_count": sum(item["projected_count"] for item in summary),
        "still_unresolved_count": sum(
            item["still_unresolved_count"] for item in summary
        ),
        "unsupported_inferred_links": 0,
        "identity_evidence_discovery": discovery,
    }
    if actual != expected or _authorized_reconciliation_blockers(summary):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_plan_input_drift"
        )
    return batches


def _lock_and_validate_plan_inputs(
    conn: Any,
    *,
    scope: _Scope,
    plan: Mapping[str, Any],
    migrations: Mapping[int, bool],
) -> None:
    baseline = dict(plan["baseline"])
    with conn.cursor() as cur:
        cur.execute(
            """
            select revision
            from acquisition_stream_cursors
            where source_instance_id=%s
              and stream_id=%s
              and transport_binding=%s
            for share
            """,
            (
                scope.source_instance_id,
                RADIUS_ACCOUNTING_STREAM_ID,
                RADIUS_ACCOUNTING_TRANSPORT_BINDING,
            ),
        )
        cursor = cur.fetchone()
        if cursor is None or int(cursor["revision"]) != int(
            baseline["cursor_revision"]
        ):
            raise RadiusReconciliationProductionControlError(
                "production_reconciliation_plan_input_drift"
            )
        cur.execute(
            """
            select
              (
                select count(*)::bigint
                from radius_accounting_session_observations observation
                join core_evidence_manifests evidence
                  on evidence.evidence_uid=observation.evidence_uid
                where evidence.source_instance_id=%s
                  and evidence.stream_id=%s
                  and evidence.transport_binding=%s
              ) as observations,
              (
                select count(*)::bigint
                from radius_session_projection_receipts receipt
                join radius_accounting_session_observations observation
                  on observation.observation_id=receipt.observation_id
                join core_evidence_manifests evidence
                  on evidence.evidence_uid=observation.evidence_uid
                where evidence.source_instance_id=%s
                  and evidence.stream_id=%s
                  and evidence.transport_binding=%s
                  and receipt.outcome='identity_unresolved'
              ) as terminal_unresolved_receipts,
              (
                select count(*)::bigint
                from acquisition_delivery_outbox delivery
                where delivery.subscription_id=%s
                  and delivery.delivery_state in ('queued','leased')
              ) as nonterminal_deliveries,
              to_regclass('radius_session_reconciliation_attempts') is not null as attempts_table,
              to_regclass('radius_session_identity_overlays') is not null as overlays_table,
              to_regrole('adlog_radius_session_reconciliation_writer') is not null as writer_role,
              (select rolcreaterole from pg_roles where rolname=current_user)
                as migration_role_can_create_role
            """,
            (
                scope.source_instance_id,
                RADIUS_ACCOUNTING_STREAM_ID,
                RADIUS_ACCOUNTING_TRANSPORT_BINDING,
                scope.source_instance_id,
                RADIUS_ACCOUNTING_STREAM_ID,
                RADIUS_ACCOUNTING_TRANSPORT_BINDING,
                scope.subscription_id,
            ),
        )
        current = dict(cur.fetchone())
    for key in (
        "observations",
        "terminal_unresolved_receipts",
        "nonterminal_deliveries",
        "attempts_table",
        "overlays_table",
        "writer_role",
        "migration_role_can_create_role",
    ):
        if current[key] != baseline[key]:
            raise RadiusReconciliationProductionControlError(
                "production_reconciliation_plan_input_drift"
            )
    with conn.cursor() as cur:
        cur.execute(
            """
            select version,name
            from schema_migrations
            where version between 61 and 80
            order by version
            """
        )
        locked_migrations = _migration_markers(list(cur.fetchall()))
    if dict(locked_migrations) != dict(migrations):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_plan_input_drift"
        )
    if bool(baseline["attempts_table"]) and bool(baseline["overlays_table"]):
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                  (
                    select count(*)::bigint
                    from radius_session_reconciliation_attempts attempt
                    join radius_accounting_session_observations observation
                      on observation.observation_id=attempt.observation_id
                    join core_evidence_manifests evidence
                      on evidence.evidence_uid=observation.evidence_uid
                    where evidence.source_instance_id=%s
                      and evidence.stream_id=%s
                      and evidence.transport_binding=%s
                  ) as attempt_count,
                  (
                    select count(*)::bigint
                    from radius_session_identity_overlays overlay
                    join radius_accounting_session_observations observation
                      on observation.observation_id=overlay.observation_id
                    join core_evidence_manifests evidence
                      on evidence.evidence_uid=observation.evidence_uid
                    where evidence.source_instance_id=%s
                      and evidence.stream_id=%s
                      and evidence.transport_binding=%s
                  ) as overlay_count
                """,
                (
                    scope.source_instance_id,
                    RADIUS_ACCOUNTING_STREAM_ID,
                    RADIUS_ACCOUNTING_TRANSPORT_BINDING,
                    scope.source_instance_id,
                    RADIUS_ACCOUNTING_STREAM_ID,
                    RADIUS_ACCOUNTING_TRANSPORT_BINDING,
                ),
            )
            locked_outputs = dict(cur.fetchone())
        for key in ("attempt_count", "overlay_count"):
            if int(locked_outputs[key]) != int(baseline[key]):
                raise RadiusReconciliationProductionControlError(
                    "production_reconciliation_plan_input_drift"
                )
    with conn.cursor() as cur:
        terminal_evidence, observations = _select_terminal_inventory(cur, scope)
    _manifests, _access_accepts, discovery = _scan_authorized_identity_evidence(
        scope, terminal_evidence, conn=conn
    )
    discovery = {
        **discovery,
        "terminal_identity_sha256": _terminal_identity_sha256(
            observations, terminal_evidence
        ),
    }
    expected = dict(plan.get("reconciliation") or {}).get(
        "identity_evidence_discovery"
    )
    if discovery != expected:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_plan_input_drift"
        )


def _apply_migrations_in_transaction(
    conn: Any,
    state: str,
    migrations: Mapping[int, bool],
) -> list[int]:
    if state not in {"resumable", "applied"}:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_migration_state_inconsistent"
        )
    applied: list[int] = []
    with conn.cursor() as cur:
        for version, path in MIGRATIONS.items():
            if migrations[version]:
                continue
            cur.execute(_migration_sql_without_outer_transaction(path))
            _restore_session_role(conn)
            applied.append(version)
    return applied


def _migration_sql_without_outer_transaction(path: Path) -> str:
    """Use a reviewed migration body inside the plan-bound outer transaction."""
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    executable = [
        index
        for index, line in enumerate(lines)
        if line.strip() and not line.lstrip().startswith("--")
    ]
    if (
        len(executable) < 2
        or lines[executable[0]].strip().lower() != "begin;"
        or lines[executable[-1]].strip().lower() != "commit;"
    ):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_migration_transaction_boundary_invalid"
        )
    return "\n".join(
        line
        for index, line in enumerate(lines)
        if index not in {executable[0], executable[-1]}
    )


def _projection_requests(
    *, scope: _Scope,
    observation_ids: list[str],
    conn: Any,
) -> tuple[ReconciledRadiusProjection, ...]:
    if not observation_ids:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_projection_request_empty"
        )
    with conn.cursor() as cur:
        cur.execute(
            """
            select delivery.delivery_id,overlay.session_identity_key
            from acquisition_delivery_outbox delivery
            join radius_session_identity_overlays overlay
              on overlay.observation_id=delivery.observation_id
            where delivery.subscription_id=%s
              and delivery.delivery_state='delivered'
              and delivery.observation_id=any(%s::uuid[])
            order by delivery.delivery_id
            """,
            (scope.subscription_id, observation_ids),
        )
        rows = list(cur.fetchall())
    if len(rows) != len(observation_ids):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_delivered_overlay_required"
        )
    return tuple(
        ReconciledRadiusProjection(
            delivery_id=int(row["delivery_id"]),
            session_identity_key=str(row["session_identity_key"]),
        )
        for row in rows
    )


def _restore_session_role(conn: Any) -> None:
    """Undo a nested worker/consumer SET LOCAL ROLE before the next phase."""
    with conn.cursor() as cur:
        cur.execute("reset role")


def _postcondition(
    conn: Any,
    *,
    observation_ids: list[str],
) -> dict[str, int]:
    """Verify only the immutable plan membership inside the write transaction."""
    if len(observation_ids) != AUTHORIZED_TERMINAL_RECEIPT_COUNT:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_postcondition_scope_invalid"
        )
    with conn.cursor() as cur:
        cur.execute(
            """
            select
              (
                select count(*)::bigint
                from radius_session_reconciliation_attempts attempt
                where attempt.observation_id=any(%s::uuid[])
              ) as attempt_count,
              (
                select count(*) filter(where attempt.outcome='projected')::bigint
                from radius_session_reconciliation_attempts attempt
                where attempt.observation_id=any(%s::uuid[])
              ) as projected_attempt_count,
              (
                select count(*) filter(where attempt.outcome='still_unresolved')::bigint
                from radius_session_reconciliation_attempts attempt
                where attempt.observation_id=any(%s::uuid[])
              ) as still_unresolved_attempt_count,
              (
                select count(*)::bigint
                from radius_session_identity_overlays overlay
                where overlay.observation_id=any(%s::uuid[])
              ) as overlay_count,
              (
                select count(*)::bigint
                from radius_vpn_session_projection projection
                where exists (
                  select 1
                  from radius_session_identity_overlays overlay
                  where overlay.observation_id=any(%s::uuid[])
                    and overlay.session_identity_key=projection.session_identity_key
                )
              ) as projection_row_count,
              (
                select count(*)::bigint
                from radius_accounting_session_observations observation
                where observation.observation_id=any(%s::uuid[])
                  and observation.identity_state='unresolved'
              ) as original_unresolved_observation_count,
              (
                select count(*)::bigint
                from radius_session_projection_receipts receipt
                where receipt.observation_id=any(%s::uuid[])
                  and receipt.outcome='identity_unresolved'
              ) as original_unresolved_receipt_count
            """,
            (
                observation_ids,
                observation_ids,
                observation_ids,
                observation_ids,
                observation_ids,
                observation_ids,
                observation_ids,
            ),
        )
        row = {key: int(value) for key, value in dict(cur.fetchone()).items()}
    return row


def apply(
    plan: Mapping[str, Any],
    *,
    disposable_acceptance: Path = DEFAULT_DISPOSABLE_ACCEPTANCE,
) -> dict[str, Any]:
    fresh = build_plan(disposable_acceptance=disposable_acceptance)
    _validate_plan(plan, fresh)
    scope, _baseline, migrations = _scope_and_baseline()
    migration_state = _migration_state(migrations, _baseline)
    _validate_disposable_acceptance(disposable_acceptance)
    reconciliation_receipts: list[dict[str, int]] = []
    with _connect() as conn, conn.transaction():
        _lock_and_validate_plan_inputs(
            conn, scope=scope, plan=plan, migrations=migrations
        )
        applied_migrations = _apply_migrations_in_transaction(
            conn, migration_state, migrations
        )
        batches = _validated_batches_after_migration(plan, scope, conn=conn)
        observation_ids = [
            attempt.observation_id
            for _batch, attempts in batches
            for attempt in attempts
        ]
        for batch, attempts in batches:
            receipts = write_reconciliation_attempts(
                conn,
                attempts,
                batch.proposals,
            )
            if len(receipts) != len(attempts) or any(
                (item.outcome == "projected") != item.overlay_created
                or item.outcome not in {"projected", "still_unresolved"}
                for item in receipts
            ):
                raise RadiusReconciliationProductionControlError(
                    "production_reconciliation_overlay_write_failed"
                )
            _restore_session_role(conn)
            projected_observation_ids = [
                item.observation_id for item in receipts if item.outcome == "projected"
            ]
            if projected_observation_ids:
                requests = _projection_requests(
                    scope=scope,
                    observation_ids=projected_observation_ids,
                    conn=conn,
                )
                rebuild_reconciled_radius_projections(
                    conn,
                    subscription_id=scope.subscription_id,
                    projections=requests,
                )
                _restore_session_role(conn)
            reconciliation_receipts.append(
                {
                    "attempt_count": len(receipts),
                    "overlay_count": sum(item.overlay_created for item in receipts),
                    "projected_count": len(projected_observation_ids),
                    "still_unresolved_count": len(receipts)
                    - len(projected_observation_ids),
                }
            )
        postcondition = _postcondition(conn, observation_ids=observation_ids)
        expected_candidates = int(plan["reconciliation"]["terminal_candidate_count"])
        expected_projected = int(plan["reconciliation"]["projected_count"])
        expected_unresolved = int(plan["reconciliation"]["still_unresolved_count"])
        if (
            postcondition["attempt_count"] != expected_candidates
            or postcondition["projected_attempt_count"] != expected_projected
            or postcondition["still_unresolved_attempt_count"] != expected_unresolved
            or postcondition["overlay_count"] != expected_projected
            or postcondition["original_unresolved_observation_count"]
            != expected_candidates
            or postcondition["original_unresolved_receipt_count"] != expected_candidates
            or postcondition["projection_row_count"] < 1
        ):
            raise RadiusReconciliationProductionControlError(
                "production_reconciliation_postcondition_failed"
            )
    return {
        "status": "passed",
        "applied_migrations": applied_migrations,
        "reconciliation": {
            "batches": reconciliation_receipts,
            "attempt_count": sum(item["attempt_count"] for item in reconciliation_receipts),
            "overlay_count": sum(item["overlay_count"] for item in reconciliation_receipts),
            "terminal_candidate_count": expected_candidates,
            "projected_count": expected_projected,
            "still_unresolved_count": expected_unresolved,
            "projection_row_count": postcondition["projection_row_count"],
            "original_unresolved_observation_count": postcondition[
                "original_unresolved_observation_count"
            ],
            "original_unresolved_receipt_count": postcondition[
                "original_unresolved_receipt_count"
            ],
            "unsupported_inferred_links": 0,
        },
        "cursor_revision_before": plan["baseline"]["cursor_revision"],
        "cursor_revision_after_locked_write": plan["baseline"]["cursor_revision"],
        "source_contacted": False,
        "production_database_changed": True,
        "queue_or_lease_changed": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
    }


def _read_plan(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusReconciliationProductionControlError(
            "production_apply_without_plan_binding"
        ) from exc
    if not isinstance(value, dict):
        raise RadiusReconciliationProductionControlError(
            "production_apply_without_plan_binding"
        )
    return value


def _write_output(path: Path, payload: Mapping[str, Any]) -> None:
    """Write a new plan artifact without overwriting prior evidence."""
    output = path.resolve()
    if (ROOT / "artifacts" / "g11a3").resolve() not in output.parents:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_output_path_invalid"
        )
    if output.exists():
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_output_already_exists"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    _exclusive_json_create(output, payload)


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n"
    ).encode("utf-8")


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _exclusive_json_create(output: Path, payload: Mapping[str, Any]) -> None:
    try:
        descriptor = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError as exc:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_output_already_exists"
        ) from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(_json_bytes(payload))
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_parent(output.parent)


def _atomic_json_finalize(
    output: Path,
    payload: Mapping[str, Any],
    *,
    reservation_id: str,
) -> None:
    temporary = output.with_name(f".{output.name}.{reservation_id}.tmp")
    _exclusive_json_create(temporary, payload)
    temporary.replace(output)
    _fsync_parent(output.parent)


def _finalize_apply_output(
    path: Path,
    payload: Mapping[str, Any],
    *,
    reservation_id: str,
) -> None:
    """Atomically replace only evidence reserved by this apply invocation."""
    output = path.resolve()
    if not output.exists():
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_apply_evidence_missing"
        )
    try:
        reserved = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_apply_evidence_invalid"
        ) from exc
    if (
        not isinstance(reserved, dict)
        or reserved.get("status") != "apply_started"
        or reserved.get("reservation_id") != reservation_id
    ):
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_apply_evidence_not_reserved"
        )
    finalized = {
        **dict(payload),
        "plan_sha256": reserved["plan_sha256"],
        "reservation_id": reservation_id,
    }
    _atomic_json_finalize(output, finalized, reservation_id=reservation_id)


def _apply_failure_payload(error: Exception) -> dict[str, Any]:
    code = (
        str(error)
        if isinstance(error, RadiusReconciliationProductionControlError)
        else "production_reconciliation_apply_failed"
    )
    return {
        "status": "failed",
        "failure_code": code,
        "mutation_state": "unknown_after_apply_exception",
        "production_database_changed": "unknown",
        "source_contacted": False,
        "queue_or_lease_changed": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
    }


def _prepare_apply_output(path: Path, plan: Mapping[str, Any]) -> tuple[Path, str]:
    """Reserve durable, sanitized evidence before an irreversible apply."""
    output = path.resolve()
    if (ROOT / "artifacts" / "g11a3").resolve() not in output.parents:
        raise RadiusReconciliationProductionControlError(
            "production_reconciliation_output_path_invalid"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    reservation_id = secrets.token_hex(16)
    _exclusive_json_create(
        output,
        {
            "status": "apply_started",
            "reservation_id": reservation_id,
            "plan_sha256": sha256(
                json.dumps(plan, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest(),
            "mutation_state": "not_started_or_unknown",
            "production_database_changed": "unknown",
        },
    )
    return output, reservation_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("plan", "apply"), default="plan")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--disposable-acceptance",
        type=Path,
        default=DEFAULT_DISPOSABLE_ACCEPTANCE,
    )
    parser.add_argument("--confirmation", default="")
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args(argv)
    if args.load_supervisor_environment:
        _load_environment()
    if args.action == "plan":
        result = build_plan(disposable_acceptance=args.disposable_acceptance)
        if args.output is not None:
            _write_output(args.output, result)
    else:
        if (
            args.confirmation != CONFIRMATION
            or args.plan is None
            or args.output is None
        ):
            raise RadiusReconciliationProductionControlError(
                "production_apply_without_plan_binding"
            )
        plan = _read_plan(args.plan.resolve())
        _output, reservation_id = _prepare_apply_output(args.output, plan)
        try:
            result = apply(
                plan,
                disposable_acceptance=args.disposable_acceptance,
            )
        except Exception as exc:
            _finalize_apply_output(
                args.output,
                _apply_failure_payload(exc),
                reservation_id=reservation_id,
            )
            raise
        _finalize_apply_output(
            args.output,
            result,
            reservation_id=reservation_id,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

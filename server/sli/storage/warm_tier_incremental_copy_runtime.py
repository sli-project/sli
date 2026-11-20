#!/usr/bin/env python3
# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``warm_tier_incremental_copy_runtime`` at call time.
"""Publish one exact Stage 7 batch to the isolated warm tier.

The source PostgreSQL transaction is REPEATABLE READ / READ ONLY.  The command
accepts only the exact batch frozen by ``warm_tier_incremental_plan.py`` and
re-verifies every canonical archive block before writing ClickHouse.  Session
boundary events use the accepted append-only lifecycle overlay; prior session
rows and event placements are never updated or deleted.

The published ClickHouse batch is append-only.  A single INSERT publishes all
placement rows, and the immutable manifest row is written last.  A retry can
finalize a fully written batch after an interruption, but partial or mismatched
state fails closed.  This command never changes routing and never deletes hot
PostgreSQL rows.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.sources.source_capture_continuity import (
    load_verified_lifecycle_context,  # noqa: E402
)
from server.sli.storage.storage_lifecycle_bounded_io import (  # noqa: E402
    iter_json_lines,
    read_json,
)
from server.sli.storage.storage_lifecycle_io import (  # noqa: E402
    CONTAINER,
    CREATE_PLACEMENT_INPUT,
    DATABASE,
    _connect,
    _container_port,
    _drop_database,
    _http_insert_json_rows,
    _http_query,
)
from server.sli.storage.storage_v2_models import (  # noqa: E402
    canonical_json_bytes,
    event_source_core_sha256,
)
from server.sli.storage.warm_session_lifecycle import (  # noqa: E402
    AuthenticationEvidence,
    AuthenticationSessionObservation,
    ContinuityDeclaration,
    SessionBoundary,
    SessionRevision,
    assemble_authentication_sessions,
    legacy_base_revision,
    plan_revision,
)
from server.sli.storage.warm_session_lifecycle import (
    load_contract as load_session_contract,
)
from server.sli.storage.warm_tier_incremental_plan_runtime import (  # noqa: E402
    _build_declaration_progress,
    _freeze_descriptor_lifecycle,
)
from server.source_packs.windows_ad_dc import (  # noqa: E402
    event_ids_for_analysis_family,
)

DEFAULT_PLAN = (
    ROOT
    / "artifacts"
    / "stage7"
    / "evidence"
    / "warm-tier-incremental-plan.json"
)
EVIDENCE_ROOT = ROOT / "artifacts" / "stage7" / "evidence"
CONFIRMATION = "START-STAGE7-WARM-INCREMENTAL-COPY"
MAX_BATCH_ROWS = 10_000
MAX_ARCHIVE_BLOCKS = 128
MAX_ARCHIVE_COMPRESSED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_RAW_BYTES = 2 * 1024 * 1024 * 1024
# Peak memory for one archive block is bounded by this chunk size, not by
# the (possibly multi-gigabyte) compressed or decompressed block size.
ARCHIVE_STREAM_CHUNK_BYTES = 1024 * 1024
MAX_ARCHIVE_JSONL_RECORD_BYTES = 256 * 1024
SESSION_OPEN_EVENT_IDS = frozenset(event_ids_for_analysis_family("successful_logon"))
SESSION_EVENT_IDS = frozenset(
    event_ids_for_analysis_family("successful_logon")
    + event_ids_for_analysis_family("logoff")
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SESSION_SCHEMA = ROOT / "config/clickhouse/001_warm_session_lifecycle_revisions.sql"
MAX_PENDING_SESSIONS = 5_000
PENDING_SESSION_UID_BYTES = 16
PENDING_SESSION_UID_RANGE_COUNT = 256
MAX_PLAN_JSON_BYTES = 8 * 1024 * 1024
MAX_PROCESSED_LEDGER_BYTES = 32 * 1024 * 1024
MAX_PROCESSED_LEDGER_LINE_BYTES = 256 * 1024
MAX_PROCESSED_LEDGER_ROWS = 100_000
MAX_PROCESSED_DECLARATION_IDS = 1_000_000
MAX_DECLARATION_MEMBERS = 10_000
MAX_DECLARATION_IDS = 10_000
MAX_SOURCE_REFERENCES = 10_000
MAX_DERIVED_ROWS = 10_000




def _observation_evidence_references(
    observation: AuthenticationSessionObservation,
) -> tuple[tuple[int, str], ...]:
    """Return every immutable source reference carried by the fold."""

    return tuple(zip(observation.source_event_ids, observation.source_hashes)) + tuple(
        zip(
            observation.privilege_evidence_source_event_ids,
            observation.privilege_evidence_normalized_hashes,
        )
    ) + tuple(zip(
        observation.supplemental_logout_source_event_ids,
        observation.supplemental_logout_normalized_hashes,
    )) + tuple(zip(
        observation.explicit_credentials_source_event_ids,
        observation.explicit_credentials_normalized_hashes,
    ))


def _derived_output_digest(rows: list[dict[str, Any]]) -> str:
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _source_reference_digest(references: list[dict[str, Any]]) -> str:
    payload = json.dumps(references, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _derived_output_identity(row: dict[str, Any]) -> str:
    """Recompute immutable output identity from one persisted row payload."""
    identity_payload = {
        "batch_identity": row["batch_identity"],
        "candidate_identity_sha256": row["candidate_identity_sha256"],
        "policy_fingerprint": row["policy_fingerprint"],
        "derived_output_digest": row["derived_output_digest"],
        "source_reference_digest": row["source_reference_digest"],
        "manifest_digest": row["manifest_digest"],
        "continuity_declaration_scope_identity": row[
            "continuity_declaration_scope_identity"
        ],
        "continuity_declaration_sha256": row[
            "continuity_declaration_sha256"
        ],
        "payload_sha256": hashlib.sha256(
            str(row["payload_json"]).encode("utf-8")
        ).hexdigest(),
    }
    return hashlib.sha256(
        json.dumps(
            identity_payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()








CREATE_INCREMENTAL_MANIFEST = f"""
CREATE TABLE IF NOT EXISTS {DATABASE}.incremental_copy_manifest
(
 batch_identity FixedString(64),
 plan_generated_at_utc DateTime64(6,'UTC'),
 planned_rows UInt32,
 first_event_id UInt64,
 last_event_id UInt64,
 archive_identity_sha256 FixedString(64),
 selection_mode LowCardinality(String) DEFAULT 'legacy_max_event_id_v1',
 selection_lower_utc Nullable(DateTime64(6,'UTC')),
 selection_upper_utc Nullable(DateTime64(6,'UTC')),
 published_at_utc DateTime64(6,'UTC')
) ENGINE=MergeTree ORDER BY batch_identity
"""

SELECTION_MODE = "missing_placement_time_window_v2"

CREATE_SESSION_REVISION_INPUT = """
CREATE TABLE {db}.session_revision_input
(
 session_uid_hex String,revision UInt32,state String,server_id UInt16,
 domain_id UInt16,channel_id UInt16,
 logon_time_utc Nullable(DateTime64(6,'UTC')),
 logoff_time_utc Nullable(DateTime64(6,'UTC')),
 duration_s Nullable(UInt32),logon_id String,
 logon_source_id Nullable(UInt64),logoff_source_id Nullable(UInt64),
 previous_revision_sha256 Nullable(String),revision_sha256 String,
 batch_identity String,published_at_utc DateTime64(6,'UTC')
) ENGINE=MergeTree ORDER BY tuple()
"""

CREATE_SESSION_PLACEMENT_INPUT = """
CREATE TABLE {db}.session_placement_input
(
 event_id UInt64,revision UInt32,session_uid_hex String,placement String,
 lifecycle_revision_sha256 String,batch_identity String,
 published_at_utc DateTime64(6,'UTC')
) ENGINE=MergeTree ORDER BY tuple()
"""

CREATE_DERIVED_OUTPUT_INPUT = """
CREATE TABLE {db}.authentication_session_derived_output_input
(
 output_identity String,batch_identity String,candidate_identity_sha256 String,
 policy_fingerprint String,derived_output_digest String,
 source_reference_digest String,manifest_digest String,
 continuity_declaration_scope_identity String,
 continuity_declaration_sha256 String,
 source_count UInt32,observation_count UInt32,payload_json String,
 published_at_utc DateTime64(6,'UTC')
) ENGINE=MergeTree ORDER BY tuple()
"""


def _parse_utc(value: Any) -> datetime:
    text = str(value or "").strip().replace("Z", "+00:00")
    if not text:
        raise ValueError("plan timestamp is missing")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _identity(rows: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        event_id = int(row["id"])
        normalized = row["normalized_hash"]
        value = (
            bytes.fromhex(str(normalized))
            if isinstance(normalized, str)
            else bytes(normalized)
        )
        if len(value) != 32:
            raise RuntimeError(f"normalized_hash_is_not_32_bytes:{event_id}")
        digest.update(event_id.to_bytes(8, "big", signed=False))
        digest.update(value)
    return digest.hexdigest()






def _source_batch(conn: Any, frozen: dict[str, Any]) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select event.id,event.normalized_hash,event.source_core_sha256,event.event_id,
                   event.server_id,event.domain_id,event.channel_id,event.log_source_id,event.raw_log_file_id,
                   event.logon_id,event.time_created_utc,
                   channel.value as channel_value,provider.value as provider_name
            from events_v2_core event
            join storage_v2_channel channel on channel.id=event.channel_id
            left join storage_v2_provider provider on provider.id=event.provider_id
            where event.id = any(%s::bigint[])
              and event.time_created_utc < %s
              and event.time_created_utc >= %s
            order by event.id
            """,
            (
                frozen["event_ids"],
                frozen["eligibility_upper_utc"],
                frozen["warm_cutoff_utc"],
            ),
        )
        rows = [dict(row) for row in cur.fetchall()]
    if len(rows) != frozen["rows"]:
        raise RuntimeError("source_batch_row_count_changed")
    if int(rows[0]["id"]) != frozen["first_event_id"]:
        raise RuntimeError("source_batch_first_event_changed")
    if int(rows[-1]["id"]) != frozen["last_event_id"]:
        raise RuntimeError("source_batch_last_event_changed")
    if [int(row["id"]) for row in rows] != frozen["event_ids"]:
        raise RuntimeError("source_batch_event_id_set_changed")
    if _identity(rows) != frozen["identity_sha256"]:
        raise RuntimeError("source_batch_identity_changed")
    return rows


def _session_boundaries(rows: list[dict[str, Any]]) -> list[SessionBoundary]:
    result: list[SessionBoundary] = []
    for row in rows:
        event_key = int(row["event_id"])
        if event_key not in SESSION_EVENT_IDS or row["channel_value"] != "Security":
            continue
        normalized = row["normalized_hash"]
        result.append(
            SessionBoundary(
                source_event_id=int(row["id"]),
                role="open" if event_key in SESSION_OPEN_EVENT_IDS else "close",
                server_id=int(row["server_id"]),
                channel_id=int(row["channel_id"]),
                logon_id=str(row.get("logon_id") or ""),
                observed_at_utc=_parse_utc(row["time_created_utc"]),
                normalized_hash=(
                    str(normalized).lower()
                    if isinstance(normalized, str)
                    else bytes(normalized).hex()
                ),
                domain_id=int(row.get("domain_id") or 0),
            )
        )
    return result


def _archive_blocks(conn: Any, ids: list[int]) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select distinct block.archive_set_id,block.block_index,
                   block.first_event_id,block.last_event_id,block.row_count,
                   block.raw_bytes,block.compressed_bytes,block.raw_sha256,
                   block.archive_sha256,block.object_location
            from storage_v2_archive_blocks block
            join unnest(%s::bigint[]) candidate(event_id)
              on candidate.event_id between
                 block.first_event_id and block.last_event_id
            where block.archive_kind=%s and block.state=%s
            order by block.first_event_id,block.last_event_id,
                     block.archive_set_id,block.block_index
            """,
            (ids, "event", "published"),
        )
        blocks = [dict(row) for row in cur.fetchall()]
    if not blocks or len(blocks) > MAX_ARCHIVE_BLOCKS:
        raise RuntimeError("archive_block_count_out_of_bounds")
    compressed = sum(int(row["compressed_bytes"]) for row in blocks)
    raw = sum(int(row["raw_bytes"]) for row in blocks)
    if compressed > MAX_ARCHIVE_COMPRESSED_BYTES:
        raise RuntimeError("archive_compressed_bytes_out_of_bounds")
    if raw > MAX_ARCHIVE_RAW_BYTES:
        raise RuntimeError("archive_raw_bytes_out_of_bounds")
    return blocks




def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev), int(metadata.st_ino), int(metadata.st_size),
        int(metadata.st_mtime_ns), int(getattr(metadata, "st_nlink", 1)),
    )


@dataclass
class _LockedArchiveObject:
    path: Path
    handle: BinaryIO
    identity: tuple[int, int, int, int, int]

    def verify_identity(self) -> None:
        try:
            current = os.fstat(self.handle.fileno())
        except OSError as exc:
            raise RuntimeError("archive_object_identity_unavailable") from exc
        if _file_identity(current) != self.identity or int(getattr(current, "st_nlink", 1)) < 1:
            raise RuntimeError("archive_object_identity_changed")

    def close(self) -> None:
        self.handle.close()


class _ArchiveObjectLease:
    """Locked stable handles retained across the caller's commit boundary."""

    def __init__(self, objects: list[_LockedArchiveObject]) -> None:
        self.objects = objects

    def verify_identity(self) -> None:
        for item in self.objects:
            item.verify_identity()

    def close(self) -> None:
        for item in reversed(self.objects):
            item.close()




class _CompressedHashReader:
    def __init__(self, item: _LockedArchiveObject, *, declared_bytes: int, hard_bytes: int) -> None:
        self.item = item
        self.declared_bytes = declared_bytes
        self.hard_bytes = hard_bytes
        self.length = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > ARCHIVE_STREAM_CHUNK_BYTES:
            size = ARCHIVE_STREAM_CHUNK_BYTES
        chunk = self.item.handle.read(size)
        self.length += len(chunk)
        if self.length > self.hard_bytes:
            raise RuntimeError("archive_compressed_bytes_out_of_bounds")
        if self.length > self.declared_bytes:
            raise RuntimeError(f"archive_compressed_mismatch:{self.item.path.name}")
        self.digest.update(chunk)
        return chunk

    def readable(self) -> bool:
        return True


def _archive_placements(
    rows: list[dict[str, Any]],
    blocks: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    lease, placements, evidence = _open_verified_archive_placements(rows, blocks)
    try:
        return placements, evidence
    finally:
        lease.close()




def _clickhouse_json(port: int, query: str) -> list[dict[str, Any]]:
    if re.search(r"\bFORMAT\s+", query, re.IGNORECASE) is None:
        query = query.rstrip().rstrip(";") + " FORMAT JSONEachRow"
    payload = _http_query(port, query).decode("utf-8")
    if not payload.strip():
        return []
    rows: list[dict[str, Any]] = []
    for line in payload.splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "clickhouse_json_each_row_invalid:"
                + repr(line[:300])
            ) from exc
    return rows


def _session_schema_present(port: int) -> bool:
    count = _http_query(
        port,
        "SELECT count() FROM system.tables "
        f"WHERE database='{DATABASE}' AND name='session_lifecycle_revisions'",
    ).decode("utf-8").strip()
    return int(count or 0) == 1


def _derived_output_schema_present(port: int) -> bool:
    count = _http_query(
        port,
        "SELECT count() FROM system.tables "
        f"WHERE database='{DATABASE}' "
        "AND name='authentication_session_derived_outputs'",
    ).decode("utf-8").strip()
    return int(count or 0) == 1


def _apply_session_schema(port: int) -> None:
    for statement in SESSION_SCHEMA.read_text(encoding="utf-8").split(";"):
        if statement.strip():
            _http_query(port, statement.strip())
    _http_query(
        port,
        f"ALTER TABLE {DATABASE}.authentication_session_derived_outputs "
        "ADD COLUMN IF NOT EXISTS continuity_declaration_scope_identity "
        "String DEFAULT ''",
    )
    _http_query(
        port,
        f"ALTER TABLE {DATABASE}.authentication_session_derived_outputs "
        "ADD COLUMN IF NOT EXISTS continuity_declaration_sha256 "
        "FixedString(64) DEFAULT toFixedString(repeat('0',64),64)",
    )
    if not _session_schema_present(port) or not _derived_output_schema_present(port):
        raise RuntimeError("warm_session_schema_apply_failed")


def _pending_session_uid_ranges() -> tuple[tuple[str, str | None], ...]:
    """Return complete, disjoint FixedString(16) ranges in byte order."""
    suffix = "00" * (PENDING_SESSION_UID_BYTES - 1)
    return tuple(
        (f"{prefix:02x}" + suffix, f"{prefix + 1:02x}" + suffix)
        if prefix + 1 < PENDING_SESSION_UID_RANGE_COUNT
        else (f"{prefix:02x}" + suffix, None)
        for prefix in range(PENDING_SESSION_UID_RANGE_COUNT)
    )


def _pending_session_uid_range_predicate(
    lower_bound_hex: str, upper_bound_hex: str | None,
) -> str:
    predicate = f"session_uid >= unhex('{lower_bound_hex}')"
    if upper_bound_hex is not None:
        predicate += f" AND session_uid < unhex('{upper_bound_hex}')"
    return predicate




def _compatible_prior(
    pending: list[SessionRevision], boundary: SessionBoundary,
) -> SessionRevision | None:
    same = [
        item for item in pending
        if item.server_id == boundary.server_id
        and item.channel_id == boundary.channel_id
        and item.logon_id == boundary.logon_id
    ]
    if boundary.role == "close":
        compatible = [
            item for item in same
            if item.state == "open" and item.logon_time_utc is not None
            and 0 <= (boundary.observed_at_utc - item.logon_time_utc).total_seconds()
            <= 86_400
        ]
        compatible.sort(key=lambda item: item.logon_time_utc, reverse=True)
    else:
        compatible = [
            item for item in same
            if item.state == "orphan_logoff" and item.logoff_time_utc is not None
            and 0 <= (item.logoff_time_utc - boundary.observed_at_utc).total_seconds()
            <= 86_400
        ]
        compatible.sort(key=lambda item: item.logoff_time_utc)
    if len(compatible) > 1:
        raise RuntimeError("ambiguous_pending_warm_session_pair")
    if compatible:
        return compatible[0]
    # A Windows Logon ID can be reused by independent sessions (notably the
    # well-known SYSTEM LUID 0x3e7). Exact event IDs are already deduplicated by
    # event placement, so an unmatched boundary starts a distinct session.
    return None




def _existing_rows(
    port: int,
    frozen: dict[str, Any],
) -> list[dict[str, Any]]:
    exact_ids = ",".join(str(int(value)) for value in frozen["event_ids"])
    return _clickhouse_json(
        port,
        "SELECT event_id AS id,lower(hex(normalized_hash)) AS normalized_hash,"
        "archived_payload_path AS archive_file,"
        "archived_payload_line AS archive_line,placement "
        f"FROM {DATABASE}.event_placement "
        f"WHERE event_id IN ({exact_ids}) "
        "ORDER BY event_id FORMAT JSONEachRow",
    )


def _manifest_rows(port: int, identity: str) -> list[dict[str, Any]]:
    exists = int(
        _http_query(
            port,
            "SELECT count() FROM system.tables "
            f"WHERE database='{DATABASE}' "
            "AND name='incremental_copy_manifest'",
        ).decode("utf-8").strip()
        or 0
    )
    if not exists:
        return []
    return _clickhouse_json(
        port,
        "SELECT batch_identity,planned_rows,first_event_id,last_event_id,"
        "archive_identity_sha256,selection_mode,selection_lower_utc,"
        "selection_upper_utc FROM "
        f"{DATABASE}.incremental_copy_manifest "
        f"WHERE batch_identity='{identity}' FORMAT JSONEachRow",
    )


def _validate_manifest_contract(
    manifests: list[dict[str, Any]], frozen: dict[str, Any], archive: dict[str, Any],
) -> None:
    """Bind an existing cursor to this frozen batch and verified archive."""
    expected = {
        "batch_identity": str(frozen["identity_sha256"]),
        "planned_rows": int(frozen["rows"]),
        "first_event_id": int(frozen["first_event_id"]),
        "last_event_id": int(frozen["last_event_id"]),
        "archive_identity_sha256": str(archive["block_sha256_sequence"]),
        "selection_mode": str(frozen["selection_mode"]),
        "selection_lower_utc": _format_utc(frozen["selection_lower_utc"]),
        "selection_upper_utc": _format_utc(frozen["checkpoint_upper_utc"]),
    }
    for manifest in manifests:
        actual = {
            "batch_identity": str(manifest.get("batch_identity") or ""),
            "planned_rows": int(manifest.get("planned_rows") or 0),
            "first_event_id": int(manifest.get("first_event_id") or 0),
            "last_event_id": int(manifest.get("last_event_id") or 0),
            "archive_identity_sha256": str(manifest.get("archive_identity_sha256") or ""),
            "selection_mode": str(manifest.get("selection_mode") or ""),
            "selection_lower_utc": _format_utc(_parse_utc(manifest.get("selection_lower_utc"))),
            "selection_upper_utc": _format_utc(_parse_utc(manifest.get("selection_upper_utc"))),
        }
        if actual != expected:
            raise RuntimeError("incremental_manifest_contract_mismatch")




def _stage_rows(port: int, stage: str, placements: list[dict[str, Any]]) -> None:
    _http_query(port, f"CREATE DATABASE {stage}")
    _http_query(port, CREATE_PLACEMENT_INPUT.format(db=stage))
    inserted, interrupted = _http_insert_json_rows(
        port,
        f"{stage}.placement_input",
        (
            {
                "event_id": int(row["id"]),
                "normalized_hash_hex": str(row["normalized_hash"]),
                "archive_file": str(row["archive_file"]),
                "archive_line": int(row["archive_line"]),
            }
            for row in placements
        ),
    )
    if interrupted or inserted != len(placements):
        raise RuntimeError("staging_insert_incomplete")
    staged = _clickhouse_json(
        port,
        "SELECT event_id AS id,lower(normalized_hash_hex) AS normalized_hash,"
        "archive_file,archive_line,'unclassified' AS placement "
        f"FROM {stage}.placement_input ORDER BY event_id FORMAT JSONEachRow",
    )
    classify_existing(placements, staged, [], _identity(placements))




def _canonical_session_placement(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": int(row["event_id"]),
        "revision": int(row["revision"]),
        "session_uid_hex": str(row["session_uid_hex"]).lower(),
        "placement": str(row["placement"]),
        "lifecycle_revision_sha256": str(row["lifecycle_revision_sha256"]),
        "batch_identity": str(row["batch_identity"]),
    }


def _session_actual(
    port: int, batch_identity: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not _session_schema_present(port):
        return [], []
    revisions = _clickhouse_json(
        port,
        "SELECT lower(hex(session_uid)) session_uid_hex,revision,state,"
        "server_id,domain_id,channel_id,logon_time_utc,logoff_time_utc,"
        "duration_s,logon_id,logon_source_id,logoff_source_id,"
        "ifNull(toString(previous_revision_sha256),'') previous_revision_sha256,"
        "toString(revision_sha256) revision_sha256,"
        "toString(batch_identity) batch_identity "
        f"FROM {DATABASE}.session_lifecycle_revisions "
        f"WHERE batch_identity='{batch_identity}' "
        "ORDER BY session_uid,revision,revision_sha256",
    )
    placements = _clickhouse_json(
        port,
        "SELECT event_id,revision,lower(hex(session_uid)) session_uid_hex,"
        "placement,toString(lifecycle_revision_sha256) lifecycle_revision_sha256,"
        "toString(batch_identity) batch_identity "
        f"FROM {DATABASE}.event_session_placement_revisions "
        f"WHERE batch_identity='{batch_identity}' "
        "ORDER BY event_id,revision,lifecycle_revision_sha256",
    )
    return revisions, placements




def _derived_output_actual(port: int, output_identity: str) -> list[dict[str, Any]]:
    return _clickhouse_json(
        port,
        "SELECT toString(output_identity) output_identity,"
        "toString(batch_identity) batch_identity,"
        "toString(candidate_identity_sha256) candidate_identity_sha256,"
        "toString(policy_fingerprint) policy_fingerprint,"
        "toString(derived_output_digest) derived_output_digest,"
        "toString(source_reference_digest) source_reference_digest,"
        "toString(manifest_digest) manifest_digest,"
        "continuity_declaration_scope_identity,"
        "toString(continuity_declaration_sha256) continuity_declaration_sha256,"
        "source_count,observation_count,payload_json,"
        "toString(published_at_utc) published_at_utc "
        f"FROM {DATABASE}.authentication_session_derived_outputs "
        f"WHERE output_identity='{output_identity}' "
        "ORDER BY output_identity,published_at_utc",
    )


def is_derived_publication_durably_verified(
    port: int, publication: dict[str, Any],
) -> bool:
    """Return true only for one complete, exact immutable output readback."""
    try:
        expected = _expected_derived_output_row(publication)
        actual = _derived_output_actual(port, expected["output_identity"])
        classify_derived_output_readback(publication, actual)
    except (KeyError, TypeError, ValueError, RuntimeError, OSError):
        return False
    return True




def _persist_derived_publication(
    port: int, publication: dict[str, Any],
) -> dict[str, Any]:
    """Persist then reopen one compact output by its immutable identity."""
    _apply_session_schema(port)
    expected = _expected_derived_output_row(publication)
    actual_before = _derived_output_actual(port, expected["output_identity"])
    if actual_before:
        readback = classify_derived_output_readback(publication, actual_before)
        return {"mode": "already_published", "readback": readback}
    stage = "sli_warm_derived_" + uuid.uuid4().hex[:12]
    try:
        _http_query(port, f"CREATE DATABASE {stage}")
        _stage_derived_output(port, stage, publication)
        actual_after = _derived_output_actual(port, expected["output_identity"])
        readback = classify_derived_output_readback(publication, actual_after)
    finally:
        _drop_database(port, stage)
    return {"mode": "published", "readback": readback}






def _ensure_incremental_manifest_schema(port: int) -> None:
    """Apply only additive manifest metadata required by the v2 cursor."""
    _http_query(port, CREATE_INCREMENTAL_MANIFEST)
    _http_query(
        port,
        f"ALTER TABLE {DATABASE}.incremental_copy_manifest "
        "ADD COLUMN IF NOT EXISTS selection_mode LowCardinality(String) "
        "DEFAULT 'legacy_max_event_id_v1'",
    )
    _http_query(
        port,
        f"ALTER TABLE {DATABASE}.incremental_copy_manifest "
        "ADD COLUMN IF NOT EXISTS selection_lower_utc "
        "Nullable(DateTime64(6,'UTC'))",
    )
    _http_query(
        port,
        f"ALTER TABLE {DATABASE}.incremental_copy_manifest "
        "ADD COLUMN IF NOT EXISTS selection_upper_utc "
        "Nullable(DateTime64(6,'UTC'))",
    )


def run(
    plan_path: Path, *, execute: bool, port: int | None = None,
    plan_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """``port`` lets a multi-batch drain loop pass in an already-resolved
    container port instead of this function re-resolving it via a fresh
    ``docker port`` launch on every batch."""
    plan = (
        read_json(
            plan_path, max_bytes=MAX_PLAN_JSON_BYTES,
            too_large="warm_plan_too_large",
        )
        if plan_payload is None
        else json.loads(json.dumps(plan_payload))
    )
    frozen = validate_plan(plan)
    with _connect() as conn:
        conn.execute("begin transaction isolation level repeatable read read only")
        source_rows = _source_batch(conn, frozen)
        derived_publication = _derived_publication_from_frozen_plan(
            conn, frozen, source_rows,
        )
        archive_required_descriptor = bool(
            derived_publication is not None
            and derived_publication["descriptor_lifecycle"]["archive_requirement"]
            == "archive_required"
        )
        if derived_publication is None or archive_required_descriptor:
            boundaries = _session_boundaries(source_rows)
            blocks = _archive_blocks(
                conn, [int(row["id"]) for row in source_rows]
            )
            placements, archive = _archive_placements(source_rows, blocks)
        else:
            boundaries = []
            placements = []
            archive = {"required": False, "placement_created": False}

    manifests_before: list[dict[str, Any]] | None = None
    if execute and (derived_publication is None or archive_required_descriptor):
        if port is None:
            port = _container_port(CONTAINER)
        manifests_before = _manifest_rows(port, frozen["identity_sha256"])
        if len(manifests_before) > 1:
            raise RuntimeError("duplicate_incremental_manifest")
        if manifests_before:
            _validate_manifest_contract(manifests_before, frozen, archive)

    session_revisions: list[dict[str, Any]] = []
    session_placements: list[dict[str, Any]] = []
    session_mode = "not_applicable"
    schema_applied_now = False
    if boundaries:
        if port is None:
            port = _container_port(CONTAINER)
        if execute and not _session_schema_present(port):
            _apply_session_schema(port)
            schema_applied_now = True
        pending = _pending_sessions(port, frozen["identity_sha256"])
        session_revisions, session_placements = _session_plan(
            pending, boundaries, frozen["identity_sha256"],
        )
        actual_session_rows, actual_session_placements = _session_actual(
            port, frozen["identity_sha256"],
        )
        session_mode = classify_session_existing(
            session_revisions,
            session_placements,
            actual_session_rows,
            actual_session_placements,
        )

    result: dict[str, Any] = {
        "package_type": "WARM_TIER_INCREMENTAL_COPY",
        "status": "validated_not_executed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "plan": {
            "path": str(plan_path.resolve()),
            "selection_mode": frozen["selection_mode"],
            "batch_identity": frozen["identity_sha256"],
            "rows": frozen["rows"],
            "first_event_id": frozen["first_event_id"],
            "last_event_id": frozen["last_event_id"],
        },
        "source": {
            "postgres_transaction": "REPEATABLE READ, READ ONLY",
            "batch_identity_verified": True,
            "session_boundary_events": len(boundaries),
        },
        "archive": (
            {**archive, "all_batch_rows_found": True}
            if derived_publication is None or archive_required_descriptor
            else archive
        ),
        "session_lifecycle": {
            "contract": "sli.warm-authentication-session-lifecycle.v1",
            "boundary_events": len(boundaries),
            "planned_revisions": len(session_revisions),
            "planned_placement_revisions": len(session_placements),
            "mode_before": session_mode,
            "active_schema_applied_now": schema_applied_now,
        },
        "safety": {
            "postgres_mutated": False,
            "routing_changed": False,
            "delete_performed": False,
            "runtime_started": False,
        },
    }
    if derived_publication is not None:
        result["descriptor_lifecycle"] = frozen["descriptor_lifecycle"]
        result["derived_publication"] = derived_publication
        result["read_availability"] = derived_publication["read_availability"]
        result["readback"] = {
            "status": "not_attempted_without_execute",
            "verified": False,
            "promotion_eligible": False,
        }
        if not execute:
            return result
        if not archive_required_descriptor:
            if port is None:
                port = _container_port(CONTAINER)
            persisted = _persist_derived_publication(port, derived_publication)
            result["status"] = (
                "already_published"
                if persisted["mode"] == "already_published"
                else "copied_and_verified"
            )
            result["readback"] = persisted["readback"]
            result["warm_tier"] = {
                "container": CONTAINER,
                "database": DATABASE,
                "mode_before": persisted["mode"],
                "derived_output_rows": 1,
            }
            return result
    if not execute:
        return result

    if port is None:
        port = _container_port(CONTAINER)
    actual_before = _existing_rows(port, frozen)
    if manifests_before is None:
        manifests_before = _manifest_rows(port, frozen["identity_sha256"])
    mode = classify_existing(
        placements,
        actual_before,
        manifests_before,
        frozen["identity_sha256"],
        frozen=frozen,
        archive=archive,
    )
    if mode == "new" and session_mode == "present":
        raise RuntimeError("session_batch_exists_without_base_placements")
    if mode == "published" and session_mode == "new":
        raise RuntimeError("published_manifest_missing_session_batch")
    stage: str | None = None
    try:
        if mode in {"new", "recover_placements"}:
            _http_query(port, CREATE_INCREMENTAL_MANIFEST)
            stage = "sli_warm_incremental_" + uuid.uuid4().hex[:12]
            existing_ids = {int(row["id"]) for row in actual_before}
            missing_placements = [
                row for row in placements if int(row["id"]) not in existing_ids
            ]
            _stage_rows(port, stage, missing_placements)
            _http_query(
                port,
                f"INSERT INTO {DATABASE}.event_placement "
                "SELECT event_id,NULL,'unclassified',archive_file,"
                "archive_line,unhex(normalized_hash_hex) "
                f"FROM {stage}.placement_input ORDER BY event_id",
                timeout=300,
            )
        if session_mode == "new":
            if stage is None:
                stage = "sli_warm_incremental_" + uuid.uuid4().hex[:12]
                _http_query(port, f"CREATE DATABASE {stage}")
            _stage_session_rows(
                port, stage, session_revisions, session_placements,
            )
        actual_session_rows, actual_session_placements = _session_actual(
            port, frozen["identity_sha256"],
        )
        classify_session_existing(
            session_revisions,
            session_placements,
            actual_session_rows,
            actual_session_placements,
        )
        actual_after = _existing_rows(port, frozen)
        manifests_mid = _manifest_rows(port, frozen["identity_sha256"])
        post_insert_mode = classify_existing(
            placements,
            actual_after,
            manifests_mid,
            frozen["identity_sha256"],
            frozen=frozen,
            archive=archive,
        )
        if post_insert_mode == "recover_manifest":
            _write_manifest(port, frozen, archive)
        manifests_after = _manifest_rows(port, frozen["identity_sha256"])
        final_mode = classify_existing(
            placements,
            _existing_rows(port, frozen),
            manifests_after,
            frozen["identity_sha256"],
            frozen=frozen,
            archive=archive,
        )
        if final_mode != "published":
            raise RuntimeError("incremental_batch_not_published")
    finally:
        if stage is not None:
            _drop_database(port, stage)

    result["status"] = (
        "already_published" if mode == "published" else "copied_and_verified"
    )
    result["warm_tier"] = {
        "container": CONTAINER,
        "database": DATABASE,
        "mode_before": mode,
        "rows_before": len(actual_before),
        "rows_after": len(placements),
        "manifest_rows": 1,
        "session_rows_inserted": (
            len(session_revisions) if session_mode == "new" else 0
        ),
        "session_placement_revisions_inserted": (
            len(session_placements) if session_mode == "new" else 0
        ),
        "placement_rows_inserted": (
            0 if mode in {"published", "recover_manifest"} else len(placements)
        ),
    }
    if derived_publication is not None:
        persisted = _persist_derived_publication(port, derived_publication)
        result["readback"] = persisted["readback"]
        result["warm_tier"]["derived_output_rows"] = 1
        if mode == "published" and persisted["mode"] == "already_published":
            result["status"] = "already_published"
    return result


def execute_and_record(
    plan_path: Path,
    *,
    execute: bool,
    output_path: Path | None = None,
    port: int | None = None,
    plan_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one warm-tier copy and record it as evidence, in-process.

    Shared by the CLI (``main``) and by :func:`drain_warm_tier_backlog`. On
    failure, the same ``status: blocked`` evidence shape that the CLI wrote
    is returned (never raised) so callers keep making the pass/fail
    decision from the result dict, exactly as they did from the previous
    subprocess's exit code and stdout JSON. ``port`` lets a multi-batch
    drain loop pass in an already-resolved container port instead of
    ``run()`` re-resolving it via a fresh ``docker port`` launch per batch.
    """
    evidence_root = EVIDENCE_ROOT.resolve()
    if output_path is None:
        try:
            payload = (
                read_json(
                    plan_path, max_bytes=MAX_PLAN_JSON_BYTES,
                    too_large="warm_plan_too_large",
                )
                if plan_payload is None
                else json.loads(json.dumps(plan_payload))
            )
            batch_identity = validate_plan(payload)["identity_sha256"]
            output_path = evidence_root / (
                f"warm-tier-incremental-copy-{batch_identity[:16]}.json"
            )
        except Exception:
            output_path = evidence_root / "warm-tier-incremental-copy-blocked.json"
    output_path = output_path.resolve()
    if output_path.parent != evidence_root:
        raise ValueError(f"output must be directly inside {evidence_root}")
    try:
        result = run(
            plan_path, execute=execute, port=port, plan_payload=plan_payload,
        )
    except Exception as exc:
        result = {
            "package_type": "WARM_TIER_INCREMENTAL_COPY",
            "status": "blocked",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "error": str(exc)[:1000],
            "safety": {
                "routing_changed": False,
                "delete_performed": False,
                "runtime_started": False,
            },
        }
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def _processed_declaration_ids_from_ledger(path: Path | None) -> set[int]:
    if path is None or not path.is_file():
        return set()
    result: set[int] = set()
    total_ids = 0
    for row in iter_json_lines(
        path, max_bytes=MAX_PROCESSED_LEDGER_BYTES,
        max_line_bytes=MAX_PROCESSED_LEDGER_LINE_BYTES,
        max_rows=MAX_PROCESSED_LEDGER_ROWS,
        too_large="processed_package_ledger_too_large",
    ):
        try:
            progress = dict(row["declaration_progress"])
            payload = {
                key: progress.get(key)
                for key in (
                    "contract", "declaration_ids", "scope_identity",
                    "declaration_sha256", "candidate_identity_sha256",
                )
            }
            digest = hashlib.sha256(json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            ids = progress["declaration_ids"]
            if (
                progress.get("contract") != "sli.storage-lifecycle-declaration-progress.v1"
                or progress.get("digest") != digest or row.get("progress_digest") != digest
                or not isinstance(ids, list) or not ids or ids != sorted(set(ids))
                or len(ids) > MAX_DECLARATION_IDS
            ):
                raise ValueError("ledger contract mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("processed_package_ledger_invalid") from exc
        total_ids += len(ids)
        if total_ids > MAX_PROCESSED_DECLARATION_IDS:
            raise RuntimeError("processed_package_declaration_id_count_out_of_bounds")
        result.update(int(value) for value in ids)
    return result


def drain_warm_tier_backlog(
    *,
    batch_limit: int,
    scan_limit: int,
    max_batches: int,
    plan_output_path: Path = DEFAULT_PLAN,
    descriptor_after_id: int = 0,
    processed_package_ledger: Path | None = None,
) -> dict[str, Any]:
    """Plan and copy warm-tier batches in a loop, entirely in one process.

    This is what ``storage_lifecycle_worker.py`` launches as a single
    subprocess to drain a cycle's warm-tier backlog, instead of launching a
    new Python child process per batch (the previous mechanism, which could
    spawn hundreds of processes across a large backlog). Planning and
    copying inside this loop are plain in-process function calls; only this
    whole loop is itself a subprocess launch, and exactly one.

    The warm-tier container's published port is resolved via a single
    ``docker port`` inspection before the loop starts and threaded through
    every ``plan_and_record``/``execute_and_record`` call inside it, so a
    backlog of many batches does not launch a proportional number of
    ``docker port`` OS processes -- one for the whole drain cycle, not one
    (or two) per batch.

    A single bad item inside one batch (e.g. an archive hash mismatch)
    stops the loop with ``status: blocked`` for that batch only -- batches
    already committed earlier in the loop are not retried, undone, or
    reported as anything but successful.
    """
    from server.sli.storage.warm_tier_incremental_plan_runtime import plan_and_record

    port = _container_port(CONTAINER)
    batches = 0
    copied_rows = 0
    completed_copy_paths: list[str] = []
    completed_packages: list[dict[str, Any]] = []
    current_descriptor_after_id = max(0, int(descriptor_after_id))
    processed_declaration_ids = _processed_declaration_ids_from_ledger(
        processed_package_ledger,
    )
    final_plan: dict[str, Any] = {}
    while True:
        planner_kwargs: dict[str, Any] = {
            "output_path": plan_output_path,
            "port": port,
        }
        if current_descriptor_after_id:
            planner_kwargs["declaration_after_id"] = current_descriptor_after_id
        if processed_declaration_ids:
            planner_kwargs["processed_declaration_ids"] = set(processed_declaration_ids)
        final_plan = plan_and_record(batch_limit, scan_limit, **planner_kwargs)
        status = str(final_plan.get("status") or "")
        planned = int(((final_plan.get("planned_batch") or {}).get("rows")) or 0)
        if status == "waiting_for_data_accumulation" and planned == 0:
            return {
                "status": "drained",
                "batches": batches,
                "copied_rows": copied_rows,
                "completed_copy_paths": completed_copy_paths,
                "completed_packages": completed_packages,
                "final_plan": final_plan,
            }
        if status != "ready_for_manual_bounded_copy" or planned <= 0:
            return {
                "status": "blocked",
                "reason": f"warm_plan_not_copyable:{status}",
                "batches": batches,
                "copied_rows": copied_rows,
                "completed_copy_paths": completed_copy_paths,
                "completed_packages": completed_packages,
                "final_plan": final_plan,
            }
        if batches >= max_batches:
            return {
                "status": "partial",
                "batches": batches,
                "copied_rows": copied_rows,
                "next_planned_rows": planned,
                "completed_copy_paths": completed_copy_paths,
                "completed_packages": completed_packages,
                "final_plan": final_plan,
            }
        copy_result = execute_and_record(plan_output_path, execute=True, port=port)
        copy_status = str(copy_result.get("status") or "")
        if copy_status not in {"copied_and_verified", "already_published"}:
            return {
                "status": "blocked",
                "reason": f"warm_copy_not_verified:{copy_status}",
                "error": copy_result.get("error"),
                "batches": batches,
                "copied_rows": copied_rows,
                "completed_copy_paths": completed_copy_paths,
                "completed_packages": completed_packages,
                "final_plan": final_plan,
            }
        batches += 1
        copied_rows += planned
        batch_identity = str(
            (copy_result.get("plan") or {}).get("batch_identity") or ""
        ).lower()
        if len(batch_identity) != 64 or any(
            value not in "0123456789abcdef" for value in batch_identity
        ):
            return {
                "status": "blocked",
                "reason": "persisted_copy_batch_identity_invalid",
                "batches": batches,
                "copied_rows": copied_rows,
                "completed_copy_paths": completed_copy_paths,
                "completed_packages": completed_packages,
                "final_plan": final_plan,
            }
        copy_path = str(
            EVIDENCE_ROOT / f"warm-tier-incremental-copy-{batch_identity[:16]}.json"
        )
        # Every verified batch binds its exact persisted evidence path to the
        # drain result. Copy-only lifecycle receipts consume this generic set;
        # descriptor promotion adds separate retention-only package metadata.
        completed_copy_paths.append(copy_path)
        # Only the canonical descriptor-promotion evidence can enter retention.
        # A plain archive copy remains source-preserving until it has the same
        # immutable lifecycle, derived-output and readback proof.
        if copy_result.get("descriptor_lifecycle") is not None:
            lifecycle = dict(copy_result["descriptor_lifecycle"])
            progress = lifecycle.get("declaration_progress")
            readback = dict(copy_result.get("readback") or {})
            if not isinstance(progress, dict) or not bool(readback.get("promotion_eligible")):
                return {
                    "status": "blocked", "reason": "durable_descriptor_progress_not_bound",
                    "batches": batches, "copied_rows": copied_rows,
                    "completed_copy_paths": completed_copy_paths,
                    "completed_packages": completed_packages, "final_plan": final_plan,
                }
            frontier_id = int(((final_plan.get("selection") or {}).get(
                "durable_declaration_frontier_id"
            )) or 0)
            if frontier_id <= 0:
                return {
                    "status": "blocked",
                    "reason": "durable_descriptor_progress_identity_invalid",
                    "batches": batches,
                    "copied_rows": copied_rows,
                    "completed_copy_paths": completed_copy_paths,
                    "completed_packages": completed_packages,
                    "final_plan": final_plan,
                }
            completed_packages.append({
                "promotion_evidence_path": copy_path,
                "declaration_frontier_id": frontier_id,
                "declaration_progress": progress,
                "promotion_output_identity": str(readback.get("output_identity") or ""),
            })
            processed_declaration_ids.update(int(value) for value in progress["declaration_ids"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation")
    parser.add_argument(
        "--drain-backlog",
        action="store_true",
        help=(
            "Plan and copy warm-tier batches in a loop inside this single "
            "process until the backlog is empty or --max-batches is hit, "
            "instead of one process launch per batch."
        ),
    )
    parser.add_argument("--batch-limit", type=int, default=10_000)
    parser.add_argument("--scan-limit", type=int, default=2_000_000)
    parser.add_argument("--max-batches", type=int, default=500)
    parser.add_argument("--descriptor-after-id", type=int, default=0)
    parser.add_argument("--processed-package-ledger", type=Path)
    args = parser.parse_args()
    if (args.execute or args.drain_backlog) and args.confirmation != CONFIRMATION:
        parser.error(
            f"--execute/--drain-backlog requires --confirmation {CONFIRMATION}"
        )

    if args.drain_backlog:
        result = drain_warm_tier_backlog(
            batch_limit=args.batch_limit,
            scan_limit=args.scan_limit,
            max_batches=args.max_batches,
            descriptor_after_id=args.descriptor_after_id,
            processed_package_ledger=args.processed_package_ledger,
        )
        print(json.dumps(result, ensure_ascii=False, default=str))
        return 0 if result.get("status") in {"drained", "partial"} else 2

    plan_path = args.plan.resolve()
    evidence_root = EVIDENCE_ROOT.resolve()
    if plan_path.parent != evidence_root:
        parser.error(f"plan must be directly inside {evidence_root}")
    output = args.output.resolve() if args.output else None
    try:
        result = execute_and_record(plan_path, execute=args.execute, output_path=output)
    except ValueError as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - parser.error already exits
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("status") != "blocked" else 2


# Split-out parts (plan 7.2b): they read this module's names through ``_src``.
if __name__ == "__main__":
    # Run as ``python -m``: the split-out parts import this module by its real
    # name; register this very module object so that import does not load a
    # second copy (which would re-enter these imports half-initialised).
    import sys as _sys

    _sys.modules.setdefault("server.sli.storage.warm_tier_incremental_copy_runtime", _sys.modules[__name__])
from server.sli.storage.warm_tier_incremental_copy_runtime_archive import (
    _open_archive_object,
    _open_verified_archive_placements,
    _validated_archive_object_path,
)
from server.sli.storage.warm_tier_incremental_copy_runtime_derived import (
    _build_derived_publication,
    _canonical_derived_observation,
    _derived_publication_from_frozen_plan,
    _expected_derived_output_row,
    _stage_derived_output,
    classify_derived_output_readback,
)
from server.sli.storage.warm_tier_incremental_copy_runtime_plan import (
    _write_manifest,
    classify_existing,
    validate_plan,
)
from server.sli.storage.warm_tier_incremental_copy_runtime_sessions import (
    _canonical_session_revision,
    _pending_sessions,
    _session_plan,
    _stage_session_rows,
    classify_session_existing,
)

if __name__ == "__main__":
    raise SystemExit(main())

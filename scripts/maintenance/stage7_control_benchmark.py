#!/usr/bin/env python3
"""Read-only full-corpus baseline for stage 7 candidate D.

This command measures the already published Storage V2 R3 data plane without
creating tables, starting workers or changing routing.  Backup/restore and the
three ClickHouse candidates remain separate isolated benchmark steps.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import load_config
from server.sli.storage.storage_v2_archive import ArchiveReader
from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore


CONTROL_TABLES = {
    "events_v2_core",
    "event_facts_v2",
    "entities_v2",
    "entity_details_v2",
    "event_entity_link_blocks_v2",
    "storage_v2_provider",
    "storage_v2_channel",
    "storage_v2_computer",
    "storage_v2_keywords",
    "storage_v2_domain_name",
    "storage_v2_role",
    "storage_v2_extracted_from",
    "storage_v2_entity_type",
    "storage_v2_archive_sets",
    "storage_v2_archive_blocks",
    "storage_v2_backfill_checkpoints",
    "storage_v2_backfill_chunks",
    "storage_v2_outbox",
    "storage_v2_shadow_results",
    "storage_v2_cutover_state",
}
LEGACY_DATA_TABLES = {"events", "event_entity_links", "observed_entities"}


def _load_contract() -> dict[str, Any]:
    return json.loads(
        (ROOT / "config" / "stage7_storage_evaluation.json").read_text(
            encoding="utf-8"
        )
    )


def _connection_parts() -> dict[str, Any]:
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    cfg = load_config()
    if not cfg.postgres_dsn:
        raise RuntimeError("postgres_dsn_not_configured")
    parts = conninfo_to_dict(cfg.postgres_dsn)
    admin_user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    admin_password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not admin_user or not admin_password:
        raise RuntimeError("protected_read_only_admin_credentials_required")
    parts.update(
        user=admin_user,
        password=admin_password,
        connect_timeout=max(1, int(cfg.postgres_connect_timeout_seconds)),
        application_name="sli_stage7_control_d_benchmark",
        options=(
            "-c default_transaction_read_only=on "
            "-c statement_timeout=180000 -c lock_timeout=3000"
        ),
    )
    # Keep the import guard useful for source-only tests.
    if psycopg is None:  # pragma: no cover
        raise RuntimeError("psycopg_not_available")
    return parts


def _connect(*, parts=None):
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(**(parts if parts is not None else _connection_parts()), row_factory=dict_row)


def _snapshot_source():
    # Freeze credentials/database configuration once without recording them.
    parts = _connection_parts()
    return lambda: _connect(parts=parts)


@contextmanager
def _exported_snapshot(connect):
    identity_sql = "select current_database() || ':' || pg_postmaster_start_time()::text as identity"
    with connect() as exporter:
        exporter.execute("set transaction isolation level repeatable read read only")
        identity = exporter.execute(identity_sql).fetchone()["identity"]
        snapshot = exporter.execute("select pg_export_snapshot() as snapshot").fetchone()["snapshot"]
        # PostgreSQL generates a hexadecimal identifier. Never interpolate caller input.
        if not snapshot or any(char not in "0123456789ABCDEFabcdef-" for char in snapshot):
            raise RuntimeError("invalid exported snapshot identifier")
        active = True

        @contextmanager
        def bound():
            if not active:
                raise RuntimeError("benchmark snapshot is no longer active")
            with connect() as conn:
                conn.execute("set transaction isolation level repeatable read read only")
                conn.execute("set transaction snapshot '" + snapshot + "'")
                if conn.execute(identity_sql).fetchone()["identity"] != identity:
                    raise RuntimeError("benchmark snapshot database identity mismatch")
                yield conn

        try:
            yield bound, {
                "binding": "exported_repeatable_read_read_only",
                "receipt_sha256": hashlib.sha256((identity + ":" + snapshot).encode()).hexdigest(),
                "archive_binding": "snapshot_manifest_hashes_verified_on_every_read",
                "premeasurement_corpus_verification_reads_archives": True,
            }
        finally:
            active = False


def _verify_snapshot_corpus(conn, expected: dict[str, Any]) -> dict[str, Any]:
    # These historical helpers are read-only; imports are local to avoid a cycle.
    from scripts.maintenance.stage7_clickhouse_candidate_a import _stream_contracts
    from scripts.maintenance.stage7_event_identity import event_uid

    contracts = _stream_contracts(conn)

    def uid(row):
        stream = contracts[(int(row["server_id"]), str(row["channel"]))]
        return event_uid(source_instance_uid=stream["source_instance_uid"],
                         stream_uid_value=stream["stream_uid"], log_epoch_uid=stream["log_epoch_uid"],
                         event_record_id=int(row["event_record_id"]), event_time_utc=row["time_created_utc"],
                         normalized_sha256=str(row["normalized_hash"]))

    def link_identity(rows):
        count, xor, total = 0, 0, 0
        for row in rows:
            # unnest pads unequal PG arrays with NULL: reject rather than truncate.
            values = [int(row[key]) for key in ("event_id", "entity_id", "role_id")]
            value = int.from_bytes(hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).digest(), "big")
            count += 1
            xor ^= value
            total = (total + value) % (1 << 256)
        return count, xor, total

    core_digest, core_count = hashlib.sha256(), 0
    with conn.cursor(name="stage7_snapshot_identity") as cur:
        cur.execute("""
            select core.id,core.server_id,core.event_record_id,core.time_created_utc,
                   encode(core.normalized_hash,'hex') as normalized_hash,channel.value as channel
            from events_v2_core core join storage_v2_channel channel on channel.id=core.channel_id
            order by core.id
        """)
        for row in cur:
            core_digest.update((uid(row) + "\n").encode("ascii"))
            core_count += 1
    if (core_count != int(expected["events"]) or
            core_digest.hexdigest() != expected["event_uid_sequence_sha256"]):
        raise RuntimeError("fresh snapshot canonical event UID mismatch")

    with conn.cursor(name="stage7_snapshot_links") as cur:
        cur.execute("""
            select expanded.event_id,block.entity_id,expanded.role_id
            from event_entity_link_blocks_v2 block
            cross join lateral unnest(block.event_ids,block.role_ids) expanded(event_id,role_id)
        """)
        core_links = link_identity(cur)
    if core_links[0] != int(expected["event_entity_links"]):
        raise RuntimeError("fresh snapshot canonical link count mismatch")

    with conn.cursor() as cur:
        cur.execute("""
            select * from storage_v2_archive_blocks where state='published'
            order by archive_kind,first_event_id,last_event_id,archive_set_id,block_index
        """)
        blocks = [PostgresArchiveManifestStore._from_row(dict(row)) for row in cur.fetchall()]
    reader = ArchiveReader(None)
    archive_digest, archive_events, archive_rows, previous_id = hashlib.sha256(), 0, 0, -1
    manifest_identity = []
    archive_links = (0, 0, 0)
    for block in blocks:
        rows = reader.read_block_rows(block)
        archive_rows += len(rows)
        manifest_identity.append({key: value for key, value in block.public_dict().items()
                                  if key not in {"object_location", "created_at", "verified_at", "published_at"}})
        if block.archive_kind == "link_detail":
            count, xor, total = link_identity(rows)
            archive_links = (archive_links[0] + count, archive_links[1] ^ xor,
                             (archive_links[2] + total) % (1 << 256))
        if block.archive_kind == "event":
            for row in rows:
                if int(row["id"]) <= previous_id:
                    raise RuntimeError("snapshot archive event order mismatch")
                previous_id = int(row["id"])
                archive_digest.update((uid(row) + "\n").encode("ascii"))
                archive_events += 1
    if archive_links != core_links:
        raise RuntimeError("snapshot archive/core link identity mismatch")
    if (archive_events != core_count or archive_digest.hexdigest() != core_digest.hexdigest() or
            len(blocks) != int(expected["archive_blocks"]) or archive_rows != int(expected["archive_rows"])):
        raise RuntimeError("snapshot archive/core corpus mismatch")
    return {"identity_version": 1, "events": core_count,
            "event_uid_sequence_sha256": core_digest.hexdigest(),
            "archive_blocks_verified": len(blocks), "archive_rows_verified": archive_rows,
            "event_entity_links_verified": core_links[0],
            "archive_manifest_sha256": _digest_rows(manifest_identity)}


def _p95(values: list[float]) -> float:
    if not values:
        raise ValueError("at least one latency value is required")
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return ordered[index]


def _digest_rows(rows: list[dict[str, Any]]) -> str:
    encoded = json.dumps(
        rows,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# Version 1: ordered link occurrences, not distinct event metadata.
TIMELINE_CONTRACT_VERSION = 1


def _normalize_timeline(rows: list[dict[str, Any]]) -> list[dict[str, int]]:
    if len(rows) > 100:
        raise RuntimeError("timeline response exceeds limit")
    result = []
    for row in rows:
        if set(row) != {"event_id", "role_id"}:
            raise RuntimeError("timeline projection mismatch")
        item = {}
        for key in ("event_id", "role_id"):
            value = row[key]
            if type(value) is int:
                item[key] = value
            elif isinstance(value, str) and value.isascii() and value.isdecimal():
                item[key] = int(value)
            else:
                raise ValueError("timeline requires integer identifiers")
            if item[key] < 0:
                raise ValueError("timeline requires nonnegative identifiers")
        result.append(item)
    if result != sorted(result, key=lambda row: (-row["event_id"], row["role_id"])):
        raise RuntimeError("timeline ordering mismatch")
    return result


def _relation_sizes(conn: Any) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select relname as table_name,
                   pg_total_relation_size(relid)::bigint as total_bytes
            from pg_stat_user_tables
            order by relname
            """
        )
        rows = [dict(row) for row in cur.fetchall()]
        cur.execute(
            """
            select coalesce(sum(compressed_bytes), 0)::bigint as archive_bytes
            from storage_v2_archive_blocks
            where state='published'
            """
        )
        archive_bytes = int((cur.fetchone() or {})["archive_bytes"])
    by_name = {str(row["table_name"]): int(row["total_bytes"]) for row in rows}
    user_relations = sum(by_name.values())
    legacy_bytes = sum(by_name.get(name, 0) for name in LEGACY_DATA_TABLES)
    control_data_plane = sum(by_name.get(name, 0) for name in CONTROL_TABLES)
    common_control_plane = user_relations - legacy_bytes - control_data_plane
    return {
        "postgresql_physical_size_scope": "live_files_not_mvcc_snapshot_isolated",
        "current_database_user_relation_bytes": user_relations,
        "legacy_transition_bytes_excluded": legacy_bytes,
        "candidate_d_postgres_data_plane_bytes": control_data_plane,
        "common_postgres_control_plane_bytes": common_control_plane,
        "canonical_archive_bytes": archive_bytes,
        "candidate_d_projected_live_bytes": (
            common_control_plane + control_data_plane + archive_bytes
        ),
        "full_managed_storage_bytes": None,
        "full_managed_storage_status": (
            "pending_completed_backup_independent_copy_and_restore_peak"
        ),
        "relations": by_name,
    }


def _query_seeds(conn: Any) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select event_id from events_v2_core
            group by event_id order by count(*) desc, event_id limit 1
            """
        )
        event_id = int(cur.fetchone()["event_id"])
        cur.execute(
            "select server_id,channel_id from events_v2_core "
            "order by time_created_utc desc,id desc limit 1"
        )
        server_channel = dict(cur.fetchone())
        seeds: dict[str, Any] = {
            "event_id": event_id,
            "server_id": int(server_channel["server_id"]),
            "channel_id": int(server_channel["channel_id"]),
        }
        for column in (
            "subject_user_name",
            "target_user_name",
            "ip_address",
            "logon_id",
        ):
            cur.execute(
                f"select {column} as value from events_v2_core "
                f"where {column} is not null order by time_created_utc desc limit 1"
            )
            row = cur.fetchone()
            seeds[column] = row["value"] if row else None
        cur.execute(
            "select entity_id from event_entity_link_blocks_v2 "
            "order by entity_id limit 1"
        )
        seeds["entity_id"] = int(cur.fetchone()["entity_id"])
        cur.execute(
            """
            select id from events_v2_core
            where id >= (
                select (min(id)::bigint + max(id)::bigint) / 2
                from events_v2_core
            )
            order by id limit 1
            """
        )
        seeds["detail_event_id"] = int(cur.fetchone()["id"])
    return seeds


def _workloads(seeds: dict[str, Any]) -> dict[str, tuple[str, tuple[Any, ...]]]:
    workloads: dict[str, tuple[str, tuple[Any, ...]]] = {
        "latest_events": (
            "select id,event_id,event_record_id,time_created_utc "
            "from events_v2_core order by time_created_utc desc,id desc limit 100",
            (),
        ),
        "event_id_time": (
            "select id,event_id,event_record_id,time_created_utc "
            "from events_v2_core where event_id=%s "
            "order by time_created_utc desc,id desc limit 100",
            (seeds["event_id"],),
        ),
        "server_time": (
            "select id,event_id,event_record_id,time_created_utc "
            "from events_v2_core where server_id=%s "
            "order by time_created_utc desc,id desc limit 100",
            (seeds["server_id"],),
        ),
        "channel_event_time": (
            "select id,event_id,event_record_id,time_created_utc "
            "from events_v2_core where channel_id=%s and event_id=%s "
            "order by time_created_utc desc,id desc limit 100",
            (seeds["channel_id"], seeds["event_id"]),
        ),
        "entity_timeline": (
            "select expanded.event_id,expanded.role_id "
            "from event_entity_link_blocks_v2 block "
            "cross join lateral unnest(block.event_ids,block.role_ids) "
            "expanded(event_id,role_id) "
            "where block.entity_id=%s order by expanded.event_id desc,expanded.role_id asc limit 100",
            (seeds["entity_id"],),
        ),
    }
    for name, column in (
        ("subject_account_time", "subject_user_name"),
        ("target_account_time", "target_user_name"),
        ("ip_time", "ip_address"),
        ("logon_id_time", "logon_id"),
    ):
        if seeds.get(column) is None:
            continue
        workloads[name] = (
            f"select id,event_id,event_record_id,time_created_utc "
            f"from events_v2_core where {column}=%s "
            f"order by time_created_utc desc,id desc limit 100",
            (seeds[column],),
        )
    return workloads


def _measure_sql_workloads(
    *,
    connect,
    seeds: dict[str, Any],
    independent_runs: int,
    warmups: int,
    measured: int,
) -> dict[str, Any]:
    workloads = _workloads(seeds)
    samples: dict[str, list[float]] = {name: [] for name in workloads}
    expected: dict[str, tuple[int, str]] = {}
    for _run in range(independent_runs):
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select current_setting('transaction_read_only')::boolean "
                    "as read_only"
                )
                if cur.fetchone()["read_only"] is not True:
                    raise RuntimeError("stage7_control_query_session_not_read_only")
                for name, (sql, params) in workloads.items():
                    for _ in range(warmups):
                        cur.execute(sql, params)
                        cur.fetchall()
                    for _ in range(measured):
                        started = time.perf_counter()
                        cur.execute(sql, params)
                        rows = [dict(row) for row in cur.fetchall()]
                        samples[name].append(
                            (time.perf_counter() - started) * 1000
                        )
                        if name == "entity_timeline":
                            rows = _normalize_timeline(rows)
                        identity = (len(rows), _digest_rows(rows))
                        if name in expected and expected[name] != identity:
                            raise RuntimeError(
                                f"non_deterministic_control_result:{name}"
                            )
                        expected[name] = identity
    return {
        name: {
            "sample_count": len(values),
            "p50_ms": sorted(values)[len(values) // 2],
            "p95_ms": _p95(values),
            "max_ms": max(values),
            "result_rows": expected[name][0],
            "semantic_sha256": expected[name][1],
            **({"timeline_contract_version": TIMELINE_CONTRACT_VERSION,
                "entity_id": int(seeds["entity_id"])} if name == "entity_timeline" else {}),
        }
        for name, values in samples.items()
    }


def _measure_event_detail(
    *,
    connect,
    event_id: int,
    independent_runs: int,
    warmups: int,
    measured: int,
) -> dict[str, Any]:
    archive = ArchiveReader(
        PostgresArchiveManifestStore(connect),
    )
    cold_samples: list[float] = []
    warm_samples: list[float] = []
    expected_hash: str | None = None
    for _run in range(independent_runs):
        started = time.perf_counter()
        row = dict(archive.read_event(archive_kind="event", event_id=event_id))
        cold_samples.append((time.perf_counter() - started) * 1000)
        row_hash = _digest_rows([row])
        if expected_hash not in (None, row_hash):
            raise RuntimeError("non_deterministic_archive_event_detail")
        expected_hash = row_hash
        for _ in range(warmups):
            archive.read_event(archive_kind="event", event_id=event_id)
        for _ in range(measured):
            started = time.perf_counter()
            row = dict(
                archive.read_event(archive_kind="event", event_id=event_id)
            )
            warm_samples.append((time.perf_counter() - started) * 1000)
            if _digest_rows([row]) != expected_hash:
                raise RuntimeError("non_deterministic_archive_event_detail")
    return {
        "cold_sample_count": len(cold_samples),
        "cold_p95_ms": _p95(cold_samples),
        "warm_sample_count": len(warm_samples),
        "warm_p95_ms": _p95(warm_samples),
        "semantic_sha256": expected_hash,
        "payload_exposed_in_evidence": False,
        "cold_cache_control": "first_lookup_per_independent_run_after_archive_verification_without_os_cache_flush",
    }


def diagnose_control_d() -> dict[str, Any]:
    with _connect() as conn:
        seeds = _query_seeds(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                select percentile_disc(0.5) within group (order by row_count)::bigint
                           as row_count_p50,
                       percentile_disc(0.95) within group (order by row_count)::bigint
                           as row_count_p95,
                       max(row_count)::bigint as row_count_max,
                       percentile_disc(0.95) within group (order by raw_bytes)::bigint
                           as raw_bytes_p95,
                       max(raw_bytes)::bigint as raw_bytes_max
                from storage_v2_archive_blocks
                where archive_kind='event' and state='published'
                """
            )
            archive_shape = dict(cur.fetchone())
            cur.execute(
                """
                select row_count,raw_bytes,compressed_bytes
                from storage_v2_archive_blocks
                where archive_kind='event' and state='published'
                  and first_event_id<=%s and last_event_id>=%s
                order by first_event_id desc limit 1
                """,
                (seeds["detail_event_id"], seeds["detail_event_id"]),
            )
            selected_block = dict(cur.fetchone())
            cur.execute(
                """
                select count(*)::bigint as block_count,
                       coalesce(sum(cardinality(event_ids)), 0)::bigint
                           as expanded_event_count,
                       coalesce(max(cardinality(event_ids)), 0)::bigint
                           as largest_block_items
                from event_entity_link_blocks_v2
                where entity_id=%s
                """,
                (seeds["entity_id"],),
            )
            entity_shape = dict(cur.fetchone())
            cur.execute(
                """
                explain (analyze,buffers,format json)
                select expanded.event_id,expanded.role_id
                from event_entity_link_blocks_v2 block
                cross join lateral unnest(block.event_ids,block.role_ids)
                    expanded(event_id,role_id)
                where block.entity_id=%s
                order by expanded.event_id desc limit 100
                """,
                (seeds["entity_id"],),
            )
            explain = cur.fetchone()["QUERY PLAN"][0]

    manifest = PostgresArchiveManifestStore(_connect)
    started = time.perf_counter()
    block = manifest.find_published("event", int(seeds["detail_event_id"]))
    manifest_ms = (time.perf_counter() - started) * 1000
    if block is None:
        raise RuntimeError("control_detail_archive_block_missing")
    reader = ArchiveReader(
        manifest,
    )
    started = time.perf_counter()
    rows = reader.read_block_rows(block)
    block_decode_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    matches = [row for row in rows if int(row["id"]) == int(seeds["detail_event_id"])]
    row_scan_ms = (time.perf_counter() - started) * 1000
    if len(matches) != 1:
        raise RuntimeError("control_detail_archive_identity_mismatch")

    plan = explain["Plan"]
    return {
        "status": "diagnosed",
        "mode": "production_read_only",
        "archive_shape": archive_shape,
        "selected_event_block": selected_block,
        "event_detail_breakdown_ms": {
            "manifest_lookup": manifest_ms,
            "block_decode_and_json_parse": block_decode_ms,
            "in_memory_identity_scan": row_scan_ms,
        },
        "selected_entity_shape": entity_shape,
        "entity_timeline_plan": {
            "planning_time_ms": explain.get("Planning Time"),
            "execution_time_ms": explain.get("Execution Time"),
            "top_node": plan.get("Node Type"),
            "actual_rows": plan.get("Actual Rows"),
            "shared_hit_blocks": plan.get("Shared Hit Blocks"),
            "shared_read_blocks": plan.get("Shared Read Blocks"),
        },
        "payload_values_exposed": False,
        "production_mutated": False,
    }


def run() -> dict[str, Any]:
    with _exported_snapshot(_snapshot_source()) as (connect, receipt):
        return _run_snapshot(connect, receipt)


def _run_snapshot(connect, receipt) -> dict[str, Any]:
    contract = _load_contract()
    performance = contract["performance_gates"]
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select current_user as role,"
                "current_setting('transaction_read_only')::boolean as read_only"
            )
            session = dict(cur.fetchone())
            if session["read_only"] is not True:
                raise RuntimeError("stage7_control_session_not_read_only")
        corpus = _verify_snapshot_corpus(conn, contract["canonical_corpus"])
        sizes = _relation_sizes(conn)
        seeds = _query_seeds(conn)

    queries = _measure_sql_workloads(
        connect=connect,
        seeds=seeds,
        independent_runs=int(performance["independent_runs"]),
        warmups=int(performance["warmup_runs_per_query"]),
        measured=int(performance["measured_runs_per_query"]),
    )
    detail = _measure_event_detail(
        connect=connect,
        event_id=int(seeds["detail_event_id"]),
        independent_runs=int(performance["independent_runs"]),
        warmups=int(performance["warmup_runs_per_query"]),
        measured=int(performance["measured_runs_per_query"]),
    )
    return {
        "status": "measured_with_pending_gates",
        "candidate": "D",
        "mode": "production_read_only_full_corpus",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "session": {
            "effective_role": session["role"],
            "read_only": session["read_only"],
            "credential_values_exposed": False,
        },
        "corpus": corpus,
        "snapshot": receipt,
        "query_seed_sha256": _digest_rows([seeds]),
        "storage": sizes,
        "query_benchmarks": queries,
        "event_detail_benchmark": detail,
        "pending_gates": [
            "isolated PostgreSQL physical-size measurement bound to verified corpus",
            "isolated final-D dump and empty restore",
            "completed backup bytes",
            "independent recovery-copy bytes",
            "peak restore/backfill temporary bytes",
            "report and access semantic parity suite",
            "sustained ingest throughput",
        ],
        "production_mutated": False,
        "collection_started": False,
        "event_payloads_in_evidence": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Измерить CONTROL D этапа 7 без изменений production."
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--diagnostics-only", action="store_true")
    args = parser.parse_args()
    result = diagnose_control_d() if args.diagnostics_only else run()
    output = (ROOT / args.output).resolve()
    output.relative_to(ROOT.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    if args.diagnostics_only:
        print("CONTROL D диагностирован без изменений production.")
    else:
        print(
            "CONTROL D измерен без изменений production; "
            f"SQL workloads: {len(result['query_benchmarks'])}; "
            f"projected live bytes: "
            f"{result['storage']['candidate_d_projected_live_bytes']}."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

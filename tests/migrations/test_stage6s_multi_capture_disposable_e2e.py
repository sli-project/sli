from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("SLI_STAGE6S_DISPOSABLE_E2E") != "1",
    reason="explicit disposable PostgreSQL + ClickHouse resources required",
)

BASE_CLICKHOUSE_SCHEMA = (
    "CREATE DATABASE sli_warm",
    """CREATE TABLE sli_warm.sessions(
        session_uid FixedString(16),logon_source_id Nullable(UInt64),
        logoff_source_id Nullable(UInt64),server_id UInt16,domain_id UInt16,
        channel_id UInt16,logon_time_utc DateTime64(6,'UTC'),
        logoff_time_utc Nullable(DateTime64(6,'UTC')),duration_s Nullable(UInt32),
        state Enum8('closed'=1,'open'=2,'orphan_logoff'=3),logon_id String
    ) ENGINE=MergeTree ORDER BY session_uid""",
    """CREATE TABLE sli_warm.event_placement(
        event_id UInt64,session_uid Nullable(FixedString(16)),
        placement LowCardinality(String),archived_payload_path String,
        archived_payload_line UInt32,normalized_hash FixedString(32)
    ) ENGINE=MergeTree ORDER BY event_id""",
)


@pytest.fixture
def disposable_resources(monkeypatch):
    from tests.migrations.stage6s_disposable import local_docker, owned_resources

    # Also guarded inside the helper: direct calls cannot bypass the opt-in.
    with local_docker() as docker, owned_resources(docker) as resources:
        # libpq must not load inherited service, passfile, TLS or options settings.
        for key in tuple(os.environ):
            if key.startswith("PG"):
                monkeypatch.delenv(key, raising=False)
        yield resources


def _wait_ready(probe):
    import time

    for _ in range(60):
        try:
            probe()
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("stage6s_disposable_readiness_timeout") from None


def _setup_postgres(conn) -> None:
    conn.execute("create role adlog_storage_owner nologin")
    conn.execute("create role adlog_user nologin")
    conn.execute("grant adlog_storage_owner to current_user")
    conn.execute("grant create on schema public to adlog_storage_owner")
    conn.execute(
        "create table schema_migrations(version integer primary key,name text not null,applied_at timestamptz default now())"
    )
    conn.execute("alter table schema_migrations owner to adlog_storage_owner")
    conn.execute("insert into schema_migrations(version,name) values(87,'ad_group_membership_warm_facts')")
    conn.execute("create table collection_runs(id bigint primary key)")
    conn.execute(
        "create table collection_channel_state("
        "server_hostname text not null, channel text not null, updated_at timestamptz, "
        "primary key(server_hostname,channel))"
    )
    conn.execute("create table raw_log_files(id bigint primary key,sha256 text not null)")
    conn.execute("create table servers(id bigint primary key)")
    conn.execute("create table log_sources(id bigint primary key)")
    conn.execute("create table storage_v2_channel(id bigint primary key,value text not null)")
    conn.execute("create table storage_v2_provider(id bigint primary key,value text not null)")
    conn.execute(
        """create table events_v2_core(
            id bigint primary key,event_record_id bigint not null,event_id integer not null,
            normalized_hash bytea not null,server_id bigint not null references servers(id),
            domain_id bigint,channel_id bigint not null references storage_v2_channel(id),
            provider_id bigint references storage_v2_provider(id),
            log_source_id bigint not null references log_sources(id),
            raw_log_file_id bigint not null references raw_log_files(id),
            logon_id text,time_created_utc timestamptz not null,target_user_name text,
            workstation_name text)"""
    )
    conn.execute(
        "create table event_facts_v2(event_id bigint primary key references events_v2_core(id) on delete cascade,logon_type text)"
    )
    migration = Path(
        "config/postgres_migrations/088_source_capture_continuity_declarations.sql"
    ).read_text(encoding="utf-8")
    conn.execute(migration)


def _seed_three_captures(conn):
    from server.sli.sources.source_capture_continuity import build_capture_declaration

    specs = [
        (10, 100, 4608, "1" * 64, 21, "a" * 64),
        (11, 101, 4624, "2" * 64, 21, "a" * 64),
        (13, 102, 4672, "3" * 64, 22, "b" * 64),
        (14, 103, 9999, "5" * 64, 22, "b" * 64),
        (12, 104, 4634, "4" * 64, 23, "c" * 64),
    ]
    conn.execute("insert into servers values(7)")
    conn.execute("insert into log_sources values(3)")
    conn.execute("insert into storage_v2_channel values(9,'Security')")
    conn.execute(
        "insert into storage_v2_provider values(8,'Microsoft-Windows-Security-Auditing')"
    )
    for run, raw_id, _after, capture_specs in (
        (1, 21, 99, specs[:2]), (2, 22, 101, specs[2:4]), (3, 23, 103, specs[4:]),
    ):
        conn.execute("insert into collection_runs values(%s)", (run,))
        conn.execute("insert into raw_log_files values(%s,%s)", (raw_id, capture_specs[0][5]))
    observed = datetime(2026, 7, 1, tzinfo=timezone.utc)
    for index, (event_id, record_id, event_key, digest, raw_id, _raw_sha) in enumerate(specs):
        conn.execute(
            """insert into events_v2_core(
                id,event_record_id,event_id,normalized_hash,server_id,domain_id,
                channel_id,provider_id,log_source_id,raw_log_file_id,logon_id,
                time_created_utc,target_user_name,workstation_name)
                values(%s,%s,%s,%s,7,1,9,8,3,%s,%s,%s,'EXAMPLE\\alice','WS01')""",
            (
                event_id, record_id, event_key, bytes.fromhex(digest), raw_id,
                None if event_key == 4608 else "0xabc",
                observed.replace(minute=index),
            ),
        )
        conn.execute(
            "insert into event_facts_v2(event_id,logon_type) values(%s,'10')",
            (event_id,),
        )
    declarations = []
    for run, raw_id, after, capture_specs in (
        (1, 21, 99, specs[:2]), (2, 22, 101, specs[2:4]), (3, 23, 103, specs[4:]),
    ):
        declaration = build_capture_declaration({
            "collection_run_id": run, "raw_log_file_id": raw_id,
            "raw_log_sha256": capture_specs[0][5], "server_id": 7,
            "log_source_id": 3, "descriptor_source": "sli.windows.ad-dc",
            "descriptor_stream": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "channel_value": "Security",
            "channel_generation_identity": "generation-stable",
            "selector_event_ids": [4608, 4624, 4634, 4672, 9999],
            "query_exhausted": True,
            "capture_status": "completed",
            "cursor_strategy": "record_id", "capture_after_record_id": after,
            "capture_latest_record_id": capture_specs[-1][1], "truncated": False,
            "source_events": [
                {"id": event_id, "record_id": record_id, "event_key": event_key,
                 "normalized_hash": digest}
                for event_id, record_id, event_key, digest, _raw, _sha in capture_specs
            ],
        })
        record = declaration.to_record()
        columns = list(record)
        conn.execute(
            "insert into source_capture_continuity_declarations("
            + ",".join(columns)
            + ") values("
            + ",".join(["%s"] * len(columns))
            + ")",
            tuple(
                json.dumps(value)
                if key in {"covered_source_events", "selector_event_ids"}
                else value
                for key, value in record.items()
            ),
        )
        declarations.append(record)
    return declarations


def test_normal_bounded_multi_capture_storage_path_is_durable_and_idempotent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, disposable_resources,
) -> None:
    import psycopg
    from psycopg.rows import dict_row
    from server.sli.storage import storage_lifecycle_io
    from server.sli.storage import tier_retention_delete_executor_runtime as executor
    from server.sli.storage import tier_retention_delete_plan_runtime as retention
    from server.sli.storage import warm_tier_incremental_copy_runtime as copy_runtime
    from server.sli.storage import warm_tier_incremental_plan_runtime as plan_runtime
    from server.sli.sources.source_capture_continuity import recheck_durable_promotion_continuity

    from tests.migrations.stage6s_disposable import pin_clickhouse

    resources = disposable_resources
    dsn, clickhouse_port = resources.pg_dsn, resources.ch_port
    pin_clickhouse(monkeypatch, resources, storage_lifecycle_io,
                   copy_runtime, plan_runtime, retention)

    def postgres_ready():
        with psycopg.connect(dsn) as probe:
            probe.execute("SELECT 1")

    # Both resources have passed ownership validation before any network probe.
    _wait_ready(postgres_ready)
    _wait_ready(lambda: storage_lifecycle_io._http_query(clickhouse_port, "SELECT 1", timeout=2))
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        _setup_postgres(conn)
        _seed_three_captures(conn)

        monkeypatch.setattr(plan_runtime, "_warm_present_ids", lambda _ids, _port: [])
        selected = plan_runtime._next_durable_descriptor_batch(
            conn, batch_limit=10,
            hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
            warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc),
            port=clickhouse_port,
        )
        assert selected is not None
        source_rows, selection = selected
        assert [row["id"] for row in source_rows] == [10, 11, 12]
        assert selection["supplemental_event_ids"] == [13]

        plan = {"planned_batch": {"limit": 10}}
        plan_runtime.apply_durable_descriptor_selection(plan, source_rows, selection)
        publication = copy_runtime._derived_publication_from_frozen_plan(
            conn,
            {"descriptor_lifecycle": plan["descriptor_lifecycle"],
             "identity_sha256": plan["planned_batch"]["identity_sha256"]},
            source_rows,
        )
        assert publication is not None
        assert publication["derived"][0]["state"] == "closed"
        assert publication["derived"][0]["duration_seconds"] == 180
        assert publication["derived"][0]["privilege_source_event_id"] == 13
        assert publication["manifest"]["source_ids"] == [10, 11, 12]

        # The standard production namespace is safe inside our new empty container.
        for statement in BASE_CLICKHOUSE_SCHEMA:
            storage_lifecycle_io._http_query(clickhouse_port, statement)
        first = copy_runtime._persist_derived_publication(clickhouse_port, publication)
        retry = copy_runtime._persist_derived_publication(clickhouse_port, publication)
        assert first["readback"]["promotion_eligible"] is True
        assert retry["readback"]["promotion_eligible"] is True
        assert first["readback"]["output_identity"] == retry["readback"]["output_identity"]
        reoffered = plan_runtime._next_durable_descriptor_batch(
            conn, batch_limit=10,
            hot_cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
            warm_cutoff_utc=datetime(2026, 6, 1, tzinfo=timezone.utc),
            port=clickhouse_port,
        )
        assert reoffered is not None
        assert [row["id"] for row in reoffered[0]] == [10, 11, 12]

        promotion = retention.build_promoted_delete_manifest(
            source_rows=source_rows,
            cutoff_utc=datetime(2026, 7, 2, tzinfo=timezone.utc),
            promotion_evidence={
                "descriptor_lifecycle": plan["descriptor_lifecycle"],
                "derived_publication": publication,
                "readback": first["readback"],
            },
        )
        assert promotion["status"] == "ready_for_owner_authorization"
        assert promotion["candidate_ids"] == [10, 11, 12]
        assert promotion["promotion_gate"]["supplemental_context_ids"] == [13]
        with conn.cursor() as cur:
            recheck_durable_promotion_continuity(
                cur, promotion_gate=promotion["promotion_gate"],
            )

        references = promotion["promotion_gate"]["source_references"]
        payload = b"".join(
            struct.pack(">Q32s", int(row["id"]), bytes.fromhex(row["sha256"]))
            for row in references
        )
        manifest = tmp_path / "candidates.bin"
        manifest.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        package = {
            "status": "ready_for_owner_authorization", "technical_gate_passed": True,
            "blockers": [], "candidate_count": len(references),
            "candidate_manifest": {
                "path": str(manifest),
                "format": "big_endian_uint64_event_id_plus_32_byte_normalized_hash",
                "record_bytes": 40, "rows": len(references), "bytes": len(payload),
                "sha256": digest, "published": True,
            },
            "postgres": {
                "cutoff_utc": "2026-07-02T00:00:00+00:00",
                "deletion_identity_sha256": digest,
            },
            "promotion_gate": promotion["promotion_gate"],
        }
        package_path = tmp_path / "plan.json"
        package_path.write_text(json.dumps(package), encoding="utf-8")

        monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)

        @contextmanager
        def disposable_write():
            with psycopg.connect(dsn, row_factory=dict_row) as write_conn:
                yield write_conn

        monkeypatch.setattr(executor, "_connect_write", disposable_write)
        disposed = executor.execute(
            plan_path=package_path, output=tmp_path / "disposed.json",
            confirmation=executor.CONFIRMATION, batch_size=10,
        )
        exact_retry = executor.execute(
            plan_path=package_path, output=tmp_path / "retry.json",
            confirmation=executor.CONFIRMATION, batch_size=10,
        )
        assert disposed["deleted_rows"] == 3
        assert exact_retry["deleted_rows"] == 0
        assert conn.execute(
            "select array_agg(id order by id) as ids from events_v2_core"
        ).fetchone()["ids"] == [13, 14]

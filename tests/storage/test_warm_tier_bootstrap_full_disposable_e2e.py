from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Iterator
from urllib.parse import urlencode
from urllib.request import urlopen
import uuid

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("SLI_WARM_BOOTSTRAP_FULL_DISPOSABLE_E2E") != "1",
    reason="explicit disposable PostgreSQL + ClickHouse bootstrap E2E required",
)

_CLICKHOUSE_USER = "bootstrap"
_CLICKHOUSE_PASSWORD = "disposable-clickhouse-only"


def _authenticated_clickhouse_query(
    port: int,
    query: str,
    *,
    timeout: int = 300,
    params: dict[str, str] | None = None,
) -> bytes:
    """Use the same real loopback HTTP protocol with disposable-only auth."""
    connection = http.client.HTTPConnection("127.0.0.1", int(port), timeout=timeout)
    path = f"/?{urlencode(params)}" if params else "/"
    token = base64.b64encode(
        f"{_CLICKHOUSE_USER}:{_CLICKHOUSE_PASSWORD}".encode("utf-8")
    ).decode("ascii")
    try:
        connection.request(
            "POST", path, body=query.encode("utf-8"), headers={
                "Content-Type": "text/plain; charset=utf-8",
                "Authorization": f"Basic {token}",
            },
        )
        response = connection.getresponse()
        payload = response.read()
    finally:
        connection.close()
    if response.status != 200:
        raise RuntimeError(f"disposable_clickhouse_http_{response.status}")
    return payload


def _docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def _published_port(container: str, container_port: str) -> int:
    value = _docker("port", container, container_port).strip()
    host, port = value.rsplit(":", 1)
    if host not in {"127.0.0.1", "[::1]"}:
        raise RuntimeError("disposable_container_not_loopback_bound")
    return int(port)


def _wait_for_postgres(dsn: str) -> None:
    import psycopg

    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(dsn, connect_timeout=2):
                return
        except psycopg.OperationalError:
            time.sleep(0.5)
    raise RuntimeError("disposable_postgresql_not_ready")


def _wait_for_clickhouse(port: int) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}/ping", timeout=2) as response:
                if response.read() == b"Ok.\n":
                    return
        except OSError:
            time.sleep(0.5)
    raise RuntimeError("disposable_clickhouse_not_ready")


@contextmanager
def _disposable_services() -> Iterator[tuple[str, int, Path]]:
    """Own only unique loopback resources and prove their teardown in finally."""
    token = uuid.uuid4().hex[:12]
    database = f"sli_disposable_warm_bootstrap_{token}"
    pg = f"sli-disposable-warm-bootstrap-pg-{token}"
    ch = f"sli-disposable-warm-bootstrap-ch-{token}"
    if not database.startswith("sli_disposable_") or not all(
        item.startswith("sli-disposable-") for item in (pg, ch)
    ):
        raise RuntimeError("disposable_name_guard_failed")
    archive_root = Path(tempfile.mkdtemp(prefix="sli-disposable-warm-bootstrap-"))
    if archive_root.resolve().is_relative_to(Path.cwd().resolve()):
        raise RuntimeError("archive_root_must_be_outside_tracked_source")
    password = "disposable-only-" + uuid.uuid4().hex
    started: list[str] = []
    try:
        _docker(
            "run", "-d", "--rm", "--name", pg,
            "-e", f"POSTGRES_DB={database}", "-e", "POSTGRES_USER=postgres",
            "-e", f"POSTGRES_PASSWORD={password}", "-p", "127.0.0.1::5432",
            "postgres:16-alpine",
        )
        started.append(pg)
        _docker(
            "run", "-d", "--rm", "--name", ch,
            "-e", f"CLICKHOUSE_USER={_CLICKHOUSE_USER}",
            "-e", f"CLICKHOUSE_PASSWORD={_CLICKHOUSE_PASSWORD}",
            "-p", "127.0.0.1::8123",
            "clickhouse/clickhouse-server:24.8-alpine",
        )
        started.append(ch)
        pg_port = _published_port(pg, "5432/tcp")
        ch_port = _published_port(ch, "8123/tcp")
        dsn = (
            f"host=127.0.0.1 port={pg_port} dbname={database} "
            f"user=postgres password={password}"
        )
        _wait_for_postgres(dsn)
        _wait_for_clickhouse(ch_port)
        yield dsn, ch_port, archive_root
    finally:
        for container in reversed(started):
            subprocess.run(
                ["docker", "rm", "-f", container], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
        remaining = _docker("ps", "-a", "--format", "{{.Names}}")
        if any(name in remaining.splitlines() for name in started):
            raise RuntimeError("disposable_container_cleanup_failed")
        shutil.rmtree(archive_root, ignore_errors=False)
        if archive_root.exists():
            raise RuntimeError("disposable_archive_cleanup_failed")


def _setup_source(conn) -> None:
    from tests.migrations.test_stage6s_multi_capture_disposable_e2e import _setup_postgres

    _setup_postgres(conn)
    conn.execute(
        "alter table events_v2_core add column source_core_sha256 bytea "
        "not null default repeat('0', 32)::bytea"
    )
    conn.execute(
        """create table storage_v2_archive_sets(
            archive_set_id uuid primary key,archive_kind text not null,
            format_version integer not null,source_min_event_id bigint not null,
            source_max_event_id bigint not null,expected_rows bigint not null,
            state text not null,created_at timestamptz not null default now(),
            verified_at timestamptz,published_at timestamptz)"""
    )
    conn.execute(
        """create table storage_v2_archive_blocks(
            archive_set_id uuid not null references storage_v2_archive_sets(archive_set_id),
            archive_kind text not null,format_version integer not null,block_index integer not null,
            first_event_id bigint not null,last_event_id bigint not null,row_count integer not null,
            raw_bytes bigint not null,compressed_bytes bigint not null,raw_sha256 bytea not null,
            archive_sha256 bytea not null,object_location text not null unique,state text not null,
            created_at timestamptz not null default now(),verified_at timestamptz,published_at timestamptz,
            quarantine_reason text,primary key(archive_set_id,archive_kind,block_index))"""
    )


def _seed_archive_backed_ordinary_rows(conn, archive_root: Path, dsn: str) -> list[int]:
    from server.sli.storage.storage_v2_archive import ArchivePublisher
    from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore

    observed = datetime.now(timezone.utc) - timedelta(days=20)
    conn.execute("insert into servers values(7)")
    conn.execute("insert into log_sources values(3)")
    conn.execute("insert into storage_v2_channel values(9,'Security')")
    conn.execute("insert into storage_v2_provider values(8,'Microsoft-Windows-Security-Auditing')")
    conn.execute("insert into raw_log_files values(21,%s)", ("a" * 64,))
    rows = []
    for event_id, event_key, digest in ((101, 9998, "1" * 64), (102, 9999, "2" * 64)):
        row = {
            "id": event_id, "raw_log_file_id": 21, "server_id": 7, "domain_id": 1,
            "site_id": None, "log_source_id": 3, "event_record_id": event_id + 1000,
            "event_id": event_key, "version": None, "level": None, "task": None,
            "opcode": None, "keywords": None,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "provider_guid": None, "channel": "Security", "computer": "DC01",
            "time_created_utc": observed, "time_created_local": None, "record_xml": None,
            "message_text": None, "event_data_json": "{}", "subject_user_sid": None,
            "subject_user_name": "alice", "subject_domain_name": None,
            "target_user_sid": None, "target_user_name": None,
            "target_domain_name": None, "ip_address": None, "workstation_name": "WS01",
            "logon_id": None, "correlation_id": None, "normalized_at": observed,
            "normalized_hash": digest,
        }
        conn.execute(
            """insert into events_v2_core(
                id,event_record_id,event_id,normalized_hash,source_core_sha256,server_id,domain_id,
                channel_id,provider_id,log_source_id,raw_log_file_id,logon_id,time_created_utc,
                target_user_name,workstation_name)
                values(%s,%s,%s,%s,%s,7,1,9,8,3,21,null,%s,null,'WS01')""",
            (event_id, event_id + 1000, event_key, bytes.fromhex(digest), b"x" * 32, observed),
        )
        rows.append(row)

    import psycopg
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, autocommit=True, row_factory=dict_row)

    block = ArchivePublisher(archive_root.resolve(), PostgresArchiveManifestStore(connect)).publish_rows(
        archive_set_id=str(uuid.uuid4()), archive_kind="event", block_index=0, rows=rows,
    )
    assert block.state == "published" and Path(block.object_location).is_file()
    return [row["id"] for row in rows]


def test_full_disposable_bootstrap_is_exact_idempotent_and_leaves_the_ordinary_v2_cursor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import psycopg
    from psycopg.rows import dict_row
    from server.sli.storage import storage_lifecycle_io
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap
    from server.sli.storage import warm_tier_incremental_copy_runtime as copy_runtime
    from server.sli.storage import warm_tier_incremental_plan_runtime as planner

    with _disposable_services() as (dsn, clickhouse_port, archive_root):
        with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
            _setup_source(conn)
            ids = _seed_archive_backed_ordinary_rows(conn, archive_root, dsn)

        def connect():
            return psycopg.connect(dsn, row_factory=dict_row)

        policy = type("Policy", (), {
            "db_retention_days": 7, "warm_retention_days": 365,
            "archive_auto_delete_enabled": False,
        })()
        monkeypatch.setattr(bootstrap, "_connect", connect)
        monkeypatch.setattr(bootstrap, "_http_query", _authenticated_clickhouse_query)
        monkeypatch.setattr(copy_runtime, "_connect", connect)
        monkeypatch.setattr(copy_runtime, "_http_query", _authenticated_clickhouse_query)
        monkeypatch.setattr(planner, "_connect", connect)
        monkeypatch.setattr(planner, "_http_query", _authenticated_clickhouse_query)
        monkeypatch.setattr(storage_lifecycle_io, "_http_query", _authenticated_clickhouse_query)
        monkeypatch.setattr(planner, "load_storage_policy", lambda: policy)
        monkeypatch.setattr(storage_lifecycle_io, "CONTAINER", "sli-disposable-warm-bootstrap-e2e")
        evidence_root = tmp_path / "copy-evidence"
        evidence_root.mkdir()
        monkeypatch.setattr(bootstrap, "EVIDENCE_ROOT", evidence_root)
        monkeypatch.setattr(copy_runtime, "EVIDENCE_ROOT", evidence_root)

        assert bootstrap.preflight_target(clickhouse_port)["database_exists"] is False
        plan = bootstrap.build_bootstrap_plan(batch_limit=10, scan_limit=10, port=clickhouse_port)
        assert plan["status"] == "ready_for_manual_bounded_copy"
        assert plan["planned_batch"]["event_ids"] == ids
        assert plan["bootstrap"]["plan_digest"] == bootstrap.plan_digest(plan)
        plan_path = tmp_path / "bootstrap-plan.json"
        plan_path.write_text(json.dumps(plan), encoding="utf-8")

        first = bootstrap.execute_bootstrap(
            plan_path, confirmation=plan["bootstrap"]["plan_digest"], execute=True,
            port=clickhouse_port, output_path=evidence_root / "first.json",
        )
        assert first["status"] == "copied_and_verified", first
        assert first["source"]["postgres_transaction"] == "REPEATABLE READ, READ ONLY"
        assert first["archive"]["all_batch_rows_found"] is True
        assert first["archive"]["blocks"] == 1

        placement_rows = copy_runtime._clickhouse_json(
            clickhouse_port,
            "SELECT event_id,placement FROM sli_warm.event_placement ORDER BY event_id",
        )
        assert [
            {"event_id": int(row["event_id"]), "placement": row["placement"]}
            for row in placement_rows
        ] == [
            {"event_id": event_id, "placement": "unclassified"} for event_id in ids
        ]
        assert len(copy_runtime._manifest_rows(clickhouse_port, plan["planned_batch"]["identity_sha256"])) == 1
        # This ordinary fixture has no authentication boundary events, so the
        # lifecycle views are intentionally not installed.  The required base
        # sessions table must still be valid for a later boundary-bearing batch.
        assert copy_runtime._http_query(
            clickhouse_port, "SELECT count() FROM sli_warm.sessions",
        ).decode().strip() == "0"
        staging = copy_runtime._clickhouse_json(
            clickhouse_port,
            "SELECT name FROM system.databases WHERE startsWith(name,'sli_warm_incremental_') "
            "OR startsWith(name,'sli_warm_derived_')",
        )
        assert staging == []

        retry = bootstrap.execute_bootstrap(
            plan_path, confirmation=plan["bootstrap"]["plan_digest"], execute=True,
            port=clickhouse_port, output_path=evidence_root / "retry.json",
        )
        assert retry["status"] == "already_published", retry
        assert len(copy_runtime._manifest_rows(clickhouse_port, plan["planned_batch"]["identity_sha256"])) == 1
        assert [
            int(row["event_id"])
            for row in copy_runtime._clickhouse_json(
                clickhouse_port,
                "SELECT event_id FROM sli_warm.event_placement ORDER BY event_id",
            )
        ] == ids

        ordinary = planner.build_plan(batch_limit=10, scan_limit=10, port=clickhouse_port)
        assert ordinary["warm"]["latest_v2_selection_upper_utc"] is not None
        assert ordinary["planned_batch"]["event_ids"] == []
        assert ordinary["status"] == "waiting_for_data_accumulation"

        # The same real target must also accept the append-only session schema
        # once a later ordinary batch contains authentication boundaries.
        copy_runtime._apply_session_schema(clickhouse_port)
        assert copy_runtime._http_query(
            clickhouse_port, "SELECT count() FROM sli_warm.sessions_effective_v1",
        ).decode().strip() == "0"
        assert bootstrap._preflight_exact_recovery_target(
            clickhouse_port, copy_runtime.validate_plan(plan),
        )["status"] == "exact_recovery"

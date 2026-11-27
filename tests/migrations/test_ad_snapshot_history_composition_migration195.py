import os
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/195_ad_snapshot_history_composition.sql"


def test_forward_migration_preserves_165_and_follows_exact_194():
    inventory = forward_migration_inventory(PATH.parent)
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((195, "ad_snapshot_history_composition"))
    assert pairs[position - 1] == (194, "agent_deployment_scope")
    assert len(pairs) == len({version for version, _ in pairs})
    sql = PATH.read_text("utf-8")
    assert "version=194 and name='agent_deployment_scope'" in sql
    assert "version=165 and name='ad_snapshot_change_history'" in sql
    assert "version>=195" in sql
    assert "values(195,'ad_snapshot_history_composition')" in sql


@pytest.fixture
def history_database():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL DSN required")
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as connection:
        assert_disposable_database(connection)
        connection.execute("""do $$ begin
            if to_regrole('adlog_storage_owner') is null then create role adlog_storage_owner nologin; end if;
            if to_regrole('adlog_user') is null then create role adlog_user login; end if;
            end $$;
            create table public.schema_migrations(version int primary key,name text);
            insert into public.schema_migrations values(164,'agent_instances');
            create table public.ad_snapshot_manifests(manifest_id uuid primary key,domain_id bigint,
                slot_start_utc timestamptz,coverage_state text default 'partial');
            create table public.ad_snapshot_manifest_sources(manifest_id uuid,family text,source_id text,
                payload_sha256 bytea,primary key(manifest_id,family));
            create table public.users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,captured_at_utc timestamptz);
            create table public.computers_v6_source_snapshots(snapshot_uuid uuid,domain_id bigint,captured_at_utc timestamptz);
            create table public.gpo_report_v2_source_snapshots(source_run_id uuid,domain_id bigint,created_at timestamptz);
            create table public.platform_settings(key text,value text);
            create table public.expiry_calls(manifest_id uuid);
            create procedure public.expire_ad_snapshot_seven_day_ring(p_manifest_id uuid)
                language sql security definer as $$ insert into public.expiry_calls values(p_manifest_id); $$;
            revoke all on procedure public.expire_ad_snapshot_seven_day_ring(uuid) from public;
            grant select on public.schema_migrations,public.ad_snapshot_manifests,
                public.ad_snapshot_manifest_sources,public.platform_settings to adlog_user;
        """)
        connection.execute((ROOT / "config/postgres_migrations/165_ad_snapshot_change_history.sql").read_text("utf-8"))
        connection.execute("insert into public.schema_migrations values(194,'agent_deployment_scope')")
        connection.execute(PATH.read_text("utf-8"))
        yield connection


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_health_probe_keeps_freshness_pid_and_failure_checks(history_database, monkeypatch, capsys):
    from deploy.linux import healthcheck

    admin = history_database
    admin.execute("""create table public.runtime_worker_heartbeats(worker_name text primary key,
        status text,details_json jsonb,heartbeat_at timestamptz,process_pid integer,expected_interval_seconds integer);
        insert into public.runtime_worker_heartbeats values('storage_lifecycle','warning',
            '{"last_cycle_reason":"snapshot_history_migration_required"}',now(),1,300);""")
    monkeypatch.setattr(healthcheck, "native_postgres_dsn", lambda: os.environ["ADLOG_TEST_PG_DSN"])
    started_at = admin.execute("select now() - interval '1 hour'").fetchone()[0]
    assert healthcheck.native_healthy("storage_lifecycle", process_pid=1, started_at=started_at)
    assert capsys.readouterr().out == "warning: storage_lifecycle: snapshot_history_migration_required\n"
    for update in ("heartbeat_at=now()-interval '631 seconds'", "heartbeat_at=now()+interval '60 seconds'",
                   "process_pid=2", "status='blocked'", "status='failed'"):
        admin.execute("update public.runtime_worker_heartbeats set status='warning',heartbeat_at=now(),process_pid=1")
        admin.execute("update public.runtime_worker_heartbeats set " + update)
        assert not healthcheck.native_healthy("storage_lifecycle", process_pid=1, started_at=started_at)
        assert capsys.readouterr().out == ""

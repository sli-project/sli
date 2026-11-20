import os
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.storage import ad_snapshot_change_history as history
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
def test_upgrade_publishes_optional_families_and_keeps_expiry_fences(history_database, monkeypatch):
    psycopg = pytest.importorskip("psycopg")
    from server.sli.core import postgres_runtime_pipeline
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    admin = history_database
    now = datetime(2026, 10, 10, tzinfo=timezone.utc)
    payload = {"metadata": {"collection_status": "complete"}, "users": [], "groups": [], "objects": [], "gpos": []}
    digest = history.canonical_output_sha256(payload)
    manifests = {}
    for index, has_gpo in enumerate((False, True, False, True)):
        manifest_id = str(uuid4())
        members = [{"family": family, "source_id": "synthetic", "payload_sha256": digest}
                   for family in history.FAMILIES if family != "gpo_v2" or has_gpo]
        manifests[manifest_id] = {"coverage_state": "partial", "members": members}
        admin.execute("insert into public.ad_snapshot_manifests(manifest_id,domain_id,slot_start_utc) values(%s,1,%s)",
                      (manifest_id, now + timedelta(hours=index)))
        for member in members:
            admin.execute("insert into public.ad_snapshot_manifest_sources values(%s,%s,%s,%s)",
                          (manifest_id, member["family"], member["source_id"], bytes.fromhex(digest)))
    runtime_dsn = make_conninfo(os.environ["ADLOG_TEST_PG_DSN"], user="adlog_user")
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: psycopg.connect(runtime_dsn, row_factory=dict_row))
    monkeypatch.setattr(history, "ensure_schema", lambda *a: None)
    monkeypatch.setattr(history, "load_projection_manifest", lambda _, key: manifests[key])
    monkeypatch.setattr(history, "load_exact_projection_source", lambda *a, **kw: payload)
    monkeypatch.setattr(history, "publish_batch", lambda *a: None)  # ClickHouse readback covered by unit tests.
    monkeypatch.setattr(history, "purge_history", lambda *a, **kw: pytest.fail("copy-only purge"))
    anchor = list(manifests)[-1]
    with psycopg.connect(runtime_dsn, autocommit=True) as runtime:
        with pytest.raises(psycopg.Error, match="unconfirmed snapshots"):
            runtime.execute("call public.expire_ad_snapshot_confirmed_ring_v165(%s)", (anchor,))
    result = history.run_cycle(port=8123, apply_retention=False, now=now, max_manifests=2)
    assert result["status"] == "partial"
    assert result["coverage_state"] == "partial"
    assert admin.execute("select count(*) as n from public.ad_snapshot_history_confirmations").fetchone()["n"] == 5
    history.run_cycle(port=8123, apply_retention=False, now=now, max_manifests=2)
    result = history.run_cycle(port=8123, apply_retention=False, now=now, max_manifests=2)
    assert result["status"] == "ok" and result["manifests_published"] == 0
    receipts = admin.execute("select * from public.ad_snapshot_history_confirmations order by observed_at,family").fetchall()
    assert len(receipts) == 10
    for row in receipts:
        if row["family"] == "gpo_v2":
            assert row["previous_manifest_id"] is None and row["previous_sha256"] is None
            assert row["record_count"] == 0 and row["coverage_state"] == "partial"
    with psycopg.connect(runtime_dsn, autocommit=True) as runtime:
        runtime.execute("call public.expire_ad_snapshot_confirmed_ring_v165(%s)", (anchor,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute("call public.expire_ad_snapshot_seven_day_ring(%s)", (anchor,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute("update public.ad_snapshot_history_confirmations set record_count=0")
    with pytest.raises(psycopg.Error, match="immutable"):
        admin.execute("update public.ad_snapshot_history_confirmations set record_count=0")
    assert admin.execute("select count(*) as n from public.expiry_calls").fetchone()["n"] == 1
    # Confirmations still fence retention after a predecessor leaves the hot ring.
    oldest = list(manifests)[0]
    admin.execute("delete from public.ad_snapshot_manifest_sources where manifest_id=%s", (oldest,))
    admin.execute("delete from public.ad_snapshot_manifests where manifest_id=%s", (oldest,))
    with psycopg.connect(runtime_dsn, autocommit=True) as runtime:
        runtime.execute("call public.expire_ad_snapshot_confirmed_ring_v165(%s)", (anchor,))
    # Forged baselines, hashes and source identities remain rejected by the trigger.
    target = next(row for row in receipts if str(row["manifest_id"]) == anchor and row["family"] == "users_v2")
    admin.execute("alter table public.ad_snapshot_history_confirmations disable trigger user")
    admin.execute("delete from public.ad_snapshot_history_confirmations where manifest_id=%s and family='users_v2'", (anchor,))
    admin.execute("alter table public.ad_snapshot_history_confirmations enable trigger user")
    insert = """insert into public.ad_snapshot_history_confirmations
        (manifest_id,family,domain_id,previous_manifest_id,source_sha256,previous_sha256,
         batch_id,records_sha256,record_count,observed_at,coverage_state)
        values (%(manifest_id)s,%(family)s,%(domain_id)s,%(previous_manifest_id)s,%(source_sha256)s,
                %(previous_sha256)s,%(batch_id)s,%(records_sha256)s,%(record_count)s,%(observed_at)s,%(coverage_state)s)"""
    with psycopg.connect(runtime_dsn, autocommit=True) as runtime:
        for overrides, reason in [
            ({"source_sha256": "b" * 64}, "source mismatch"),
            ({"domain_id": 2}, "source mismatch"),
            ({"observed_at": now}, "source mismatch"),
            ({"previous_manifest_id": None, "previous_sha256": None}, "predecessor mismatch"),
            ({"previous_sha256": "b" * 64}, "predecessor hash mismatch"),
        ]:
            with pytest.raises(psycopg.Error, match=reason):
                runtime.execute(insert, {**target, **overrides})
        runtime.execute(insert, target)
    # Unbound compatibility snapshots also keep their preservation fence.
    admin.execute("insert into public.users_report_v2_snapshots values(999,1,%s)", (now - timedelta(days=8),))
    with psycopg.connect(runtime_dsn, autocommit=True) as runtime:
        with pytest.raises(psycopg.Error, match="unconfirmed compatibility snapshots"):
            runtime.execute("call public.expire_ad_snapshot_confirmed_ring_v165(%s)", (anchor,))
    admin.execute("delete from public.users_report_v2_snapshots")
    # Even an optional family cannot expire if a real bound source lacks its receipt.
    admin.execute("alter table public.ad_snapshot_history_confirmations disable trigger user")
    admin.execute("delete from public.ad_snapshot_history_confirmations where manifest_id=%s and family='gpo_v2'", (anchor,))
    admin.execute("alter table public.ad_snapshot_history_confirmations enable trigger user")
    with psycopg.connect(runtime_dsn, autocommit=True) as runtime:
        with pytest.raises(psycopg.Error, match="unconfirmed snapshots"):
            runtime.execute("call public.expire_ad_snapshot_confirmed_ring_v165(%s)", (anchor,))
    with pytest.raises(psycopg.Error, match="already|prerequisites"):
        admin.execute(PATH.read_text("utf-8"))
    admin.execute("rollback")


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_health_probe_keeps_freshness_pid_and_failure_checks(history_database, monkeypatch, capsys):
    from deploy.linux import healthcheck

    admin = history_database
    admin.execute("""create table public.runtime_worker_heartbeats(worker_name text primary key,
        status text,details_json jsonb,heartbeat_at timestamptz,process_pid integer,expected_interval_seconds integer);
        insert into public.runtime_worker_heartbeats values('storage_lifecycle','warning',
            '{"last_cycle_reason":"snapshot_history_migration_required"}',now(),1,300);""")
    monkeypatch.setattr(healthcheck, "load_config", lambda: SimpleNamespace(postgres_dsn=os.environ["ADLOG_TEST_PG_DSN"]))
    assert healthcheck.healthy("storage_lifecycle")
    assert capsys.readouterr().out == "warning: storage_lifecycle: snapshot_history_migration_required\n"
    for update in ("heartbeat_at=now()-interval '631 seconds'", "heartbeat_at=now()+interval '60 seconds'",
                   "process_pid=2", "status='blocked'", "status='failed'"):
        admin.execute("update public.runtime_worker_heartbeats set status='warning',heartbeat_at=now(),process_pid=1")
        admin.execute("update public.runtime_worker_heartbeats set " + update)
        assert not healthcheck.healthy("storage_lifecycle")
        assert capsys.readouterr().out == ""

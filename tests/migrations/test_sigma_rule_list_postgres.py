"""Real migrated API-role query and denied metadata; no fixture GRANTs."""
import json
import os
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.historical_postgres import historical_connection
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration
HISTORICAL_TIP = (325, "t109_workstation_path")


@pytest.fixture
def sigma_label_history(tmp_path, monkeypatch):
    # The complete predecessor of NPS 326 supports these historical unwinds.
    with historical_connection(tmp_path, monkeypatch, HISTORICAL_TIP) as conn:
        yield conn


@pytest.mark.postgres_owned_cluster
def test_label_migration_reapply_rollback_and_prerequisite_guards(sigma_label_history):
    from tests.migrations.test_report_producer_migration285 import (
        restore_successors,
        rollback_successors,
    )
    psycopg = pytest.importorskip("psycopg")
    root = Path(__file__).resolve().parents[2]
    forward = (root / "config/postgres_migrations/286_sigma_rule_labels.sql").read_text("utf-8")
    backward = (root / "config/postgres_migrations/286_sigma_rule_labels.rollback.sql").read_text("utf-8")
    forward287 = (root / "config/postgres_migrations/287_workstation_inventory_job.sql").read_text("utf-8")
    backward287 = (root / "config/postgres_migrations/287_workstation_inventory_job.rollback.sql").read_text("utf-8")
    conn = sigma_label_history
    assert_disposable_database(conn)
    with pytest.raises(psycopg.errors.RaiseException, match="migration 286 prerequisites failed"):
        conn.execute(forward)
    conn.execute("rollback")
    # Later migrations must still fence a direct 287 rollback.
    with pytest.raises(psycopg.errors.RaiseException, match="migration 287 rollback prerequisites failed"):
        conn.execute(backward287)
    conn.execute("rollback")
    successors = rollback_successors(conn, after=287)
    # A real 287 successor must block direct 286 rollback. Remove it
    # through its own guarded rollback before exercising the 286 body.
    with pytest.raises(psycopg.errors.RaiseException, match="migration 286 rollback prerequisites failed"):
        conn.execute(backward)
    conn.execute("rollback")
    conn.execute(backward287)
    conn.execute(backward)
    assert conn.execute("select to_regprocedure('sli_sigma.read_rule_labels(uuid,text,text,uuid,text)')").fetchone()[0] is None
    # 287 may not be applied to 285 without the genuine 286.
    with pytest.raises(psycopg.errors.RaiseException, match="migration 287 prerequisites failed"):
        conn.execute(forward287)
    conn.execute("rollback")
    conn.execute("update schema_migrations set name='wrong' where version=285")
    with pytest.raises(psycopg.errors.RaiseException, match="migration 286 prerequisites failed"):
        conn.execute(forward)
    conn.execute("rollback")
    conn.execute("update schema_migrations set name='report_producer' where version=285")
    conn.execute(forward)
    assert conn.execute("select has_function_privilege('adlog_user','sli_sigma.read_rule_labels(uuid,text,text,uuid,text)','EXECUTE')").fetchone()[0]
    assert not conn.execute("select has_function_privilege('adlog_semantic_worker','sli_sigma.read_rule_labels(uuid,text,text,uuid,text)','EXECUTE')").fetchone()[0]
    catalog = conn.execute("""select r.rolname,p.prosecdef,p.proconfig,
        not exists(select 1 from aclexplode(p.proacl) a where a.grantee=0 and a.privilege_type='EXECUTE')
        from pg_proc p join pg_roles r on r.oid=p.proowner
        where p.oid='sli_sigma.read_rule_labels(uuid,text,text,uuid,text)'::regprocedure""").fetchone()
    assert catalog[0:2] == ('adlog_sigma_owner', True) and catalog[3] is True
    assert [value.replace(' ', '') for value in catalog[2]] == ['search_path=pg_catalog,pg_temp']
    conn.execute(forward287)
    restore_successors(conn, successors)
    assert conn.execute("select version,name from schema_migrations where version>=285 order by version").fetchall() == [
        (285, "report_producer"), (286, "sigma_rule_labels"), (287, "workstation_inventory_job"),
        *successors]


@pytest.mark.postgres_owned_cluster
def test_report_fixture_restores_exact_label_successor(sigma_label_history):
    from psycopg.rows import dict_row

    from tests.migrations import test_report_producer_migration285 as producer

    conn = sigma_label_history
    conn.row_factory = dict_row
    assert_disposable_database(conn)
    upstream = conn.execute('select * from schema_migrations where version<=284 order by version').fetchall()
    query = 'select version,name from schema_migrations where version>=285 order by version'
    expected = conn.execute(query).fetchall()
    assert {'version': 288, 'name': 'file_audit_service_filter'} in expected
    assert {'version': 297, 'name': 'agent_stream_import_health'} in expected
    assert {'version': 296, 'name': 'agent_runtime_switch'} in expected
    producer.reapply(conn)
    assert conn.execute(query).fetchall() == expected
    assert conn.execute('select * from schema_migrations where version<=284 order by version').fetchall() == upstream
    assert conn.execute("select to_regprocedure('sli_sigma.read_rule_labels(uuid,text,text,uuid,text)') as f").fetchone()['f']
    assert conn.execute("select to_regprocedure('public.read_workstation_inventory_input_v1(uuid,uuid,bigint)') as f").fetchone()['f']
    assert conn.execute("select to_regclass('public.sli_agent_stream_import_health') as t").fetchone()['t']
    assert conn.execute("select to_regprocedure('public.replace_agent_runtime_v296(uuid,uuid,text,text)') as f").fetchone()['f']


@pytest.mark.parametrize('missing_rollback', [False, True])
@pytest.mark.postgres_owned_cluster
def test_successor_files_define_future_order_and_missing_rollback_refuses_before_reset(
    tmp_path, monkeypatch, sigma_label_history, missing_rollback,
):
    from tests.migrations import test_report_producer_migration285 as producer

    directory = tmp_path / 'config/postgres_migrations'
    directory.mkdir(parents=True)
    for path in (producer.ROOT / 'config/postgres_migrations').glob('*.sql'):
        if path.name[:3].isdigit() and 287 < int(path.name[:3]) <= HISTORICAL_TIP[0]:
            (directory / path.name).write_bytes(path.read_bytes())
    conn = sigma_label_history
    assert_disposable_database(conn)
    # Two synthetic successors require ascending apply / descending rollback.
    # Their SQL guards fail if the helper gets either order wrong.
    previous = conn.execute('select max(version) from schema_migrations').fetchone()[0]
    for version in (997, 998):
        forward = f"""begin;
            do $$ begin
                if (select max(version) from schema_migrations)<>{previous} then
                    raise exception 'synthetic_successor_order';
                end if;
            end $$;
            create table public.synthetic_successor_{version}(id integer);
            insert into schema_migrations(version,name) values({version},'synthetic_successor');
            commit;"""
        backward = f"""begin;
            do $$ begin
                if (select max(version) from schema_migrations)<>{version} then
                    raise exception 'synthetic_successor_order';
                end if;
            end $$;
            drop table public.synthetic_successor_{version};
            delete from schema_migrations where version={version};
            commit;"""
        (directory / f'{version}_synthetic_successor.sql').write_text(forward, encoding='utf-8')
        if not (missing_rollback and version == 997):
            (directory / f'{version}_synthetic_successor.rollback.sql').write_text(backward, encoding='utf-8')
        conn.execute(forward)
        previous = version
    monkeypatch.setattr(producer, 'ROOT', tmp_path)
    query = 'select version,name from schema_migrations order by version'
    before = conn.execute(query).fetchall()
    if missing_rollback:
        with pytest.raises(ValueError, match='producer_fixture_reviewed_successor_missing'):
            producer.rollback_successors(conn, after=287)
        assert conn.execute(query).fetchall() == before
    else:
        successors = producer.rollback_successors(conn, after=287)
        assert conn.execute('select max(version) from schema_migrations').fetchone() == (287,)
        assert conn.execute("select to_regclass('public.synthetic_successor_998')").fetchone() == (None,)
        producer.restore_successors(conn, successors)
        assert conn.execute(query).fetchall() == before
    assert conn.execute("select to_regclass('public.synthetic_successor_997'),"
                        "to_regclass('public.synthetic_successor_998')").fetchone() == (
                            'synthetic_successor_997', 'synthetic_successor_998')


@pytest.mark.parametrize('successor_state', ['foreign', 'foreign_filter', 'foreign_health', 'foreign_runtime', 'future'])
def test_report_predecessor_rejects_foreign_or_future_successor_without_partial_reset(successor_state):
    from tests.migrations import test_report_producer_migration285 as producer

    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('Disposable migrated PostgreSQL required')
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        upstream = conn.execute('select * from schema_migrations where version<=285 order by version').fetchall()
        if successor_state == 'foreign':
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=286")
        elif successor_state == 'foreign_filter':
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=288")
        elif successor_state == 'foreign_health':
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=297")
        elif successor_state == 'foreign_runtime':
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=296")
        else:
            conn.execute("insert into schema_migrations(version,name) values(999999,'synthetic_future')")
        ledger = conn.execute('select * from schema_migrations order by version').fetchall()
        # Whole-chain preflight rejects foreign/future ledger entries before
        # rolling back the otherwise valid 287 successor.
        with pytest.raises(ValueError, match='producer_fixture_successor_invalid'):
            producer.predecessor(conn)
        conn.execute('rollback')
        assert conn.execute('select * from schema_migrations order by version').fetchall() == ledger
        assert conn.execute('select * from schema_migrations where version<=285 order by version').fetchall() == upstream
        assert conn.execute("select to_regclass('public.report_producer_claims') as t").fetchone()['t']
        assert conn.execute("select to_regprocedure('sli_sigma.read_rule_labels(uuid,text,text,uuid,text)') as f").fetchone()['f']
        assert conn.execute("select to_regprocedure('public.read_workstation_inventory_input_v1(uuid,uuid,bigint)') as f").fetchone()['f']
        assert conn.execute("select to_regclass('public.sli_agent_stream_import_health') as t").fetchone()['t']
        assert conn.execute("select name from schema_migrations where version=287").fetchone()['name'] == 'workstation_inventory_job'
        assert conn.execute("select to_regclass('public.sli_agent_runtime_switches') as t").fetchone()['t']

"""W02 forward migration and actual SQL contracts on disposable PostgreSQL."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.semantic import account_watch as watch, account_watch_runtime as worker
from server.sli.semantic import qw_input as qw, semantic_risk_runtime_repository as runtime
from tests.migrations.test_qw_semantic_input_migration228 import pg as pg
from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg
from tests.unit.test_account_watch import event, rule, IDENTITY

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/253_account_watch.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_is_dormant_and_requires_w01_without_rewriting_it():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    # WR02 is the immediate inventory predecessor; W01 remains an explicit SQL prerequisite.
    assert pairs[pairs.index((253, "account_watch")) - 1] == (252, "workstation_overview_projections")
    assert list(PATH.parent.glob("253_*.sql")) == [PATH]
    assert "version=251 and name='workstation_access'" in SQL
    assert "sli_account_watch_v253" in SQL
    assert "version=249 and name='watch_registry'" in SQL
    assert "version=248 and name='entity_context_history_reads'" in SQL
    assert "where version>=253" in SQL and "values(253,'account_watch')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    for table in ("finding_evidence_source_bindings", "semantic_risk_policies", "semantic_policy_admission",
                  "notification_channels", "notification_subscriptions", "watch_entry_versions"):
        assert "insert into public." + table not in SQL


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("markers", [
    [(248, "entity_context_history_reads"), (251, "workstation_access")],
    [(247, "entity_context_history_reads"), (249, "watch_registry"), (251, "workstation_access")],
    [(248, "entity_context_history_reads"), (249, "watch_registry")],
    [(248, "entity_context_history_reads"), (249, "watch_registry"), (250, "workstation_access")],
    [(248, "entity_context_history_reads"), (249, "watch_registry"), (251, "wrong_predecessor")],
    [(248, "entity_context_history_reads"), (249, "watch_registry"),
     (251, "workstation_access"), (253, "account_watch")],
    [(248, "entity_context_history_reads"), (249, "watch_registry"),
     (251, "workstation_access"), (254, "later_migration")],
])
def test_forward_migration_rejects_inexact_prerequisites_without_schema_changes(pg, markers):
    import psycopg

    with psycopg.connect(pg, autocommit=True) as conn:
        # Keep the independent column prerequisite valid so each marker check is exercised.
        conn.execute("create table public.notification_outbox(delivery_reason text)")
        with conn.cursor() as cur:
            cur.executemany("insert into schema_migrations values(%s,%s)", markers)
        with pytest.raises(psycopg.errors.RaiseException, match="migration 253 prerequisites failed"):
            conn.execute(SQL)
        conn.execute("rollback")
        assert conn.execute("select to_regclass('public.semantic_account_watch_checks')").fetchone()[0] is None
        assert conn.execute("select count(*) from schema_migrations where version>=247").fetchone()[0] == len(markers)


@pytest.fixture
def watch_pg(publication_pg):
    """Synthetic W01/predecessor contract; source hashes use the N06 fake resolver.

    This deliberately does not claim a complete installation migration chain.
    W01 is a separately verified prerequisite from main.
    """
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.conninfo import make_conninfo

    selected = rule(evaluation_mode="enabled")
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    row = event()
    with psycopg.connect(publication_pg, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("do $$ begin if not exists(select 1 from pg_roles where rolname='sli_test_watch_login') then "
                     "create role sli_test_watch_login login; end if; end $$")
        conn.execute("grant adlog_semantic_worker to sli_test_watch_login")
        conn.execute("""
            set role adlog_storage_owner;
            insert into schema_migrations values(248,'entity_context_history_reads'),(249,'watch_registry'),
                (251,'workstation_access');
            create table watch_entry_versions(id uuid,revision bigint,identity jsonb,entity_id bigint,
                plugin_id text default 'sli.ad',collection_scope_id text,active boolean,active_from timestamptz,
                expires_at timestamptz,valid_from timestamptz,valid_to timestamptz);
            create table storage_v2_channel(id bigint,value text);
            create table storage_v2_provider(id bigint,value text);
            insert into storage_v2_channel values(1,'Security');
            insert into storage_v2_provider values(1,'Microsoft-Windows-Security-Auditing');
            create table events_v2_core(id bigint,event_id integer,domain_id bigint,normalized_hash bytea,
                time_created_utc timestamptz,channel_id bigint default 1,provider_id bigint default 1);
            alter table normalized_events add column processing_status text default 'normalized',
                add column normalizer_id text default 'windows.named-eventdata',
                add column semantic_contract_version integer default 1,add column source_event_sha256 bytea,
                add column occurred_at_utc timestamptz,add column normalized_at timestamptz default now(),
                add column semantic_type text,add column roles_json jsonb,add column quality_json jsonb;
            create table ad_context_runs(run_id uuid,domain_id bigint,status text);
            create table ad_context_entity_versions(id bigint,entity_id bigint,source_section text,
                source_run_id uuid,attributes_json jsonb,valid_from_utc timestamptz,valid_to_utc timestamptz);
            alter table notification_outbox
                drop constraint notification_outbox_object_kind_object_id_recipient_user_id_key,
                add column change_key text not null default 'initial',
                add column object_severity text,add column delivery_reason text default 'live',
                add column delay_minutes integer default 0,
                add constraint notification_outbox_change_key_check check(change_key in ('initial','medium','high')),
                add constraint notification_outbox_change unique(object_kind,object_id,recipient_user_id,channel,change_key);
            create or replace function finding_evidence_scope_allowed(uuid,text,text,text,text,text) returns boolean
                language sql stable as $$ select exists(select 1 from public.fixture_native_evidence
                    where allowed and params->>0=$1::text and params->>1=$2 and params->>2=$3
                      and params->>3=$4 and params->>4=$5 and params->>5=$6) $$;
            reset role;
        """)
        conn.execute(SQL)
        conn.execute("insert into watch_entry_versions values(%s,1,%s::jsonb,41,'sli.ad','ad-domain:7',true,%s,%s,%s,null)",
                     (row["entries"][0]["id"], json.dumps(IDENTITY), now-timedelta(hours=1),
                      now+timedelta(days=1), now-timedelta(hours=1)))
        run_id = uuid4()
        conn.execute("insert into ad_context_runs values(%s,7,'completed')", (run_id,))
        for native_id, sid, guid, entity_id in ((42, IDENTITY["sid"], IDENTITY["guid"], 41),
                (43, "S-1-5-21-100-200-300-9002", "00000000-0000-0000-0000-000000000099", 99)):
            key = "sid:" + sid
            conn.execute("insert into events_v2_core(id,event_id,domain_id,normalized_hash,time_created_utc) "
                         "values(%s,4624,7,%s,%s)", (native_id, bytes.fromhex("a"*64), now))
            conn.execute("insert into normalized_events(normalized_event_id,source_event_id,source_event_sha256,"
                         "occurred_at_utc,semantic_type,roles_json,quality_json) values(%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)",
                         (uuid4(), native_id, bytes.fromhex("a"*64), now, row["semantic_type"],
                          json.dumps({"affected_entity": key}), json.dumps({"identity_roles": {"affected_entity": {
                              "key": key, "state": "resolved", "provisional": False}}})))
            conn.execute("insert into ad_context_entity_versions values(%s,%s,'directory_accounts',%s,%s::jsonb,%s,null)",
                         (entity_id, entity_id, run_id, json.dumps({"identity": {
                             "kind": "ad_user", "object_sid": sid, "object_guid": guid}}), now-timedelta(days=1)))
            from server.sli.storage.evidence_ref import EvidenceRef
            ref = EvidenceRef("core_event", str(native_id), "a"*64, selected.scope)
            conn.execute("insert into fixture_native_evidence values(%s::jsonb,true)", (json.dumps(ref.params),))
        runtime.register_risk_policy(conn.cursor(), policy=watch.risk_policy(selected, policy_id="fixture-qw"))
        conn.execute("update semantic_risk_policies set lifecycle_status='enabled'")
        conn.execute("insert into semantic_policy_admission values('fixture-qw',1,true)")
        conn.execute("insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled) "
                     "values(%s,1,2,'smtp',true),(%s,1,2,'telegram',true)", (uuid4(), uuid4()))
    return publication_pg, make_conninfo(publication_pg, user="sli_test_watch_login"), selected, now


def publish_jobs(conn):
    outcomes = []
    for job in runtime.claim_risk_evaluation_jobs(conn.cursor(), limit=32):
        work = runtime.load_risk_evaluation_work_item(conn.cursor(), job_id=job["job_id"], lease_token=job["lease_token"])
        outcomes.append(runtime.execute_risk_evaluation(conn.cursor(), work=work, evaluation_ms=0, create_finding=True))
    return outcomes


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_two_accounts_one_priority_one_problem_two_outbox_rows_and_replay(watch_pg):
    import psycopg
    from psycopg.rows import dict_row
    admin, login, selected, now = watch_pg
    with psycopg.connect(login, row_factory=dict_row) as conn:
        result = worker.run_once(conn.cursor(), rule=selected, now=now)
        assert result["events"] == 2 and result["results"] == {"observed": 1, "no_match": 1}
        outcome, = publish_jobs(conn)
        assert outcome.finding_created and outcome.risk_class.value == "medium"
    with psycopg.connect(admin, row_factory=dict_row) as conn:
        rows = list(conn.execute("select channel,object_severity,state from notification_outbox order by channel"))
        assert [(r["channel"], r["object_severity"], r["state"]) for r in rows] == [
            ("smtp", "medium", "pending"), ("telegram", "medium", "pending")]
        assert conn.execute("select severity from findings").fetchone()["severity"] == "medium"
        conn.execute("set role adlog_user")
        priority = conn.execute("select account_watch_event_priority(42,%s) as p", ("a"*64,)).fetchone()["p"]
        assert priority == {"base_severity": "low", "effective_severity": "medium", "reason": "watch"}
        assert conn.execute("select account_watch_event_priority(43,%s) as p", ("a"*64,)).fetchone()["p"] is None
        assert conn.execute("select account_watch_event_priority(42,%s) as p", ("b"*64,)).fetchone()["p"] is None
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=now)["events"] == 0
    with psycopg.connect(admin) as conn:
        assert conn.execute("select count(*) from notification_outbox").fetchone()[0] == 2


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_rollback_revocation_and_raw_registry_access(watch_pg):
    import psycopg
    from psycopg.rows import dict_row
    from dataclasses import replace
    admin, login, selected, now = watch_pg
    with pytest.raises(RuntimeError, match="synthetic_rollback"), psycopg.connect(login, row_factory=dict_row) as conn:
        worker.run_once(conn.cursor(), rule=selected, now=now)
        assert publish_jobs(conn)[0].finding_created
        raise RuntimeError("synthetic_rollback")
    with psycopg.connect(admin) as conn:
        for table in ("semantic_account_watch_checks", "semantic_qw_signals", "findings", "notification_outbox"):
            assert conn.execute("select count(*) from " + table).fetchone()[0] == 0
    other = replace(selected, scope=replace(selected.scope, source_generation="synthetic-other"))
    with pytest.raises(psycopg.errors.InsufficientPrivilege), psycopg.connect(login, row_factory=dict_row) as conn:
        worker.run_once(conn.cursor(), rule=other, now=now)
    with pytest.raises(psycopg.errors.InsufficientPrivilege), psycopg.connect(login) as conn:
        conn.execute("select * from watch_entry_versions")
    with psycopg.connect(admin) as conn:
        conn.execute("update fixture_native_evidence set allowed=false")
    with pytest.raises(psycopg.errors.InsufficientPrivilege), psycopg.connect(login, row_factory=dict_row) as conn:
        worker.run_once(conn.cursor(), rule=selected, now=now)

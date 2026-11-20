"""N08 forward migration and actual SQL against disposable PostgreSQL only."""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.semantic import nps_threshold as nps, nps_threshold_runtime as worker
from server.sli.semantic import qw_input as qw, semantic_risk_runtime_repository as runtime
from tests.migrations.test_qw_semantic_input_migration228 import pg as pg
from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg
from tests.unit.test_nps_threshold import rule

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/230_nps_threshold.sql"
SQL = PATH.read_text("utf-8")
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def test_forward_migration_is_additive_dormant_and_exact():
    assert list(PATH.parent.glob("230_*.sql")) == [PATH]
    assert "version=229 and name='qw_finding_notifications'" in SQL
    assert "where version>=230" in SQL and "values(230,'nps_threshold')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "grant select on public.normalized_events to adlog_semantic_worker" not in SQL
    assert "insert into public.finding_evidence_source_bindings" not in SQL
    assert "insert into public.semantic_risk_policies" not in SQL


@pytest.fixture
def nps_pg(publication_pg):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    selected = rule(evaluation_mode="enabled")
    source = (ROOT / "config/postgres_migrations/219_finding_evidence_refs.sql").read_text("utf-8")
    with psycopg.connect(publication_pg, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("set role adlog_storage_owner")
        binding = source[source.index("create table public.finding_evidence_source_bindings"):].split("\n);", 1)[0] + "\n);"
        conn.execute(binding)
        conn.execute("""
            alter table normalized_events add column occurred_at_utc timestamptz,
                add column facts_json jsonb,add column roles_json jsonb,add column quality_json jsonb,
                add column normalizer_id text,add column normalized_at timestamptz default now(),
                add column semantic_contract_version integer,add column processing_status text,add column semantic_type text;
            create table events_v2_core(id bigint primary key,event_id integer,log_source_id bigint,
                normalized_hash bytea,raw_log_file_id bigint,time_created_utc timestamptz);
            create table raw_log_files(id bigint primary key,file_path text);
            create table sli_agent_packet_inbox(packet_id uuid primary key,envelope jsonb,packet jsonb,
                imported_at timestamptz,received_at timestamptz default now());
            create table sli_agent_receipts(packet_id uuid primary key,module_id text,receipt jsonb,envelope jsonb,
                agent_id uuid default '00000000-0000-0000-0000-000000000003',sequence bigserial);
            reset role;
        """)
        # Use the actual native source verifier and login-bound authorization.
        for name in ("finding_evidence_scope_allowed", "resolve_finding_evidence_ref"):
            function = "create or replace function public." + name + "(" + source.split(
                "create function public." + name + "(", 1)[1].split("$$;", 1)[0] + "$$;"
            conn.execute("set role adlog_storage_owner")
            conn.execute(function)
            conn.execute("reset role")
        conn.execute(SQL)
        # Fixed disposable login; session_user matters even after SET ROLE.
        conn.execute("do $$ begin if not exists(select 1 from pg_roles where rolname='sli_test_nps_login') then "
                     "create role sli_test_nps_login login; end if; end $$")
        conn.execute("grant adlog_semantic_worker to sli_test_nps_login")
        conn.execute("insert into finding_evidence_source_bindings values("
                     "'sli_test_nps_login'::regrole::oid,'sli_test_nps_login',%s,%s,%s,%s,'','core_event',1,null,%s)",
                     (selected.scope.installation_id, selected.scope.plugin_id, selected.scope.source_instance_id,
                      selected.scope.source_generation, "00000000-0000-0000-0000-000000000003"))
        runtime.register_risk_policy(conn.cursor(), policy=nps.risk_policy(selected, policy_id="fixture-qw"))
        conn.execute("update semantic_risk_policies set lifecycle_status='enabled'")
        conn.execute("insert into semantic_policy_admission values('fixture-qw',1,true)")
        conn.execute("insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled) "
                     "values(%s,1,2,'smtp',true),(%s,1,2,'telegram',true)", (uuid4(), uuid4()))
    return publication_pg, make_conninfo(publication_pg, user="sli_test_nps_login"), selected


def seed_events(dsn, selected, now, *, count=20, previous=0, complete=False):
    import psycopg
    packet_id = uuid4()
    envelope = {"agent_id": "00000000-0000-0000-0000-000000000003", "source_instance_id": selected.scope.source_instance_id,
                "generation": selected.scope.source_generation}
    continuity = ({"status": "complete", "from_utc": (now - timedelta(minutes=10)).isoformat(), "to_utc": now.isoformat()}
                  if complete else {"status": "not_proven"})
    with psycopg.connect(dsn) as conn:
        conn.execute("insert into sli_agent_packet_inbox values(%s,%s::jsonb,%s::jsonb,now(),now())",
                     (packet_id, json.dumps(envelope), json.dumps({"header": {"observed_at_utc": now.isoformat()}, "continuity": continuity})))
        conn.execute("insert into sli_agent_receipts(packet_id,module_id,receipt,envelope) values(%s,%s,'{\"status\":\"committed\"}'::jsonb,%s::jsonb)",
                     (packet_id, selected.scope.plugin_id, json.dumps(envelope)))
        conn.execute("insert into raw_log_files values(1,%s)", ("agent-packet:" + str(packet_id),))
        for index in range(count + previous):
            stamp = now - timedelta(seconds=10 + index if index < count else 310 + index - count)
            conn.execute("insert into events_v2_core values(%s,6273,1,decode(%s,'hex'),1,%s)", (index + 1, "b" * 64, stamp))
            conn.execute("""insert into normalized_events(normalized_event_id,source_event_id,occurred_at_utc,facts_json,roles_json,
                quality_json,normalizer_id,semantic_contract_version,processing_status,semantic_type)
                values(%s,%s,%s,'{}','{}','{}','windows.named-eventdata',1,'normalized','remote_access.authentication.denied')""",
                (uuid4(), index + 1, stamp))


def publish_jobs(conn):
    results = []
    for job in runtime.claim_risk_evaluation_jobs(conn.cursor(), limit=16):
        work = runtime.load_risk_evaluation_work_item(conn.cursor(), job_id=job["job_id"], lease_token=job["lease_token"])
        results.append(runtime.execute_risk_evaluation(conn.cursor(), work=work, evaluation_ms=0, create_finding=True))
    return results


@pytest.mark.parametrize("complete,previous,expected", [(False, 1, "medium"), (True, 1, "high"), (True, 0, "medium")])
def test_sql_windows_native_evidence_publication_and_both_channels(nps_pg, complete, previous, expected):
    import psycopg
    from psycopg.rows import dict_row
    admin, login, selected = nps_pg
    now = datetime.now(timezone.utc)
    seed_events(admin, selected, now, previous=previous, complete=complete)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        result = worker.run_once(conn.cursor(), rule=selected, now=now)
        assert result["rows"][0]["count"] == 20 and result["jobs"] == 1
        published, = publish_jobs(conn)
        assert published.risk_class.value == expected and published.finding_created
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=now + timedelta(seconds=1))["jobs"] == 0
    with psycopg.connect(admin, row_factory=dict_row) as conn:
        jobs = conn.execute("select channel,object_severity from notification_outbox order by channel").fetchall()
        assert jobs == [{"channel": "smtp", "object_severity": expected}, {"channel": "telegram", "object_severity": expected}]
        finding = conn.execute("select severity,summary from findings").fetchone()
        assert finding["severity"] == expected and "20 unique denials" in finding["summary"]
        assert ("partial/partial" if not complete else "good/good") in finding["summary"]


def test_sql_19_no_job_20_one_pair_and_rollback_keeps_checkpoint(nps_pg):
    import psycopg
    from psycopg.rows import dict_row
    admin, login, selected = nps_pg
    now = datetime.now(timezone.utc)
    seed_events(admin, selected, now, count=19)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=now)["jobs"] == 0
    with psycopg.connect(admin) as conn:
        conn.execute("insert into events_v2_core values(20,6273,1,decode(%s,'hex'),1,%s)", ("b" * 64, now - timedelta(seconds=1)))
        conn.execute("insert into normalized_events select %s,20,%s,facts_json,roles_json,quality_json,normalizer_id,normalized_at,"
                     "semantic_contract_version,processing_status,semantic_type from normalized_events limit 1", (uuid4(), now - timedelta(seconds=1)))
    with pytest.raises(RuntimeError, match="fixture_rollback"), psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=now)["jobs"] == 1
        assert publish_jobs(conn)[0].finding_created
        raise RuntimeError("fixture_rollback")
    with psycopg.connect(admin) as conn:
        for table in ("findings", "semantic_qw_signals", "notification_outbox"):
            assert conn.execute("select count(*) from " + table).fetchone()[0] == 0
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=now)["jobs"] == 1
        assert publish_jobs(conn)[0].finding_created


def test_sql_source_rls_revocation_and_absent_nps(nps_pg):
    import psycopg
    from psycopg.rows import dict_row
    admin, login, selected = nps_pg
    now = datetime.now(timezone.utc)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        result = worker.run_once(conn.cursor(), rule=selected, now=now)
        assert result["state"] == "not_proven" and not result["rows"] and result["jobs"] == 0
    foreign = replace(selected, scope=replace(selected.scope, source_generation="generation-other"))
    with psycopg.connect(login, row_factory=dict_row) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        worker.run_once(conn.cursor(), rule=foreign, now=now)
    with psycopg.connect(admin) as conn:
        conn.execute("delete from finding_evidence_source_bindings")
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert conn.execute("select count(*) as n from semantic_nps_threshold_state").fetchone()["n"] == 0
    with psycopg.connect(login) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("select * from events_v2_core")


def test_sql_confirmed_escalation_keeps_episode_and_sends_each_channel_once(nps_pg):
    import psycopg
    from psycopg.rows import dict_row
    admin, login, selected = nps_pg
    now = datetime.now(timezone.utc)
    seed_events(admin, selected, now, previous=1)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        worker.run_once(conn.cursor(), rule=selected, now=now)
        first, = publish_jobs(conn)
        assert first.risk_class.value == "medium"
    with psycopg.connect(admin) as conn:
        conn.execute("update sli_agent_packet_inbox set packet=jsonb_set(packet,'{continuity}',%s::jsonb)",
                     (json.dumps({"status": "complete", "from_utc": (now - timedelta(minutes=10)).isoformat(), "to_utc": now.isoformat()}),))
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=now)["jobs"] == 1
        second, = publish_jobs(conn)
        assert second.risk_class.value == "high" and second.finding_id == first.finding_id
        assert second.scenario_id == first.scenario_id and not second.finding_created
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=now)["jobs"] == 0
        assert conn.execute("select enqueue_qw_finding_notifications(%s) as n", (first.scenario_id,)).fetchone()["n"] == 0
    with psycopg.connect(admin) as conn:
        assert conn.execute("select count(*) from findings").fetchone()[0] == 1
        assert conn.execute("select channel,change_key,count(*) from notification_outbox group by channel,change_key "
                            "order by channel,change_key").fetchall() == [
            ("smtp", "high", 1), ("smtp", "medium", 1), ("telegram", "high", 1), ("telegram", "medium", 1)]

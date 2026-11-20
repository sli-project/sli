"""N07 forward migration and disposable PostgreSQL publication/outbox tests."""
from dataclasses import replace
import json
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.semantic import qw_input as qw, semantic_risk_runtime_repository as runtime
from server.sli.storage.evidence_ref import EvidenceRefError
from tests.migrations.test_qw_semantic_input_migration228 import pg as pg, seed_policy
from tests.semantic.test_semantic_risk1 import _snapshot
from tests.unit.test_qw_semantic_input import signal

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/229_qw_finding_notifications.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_is_additive_dormant_and_uses_the_next_number():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((229, "qw_finding_notifications")) - 1] == (228, "qw_semantic_input")
    assert list(PATH.parent.glob("229_*.sql")) == [PATH]
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "version=228 and name='qw_semantic_input'" in SQL and "where version>=229" in SQL
    assert "values(229,'qw_finding_notifications')" in SQL
    assert "grant execute on function public.enqueue_qw_finding_notifications(uuid) to adlog_semantic_worker" in SQL
    assert "grant select,insert on public.notification" not in SQL
    assert "publication_scenario_id uuid references public.semantic_finding_publications(scenario_id) on delete restrict" in SQL
    assert SQL.count("qw_signal_id is null") == 8


@pytest.fixture
def publication_pg(pg, monkeypatch):
    """Synthetic predecessor tables with actual scenario and link definitions."""
    import psycopg
    from psycopg.rows import dict_row

    def table(migration, name):
        source = (ROOT / "config/postgres_migrations" / migration).read_text("utf-8")
        return source[source.index("create table " + name):].split("\n);", 1)[0] + "\n);"

    with psycopg.connect(pg, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("set role adlog_storage_owner")
        conn.execute("""
            alter table canonical_actions add primary key(canonical_action_id);
            alter table semantic_correlation_candidates add primary key(candidate_id);
            create table normalized_events(normalized_event_id uuid primary key,source_event_id bigint);
            alter table semantic_detection_matches add primary key(match_id);
            alter table semantic_detection_matches add column evidence_key text;
            create table findings(id bigserial primary key,fingerprint text unique,rule_code text,title text,severity text,
                confidence numeric,status text,first_seen_utc text,last_seen_utc text,actor text,target text,source text,
                summary text,why_it_matters text,recommended_action text,evidence_count bigint,status_reason text,
                repeat_count integer,last_evidence_event_id bigint,updated_at timestamptz);
            create table finding_evidence(id bigserial primary key,finding_id bigint references findings(id),event_id bigint,
                evidence_role text,note text,unique(finding_id,event_id,evidence_role));
            create table finding_entities(id bigserial primary key,finding_id bigint,entity_type text,display_name text,entity_role text);
            create table finding_status_history(id bigserial primary key,finding_id bigint,old_status text,new_status text,changed_by text,note text);
            create table notification_channels(kind text primary key);
            insert into notification_channels values('smtp'),('telegram');
        """)
        for name in ("semantic_security_scenarios", "semantic_scenario_steps", "semantic_scenario_evidence",
                     "semantic_risk_contributions", "semantic_scenario_coverage_history"):
            conn.execute(table("028_semantic_risk_scenarios.sql", "if not exists " + name))
        detection = (ROOT / "config/postgres_migrations/220_detection_match_risk.sql").read_text("utf-8")
        for name in ("semantic_scenario_steps", "semantic_risk_contributions"):
            conn.execute("alter table public." + name + "\n" + detection.split(
                "alter table public." + name + "\n", 1)[1].split(";", 1)[0])
        conn.execute(table("055_semantic_finding_publication.sql", "if not exists semantic_finding_publications"))
        conn.execute(table("219_finding_evidence_refs.sql", "public.finding_evidence_refs"))
        # Exercise the actual native linker, against the fake immutable source
        # resolver installed by N06's disposable fixture.
        native = (ROOT / "config/postgres_migrations/219_finding_evidence_refs.sql").read_text("utf-8")
        conn.execute("create function public.link_finding_evidence_ref(" + native.split(
            "create function public.link_finding_evidence_ref(", 1)[1].split("$$;", 1)[0] + "$$;")
        for name in ("notification_subscriptions", "notification_outbox", "notification_attempts"):
            conn.execute(table("225_notification_outbox.sql", "public." + name))
        conn.execute("""
            grant select,insert,update on semantic_security_scenarios,findings to adlog_semantic_worker;
            grant select,insert on semantic_scenario_steps,semantic_scenario_evidence,semantic_risk_contributions,
                semantic_scenario_coverage_history,semantic_finding_publications,finding_evidence,finding_entities,
                finding_status_history to adlog_semantic_worker;
            grant select on normalized_events,finding_evidence_refs to adlog_semantic_worker;
            grant usage,select on all sequences in schema public to adlog_semantic_worker;
            grant select,insert on notification_outbox,notification_subscriptions to adlog_user;
            grant update(state,attempts,lease_token,lease_until,available_at,result_code,updated_at) on notification_outbox to adlog_user;
            create function is_semantic_finding_published_v1(bigint) returns boolean language sql stable
                security definer set search_path=pg_catalog,pg_temp as $$
                select exists(select 1 from public.semantic_finding_publications where finding_id=$1) $$;
            reset role;
        """)
        conn.execute(SQL)
    monkeypatch.setattr(runtime, "_capture_completeness_snapshot", lambda *a, **kw: _snapshot(complete=False))
    monkeypatch.setattr(runtime, "record_scenario_identity_supersessions", lambda *a, **kw: None)
    monkeypatch.setattr(runtime, "record_finding_identity_supersessions", lambda *a, **kw: None)
    return pg


def seed(dsn, item, *, recipient=2):
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        seed_policy(conn, item)
        conn.execute("insert into semantic_policy_admission values('fixture-qw',1,true)")
        conn.execute("insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled) values(%s,1,%s,'smtp',true)",
                     (str(uuid4()), recipient))


def evaluate(conn, item):
    conn.execute("set role adlog_semantic_worker")
    cur = conn.cursor()
    job, = qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    claimed, = runtime.claim_risk_evaluation_jobs(cur)
    work = runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token=claimed["lease_token"])
    return runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_enabled_has_one_queue_row_job_and_native_portions(publication_pg):
    import psycopg
    from psycopg.rows import dict_row
    item = signal(evaluation_mode="enabled")
    ref, = item.evidence_refs
    item = replace(item, evidence_refs=tuple(replace(ref, native_id=str(n)) for n in range(1, 257)), evidence_total=257)
    seed(publication_pg, item)
    with psycopg.connect(publication_pg, row_factory=dict_row) as conn:
        first = evaluate(conn, item)
        assert first.finding_id is None and first.publication_state == "evidence_pending"
        conn.execute("reset role")
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 0
        assert conn.execute("select count(*) as n from findings").fetchone()["n"] == 0
    other = replace(item, evidence_refs=(replace(ref, native_id="257"),))
    with psycopg.connect(publication_pg, row_factory=dict_row) as conn:
        conn.execute("insert into fixture_native_evidence values(%s::jsonb,true)", (json.dumps(other.evidence_refs[0].params),))
    with psycopg.connect(publication_pg, row_factory=dict_row) as conn:
        second = evaluate(conn, other)
        assert second.scenario_id == first.scenario_id and second.finding_created
    with psycopg.connect(publication_pg) as conn:
        conn.execute("update findings set status='closed'")
    for _ in range(2):
        with psycopg.connect(publication_pg, row_factory=dict_row) as conn:
            conn.execute("set role adlog_semantic_worker")
            assert qw.enqueue_qw_signal_risk_jobs(conn.cursor(), signal=item)
            assert conn.execute("select enqueue_qw_finding_notifications(%s)", (first.scenario_id,)).fetchone()["enqueue_qw_finding_notifications"] == 0
    with psycopg.connect(publication_pg, row_factory=dict_row) as conn:
        assert conn.execute("select count(*) as n from findings where is_semantic_finding_published_v1(id)").fetchone()["n"] == 1
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 1
        assert conn.execute("select evidence_count,status from findings").fetchone() == {"evidence_count": 257, "status": "closed"}
        assert conn.execute("select count(*) as n from finding_evidence_refs").fetchone()["n"] == 257


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("failure", ["caller_rollback", "outbox_failure", "bad_evidence"])
def test_postgres_failure_rolls_back_problem_publication_and_outbox(publication_pg, failure):
    import psycopg
    from psycopg.rows import dict_row
    item = signal(evaluation_mode="enabled")
    seed(publication_pg, item)
    if failure == "outbox_failure":
        with psycopg.connect(publication_pg) as conn:
            conn.execute("""create function fixture_reject_outbox() returns trigger language plpgsql as $$
                begin raise exception 'synthetic delivery admission failure'; end $$;
                create trigger fixture_outbox before insert on notification_outbox
                for each row execute function fixture_reject_outbox();""")
    with pytest.raises((RuntimeError, psycopg.Error, EvidenceRefError)), psycopg.connect(publication_pg, row_factory=dict_row) as conn:
        if failure == "bad_evidence":
            conn.execute("update fixture_native_evidence set allowed=false")
        evaluate(conn, item)
        if failure == "caller_rollback":
            raise RuntimeError("synthetic rollback")
    with psycopg.connect(publication_pg) as conn:
        for table_name in ("findings", "semantic_finding_publications", "notification_outbox", "finding_evidence_refs"):
            assert conn.execute("select count(*) from " + table_name).fetchone()[0] == 0


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_linkage_and_least_privilege(publication_pg):
    import psycopg
    from psycopg.rows import dict_row
    item = signal(evaluation_mode="enabled")
    seed(publication_pg, item)
    with psycopg.connect(publication_pg, row_factory=dict_row) as conn:
        published = evaluate(conn, item)
    for role, statement in (
        ("adlog_user", "select enqueue_qw_finding_notifications('00000000-0000-0000-0000-000000000000')"),
        ("adlog_semantic_worker", "select * from notification_subscriptions"),
        ("adlog_semantic_worker", "select * from notification_outbox"),
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege), psycopg.connect(publication_pg) as conn:
            conn.execute("set role " + role)
            conn.execute(statement)
    with psycopg.connect(publication_pg) as conn:
        conn.execute("set role adlog_user")
        assert conn.execute("select notification_finding_object(%s)", (published.scenario_id,)).fetchone()[0] == published.finding_id
    with pytest.raises(psycopg.errors.CheckViolation), psycopg.connect(publication_pg) as conn:
        conn.execute("update notification_outbox set object_id=%s", (str(uuid4()),))
    with psycopg.connect(publication_pg) as conn:
        conn.execute("update semantic_policy_admission set enabled=false")
    with pytest.raises(psycopg.errors.RaiseException, match="qw_publication_unavailable"), psycopg.connect(publication_pg) as conn:
        conn.execute("set role adlog_semantic_worker")
        conn.execute("select enqueue_qw_finding_notifications(%s)", (published.scenario_id,))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("kind", ["workstation_observation", "file_audit_observation"])
def test_postgres_plugin_ids_stay_native_and_do_not_become_core_event_ids(publication_pg, kind):
    import psycopg
    from psycopg.rows import dict_row
    item = signal(kind, evaluation_mode="enabled")
    seed(publication_pg, item)
    with psycopg.connect(publication_pg, row_factory=dict_row) as conn:
        published = evaluate(conn, item)
    with psycopg.connect(publication_pg, row_factory=dict_row) as conn:
        assert published.finding_created
        assert conn.execute("select count(*) as n from finding_evidence").fetchone()["n"] == 0
        assert conn.execute("select storage_kind,native_id from finding_evidence_refs").fetchone() == {
            "storage_kind": kind, "native_id": item.evidence_refs[0].native_id,
        }
        assert conn.execute("select evidence_count,last_evidence_event_id from findings").fetchone() == {
            "evidence_count": 1, "last_evidence_event_id": None,
        }
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 1

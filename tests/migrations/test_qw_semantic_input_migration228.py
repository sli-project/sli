"""N06 forward schema, ACL and isolated PostgreSQL admission contracts."""
import json
import os
from pathlib import Path
import re

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.semantic import qw_input as qw, semantic_risk_runtime_repository as runtime
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_qw_semantic_input import policy, signal

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/228_qw_semantic_input.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_is_dormant_transactional_and_has_exact_predecessor():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((228, "qw_semantic_input")) - 1] == (227, "notification_telegram")
    assert list(PATH.parent.glob("228_*.sql")) == [PATH]
    for fragment in ("begin;", "pg_advisory_xact_lock", "pg_has_role(session_user,'adlog_storage_owner','MEMBER')",
                     "version=227 and name='notification_telegram'", "where version>=228",
                     "values(228,'qw_semantic_input')", "set local role adlog_storage_owner"):
        assert fragment in SQL
    assert SQL.strip().endswith("commit;")
    assert not re.search(r"insert into (?:public\.)?(?:semantic_risk_policies|semantic_policy_admission|findings|notification_outbox)\b", SQL)


def test_native_inputs_are_bounded_immutable_and_all_evidence_is_authorized():
    for fragment in ("before update or delete", "before truncate", "enable row level security",
                     "between 1 and 256", "octet_length(document_json::text)<=524288",
                     "jsonb_array_elements(document->'evidence_refs')", "bool_and(coalesce(",
                     "public.resolve_finding_evidence_ref(", "public.finding_evidence_scope_allowed(",
                     "using (public.qw_signal_evidence_allowed(document_json,false))",
                     "with check (public.qw_signal_evidence_allowed(document_json,true))",
                     "qw_signal_id text references public.semantic_qw_signals(signal_id) on delete restrict"):
        assert fragment in SQL
    assert SQL.count("qw_signal_id is null") == 4
    assert "grant select,insert on public.semantic_qw_signals to adlog_semantic_worker" in SQL
    assert "grant select on public.semantic_qw_signals to adlog_storage_worker" in SQL
    assert not re.search(r"grant\s+(?:update|delete|truncate|all)[^;]+semantic_qw_signals", SQL, re.I)
    assert "security definer" not in SQL.lower()


@pytest.fixture
def pg():
    """Minimal synthetic predecessor, never an installation or live source."""
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL not configured")
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        for role in ("adlog_storage_owner", "adlog_user", "adlog_storage_worker", "adlog_semantic_worker"):
            if not conn.execute("select 1 from pg_roles where rolname=%s", (role,)).fetchone():
                conn.execute(sql.SQL("create role {} nologin").format(sql.Identifier(role)))
        conn.execute("""
            grant usage,create on schema public to adlog_storage_owner;
            grant usage on schema public to adlog_user,adlog_storage_worker,adlog_semantic_worker;
            set role adlog_storage_owner;
            create table schema_migrations(version integer primary key,name text);
            insert into schema_migrations values(52,'semantic_conclusion_completeness'),(227,'notification_telegram');
            create table semantic_risk_policies(
                policy_id text,policy_version integer,source_kind text check(source_kind<>'qw_signal'),
                lifecycle_status text default 'draft',definition_json jsonb,definition_sha256 bytea,
                updated_at timestamptz default now(),primary key(policy_id,policy_version));
            create table semantic_risk_policy_subscriptions(
                policy_id text,policy_version integer,source_kind text check(source_kind<>'qw_signal'),
                selector_value text,definition_sha256 bytea,primary key(policy_id,policy_version));
            create table semantic_policy_admission(policy_id text,policy_version integer,enabled boolean);
            create table semantic_risk_evaluation_jobs(
                job_id uuid primary key,policy_id text,policy_version integer,
                source_kind text check(source_kind<>'qw_signal'),canonical_action_id uuid,
                correlation_candidate_id uuid,control_health_id uuid,detection_match_id text,
                source_reference text,evaluation_mode text,idempotency_key bytea unique,
                evaluation_status text default 'queued',attempt_count integer default 0,max_attempts integer default 5,
                available_at timestamptz default now(),created_at timestamptz default now(),
                updated_at timestamptz,completed_at timestamptz,heartbeat_at timestamptz,
                lease_token uuid,lease_until timestamptz,last_error_code text,last_error_detail text,
                constraint semantic_risk_evaluation_source check(source_kind<>'qw_signal'));
            create table semantic_risk_evaluation_results(
                job_id uuid primary key,scenario_id uuid,evaluation_mode text,risk_class text,
                raw_score numeric,display_score integer,hard_critical boolean,confidence text,
                confidence_score integer,coverage_status text,evaluation_ms integer,conclusion_state text,
                completeness_snapshot_json jsonb);
            create table fixture_native_evidence(params jsonb primary key,allowed boolean not null);
            create table canonical_actions(canonical_action_id uuid,action_kind text,action_status text,occurred_at_utc timestamptz);
            create table semantic_correlation_candidates(candidate_id uuid,relation_kind text,candidate_status text,first_matched_at timestamptz);
            create table semantic_control_health_observations(observation_id uuid,control_id text,observed_at_utc timestamptz);
            create table semantic_detection_matches(match_id text,rule_id text,evaluation_mode text,occurred_at_utc timestamptz,document_json jsonb);
            create function finding_evidence_scope_allowed(uuid,text,text,text,text,text) returns boolean
                language sql stable as $$ select coalesce(bool_and(allowed),false) from public.fixture_native_evidence $$;
            create function resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) returns boolean
                language sql stable as $$ select coalesce((select allowed from public.fixture_native_evidence
                    where params=jsonb_build_array($1::text,$2,$3,$4,$5,$6,$7,$8)),false) $$;
            create function semantic_policy_mode_v160(text,integer,text) returns text
                language sql stable as $$ select $3 $$;
            grant select on schema_migrations,semantic_risk_policies,semantic_policy_admission,
                semantic_risk_policy_subscriptions,fixture_native_evidence to adlog_semantic_worker;
            grant select,insert,update on semantic_risk_evaluation_jobs,semantic_risk_evaluation_results
                to adlog_semantic_worker;
            grant update(policy_id) on semantic_risk_policies to adlog_semantic_worker;
            grant select on canonical_actions,semantic_correlation_candidates,semantic_control_health_observations,
                semantic_detection_matches to adlog_semantic_worker;
            reset role;
        """)
        conn.execute(SQL)
    yield dsn


def seed_policy(conn, item):
    runtime.register_risk_policy(conn.cursor(), policy=policy(item))
    conn.execute("update semantic_risk_policies set lifecycle_status=%s", (item.evaluation_mode,))
    for ref in item.evidence_refs:
        conn.execute("insert into fixture_native_evidence values(%s::jsonb,true) on conflict do nothing",
                     (json.dumps(ref.params),))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("mode", ["test", "shadow"])
def test_postgres_migration_replay_lease_diagnostics_and_native_rls(pg, mode, monkeypatch):
    import psycopg
    from psycopg.rows import dict_row

    item = signal(evaluation_mode=mode)
    with psycopg.connect(pg, row_factory=dict_row) as conn:
        seed_policy(conn, item)
    with psycopg.connect(pg, row_factory=dict_row) as conn:
        conn.execute("set role adlog_semantic_worker")
        jobs = qw.enqueue_qw_signal_risk_jobs(conn.cursor(), signal=item)
        assert len(jobs) == 1
    with psycopg.connect(pg, row_factory=dict_row) as conn:
        conn.execute("set role adlog_semantic_worker")
        assert qw.enqueue_qw_signal_risk_jobs(conn.cursor(), signal=item) == jobs
        job, = runtime.claim_risk_evaluation_jobs(conn.cursor())
        # Completeness is already covered independently; this fixture contains
        # native evidence and semantic jobs only, with no collection sources.
        from tests.semantic.test_semantic_risk1 import _snapshot
        monkeypatch.setattr(runtime, "_capture_completeness_snapshot", lambda *args, **kwargs: _snapshot(complete=False))
        work = runtime.load_risk_evaluation_work_item(conn.cursor(), job_id=job["job_id"], lease_token=job["lease_token"])
        result = runtime.execute_risk_evaluation(conn.cursor(), work=work, evaluation_ms=1, create_finding=True)
        assert result.scenario_id is None and result.finding_id is None
        assert conn.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 1
        assert conn.execute("select evaluation_mode from semantic_risk_evaluation_results").fetchone()["evaluation_mode"] == mode
    with psycopg.connect(pg) as conn:
        conn.execute("update fixture_native_evidence set allowed=false")
    with psycopg.connect(pg) as conn:
        conn.execute("set role adlog_semantic_worker")
        assert conn.execute("select count(*) from semantic_qw_signals").fetchone()[0] == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("insert into semantic_qw_signals values(%s,%s,%s::jsonb,now())",
                         ("f" * 64, mode, json.dumps(item.document)))
    with psycopg.connect(pg) as conn:
        conn.execute("set role adlog_storage_worker")
        assert conn.execute("select count(*) from semantic_qw_signals").fetchone()[0] == 0
    with psycopg.connect(pg) as conn:
        conn.execute("set role adlog_user")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("select * from semantic_qw_signals")


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_input_immutability_reference_constraints_and_rollback(pg):
    import psycopg
    from psycopg.rows import dict_row

    item = signal()
    with psycopg.connect(pg, row_factory=dict_row) as conn:
        seed_policy(conn, item)
    with pytest.raises(RuntimeError, match="fixture rollback"), psycopg.connect(pg, row_factory=dict_row) as conn:
        conn.execute("set role adlog_semantic_worker")
        assert qw.enqueue_qw_signal_risk_jobs(conn.cursor(), signal=item)
        raise RuntimeError("fixture rollback")
    with psycopg.connect(pg) as conn:
        assert conn.execute("select count(*) from semantic_qw_signals").fetchone()[0] == 0
        assert conn.execute("select count(*) from semantic_risk_evaluation_jobs").fetchone()[0] == 0
        conn.execute("insert into semantic_qw_signals values(%s,%s,%s::jsonb,now())",
                     (item.signal_id, item.evaluation_mode, json.dumps(item.document)))
    for statement in ("update semantic_qw_signals set evaluation_mode='test'", "delete from semantic_qw_signals",
                      "truncate semantic_qw_signals cascade"):
        with psycopg.connect(pg) as conn, pytest.raises(psycopg.errors.RaiseException):
            conn.execute(statement)
    with psycopg.connect(pg, row_factory=dict_row) as conn:
        conn.execute("set role adlog_semantic_worker")
        jobs = qw.enqueue_qw_signal_risk_jobs(conn.cursor(), signal=item)
    with psycopg.connect(pg) as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("update semantic_risk_evaluation_jobs set source_reference=%s", ("f" * 64,))
    with psycopg.connect(pg) as conn, pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn.execute("update semantic_risk_evaluation_jobs set qw_signal_id=%s,source_reference=%s", ("f" * 64, "f" * 64))
    assert len(jobs) == 1


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_backlog_checks_pin_revision_mode_and_enabled_admission(pg):
    import psycopg
    from psycopg.rows import dict_row

    item = signal(evaluation_mode="enabled")
    with psycopg.connect(pg, row_factory=dict_row) as conn:
        seed_policy(conn, item)
        conn.execute("set role adlog_semantic_worker")
        assert qw.enqueue_qw_signal_risk_jobs(conn.cursor(), signal=item) == ()
        assert runtime.enqueue_risk_backlog(conn.cursor()) == ()
    with psycopg.connect(pg) as conn:
        conn.execute("insert into semantic_policy_admission values('fixture-qw',1,true)")
    with psycopg.connect(pg, row_factory=dict_row) as conn:
        conn.execute("set role adlog_semantic_worker")
        jobs = runtime.enqueue_risk_backlog(conn.cursor())
        assert len(jobs) == 1 and runtime.enqueue_risk_backlog(conn.cursor()) == ()
        assert len(runtime.claim_risk_evaluation_jobs(conn.cursor())) == 1

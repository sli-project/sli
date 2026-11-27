"""N06 forward schema, ACL and isolated PostgreSQL admission contracts."""
import json
import os
from pathlib import Path
import re

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.postgres_integration_guard import assert_disposable_database

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

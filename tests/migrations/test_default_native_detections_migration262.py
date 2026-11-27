"""Default policy admission and native domain membership on disposable SQL only."""
from dataclasses import asdict
import json
from pathlib import Path

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg

from tests.migrations.test_qw_semantic_input_migration228 import pg as pg

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/262_default_native_detections.sql").read_text("utf-8")


def test_forward_defaults_preserve_owner_decisions_and_do_not_duplicate_l1():
    assert "version=261 and name='telegram_delivery'" in SQL
    assert "where version>=262" in SQL and "values(262,'default_native_detections')" in SQL
    assert "true,'system:defaults'" in SQL
    assert "on conflict(policy_id,policy_version) do nothing" in SQL
    assert "update public.semantic_policy_admission" not in SQL
    assert "l1-audit-policy-changed" not in SQL
    assert "grant select,insert,update on public.semantic_policy_admission" not in SQL
    assert "limit 128" in SQL and "limit 10001" in SQL
    assert "binding.principal_name" in SQL and "r.rolname=session_user" in SQL


@pytest.fixture
def defaults_pg(publication_pg):
    import psycopg
    source = (ROOT / "config/postgres_migrations/219_finding_evidence_refs.sql").read_text("utf-8")
    governance = (ROOT / "config/postgres_migrations/153_semantic_governance.sql").read_text("utf-8")
    with psycopg.connect(publication_pg, autocommit=True) as conn:
        conn.execute("create schema sli_plugin_file_audit authorization adlog_storage_owner")
        conn.execute("create schema sli_sigma authorization adlog_storage_owner")
        conn.execute("set role adlog_storage_owner")
        conn.execute(source[source.index("create table public.finding_evidence_source_bindings"):].split("\n);", 1)[0] + "\n);")
        conn.execute("""
            insert into schema_migrations values(259,'admin_problem_evidence'),(261,'telegram_delivery');
            alter table semantic_policy_admission add column updated_by text,add column updated_at timestamptz default now(),
                add primary key(policy_id,policy_version);
            create table semantic_control_audit(id bigserial primary key,action text,target text,actor text,details jsonb);
            create table events_v2_core(id bigint primary key,event_id integer,log_source_id bigint,domain_id bigint,
                normalized_hash bytea,raw_log_file_id bigint,time_created_utc timestamptz,event_record_id bigint);
            create table raw_log_files(id bigint primary key,file_path text);
            create table sli_agents(id uuid primary key,status text,assigned_modules jsonb,
                source_host_id uuid,source_agent_id uuid references sli_agents(id),
                runtime_resume jsonb not null default '{}'::jsonb check(jsonb_typeof(runtime_resume)='object'));
            create table sli_agent_module_bindings(agent_id uuid,module_id text,source_instance_id text);
            create table sli_agent_packet_inbox(packet_id uuid primary key,envelope jsonb,packet jsonb,event_rows jsonb,
                imported_at timestamptz);
            create table sli_agent_receipts(packet_id uuid primary key,agent_id uuid,module_id text,envelope jsonb,
                receipt jsonb,sequence bigint);
            create table servers(hostname text,domain_id bigint);
            create table sli_plugin_file_audit.observations(evidence_key text,agent_id uuid,source_instance_id text,
                generation text,collection_scope_id text,payload_sha256 text,policy_revision bigint);
            create table sli_sigma.sigma_rule_revisions(installation_id uuid,plugin_id text,source_instance_id text,
                rule_id uuid,raw_sha256 text,raw_yaml text,source_uri text,upstream_commit text,license text);
        """)
        for name in ("semantic_control_audit_v160", "semantic_policy_mode_v160"):
            function = governance.split("create function " + name + "(", 1)[1].split("$$;", 1)[0]
            conn.execute("create or replace function public." + name + "(" + function + "$$;")
        conn.execute("""create trigger semantic_policy_admission_audit after insert or update on semantic_policy_admission
            for each row execute function semantic_control_audit_v160()""")
        native = (ROOT / "config/postgres_migrations/190_agent_semantic_source.sql").read_text("utf-8")
        conn.execute("create function public.read_agent_semantic_source_v190(" + native.split(
            "create function public.read_agent_semantic_source_v190(", 1)[1].split("$$;", 1)[0] + "$$;")
        # Use the actual scope check, keeping the fixture's hash resolver.
        conn.execute("create or replace function public.finding_evidence_scope_allowed(" + source.split(
            "create function public.finding_evidence_scope_allowed(", 1)[1].split("$$;", 1)[0] + "$$;")
        conn.execute("reset role")
        conn.execute(SQL)
    return publication_pg

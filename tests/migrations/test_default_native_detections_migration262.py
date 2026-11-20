"""Default policy admission and native domain membership on disposable SQL only."""
from dataclasses import asdict
import json
from pathlib import Path

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg
from tests.migrations.test_qw_semantic_input_migration228 import pg as pg
from tests.unit.test_default_detections import SCOPE
from server.sli.semantic import default_detections as defaults, password_attacks as passwords

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


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_migration_rejects_predecessor_before_main_admin_evidence(publication_pg):
    import psycopg
    with psycopg.connect(publication_pg, autocommit=True) as conn:
        conn.execute("insert into schema_migrations values(258,'workstation_device_seen')")
        with pytest.raises(psycopg.errors.RaiseException, match="migration 262 prerequisites failed"):
            conn.execute(SQL)
        conn.execute("rollback")
        assert conn.execute("select to_regclass('public.semantic_default_installation')").fetchone()[0] is None


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


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_actual_sql_seeds_audits_preserves_disable_and_denies_unbound_scope(defaults_pg):
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(defaults_pg, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("select * from public.default_detection_sources()")  # executes every discovery statement, empty installation
        conn.execute("""insert into finding_evidence_source_bindings
            values((select oid from pg_roles where rolname=session_user),session_user,%s,%s,%s,%s,'','core_event',1,null,%s)""",
            (SCOPE.installation_id, SCOPE.plugin_id, SCOPE.source_instance_id, SCOPE.source_generation,
             "00000000-0000-0000-0000-000000000003"))
        policy = passwords.risk_policy(SCOPE, "qw.password-brute-force", policy_id=defaults.policy_id(
            passwords.execution(SCOPE, "qw.password-brute-force")))
        assert defaults._admit(conn.cursor(), policy)
        assert defaults._admit(conn.cursor(), policy)
        assert conn.execute("select count(*) as n from semantic_control_audit where actor='system:defaults'").fetchone()["n"] == 1
        conn.execute("update semantic_policy_admission set enabled=false,updated_by='fixture-admin'")
        assert not defaults._admit(conn.cursor(), policy)
        assert conn.execute("select updated_by from semantic_policy_admission").fetchone()["updated_by"] == "fixture-admin"
        assert conn.execute("select count(*) as n from semantic_control_audit").fetchone()["n"] == 2
        assert conn.execute("select * from read_default_password_events(%s::jsonb)", (json.dumps(asdict(SCOPE)),)).fetchall() == []
        assert conn.execute("select * from read_admitted_sigma_events(%s::jsonb,0)", (json.dumps(asdict(SCOPE)),)).fetchall() == []
        scope = asdict(SCOPE) | {"source_generation": "unbound"}
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("select * from read_default_password_events(%s::jsonb)", (json.dumps(scope),))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_actual_sql_domain_membership_requires_every_witness_and_handles_native_file_refs(defaults_pg):
    import psycopg
    with psycopg.connect(defaults_pg, autocommit=True) as conn:
        # No evidence cannot establish membership, including an empty domain selection.
        assert conn.execute("select semantic_finding_in_domains_v262(1,array[7]::bigint[])").fetchone()[0] is False
        conn.execute("insert into findings(id,fingerprint) values(1,'fixture')")
        conn.execute("insert into events_v2_core(id,domain_id) values(1,7),(2,8),(3,null)")
        conn.execute("insert into finding_evidence(finding_id,event_id,evidence_role) values(1,1,'semantic_scenario')")
        assert conn.execute("select semantic_finding_in_domains_v262(1,array[7]::bigint[])").fetchone()[0] is True
        assert conn.execute("select semantic_finding_in_domains_v262(1,array[8]::bigint[])").fetchone()[0] is False
        conn.execute("insert into finding_evidence(finding_id,event_id,evidence_role) values(1,2,'semantic_scenario')")
        assert conn.execute("select semantic_finding_in_domains_v262(1,array[7]::bigint[])").fetchone()[0] is False
        assert conn.execute("select semantic_finding_in_domains_v262(1,array[7,8]::bigint[])").fetchone()[0] is True
        conn.execute("insert into finding_evidence(finding_id,event_id,evidence_role) values(1,3,'semantic_scenario')")
        assert conn.execute("select semantic_finding_in_domains_v262(1,array[7,8]::bigint[])").fetchone()[0] is False
        conn.execute("insert into findings(id,fingerprint) values(2,'fixture-native')")
        agent = "00000000-0000-0000-0000-000000000003"
        packet = "00000000-0000-0000-0000-000000000004"
        conn.execute("""insert into finding_evidence_source_bindings
            values((select oid from pg_roles where rolname=session_user),session_user,%s,'sli.file-audit',
                'fixture-source','generation-1','fixture-root','file_audit_observation',null,null,%s)""", (SCOPE.installation_id, agent))
        conn.execute("""insert into finding_evidence_refs(finding_id,installation_id,plugin_id,source_instance_id,
            source_generation,collection_scope_id,storage_kind,native_id,sha256)
            values(2,%s,'sli.file-audit','fixture-source','generation-1','fixture-root','file_audit_observation',%s,%s)""",
            (SCOPE.installation_id, "a" * 64, "b" * 64))
        conn.execute("insert into sli_plugin_file_audit.observations values(%s,%s,'fixture-source','generation-1','fixture-root',%s,1)",
                     ("a" * 64, agent, "b" * 64))
        envelope = json.dumps({"source_instance_id": "fixture-source", "generation": "generation-1"})
        conn.execute("insert into sli_agent_receipts values(%s,%s,'sli.file-audit',%s::jsonb,'{\"status\":\"committed\"}',1)",
                     (packet, agent, envelope))
        conn.execute("insert into sli_agent_packet_inbox values(%s,%s::jsonb,'{\"header\":{\"source\":\"fixture-server\"}}','[]',now())",
                     (packet, envelope))
        conn.execute("insert into servers values('fixture-server',7)")
        assert conn.execute("select semantic_finding_in_domains_v262(2,array[7]::bigint[])").fetchone()[0] is True
        assert conn.execute("select semantic_finding_in_domains_v262(2,array[8]::bigint[])").fetchone()[0] is False
        conn.execute("update sli_plugin_file_audit.observations set payload_sha256=%s", ("c" * 64,))
        assert conn.execute("select semantic_finding_in_domains_v262(2,array[7]::bigint[])").fetchone()[0] is False


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_actual_discovery_uses_worker_login_committed_source_and_no_elevated_admission_grants(defaults_pg):
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(defaults_pg, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("""do $$ begin if not exists(select 1 from pg_roles where rolname='sli_test_defaults_login') then
            create role sli_test_defaults_login login; end if; end $$;
            grant adlog_semantic_worker to sli_test_defaults_login""")
        agent = "00000000-0000-0000-0000-000000000003"
        packet = "00000000-0000-0000-0000-000000000004"
        conn.execute("insert into sli_agents(id,status,assigned_modules) values(%s,'active','[{\"module_id\":\"sli.windows.ad-dc\",\"enabled\":true}]')", (agent,))
        conn.execute("insert into sli_agent_module_bindings values(%s,'sli.windows.ad-dc','fixture-source')", (agent,))
        envelope = json.dumps({"source_instance_id": "fixture-source", "generation": "generation-1"})
        conn.execute("insert into sli_agent_receipts values(%s,%s,'sli.windows.ad-dc',%s::jsonb,'{\"status\":\"committed\"}',1)",
                     (packet, agent, envelope))
        conn.execute("insert into sli_agent_packet_inbox values(%s,%s::jsonb,'{}','[]',now())", (packet, envelope))
        conn.execute("insert into raw_log_files values(1,%s)", ("agent-packet:" + packet,))
        conn.execute("insert into events_v2_core(id,log_source_id,raw_log_file_id) values(1,3,1)")
        conn.execute("set session authorization sli_test_defaults_login; set role adlog_semantic_worker")
        source, = conn.execute("select source from default_detection_sources()").fetchall()
        scope = source["source"]["scope"]
        assert scope["source_instance_id"] == "fixture-source" and scope["source_generation"] == "generation-1"
        from server.sli.storage.evidence_ref import EvidenceScope
        selected = EvidenceScope(**scope)
        policy = passwords.risk_policy(selected, "qw.password-spray", policy_id=defaults.policy_id(
            passwords.execution(selected, "qw.password-spray")))
        assert defaults._admit(conn.cursor(), policy)
        assert len(conn.execute("select source from default_detection_sources()").fetchall()) == 1
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("update semantic_policy_admission set enabled=false")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("select * from finding_evidence_source_bindings")
        conn.execute("reset session authorization; reset role")
        conn.execute("update sli_agents set status='disabled'")
        conn.execute("set session authorization sli_test_defaults_login; set role adlog_semantic_worker")
        assert not conn.execute("select source from default_detection_sources()").fetchall()

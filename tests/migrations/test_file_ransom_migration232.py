"""R01 forward migration, native root admission, episodes and atomic publication."""
from dataclasses import asdict
from datetime import timedelta
import json
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.semantic import file_ransom as ransom, file_ransom_runtime as worker
from server.sli.semantic import semantic_risk_runtime_repository as runtime
from tests.migrations.test_qw_semantic_input_migration228 import pg as pg
from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg
from tests.unit.test_file_ransom import NOW, results, rule
from tests.unit.test_file_audit_rules import action

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/232_file_ransom.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_is_dormant_additive_and_unique():
    assert list(PATH.parent.glob("232_*.sql")) == [PATH]
    assert "version=231 and name='agent_gpo_plans'" in SQL
    assert "where version>=232" in SQL and "values(232,'file_ransom')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "insert into public.finding_evidence_source_bindings" not in SQL
    assert "insert into public.semantic_risk_policies" not in SQL
    assert "grant select on sli_plugin_file_audit.observations to adlog_semantic_worker" not in SQL


@pytest.fixture
def ransomware_pg(publication_pg):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    selected = rule(threshold=20, evaluation_mode="enabled")
    native = (ROOT / "config/postgres_migrations/219_finding_evidence_refs.sql").read_text("utf-8")
    with psycopg.connect(publication_pg, autocommit=True, row_factory=dict_row) as conn:
        conn.execute("do $$ begin if not exists(select 1 from pg_roles where rolname='adlog_file_audit_owner') then "
                     "create role adlog_file_audit_owner nologin; end if; "
                     "if not exists(select 1 from pg_roles where rolname='sli_test_ransom_login') then "
                     "create role sli_test_ransom_login login; end if; end $$")
        conn.execute("grant adlog_semantic_worker to sli_test_ransom_login")
        conn.execute("grant adlog_file_audit_owner to adlog_storage_owner")
        conn.execute("create schema sli_plugin_file_audit authorization adlog_file_audit_owner")
        conn.execute("grant usage on schema sli_plugin_file_audit to adlog_storage_owner")
        conn.execute("""
            set role adlog_file_audit_owner;
            create table sli_plugin_file_audit.observations(evidence_key text primary key,agent_id uuid,
                source_instance_id text,collection_scope_id text,generation text,policy_revision bigint,
                payload_sha256 text,normalized jsonb);
            create table sli_plugin_file_audit.actions(action_id text primary key,agent_id uuid,
                source_instance_id text,collection_scope_id text,outcome text,operation text,correlation_state text);
            create table sli_plugin_file_audit.rule_results(result_id text primary key,agent_id uuid,
                source_instance_id text,collection_scope_id text,rule_code text,conclusion_state text,
                observed_at timestamptz,result jsonb);
            create table sli_plugin_file_audit.rule_actions(result_id text,action_id text,primary key(result_id,action_id));
            create table sli_plugin_file_audit.action_evidence(action_id text,evidence_key text,primary key(action_id,evidence_key));
            create table sli_plugin_file_audit.policy_revisions(agent_id uuid,source_instance_id text,revision bigint,policy jsonb);
            reset role;
            grant select on sli_plugin_file_audit.observations to adlog_storage_owner;
            set role adlog_storage_owner;
            create table sli_agent_receipts(packet_id uuid primary key,agent_id uuid,module_id text,envelope jsonb,receipt jsonb);
            create table sli_agent_packet_inbox(packet_id uuid primary key,envelope jsonb,imported_at timestamptz);
            insert into schema_migrations values(230,'nps_threshold'),(231,'agent_gpo_plans');
        """)
        binding = native[native.index("create table public.finding_evidence_source_bindings"):].split("\n);", 1)[0] + "\n);"
        conn.execute(binding)
        scope_function = "create or replace function public.finding_evidence_scope_allowed(" + native.split(
            "create function public.finding_evidence_scope_allowed(", 1)[1].split("$$;", 1)[0] + "$$;"
        conn.execute(scope_function)
        conn.execute("reset role")
        conn.execute(SQL)
        conn.execute("insert into finding_evidence_source_bindings values("
                     "'sli_test_ransom_login'::regrole::oid,'sli_test_ransom_login',%s,%s,%s,%s,%s,"
                     "'file_audit_observation',null,null,%s)", tuple(asdict(selected.scope).values()) + (selected.agent_id,))
        conn.execute("insert into sli_plugin_file_audit.policy_revisions values(%s,%s,1,%s::jsonb)",
                     (selected.agent_id, selected.scope.source_instance_id,
                      json.dumps({"mass_operation_files": selected.threshold, "mass_operation_seconds": selected.window_seconds})))
        envelope = {"agent_id": selected.agent_id, "source_instance_id": selected.scope.source_instance_id,
                    "generation": selected.scope.source_generation, "sequence": 1, "continuity_state": "complete"}
        packet_id = uuid4()
        conn.execute("insert into sli_agent_receipts values(%s,%s,'sli.file-audit',%s::jsonb,'{\"status\":\"committed\"}')",
                     (packet_id, selected.agent_id, json.dumps(envelope)))
        conn.execute("insert into sli_agent_packet_inbox values(%s,%s::jsonb,now())", (packet_id, json.dumps(envelope)))
        runtime.register_risk_policy(conn.cursor(), policy=ransom.risk_policy(selected, policy_id="fixture-qw"))
        conn.execute("update semantic_risk_policies set lifecycle_status='enabled'")
        conn.execute("insert into semantic_policy_admission values('fixture-qw',1,true)")
        conn.execute("insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled) "
                     "values(%s,1,2,'smtp',true),(%s,1,2,'telegram',true)", (uuid4(), uuid4()))
        # Current worker also records R02 evaluation modes/exclusion decisions.
        conn.execute("insert into schema_migrations values(237,'entity_context_health')")
        conn.execute((ROOT / "config/postgres_migrations/240_file_ransom_details.sql").read_text("utf-8"))
    return publication_pg, make_conninfo(publication_pg, user="sli_test_ransom_login"), selected


def seed_result(dsn, selected, *, count=20, operation="write", start=NOW, offset=0, **changes):
    import psycopg
    found = results(count, operation=operation, threshold=selected.threshold, start=start, offset=offset,
                    collection_scope_id=selected.scope.collection_scope_id, **changes)
    with psycopg.connect(dsn) as conn:
        # File rows survive even below the security threshold, just as in the
        # admitted importer transaction. Reaching N only adds a mass result.
        for index in range(1, count + 1):
            action_id = action(index + offset)["action_id"]
            conn.execute("insert into sli_plugin_file_audit.actions values(%s,%s,%s,%s,'success',%s,'complete') on conflict do nothing", (
                action_id, selected.agent_id, selected.scope.source_instance_id, selected.scope.collection_scope_id, operation))
            for witness in range(2 if operation == "delete" else 1):
                native_id = f"{int(action_id, 16) * 2 + witness:064x}"
                root = "technical" if operation == "delete" and witness == 0 else selected.scope.collection_scope_id
                conn.execute("insert into sli_plugin_file_audit.observations values(%s,%s,%s,%s,%s,1,%s,%s::jsonb) on conflict do nothing", (
                    native_id, selected.agent_id, selected.scope.source_instance_id, root,
                    selected.scope.source_generation, "b" * 64,
                    json.dumps({"evidence_key": native_id, "payload_sha256": "b" * 64})))
                conn.execute("insert into sli_plugin_file_audit.action_evidence values(%s,%s) on conflict do nothing", (action_id, native_id))
        for result in found:
            conn.execute("insert into sli_plugin_file_audit.rule_results values(%s,%s,%s,%s,%s,'observed',%s,%s::jsonb)", (
                result["result_id"], selected.agent_id, selected.scope.source_instance_id,
                selected.scope.collection_scope_id, result["rule_code"], start, json.dumps(result)))
            for action_id in result["action_ids"]:
                conn.execute("insert into sli_plugin_file_audit.rule_actions values(%s,%s)", (result["result_id"], action_id))
    return found


def publish_jobs(conn):
    outcomes = []
    for job in runtime.claim_risk_evaluation_jobs(conn.cursor(), limit=32):
        work = runtime.load_risk_evaluation_work_item(conn.cursor(), job_id=job["job_id"], lease_token=job["lease_token"])
        outcomes.append(runtime.execute_risk_evaluation(conn.cursor(), work=work, evaluation_ms=0, create_finding=True))
    return outcomes


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("operation", ["write", "delete"])
def test_sql_threshold_native_publication_replay_and_expansion(ransomware_pg, operation):
    import psycopg
    from psycopg.rows import dict_row
    admin, login, selected = ransomware_pg
    assert not seed_result(admin, selected, count=19, operation=operation)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=NOW)["jobs"] == 0
    with psycopg.connect(admin) as conn:
        assert conn.execute("select count(*) from sli_plugin_file_audit.actions").fetchone()[0] == 19
        assert conn.execute("select count(*) from findings").fetchone()[0] == 0
    seed_result(admin, selected, operation=operation)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=NOW)["jobs"] == 1
        outcome, = publish_jobs(conn)
        assert outcome.finding_created and outcome.risk_class.value == "high"
    seed_result(admin, selected, operation=operation, start=NOW + timedelta(seconds=240), offset=100)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=NOW + timedelta(seconds=240))["jobs"] == 1
        expanded, = publish_jobs(conn)
        assert expanded.finding_id == outcome.finding_id and not expanded.finding_created
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=NOW + timedelta(seconds=241))["jobs"] == 0
    with psycopg.connect(admin, row_factory=dict_row) as conn:
        assert conn.execute("select count(*) as n from sli_plugin_file_audit.actions").fetchone()["n"] == 40
        assert conn.execute("select count(*) as n from semantic_file_ransom_episodes").fetchone()["n"] == 1
        assert conn.execute("select severity from findings").fetchone()["severity"] == "high"
        assert conn.execute("select count(*) as n from semantic_finding_publications").fetchone()["n"] == 1
        assert conn.execute("select count(*) as n from finding_evidence_refs").fetchone()["n"] == (80 if operation == "delete" else 40)
        # January evidence is historical: N08's transport freshness rule is
        # outside this synthetic N07 predecessor fixture, which enqueues both.
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 2


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_rollback_native_tampering_and_revoked_scope(ransomware_pg):
    import psycopg
    from psycopg.rows import dict_row
    admin, login, selected = ransomware_pg
    seed_result(admin, selected, operation="delete")
    with pytest.raises(RuntimeError, match="synthetic_rollback"), psycopg.connect(login, row_factory=dict_row) as conn:
        worker.run_once(conn.cursor(), rule=selected, now=NOW)
        assert publish_jobs(conn)[0].finding_created
        raise RuntimeError("synthetic_rollback")
    with psycopg.connect(admin) as conn:
        for table in ("semantic_file_ransom_members", "semantic_file_ransom_episodes", "semantic_qw_signals", "findings", "notification_outbox"):
            assert conn.execute("select count(*) from " + table).fetchone()[0] == 0
        conn.execute("update sli_plugin_file_audit.observations set normalized='{}'")
    with pytest.raises(RuntimeError), psycopg.connect(login, row_factory=dict_row) as conn:
        worker.run_once(conn.cursor(), rule=selected, now=NOW)
    with psycopg.connect(admin) as conn:
        conn.execute("delete from finding_evidence_source_bindings")
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert conn.execute("select count(*) as n from semantic_file_ransom_episodes").fetchone()["n"] == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.run_once(conn.cursor(), rule=selected, now=NOW)


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_other_scope_agent_policy_and_raw_table_access_denied(ransomware_pg):
    import psycopg
    from psycopg.rows import dict_row
    from dataclasses import replace
    admin, login, selected = ransomware_pg
    seed_result(admin, selected)
    for candidate in (replace(selected, scope=replace(selected.scope, collection_scope_id="scope:other")),
                      replace(selected, agent_id=str(uuid4())), replace(selected, threshold=19)):
        with pytest.raises(psycopg.Error), psycopg.connect(login, row_factory=dict_row) as conn:
            worker.run_once(conn.cursor(), rule=candidate, now=NOW)
    with pytest.raises(psycopg.errors.InsufficientPrivilege), psycopg.connect(login) as conn:
        conn.execute("select * from sli_plugin_file_audit.observations")
    with psycopg.connect(admin) as conn:
        conn.execute("set role adlog_user")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("select * from semantic_file_ransom_episodes")

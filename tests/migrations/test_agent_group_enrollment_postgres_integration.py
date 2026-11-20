"""Actual group table constraints and row locks in a disposable test schema."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
from threading import Barrier
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import group_enrollment as groups
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_agent_group_enrollment import directory_record
from tests.unit.test_agent_registry import request

pytestmark = pytest.mark.postgres_integration
MIGRATION = Path(__file__).resolve().parents[2] / "config/postgres_migrations/175_agent_group_enrollment.sql"
DEPLOYMENT = MIGRATION.with_name("188_agent_group_deployment.sql")
SCOPE = MIGRATION.with_name("194_agent_deployment_scope.sql")


@pytest.fixture
def group_database():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN", "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is required for disposable PostgreSQL concurrency tests")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.rows import dict_row

    schema = "sli_test_group_" + uuid4().hex
    def connect():
        conn = psycopg.connect(dsn, row_factory=dict_row)
        conn.execute(sql.SQL("set search_path to {}").format(sql.Identifier(schema)))
        return conn

    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        admin.execute(sql.SQL("create schema {}").format(sql.Identifier(schema)))
        try:
            with connect() as conn:
                # Synthetic predecessors; use the real migration's new tables.
                conn.execute("""create table domains(id bigint primary key);
                    create table entities_v2(id bigint primary key,domain_id bigint not null);
                    create table ad_context_runs(run_id uuid primary key,domain_id bigint,status text);
                    create table ad_context_sections(run_id uuid,section_name text,status text);
                    create table ad_context_entity_versions(id bigint primary key,entity_id bigint,
                        source_run_id uuid,source_section text,attributes_json jsonb,
                        last_observed_at_utc timestamptz,valid_to_utc timestamptz);
                    create table sli_agents(id uuid primary key,host_id uuid,instance_name text,key_fingerprint text,
                        source_host_id uuid,source_agent_id uuid references sli_agents(id),
                        runtime_resume jsonb not null default '{}'::jsonb check(jsonb_typeof(runtime_resume)='object'));
                    create table sli_agent_enrollment_tokens(id uuid primary key,used_at timestamptz,revoked_at timestamptz);
                    create table sli_agent_onboarding_copies(request_id uuid,enrollment_token_id uuid);
                    create table sli_agent_audit(id bigint generated always as identity primary key,
                        action text,actor text,target text,details jsonb)""")
                migration = MIGRATION.read_text("utf-8")
                for table in ("sli_agent_group_tokens", "sli_agent_group_requests"):
                    ddl = re.search(rf"create table public\.{table} \(.*?\n\);", migration, re.S)
                    assert ddl is not None
                    conn.execute(ddl.group().replace("public.", ""))
                deployment = DEPLOYMENT.read_text("utf-8")
                for table in ("sli_agent_enrollment_groups", "sli_agent_group_approvals", "sli_agent_group_members"):
                    ddl = re.search(rf"create table public\.{table} \(.*?\n\);", deployment, re.S)
                    assert ddl is not None
                    conn.execute(ddl.group().replace("public.", ""))
                for pattern in (
                    r"alter table public\.sli_agent_group_tokens add column group_id uuid;",
                    r"alter table public\.sli_agent_group_tokens alter column group_id set not null;",
                    r"alter table public\.sli_agent_group_tokens add constraint sli_agent_group_tokens_scope_fk.*?;",
                    r"do \$\$\ndeclare ttl_constraint.*?end \$\$;",
                    r"alter table public\.sli_agent_group_tokens add constraint sli_agent_group_tokens_ttl_check.*?;",
                    r"create view public\.sli_agent_group_approval_links.*?;",
                ):
                    ddl = re.search(pattern, deployment, re.S)
                    assert ddl is not None
                    conn.execute(ddl.group().replace("public.", ""))
                scope = SCOPE.read_text("utf-8")
                for pattern in (
                    r"do \$\$\ndeclare target regclass.*?end \$\$;",
                    r"alter table public\.sli_agent_group_tokens\n.*?;",
                ):
                    ddl = re.search(pattern, scope, re.S)
                    assert ddl is not None
                    conn.execute(ddl.group().replace("public.", ""))
                conn.execute("insert into domains values(1); insert into entities_v2 values(2,1),(3,1)")
                run_id = uuid4()
                conn.execute("insert into ad_context_runs values(%s,1,'completed')", (run_id,))
                for entity_id, section, ou in ((2, "domain_posture", True), (3, "directory_accounts", False)):
                    conn.execute("insert into ad_context_sections values(%s,%s,'complete')", (run_id, section))
                    conn.execute("""insert into ad_context_entity_versions
                        values(%s,%s,%s,%s,%s::jsonb,clock_timestamp(),null)""",
                        (entity_id * 10, entity_id, run_id, section, json.dumps(directory_record(ou=ou))))
            yield connect
        finally:
            # The generated schema belongs exclusively to this fixture, on a
            # database already checked by assert_disposable_database.
            admin.execute(sql.SQL("drop schema {} cascade").format(sql.Identifier(schema)))


def _token(connect, maximum):
    with connect() as conn, conn.cursor() as cur:
        return groups.create_token(cur, {"max_uses": maximum, "domain_id": 1, "ou_entity_ids": [2]}, actor="session:1")


def _body(token):
    host = str(uuid4())
    key = ec.generate_private_key(ec.SECP256R1())
    return {"token": token["token"], "host_id": host, "computer_entity_id": 3, "csr_pem": request(key, host)}


def _concurrent(connect, bodies):
    barrier = Barrier(len(bodies))
    def submit(body):
        with connect() as conn, conn.cursor() as cur:
            barrier.wait(timeout=15)
            try:
                result = groups.submit(cur, body)
            except groups.AuditedRejection:
                result = {"status": "rejected"}
            conn.commit()  # Preserve denial audits exactly as the HTTP adapter.
            return result
    with ThreadPoolExecutor(max_workers=len(bodies)) as workers:
        return list(workers.map(submit, bodies))


def test_concurrent_new_requests_cannot_exceed_capacity(group_database):
    token = _token(group_database, 3)
    results = _concurrent(group_database, [_body(token) for _ in range(10)])
    assert sum(r["status"] == "pending" for r in results) == 3
    assert sum(r["status"] == "rejected" for r in results) == 7
    with group_database() as conn:
        assert conn.execute("select uses_count from sli_agent_group_tokens").fetchone()["uses_count"] == 3
        assert conn.execute("select count(*) as n from sli_agent_group_requests").fetchone()["n"] == 3
        assert conn.execute("select count(*) as n from sli_agents").fetchone()["n"] == 0
        assert conn.execute("select count(*) as n from sli_agent_audit where details->>'result'='rejected'").fetchone()["n"] == 7


def test_concurrent_retry_uses_one_slot_and_one_request(group_database):
    token = _token(group_database, 1)
    body = _body(token)
    results = _concurrent(group_database, [body] * 8)
    assert all(r == results[0] and r["status"] == "pending" for r in results)
    with group_database() as conn:
        assert conn.execute("select uses_count from sli_agent_group_tokens").fetchone()["uses_count"] == 1
        assert conn.execute("select count(*) as n from sli_agent_group_requests").fetchone()["n"] == 1


def test_incomplete_stale_or_wrong_domain_snapshot_cannot_admit(group_database):
    token = _token(group_database, 3)
    for change in (
        "update ad_context_sections set status='partial' where section_name='directory_accounts'",
        "update ad_context_entity_versions set last_observed_at_utc=clock_timestamp()-interval '25 hours' where entity_id=3",
        "update entities_v2 set domain_id=2 where id=3",
    ):
        with group_database() as conn, conn.cursor() as cur:
            cur.execute(change)
            with pytest.raises(groups.AuditedRejection):
                groups.submit(cur, _body(token))
            conn.rollback()
    with group_database() as conn:
        assert conn.execute("select uses_count from sli_agent_group_tokens").fetchone()["uses_count"] == 0
        assert conn.execute("select count(*) as n from sli_agent_group_requests").fetchone()["n"] == 0


def test_failed_transaction_rolls_back_reserved_slot_and_pending_request(group_database):
    from psycopg.errors import CheckViolation

    token = _token(group_database, 1)
    with group_database() as conn:
        conn.execute("alter table sli_agent_audit add check(action<>'group_request')")
    with pytest.raises(CheckViolation), group_database() as conn, conn.cursor() as cur:
        groups.submit(cur, _body(token))
    with group_database() as conn:
        assert conn.execute("select uses_count from sli_agent_group_tokens").fetchone()["uses_count"] == 0
        assert conn.execute("select count(*) as n from sli_agent_group_requests").fetchone()["n"] == 0



def test_display_names_follow_enrollment_and_remain_bounded(group_database):
    from server.sli.agents.agent_names import read_agent_names

    token = _token(group_database, 2)
    agent_id, other_id, enrollment_id = str(uuid4()), str(uuid4()), str(uuid4())
    with group_database() as conn, conn.cursor() as cur:
        pending = groups.submit(cur, _body(token))
        cur.execute("alter table sli_agents add column assigned_modules jsonb not null default '[]'")
        cur.execute("insert into sli_agents(id,host_id) values(%s,%s),(%s,%s)",
                    (agent_id, str(uuid4()), other_id, str(uuid4())))
        cur.execute("update ad_context_entity_versions set attributes_json=jsonb_set(attributes_json, "
                    "'{attributes,dns_host_name}', '\"pc.example.invalid\"') where id=30")
        cur.execute("insert into sli_agent_onboarding_copies(request_id,enrollment_token_id) values(%s,%s)",
                    (pending["request_id"], enrollment_id))
        cur.execute("insert into sli_agent_audit(action,actor,target,details) values('issue',%s,%s,'{}')",
                    ("enrollment:" + enrollment_id, agent_id))
        assert read_agent_names(cur, [agent_id]) == {agent_id: "pc.example.invalid"}
        assert read_agent_names(cur, [other_id]) == {other_id: None}
        assert read_agent_names(cur, []) == {}
        cur.execute("update ad_context_entity_versions set attributes_json=jsonb_set(attributes_json, "
                    "'{attributes,dns_host_name}', %s::jsonb) where id=30", (json.dumps(agent_id),))
        assert read_agent_names(cur, [agent_id]) == {agent_id: None}


def test_display_name_query_uses_existing_fully_migrated_runtime_privileges():
    """No schema/grant substitutes: execute the display query as the real role."""
    from server.sli.agents.agent_names import read_agent_names

    dsn = os.environ.get("ADLOG_TEST_PG_DSN", "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("set local role adlog_user")
        with conn.cursor() as cur:
            # Even an empty match checks every referenced relation and its
            # existing runtime privileges on the migrated production schema.
            assert read_agent_names(cur, ["00000000-0000-0000-0000-000000000000"]) == {}

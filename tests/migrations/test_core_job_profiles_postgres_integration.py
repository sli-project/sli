"""L18: migrated pool identities keep exact plugin grants and deny DDL."""
from __future__ import annotations

import os

import pytest

from tests.postgres_integration_guard import assert_disposable_database

ROLES = tuple(
    f"sli_job_{purpose}_{profile}"
    for profile in ("light", "heavy", "long")
    for purpose in ("dispatcher", "executor", "publisher")
)
pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def profile_connection():
    dsn = str(os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL tests")
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(dsn, autocommit=True) as connection:
        assert_disposable_database(connection)
        assert connection.execute(
            "select exists(select 1 from public.schema_migrations "
            "where version=154 and name='core_job_queue'),"
            "exists(select 1 from public.schema_migrations "
            "where version=192 and name='workstation_retention_jobs'),"
            "exists(select 1 from public.schema_migrations "
            "where version=254 and name='workstation_projection_queue'),"
            "exists(select 1 from public.schema_migrations "
            "where version=255 and name='workstation_protection_predecessor'),"
            "exists(select 1 from public.schema_migrations "
            "where version=258 and name='workstation_device_seen'),"
            "to_regnamespace('sli_plugin_workstations') is not null"
        ).fetchone() == (True,) * 6, "test template requires migrations 154, 192, 254, 255 and 258"
        yield connection


@pytest.mark.parametrize("role", ROLES)
def test_profile_cannot_run_ddl_or_access_foreign_plugin(profile_connection, role):
    from psycopg import sql
    from psycopg.errors import InsufficientPrivilege

    connection = profile_connection
    # Migrations 192/254/255/258 admit only these light identities to retention/projection.
    workstation_reader = role in {"sli_job_executor_light", "sli_job_publisher_light"}
    workstation_publisher = role == "sli_job_publisher_light"
    grants = {}
    column_grants = []
    if role == "sli_job_executor_light":
        # WR06 stages age-only refreshes using just these summary columns.
        column_grants = [("station_summary", column, "SELECT") for column in ("protection", "station_id")]
    if workstation_reader:
        grants = {table: {"SELECT"} for table in (
            "observation_holds", "observations", "projection_receipts", "projection_work", "station_inventory",
        )}
    if workstation_publisher:
        column_grants = [("observations", "id", "UPDATE")]
        grants["observations"].add("DELETE")
        grants["protection_state"] = {"SELECT"}
        grants["station_changes"] = {"SELECT", "INSERT"}
        grants["device_seen"] = {"SELECT", "INSERT", "UPDATE"}
        grants["device_seen_occurrences"] = {"SELECT", "INSERT"}
        for table in ("projection_checkpoints", "projection_receipts", "projection_consumers",
                      "station_summary", "check_findings"):
            grants[table] = {"SELECT", "INSERT", "UPDATE"}
    flags = connection.execute(
        "select rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,rolreplication "
        "from pg_roles where rolname=%s", (role,),
    ).fetchone()
    assert flags == (False,) * 5, role
    assert not connection.execute(
        "select has_database_privilege(%s,current_database(),'CREATE')", (role,),
    ).fetchone()[0], role
    assert connection.execute(
        "select nspname from pg_namespace where "
        "has_schema_privilege(%s,oid,'CREATE')", (role,),
    ).fetchall() == [], role
    assert connection.execute(
        "select nspname from pg_namespace where nspname like 'sli\\_plugin\\_%%' "
        "and has_schema_privilege(%s,oid,'USAGE,CREATE') order by nspname", (role,),
    ).fetchall() == ([("sli_plugin_workstations",)] if workstation_reader else []), role
    assert connection.execute(
        "select n.nspname,c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace "
        "where n.nspname like 'sli\\_plugin\\_%%' and c.relkind in ('r','p','v','m') "
        "and (has_table_privilege(%s,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') "
        "or has_any_column_privilege(%s,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')) "
        "order by n.nspname,c.relname",
        (role, role),
    ).fetchall() == [("sli_plugin_workstations", table)
                    for table in sorted(set(grants) | {table for table, _, _ in column_grants})], role
    # Match every table privilege exactly, including the new projection grants.
    assert connection.execute(
        "select c.relname,p.privilege from pg_class c "
        "join pg_namespace n on n.oid=c.relnamespace "
        "cross join unnest(array['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) "
        "as p(privilege) where n.nspname='sli_plugin_workstations' "
        "and c.relkind in ('r','p','v','m') and has_table_privilege(%s,c.oid,p.privilege) "
        "order by c.relname,p.privilege", (role,),
    ).fetchall() == sorted((table, privilege) for table, privileges in grants.items()
                          for privilege in privileges), role
    # Check every column-only privilege, including SELECT: WR06's summary read
    # must not grow to the entire table or to additional columns.
    assert connection.execute(
        "select c.relname,a.attname,p.privilege from pg_class c "
        "join pg_namespace n on n.oid=c.relnamespace "
        "join pg_attribute a on a.attrelid=c.oid "
        "cross join unnest(array['SELECT','INSERT','UPDATE','REFERENCES']) as p(privilege) "
        "where n.nspname='sli_plugin_workstations' and c.relkind in ('r','p','v','m') "
        "and a.attnum>0 and not a.attisdropped "
        "and has_column_privilege(%s,c.oid,a.attnum,p.privilege) "
        "and not has_table_privilege(%s,c.oid,p.privilege) "
        "order by c.relname,a.attname,p.privilege", (role, role),
    ).fetchall() == column_grants, role
    statements = (
        "set role adlog_user",
        "set role adlog_storage_owner",
        "set role sli_job_owner",
        "create table public.sli_test_profile_ddl(id integer)",
        "create schema sli_test_profile_ddl",
        "create function public.sli_test_profile_ddl() returns integer "
        "language sql as 'select 1'",
        "create table sli_jobs.sli_test_profile_ddl(id integer)",
        "create function sli_jobs.sli_test_profile_ddl() returns integer "
        "language sql as 'select 1'",
        "create table sli_plugin_workstations.sli_test_profile_ddl(id integer)",
        "create function sli_plugin_workstations.sli_test_profile_ddl() returns integer "
        "language sql as 'select 1'",
        "insert into sli_plugin_workstations.observations default values",
    )
    if not workstation_reader:
        statements += ("select * from sli_plugin_workstations.observations limit 0",)
    if not workstation_publisher:
        statements += (
            "update sli_plugin_workstations.observations set id=id where false",
            "delete from sli_plugin_workstations.observations where false",
        )
    # Credential hashes and enrollment material are core-owned, even when the
    # runtime role can read them. Test column grants as well as table grants.
    for table, column in (
        ("auth_users", "password_hash"), ("auth_sessions", "token_hash"),
        ("auth_api_keys", "key_hash"), ("sli_agent_enrollment_tokens", "token_hash"),
    ):
        assert connection.execute(
            "select to_regclass(%s) is not null,has_any_column_privilege(%s,%s,'SELECT')",
            (f"public.{table}", role, f"public.{table}"),
        ).fetchone() == (True, False), (role, table)
        statements += (f"select {column} from public.{table} limit 0",)
    for statement in statements:
        # A failed statement rolls back only its savepoint; the outer transaction
        # also removes any object should a forbidden DDL unexpectedly succeed.
        with connection.transaction():
            connection.execute(sql.SQL("set local session authorization {}").format(sql.Identifier(role)))
            with pytest.raises(InsufficientPrivilege), connection.transaction():
                connection.execute(statement)


@pytest.mark.parametrize("role", ("sli_job_executor_light", "sli_job_publisher_light"))
@pytest.mark.parametrize("statement", (
    "update sli_plugin_workstations.observations set id=id where id=%s",
    "delete from sli_plugin_workstations.observations where id=%s",
))
def test_retention_profiles_read_but_cannot_write_without_a_live_lease(profile_connection, role, statement):
    from psycopg import sql
    from psycopg.errors import InsufficientPrivilege, RaiseException

    connection = profile_connection
    with connection.transaction():
        observation_id = connection.execute(
            "insert into sli_plugin_workstations.observations "
            "(id,agent_key,entity_id,family,event_id,observed_at,observation,observation_sha256,source_xml) "
            "values(md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),"
            "'fixture-agent',1,'processes',4688,clock_timestamp()-interval '366 days',"
            "'{}'::jsonb,repeat('b',64),'<Event/>') returning id"
        ).fetchone()[0]
        try:
            connection.execute(sql.SQL("set local session authorization {}").format(sql.Identifier(role)))
            assert connection.execute(
                "select id from sli_plugin_workstations.observations where id=%s", (observation_id,),
            ).fetchone() == (observation_id,)
            assert connection.execute(
                "select observation_id from sli_plugin_workstations.observation_holds where observation_id=%s",
                (observation_id,),
            ).fetchall() == []
            error = RaiseException if role == "sli_job_publisher_light" else InsufficientPrivilege
            message = "workstation_retention_write_denied" if role == "sli_job_publisher_light" else None
            with pytest.raises(error, match=message), connection.transaction():
                connection.execute(statement, (observation_id,))
        finally:
            connection.execute("reset session authorization")
        assert connection.execute(
            "select id from sli_plugin_workstations.observations where id=%s", (observation_id,),
        ).fetchone() == (observation_id,)
        connection.execute("delete from sli_plugin_workstations.observations where id=%s", (observation_id,))


@pytest.mark.parametrize("role", ("sli_job_executor_light", "sli_job_publisher_light"))
@pytest.mark.parametrize("statement", (
    "update sli_plugin_workstations.projection_receipts set applied_at=now() "
    "where projector_key='fixture-projector'",
    "select sli_plugin_workstations.register_projection_consumer('fixture-denied',1)",
    "insert into sli_plugin_workstations.device_seen default values",
    "insert into sli_plugin_workstations.device_seen_occurrences default values",
))
def test_projection_profiles_cannot_publish_without_a_live_lease(profile_connection, role, statement):
    from psycopg import sql
    from psycopg.errors import InsufficientPrivilege, RaiseException

    connection = profile_connection
    with connection.transaction():
        connection.execute("insert into sli_plugin_workstations.projection_consumers(projector_key,projection_version) "
                           "values('fixture-projector',1)")
        work_id = connection.execute(
            "insert into sli_plugin_workstations.projection_work(kind,source_id,agent_key,payload,payload_sha256) "
            "values('observations','fixture-input','fixture-agent','{}',"
            "encode(sha256(convert_to('{}','UTF8')),'hex')) returning work_id"
        ).fetchone()[0]
        connection.execute(
            "insert into sli_plugin_workstations.projection_receipts(work_id,projector_key,projection_version,payload_sha256) "
            "select work_id,'fixture-projector',1,payload_sha256 "
            "from sli_plugin_workstations.projection_work where work_id=%s", (work_id,),
        )
        try:
            connection.execute(sql.SQL("set local session authorization {}").format(sql.Identifier(role)))
            error = RaiseException if role == "sli_job_publisher_light" else InsufficientPrivilege
            message = "workstation_projection_write_denied" if role == "sli_job_publisher_light" else None
            with pytest.raises(error, match=message), connection.transaction():
                connection.execute(statement)
        finally:
            connection.execute("reset session authorization")
        assert connection.execute(
            "select applied_at from sli_plugin_workstations.projection_receipts where work_id=%s", (work_id,),
        ).fetchone() == (None,)
        assert connection.execute(
            "select projector_key from sli_plugin_workstations.projection_consumers where projector_key='fixture-denied'"
        ).fetchall() == []


@pytest.mark.parametrize("profile,rights_profile", (
    ("light", "vpn-read"), ("heavy", "ad-read"), ("long", "gpo-read"),
))
@pytest.mark.parametrize("attempts,state", [(1, "retry_wait"), (5, "quarantined")])
def test_timeout_failure_retries_then_quarantines(profile_connection, profile, rights_profile, attempts, state):
    from psycopg import sql

    from server.sli.core import job_queue

    connection = profile_connection
    # Synthetic lease only: admission/source acquisition is never enabled.
    # Migration 158 binds each resource profile to its own rights profile.
    with connection.transaction():
        job_id, token, generation, available_at = connection.execute(
            "insert into sli_jobs.jobs(job_id,spec,idempotency_key,plugin_id,source_instance_id,"
            "partition_key,resource_profile,rights_profile,state,priority,attempts,max_attempts,"
            "available_at,deadline_at,lease_token,lease_generation,lease_until) "
            "values(gen_random_uuid(),'{}'::jsonb,md5(gen_random_uuid()::text)||md5(gen_random_uuid()::text),'sli.remote-access',"
            "'synthetic-source','synthetic-partition',%s,%s,'leased',0,%s,5,"
            "clock_timestamp(),clock_timestamp()+interval '1 hour',gen_random_uuid(),1,"
            "clock_timestamp()+interval '60 seconds') returning job_id,lease_token,lease_generation,available_at",
            (profile, rights_profile, attempts),
        ).fetchone()
        try:
            # SECURITY DEFINER checks session_user, so SET ROLE alone would not
            # prove the actual dispatcher's authorization.
            connection.execute(sql.SQL("set local session authorization {}").format(
                sql.Identifier(f"sli_job_dispatcher_{profile}")))
            with connection.cursor() as cur:
                job_queue.fail(cur, {
                    "job_id": job_id, "lease_token": token, "lease_generation": generation,
                }, "job_deadline_exceeded")
        finally:
            connection.execute("reset session authorization")
        row = connection.execute(
            "select state,error_code,lease_token,lease_until,attempts,"
            "available_at>clock_timestamp(),available_at,deadline_at "
            "from sli_jobs.jobs where job_id=%s", (job_id,),
        ).fetchone()
        assert row[:6] == (state, "job_deadline_exceeded", None, None, attempts, state == "retry_wait")
        assert row[6] < row[7]
        if state == "quarantined":
            # Migration 211 preserves terminal schedules instead of adding retry backoff.
            assert row[6] == available_at
        assert connection.execute(
            "select transition,error_code,lease_generation from sli_jobs.audit where job_id=%s", (job_id,),
        ).fetchall() == [(state, "job_deadline_exceeded", generation)]

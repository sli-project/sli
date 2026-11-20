from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from server.sli.semantic.semantic_worker_connection import connect_semantic_worker
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
TARGET_TABLES = (
    "events_v2_core",
    "storage_v2_provider",
    "storage_v2_channel",
    "storage_v2_computer",
    "storage_v2_archive_sets",
    "storage_v2_archive_blocks",
    "semantic_processing_outbox",
    "normalized_events",
    "canonical_actions",
    "canonical_action_evidence",
    "canonical_action_state_evidence",
    "semantic_correlation_rules",
    "semantic_correlation_candidates",
    "semantic_correlation_candidate_evidence",
    "semantic_correlation_replays",
    "semantic_correlation_subscriptions",
    "semantic_correlation_dispatch_jobs",
    "semantic_security_scenarios",
    "semantic_scenario_steps",
    "semantic_scenario_evidence",
    "semantic_risk_contributions",
    "semantic_scenario_coverage_history",
    "semantic_risk_policies",
    "semantic_risk_policy_subscriptions",
    "semantic_control_health_observations",
    "semantic_risk_evaluation_jobs",
    "semantic_risk_evaluation_results",
    "runtime_worker_heartbeats",
)


def _bootstrap_migration_contract(conn) -> None:
    from psycopg import sql

    roles_sql = (
        ROOT / "config/postgres_migrations/storage_v2_roles.sql"
    ).read_text(encoding="utf-8")
    with conn.cursor() as cur:
        cur.execute(
            """
            do $$
            begin
                if to_regrole('adlog_user') is null then
                    create role adlog_user nologin nosuperuser nocreatedb
                        nocreaterole noinherit nobypassrls noreplication;
                end if;
            end
            $$;
            create table schema_migrations(
                id bigint generated always as identity primary key,
                version integer not null unique,
                name text not null
            );
            create table events(id bigint primary key);
            create table observed_entities(id bigint primary key);
            create table event_entity_links(id bigint primary key);
            """
        )
        cur.execute(roles_sql)
        cur.execute("begin")
        cur.execute("set local role adlog_storage_owner")
        for table in TARGET_TABLES:
            cur.execute(
                sql.SQL("create table {}(id bigint primary key)").format(
                    sql.Identifier(table)
                )
            )
        cur.execute(
            "insert into schema_migrations(version,name) "
            "values (49,'event_noise_browse_index')"
        )
        cur.execute("commit")


def _create_login(conn, *, role_name: str, password: str, createdb: bool) -> None:
    from psycopg import sql

    createdb_sql = sql.SQL("createdb") if createdb else sql.SQL("nocreatedb")
    with conn.cursor() as cur:
        cur.execute(
            sql.SQL(
                "create role {} login password {} nosuperuser {} "
                "nocreaterole noinherit nobypassrls noreplication"
            ).format(
                sql.Identifier(role_name),
                sql.Literal(password),
                createdb_sql,
            )
        )
        cur.execute(
            sql.SQL("grant adlog_semantic_worker to {}").format(
                sql.Identifier(role_name)
            )
        )


def _assert_worker_runtime_privileges(cur) -> None:
    # PostgreSQL comma-separated privilege lists mean ANY, not ALL.
    for table in ("semantic_processing_outbox", "runtime_worker_heartbeats"):
        for privilege in ("SELECT", "INSERT", "UPDATE"):
            cur.execute(
                "select has_table_privilege(%s, %s, %s) as allowed",
                ("adlog_semantic_worker", table, privilege),
            )
            assert cur.fetchone()["allowed"] is True, f"{table}:{privilege}"


@pytest.mark.parametrize("table", ["semantic_processing_outbox", "runtime_worker_heartbeats"])
@pytest.mark.parametrize("missing", [None, "SELECT", "INSERT", "UPDATE"])
def test_runtime_privilege_assertion_requires_each_grant(table, missing) -> None:
    class PrivilegeCursor:
        def execute(self, query, params):
            assert query == "select has_table_privilege(%s, %s, %s) as allowed"
            role, self.table, self.privilege = params
            assert role == "adlog_semantic_worker"
            assert self.privilege in {"SELECT", "INSERT", "UPDATE"}

        def fetchone(self):
            return {"allowed": (self.table, self.privilege) != (table, missing)}

    if missing is None:
        _assert_worker_runtime_privileges(PrivilegeCursor())
    else:
        with pytest.raises(AssertionError, match=f"{table}:{missing}"):
            _assert_worker_runtime_privileges(PrivilegeCursor())


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_migration_050_and_real_login_preflight_are_least_privilege(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dsn = str(os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip(
            "ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL "
            "integration tests"
        )

    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    suffix = uuid.uuid4().hex[:12]
    good_login = f"adlog_semantic_l2_{suffix}"
    bad_login = f"adlog_semantic_l2_bad_{suffix}"
    password = f"sli-l2-{suffix}"
    forward = (
        ROOT
        / "config/postgres_migrations/050_semantic_worker_least_privilege.sql"
    ).read_text(encoding="utf-8")
    rollback = (
        ROOT
        / "config/postgres_migrations/050_semantic_worker_least_privilege.rollback.sql"
    ).read_text(encoding="utf-8")

    admin = psycopg.connect(dsn, row_factory=dict_row, autocommit=True)
    try:
        assert_disposable_database(admin)
        _bootstrap_migration_contract(admin)
        with admin.cursor() as cur:
            cur.execute(forward)
            cur.execute(forward)
            cur.execute(
                "select count(1) as rows from schema_migrations "
                "where version=50 and name='semantic_worker_least_privilege'"
            )
            assert cur.fetchone()["rows"] == 1
            cur.execute(
                """
                select
                    has_schema_privilege(
                        'adlog_semantic_worker','public','USAGE'
                    ) as schema_usage,
                    has_table_privilege(
                        'adlog_semantic_worker','events_v2_core','SELECT'
                    ) as source_select,
                    has_table_privilege(
                        'adlog_semantic_worker','events_v2_core','INSERT'
                    ) as source_insert,
                    has_table_privilege(
                        'adlog_semantic_worker',
                        'semantic_processing_outbox','DELETE'
                    ) as outbox_delete
                """
            )
            grants = dict(cur.fetchone())
            assert grants == {
                "schema_usage": True,
                "source_select": True,
                "source_insert": False,
                "outbox_delete": False,
            }
            _assert_worker_runtime_privileges(cur)

        _create_login(
            admin,
            role_name=good_login,
            password=password,
            createdb=False,
        )
        _create_login(
            admin,
            role_name=bad_login,
            password=password,
            createdb=True,
        )

        monkeypatch.setenv(
            "ADLOG_SEMANTIC_WORKER_DSN",
            make_conninfo(dsn, user=good_login, password=password),
        )
        worker = connect_semantic_worker()
        try:
            with worker.cursor() as cur:
                cur.execute(
                    "select current_user as current_role,"
                    "session_user as session_role"
                )
                identity = dict(cur.fetchone())
                assert identity == {
                    "current_role": "adlog_semantic_worker",
                    "session_role": good_login,
                }
        finally:
            worker.close()

        monkeypatch.setenv(
            "ADLOG_SEMANTIC_WORKER_DSN",
            make_conninfo(dsn, user=bad_login, password=password),
        )
        with pytest.raises(
            RuntimeError,
            match="refuses elevated PostgreSQL credentials",
        ):
            connect_semantic_worker()

        with admin.cursor() as cur:
            cur.execute(rollback)
            cur.execute(
                "select count(1) as rows from schema_migrations where version=50"
            )
            assert cur.fetchone()["rows"] == 0
            cur.execute(
                "select has_table_privilege("
                "'adlog_semantic_worker','semantic_processing_outbox','SELECT'"
                ") as retained"
            )
            assert cur.fetchone()["retained"] is False
    finally:
        with admin.cursor() as cur:
            for role_name in (good_login, bad_login):
                cur.execute(
                    "select pg_terminate_backend(pid) from pg_stat_activity "
                    "where usename=%s and pid<>pg_backend_pid()",
                    (role_name,),
                )
                cur.execute(
                    sql.SQL("drop role if exists {}").format(
                        sql.Identifier(role_name)
                    )
                )
        admin.close()

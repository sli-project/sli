from __future__ import annotations

import json
import os
import secrets
import sys
import uuid
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def hermetic_report_domain(monkeypatch: pytest.MonkeyPatch):
    """Reports use a synthetic DB setting without connecting to a real DB."""
    from server.sli.core import platform_settings

    query_rows = platform_settings.database.query_rows

    def stored_setting(sql, params=(), **kwargs):
        if sql == "select is_archived from domains where lower(fqdn) = ?" and params == ("example.test",):
            return [{"is_archived": False}]
        if (
            sql == "select value, updated_by, updated_at from platform_settings where key = ?"
            and params == ("reports.domain_fqdn",)
        ):
            return [{"value": "example.test", "updated_by": None, "updated_at": None}]
        return query_rows(sql, params, **kwargs)

    monkeypatch.setattr(platform_settings.database, "query_rows", stored_setting)
    platform_settings.clear_cache()
    yield
    platform_settings.clear_cache()


def pytest_collection_modifyitems(items) -> None:
    """Skip native Windows tests while keeping portable Windows contracts."""
    if sys.platform == "win32":
        return
    skip = pytest.mark.skip(reason="Windows runtime required")
    for item in items:
        if item.get_closest_marker("windows_only") is not None:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def hermetic_domain_controller_targets(monkeypatch: pytest.MonkeyPatch):
    """Keep unit tests off any real database: stored DC targets are unreadable.

    Resolution then falls back to config/domain_controllers.json exactly as on
    an installation where migration 147 is not applied. Tests of the database
    path patch ``_query_target_rows`` themselves.
    """
    from server.sli.sources import dc_discovery

    def unreadable() -> list[dict]:
        raise RuntimeError("no database in unit tests")

    monkeypatch.setattr(dc_discovery, "_query_target_rows", unreadable)
    dc_discovery.clear_database_target_cache()
    yield
    dc_discovery.clear_database_target_cache()


_LEGACY_RADIUS_TARGET = [{
    "source_name": "radius01.example.invalid",
    "connect_address": "radius01.example.invalid",
    "owner_confirmed_ip": "192.0.2.15",
}]


@pytest.fixture
def legacy_radius_target_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    """Supply retired target data only to hermetic legacy-plan contract tests."""

    target_path = (
        Path(__file__).resolve().parents[1] / "config/stage9_radius_targets.json"
    ).resolve()
    original_read_text = Path.read_text

    def read_text(path: Path, *args, **kwargs) -> str:
        if path.resolve() == target_path:
            return json.dumps({"targets": _LEGACY_RADIUS_TARGET})
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)


@pytest.fixture(scope="session")
def historical_postgres_templates(tmp_path_factory):
    """Keep each exact historical template available until all its clones finish."""
    from contextlib import ExitStack

    from tests.migrations.historical_postgres import historical_connection

    templates = {}
    with ExitStack() as clusters, pytest.MonkeyPatch.context() as environment:
        def template_dsn(last_migration):
            if last_migration not in templates:
                root = tmp_path_factory.mktemp(f"pg-history-{last_migration[0]}")
                source = clusters.enter_context(historical_connection(root, environment, last_migration))
                templates[last_migration] = source.info.dsn
                source.close()  # PostgreSQL copies templates with no connected sessions.
            return templates[last_migration]

        yield template_dsn


@pytest.fixture(autouse=True)
def isolated_postgres_integration_database(request):
    """Clone a migrated or empty disposable template for each PostgreSQL test."""

    historical = request.node.get_closest_marker("postgres_historical")
    if (request.node.get_closest_marker("postgres_integration") is None
            or request.node.get_closest_marker("postgres_owned_cluster") is not None):
        if historical is not None:
            pytest.fail("A historical template requires a PostgreSQL integration test with a shared clone")
        yield
        return

    empty_schema = request.node.get_closest_marker("postgres_empty") is not None
    if historical is not None and empty_schema:
        pytest.fail("A PostgreSQL test cannot select both an empty and a historical template")
    dsn_variable = "ADLOG_TEST_PG_EMPTY_DSN" if empty_schema else "ADLOG_TEST_PG_DSN"
    base_dsn = str(os.environ.get(dsn_variable) or "").strip()
    if empty_schema and not base_dsn and os.environ.get("ADLOG_TEST_PG_DSN"):
        pytest.fail("Schema bootstrap tests require ADLOG_TEST_PG_EMPTY_DSN")
    if not base_dsn:
        yield
        return
    if historical is not None:
        version, name = historical.args
        template_dsn = request.getfixturevalue("historical_postgres_templates")
        base_dsn = template_dsn((version, name))

    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    values = conninfo_to_dict(base_dsn)
    template_name = str(values.get("dbname") or "")
    if not template_name.startswith("sli_test_"):
        pytest.fail(
            "PostgreSQL integration template must use the sli_test_ namespace"
        )

    database_name = f"sli_test_{uuid.uuid4().hex}"
    admin_dsn = make_conninfo(base_dsn, dbname="postgres")
    test_dsn = make_conninfo(base_dsn, dbname=database_name)
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL("create database {} with template {}").format(
                sql.Identifier(database_name),
                sql.Identifier(template_name),
            )
        )

    previous_test_dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    previous_runtime_dsn = os.environ.get("ADLOG_PG_DSN")
    os.environ["ADLOG_TEST_PG_DSN"] = test_dsn
    os.environ["ADLOG_PG_DSN"] = test_dsn
    try:
        if not empty_schema:
            with psycopg.connect(test_dsn, autocommit=True) as conn:
                # Synthetic core rows omit attribution and inherit this default.
                conn.execute(
                    "insert into event_catalog_revisions(version) "
                    "values ('pending-backfill') on conflict(version) do nothing"
                )
        yield
    finally:
        if previous_test_dsn is None:
            os.environ.pop("ADLOG_TEST_PG_DSN", None)
        else:
            os.environ["ADLOG_TEST_PG_DSN"] = previous_test_dsn
        if previous_runtime_dsn is None:
            os.environ.pop("ADLOG_PG_DSN", None)
        else:
            os.environ["ADLOG_PG_DSN"] = previous_runtime_dsn
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            admin.execute(
                "select pg_terminate_backend(pid) from pg_stat_activity "
                "where datname=%s and pid<>pg_backend_pid()",
                (database_name,),
            )
            admin.execute(
                sql.SQL("drop database {}").format(sql.Identifier(database_name))
            )


@pytest.fixture(autouse=True)
def _restore_process_environment():
    """Undo environment changes a test makes outside ``monkeypatch``.

    Some scripts under test load the protected runtime environment into
    ``os.environ`` (DSN, storage read mode); without this a single test could
    switch every later test to the V2 route or a real DSN.
    """
    snapshot = dict(os.environ)
    try:
        yield
    finally:
        for name in set(os.environ) - set(snapshot):
            os.environ.pop(name, None)
        for name, value in snapshot.items():
            if os.environ.get(name) != value:
                os.environ[name] = value


@pytest.fixture
def postgres_semantic_worker_dsn(isolated_postgres_integration_database):
    """Use a disposable non-elevated login for subprocess worker preflight."""
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    dsn = str(os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL tests")
    role = f"sli_test_worker_{uuid.uuid4().hex}"
    password = secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL(
            "create role {} login password {} nosuperuser nocreatedb "
            "nocreaterole noinherit nobypassrls noreplication"
        ).format(sql.Identifier(role), sql.Literal(password)))
        try:
            admin.execute(sql.SQL("grant adlog_semantic_worker to {}").format(sql.Identifier(role)))
            yield make_conninfo(dsn, user=role, password=password)
        finally:
            admin.execute(
                "select pg_terminate_backend(pid) from pg_stat_activity "
                "where usename=%s and pid<>pg_backend_pid()",
                (role,),
            )
            admin.execute(sql.SQL("drop role {}").format(sql.Identifier(role)))

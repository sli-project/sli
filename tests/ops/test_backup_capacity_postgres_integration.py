"""Real SQL contracts, exclusively on the repository's disposable CI database.

No archive restore, disk-fill, host measurement or production DSN is used.
The existing postgres job discovers this marker; no new service is provisioned.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from types import SimpleNamespace

import pytest

from deploy.linux import backup, backup_restore_check as drill
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


@pytest.fixture
def pg(isolated_postgres_integration_database):
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ.get("ADLOG_TEST_PG_DSN", "")
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured")
    with psycopg.connect(dsn, autocommit=True) as conn:
        identity = assert_disposable_database(conn)
        # Require the per-test clone, not the template or an arbitrary database.
        assert re.fullmatch(r"sli_test_[0-9a-f]{32}", str(identity["name"]))
        yield psycopg, dsn, conn


def test_restore_advisory_lock_serializes_real_sessions_and_releases_on_error(pg):
    psycopg, dsn, first = pg
    with psycopg.connect(dsn, autocommit=True) as second:
        with drill.postgres_restore_lock(first) as acquired:
            assert acquired is True
            with drill.postgres_restore_lock(second) as competing:
                assert competing is False
        with pytest.raises(RuntimeError, match="synthetic interrupted check"):
            with drill.postgres_restore_lock(first) as acquired:
                assert acquired is True
                raise RuntimeError("synthetic interrupted check")
        with drill.postgres_restore_lock(second) as acquired:
            assert acquired is True


@pytest.fixture
def owned(pg, tmp_path, monkeypatch):
    _, _, conn = pg
    statements = []
    raw_execute = conn.execute

    def execute(statement, params=()):
        statements.append(statement if isinstance(statement, str) else statement.as_string(conn))
        return raw_execute(statement, params)

    admin = SimpleNamespace(execute=execute)
    token = uuid.uuid4()
    # Predetermine this invocation's name, never enumerate/delete by prefix.
    monkeypatch.setattr(drill, "uuid", SimpleNamespace(uuid4=lambda: token))
    name = "sli_backup_check_" + token.hex
    assert conn.execute("SELECT oid FROM pg_database WHERE datname=%s", (name,)).fetchone() is None
    point = conn.execute(backup.PG_CAPACITY_SQL).fetchone()[0]
    with drill.postgres_restore_lock(admin) as acquired:
        assert acquired is True
        run = drill.create_owned_restore(tmp_path, admin, point)
        try:
            yield admin, point, run, tmp_path
        finally:
            # Tests restore deliberate metadata mutations before reaching here.
            # The production proof checks still authorize every DROP; no FORCE.
            assert drill.drop_owned_restore(tmp_path, admin, point, run)
            assert not any("FORCE" in query.upper() for query in statements)


def test_create_records_real_oid_comment_owner_and_revokes_public_connect(owned):
    conn, _, run, root = owned
    row = conn.execute(
        "SELECT d.oid, shobj_description(d.oid, 'pg_database'), "
        "d.datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user) "
        "FROM pg_database d WHERE datname=%s", (run["database"],)).fetchone()
    assert row == (run["oid"], drill._ownership_marker(run), True)
    public_connect = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM pg_database d, LATERAL "
        "aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a "
        "WHERE d.datname=%s AND a.grantee=0 AND a.privilege_type='CONNECT')",
        (run["database"],)).fetchone()[0]
    assert public_connect is False
    assert json.loads((root / ".restore-runs" / (run["token"] + ".json")).read_text()) == run


@pytest.mark.parametrize("defect", ["oid", "cluster_id", "token"])
def test_cleanup_rejects_unmatched_owned_identity_without_drop(owned, defect):
    conn, point, run, root = owned
    altered = dict(run)
    altered[defect] = run["oid"] + 1 if defect == "oid" else "0" * 32
    assert drill.drop_owned_restore(root, conn, point, altered) is False
    assert conn.execute("SELECT oid FROM pg_database WHERE datname=%s", (run["database"],)).fetchone() == (run["oid"],)
    assert (root / ".restore-runs" / (run["token"] + ".json")).is_file()


def test_cleanup_retains_database_when_real_comment_is_missing(owned):
    conn, point, run, root = owned
    from psycopg import sql

    statement = sql.SQL("COMMENT ON DATABASE {} IS {}")
    conn.execute(statement.format(sql.Identifier(run["database"]), sql.SQL("NULL")))
    try:
        assert drill.cleanup_owned_restores(root, conn, point) == {"removed": 0, "retained": 1}
        assert conn.execute("SELECT oid FROM pg_database WHERE datname=%s", (run["database"],)).fetchone() == (run["oid"],)
    finally:
        conn.execute(statement.format(sql.Identifier(run["database"]), sql.Literal(drill._ownership_marker(run))))


def test_cleanup_rejects_other_role_without_changing_privileges(owned):
    conn, point, run, root = owned
    # Built-in read-only role: session identity only, no CREATE ROLE or GRANT.
    conn.execute("SET ROLE pg_read_all_data")
    try:
        assert drill.drop_owned_restore(root, conn, point, run) is False
    finally:
        conn.execute("RESET ROLE")
    assert conn.execute("SELECT oid FROM pg_database WHERE datname=%s", (run["database"],)).fetchone() == (run["oid"],)


def test_cleanup_does_not_force_disconnect_active_owned_database(pg, owned):
    psycopg, dsn, _ = pg
    conn, point, run, root = owned
    with psycopg.connect(dsn, dbname=run["database"], autocommit=True) as active:
        assert drill.drop_owned_restore(root, conn, point, run) is False
        assert active.execute("SELECT 1").fetchone() == (1,)
        assert (root / ".restore-runs" / (run["token"] + ".json")).exists()
    # Closing our client is asynchronous on the server; observe its exit, never
    # terminate a backend or force a DROP to make the test finish.
    deadline = time.monotonic() + 5
    while conn.execute("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datid=%s)",
                       (run["oid"],)).fetchone()[0]:
        assert time.monotonic() < deadline, "owned test session did not exit"
        time.sleep(0.05)


def test_cleanup_removes_exact_owned_database_and_registry(owned):
    conn, point, run, root = owned
    assert drill.cleanup_owned_restores(root, conn, point) == {"removed": 1, "retained": 0}
    assert conn.execute("SELECT oid FROM pg_database WHERE datname=%s", (run["database"],)).fetchone() is None
    assert not (root / ".restore-runs" / (run["token"] + ".json")).exists()

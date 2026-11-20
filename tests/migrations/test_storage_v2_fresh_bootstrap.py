"""Fresh-store admission must not masquerade as a historical cutover."""
from datetime import datetime, timedelta, timezone

import pytest
import os
from pathlib import Path
import uuid
import importlib

from server.sli.storage import storage_v2_runtime_authorization as auth


class Cursor:
    def __init__(self, row):
        self.row = row

    def execute(self, query, params=()):
        pass

    def fetchone(self):
        return self.row


def record(tmp_path, **changes):
    issued = datetime(2026, 9, 10, tzinfo=timezone.utc)
    values = dict(
        route="v2", authority="storage-v2-fresh-bootstrap/v1",
        preflight_digest="a" * 64, archive_root=str(tmp_path),
        evidence={"kind": "fresh-event-store", "version": 1},
        authorized_by="local-owner", authorized_at=issued,
        expires_at=issued + timedelta(days=365),
    )
    values.update(changes)
    return dict(values, singleton=True, revoked_at=None,
                authorization_digest=auth.runtime_authorization_digest(**values))


def test_fresh_admission_loads_into_existing_direct_runtime_boundary(tmp_path):
    row = record(tmp_path)
    result = auth.load_runtime_authorization(Cursor(row), now=row["authorized_at"])
    assert auth.is_persisted_runtime_authorization(result)
    assert result.route == "v2"
    assert result.authority == "storage-v2-fresh-bootstrap/v1"


@pytest.mark.parametrize("changes", [
    {"route": "v2_primary_compat"},
    {"evidence": {"backup_restore_verified": True}},
])
def test_fresh_admission_cannot_authorize_legacy_transition(tmp_path, changes):
    row = record(tmp_path, **changes)
    with pytest.raises(RuntimeError):
        auth.load_runtime_authorization(Cursor(row), now=row["authorized_at"])


def test_fresh_admission_remains_revocable_and_tamper_evident(tmp_path):
    row = record(tmp_path)
    for changed in [dict(row, revoked_at=row["authorized_at"]),
                    dict(row, archive_root=str(tmp_path / "different"))]:
        with pytest.raises(RuntimeError):
            auth.load_runtime_authorization(Cursor(changed), now=row["authorized_at"])


class FreshCursor:
    def __init__(self, dirty_table=None):
        self.dirty_table = dirty_table
        self.query = ""

    def execute(self, query, params=()):
        from psycopg.sql import Composable

        self.query = query.as_string() if isinstance(query, Composable) else query

    def fetchall(self):
        return [{"version": version, "name": name}
                for version, name in auth.FRESH_REQUIRED_MIGRATIONS.items()]

    def fetchone(self):
        if "current_database()" in self.query:
            return {"database": "synthetic_store", "issuer": "synthetic_owner"}
        return {"present": self.dirty_table is not None and self.dirty_table in self.query}


@pytest.mark.parametrize("existing_payload", [False, True])
def test_fresh_storage_inspection_does_not_require_an_empty_directory(tmp_path, existing_payload):
    root = tmp_path / "historical-location"
    if existing_payload:
        root.mkdir()
        (root / "object.bin").write_bytes(b"synthetic")
    evidence = auth.inspect_fresh_storage(FreshCursor(), archive_root=root)
    assert evidence["kind"] == "fresh-event-store"
    assert evidence["historical_cutover_performed"] is False
    assert "archive_empty" not in evidence
    assert root.exists() is existing_payload


@pytest.mark.parametrize("dirty_table", [
    "events_v2_core", "event_facts_v2", "event_entity_link_blocks_v2",
    "storage_v2_event_identity_allocations", "raw_log_files", "storage_v2_outbox",
    "storage_v2_archive_blocks", "storage_v2_archive_sets",
])
def test_fresh_storage_inspection_still_refuses_nonempty_database(tmp_path, dirty_table):
    with pytest.raises(RuntimeError, match="fresh_storage_not_empty"):
        auth.inspect_fresh_storage(FreshCursor(dirty_table), archive_root=tmp_path / "missing")


@pytest.fixture
def disposable_pg():
    """Only create/drop this invocation's UUID database, never the runtime DB."""
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from psycopg.rows import dict_row
    dsn = os.environ.get("SLI_TEST_ADMIN_DSN")
    if not dsn:
        pytest.skip("explicit disposable PostgreSQL admin DSN required")
    parts = conninfo_to_dict(dsn)
    assert parts.get("host") in {"127.0.0.1", "localhost", "::1"}
    name = "sli_fresh_test_" + uuid.uuid4().hex
    parts["dbname"] = "postgres"
    with psycopg.connect(make_conninfo(**parts), autocommit=True, connect_timeout=5) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(name)))
        try:
            parts["dbname"] = name
            with psycopg.connect(make_conninfo(**parts), row_factory=dict_row, connect_timeout=5) as conn:
                conn.execute("SET statement_timeout='10s'")
                conn.execute("SET lock_timeout='2s'")
                conn.execute("CREATE TABLE schema_migrations(version integer primary key,name text not null)")
                conn.execute("INSERT INTO schema_migrations VALUES (90,'test-prerequisite')")
                conn.commit()
                conn.execute(Path("config/postgres_migrations/091_storage_v2_runtime_authorization.sql").read_text(encoding="utf-8"))
                conn.execute("INSERT INTO schema_migrations VALUES (93,'storage_v2_runtime_authorization_reader'),(94,'storage_v2_runtime_authorization_owner'),(96,'storage_v2_direct_ingest_worker_grants'),(97,'storage_v2_drop_legacy_v1_relations'),(133,'runtime_collection_history_restoration')")
                for table in ("events_v2_core", "event_facts_v2", "event_entity_link_blocks_v2",
                              "storage_v2_event_identity_allocations", "raw_log_files", "storage_v2_outbox",
                              "storage_v2_archive_blocks", "storage_v2_archive_sets"):
                    conn.execute(sql.SQL("CREATE TABLE {} (id bigint primary key)").format(sql.Identifier(table)))
                conn.execute("CREATE TABLE entities_v2(id bigint primary key)")
                conn.execute("INSERT INTO entities_v2 VALUES (5320)")
                conn.commit()
                yield conn
        finally:
            admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))


def test_fresh_bootstrap_pg_refuses_dirty_store_then_issues_once(disposable_pg, tmp_path):
    bootstrap = getattr(auth, "bootstrap_fresh_runtime_authorization", None)
    assert callable(bootstrap), "first-time Storage V2 initialization is missing"
    conn = disposable_pg
    issued = datetime.now(timezone.utc)
    options = dict(archive_root=tmp_path, authorized_by="local-owner",
                   issued_at=issued, expires_at=issued + timedelta(days=365))
    from psycopg import sql
    for table in ("events_v2_core", "event_facts_v2", "event_entity_link_blocks_v2",
                  "storage_v2_event_identity_allocations", "raw_log_files", "storage_v2_outbox",
                  "storage_v2_archive_blocks", "storage_v2_archive_sets"):
        with conn.transaction(force_rollback=True):
            conn.execute(sql.SQL("INSERT INTO {} VALUES (1)").format(sql.Identifier(table)))
            with pytest.raises(RuntimeError, match="not_empty"):
                bootstrap(conn.cursor(), **options)
    import psycopg
    with psycopg.connect(os.environ["SLI_TEST_ADMIN_DSN"], dbname=conn.info.dbname,
                         autocommit=True, connect_timeout=5) as busy:
        busy.execute("SELECT pg_advisory_lock(hashtext('ad_log_reports_runtime_collection_process'))")
        with conn.transaction(force_rollback=True):
            with pytest.raises(RuntimeError, match="collection_active"):
                bootstrap(conn.cursor(), **options)
    with conn.transaction(force_rollback=True):
        conn.execute("CREATE TABLE events(id bigint)")
        with pytest.raises(RuntimeError, match="legacy_relations_present"):
            bootstrap(conn.cursor(), **options)
    with conn.transaction():
        result = bootstrap(conn.cursor(), **options)
    assert result.authority == "storage-v2-fresh-bootstrap/v1"
    assert conn.execute("SELECT count(*) AS n FROM entities_v2").fetchone()["n"] == 1
    conn.commit()
    with conn.transaction(force_rollback=True):
        with pytest.raises(RuntimeError, match="already_initialized"):
            bootstrap(conn.cursor(), **options)
    with conn.transaction(force_rollback=True):
        conn.execute("UPDATE storage_v2_runtime_authorizations SET revoked_at=now()")
        with pytest.raises(RuntimeError, match="revoked"):
            auth.load_runtime_authorization(conn.cursor())
    with conn.transaction():
        loaded = auth.load_runtime_authorization(conn.cursor())
    assert loaded.authorization_digest == result.authorization_digest


@pytest.mark.parametrize("dsn", [
    "host=10.1.2.243 port=55433 dbname=sli_local",
    "host=127.0.0.1 hostaddr=10.1.2.243 port=55433 dbname=sli_local",
    "host=127.0.0.1 port=5432 dbname=sli_local",
    "host=127.0.0.1 port=55433 dbname=postgres",
])
def test_local_controller_rejects_target_drift_before_connect(dsn):
    import importlib.util
    name = "scripts.maintenance.storage_v2_fresh_bootstrap"
    assert importlib.util.find_spec(name), "local fresh bootstrap controller missing"
    controller = importlib.import_module(name)
    with pytest.raises(RuntimeError):
        controller.validate_target(dsn)


def test_local_controller_rejects_apply_without_confirmation(monkeypatch):
    import importlib.util
    name = "scripts.maintenance.storage_v2_fresh_bootstrap"
    assert importlib.util.find_spec(name), "local fresh bootstrap controller missing"
    controller = importlib.import_module(name)
    monkeypatch.setattr(controller, "_dsn", lambda **kw: pytest.fail("credentials read before confirmation"))
    with pytest.raises(RuntimeError, match="confirmation"):
        controller.run(action="apply")

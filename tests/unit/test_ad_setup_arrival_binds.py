"""AD setup arrivals must cross the real project read adapter."""
import os
import re
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest

from server.sli.core import database, postgres_runtime_pipeline, setup_status
from server.sli.plugins.ad import setup_status as ad_setup
from server.sli.reporting import read_timeout


@pytest.fixture
def read_boundary(monkeypatch):
    monkeypatch.setattr(database, "_require_runtime_db", lambda: None)
    monkeypatch.setattr(read_timeout, "remaining_read_ms", lambda: None)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: pytest.fail("Unexpected database connection"))


@pytest.mark.parametrize("kind,parameters", [("context", 1), ("event", 2)])
def test_ad_arrivals_keep_real_adapter_binds(monkeypatch, read_boundary, kind, parameters):
    stamp = datetime(2026, 1, 2, tzinfo=UTC)
    calls = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def execute(self, sql, params):
            calls.append((sql, params))
            assert sum(token == "%s" for token in re.findall(r"%%|%s", sql)) == parameters == len(params)
            assert params[0] == ["fixture.invalid"]
            if kind == "event":
                assert params[1] == ["security"]

        def fetchall(self):
            return [{"source_instance_id": "FIXTURE.INVALID", "last_data_utc": stamp}]

    class Connection(Cursor):
        def cursor(self):
            return Cursor()

    monkeypatch.setattr(postgres_runtime_pipeline, "connect", Connection)
    assert ad_setup.source_data({"source_kind": kind, "channels": ["Security"]},
                                [{"source_instance_id": "Fixture.Invalid"}]) == {"fixture.invalid": stamp}
    assert len(calls) == 1


def test_empty_ad_instances_do_not_read(read_boundary):
    assert ad_setup.source_data({"source_kind": "context"}, []) == {}


def test_failed_ad_read_remains_unavailable(monkeypatch, read_boundary):
    def broken():
        raise OSError("synthetic unavailable")

    monkeypatch.setattr(postgres_runtime_pipeline, "connect", broken)
    invoke = lambda: ad_setup.source_data({"source_kind": "event", "channels": []},
                                         [{"source_instance_id": "fixture.invalid"}])
    with pytest.raises(OSError):
        invoke()
    assert setup_status._safe(invoke) is None


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_ad_arrivals_through_real_postgres_adapter(monkeypatch, read_boundary):
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    from tests.postgres_integration_guard import assert_disposable_database

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL DSN required")
    stamp = datetime(2026, 1, 2, tzinfo=UTC)
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("""
            create temporary table ad_snapshot_manifests
                (manifest_id int, domain_dns text, created_at timestamptz, coverage_state text);
            create temporary table ad_snapshot_manifest_sources
                (manifest_id int, family text, source_state text);
            create temporary table collector_channel_runs
                (server text, channel text, created_at timestamptz, inserted int);
            insert into ad_snapshot_manifests values
                (1,'Fixture.Invalid','2026-01-02T00:00:00Z','complete'),
                (2,'other.invalid','2026-02-02T00:00:00Z','complete'),
                (3,'Fixture.Invalid','2026-03-02T00:00:00Z','failed'),
                (4,'Fixture.Invalid','2026-04-02T00:00:00Z','complete');
            insert into ad_snapshot_manifest_sources values
                (1,'ad_context_base','complete'),(2,'ad_context_base','complete'),
                (3,'ad_context_base','complete'),(4,'other_family','complete');
            insert into collector_channel_runs values
                ('Fixture.Invalid','Security','2026-01-02T00:00:00Z',1),
                ('Fixture.Invalid','Security','2026-02-02T00:00:00Z',0),
                ('Fixture.Invalid','Other','2026-03-02T00:00:00Z',1),
                ('other.invalid','Security','2026-04-02T00:00:00Z',1);
        """)

        @contextmanager
        def connection():
            yield conn

        monkeypatch.setattr(postgres_runtime_pipeline, "connect", connection)
        for kind in ("context", "event"):
            pack = {"source_kind": kind, "channels": ["Security"]}
            assert ad_setup.source_data(pack, [{"source_instance_id": "Fixture.Invalid"}]) == {"fixture.invalid": stamp}
            assert ad_setup.source_data(pack, [{"source_instance_id": "missing.invalid"}]) == {}

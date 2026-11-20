"""Real disposable PostgreSQL transaction boundaries for default R01 isolation."""
from contextlib import contextmanager
from dataclasses import asdict
import os

import pytest

from server.sli.semantic import default_detections as defaults
from tests.postgres_integration_guard import assert_disposable_database
from server.sli.semantic.semantic_risk_policy import compile_risk_policy
from tests.unit.test_finding_evidence_refs import reference

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def _default_result(*, sources, jobs, failed):
    return {"sources": sources, "jobs": jobs, "failed": failed,
        "coverage_counts": dict.fromkeys(("healthy", "partial", "error", "unknown", "stale", "disabled", "failed"), 0),
        "password_work_counts": dict.fromkeys(("native_items", "xml_bytes", "retained_queries", "reservation_occurrences",
            "window_queries", "reservation_calls", "tracking_calls", "completion_calls"), 0)}


@pytest.fixture
def pg_connection():
    import psycopg
    from psycopg.rows import dict_row

    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('disposable PostgreSQL not configured')
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute('create table isolation_writes(kind text, '
                     'unique(kind) deferrable initially deferred)')
        try:
            yield conn
        finally:
            conn.close()


class DiscoveryConnection:
    """Replace discovery only; transactions and detector writes use real psycopg."""

    def __init__(self, conn, failure=None):
        self.conn = conn
        self.failure = failure

    @property
    def info(self):
        return self.conn.info

    @property
    def closed(self):
        return self.conn.closed

    def transaction(self):
        return self.conn.transaction()

    @contextmanager
    def cursor(self):
        with self.conn.cursor() as cur:
            yield DiscoveryCursor(cur, self.failure)


class DiscoveryCursor:
    def __init__(self, cur, failure):
        self.cur = cur
        self.failure = failure
        self.connection = cur.connection
        self.rows = None

    def execute(self, sql, params=()):
        self.rows = None
        if 'default_detection_sources()' in sql:
            self.rows = [{'source': {'scope': asdict(reference('file_audit_observation').scope),
                'agent_id': '00000000-0000-0000-0000-000000000003',
                'config': {'policy_revision': '3', 'mass_operation_files': 25, 'mass_operation_seconds': 60}}}]
        elif 'read_default_file_acl_resources' in sql:
            self.rows = [{'page': {'items': []}}]
        else:
            prefix = {'rollback': 'rollback to ', 'entry': 'savepoint ', 'release': 'release '}.get(self.failure)
            if prefix and sql.startswith(prefix):
                # Actual server-side failure, not a Python exception or fake transaction.
                sql = 'rollback to savepoint synthetic_missing_savepoint'
            self.cur.execute(sql, params)

    def fetchall(self):
        return self.rows if self.rows is not None else self.cur.fetchall()

    def fetchone(self):
        return self.rows[0] if self.rows is not None else self.cur.fetchone()


@pytest.mark.parametrize('failure,jobs,failed,kinds', [
    ('sql', 2, 1, ['decoy']),
    ('rollback', 0, 1, []),
    ('entry', 0, 1, []),
    ('release', 0, 1, []),
    ('commit', 0, 1, []),
    ('none', 5, 0, ['decoy', 'ransom-admission', 'ransom-runtime']),
    ('disabled', 2, 0, ['decoy', 'ransom-admission']),
])
def test_default_source_durability_and_sql_error_recovery(pg_connection, monkeypatch, failure, jobs, failed, kinds):
    def admit(cur, policy):
        if compile_risk_policy(policy).scenario_kind == 'qw.file-ransom':
            cur.execute("insert into isolation_writes values ('ransom-admission')")
            return failure != 'disabled'
        return True

    def decoy(cur, *, rule, now):
        assert now.tzinfo is not None
        cur.execute("insert into isolation_writes values ('decoy')")
        return {'jobs': 2}

    def ransom(cur, *, rule, now):
        assert rule.source_policy_revision == '3' and rule.threshold == 25 and rule.window_seconds == 60
        cur.execute("insert into isolation_writes values ('ransom-runtime')")
        if failure in ('sql', 'rollback'):
            cur.execute('select 1/0')
        elif failure == 'commit':
            # Both writes succeed; only the real outer COMMIT checks this constraint.
            cur.execute("insert into isolation_writes values ('decoy')")
        return {'jobs': 3}

    monkeypatch.setattr(defaults, '_admit', admit)
    monkeypatch.setattr(defaults.file_decoy_runtime, 'run_once', decoy)
    monkeypatch.setattr(defaults.file_ransom_runtime, 'run_once', ransom)
    result = defaults.run_default_detections(DiscoveryConnection(pg_connection, failure))
    assert result == _default_result(sources=1, jobs=jobs, failed=failed)
    assert pg_connection.execute('select 42 as recovered').fetchone() == {'recovered': 42}
    assert [row['kind'] for row in pg_connection.execute('select kind from isolation_writes order by kind')] == kinds
    # A second transaction can commit on the same connection after the failed one.
    with pg_connection.transaction():
        pg_connection.execute("insert into isolation_writes values ('recovered')")
    assert pg_connection.execute("select count(*) as count from isolation_writes where kind='recovered'").fetchone()['count'] == 1

"""Native PG-only diagnosis; does not claim CH/report or LAB acceptance."""
from datetime import datetime, timezone
import json
import os
from time import monotonic

import pytest


@pytest.mark.postgres_integration
def test_new_logon_pairs_full_context_on_5000_synthetic_workstations(monkeypatch):
    dsn = os.environ.get('ADLOG_TEST_PG_DSN', '').strip()
    if not dsn:
        pytest.skip('Disposable PostgreSQL DSN required')
    import psycopg
    from psycopg.rows import dict_row
    from server.sli.plugins.ad.reports import new_logon_pairs_reporting as engine
    from tests.reporting.new_logon_pairs_native_fixture import explain_native_context, seed_native_context
    from tests.postgres_integration_guard import assert_disposable_database

    monkeypatch.setenv('ADLOG_PG_DSN', dsn)
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        assert_disposable_database(connection)
        fixture = seed_native_context(connection, observed_at=datetime.now(timezone.utc))
    observations = []
    for observation in ('first', 'repeat'):
        before = monotonic()
        context = engine.load_context(fixture['domain_id'])
        seconds = monotonic() - before
        assert not context['partial']
        assert context['server_ids'] == sorted(fixture['server_ids'])
        assert len(context['accounts']) == len(context['computers']) == 5000
        assert context['accounts'] == {f'synthetic-user-{i}': False for i in range(5000)}
        assert set(context['computers']) == set(fixture['computer_guids'].values())
        observations.append({'observation': observation, 'seconds': seconds,
                             'users': 5000, 'computers': 5000, 'sources': 2})
        print('T002 actual PostgreSQL context:', json.dumps(observations[-1], sort_keys=True), flush=True)
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        assert_disposable_database(connection)
        explain_native_context(connection, fixture['domain_id'])
    # The <10s full-report goal is deferred, not a general CI pass condition.
    # These context-only observations remain diagnostic, not proof of report
    # latency or cold-cache p95. Correctness checks above remain mandatory.

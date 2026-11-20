"""Opt-in, disposable PG + ClickHouse diagnostic for the actual report route.

The existing hermetic fixture supplies example.test platform settings; domain
and context tables, history transport and verification are real.
All identities/events are synthetic. Timings exclude seeding and are not LAB,
production, p95, or source-continuity evidence. No runtime source is replaced.
"""
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
import json
import os
from pathlib import Path
from time import monotonic

import pytest

pytestmark = pytest.mark.postgres_integration
ROOT = Path(__file__).resolve().parents[2]


def _guard():
    if os.environ.get('SLI_T002_NATIVE_CH') != '1':
        pytest.skip('Opt-in owned temporary ClickHouse diagnostic only')
    assert os.environ.get('ADLOG_HISTORY_CLICKHOUSE_HOST') == '127.0.0.1'
    assert not os.environ.get('ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE')
    assert os.environ.get('ADLOG_HISTORY_CLICKHOUSE_USER') == 't002_ci'
    assert os.environ.get('ADLOG_HISTORY_CLICKHOUSE_PASSWORD')
    assert os.environ.get('ADLOG_TEST_PG_DSN')
    assert os.environ.get('ADLOG_HISTORY_READ_MODE') == 'primary'


def _report(domain, start, end):
    from server.api.routes import reports_v2 as routes
    from tests.reporting.test_new_logon_pairs_v2 import access

    class Handler:
        def _access_decision(self):
            return access(scope={'kind': 'domain', 'ids': [domain]})

        def _send_json(self, payload, status=HTTPStatus.OK):
            self.payload, self.status = payload, status

    handler = Handler()
    assert routes.try_handle_get(handler, '/api/v2/reports/ad.new-logon-pairs/data', {
        'period': ['custom'], 'from': [start.isoformat()], 'to': [end.isoformat()],
        'baseline_days': ['30'],
    })
    assert handler.status == HTTPStatus.OK
    return handler.payload


def _seed_history(history, port, domain, servers, start, end, *, count, known=False, corrupt=False):
    # This connection is only handed out by the opt-in owned-container runner.
    for table in ('events', 'links', 'published_batches'):
        history._http_query(port, f'TRUNCATE TABLE sli_history.{table}')
    baseline = start - timedelta(days=30)
    events = []
    for window in range(2):
        for i in range(count):
            user = i % 5000
            computer = user if window == 0 or known else (user + 1) % 5000
            at = baseline + timedelta(seconds=i) if window == 0 else start + timedelta(microseconds=i)
            event_id = len(events) + 1
            core = {
                'id': event_id, 'event_id': 4624, 'server_id': servers[i % 2],
                'domain_id': domain, 'channel': 'Security', 'time_created_utc': at.isoformat(),
                'target_domain_name': 'EXAMPLE', 'target_user_name': f'synthetic-user-{user}',
                'target_user_sid': f'S-1-5-21-1-2-3-{10000 + user}',
                'workstation_name': f'PC-{computer}', 'computer': f'DC-{i % 2}', 'logon_type': '3',
            }
            events.append({
                'event_db_id': event_id, 'time_created_utc': history._ch_time(at),
                'event_key': 4624, 'server_id': core['server_id'], 'noise_class': '',
                'core_json': json.dumps(core), 'facts_json': '{}',
                'row_sha256': history._payload_sha({'core': core, 'facts': {}}),
            })
    if count:
        # Bounds for BOTH DCs, outside the half-open query windows. They do not
        # prove continuous collection and are not added to expected pair counts.
        for at in (baseline - timedelta(seconds=1), end):
            for server in servers:
                core = json.loads(events[0]['core_json'])
                core.update(id=len(events) + 1, server_id=server, time_created_utc=at.isoformat())
                events.append({**events[0], 'event_db_id': core['id'],
                    'server_id': server, 'time_created_utc': history._ch_time(at),
                    'core_json': json.dumps(core),
                    'row_sha256': history._payload_sha({'core': core, 'facts': {}})})
    for offset in range(0, len(events), 1000):
        batch = events[offset:offset + 1000]
        identity = history._identity(batch, [])
        for row in batch:
            row['batch_sha256'] = identity['batch_sha256']
        if corrupt and offset == 0:
            batch[0]['row_sha256'] = 'F' * 64
        history._http_insert_json_rows(port, 'sli_history.events', batch)
        history._http_insert_json_rows(port, 'sli_history.published_batches', [{
            **identity, 'published_at_utc': history._ch_time(end),
        }])


def test_actual_report_native_context_history_and_volume(monkeypatch):
    _guard()
    import psycopg
    from psycopg.rows import dict_row
    from server.sli.plugins.ad.reports import new_logon_pairs_reporting as engine
    from tests.reporting.new_logon_pairs_native_fixture import explain_native_context, seed_native_context
    from tests.postgres_integration_guard import assert_disposable_database

    history = engine.history
    port = history.configured_read_port()
    assert port and 1024 <= port <= 65535
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=1)
    with psycopg.connect(os.environ['ADLOG_TEST_PG_DSN'], row_factory=dict_row) as connection:
        assert_disposable_database(connection)
        fixture = seed_native_context(connection, observed_at=end)
    domain, servers = fixture['domain_id'], fixture['server_ids']
    # Fail fast on fixture construction, outside the measured request. This is
    # the real context loader, including current workstation SQL and hash checks.
    inventory = engine.load_context(domain)
    assert not inventory['partial']
    assert len(inventory['accounts']) == 5000
    assert len(inventory['computers']) == 5000
    assert inventory['server_ids'] == sorted(servers)
    for statement in (ROOT / 'config/clickhouse/002_permanent_fact_history.sql').read_text().split(';'):
        if statement.strip():
            history._http_query(port, statement)

    timings, queries, compared_items = {}, [], []
    for name in ('load_context', 'load_history', 'compute_pairs', 'user_entities'):
        original = getattr(engine, name)
        def measured(*args, _name=name, _original=original, **kwargs):
            before = monotonic()
            try:
                value = _original(*args, **kwargs)
                if _name == 'compute_pairs':
                    compared_items.extend(value['items'])
                return value
            finally:
                timings[_name] = timings.get(_name, 0) + monotonic() - before
        monkeypatch.setattr(engine, name, measured)
    rows = history._rows
    def measured_rows(port, sql, *, query_params=None):
        before = monotonic()
        try:
            return rows(port, sql, query_params=query_params)
        finally:
            queries.append((sql, query_params, monotonic() - before))
    monkeypatch.setattr(history, '_rows', measured_rows)

    observations = []
    for label, count, known, corrupt in (
        ('empty', 0, False, False), ('new_pairs', 10, False, False),
        ('known_pairs', 10, True, False), ('corrupt', 10, False, True),
        ('volume_first', 50000, False, False), ('volume_repeat', None, False, False),
    ):
        if count is not None:
            _seed_history(history, port, domain, servers, start, end,
                          count=count, known=known, corrupt=corrupt)
        timings.clear()
        queries.clear()
        compared_items.clear()
        before = monotonic()
        payload = _report(domain, start, end)
        elapsed = monotonic() - before
        observation = {'case': label, 'seconds': elapsed, 'phases': dict(timings),
                       'history_calls': len(queries), 'history_http_seconds': sum(q[2] for q in queries),
                       'state': payload['state'], 'item_count': len(payload['items']),
                       'limitation_codes': [item['code'] for item in payload['limitations']]}
        observations.append(observation)
        print('T002 native synthetic:', json.dumps(observation, sort_keys=True), flush=True)
        if label == 'empty':
            assert payload['state'] == 'empty'
            assert 'history_empty' in observation['limitation_codes']
            assert not payload['items']
        elif corrupt:
            assert payload['state'] == 'error'
            assert 'history_verification_failed' in observation['limitation_codes']
            assert not payload['items']
        elif known:
            assert payload['state'] == 'empty' and not payload['items']
        else:
            assert payload['state'] == 'ok', observation
            assert len(payload['items']) == (10 if label == 'new_pairs' else 50)
            expected_pairs = 10 if label == 'new_pairs' else 5000
            assert len(compared_items) == expected_pairs
            assert len({item['id'] for item in compared_items}) == expected_pairs
            for item in compared_items:
                user_index = int(item['user_sid'].rsplit('-', 1)[1]) - 10000
                assert 0 <= user_index < expected_pairs
                computer = f'PC-{(user_index + 1) % 5000}'
                assert item['computer'] == computer
                assert item['computer_guid'] == fixture['computer_guids'][computer]
                assert item['source_event_id'] == (10 if label == 'new_pairs' else 50000) + 1 + user_index
                assert item['count'] == (1 if label == 'new_pairs' else 10)
            assert payload['coverage']['baseline_covered']
            assert payload['coverage']['period_covered']
            assert not payload['coverage']['truncated']
            for item in payload['items']:
                assert item['novelty'] == 'new_pair'
                assert item['prior_user_logon'] == 'yes'
                assert item['count'] == (1 if label == 'new_pairs' else 10)
                assert item['computer_entity_id'] is not None
                assert item['source_event_id'] > (10 if label == 'new_pairs' else 50000)
    # Real CH plans for each distinct query shape, outside request measurements.
    representatives = {}
    for sql, params, _ in queries:
        kind = ('bounds' if 'GROUP BY server_id' in sql else 'window' if 'SELECT event_db_id FROM' in sql
                else 'catalog' if 'SELECT batch_sha256,first_event_db_id' in sql else 'verified_events')
        representatives.setdefault(kind, (sql, params))
    for kind, (sql, params) in representatives.items():
        plan = history._http_query(port, 'EXPLAIN indexes = 1 ' + sql,
            params={f'param_{key}': value for key, value in (params or {}).items()})
        # Explain contains only generated synthetic IDs, not source/user data.
        print('T002 synthetic CH plan', kind, plan.decode(), flush=True)
    with psycopg.connect(os.environ['ADLOG_TEST_PG_DSN'], row_factory=dict_row) as connection:
        assert_disposable_database(connection)
        explain_native_context(connection, domain)
    assert all(item['seconds'] < 10 for item in observations if item['case'].startswith('volume')), observations

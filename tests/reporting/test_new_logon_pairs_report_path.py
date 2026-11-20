"""Actual v2 dispatcher and report; only external context/transport boundaries are fake.

These tests do not prove ClickHouse SQL execution, network timing or LAB acceptance.
"""
import json
import re
from http import HTTPStatus

import pytest

from server.api.routes import reports_v2 as routes
from server.sli.plugins.ad.reports import new_logon_pairs_reporting as engine
from server.sli.reporting.v2.reports import computer_logons
from tests.reporting.test_new_logon_pairs_v2 import (
    ACCOUNTS, BASELINE, END, INDEX, START, access, event,
)


def source_boundaries(monkeypatch, *, empty=False, known=False, corrupt=False):
    monkeypatch.setattr(computer_logons, 'resolve_report_domain_id', lambda: 7)
    monkeypatch.setattr(engine, 'load_context', lambda domain: {
        'index': INDEX, 'accounts': ACCOUNTS, 'server_ids': [10], 'partial': False,
        'computers': {'guid-1': {'entity_id': 101}, 'guid-2': {'entity_id': 102}},
    })
    monkeypatch.setattr(engine, 'user_entities', lambda *_: {})
    monkeypatch.setattr(engine.history, 'primary_read_enabled', lambda: True)
    monkeypatch.setattr(engine.history, 'configured_read_port', lambda: 8123)
    cores = {
        1: event(1, at=BASELINE),
        2: event(2, computer='PC-1' if known else 'PC-2'),
    }
    calls = []

    def rows(port, sql, *, query_params=None):
        calls.append((sql, query_params))
        if 'GROUP BY server_id' in sql:
            assert query_params['domain'] == '7'
            assert query_params['servers'] == '[10]'
            return [] if empty else [{
                'server_id': 10, 'first_utc': engine.history._ch_time(BASELINE),
                'last_utc': engine.history._ch_time(END),
            }]
        if 'SELECT event_db_id FROM' in sql:
            assert query_params['domain'] == '7'
            assert query_params['servers'] == '[10]'
            assert 'published_batches' in sql
            assert 'time_created_utc<' in sql and 'time_created_utc>=' in sql
            return [] if empty else [{'event_db_id': 1 if query_params['start'] == engine.history._ch_time(BASELINE) else 2}]
        if 'SELECT event_db_id,time_created_utc' in sql:
            ids = map(int, re.search(r'event_db_id IN \(([0-9,]+)\)', sql)[1].split(','))
            return [{
                'event_db_id': i, 'time_created_utc': engine.history._json_ch_time(cores[i]['time_created_utc']),
                'event_key': 4624, 'server_id': 10, 'noise_class': '',
                'core_json': json.dumps(cores[i]), 'facts_json': '{}',
                'row_sha256': 'bad-hash' if corrupt else engine.history._payload_sha({'core': cores[i], 'facts': {}}),
                'batch_sha256': '0' * 64,
            } for i in ids]
        if 'SELECT batch_sha256,first_event_db_id,last_event_db_id' in sql:
            return [{'batch_sha256': '0' * 64, 'first_event_db_id': 1, 'last_event_db_id': 2}]
        raise AssertionError('unexpected history query')

    monkeypatch.setattr(engine.history, '_rows', rows)
    return calls


def read_report(decision=None):
    class Handler:
        def _access_decision(self):
            return access() if decision is None else decision

        def _send_json(self, payload, status=HTTPStatus.OK):
            self.payload, self.status = payload, status

    handler = Handler()
    assert routes.try_handle_get(handler, '/api/v2/reports/ad.new-logon-pairs/data', {
        'period': ['custom'], 'from': [START.isoformat()], 'to': [END.isoformat()],
        'baseline_days': ['30'],
    })
    return handler


@pytest.mark.parametrize('empty,known,expected', [(False, False, 'ok'), (True, False, 'empty'), (False, True, 'empty')])
def test_dispatcher_reaches_verified_history_and_comparison(monkeypatch, empty, known, expected):
    calls = source_boundaries(monkeypatch, empty=empty, known=known)
    handler = read_report()
    assert handler.status == HTTPStatus.OK
    assert handler.payload['state'] == expected
    codes = {item['code'] for item in handler.payload['limitations']}
    assert ('history_empty' in codes) is empty
    if not empty and not known:
        row, = handler.payload['items']
        assert row['computer'] == 'PC-2'
        assert row['novelty'] == 'new_pair'
        assert row['prior_user_logon'] == 'yes'
        assert row['source_event_id'] == 2
        assert row['count'] == 1
    else:
        assert not handler.payload['items']
    assert len(calls) == (3 if empty else 7)
    assert handler.payload['coverage']['baseline_covered'] is (not empty)


def test_dispatcher_preserves_publication_integrity_failure(monkeypatch):
    source_boundaries(monkeypatch, corrupt=True)
    handler = read_report()
    assert handler.status == HTTPStatus.OK
    assert handler.payload['state'] == 'error'
    assert not handler.payload['items']
    assert handler.payload['limitations'][0]['code'] == 'history_verification_failed'
    assert 'bad-hash' not in str(handler.payload)


def test_dispatcher_denial_never_reaches_history_transport(monkeypatch):
    calls = source_boundaries(monkeypatch)
    handler = read_report(access(scope={'kind': 'domain', 'ids': [8]}))
    assert handler.status == HTTPStatus.FORBIDDEN
    assert calls == []

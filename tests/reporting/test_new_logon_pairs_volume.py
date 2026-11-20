"""Bounded synthetic cap path; transport is fake, verification/comparison are real."""
import json
import re

from server.sli.plugins.ad.reports import new_logon_pairs_reporting as engine
from tests.reporting.test_new_logon_pairs_v2 import ACCOUNTS, BASELINE, END, INDEX, START, event


def test_both_full_windows_keep_verified_counts_without_extra_transport(monkeypatch):
    calls = []
    selected = []
    windows = iter((range(1, 50001), range(50001, 100001)))
    monkeypatch.setattr(engine.history, 'primary_read_enabled', lambda: True)
    monkeypatch.setattr(engine.history, 'configured_read_port', lambda: 8123)

    def rows(port, sql, **kwargs):
        calls.append(sql)
        if 'GROUP BY server_id' in sql:
            return [{'server_id': 10, 'first_utc': '2026-09-01 00:00:00.000000',
                     'last_utc': '2026-10-07 00:00:00.000000'}]
        if 'SELECT event_db_id FROM' in sql:
            assert kwargs['query_params']['domain'] == '7'
            assert kwargs['query_params']['servers'] == '[10]'
            assert 'time_created_utc<' in sql and 'time_created_utc>=' in sql
            assert 'published_batches' in sql
            return [{'event_db_id': i} for i in next(windows)]
        if 'SELECT event_db_id,time_created_utc' in sql:
            selected[:] = [int(i) for i in re.search(r'event_db_id IN \(([0-9,]+)\)', sql)[1].split(',')]
            result = []
            for i in selected:
                prior = i <= 50000
                core = event(i, computer='PC-1' if prior else 'PC-2', at=BASELINE if prior else START)
                result.append({'event_db_id': i, 'time_created_utc': engine.history._json_ch_time(core['time_created_utc']),
                    'event_key': 4624, 'server_id': 10, 'noise_class': '',
                    'core_json': json.dumps(core), 'facts_json': '{}',
                    'row_sha256': engine.history._payload_sha({'core': core, 'facts': {}}),
                    'batch_sha256': f'{(i - 1) // 1000:064x}'})
            return result
        if 'SELECT batch_sha256,first_event_db_id,last_event_db_id' in sql:
            return [{'batch_sha256': f'{batch:064x}', 'first_event_db_id': batch * 1000 + 1,
                     'last_event_db_id': (batch + 1) * 1000}
                    for batch in sorted({(i - 1) // 1000 for i in selected})]
        raise AssertionError('unexpected transport query')

    monkeypatch.setattr(engine.history, '_rows', rows)
    raw = engine.load_history(7, [10], BASELINE, START, END)
    assert len(raw['baseline']) == 50000 and len(raw['period']) == 50000
    assert not raw['truncated'] and not raw['facts_incomplete']
    compared = engine.compute_pairs(raw['baseline'], raw['period'], baseline_start=BASELINE,
        start=START, end=END, index=INDEX, accounts=ACCOUNTS, baseline_covered=raw['baseline_covered'])
    assert len(compared['items']) == 1
    assert compared['items'][0]['count'] == 50000
    assert compared['items'][0]['novelty'] == 'new_pair'
    # Upper bound guards accidental N+1 growth, not a performance success claim.
    assert len(calls) <= 203
    print(f'T051 synthetic cap: 100000 verified facts, {len(calls)} transport queries; no real ClickHouse timing')

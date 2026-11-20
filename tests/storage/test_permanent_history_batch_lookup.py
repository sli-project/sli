"""The per-read admission index must retain every original publication witness."""
import json
from copy import deepcopy

import pytest

from server.sli.storage import permanent_fact_history as history


def retained(event_id=1, batch='a' * 64):
    core = {'id': event_id, 'time_created_utc': '2026-10-01T00:00:00+00:00',
            'event_id': 4624, 'server_id': 10}
    return {'event_db_id': event_id, 'time_created_utc': '2026-10-01 00:00:00.000000',
            'event_key': 4624, 'server_id': 10, 'noise_class': '',
            'core_json': json.dumps(core), 'facts_json': '{}',
            'row_sha256': history._payload_sha({'core': core, 'facts': {}}), 'batch_sha256': batch}


def publication(batch='a' * 64, first=1, last=1000):
    return {'batch_sha256': batch, 'first_event_db_id': first, 'last_event_db_id': last}


def read(monkeypatch, rows, batches, ids=(1,)):
    responses = iter((rows, batches))
    calls = []
    def transport(port, sql):
        calls.append(sql)
        return next(responses)
    monkeypatch.setattr(history, '_rows', transport)
    result = history.read_published_events_many(8123, list(ids))
    assert len(calls) == 2
    return result


def test_sparse_ids_do_not_rescan_every_unrelated_publication(monkeypatch):
    class CountedBatch(dict):
        lookups = 0
        def __getitem__(self, key):
            if key == 'batch_sha256':
                type(self).lookups += 1
            return super().__getitem__(key)

    # Sparse IDs make the existing min/max catalog query cover many batches.
    ids = [i * 1000 + 1 for i in range(1000)]
    rows = [retained(value, f'{i:064x}') for i, value in enumerate(ids)]
    batches = [CountedBatch(publication(f'{i:064x}', value, value + 999))
               for i, value in enumerate(ids)]
    result = read(monkeypatch, rows, batches, ids)
    assert list(result) == ids
    assert all(row['id'] == key and row['source_payload_state'] == 'expired' for key, row in result.items())
    # A structural bound, not a timing threshold or ClickHouse speed claim.
    assert CountedBatch.lookups <= 3000


@pytest.mark.parametrize('batches,valid', [
    ([publication()], True),
    ([], False),
    ([publication('b' * 64)], False),
    ([publication(first=2)], False),
    ([publication(last=0)], False),
    ([publication(), publication()], False),
    ([publication(), publication(first=1, last=1)], False),
    ([publication(), publication(first=2)], True),
    ([publication(), publication('b' * 64)], True),
    ([publication(), publication('b' * 64, first='not-used', last='not-used')], True),
])
def test_admission_multiplicity_and_range_semantics(monkeypatch, batches, valid):
    original = deepcopy(batches)
    if valid:
        result = read(monkeypatch, [retained()], batches)
        assert result == {1: {
            'id': 1, 'time_created_utc': '2026-10-01T00:00:00+00:00', 'event_id': 4624,
            'server_id': 10, 'retained_facts': {}, '_history_batch_sha256': 'a' * 64,
            'record_xml': None, 'message_text': None, 'event_data_json': None, 'source_payload_state': 'expired',
        }}
    else:
        with pytest.raises(RuntimeError, match='^published_history_event_mismatch$'):
            read(monkeypatch, [retained()], batches)
    assert batches == original


@pytest.mark.parametrize('field,value', [
    ('event_db_id', 2), ('row_sha256', '0' * 64), ('time_created_utc', '2026-10-02 00:00:00.000000'),
    ('event_key', 4625), ('server_id', 11), ('noise_class', 'changed'),
])
def test_payload_and_identity_validation_is_not_bypassed(monkeypatch, field, value):
    row = retained()
    row[field] = value
    with pytest.raises(RuntimeError, match='^published_history_event_mismatch$'):
        read(monkeypatch, [row], [publication()])


def test_duplicate_event_error_keeps_precedence_over_second_payload_error(monkeypatch):
    bad = retained()
    bad['core_json'] = 'invalid JSON'
    with pytest.raises(RuntimeError, match='^published_history_event_duplicate$'):
        read(monkeypatch, [retained(), bad], [publication()])


def test_missing_retained_event_still_fails_closed(monkeypatch):
    with pytest.raises(RuntimeError, match='^published_history_event_batch_incomplete$'):
        read(monkeypatch, [], [publication()])


def test_publication_catalog_is_not_cached_between_calls(monkeypatch):
    assert read(monkeypatch, [retained()], [publication()])[1]['id'] == 1
    with pytest.raises(RuntimeError, match='^published_history_event_mismatch$'):
        read(monkeypatch, [retained()], [publication(), publication()])


def test_catalog_transport_failure_propagates_unchanged(monkeypatch):
    failure = TimeoutError('synthetic cancellation')
    calls = 0
    def transport(port, sql):
        nonlocal calls
        calls += 1
        if calls == 1:
            return [retained()]
        raise failure
    monkeypatch.setattr(history, '_rows', transport)
    with pytest.raises(TimeoutError) as raised:
        history.read_published_events_many(8123, [1])
    assert raised.value is failure and calls == 2

"""Bounded synthetic Accounting empty progress, signing and admission contracts."""
import json
import os
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256

import pytest

from server.sli.agent_ingest import receive_packet
from sli_agent.envelope import canonical, make_packet
from sli_agent.nps import AccountingModule
from sli_collect.radius_tail import derive_file_generation
from tests.unit.test_sli_agent_nps import (
    AGENT,
    HOST,
    NOW,
    accounting_config,
    accounting_line,
    receive,
    signed,
)


def files(tmp_path, contents, *, batch_size=2, last_hash=None):
    paths = []
    for index, content in enumerate(contents):
        path = tmp_path / f'IN{index}.log'
        path.write_bytes(content)
        os.utime(path, ns=(1_000_000_000 + index, 1_000_000_000 + index))
        paths.append(path)
    generation = derive_file_generation(source_instance_id='fixture-radius', file_name=paths[0].name,
                                       file_creation_time_ns=paths[0].stat().st_ctime_ns)
    config = accounting_config(tmp_path, generation=generation) | {'batch_size': batch_size}
    config['initial_cursor']['last_record_sha256'] = last_hash
    return config, AccountingModule(HOST, config), paths


def state(sample):
    return json.loads(sample.cursor_after['token'])


def test_blank_physical_batch_advances_then_collects_accounting_line(tmp_path):
    line = accounting_line()
    config, module, _ = files(tmp_path, [b' \r\n\t\n' + line.encode() + b'\n'], last_hash='a' * 64)
    first = module.collect(now=NOW)
    assert first.payload['records'] == []
    assert state(first)['byte_offset'] == 5
    assert state(first)['last_record_sha256'] == 'a' * 64
    assert first.payload['context']['empty_progress_v1'] == {'skipped_bytes': 5, 'physical_lines': 2}
    context = signed(first, config)
    assert receive(context)['status'] == 'committed'
    assert receive(context)['status'] == 'duplicate'
    second = module.collect(context[3]['envelope'], now=NOW)
    assert second.payload['records'][0]['payload'] == line
    assert state(second)['last_record_sha256'] == sha256(line.encode()).hexdigest()
    ledger, identity, key, _ = context
    value = make_packet(key, agent_id=AGENT, sequence=2, sample=second, now=NOW)
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)['status'] == 'committed'
    assert len(ledger.imports) == 2


def test_initial_empty_and_repeated_empty_generations_reach_data(tmp_path):
    config, module, paths = files(tmp_path, [b'', b'', b' \n', accounting_line().encode() + b'\n'])
    context = None
    for sequence in range(1, 4):
        sample = module.collect(context[3]['envelope'] if context else None, now=NOW)
        assert state(sample)['file_generation'] == derive_file_generation(
            source_instance_id='fixture-radius', file_name=paths[sequence].name,
            file_creation_time_ns=paths[sequence].stat().st_ctime_ns)
        if sequence < 3:
            assert sample.payload['context']['empty_progress_v1']['skipped_bytes'] == (0 if sequence == 1 else 2)
        context = signed(sample, config, sequence=sequence, ledger=context[0] if context else None)
        assert receive(context)['status'] == 'committed'
    assert sample.payload['records']


def test_partial_unterminated_rotated_data_is_not_consumed(tmp_path):
    line = accounting_line().encode()
    config, module, paths = files(tmp_path, [b'', line[:-5]], last_hash='b' * 64)
    first = module.collect(now=NOW)
    assert not first.payload['records']
    assert state(first)['byte_offset'] == 0
    assert state(first)['file_generation'] != config['initial_cursor']['file_generation']
    assert state(first)['last_record_sha256'] == 'b' * 64
    assert receive(signed(first, config))['status'] == 'committed'
    # Appending preserves generation on Windows; Linux ctime is not creation
    # time, so inject the observed immutable generation into inventory here.
    with paths[1].open('ab') as stream:
        stream.write(line[-5:] + b'\n')
    from sli_collect import radius_tail
    original = radius_tail._inventory
    def inventory(directory, source):
        for item in original(directory, source):
            yield replace(item, file_generation=state(first)['file_generation']) if item.path == paths[1] else item
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(radius_tail, '_inventory', inventory)
        second = module.collect({'generation': HOST, 'cursor_after': first.cursor_after}, now=NOW)
    assert second.payload['records'][0]['payload'].encode() == line


def test_large_blank_line_uses_compact_bounded_progress(tmp_path):
    config, module, _ = files(tmp_path, [b' ' * 100_000 + b'\n' + accounting_line().encode() + b'\n'], batch_size=1)
    sample = module.collect(now=NOW)
    assert state(sample)['byte_offset'] == 100_001
    assert len(canonical(sample.payload)) < 4096
    assert receive(signed(sample, config))['status'] == 'committed'


def test_legacy_empty_packet_keeps_unchanged_cursor(tmp_path):
    config, module, _ = files(tmp_path, [b' \n'])
    sample = module.collect(now=NOW)
    payload = deepcopy(sample.payload)
    payload['context'].pop('empty_progress_v1', None)
    legacy = replace(sample, payload=payload, cursor_after={'strategy': 'file_offset',
        'token': canonical(config['initial_cursor']).decode('ascii')})
    assert receive(signed(legacy, config))['status'] == 'committed'


@pytest.mark.parametrize('proof', [None, {}, {'skipped_bytes': True, 'physical_lines': 1},
    {'skipped_bytes': 2, 'physical_lines': True}, {'skipped_bytes': -1, 'physical_lines': 1},
    {'skipped_bytes': 4 * 1024 * 1024 + 1, 'physical_lines': 1},
    {'skipped_bytes': 2, 'physical_lines': 0}, {'skipped_bytes': 2, 'physical_lines': 3},
    {'skipped_bytes': 2, 'physical_lines': -1}, {'skipped_bytes': 3, 'physical_lines': 1},
    {'skipped_bytes': 2, 'physical_lines': 129}, {'skipped_bytes': 2, 'physical_lines': 1, 'extra': 0}])
def test_malformed_empty_progress_is_rejected(tmp_path, proof):
    config, module, _ = files(tmp_path, [b' \n'])
    sample = module.collect(now=NOW)
    payload = deepcopy(sample.payload)
    payload['context']['empty_progress_v1'] = proof
    result = receive(signed(replace(sample, payload=payload), config))
    assert result['status'] == 'rejected'


@pytest.mark.parametrize('field,value', [('last_record_sha256', 'c' * 64),
    ('source_instance_id', 'other-source'), ('stream_id', 'other-stream'),
    ('transport_binding', 'other-binding'), ('file_generation', 'other-generation'), ('byte_offset', 0)])
def test_empty_progress_cannot_change_other_cursor_fields(tmp_path, field, value):
    config, module, _ = files(tmp_path, [b' \n'])
    sample = module.collect(now=NOW)
    after = state(sample) | {field: value}
    sample = replace(sample, cursor_after={'strategy': 'file_offset', 'token': canonical(after).decode('ascii')})
    assert receive(signed(sample, config))['status'] == 'rejected'


def test_admitted_empty_progress_reaches_shared_cursor_and_next_import(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from uuid import uuid4

    from server.sli.sources import nps_agent_import
    from server.sli.sources import radius_plugin_runtime as radius
    from sli_collect.radius_contract import RadiusFileCursor
    from tests.unit.test_nps_agent_import import Cursor, connection

    config, module, _ = files(tmp_path, [b' \n\t\n' + accounting_line().encode() + b'\n'])
    first = module.collect(now=NOW)
    context = signed(first, config)
    assert receive(context)['status'] == 'committed'
    runtime = SimpleNamespace(cursor=RadiusFileCursor(**config['initial_cursor']), revision=1,
                              cursor_epoch=uuid4(), class_cache={})
    plans = []
    imported = set()

    class ImportCursor(Cursor):
        rowcount = 1

        def execute(self, sql, params=()):
            super().execute(sql, params)
            if 'update sli_agent_packet_inbox' in sql:
                imported.add(params[0])
            if 'update acquisition_stream_cursors' in sql:
                assert params[7:] == (runtime.cursor.source_instance_id, runtime.cursor.stream_id,
                    runtime.cursor.transport_binding, runtime.cursor_epoch, runtime.revision,
                    runtime.cursor.file_generation, runtime.cursor.byte_offset, runtime.cursor.last_record_sha256)
                runtime.cursor = replace(runtime.cursor, file_generation=params[0], byte_offset=params[1],
                                         last_record_sha256=params[2])
                runtime.revision += 1

        def fetchall(self):
            if 'select packet_id,envelope,packet,event_rows,received_at' in self.sql:
                if self.value['envelope']['packet_id'] in imported:
                    return []
                return [{'packet_id': self.value['envelope']['packet_id'], 'envelope': self.value['envelope'],
                         'packet': self.value['payload'], 'event_rows': [], 'received_at': NOW}]
            return super().fetchall()

        def fetchone(self):
            if 'select current_role' in self.sql:
                return ('adlog_radius_accounting_worker',)
            if 'for update of c' in self.sql:
                return (runtime.cursor_epoch, runtime.cursor.file_generation, runtime.cursor.byte_offset,
                        runtime.cursor.last_record_sha256, runtime.revision, 'manual_enabled', 'manual_enabled')
            return super().fetchone()

    def commit(_conn, **kwargs):
        plans.append(kwargs['plan'])
        runtime.cursor = kwargs['plan'].next_cursor
        runtime.revision += 1
        return SimpleNamespace(cursor_revision=runtime.revision, evidence_rows=1, observation_rows=1,
                               outbox_rows=1, class_cache_rows=0)

    monkeypatch.setattr(radius, 'load_runtime_state', lambda *_a, **_kw: runtime)
    monkeypatch.setattr(radius, 'commit_radius_batch', commit)
    monkeypatch.setattr(radius, 'publish_radius_batch_evidence', lambda *_a, **_kw: ())
    monkeypatch.setattr(radius, 'AcquisitionEvidenceStore', lambda *_a: object())
    monkeypatch.setattr(radius, '_resolve_acquisition_identity', lambda *_a: None)
    cur = ImportCursor(context)
    from server.sli.sources.collection_packet_import import consume_agent_packets
    assert consume_agent_packets(connection(cur), import_rows=nps_agent_import.import_nps_agent_packet) == 1
    assert consume_agent_packets(connection(cur), import_rows=nps_agent_import.import_nps_agent_packet) == 0
    assert runtime.cursor.byte_offset == 4
    assert runtime.revision == 2
    assert not plans
    writes = [sql for sql, _ in cur.calls if sql.strip().lower().startswith(('update ', 'insert ', 'delete '))]
    assert len(writes) == 2 and 'update acquisition_stream_cursors' in writes[0]
    assert 'update sli_agent_packet_inbox' in writes[1]
    assert ("select set_config('role',%s,true)", ('adlog_nps_agent_import_worker',)) in cur.calls
    second = module.collect(context[3]['envelope'], now=NOW)
    next_context = signed(second, config, sequence=2, ledger=context[0])
    assert receive(next_context)['status'] == 'committed'
    cur = ImportCursor(next_context)
    assert consume_agent_packets(connection(cur), import_rows=nps_agent_import.import_nps_agent_packet) == 1
    assert len(plans) == 1 and len(plans[0].session_observations) == 1
    assert runtime.cursor.byte_offset == state(second)['byte_offset']
    assert runtime.cursor.last_record_sha256 == state(second)['last_record_sha256']


def test_empty_progress_replay_conflict_and_fork_do_not_advance(tmp_path):
    config, module, _ = files(tmp_path, [b' \n\t\n' + accounting_line().encode() + b'\n'])
    first = module.collect(now=NOW)
    context = signed(first, config)
    assert receive(context)['status'] == 'committed'
    ledger, identity, key, value = context
    # A newly signed old before-cursor cannot fork the accepted chain.
    fork = make_packet(key, agent_id=AGENT, sequence=2, sample=first, now=NOW)
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=fork,
                          now=NOW)['error_code'] == 'agent_cursor_mismatch'
    conflict = make_packet(key, agent_id=AGENT, sequence=1, sample=first, now=NOW)
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=conflict,
                          now=NOW)['error_code'] == 'agent_sequence_conflict'
    value['payload']['context']['empty_progress_v1']['skipped_bytes'] += 1
    with pytest.raises(ValueError):
        receive(context)
    assert len(ledger.rows) == 1


@pytest.mark.parametrize('change', ['end', 'start', 'before', 'source', 'generation', 'eof', 'batch'])
def test_empty_progress_packet_geometry_and_assignment_stay_bound(tmp_path, change):
    config, module, _ = files(tmp_path, [b'\n\n'], batch_size=2)
    sample = module.collect(now=NOW)
    packet = deepcopy(sample.payload)
    if change == 'end':
        packet['header']['cursor']['end_offset'] = -1
    elif change == 'start':
        packet['header']['cursor']['start_offset'] = 1
    elif change == 'before':
        packet['header']['cursor']['before']['byte_offset'] = 1
    elif change == 'source':
        packet['header']['source'] = 'another-source'
    elif change == 'generation':
        packet['header']['generation'] = 'another-generation'
    elif change == 'eof':
        packet['continuity']['previous_generation_eof'] = True
    elif change == 'batch':
        config['batch_size'] = 1
    assert receive(signed(replace(sample, payload=packet), config))['status'] == 'rejected'


def test_progress_at_existing_read_bound_and_incomplete_tail_fail_closed(tmp_path):
    from sli_collect.radius_tail import MAXIMUM_READ_BYTES, RadiusTailReadError

    config, module, _ = files(tmp_path, [b' ' * (MAXIMUM_READ_BYTES - 1) + b'\n' +
                                        accounting_line().encode() + b'\n'], batch_size=1)
    first = module.collect(now=NOW)
    assert state(first)['byte_offset'] == MAXIMUM_READ_BYTES
    assert receive(signed(first, config))['status'] == 'committed'
    assert module.collect({'generation': HOST, 'cursor_after': first.cursor_after}, now=NOW).payload['records']
    # Existing overlong unterminated record handling is unchanged.
    other = tmp_path / 'other'
    other.mkdir()
    _, incomplete, _ = files(other, [b' ' * 65_537])
    with pytest.raises(RadiusTailReadError, match='tail_record_too_large'):
        incomplete.collect(now=NOW)


def test_empty_rotation_disables_historical_hash_recovery_until_real_record(tmp_path):
    from sli_collect.radius_tail import RadiusTailReadError

    line = accounting_line().encode()
    config, module, paths = files(tmp_path, [line + b'\n', b' ' * len(line) + b'\n'])
    # Start at an anchored EOF of generation 0. Generation 1 contains only
    # blanks, at exactly the old record boundary: historical-hash recovery
    # could otherwise identify generation 0 as generation 1 after its removal.
    config['initial_cursor']['byte_offset'] = len(line) + 1
    config['initial_cursor']['last_record_sha256'] = sha256(line).hexdigest()
    module = AccountingModule(HOST, config)
    first = module.collect(now=NOW)
    assert state(first)['exact_boundary_recovery'] is False
    assert state(first)['last_record_sha256'] == sha256(line).hexdigest()
    context = signed(first, config)
    assert receive(context)['status'] == 'committed'
    unchanged = module.collect(context[3]['envelope'], now=NOW)
    assert state(unchanged)['exact_boundary_recovery'] is False
    assert receive(signed(unchanged, config, sequence=2, ledger=context[0]))['status'] == 'committed'
    paths[1].unlink()
    with pytest.raises(RadiusTailReadError, match='tail_recovery_unanchored_generation'):
        module.collect({'generation': HOST, 'cursor_after': unchanged.cursor_after}, now=NOW)


def test_real_record_reestablishes_recovery_anchor_after_empty_rotation(tmp_path):
    config, module, _ = files(tmp_path, [b'', b'', accounting_line().encode() + b'\n'])
    first = module.collect(now=NOW)
    assert state(first)['exact_boundary_recovery'] is False
    second = module.collect({'generation': HOST, 'cursor_after': first.cursor_after}, now=NOW)
    assert second.payload['records']
    assert state(second)['exact_boundary_recovery'] is True
    context = signed(first, config)
    assert receive(context)['status'] == 'committed'
    assert receive(signed(second, config, sequence=2, ledger=context[0]))['status'] == 'committed'


@pytest.mark.parametrize('value', [None, 0, 1, 'false', True, 'delete'])
def test_unanchored_recovery_flag_cannot_be_reset_by_empty_packet(tmp_path, value):
    config, module, _ = files(tmp_path, [b'', b''])
    first = module.collect(now=NOW)
    after = state(first)
    assert after['exact_boundary_recovery'] is False
    if value == 'delete':
        after.pop('exact_boundary_recovery')
    else:
        after['exact_boundary_recovery'] = value
    tampered = replace(first, cursor_after={'strategy': 'file_offset', 'token': canonical(after).decode('ascii')})
    assert receive(signed(tampered, config))['status'] == 'rejected'


def test_same_generation_blanks_retain_existing_recovery_anchor(tmp_path):
    line = accounting_line().encode()
    config, module, _ = files(tmp_path, [line + b'\n \n'], last_hash=sha256(line).hexdigest())
    config['initial_cursor']['byte_offset'] = len(line) + 1
    config['initial_cursor']['exact_boundary_recovery'] = True
    module = AccountingModule(HOST, config)
    sample = module.collect(now=NOW)
    assert state(sample)['exact_boundary_recovery'] is True
    assert state(sample)['last_record_sha256'] == sha256(line).hexdigest()
    assert receive(signed(sample, config))['status'] == 'committed'


def test_initial_empty_generation_flag_survives_signed_spool_retry_restart(tmp_path):
    from sli_agent.spool import Spool

    config, module, paths = files(tmp_path, [b''])
    sample = module.collect(now=NOW)
    assert state(sample)['exact_boundary_recovery'] is False
    ledger, identity, key, _ = signed(sample, config)
    spool_root = tmp_path / 'spool'
    def reopen():
        return Spool(spool_root, max_bytes=65536, max_age_seconds=86400)
    spool = reopen()
    packet = spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)
    spool = reopen()
    assert spool.pending(now=NOW) == [packet]
    assert json.loads(spool.captured(sample.module_id)['cursor_after']['token'])['exact_boundary_recovery'] is False
    context = ledger, identity, key, packet
    receipt = receive(context)
    assert receipt['status'] == 'committed'
    duplicate = receive(context)
    assert duplicate['status'] == 'duplicate'
    assert spool.acknowledge(packet, duplicate)
    spool = reopen()
    assert spool.pending(now=NOW) == []
    assert spool.state[sample.module_id]['committed_cursor'] == sample.cursor_after
    assert state(module.collect(spool.captured(sample.module_id), now=NOW))['exact_boundary_recovery'] is False
    paths[0].unlink()
    from sli_collect.radius_tail import RadiusTailReadError
    with pytest.raises(RadiusTailReadError, match='tail_recovery_unanchored_generation'):
        module.collect(spool.captured(sample.module_id), now=NOW)


def test_absent_legacy_recovery_flag_retains_exact_boundary_recovery(tmp_path):
    line = accounting_line().encode()
    config, _, _ = files(tmp_path, [line + b'\n'])
    config['initial_cursor'].update(file_generation='legacy-missing-generation', byte_offset=len(line) + 1,
                                   last_record_sha256=sha256(line).hexdigest())
    sample = AccountingModule(HOST, config).collect(now=NOW)
    assert sample.payload['context']['cursor_generation_recovered'] is True
    assert 'exact_boundary_recovery' not in state(sample)
    assert receive(signed(sample, config))['status'] == 'committed'

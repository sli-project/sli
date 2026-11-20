"""Synthetic local-tail witnesses never authorize arbitrary wire progress."""
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from server.sli.sources import legacy_collection, vpn_source_auth
from server.sli.sources import radius_plugin_runtime as runtime
from server.source_packs.radius.accounting_postgres import (
    RadiusPostgresContractError,
    commit_admitted_empty_radius_progress,
)
from sli_collect.radius import collect_radius_packet
from sli_collect.radius_contract import initial_cursor
from sli_collect.radius_tail import (
    RadiusTailBatch,
    RadiusTailReadError,
    derive_file_generation,
    read_bounded_tail,
)
from tests.sources.test_collection_packets import _radius_fixture


class Database:
    """Transactional cursor SQL model; all other writes fail closed."""
    def __init__(self, cursor):
        self.persisted = cursor
        self.epoch = uuid4()
        self.revision = 7
        self.writes = 0
        self.calls = []
        self.mode = None

    @contextmanager
    def transaction(self):
        snapshot = self.persisted, self.revision, self.writes
        try:
            yield
        except Exception:
            self.persisted, self.revision, self.writes = snapshot
            raise

    def cursor(self):
        return nullcontext(self)

    def execute(self, sql, params=()):
        self.sql = sql
        self.calls.append((sql, params))
        assert not any(word in sql.lower() for word in ('insert into', 'delete from'))
        if 'update acquisition_stream_cursors' in sql:
            current = self.persisted
            assert params[7:] == (current.source_instance_id, current.stream_id,
                current.transport_binding, self.epoch, self.revision,
                current.file_generation, current.byte_offset, current.last_record_sha256)
            self.rowcount = 0 if self.mode == 'cas' else 1
            if self.rowcount:
                self.persisted = replace(current, file_generation=params[0], byte_offset=params[1],
                                         last_record_sha256=params[2])
                self.revision += 1
                self.writes += 1

    def fetchone(self):
        if 'select current_role' in self.sql:
            return ('wrong' if self.mode == 'role' else 'adlog_radius_accounting_worker',)
        assert 'for update of c' in self.sql
        current = self.persisted
        if self.mode == 'missing':
            return None
        if self.mode in ('offset', 'hash', 'generation'):
            current = replace(current, **{'offset': {'byte_offset': 1},
                'hash': {'last_record_sha256': 'a' * 64},
                'generation': {'file_generation': 'changed'}}[self.mode])
        enabled = 'disabled' if self.mode == 'disabled' else 'manual_enabled'
        return (uuid4() if self.mode == 'epoch' else self.epoch, current.file_generation,
                current.byte_offset, current.last_record_sha256,
                self.revision + (self.mode == 'revision'), enabled, enabled)

    def state(self):
        return SimpleNamespace(cursor=self.persisted, cursor_epoch=self.epoch,
                               revision=self.revision, class_cache={}, exact_boundary_recovery=False)


def source(tmp_path, payload=b'\n\r\n \t\npartial'):
    path = tmp_path / 'IN-synthetic.log'
    path.write_bytes(payload)
    generation = derive_file_generation(source_instance_id='fixture-radius', file_name=path.name,
                                       file_creation_time_ns=path.stat().st_ctime_ns)
    cursor = initial_cursor(source_instance_id='fixture-radius', transport_binding='fixture-tail',
                            file_generation=generation)
    return path, Database(cursor)


def configure(monkeypatch, tmp_path, db):
    monkeypatch.setenv('SLI_LEGACY_COLLECTION_DISABLED', '0')
    monkeypatch.setattr(runtime, 'verify_collection_identity', lambda: {'status': 'ok'})
    monkeypatch.setattr(runtime, 'connect_acquisition_worker', lambda: nullcontext(db))
    monkeypatch.setattr(runtime, 'component_lease_scope', lambda *_a, **_kw: nullcontext())
    monkeypatch.setattr(runtime, 'require_accounting_source', lambda: (tmp_path, 'UTC', 0))
    monkeypatch.setattr(runtime, 'acquisition_subscription_id', lambda: 'fixture-subscription')
    monkeypatch.setattr(runtime, 'load_runtime_state', lambda *_a, **_kw: db.state())
    monkeypatch.setattr(vpn_source_auth, 'accounting_source_identity', lambda *_a, **_kw: nullcontext())
    monkeypatch.setattr(vpn_source_auth, 'validate_vpn_source_credential_mode', lambda *_a: 'process')
    monkeypatch.setattr(runtime, 'publish_radius_batch_evidence', lambda *_a, **_kw: pytest.fail('empty evidence'))
    monkeypatch.setattr(runtime, 'AcquisitionEvidenceStore', lambda *_a: pytest.fail('empty store'))


def witnessed(tmp_path, db):
    state = db.state()
    tail = read_bounded_tail(tmp_path, cursor=state.cursor)
    packet = collect_radius_packet(tmp_path, cursor=state.cursor, source_timezone_id='UTC',
        source_utc_offset_minutes=0, read_tail=lambda *_a, **_kw: tail)
    witness = runtime._LocalAcquisitionTail(state.cursor, tail)
    return state, tail, packet, witness


def test_local_blank_progress_advances_once_and_preserves_partial(tmp_path, monkeypatch):
    path, db = source(tmp_path)
    configure(monkeypatch, tmp_path, db)
    reads = []
    def read(*args, **kwargs):
        reads.append(kwargs)
        return read_bounded_tail(*args, **kwargs)
    monkeypatch.setattr(runtime, 'read_bounded_tail', read)
    result = runtime.run_acquisition_cycle()
    assert db.persisted.byte_offset == 6
    assert db.revision == 8 and db.writes == 1
    assert result['cursor_revision_before'] == 7 and result['cursor_revision_after'] == 8
    assert result['status'] == 'committed' and result['records'] == 0
    assert result['partial_trailing_bytes'] == len(b'partial')
    again = runtime.run_acquisition_cycle()
    assert again['status'] == 'no_new_complete_records'
    assert db.writes == 1 and db.revision == 8
    assert len(reads) == 2 and all('maximum_records' not in call for call in reads)
    assert path.read_bytes()[db.persisted.byte_offset:] == b'partial'


def test_generic_wire_progress_keeps_unchanged_compatibility(tmp_path):
    _, db = source(tmp_path)
    tail = read_bounded_tail(tmp_path, cursor=db.persisted)
    packet = collect_radius_packet(tmp_path, cursor=db.persisted, source_timezone_id='UTC',
        source_utc_offset_minutes=0, read_tail=lambda *_a, **_kw: tail)
    result = runtime.import_acquisition_packet(object(), packet, state=db.state())
    assert result['cursor_revision_after'] == 7 and db.writes == 0


@pytest.mark.parametrize('mode', ['epoch', 'revision', 'offset', 'hash', 'generation', 'disabled', 'missing', 'cas', 'role'])
def test_cursor_guards_fail_without_advancing(tmp_path, monkeypatch, mode):
    _, db = source(tmp_path)
    configure(monkeypatch, tmp_path, db)
    db.mode = mode
    with pytest.raises(RadiusPostgresContractError):
        runtime.run_acquisition_cycle()
    assert db.persisted.byte_offset == 0 and db.revision == 7 and db.writes == 0


def test_stale_witness_cannot_advance_twice(tmp_path):
    _, db = source(tmp_path)
    state, _, packet, witness = witnessed(tmp_path, db)
    runtime.import_acquisition_packet(db, packet, state=state, local_tail=witness,
                                       subscription_id='fixture-subscription')
    with pytest.raises(RadiusPostgresContractError, match='stale_batch_cursor'):
        runtime.import_acquisition_packet(db, packet, state=state, local_tail=witness,
                                           subscription_id='fixture-subscription')
    assert db.writes == 1 and db.revision == 8


@pytest.mark.parametrize('target', ['source', 'channel', 'before', 'start', 'end', 'start_bool',
    'generation', 'eof', 'status', 'stats', 'stats_bool', 'proof'])
def test_mismatched_wire_packet_never_uses_witness(tmp_path, target):
    _, db = source(tmp_path)
    state, _, packet, witness = witnessed(tmp_path, db)
    header = packet['header']
    if target in ('source', 'channel', 'generation'):
        header[target] = 'different'
    elif target == 'before':
        header['cursor']['before']['transport_binding'] = 'different'
    elif target in ('start', 'end'):
        header['cursor'][target + '_offset'] += 1
    elif target == 'start_bool':
        header['cursor']['start_offset'] = False
    elif target == 'eof':
        packet['continuity']['previous_generation_eof'] = True
    elif target == 'status':
        packet['continuity']['status'] = 'not_proven'
    elif target == 'stats':
        packet['context']['bytes_read'] += 1
    elif target == 'stats_bool':
        packet['context']['candidate_count'] = True
    elif target == 'proof':
        packet['context']['empty_progress_v1']['physical_lines'] += 1
    with pytest.raises(ValueError):
        runtime.import_acquisition_packet(db, packet, state=state, local_tail=witness,
                                           subscription_id='fixture-subscription')
    assert db.writes == 0 and not db.calls


@pytest.mark.parametrize('change', [None, 'wrong_type', 'cursor', 'cursor_bool', 'batch_type',
    'records', 'offset', 'eof', 'count_bool', 'bytes', 'partial', 'lines'])
def test_malformed_local_witness_fails_before_sql(tmp_path, change):
    _, db = source(tmp_path)
    state, tail, packet, witness = witnessed(tmp_path, db)
    if change == 'wrong_type':
        witness = object()
    elif change == 'cursor':
        witness = replace(witness, cursor=replace(state.cursor, transport_binding='different'))
    elif change == 'cursor_bool':
        witness = replace(witness, cursor=replace(state.cursor, byte_offset=False))
    elif change == 'batch_type':
        witness = replace(witness, batch=None)
    else:
        changes = {None: {'end_offset': True}, 'records': {'records': ('record',)},
            'offset': {'start_offset': 1}, 'eof': {'previous_generation_eof': True},
            'count_bool': {'physical_lines': True}, 'bytes': {'bytes_read': 0},
            'partial': {'partial_trailing_bytes': -1}, 'lines': {'physical_lines': 1001}}
        witness = replace(witness, batch=replace(tail, **changes[change]))
    with pytest.raises(ValueError):
        runtime.import_acquisition_packet(db, packet, state=state, local_tail=witness,
                                           subscription_id='fixture-subscription')
    assert db.writes == 0 and not db.calls


@pytest.mark.parametrize('failure', ['identity', 'legacy', 'read', 'source_scope'])
def test_admission_and_read_failures_precede_commit(tmp_path, monkeypatch, failure):
    _, db = source(tmp_path)
    configure(monkeypatch, tmp_path, db)
    if failure == 'identity':
        monkeypatch.setattr(runtime, 'verify_collection_identity', lambda: {'status': 'failed'})
    elif failure == 'legacy':
        monkeypatch.setenv('SLI_LEGACY_COLLECTION_DISABLED', '1')
    elif failure == 'read':
        monkeypatch.setattr(runtime, 'read_bounded_tail', lambda *_a, **_kw: (_ for _ in ()).throw(RadiusTailReadError('synthetic_read_failed')))
    else:
        @contextmanager
        def scope(*_a, **_kw):
            yield
            raise OSError('synthetic_identity_scope_failure')
        monkeypatch.setattr(vpn_source_auth, 'accounting_source_identity', scope)
    with pytest.raises((PermissionError, legacy_collection.LegacyCollectionDisabled, RadiusTailReadError, OSError)):
        runtime.run_acquisition_cycle()
    assert db.writes == 0 and not db.calls


def test_outer_failure_rolls_back_empty_cursor(tmp_path, monkeypatch):
    _, db = source(tmp_path)
    configure(monkeypatch, tmp_path, db)
    with pytest.raises(RuntimeError, match='synthetic outer failure'), db.transaction():
        runtime.run_acquisition_cycle()
        assert db.writes == 1
        raise RuntimeError('synthetic outer failure')
    assert db.persisted.byte_offset == 0 and db.revision == 7 and db.writes == 0


def test_blank_bound_does_not_skip_the_next_valid_record(tmp_path, monkeypatch):
    line = _radius_fixture()[1].records[0]
    _, db = source(tmp_path, b'\n' * 1001 + line.encode() + b'\npartial')
    configure(monkeypatch, tmp_path, db)
    runtime.run_acquisition_cycle()
    assert db.persisted.byte_offset == 1000
    captured = []
    monkeypatch.setattr(runtime, 'AcquisitionEvidenceStore', lambda *_a: object())
    monkeypatch.setattr(runtime, 'publish_radius_batch_evidence', lambda *_a, **kw: captured.append(kw) or ())
    def commit(_conn, **kw):
        plan = kw['plan']
        assert plan.current_cursor == db.persisted
        assert len(plan.evidence_sha256) == 1
        db.persisted = plan.next_cursor
        db.revision += 1
        return SimpleNamespace(cursor_revision=db.revision, evidence_rows=1,
            observation_rows=len(plan.session_observations), outbox_rows=len(plan.session_observations), class_cache_rows=0)
    monkeypatch.setattr(runtime, 'commit_radius_batch', commit)
    result = runtime.run_acquisition_cycle()
    assert result['records'] == 1 and captured[0]['canonical_records'] == (line,)
    assert db.persisted.byte_offset == 1002 + len(line.encode())
    assert read_bounded_tail(tmp_path, cursor=db.persisted).partial_trailing_bytes == len(b'partial')


@pytest.mark.parametrize('limit', [True, False, 0, -1, 1001, '1000', None, 128.0])
def test_shared_helper_rejects_invalid_caller_bound_before_sql(tmp_path, limit):
    _, db = source(tmp_path)
    with pytest.raises(RadiusPostgresContractError, match='empty_progress_invalid'):
        commit_admitted_empty_radius_progress(db, subscription_id='fixture-subscription',
            cursor_epoch=db.epoch, expected_revision=7, current_cursor=db.persisted,
            next_cursor=replace(db.persisted, byte_offset=2), skipped_bytes=2, physical_lines=1,
            maximum_physical_lines=limit)
    assert not db.calls and not db.writes


def test_shared_helper_default_still_rejects_129_lines(tmp_path):
    _, db = source(tmp_path)
    with pytest.raises(RadiusPostgresContractError, match='empty_progress_invalid'):
        commit_admitted_empty_radius_progress(db, subscription_id='fixture-subscription',
            cursor_epoch=db.epoch, expected_revision=7, current_cursor=db.persisted,
            next_cursor=replace(db.persisted, byte_offset=129), skipped_bytes=129, physical_lines=129)
    assert not db.calls and not db.writes


@pytest.mark.parametrize('skipped,lines', [(0, 0), (2, 2)])
def test_local_empty_rotation_keeps_hash_and_commits_only_once(tmp_path, skipped, lines):
    _, db = source(tmp_path)
    db.persisted = replace(db.persisted, byte_offset=10, last_record_sha256='b' * 64)
    state = db.state()
    tail = RadiusTailBatch('next-generation', 0, skipped, True, (), 2, skipped, 0,
                           physical_lines=lines)
    packet = collect_radius_packet(tmp_path, cursor=state.cursor, source_timezone_id='UTC',
        source_utc_offset_minutes=0, read_tail=lambda *_a, **_kw: tail)
    witness = runtime._LocalAcquisitionTail(state.cursor, tail)
    result = runtime.import_acquisition_packet(db, packet, state=state, local_tail=witness,
                                              subscription_id='fixture-subscription')
    assert result['cursor_revision_after'] == 8 and db.writes == 1
    assert db.persisted.file_generation == 'next-generation'
    assert db.persisted.byte_offset == skipped and db.persisted.last_record_sha256 == 'b' * 64
    with pytest.raises(RadiusPostgresContractError, match='stale_batch_cursor'):
        runtime.import_acquisition_packet(db, packet, state=state, local_tail=witness,
                                           subscription_id='fixture-subscription')
    assert db.writes == 1


@pytest.mark.parametrize('payload', [b'', b'partial'])
def test_local_unchanged_empty_or_partial_read_never_writes(tmp_path, monkeypatch, payload):
    _, db = source(tmp_path, payload)
    configure(monkeypatch, tmp_path, db)
    result = runtime.run_acquisition_cycle()
    assert result['status'] == 'no_new_complete_records'
    assert result['cursor_revision_after'] == 7 and db.writes == 0 and not db.calls


def test_nonempty_legacy_batch_keeps_existing_thousand_record_capacity(tmp_path, monkeypatch):
    line = _radius_fixture()[1].records[0]
    _, db = source(tmp_path, (line.encode() + b'\n') * 1001)
    configure(monkeypatch, tmp_path, db)
    monkeypatch.setattr(runtime, '_require_local_tail_packet',
                        lambda *_a, **_kw: pytest.fail('nonempty import must not rebuild the packet'))
    monkeypatch.setattr(runtime, 'AcquisitionEvidenceStore', lambda *_a: object())
    captured = []
    monkeypatch.setattr(runtime, 'publish_radius_batch_evidence', lambda *_a, **kw: captured.append(kw) or ())
    def commit(_conn, **kw):
        assert kw['plan'].counters['records'] == 1000
        return SimpleNamespace(cursor_revision=8, evidence_rows=1000,
            observation_rows=1000, outbox_rows=1000, class_cache_rows=0)
    monkeypatch.setattr(runtime, 'commit_radius_batch', commit)
    result = runtime.run_acquisition_cycle()
    assert result['records'] == 1000 and captured[0]['canonical_records'] == (line,) * 1000


def test_bad_complete_record_after_blanks_cannot_advance(tmp_path, monkeypatch):
    _, db = source(tmp_path, b'\ninvalid-accounting\n')
    configure(monkeypatch, tmp_path, db)
    with pytest.raises(ValueError):
        runtime.run_acquisition_cycle()
    assert db.persisted.byte_offset == 0 and db.writes == 0


def test_collector_rejection_before_callback_does_not_read(tmp_path, monkeypatch):
    _, db = source(tmp_path)
    configure(monkeypatch, tmp_path, db)
    monkeypatch.setattr(runtime, 'read_bounded_tail', lambda *_a, **_kw: pytest.fail('unexpected pre-read'))
    def reject(*_a, **_kw):
        raise ValueError('synthetic_collector_rejected')
    monkeypatch.setattr(runtime, 'collect_radius_packet', reject)
    with pytest.raises(ValueError, match='synthetic_collector_rejected'):
        runtime.run_acquisition_cycle()
    assert db.writes == 0 and not db.calls


def test_collector_callback_forwards_actual_read_arguments(tmp_path, monkeypatch):
    _, db = source(tmp_path)
    configure(monkeypatch, tmp_path, db)
    calls = []
    different_cursor = replace(db.persisted, transport_binding='other-fixture-tail')
    directory = tmp_path / 'synthetic-other-directory'
    tail = RadiusTailBatch(db.persisted.file_generation, 0, 0, False, (), 1, 0, 0)
    def read(*args, **kwargs):
        calls.append((args, kwargs))
        return tail
    def collect(_directory, *, read_tail, **_kwargs):
        assert read_tail(directory, cursor=different_cursor, allow_exact_boundary_recovery=True,
                         maximum_records=17) is tail
        raise ValueError('synthetic_after_callback')
    monkeypatch.setattr(runtime, 'read_bounded_tail', read)
    monkeypatch.setattr(runtime, 'collect_radius_packet', collect)
    with pytest.raises(ValueError, match='synthetic_after_callback'):
        runtime.run_acquisition_cycle()
    assert calls == [((directory,), {'cursor': different_cursor,
        'allow_exact_boundary_recovery': True, 'maximum_records': 17})]
    assert not db.calls


def test_source_free_collector_without_callback_gets_no_progress_authority(tmp_path, monkeypatch):
    _, db = source(tmp_path)
    _, _, packet, _ = witnessed(tmp_path, db)
    configure(monkeypatch, tmp_path, db)
    monkeypatch.setattr(runtime, 'read_bounded_tail', lambda *_a, **_kw: pytest.fail('source-free collector read'))
    monkeypatch.setattr(runtime, 'collect_radius_packet', lambda *_a, **_kw: packet)
    result = runtime.run_acquisition_cycle()
    assert result['status'] == 'no_new_complete_records' and result['cursor_revision_after'] == 7
    assert db.persisted.byte_offset == 0 and db.writes == 0 and not db.calls

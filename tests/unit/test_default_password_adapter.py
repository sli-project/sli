"""B5 default adapter contract tests at the public producer boundary.

Exercise public run_default_detections and spy only the existing public producer
boundary. Canonical factory and v1 disabled-account evaluator remain real.
Transaction/storage fakes below establish unit orchestration, not PG authority.
"""
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest

from server.sli.semantic import default_detections as defaults
from server.sli.semantic import password_attack_policy as factory
from server.sli.semantic import password_attack_producer as producer
from server.sli.semantic import password_attacks as legacy
from server.sli.storage.evidence_ref import EvidenceScope

SCOPE = EvidenceScope('00000000-0000-4000-8000-000000000091', 'sli.windows.ad-dc',
                      'SOURCE_PRIVATE', 'GENERATION_PRIVATE')
PASSWORD_IDS = {'qw.password-brute-force', 'qw.password-spray'}
COVERAGE_KEYS = frozenset({'healthy', 'partial', 'error', 'unknown', 'stale', 'disabled', 'failed'})
WORK_KEYS = frozenset({'native_items', 'xml_bytes', 'retained_queries', 'reservation_occurrences',
                       'window_queries', 'reservation_calls', 'tracking_calls', 'completion_calls'})
PRIVATE = ('SOURCE_PRIVATE', 'GENERATION_PRIVATE', 'ACCOUNT_PRIVATE', 'XML_PRIVATE', 'EXCEPTION_PRIVATE')


def _outcome(*, jobs=2, status='healthy', work=None):
    values = {key: 0 for key in WORK_KEYS}
    values.update(work if work is not None else {
        'native_items': 3, 'xml_bytes': 19, 'window_queries': 1,
        'reservation_calls': 1, 'reservation_occurrences': 2, 'completion_calls': 1,
    })
    return producer.ProducerOutcome(jobs=jobs, failed=False, status='committed', revision=1,
        health={'status': status, 'reason': None}, work=values)


def _disabled():
    return producer.ProducerOutcome(jobs=0, failed=False, status='disabled', revision=None, health={})


def _legacy_rows():
    # Real v1 evaluator sees qualifying brute/spray AND one disabled account.
    # The adapter must admit/emit only disabled-account from this old path.
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    accounts = ['ACCOUNT_PRIVATE'] * 10 + ['fixture-' + str(i) for i in range(5)] + ['disabled-fixture']
    return [{'source_event_id': i + 1, 'event_id': 4625,
             'occurred_at_utc': now + timedelta(microseconds=i), 'sha256': f'{i + 1:064x}',
             'event_data': {'TargetUserName': account, 'TargetDomainName': 'fixture',
                            'IpAddress': '203.0.113.7', 'Status': '0xc0000072' if i == 15 else '0xc000006a'}}
            for i, account in enumerate(accounts)]


class Connection:
    """Known-IDLE/outer COMMIT fake; legacy staged writes really roll back."""
    def __init__(self, sources, *, legacy_enabled=True, legacy_commit_failure=False):
        self.sources = [{'scope': asdict(scope)} for scope in sources]
        self.legacy_enabled = legacy_enabled
        self.legacy_commit_failure = legacy_commit_failure
        self.info = SimpleNamespace(transaction_status=defaults.TransactionStatus.IDLE)
        self.closed = False
        self.depth = 0
        self.connection = self
        self.stage = None
        self.rows = []
        self.queries = []
        self.admissions = []
        self.emitted = []
        self.staged = []
        self.durable = []
        self.managed_durable_jobs = 0
        self.legacy_exits = 0

    @contextmanager
    def transaction(self):
        assert self.depth == 0 and self.info.transaction_status == defaults.TransactionStatus.IDLE
        before = list(self.staged)
        self.depth = 1
        self.info.transaction_status = defaults.TransactionStatus.INTRANS
        self.stage = None
        try:
            yield
            if self.stage == 'legacy' and self.legacy_commit_failure:
                raise RuntimeError('EXCEPTION_PRIVATE legacy COMMIT failed')
        except Exception:
            self.staged[:] = before
            raise
        else:
            self.durable.extend(self.staged[len(before):])
            self.staged[:] = before
        finally:
            self.legacy_exits += int(self.stage == 'legacy')
            self.depth = 0
            if not self.closed and self.info.transaction_status != defaults.TransactionStatus.UNKNOWN:
                self.info.transaction_status = defaults.TransactionStatus.IDLE

    @contextmanager
    def cursor(self):
        yield self

    def execute(self, statement, params=()):
        self.queries.append(statement)
        if 'default_detection_sources()' in statement:
            self.stage = 'discovery'
            self.rows = [{'source': source} for source in self.sources]
        elif 'read_default_file_acl_resources' in statement:
            self.stage = 'acl_discovery'
            self.rows = [{'page': {'items': [], 'has_more': False, 'next_key': None}}]
        elif 'ensure_default_qw_policy(' in statement:
            self.stage = 'legacy'
            document = json.loads(params[2])
            execution = document['source_selector']['execution']
            self.admissions.append(execution)
            self.rows = [{'enabled': self.legacy_enabled and execution['rule_id'] in legacy.RULES}]
        elif 'pg_advisory_xact_lock' in statement:
            self.stage = 'legacy'
            self.rows = []
        else:
            self.rows = []

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


def _wire(monkeypatch, conn, outcomes=None, *, fault=None):
    calls, logs = [], []
    original = producer.run_password_producer

    def managed(connection, *, rule, managed_policy=None):
        calls.append((rule, managed_policy))
        assert connection is conn and conn.depth == 0 and not conn.closed
        assert conn.info.transaction_status == defaults.TransactionStatus.IDLE
        assert conn.legacy_exits >= 1, 'legacy source must leave its outer transaction before v2'
        expected = factory.risk_policy(rule)
        assert managed_policy is not None
        assert managed_policy.policy_id == expected.policy_id and managed_policy.policy_version == 1
        assert managed_policy.definition_json == expected.definition_json
        assert managed_policy.definition_sha256 == expected.definition_sha256
        if fault:
            return fault(connection)
        value = (outcomes or {}).get(rule.kind, _outcome())
        if value.status == 'committed' and not value.failed:
            conn.managed_durable_jobs += value.jobs
        return value

    # Patch the PUBLIC boundary for either normal import style, without naming
    # or requiring any future private adapter helper in product code.
    for name, value in list(vars(defaults).items()):
        if value is original:
            monkeypatch.setattr(defaults, name, managed)
    monkeypatch.setattr(producer, 'run_password_producer', managed)
    monkeypatch.setattr(defaults, 'read_password_events', lambda *args: _legacy_rows())
    monkeypatch.setattr(defaults, 'plugin_hook', lambda *args: None)
    monkeypatch.setattr(defaults, 'log_event', lambda *args, **kwargs: logs.append((args, kwargs)))

    def enqueue(cur, *, signal):
        assert cur.connection is conn and conn.depth == 1
        conn.emitted.append(signal)
        conn.staged.append(signal.signal_id)
        return [signal.signal_id]

    monkeypatch.setattr(defaults, 'enqueue_qw_signal_risk_jobs', enqueue)
    return calls, logs


def _safe(result, logs):
    assert set(result) == {'sources', 'jobs', 'failed', 'coverage_counts', 'password_work_counts'}
    for key in ('sources', 'jobs', 'failed'):
        assert type(result[key]) is int and result[key] >= 0
    assert isinstance(result['coverage_counts'], dict) and set(result['coverage_counts']) <= COVERAGE_KEYS
    assert isinstance(result['password_work_counts'], dict) and set(result['password_work_counts']) <= WORK_KEYS
    for counts in (result['coverage_counts'], result['password_work_counts']):
        assert all(type(value) is int and value >= 0 for value in counts.values())
    encoded = json.dumps([result, logs], default=str)
    assert all(marker not in encoded for marker in PRIVATE)


def test_two_canonical_managed_rules_use_same_idle_connection_and_source_count_once(monkeypatch):
    conn = Connection([SCOPE])
    calls, logs = _wire(monkeypatch, conn)
    result = defaults.run_default_detections(conn)
    assert len(calls) == 2 and {rule.kind for rule, _ in calls} == {'brute', 'spray'}
    assert all(asdict(rule.scope) == asdict(SCOPE) for rule, _ in calls)
    assert result['sources'] == 1 and result['jobs'] == len(conn.durable) + conn.managed_durable_jobs
    assert result['failed'] == 0 and result['coverage_counts'].get('healthy', 0) == 2
    _safe(result, logs)


def test_legacy_ad_brute_spray_are_never_admitted_or_emitted_but_disabled_v1_survives(monkeypatch):
    conn = Connection([SCOPE])
    calls, logs = _wire(monkeypatch, conn)
    result = defaults.run_default_detections(conn)
    assert len(calls) == 2
    assert not any(pin['rule_id'] in PASSWORD_IDS for pin in conn.admissions)
    admitted = [pin for pin in conn.admissions if pin['rule_id'] == 'qw.disabled-account-logon']
    assert len(admitted) == 1 and admitted[0]['rule_version'] == 1 and admitted[0]['scope'] == asdict(SCOPE)
    disabled, = conn.emitted
    assert disabled.rule_id == 'qw.disabled-account-logon' and disabled.rule_version == 1
    assert len(disabled.evidence_refs) == 1 and len(conn.durable) == 1
    _safe(result, logs)


def test_full_c_and_each_discovered_source_survive_two_rule_dispatch(monkeypatch):
    other = replace(SCOPE, source_generation='GENERATION_PRIVATE-other')
    conn = Connection([SCOPE, other], legacy_enabled=False)
    calls, logs = _wire(monkeypatch, conn)
    result = defaults.run_default_detections(conn)
    assert {(rule.scope, rule.kind) for rule, _ in calls} == {
        (scope, kind) for scope in (SCOPE, other) for kind in ('brute', 'spray')}
    assert len(calls) == 4 and result['sources'] == 2
    _safe(result, logs)


def test_confirmed_disabled_rules_never_become_healthy_or_failed_attempts(monkeypatch):
    conn = Connection([SCOPE], legacy_enabled=False)
    calls, logs = _wire(monkeypatch, conn, {'brute': _disabled(), 'spray': _disabled()})
    result = defaults.run_default_detections(conn)
    assert len(calls) == 2 and result['sources'] == 1 and result['jobs'] == result['failed'] == 0
    assert result['coverage_counts'].get('disabled', 0) == 2
    assert result['coverage_counts'].get('healthy', 0) == 0
    assert not any(result['password_work_counts'].values())
    _safe(result, logs)


@pytest.mark.parametrize('observed', [False, True])
def test_failed_attempt_is_counted_once_even_when_same_token_failure_observation_fails(monkeypatch, observed):
    conn = Connection([SCOPE], legacy_enabled=False)
    failed = producer.ProducerOutcome(failure_observed=observed)
    calls, logs = _wire(monkeypatch, conn, {'brute': failed, 'spray': _disabled()})
    result = defaults.run_default_detections(conn)
    assert len(calls) == 2 and result['jobs'] == 0 and result['failed'] == 1
    assert result['coverage_counts'].get('failed', 0) == 1
    assert result['coverage_counts'].get('healthy', 0) == 0
    _safe(result, logs)


def test_legacy_commit_failure_cannot_count_staged_jobs_or_nest_managed_producer(monkeypatch):
    conn = Connection([SCOPE], legacy_commit_failure=True)
    calls, logs = _wire(monkeypatch, conn)
    result = defaults.run_default_detections(conn)
    assert len(calls) == 2 and conn.legacy_exits == 1
    assert not conn.durable and not conn.staged and conn.managed_durable_jobs == 4
    assert result['jobs'] == 4 and result['failed'] == 1
    _safe(result, logs)


def test_healthy_partial_and_work_counters_aggregate_only_fixed_numeric_fields(monkeypatch):
    conn = Connection([SCOPE], legacy_enabled=False)
    good = _outcome(jobs=0, work={'native_items': 4, 'xml_bytes': 12, 'window_queries': 1})
    partial = _outcome(jobs=0, status='partial', work={'native_items': 3, 'xml_bytes': 9, 'tracking_calls': 1})
    _, logs = _wire(monkeypatch, conn, {'brute': good, 'spray': partial})
    result = defaults.run_default_detections(conn)
    assert result['coverage_counts'].get('healthy', 0) == result['coverage_counts'].get('partial', 0) == 1
    assert result['password_work_counts'].get('native_items') == 7
    assert result['password_work_counts'].get('xml_bytes') == 21
    assert result['password_work_counts'].get('window_queries') == result['password_work_counts'].get('tracking_calls') == 1
    _safe(result, logs)


def test_unknown_health_reason_extra_identity_xml_and_work_keys_never_reach_telemetry(monkeypatch):
    conn = Connection([SCOPE], legacy_enabled=False)
    noisy = replace(_outcome(jobs=0), health={'status': 'healthy', 'reason': 'ACCOUNT_PRIVATE',
        'scope': asdict(SCOPE), 'source_xml': '<XML_PRIVATE/>'},
        work={'native_items': 2, 'ACCOUNT_PRIVATE': 99, 'source_xml': '<XML_PRIVATE/>'})
    _, logs = _wire(monkeypatch, conn, {'brute': noisy, 'spray': _disabled()})
    result = defaults.run_default_detections(conn)
    assert result['password_work_counts'].get('native_items') == 2
    _safe(result, logs)


@pytest.mark.parametrize('bad', [True, -1, 1.5, '2', None])
def test_work_counters_do_not_coerce_bool_negative_float_string_or_null(monkeypatch, bad):
    conn = Connection([SCOPE], legacy_enabled=False)
    malformed = _outcome(jobs=0, status='partial', work={'native_items': bad})
    _, logs = _wire(monkeypatch, conn, {'brute': malformed, 'spray': _disabled()})
    result = defaults.run_default_detections(conn)
    assert result['password_work_counts'].get('native_items', 0) == 0
    _safe(result, logs)


@pytest.mark.parametrize('outside', ['ACCOUNT_PRIVATE', None, True, {'private': 'XML_PRIVATE'}])
def test_outside_health_status_is_unknown_without_projecting_the_raw_status(monkeypatch, outside):
    conn = Connection([SCOPE], legacy_enabled=False)
    unknown = replace(_outcome(jobs=0), health={'status': outside, 'reason': 'ACCOUNT_PRIVATE'})
    _, logs = _wire(monkeypatch, conn, {'brute': unknown, 'spray': _disabled()})
    result = defaults.run_default_detections(conn)
    assert result['coverage_counts'].get('unknown', 0) == 1
    assert result['coverage_counts'].get('healthy', 0) == 0
    _safe(result, logs)


def test_non_ad_source_does_not_become_two_password_attempts(monkeypatch):
    nps = replace(SCOPE, plugin_id='sli.vpn-nps')
    conn = Connection([nps], legacy_enabled=False)
    calls, logs = _wire(monkeypatch, conn)
    result = defaults.run_default_detections(conn)
    assert not calls and result['sources'] == 1 and result['jobs'] == result['failed'] == 0
    assert not any(result['coverage_counts'].values()) and not any(result['password_work_counts'].values())
    _safe(result, logs)


@pytest.mark.parametrize('dirty', ['busy', 'unknown', 'closed'])
def test_dirty_entry_is_fatal_before_any_sql_or_managed_attempt(monkeypatch, dirty):
    conn = Connection([SCOPE])
    calls, _ = _wire(monkeypatch, conn)
    if dirty == 'closed':
        conn.closed = True
    else:
        conn.info.transaction_status = defaults.TransactionStatus.INTRANS if dirty == 'busy' else defaults.TransactionStatus.UNKNOWN
    with pytest.raises(producer.ProducerConnectionFatal):
        defaults.run_default_detections(conn)
    assert not conn.queries and not calls


@pytest.mark.parametrize('broken', ['unknown', 'closed', 'fatal'])
def test_fatal_or_ordinary_driver_error_on_uncertain_connection_stops_next_rule_and_acl(monkeypatch, broken):
    conn = Connection([SCOPE], legacy_enabled=False)
    def fault(connection):
        if broken == 'fatal':
            raise producer.ProducerConnectionFatal('password_v2_connection_not_idle')
        if broken == 'closed':
            connection.closed = True
        else:
            connection.info.transaction_status = defaults.TransactionStatus.UNKNOWN
        raise RuntimeError('EXCEPTION_PRIVATE driver failure')
    calls, _ = _wire(monkeypatch, conn, fault=fault)
    with pytest.raises(producer.ProducerConnectionFatal):
        defaults.run_default_detections(conn)
    assert len(calls) == 1
    assert not any('read_default_file_acl_resources' in sql for sql in conn.queries)
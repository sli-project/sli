"""Managed TxB/owned-connection wire only; no default-v2 or PG acceptance claim."""
from contextlib import contextmanager
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from server.sli.semantic import default_detections as defaults
from server.sli.semantic import password_attack_policy as policy_factory
from server.sli.semantic import password_attack_producer as producer
from server.sli.semantic import password_attack_v2 as pure
from server.sli.semantic import semantic_production_runtime as runtime
from tests.unit.test_password_attack_producer import Connection, wiring
from tests.unit.test_password_attack_v2_portions import BASE, SCOPE


class ManagedConnection(Connection):
    def __init__(self, decision=True, *, commit_error=None, broken_after=None, closed_after=None):
        super().__init__(commit_error)
        self.decision = decision
        self.queries = []
        self.broken_after = broken_after
        self.closed_after = closed_after
        self.closed = False

    @contextmanager
    def transaction(self):
        index = len(self.transactions)+1
        try:
            with super().transaction():
                yield
        finally:
            if index == self.broken_after:
                self.info.transaction_status = 4
            if index == self.closed_after:
                self.closed = True

    def execute(self, statement, params=None):
        assert len(self.transactions) == 2 and self.transactions[-1][1] == 'open'
        assert 'public.ensure_default_qw_policy(' in statement
        self.queries.append((len(self.transactions),statement,params))
        if isinstance(self.decision, Exception):
            raise self.decision

    def fetchone(self):
        return {'enabled': self.decision}


def rule():
    return pure.Rule(SCOPE,'brute')


def managed_run(conn):
    return producer.run_password_producer(conn,rule=rule(),managed_policy=policy_factory.risk_policy(rule()))


def test_managed_true_ensure_is_first_txb_statement_and_jobs_wait_for_commit(monkeypatch):
    conn = ManagedConnection()
    calls = wiring(monkeypatch,conn)
    batch = producer._batch
    def checked_batch(cur, selected, attempt):
        assert len(conn.queries) == 1
        assert conn.queries[0][2] == (policy_factory.risk_policy(selected).policy_id,1,
                                     policy_factory.risk_policy(selected).definition_json)
        assert conn.transactions == [[1,'commit'],[2,'open']]
        return batch(cur,selected,attempt)
    monkeypatch.setattr(producer,'_batch',checked_batch)
    result = managed_run(conn)
    assert result.jobs == 5 and not result.failed and result.status == 'committed'
    assert conn.transactions == [[1,'commit'],[2,'commit']]
    assert [call[1] for call in calls] == ['begin_password_attempt','batch']


def test_confirmed_false_commits_only_decision_without_batch_health_or_txc(monkeypatch):
    conn = ManagedConnection(False)
    calls = wiring(monkeypatch,conn)
    result = managed_run(conn)
    assert result == producer.ProducerOutcome(jobs=0,failed=False,status='disabled',revision=None,health={})
    assert result.work == {} and not result.failure_observed
    assert conn.transactions == [[1,'commit'],[2,'commit']]
    assert [call[1] for call in calls] == ['begin_password_attempt']
    assert len(conn.queries) == 1


@pytest.mark.parametrize('decision',[None,0,1,'false',{},RuntimeError('private provenance detail')])
def test_unconfirmed_or_authority_error_uses_same_token_failure_txc(monkeypatch,decision):
    conn = ManagedConnection(decision)
    calls = wiring(monkeypatch,conn)
    result = managed_run(conn)
    assert result.failed and result.jobs == 0 and result.failure_observed and result.health == {}
    assert conn.transactions == [[1,'commit'],[2,'rollback'],[3,'commit']]
    assert calls[-1][1] == 'observe_password_failure_v2' and calls[-1][2][2] == 7
    assert 'batch' not in [call[1] for call in calls]
    assert 'private' not in repr(result) and 'private' not in repr(calls[-1])


@pytest.mark.parametrize('decision',[True,False])
def test_decision_or_batch_commit_failure_never_counts_jobs_or_disabled(monkeypatch,decision):
    conn = ManagedConnection(decision,commit_error=2)
    calls = wiring(monkeypatch,conn)
    result = managed_run(conn)
    assert result.failed and result.jobs == 0 and result.status == 'failed' and result.failure_observed
    assert conn.transactions == [[1,'commit'],[2,'rollback'],[3,'commit']]
    assert calls[-1][2][2] == 7


@pytest.mark.parametrize('wrong',['other_rule','other_scope','id','version','definition'])
def test_managed_policy_must_be_canonical_for_this_exact_rule_before_ensure(monkeypatch,wrong):
    conn = ManagedConnection()
    calls = wiring(monkeypatch,conn)
    policy = policy_factory.risk_policy(rule())
    if wrong == 'other_rule':
        policy = policy_factory.risk_policy(pure.Rule(SCOPE,'spray'))
    elif wrong == 'other_scope':
        policy = policy_factory.risk_policy(pure.Rule(replace(SCOPE,source_generation='other'),'brute'))
    elif wrong == 'id':
        policy = replace(policy,policy_id='custom')
    elif wrong == 'version':
        policy = replace(policy,policy_version=2)
    else:
        policy = replace(policy,definition=dict(policy.definition)|{'title':'changed'})
    result = producer.run_password_producer(conn,rule=rule(),managed_policy=policy)
    assert result.failed and result.failure_observed and not conn.queries
    assert calls[-1][2][2] == 7 and 'batch' not in [call[1] for call in calls]


def test_none_preserves_standalone_without_managed_policy_or_sql(monkeypatch):
    conn = ManagedConnection()
    wiring(monkeypatch,conn)
    monkeypatch.setattr(policy_factory,'risk_policy',lambda *_: pytest.fail('factory on standalone path'))
    result = producer.run_password_producer(conn,rule=rule(),managed_policy=None)
    assert result.jobs == 5 and not result.failed and conn.queries == []


@pytest.mark.parametrize('stage',['entry_busy','entry_closed','txa_rollback','txa_commit',
                                 'txb_rollback','txb_commit','txc_rollback'])
def test_uncertain_owned_connection_is_fatal_and_never_attempts_later_transactions(monkeypatch,stage):
    conn = ManagedConnection()
    if stage == 'entry_busy':
        conn.info.transaction_status = 2
    elif stage == 'entry_closed':
        conn.closed = True
    elif stage == 'txa_rollback':
        conn.commit_error,conn.broken_after = 1,1
    elif stage == 'txa_commit':
        conn.closed_after = 1
    elif stage == 'txb_rollback':
        conn.commit_error,conn.broken_after = 2,2
    elif stage == 'txb_commit':
        conn.closed_after = 2
    else:
        conn.decision,conn.commit_error,conn.broken_after = None,3,3
    calls = wiring(monkeypatch,conn)
    with pytest.raises(producer.ProducerConnectionFatal,match='password_v2_connection_not_idle'):
        managed_run(conn)
    expected = 0 if stage.startswith('entry') else 1 if stage.startswith('txa') else 2 if stage.startswith('txb') else 3
    assert len(conn.transactions) == expected
    assert sum(call[1] == 'begin_password_attempt' for call in calls) == int(expected > 0)


class DefaultConnection:
    def __init__(self):
        self.info = SimpleNamespace(transaction_status=0)
        self.events = []
        self.statement = ''

    @contextmanager
    def transaction(self):
        self.info.transaction_status = 2
        try:
            yield
        finally:
            self.info.transaction_status = 0

    @contextmanager
    def cursor(self):
        yield self

    def execute(self,statement,params=None):
        self.statement = statement
        self.events.append(('sql',statement,params))

    def fetchall(self):
        return [{'source':{'scope':asdict(SCOPE)}}]

    def fetchone(self):
        return {'page':{'items':[]}}


def test_managed_rules_follow_legacy_exit_on_same_known_idle_connection(monkeypatch):
    conn = DefaultConnection()
    policies = []
    def run(cur,source,**kwargs):
        assert cur.info.transaction_status == 2
        cur.events.append(('run_source',))
        return defaults.SourceOutcome(jobs=2)
    def managed(connection,*,rule,managed_policy):
        assert connection is conn and connection.info.transaction_status == 0
        assert any(item[0] == 'run_source' for item in conn.events)
        expected = policy_factory.risk_policy(rule)
        assert managed_policy.definition_json == expected.definition_json
        policies.append((rule,managed_policy))
        conn.events.append(('managed',))
        return producer.ProducerOutcome(jobs=1,failed=False,status='committed',revision=1,health={'status':'healthy'})
    monkeypatch.setattr(defaults,'run_source',run)
    monkeypatch.setattr(producer,'run_password_producer',managed)
    result = defaults.run_default_detections(conn)
    assert (result['sources'],result['jobs'],result['failed']) == (1,4,0)
    assert result['coverage_counts'] == dict.fromkeys(('partial','error','unknown','stale','disabled','failed'),0) | {'healthy':2}
    assert not any(result['password_work_counts'].values())
    source = next(i for i,item in enumerate(conn.events) if item[0] == 'sql' and 'pg_advisory_xact_lock' in item[1])
    legacy = next(i for i,item in enumerate(conn.events) if item[0] == 'run_source')
    assert source < legacy < next(i for i,item in enumerate(conn.events) if item[0] == 'managed')
    assert {rule.kind for rule,_ in policies} == {'brute','spray'}
    assert all(rule.scope == SCOPE for rule,_ in policies)


def test_legacy_source_emits_only_disabled_account_and_does_not_nest_v2(monkeypatch):
    admitted,signals = [],[]
    def admit(cur,policy):
        identity = policy.definition['source_selector']['rule_id']
        if identity in defaults.password_attacks.RULES:
            admitted.append(policy)
            return True
        return False
    monkeypatch.setattr(defaults,'_admit',admit)
    monkeypatch.setattr(defaults,'plugin_hook',lambda *_: None)
    monkeypatch.setattr(defaults,'read_password_events',lambda *_: [])
    monkeypatch.setattr(defaults.password_attacks,'evaluate',lambda *_args,**_kwargs:
                        [SimpleNamespace(rule_id=key) for key in defaults.password_attacks.RULES])
    monkeypatch.setattr(defaults,'enqueue_qw_signal_risk_jobs',lambda cur,signal: signals.append(signal.rule_id) or ('job',))
    monkeypatch.setattr(producer,'run_password_producer',lambda *_args,**_kwargs: pytest.fail('nested managed producer'))
    assert defaults.run_source(object(),{'scope':asdict(SCOPE)},now=BASE).jobs == 1
    assert signals == ['qw.disabled-account-logon'] and len(admitted) == 1
    assert admitted[0].definition['source_selector']['rule_id'] == 'qw.disabled-account-logon'
    assert all(p.definition['source_selector']['execution']['version'] == 'sli.qw.execution.v1' for p in admitted)


def test_default_stage_does_not_swallow_owned_connection_fatal(monkeypatch):
    conn = DefaultConnection()
    monkeypatch.setattr(defaults,'lock_password_policy_families',lambda *_: (),raising=False)
    def fail(*_args,**_kwargs):
        raise producer.ProducerConnectionFatal('password_v2_connection_not_idle')
    monkeypatch.setattr(defaults,'run_source',fail)
    with pytest.raises(producer.ProducerConnectionFatal):
        defaults.run_default_detections(conn)
    assert not any('read_default_file_acl_resources' in item[1] for item in conn.events if item[0] == 'sql')


@pytest.mark.parametrize('damage',['closed','unknown'])
def test_plain_driver_error_with_uncertain_default_connection_is_fatal_before_acl(monkeypatch,damage):
    class Broken(DefaultConnection):
        damaged = False
        closed = False

        @contextmanager
        def transaction(self):
            try:
                with super().transaction():
                    yield
            finally:
                if self.damaged:
                    if damage == 'closed':
                        self.closed = True
                    else:
                        self.info.transaction_status = 4

    conn = Broken()
    monkeypatch.setattr(defaults,'lock_password_policy_families',lambda *_: (),raising=False)
    def fail(*_args,**_kwargs):
        conn.damaged = True
        raise RuntimeError('ordinary driver failure with private detail')
    monkeypatch.setattr(defaults,'run_source',fail)
    with pytest.raises(producer.ProducerConnectionFatal,match='password_v2_connection_not_idle'):
        defaults.run_default_detections(conn)
    assert not any('read_default_file_acl_resources' in item[1] for item in conn.events if item[0] == 'sql')


@pytest.mark.parametrize('fatal',[True,False,'closed','unknown'])
def test_production_owner_closes_fatal_before_sigma_risk_but_keeps_recovered_failure(monkeypatch,fatal):
    from tests.semantic.test_semantic_continuous_production import _RuntimeConnection, _enabled_settings
    conn = _RuntimeConnection()
    stages = []
    monkeypatch.setattr(runtime,'semantic_runtime_mode_from_env',lambda: runtime.FINDINGS_MODE)
    monkeypatch.setattr(runtime,'validate_semantic_runtime_settings',lambda *_args,**_kwargs: None)
    monkeypatch.setattr(runtime,'prepare_production_connection',lambda *_args,**_kwargs: _enabled_settings())
    monkeypatch.setattr(runtime,'process_semantic_outbox',lambda *_args,**_kwargs: {'completed':0,'failed':0})
    monkeypatch.setattr(runtime,'process_semantic_dispatch',lambda *_args,**_kwargs: {'completed':0,'failed':0})
    def defaults_stage(_):
        stages.append('defaults')
        if fatal is True:
            raise producer.ProducerConnectionFatal('password_v2_connection_not_idle')
        if fatal == 'closed':
            conn.closed = True
        elif fatal == 'unknown':
            conn.info = SimpleNamespace(transaction_status=4)
        raise RuntimeError('recovered source failure')
    monkeypatch.setattr(runtime,'run_default_detections',defaults_stage)
    monkeypatch.setattr(runtime,'run_sigma_detections',lambda _: stages.append('sigma') or {'policies':0,'jobs':0,'failed':0})
    monkeypatch.setattr(runtime,'enqueue_risk_backlog',lambda *_args,**_kwargs: stages.append('risk') or ())
    monkeypatch.setattr(runtime,'claim_risk_evaluation_jobs',lambda *_args,**_kwargs: [])
    connects = []
    def connect():
        connects.append(conn)
        return conn
    if fatal:
        with pytest.raises(producer.ProducerConnectionFatal):
            runtime.run_once(limit=1,connect_factory=connect,archive=object())
        assert stages == ['defaults']
    else:
        result = runtime.run_once(limit=1,connect_factory=connect,archive=object())
        assert result['failed'] == 1 and stages == ['defaults','sigma','risk']
    assert connects == [conn] and conn.closed

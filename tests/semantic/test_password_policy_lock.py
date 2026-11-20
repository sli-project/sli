"""Writer serialization contracts using a stateful cursor fake; no PG race claim."""
from copy import deepcopy
from dataclasses import asdict, replace
from importlib import import_module
from importlib.util import find_spec

import pytest

from server.sli.semantic import password_attacks, semantic_governance as governance
from server.sli.semantic import semantic_risk_runtime_repository as repository
from server.sli.semantic.password_attack_policy import family_key, risk_policy
from server.sli.semantic.password_attack_v2 import Rule
from server.sli.semantic.semantic_risk import ScenarioSourceKind
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition, compile_risk_policy
from server.sli.storage.evidence_ref import EvidenceScope

SCOPE = EvidenceScope('00000000-0000-4000-8000-000000000099', 'sli.windows.ad-dc', 'fixture', 'generation', '')


def helper():
    name = 'server.sli.semantic.password_policy_lock'
    assert find_spec(name) is not None, 'shared password writer locks are not implemented'
    return import_module(name)


def row(policy, lifecycle='shadow'):
    return dict(policy_id=policy.policy_id, policy_version=policy.policy_version,
        source_kind=policy.source_kind.value, definition_json=deepcopy(dict(policy.definition)),
        definition_sha256=policy.definition_sha256, lifecycle_status=lifecycle)


class Cursor:
    def __init__(self, policy, *, status='shadow', on_family=None):
        self.policy = row(policy, status)
        self.calls = []
        self.result = None
        self.on_family = on_family
        self.subscription = dict(source_kind=policy.source_kind.value,
            selector_value=policy.definition['source_selector'].get('rule_id', 'other'),
            definition_sha256=policy.definition_sha256)

    def execute(self, sql, params=()):
        sql = ' '.join(sql.split())
        self.calls.append((sql, params))
        self.result = None
        if 'pg_advisory_xact_lock' in sql:
            if self.on_family:
                callback, self.on_family = self.on_family, None
                callback(self)
        elif sql.startswith('select') and 'from semantic_risk_policies' in sql:
            self.result = deepcopy(self.policy)
        elif sql.startswith('select') and 'from semantic_risk_policy_subscriptions' in sql:
            self.result = deepcopy(self.subscription)
        elif sql.startswith('update semantic_risk_policies'):
            self.policy['lifecycle_status'] = params[0]
            self.result = dict(lifecycle_status=params[0])

    def fetchone(self):
        return self.result


def invoke(entry, cur, policy, audits):
    if entry == 'admission':
        governance.set_policy_admission(cur, policy.policy_id, policy.policy_version, False,
            actor='owner', reason='fixture decision', audit=lambda *args: audits.append(args))
    elif entry == 'transition':
        repository.transition_risk_policy(cur, policy_id=policy.policy_id,
            policy_version=policy.policy_version, target_status='disabled')
    elif entry == 'subscription':
        repository.replace_risk_policy_subscription(cur, policy=compile_risk_policy(policy))
    else:
        repository.register_risk_policy(cur, policy=policy)


@pytest.mark.parametrize('entry', ['admission', 'transition', 'subscription', 'register'])
def test_password_family_precedes_every_policy_row_lock_or_write(entry):
    policy = risk_policy(Rule(SCOPE, 'brute'))
    cur, audits = Cursor(policy), []
    invoke(entry, cur, policy, audits)
    locks = [n for n, (sql, _) in enumerate(cur.calls) if 'pg_advisory_xact_lock' in sql]
    assert locks, 'ordinary password writer must acquire the common family'
    barriers = [n for n, (sql, _) in enumerate(cur.calls)
        if 'for update' in sql or sql.startswith(('insert ', 'update ', 'delete '))]
    assert locks[0] < min(barriers)
    assert all(params == (family_key(SCOPE, 'qw.password-brute-force'),)
        for sql, params in cur.calls if 'pg_advisory_xact_lock' in sql)
    assert all('hashtextextended(%s,0)' in sql for sql, _ in cur.calls if 'pg_advisory_xact_lock' in sql)
    if entry == 'admission':
        assert audits[0][3] == dict(enabled=False, actor='owner', reason='fixture decision')


@pytest.mark.parametrize('entry', ['admission', 'transition', 'subscription'])
@pytest.mark.parametrize('change', ['family', 'body', 'stored_hash', 'source_kind', 'version'])
def test_changed_identity_after_family_aborts_without_upgrade_or_mutation(entry, change):
    policy = risk_policy(Rule(SCOPE, 'brute'))
    def mutate(cur):
        if change == 'family':
            cur.policy = row(risk_policy(Rule(replace(SCOPE, source_generation='changed'), 'brute')))
        elif change == 'body':
            changed = deepcopy(dict(policy.definition))
            changed['title'] = 'Changed owner definition'
            cur.policy = row(replace(policy, definition=changed))
        elif change == 'stored_hash':
            cur.policy['definition_sha256'] = b'x'*32
        elif change == 'source_kind':
            cur.policy['source_kind'] = 'canonical_action'
        else:
            cur.policy['policy_version'] += 1
    cur, audits = Cursor(policy, on_family=mutate), []
    with pytest.raises(RuntimeError, match='password_policy_identity_changed'):
        invoke(entry, cur, policy, audits)
    assert len([sql for sql, _ in cur.calls if 'pg_advisory_xact_lock' in sql]) == 1
    assert not any(sql.startswith(('insert ', 'update ', 'delete ')) for sql, _ in cur.calls)
    assert audits == []


def test_registration_collision_never_locks_the_stored_other_family():
    incoming = risk_policy(Rule(SCOPE, 'brute'))
    other = risk_policy(Rule(replace(SCOPE, source_generation='other'), 'spray'))
    cur = Cursor(replace(other, policy_id=incoming.policy_id))
    with pytest.raises(RuntimeError, match='version replay conflict'):
        repository.register_risk_policy(cur, policy=incoming)
    locks = [params[0] for sql, params in cur.calls if 'pg_advisory_xact_lock' in sql]
    assert locks == [family_key(SCOPE, 'qw.password-brute-force')]
    assert not any('for update' in sql for sql, _ in cur.calls)


def test_family_batch_materializes_once_validates_before_locking_and_sorts_unique():
    brute = risk_policy(Rule(SCOPE, 'brute'))
    spray = risk_policy(Rule(SCOPE, 'spray'))
    legacy = password_attacks.risk_policy(SCOPE, 'qw.password-brute-force', policy_id='custom-v1')
    used = []
    def values():
        for policy in (spray, brute, legacy, brute):
            used.append(policy)
            yield policy
    cur = Cursor(brute)
    keys = helper().lock_password_policy_families(cur, values())
    expected = tuple(sorted({family_key(SCOPE, 'qw.password-brute-force'), family_key(SCOPE, 'qw.password-spray')}))
    assert keys == expected and len(used) == 4
    assert [params[0] for _, params in cur.calls] == list(expected)
    invalid = deepcopy(dict(brute.definition))
    invalid['source_selector']['execution']['scope']['source_generation'] = 123
    cur = Cursor(brute)
    with pytest.raises((ValueError, RuntimeError)):
        helper().lock_password_policy_families(cur, [spray, replace(brute, definition=invalid)])
    assert cur.calls == []


def test_subscription_mismatched_incoming_hash_fails_before_any_other_family():
    incoming = risk_policy(Rule(SCOPE, 'brute'))
    other = risk_policy(Rule(replace(SCOPE, source_generation='other'), 'brute'))
    cur = Cursor(replace(other, policy_id=incoming.policy_id))
    with pytest.raises(RuntimeError, match='subscription definition hash mismatch'):
        repository.replace_risk_policy_subscription(cur, policy=compile_risk_policy(incoming))
    assert not any('pg_advisory_xact_lock' in sql or 'for update' in sql for sql, _ in cur.calls)


@pytest.mark.parametrize('entry', ['admission', 'transition', 'subscription', 'register'])
def test_nonpassword_qw_policy_keeps_existing_behavior_without_family_lock(entry):
    policy = password_attacks.risk_policy(SCOPE, 'qw.disabled-account-logon', policy_id='disabled-account')
    cur, audits = Cursor(policy), []
    invoke(entry, cur, policy, audits)
    assert not any('pg_advisory_xact_lock' in sql for sql, _ in cur.calls)


def test_invalid_stored_password_hash_denies_before_policy_lock_or_write():
    policy = risk_policy(Rule(SCOPE, 'brute'))
    cur = Cursor(policy)
    cur.policy['definition_sha256'] = b'wrong'
    with pytest.raises(RuntimeError, match='password_policy_definition_invalid'):
        invoke('admission', cur, policy, [])
    assert not any('for update' in sql or sql.startswith(('insert ', 'update ')) for sql, _ in cur.calls)

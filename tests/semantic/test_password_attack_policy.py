"""Pure managed password policy and family identity contracts; no runtime/DB."""
from dataclasses import asdict, replace
from hashlib import sha256
from importlib import import_module
from importlib.util import find_spec
import json

import pytest

from server.sli.semantic import password_attacks
from server.sli.semantic.password_attack_v2 import Rule
from server.sli.semantic.semantic_risk import ScenarioSourceKind
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition, compile_risk_policy
from server.sli.storage.evidence_ref import EvidenceScope

SCOPE = EvidenceScope('00000000-0000-4000-8000-000000000099', 'sli.windows.ad-dc',
                      'synthetic-source', 'synthetic-generation', '')


def subject():
    name = 'server.sli.semantic.password_attack_policy'
    assert find_spec(name) is not None, 'canonical password policy factory is not implemented'
    return import_module(name)


def compact(value, *, ascii=True):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=ascii, allow_nan=False)


@pytest.mark.parametrize(('kind', 'rule_id', 'title'), [
    ('brute', 'qw.password-brute-force', 'Repeated password attempts against one account'),
    ('spray', 'qw.password-spray', 'Passwords tried across several accounts'),
])
def test_factory_pins_canonical_v2_policy_and_existing_definition_hash(kind, rule_id, title):
    rule = Rule(SCOPE, kind)
    policy = subject().risk_policy(rule)
    expected_id = 'default:'+rule_id+':'+sha256(compact(rule.execution).encode()).hexdigest()[:32]
    expected = dict(type='scenario_policy', source_selector=dict(rule_id=rule_id, execution=rule.execution),
        scenario_kind=rule_id, result_class='security_incident', merge_window_seconds=600,
        title=title, explanation='Review the linked sign-in attempts and secure the affected accounts.',
        risk={'class': 'high', 'raw_score': '60', 'display_points': 60,
              'rationale': 'Observed password attack evidence requires review.'})
    assert type(policy) is RiskPolicyDefinition
    assert policy.policy_id == expected_id and policy.policy_version == 1
    assert policy.source_kind is ScenarioSourceKind.QW_SIGNAL
    assert policy.definition == expected
    assert policy.definition['source_selector']['execution']['rule_version'] == 2
    assert policy.definition_json == compact(expected, ascii=False)
    assert policy.definition_sha256 == sha256(compact(expected, ascii=False).encode('utf-8')).digest()
    compiled = compile_risk_policy(policy)
    assert compiled.selector_value == rule_id and compiled.scenario_kind == rule_id
    assert compiled.merge_window.total_seconds() == 600
    assert compiled.risk_class.value == 'high' and compiled.display_points == 60
    assert compiled.qw_execution_sha256 == rule.pin


def test_unicode_scope_keeps_ascii_family_pin_and_utf8_policy_hash_domains_distinct():
    scope = replace(SCOPE, source_instance_id='источник-α', source_generation='поколение-β')
    rule = Rule(scope, 'brute')
    policy = subject().risk_policy(rule)
    ascii_definition = compact(policy.definition).encode('utf-8')
    utf8_definition = compact(policy.definition, ascii=False).encode('utf-8')
    assert ascii_definition != utf8_definition
    assert policy.definition_sha256 == sha256(utf8_definition).digest()
    assert policy.definition_sha256 != sha256(ascii_definition).digest()
    scope_digest = sha256(compact(asdict(scope)).encode('utf-8')).hexdigest()
    assert subject().family_key(scope, rule.execution['rule_id']) == (
        'sli.password.policy-family.1:'+scope_digest+':qw.password-brute-force')


@pytest.mark.parametrize('kind', ['brute', 'spray'])
def test_family_key_unifies_v1_v2_but_not_their_execution_pins(kind):
    rule = Rule(SCOPE, kind)
    legacy = password_attacks.execution(SCOPE, rule.execution['rule_id'])
    assert legacy != rule.execution
    assert subject().family_key(legacy['scope'], legacy['rule_id']) == subject().family_key(
        rule.execution['scope'], rule.execution['rule_id'])
    expected = 'sli.password.policy-family.1:'+sha256(compact(asdict(SCOPE)).encode()).hexdigest()+':'+legacy['rule_id']
    assert subject().family_key(SCOPE, legacy['rule_id']) == expected
    assert subject().family_key(dict(reversed(list(asdict(SCOPE).items()))), legacy['rule_id']) == expected


@pytest.mark.parametrize(('field', 'value'), [
    ('installation_id', '00000000-0000-4000-8000-000000000100'),
    ('plugin_id', 'sli.vpn-nps'), ('source_instance_id', 'another-source'),
    ('source_generation', 'another-generation'), ('collection_scope_id', 'another-collection'),
])
def test_family_key_separates_every_full_scope_dimension(field, value):
    rule_id = 'qw.password-brute-force'
    assert subject().family_key(SCOPE, rule_id) != subject().family_key(replace(SCOPE, **{field: value}), rule_id)


def test_family_key_separates_brute_and_spray_and_does_not_mutate_scope():
    document = asdict(SCOPE)
    before = dict(document)
    brute = subject().family_key(document, 'qw.password-brute-force')
    spray = subject().family_key(document, 'qw.password-spray')
    assert brute != spray and document == before


@pytest.mark.parametrize(('field', 'value'), [
    ('installation_id', None), ('installation_id', 'not-a-uuid'), ('plugin_id', True),
    ('plugin_id', 'x'*129), ('source_instance_id', 1), ('source_instance_id', ''),
    ('source_instance_id', ' source'), ('source_instance_id', 'x'*257),
    ('source_generation', ''), ('source_generation', 'x'*513),
    ('collection_scope_id', None), ('collection_scope_id', 'x'*257),
])
def test_family_key_denies_invalid_scope_values_without_coercion(field, value):
    with pytest.raises(ValueError, match='password_policy_family_invalid'):
        subject().family_key(asdict(SCOPE) | {field: value}, 'qw.password-brute-force')


@pytest.mark.parametrize('scope', [None, 'scope', [], {}, asdict(SCOPE) | {'login': 'ignored'},
    {key:value for key,value in asdict(SCOPE).items() if key != 'collection_scope_id'}])
def test_family_key_denies_noncanonical_scope_shape(scope):
    with pytest.raises(ValueError, match='password_policy_family_invalid'):
        subject().family_key(scope, 'qw.password-brute-force')


@pytest.mark.parametrize('rule_id', [None, 1, {}, 'brute', 'qw.disabled-account-logon'])
def test_family_key_denies_other_rule_families_and_types(rule_id):
    with pytest.raises(ValueError, match='password_policy_family_invalid'):
        subject().family_key(SCOPE, rule_id)


@pytest.mark.parametrize('rule', [None, True, 'brute', asdict(SCOPE), SCOPE])
def test_factory_denies_other_input_types(rule):
    with pytest.raises(ValueError, match='password_policy_rule_invalid'):
        subject().risk_policy(rule)


def test_factory_denies_rule_subclass_and_returns_fresh_definition_without_mutating_rule():
    class OtherRule(Rule):
        pass
    with pytest.raises(ValueError, match='password_policy_rule_invalid'):
        subject().risk_policy(OtherRule(SCOPE, 'brute'))
    rule = Rule(SCOPE, 'brute')
    execution = rule.execution
    first = subject().risk_policy(rule)
    first.definition['risk']['class'] = 'critical'
    first.definition['source_selector']['execution']['scope']['source_instance_id'] = 'changed'
    second = subject().risk_policy(rule)
    assert rule.execution == execution
    assert second.definition['risk']['class'] == 'high'
    assert second.definition['source_selector']['execution'] == execution
"""Pure canonical managed password policy and shared family identity.

The family key identifies serialization peers; it grants no source authority.
Scope digests use the existing compact ASCII execution codec. Policy definition
serialization and hashing remain owned by RiskPolicyDefinition.
"""
from dataclasses import asdict

from server.sli.semantic.password_attack_v2 import Rule
from server.sli.semantic.qw_input import _digest
from server.sli.semantic.semantic_risk import ScenarioSourceKind
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition
from server.sli.storage.evidence_ref import EvidenceRefError, EvidenceScope

_SCOPE_FIELDS = frozenset({
    'installation_id', 'plugin_id', 'source_instance_id',
    'source_generation', 'collection_scope_id',
})
_RULE_IDS = frozenset({'qw.password-brute-force', 'qw.password-spray'})


def _scope_document(scope: EvidenceScope | dict) -> dict[str, str]:
    if type(scope) is EvidenceScope:
        document = asdict(scope)
    elif type(scope) is dict:
        document = dict(scope)
    else:
        raise ValueError('password_policy_family_invalid')
    if set(document) != _SCOPE_FIELDS or any(type(value) is not str for value in document.values()):
        raise ValueError('password_policy_family_invalid')
    try:
        EvidenceScope(**document)
    except EvidenceRefError:
        raise ValueError('password_policy_family_invalid') from None
    return document


def family_key(scope: EvidenceScope | dict, rule_id: str) -> str:
    """Return the full-C/rule family text shared by v1 and v2 callers."""
    if type(rule_id) is not str or rule_id not in _RULE_IDS:
        raise ValueError('password_policy_family_invalid')
    return 'sli.password.policy-family.1:' + _digest(_scope_document(scope)) + ':' + rule_id


def risk_policy(rule: Rule) -> RiskPolicyDefinition:
    """Build revision-one managed metadata for an existing v2 password Rule."""
    if (type(rule) is not Rule or type(rule.kind) is not str or rule.kind not in {'brute', 'spray'}
            or type(rule.scope) is not EvidenceScope):
        raise ValueError('password_policy_rule_invalid')
    try:
        _scope_document(rule.scope)
        Rule(rule.scope, rule.kind)
    except ValueError:
        raise ValueError('password_policy_rule_invalid') from None
    execution = rule.execution
    rule_id = execution['rule_id']
    title = ('Repeated password attempts against one account' if rule.kind == 'brute'
             else 'Passwords tried across several accounts')
    return RiskPolicyDefinition(
        policy_id='default:' + rule_id + ':' + _digest(execution)[:32],
        policy_version=1,
        source_kind=ScenarioSourceKind.QW_SIGNAL,
        definition={
            'type': 'scenario_policy',
            'source_selector': {'rule_id': rule_id, 'execution': execution},
            'scenario_kind': rule_id,
            'result_class': 'security_incident',
            'merge_window_seconds': 600,
            'title': title,
            'explanation': 'Review the linked sign-in attempts and secure the affected accounts.',
            'risk': {
                'class': 'high', 'raw_score': '60', 'display_points': 60,
                'rationale': 'Observed password attack evidence requires review.',
            },
        },
    )

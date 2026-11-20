"""Common password-family transaction locks for ordinary policy writers.

These locks serialize decisions; full stored identity is rechecked separately.
Callers with several policies must acquire the complete sorted family set before
any policy/source lock. Changed identity requires rollback and whole-writer retry.
"""
from collections.abc import Iterable, Mapping
from copy import deepcopy
import json

from server.sli.semantic.password_attack_policy import family_key
from server.sli.semantic.semantic_risk import ScenarioSourceKind
from server.sli.semantic.semantic_risk_policy import (
    CompiledRiskPolicy, RiskPolicyDefinition, compile_risk_policy,
)

_PASSWORD_RULES = ('qw.password-brute-force', 'qw.password-spray')
_IDENTITY_COLUMNS = 'policy_id,policy_version,source_kind,definition_json,definition_sha256,lifecycle_status'


def _family(policy: RiskPolicyDefinition) -> str | None:
    if policy.source_kind is not ScenarioSourceKind.QW_SIGNAL:
        return None
    selector = policy.definition.get('source_selector')
    if not isinstance(selector, Mapping):
        return None
    execution = selector.get('execution')
    outer = selector.get('rule_id')
    inner = execution.get('rule_id') if isinstance(execution, Mapping) else None
    if outer not in _PASSWORD_RULES and inner not in _PASSWORD_RULES:
        return None
    try:
        compile_risk_policy(policy)
        return family_key(execution['scope'], outer)
    except (KeyError, TypeError, ValueError, RuntimeError):
        raise RuntimeError('password_policy_definition_invalid') from None


def lock_password_policy_families(cur, policies: Iterable[RiskPolicyDefinition]) -> tuple[str, ...]:
    """Validate once, then acquire unique sorted families, including legacy v1."""
    materialized = tuple(policies)
    keys = tuple(sorted({key for policy in materialized if (key := _family(policy)) is not None}))
    for key in keys:
        cur.execute('select pg_advisory_xact_lock(hashtextextended(%s,0))', (key,))
    return keys


def _identity(row: dict) -> tuple:
    body = row.get('definition_json')
    if isinstance(body, Mapping):
        body = deepcopy(dict(body))
    else:
        try:
            body = json.loads(str(body or '{}'))
        except (TypeError, ValueError):
            raise RuntimeError('password_policy_definition_invalid') from None
    return (row.get('policy_id'), row.get('policy_version'), row.get('source_kind'),
            body, bytes(row.get('definition_sha256') or b''))


def _stored_family(identity: tuple) -> str | None:
    policy_id, version, source_kind, definition, stored_hash = identity
    if source_kind != ScenarioSourceKind.QW_SIGNAL.value:
        return None
    # Nonpassword QW policies retain their existing validation behavior.
    selector = definition.get('source_selector') if isinstance(definition, Mapping) else None
    execution = selector.get('execution') if isinstance(selector, Mapping) else None
    outer = selector.get('rule_id') if isinstance(selector, Mapping) else None
    inner = execution.get('rule_id') if isinstance(execution, Mapping) else None
    if outer not in _PASSWORD_RULES and inner not in _PASSWORD_RULES:
        return None
    try:
        policy = RiskPolicyDefinition(policy_id=policy_id, policy_version=version,
            source_kind=ScenarioSourceKind.QW_SIGNAL, definition=definition)
        if policy.definition_sha256 != stored_hash:
            raise ValueError
        return _family(policy)
    except (TypeError, ValueError, RuntimeError):
        raise RuntimeError('password_policy_definition_invalid') from None


def lock_policy_row(cur, policy_id: str, policy_version: int, *, expected: CompiledRiskPolicy | None = None) -> dict:
    """Snapshot, family, policy row, fresh identity; never upgrade to another family."""
    query = ('select '+_IDENTITY_COLUMNS+' from semantic_risk_policies '
             'where policy_id=%s and policy_version=%s')
    params = (policy_id, policy_version)
    cur.execute(query, params)
    snapshot = dict(cur.fetchone() or {})
    if not snapshot:
        return {}
    identity = _identity(snapshot)
    if expected is not None and (identity[2] != expected.source_kind.value
            or identity[4] != expected.definition_sha256):
        raise RuntimeError('risk policy subscription definition hash mismatch')
    key = _stored_family(identity)
    if key is not None:
        cur.execute('select pg_advisory_xact_lock(hashtextextended(%s,0))', (key,))
    cur.execute(query+' for update', params)
    current = dict(cur.fetchone() or {})
    fresh = _identity(current)
    if fresh != identity or _stored_family(fresh) != key:
        raise RuntimeError('password_policy_identity_changed')
    return current

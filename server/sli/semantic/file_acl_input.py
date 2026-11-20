"""Typed Everyone-medium bridge; native authority is issued by owner SQL265."""
from datetime import datetime
import json
import re
from uuid import UUID

from sli_agent.envelope import digest
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope

RULE_ID = 'qw.file-acl-broad-write'
RULE_HASH = digest(['sli.qw.file-acl-broad-write.v1', 'everyone', 'medium', 'native-v265'])
RESOURCE_FIELDS = {'installation_id', 'plugin_id', 'agent_id', 'source_instance_id', 'collection_scope_id'}


def resource_key(resource):
    if (not isinstance(resource, dict) or set(resource) != RESOURCE_FIELDS
            or resource['plugin_id'] != 'sli.file-audit'
            or any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in resource.values())):
        raise ValueError('file_acl_resource_invalid')
    for field in ('installation_id', 'agent_id'):
        if str(UUID(resource[field])) != resource[field]:
            raise ValueError('file_acl_resource_invalid')
    return digest(['file-acl-resource.v1', resource['installation_id'], resource['agent_id'],
                   resource['source_instance_id'], resource['collection_scope_id']])


def execution(resource):
    resource_key(resource)
    return dict(version='sli.qw.file-acl-execution.v1', kind='acl', rule_id=RULE_ID,
                rule_version=1, rule_sha256=RULE_HASH, resource=resource)


def validate_execution(pin):
    try:
        if pin != execution(pin['resource']):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError('file_acl_execution_invalid') from None


def validate_signal(signal):
    """Structural equality is not native authority; verify_signal remains mandatory."""
    try:
        ctx = signal.acl_context
        if (not isinstance(ctx, dict) or set(ctx) != {'version', 'resource', 'resource_key', 'portion_id', 'proof_sha256', 'members'}
                or ctx['version'] != 'sli.file-acl-context.v1'):
            raise ValueError
        key = resource_key(ctx['resource'])
        members = ctx['members']
        if (not isinstance(members, list) or not 1 <= len(members) <= 32
                or len(json.dumps(ctx).encode()) > 49152
                or signal.kind != 'acl' or signal.rule_id != RULE_ID or signal.rule_version != 1
                or signal.rule_sha256 != RULE_HASH or signal.entity_key != key or ctx['resource_key'] != key
                or signal.episode_key != digest(['file-acl-episode.v1', key, RULE_ID])
                or signal.base_severity != 'medium' or signal.effective_severity != 'medium'
                or signal.severity_reasons or signal.conclusion_state != 'observed'
                or signal.policy_revision != 1
                or any(x is not None for x in (signal.threshold_context, signal.decoy_context,
                                               signal.file_decoy_context, signal.watch_context))):
            raise ValueError
        required = {'result_id', 'result_sha256', 'snapshot_id', 'snapshot_sha256', 'command_id', 'domain_id'}
        ids = []
        expected_refs = set()
        for member in members:
            if not isinstance(member, dict) or set(member) != required:
                raise ValueError
            for name in ('result_id', 'result_sha256', 'snapshot_sha256'):
                if not isinstance(member[name], str) or not re.fullmatch('[a-f0-9]{64}', member[name]):
                    raise ValueError
            if (not isinstance(member['command_id'], str) or not re.fullmatch('[a-zA-Z0-9_-]{1,128}', member['command_id'])
                    or type(member['domain_id']) is not int or member['domain_id'] <= 0):
                raise ValueError
            r = ctx['resource']
            scope = EvidenceScope(r['installation_id'], 'sli.file-audit', r['source_instance_id'],
                                  'audit-command:' + member['command_id'], r['collection_scope_id'])
            expected_refs.add(EvidenceRef(scope=scope, storage_kind='file_audit_snapshot',
                                          native_id=member['snapshot_id'], sha256=member['snapshot_sha256']))
            ids.append(member['result_id'])
        if (ids != sorted(set(ids)) or expected_refs != set(signal.evidence_refs)
                or signal.evidence_total != len(expected_refs)
                or len({m['domain_id'] for m in members}) != 1
                or ctx['portion_id'] != digest(['file-acl-portion.v1', key, members])
                or ctx['proof_sha256'] != digest(['file-acl-proof.v1', key, members])):
            raise ValueError
    except (KeyError, TypeError, ValueError, RuntimeError, AttributeError):
        raise ValueError('file_acl_signal_invalid') from None


def signal_from_portion(portion):
    from server.sli.semantic.qw_input import QWSignal

    doc = dict(portion['document'])
    refs = tuple(EvidenceRef(**(ref | {'scope': EvidenceScope(**ref['scope'])})) for ref in doc.pop('evidence_refs'))
    for field in ('occurred_at_utc', 'received_at_utc'):
        doc[field] = datetime.fromisoformat(doc[field])
    doc['severity_reasons'] = tuple(doc['severity_reasons'])
    signal = QWSignal(**doc, evidence_refs=refs)
    if signal.signal_id != portion['signal_id'] or json.loads(json.dumps(signal.document)) != portion['document']:
        raise ValueError('file_acl_portion_conflict')
    return signal


def risk_policy(resource, *, policy_id):
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition

    return RiskPolicyDefinition(policy_id=policy_id, policy_version=1,
        source_kind=ScenarioSourceKind.QW_SIGNAL, definition={
            'type': 'scenario_policy', 'source_selector': {'rule_id': RULE_ID, 'execution': execution(resource)},
            'scenario_kind': RULE_ID, 'result_class': 'security_incident',
            'merge_window_seconds': 300, 'expected_evidence_count': 1,
            'title': 'Write permissions granted to a broad group',
            'explanation': 'A retained snapshot shows an Everyone write grant; effective network access is not established.',
            'risk': {'class': 'medium', 'raw_score': '25', 'display_points': 25,
                     'rationale': 'Supported native retained DACL grant; historical observation.'}})

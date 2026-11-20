"""ACL-only QW execution keeps native command scopes and medium boundaries."""
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from sli_agent.envelope import digest
from server.sli.semantic.qw_input import QWSignal
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope

INSTALLATION = '00000000-0000-4000-8000-000000000099'
AGENT = '00000000-0000-4000-8000-000000000001'
RESOURCE = dict(installation_id=INSTALLATION, plugin_id='sli.file-audit', agent_id=AGENT,
                source_instance_id='synthetic-source', collection_scope_id='synthetic-root')
R = digest(['file-acl-resource.v1', INSTALLATION, AGENT, 'synthetic-source', 'synthetic-root'])
RULE_HASH = digest(['sli.qw.file-acl-broad-write.v1', 'everyone', 'medium', 'native-v265'])


def ref(command='synthetic-command'):
    scope = EvidenceScope(INSTALLATION, 'sli.file-audit', 'synthetic-source', 'audit-command:' + command, 'synthetic-root')
    return EvidenceRef(scope=scope, storage_kind='file_audit_snapshot',
                       native_id='00000000-0000-4000-8000-000000000002', sha256='1' * 64)


def base(**changes):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return dict(kind='ransom', rule_id='qw.synthetic', rule_version=1, rule_sha256='1' * 64,
                policy_revision=1, evaluation_mode='enabled', entity_key=R, episode_key='2' * 64,
                occurred_at_utc=now, received_at_utc=now, evidence_refs=(ref(),)) | changes


def context(command='synthetic-command'):
    members = [dict(result_id='3' * 64, result_sha256='4' * 64, snapshot_id=ref().native_id,
                    snapshot_sha256=ref().sha256, command_id=command, domain_id=7)]
    return dict(version='sli.file-acl-context.v1', resource=RESOURCE, resource_key=R, members=members,
                portion_id=digest(['file-acl-portion.v1', R, members]),
                proof_sha256=digest(['file-acl-proof.v1', R, members]))


def signal(command='synthetic-command'):
    return QWSignal(**base(kind='acl', rule_id='qw.file-acl-broad-write', rule_sha256=RULE_HASH,
                          episode_key=digest(['file-acl-episode.v1', R, 'qw.file-acl-broad-write']),
                          evidence_refs=(ref(command),), evidence_total=1, acl_context=context(command),
                          processing_mode='historical_replay'))


def test_snapshot_refs_cannot_masquerade_as_legacy_qw_kind():
    with pytest.raises(ValueError):
        QWSignal(**base())


def test_resource_execution_stays_stable_while_command_scope_and_signal_change():
    first, second = signal(), signal('synthetic-command-2')
    assert first.partition_key == second.partition_key == R
    assert first.execution == second.execution
    assert first.execution['version'] == 'sli.qw.file-acl-execution.v1'
    assert first.execution['resource'] == RESOURCE
    assert first.episode_key == second.episode_key
    assert first.signal_id != second.signal_id
    assert first.evidence_refs[0].scope != second.evidence_refs[0].scope
    assert first.base_severity == first.effective_severity == 'medium'
    assert replace(first, received_at_utc=datetime(2026, 2, 1, tzinfo=timezone.utc)).signal_id == first.signal_id


@pytest.mark.parametrize('changes', [dict(effective_severity='high'), dict(base_severity='high'),
                                    dict(rule_id='qw.file-acl-direct-write'), dict(entity_key='9' * 64)])
def test_typed_acl_signal_cannot_assert_high_or_other_resource(changes):
    with pytest.raises(ValueError):
        replace(signal(), **changes)


def test_typed_acl_context_cannot_change_native_member_hash_or_ref_scope():
    original = signal()
    changed = context()
    changed['members'][0]['result_sha256'] = '8' * 64
    with pytest.raises(ValueError):
        replace(original, acl_context=changed)
    with pytest.raises(ValueError):
        replace(original, evidence_refs=(ref('other-command'),))

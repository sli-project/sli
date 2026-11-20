"""Enabled risk sources must prove admission before hydrating any evidence."""
import pytest

from server.sli.semantic import semantic_risk_runtime_repository as repository


class Cursor:
    def __init__(self, source_kind, admitted, mode='enabled'):
        self.source_kind = source_kind
        self.admitted = admitted
        self.mode = mode
        self.query = ''
        self.queries = []

    def execute(self, query, params=()):
        self.query = query
        self.queries.append(query)

    def fetchone(self):
        if 'schema_migrations' in self.query:
            return {'ready': 1}
        if 'from semantic_risk_evaluation_jobs job' in self.query:
            return {
                'policy_id': 'fixture-policy', 'policy_version': 1,
                'policy_source_kind': self.source_kind, 'source_kind': self.source_kind,
                'lifecycle_status': self.mode, 'evaluation_mode': self.mode,
                'definition_json': {'type': 'scenario_policy'},
            }
        if 'select enabled from semantic_policy_admission' in self.query:
            return {} if self.admitted is None else {'enabled': self.admitted}
        raise AssertionError('unexpected evidence access')


@pytest.mark.parametrize('source_kind,error', [
    ('canonical_action', 'semantic_policy_admission_required'),
    ('correlation_candidate', 'semantic_policy_admission_required'),
    ('control_health', 'semantic_policy_admission_required'),
    ('detection_match', 'sigma_detection_admission_required'),
    ('qw_signal', 'qw_policy_admission_required'),
])
@pytest.mark.parametrize('admitted', [None, False])
def test_missing_or_revoked_admission_stops_before_source_reads(source_kind, error, admitted):
    cur = Cursor(source_kind, admitted)
    with pytest.raises(RuntimeError, match=f'^{error}$'):
        repository.load_risk_evaluation_work_item(cur, job_id='fixture-job', lease_token='fixture-lease')
    assert len(cur.queries) == 3
    assert 'for share of policy' in cur.queries[1]
    assert 'select enabled from semantic_policy_admission' in cur.queries[2]


def test_direct_enqueue_checks_admission_for_every_source():
    class EnqueueCursor:
        def execute(self, query, params=()):
            self.query = query

        def fetchone(self):
            return {'source_id': 'fixture-source', 'selector_value': 'fixture-kind'}

        def fetchall(self):
            # Simulate no admitted subscription; enqueue must not write a job.
            assert "policy.lifecycle_status)<>'enabled'" in self.query
            assert 'admission.enabled is true' in self.query
            return []

    cur = EnqueueCursor()
    assert repository.enqueue_canonical_action_risk_jobs(cur, canonical_action_id='fixture-source') == ()
    assert 'insert into' not in cur.query


@pytest.mark.parametrize('source_kind', [
    'canonical_action', 'correlation_candidate', 'control_health', 'detection_match', 'qw_signal',
])
@pytest.mark.parametrize('mode,admitted', [('enabled', True), ('shadow', None), ('test', None)])
def test_admitted_enabled_and_nonpublishing_modes_reach_policy_validation(monkeypatch, source_kind, mode, admitted):
    class PolicyValidationReached(Exception):
        pass

    def validate(_definition):
        raise PolicyValidationReached

    monkeypatch.setattr(repository, 'compile_risk_policy', validate)
    cur = Cursor(source_kind, admitted, mode)
    with pytest.raises(PolicyValidationReached):
        repository.load_risk_evaluation_work_item(cur, job_id='fixture-job', lease_token='fixture-lease')
    assert len(cur.queries) == (3 if mode == 'enabled' else 2)

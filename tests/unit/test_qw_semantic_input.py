"""N06 contracts with fake storage, native verification and policy admission."""
from dataclasses import asdict, replace
from datetime import timedelta
from hashlib import sha256
import json

import pytest

from server.sli.semantic import qw_input as qw, semantic_risk_runtime_repository as runtime
from server.sli.semantic.semantic_risk import ScenarioSourceKind
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition, compile_risk_policy
from server.sli.storage.evidence_ref import EvidenceRefError
from tests.unit.test_detection_match_risk import Cursor as DetectionCursor, NOW
from tests.unit.test_finding_evidence_refs import KINDS, reference


def signal(kind="core_event", **changes):
    return replace(qw.QWSignal(
        kind="threshold", rule_id="qw.fixture", rule_version=1, rule_sha256="1" * 64,
        policy_revision=1, evaluation_mode="shadow", entity_key="2" * 64, episode_key="3" * 64,
        occurred_at_utc=NOW, received_at_utc=NOW, evidence_refs=(reference(kind),),
    ), **changes)


def policy(item=None, **changes):
    item = item or signal()
    definition = {
        "type": "scenario_policy", "source_selector": {"rule_id": item.rule_id, "execution": item.execution},
        "scenario_kind": "qw.fixture", "result_class": "security_incident", "merge_window_seconds": 300,
        "title": "QW input requires review", "explanation": "A source-bound QW signal was admitted.",
        "risk": {"class": "medium", "raw_score": "25", "display_points": 25, "rationale": "Explicit risk policy"},
    } | changes
    return RiskPolicyDefinition(policy_id="fixture-qw", policy_version=item.policy_revision,
                                source_kind=ScenarioSourceKind.QW_SIGNAL, definition=definition)


class Cursor(DetectionCursor):
    def __init__(self, item=None, *, admitted=True):
        item = item or signal()
        super().__init__(item.evidence_refs)
        self.signals = {}
        self.admitted = admitted
        self.policies = [(policy(item), item.evaluation_mode)]

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        self.calls.append((normalized, params))
        self.rows = []
        if "insert into semantic_qw_signals(" in normalized:
            self._insert(normalized, params, self.signals, "signal_id")
        elif "select signal_id,evaluation_mode,document_json" in normalized:
            self.rows = [self.signals[params[0]]] if params[0] in self.signals else []
        elif "select signal_id as source_id" in normalized:
            row = self.signals[params[0]]
            self.rows = [{"source_id": row["signal_id"], "selector_value": row["document_json"]["rule_id"],
                          "evaluation_mode": row["evaluation_mode"]}]
        elif "from semantic_risk_policy_subscriptions subscription" in normalized:
            self.rows = [{"policy_id": item.policy_id, "policy_version": item.policy_version,
                          "definition_sha256": item.definition_sha256, "lifecycle_status": mode,
                          "detection_execution": item.definition["source_selector"]["execution"]}
                         for item, mode in self.policies if mode in params[2]
                         and compile_risk_policy(item).selector_value == params[1]
                         and item.definition["source_selector"]["execution"] == json.loads(params[3])
                         and (mode != "enabled" or self.admitted)]
        elif "select job.*,policy.source_kind" in normalized:
            row = next(row for row in self.jobs.values() if row["job_id"] == params[0])
            item, mode = next((p, mode) for p, mode in self.policies if p.policy_version == row["policy_version"])
            self.rows = [row | {"policy_source_kind": "qw_signal", "lifecycle_status": mode,
                                "definition_json": item.definition, "definition_sha256": item.definition_sha256,
                                "lease_token": params[1], "attempt_count": 1, "max_attempts": 5}]
        elif "with candidates as" in normalized:
            self.rows = list(self.jobs.values())
        else:
            self.calls.pop()
            super().execute(sql, params)


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected database or publication access")
    from server.sli.core import database, postgres_runtime_pipeline

    monkeypatch.setattr(database, "query_rows", forbidden)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", forbidden)
    for name in ("persist_scenario_proposal", "publish_enabled_scenario_finding",
                 "record_scenario_identity_supersessions", "record_finding_identity_supersessions"):
        monkeypatch.setattr(runtime, name, forbidden)


def load(cur, item):
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    assert len(jobs) == 1
    return runtime.load_risk_evaluation_work_item(cur, job_id=jobs[0], lease_token="fixture-lease")


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("mode", ["test", "shadow"])
def test_native_input_is_diagnostic_only_for_test_shadow_even_when_publication_requested(kind, mode):
    item = signal(kind, evaluation_mode=mode)
    cur = Cursor(item)
    work = load(cur, item)
    assert work.proposal.step.evidence_refs == item.evidence_refs
    assert work.proposal.step.normalized_event_ids == ()
    result = runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)
    assert result.scenario_id is None and result.finding_id is None
    assert cur.results[result.job_id]["evaluation_mode"] == mode
    assert not cur.scenarios and not cur.findings and not cur.risks and not cur.links
    assert not any("notification_outbox" in sql or "insert into normalized_events" in sql for sql, _ in cur.calls)
    job = next(iter(cur.jobs.values()))
    assert job["qw_signal_id"] == item.signal_id and job["detection_match_id"] is None


def test_replay_arrival_time_order_and_fresh_worker_keep_one_signal_and_job():
    ref = reference()
    item = signal(evidence_refs=(replace(ref, native_id="43"), ref))
    cur = Cursor(item)
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    replay = replace(item, evidence_refs=tuple(reversed(item.evidence_refs)), received_at_utc=NOW + timedelta(minutes=2))
    assert replay.signal_id == item.signal_id
    assert qw.enqueue_qw_signal_risk_jobs(cur, signal=replay) == jobs
    restarted = Cursor(item)
    restarted.signals, restarted.jobs = cur.signals, cur.jobs
    assert qw.enqueue_qw_signal_risk_jobs(restarted, signal=replay) == jobs
    assert len(cur.signals) == len(cur.jobs) == 1


def test_n06_durable_signal_keeps_its_identity_without_evidence_total():
    item = signal()
    legacy_document = asdict(item)
    legacy_document.pop("evidence_total")
    legacy_document.pop("threshold_context")
    legacy_document.pop("decoy_context")
    legacy_document.pop("file_decoy_context")
    legacy_document.pop("watch_context")
    legacy_document.pop("acl_context")
    legacy_document.pop("password_context")
    legacy_document.pop("processing_mode")
    for field in ("occurred_at_utc", "received_at_utc"):
        legacy_document[field] = getattr(item, field).isoformat()
    identity = {key: value for key, value in legacy_document.items() if key != "received_at_utc"}
    legacy_id = sha256(json.dumps(identity, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    cur = Cursor(item)
    cur.signals[legacy_id] = {"signal_id": legacy_id, "evaluation_mode": item.evaluation_mode,
                              "document_json": json.loads(json.dumps(legacy_document))}
    assert item.signal_id == legacy_id
    assert legacy_id == "2d6d4baa43865abf5f35fb8ca150a0b80288067e30d8ad78f8f00c42d8e94f48"
    assert qw.load_qw_signal(cur, signal_id=legacy_id) == item
    assert len(qw.enqueue_qw_signal_risk_jobs(cur, signal=item)) == 1
    assert len(cur.signals) == 1


@pytest.mark.parametrize("mode", ["test", "shadow", "enabled"])
def test_policy_mode_and_revision_are_exact(mode):
    item = signal(evaluation_mode=mode)
    cur = Cursor(item)
    cur.policies = [(policy(item), other) for other in ("test", "shadow", "enabled")]
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    assert len(jobs) == 1
    assert next(iter(cur.jobs.values()))["evaluation_mode"] == mode
    cur = Cursor(item)
    cur.policies = [(replace(policy(item), policy_version=2), mode)]
    assert qw.enqueue_qw_signal_risk_jobs(cur, signal=item) == ()


def test_enabled_admission_rechecked_before_loading_claimed_work():
    item = signal(evaluation_mode="enabled")
    cur = Cursor(item, admitted=False)
    assert qw.enqueue_qw_signal_risk_jobs(cur, signal=item) == ()
    assert not cur.jobs
    cur.admitted = True
    work = load(cur, item)
    assert runtime.claim_risk_evaluation_jobs(cur)
    assert not cur.results and not cur.findings
    cur.admitted = False
    with pytest.raises(RuntimeError, match="^qw_policy_admission_required$"):
        runtime.load_risk_evaluation_work_item(cur, job_id=work.job_id, lease_token="fixture-lease")


def test_direct_qw_publication_cannot_fall_through_to_canonical_action_storage():
    from server.sli.semantic.semantic_risk_repository import persist_scenario_proposal

    item = signal()
    cur = Cursor(item)
    work = load(cur, item)
    before = len(cur.calls)
    with pytest.raises(RuntimeError, match="^qw_signal_source_mismatch$"):
        persist_scenario_proposal(cur, proposal=work.proposal)
    assert not any("insert into" in sql for sql, _ in cur.calls[before:])


@pytest.mark.parametrize("kind", KINDS)
def test_source_access_hash_and_generation_checked_before_writes_and_again_at_evaluation(kind):
    item = signal(kind)
    cur = Cursor(item)
    cur.allowed.clear()
    with pytest.raises(EvidenceRefError):
        qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    assert not cur.signals and not cur.jobs
    cur.allowed.add(item.evidence_refs[0].params)
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    cur.allowed.clear()
    with pytest.raises(EvidenceRefError):
        runtime.load_risk_evaluation_work_item(cur, job_id=jobs[0], lease_token="fixture-lease")
    assert not cur.results


@pytest.mark.parametrize("field,value", [("rule_version", 2), ("rule_sha256", "4" * 64),
                                        ("kind", "decoy")])
def test_rule_pin_mismatch_cannot_enqueue(field, value):
    item = signal()
    cur = Cursor(item)
    other = replace(item, **{field: value})
    assert qw.enqueue_qw_signal_risk_jobs(cur, signal=other) == ()
    assert not cur.jobs


@pytest.mark.parametrize("field,value", [("installation_id", "00000000-0000-0000-0000-000000000002"),
    ("source_instance_id", "fixture-other"), ("source_generation", "generation-2"),
    ("collection_scope_id", "fixture-other-root")])
def test_policy_execution_pin_isolated_by_every_native_scope_dimension(field, value):
    item = signal("file_audit_observation")
    ref, = item.evidence_refs
    other = replace(item, evidence_refs=(replace(ref, scope=replace(ref.scope, **{field: value})),))
    cur = Cursor(item)
    cur.allowed.add(other.evidence_refs[0].params)
    assert qw.enqueue_qw_signal_risk_jobs(cur, signal=other) == ()
    assert not cur.jobs and item.partition_key != other.partition_key


@pytest.mark.parametrize("state", ["not_checked", "not_found"])
def test_non_observed_diagnostics_cannot_infer_absence_without_complete_coverage(state):
    item = signal(conclusion_state=state, quality="unknown")
    cur = Cursor(item)
    result = runtime.execute_risk_evaluation(cur, work=load(cur, item), evaluation_ms=1)
    assert result.conclusion_state.value == "not_checked"
    assert cur.results[result.job_id]["conclusion_state"] == "not_checked"
    assert result.finding_id is None


def test_tampered_durable_document_and_mode_change_fail_closed():
    item = signal()
    cur = Cursor(item)
    work = load(cur, item)
    cur.policies = [(policy(item), "test")]
    with pytest.raises(RuntimeError, match="policy admission changed"):
        runtime.load_risk_evaluation_work_item(cur, job_id=work.job_id, lease_token="fixture-lease")
    cur.signals[item.signal_id]["document_json"]["entity_key"] = "7" * 64
    with pytest.raises(RuntimeError, match="^qw_signal_conflict$"):
        qw.load_qw_signal(cur, signal_id=item.signal_id)


@pytest.mark.parametrize("changes", [
    {"evidence_refs": ()}, {"evidence_refs": (reference(),) * 257},
    {"evidence_refs": (reference(), reference("file_audit_observation"))},
    {"rule_version": True}, {"policy_revision": 0}, {"rule_sha256": "invalid"},
    {"entity_key": "fixture-name"}, {"episode_key": "invalid"}, {"evaluation_mode": "disabled"},
    {"occurred_at_utc": NOW.replace(tzinfo=None)}, {"severity_reasons": ("private value",)},
    {"effective_severity": "low"},
    {"conclusion_state": "unknown"},
    {"evidence_total": True}, {"evidence_total": -1}, {"evidence_total": 32769},
])
def test_contract_rejects_unbounded_unversioned_unscoped_or_private_values(changes):
    with pytest.raises(ValueError):
        signal(**changes)


def test_pin_is_qw_native_and_does_not_accept_sigma_manifest():
    item = signal()
    compiled = compile_risk_policy(policy(item))
    assert compiled.qw_execution_sha256 == qw.execution_pin_sha256(item.execution, rule_id=item.rule_id)
    assert compiled.detection_execution_sha256 is None
    execution = item.execution | {"manifest_sha256": "8" * 64}
    with pytest.raises(ValueError, match="^qw_execution_pin_invalid$"):
        compile_risk_policy(policy(item, source_selector={"rule_id": item.rule_id, "execution": execution}))
    assert item.entity_key not in repr(item)

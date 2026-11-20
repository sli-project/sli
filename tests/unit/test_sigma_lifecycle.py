"""Stage 15: lifecycle, immutable execution selection and scoped metrics, no DB."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json

import pytest

from server.sli.semantic import semantic_risk_runtime_repository as runtime
from server.sli.semantic.semantic_governance import set_policy_admission
from server.sli.semantic.semantic_risk_policy import compile_risk_policy
from server.sli.sigma.detection_input import detection_match_proposal, enqueue_detection_match_risk_jobs
from server.sli.sigma.lifecycle import execution_pin_sha256, read_lifecycle_metrics
from tests.unit.test_detection_match_risk import Cursor, NOW, RULE, evaluate, match, policy


class LifecycleCursor(Cursor):
    def __init__(self, item, definitions):
        super().__init__((item.evidence,))
        self.definitions = definitions
        self.states = dict.fromkeys((p.policy_version for p in definitions), "draft")
        self.admissions = {}
        self.audit = []
        self.sync()

    def sync(self):
        def effective(version):
            state = self.states[version]
            admitted = self.admissions.get(version)
            if state not in {"test", "shadow", "enabled"} or admitted is False:
                return None
            return "enabled" if admitted is True and state in {"shadow", "enabled"} else state
        self.policies = [(p, effective(p.policy_version)) for p in self.definitions]

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        identity_query = ("select policy_id,policy_version,source_kind,definition_json,"
                          "definition_sha256,lifecycle_status from semantic_risk_policies "
                          "where policy_id=%s and policy_version=%s")
        if normalized in (identity_query, identity_query + " for update"):
            self.calls.append((normalized, params))
            self.rows = [{"policy_id": p.policy_id, "policy_version": p.policy_version,
                          "source_kind": p.source_kind.value,
                          "definition_json": json.loads(p.definition_json),
                          "definition_sha256": p.definition_sha256,
                          "lifecycle_status": self.states[p.policy_version]}
                         for p in self.definitions
                         if (p.policy_id, p.policy_version) == tuple(params)]
        elif normalized.startswith("update semantic_risk_policies set lifecycle_status="):
            target, _, version, previous = params
            assert self.states[version] == previous
            self.states[version] = target
            self.sync()
            self.calls.append((normalized, params))
            self.rows = [{"lifecycle_status": target}]
        elif normalized.startswith("insert into semantic_policy_admission"):
            _, version, enabled, _ = params
            self.admissions[version] = enabled
            self.admitted = enabled
            self.sync()
            self.calls.append((normalized, params))
            self.rows = []
        elif normalized.startswith("select enabled from semantic_policy_admission"):
            self.calls.append((normalized, params))
            self.rows = [{"enabled": self.admissions.get(params[1])}]
        else:
            super().execute(sql, params)

    def transition(self, version, state):
        return runtime.transition_risk_policy(self, policy_id=self.definitions[0].policy_id,
                                              policy_version=version, target_status=state)

    def admit(self, version, enabled):
        set_policy_admission(self, self.definitions[0].policy_id, version, enabled,
                             actor="fixture-owner", reason="Fixture decision",
                             audit=lambda *args: self.audit.append(args[1:]))


def test_lifecycle_is_sequential_and_test_shadow_leave_existing_production_untouched(monkeypatch):
    item = match()
    cur = LifecycleCursor(item, [policy()])
    with pytest.raises(ValueError, match="invalid risk policy transition"):
        cur.transition(1, "shadow")
    with pytest.raises(ValueError, match="policy_not_ready"):
        cur.admit(1, True)
    cur.transition(1, "validated")
    cur.transition(1, "test")
    tested = evaluate(cur, monkeypatch, replace(item, evaluation_mode="test"))
    cur.transition(1, "shadow")
    shadow = evaluate(cur, monkeypatch, replace(item, evaluation_mode="shadow"))
    assert tested.scenario_id is shadow.scenario_id is None
    assert not cur.findings and not cur.risks and not cur.scenarios and not cur.links and not cur.history
    assert len(cur.results) == 2
    cur.admit(1, True)
    enabled = evaluate(cur, monkeypatch, item)
    assert enabled.finding_created and len(cur.risks) == len(cur.findings) == 1
    before = deepcopy((cur.scenarios, cur.risks, cur.findings, cur.links, cur.history))
    newer = replace(item, manifest_sha256="e" * 64)
    cur.definitions.append(policy(2, execution=newer.execution))
    cur.states[2] = "draft"
    cur.transition(2, "validated")
    cur.transition(2, "test")
    evaluate(cur, monkeypatch, replace(newer, evaluation_mode="test"))
    cur.transition(2, "shadow")
    evaluate(cur, monkeypatch, replace(newer, evaluation_mode="shadow"))
    assert (cur.scenarios, cur.risks, cur.findings, cur.links, cur.history) == before
    assert cur.audit[0][0:2] == ("semantic_policy_admission", f"{policy().policy_id}:1")


@pytest.mark.parametrize("mode", ["test", "shadow"])
def test_execution_version_switch_and_rollback_reproduce_ids_and_keep_history(mode, monkeypatch):
    first = match(evaluation_mode=mode)
    second = replace(first, rule_sha256="5" * 64, manifest_sha256="6" * 64,
                     mapping_version="fixture-v2", overlay_sha256="7" * 64)
    p1 = policy(1, execution=first.execution)
    p2 = policy(2, execution=second.execution)
    cur = LifecycleCursor(first, [p1, p2])
    path = ("validated", "test") + (("shadow",) if mode == "shadow" else ())
    for state in path:
        cur.transition(1, state)
    original = evaluate(cur, monkeypatch, first)
    snapshot = deepcopy(cur.results[original.job_id])
    cur.transition(1, "disabled")
    for state in path:
        cur.transition(2, state)
    assert enqueue_detection_match_risk_jobs(cur, match=first) == ()
    updated = evaluate(cur, monkeypatch, second)
    assert updated.job_id != original.job_id
    assert {row["policy_version"] for row in cur.jobs.values()} == {1, 2}
    cur.transition(2, "disabled")
    for state in ("draft",) + path:
        cur.transition(1, state)
    assert enqueue_detection_match_risk_jobs(cur, match=second) == ()
    rolled_back = evaluate(cur, monkeypatch, first)
    assert rolled_back.job_id == original.job_id
    assert cur.results[original.job_id] == snapshot and len(cur.results) == len(cur.jobs) == 2
    assert not cur.scenarios and not cur.risks and not cur.findings


@pytest.mark.parametrize("field,value", [("rule_sha256", "5" * 64), ("manifest_sha256", "6" * 64),
    ("overlay_sha256", "7" * 64), ("compiler_version", "fixture-v2"), ("mapping_version", "fixture-v2")])
def test_unadmitted_execution_cannot_reuse_a_policy_with_same_uuid(field, value):
    original = match()
    changed = replace(original, **{field: value})
    cur = Cursor((changed.evidence,))
    assert enqueue_detection_match_risk_jobs(cur, match=changed) == ()
    with pytest.raises(RuntimeError, match="^sigma_detection_execution_mismatch$"):
        detection_match_proposal(cur, policy=compile_risk_policy(policy()), source_id=changed.match_id)
    assert not cur.jobs and not cur.risks and not cur.findings


@pytest.mark.parametrize("field,value", [("installation_id", "00000000-0000-0000-0000-000000000002"),
    ("source_instance_id", "other-fixture"), ("source_generation", "generation-2")])
def test_pin_cannot_cross_source_scope(field, value):
    item = match()
    changed = replace(item, evidence=replace(item.evidence, scope=replace(item.evidence.scope, **{field: value})))
    cur = Cursor((item.evidence, changed.evidence))
    assert enqueue_detection_match_risk_jobs(cur, match=changed) == ()
    assert not cur.jobs


def test_pin_excludes_mode_time_and_event_identity_but_keeps_source_and_root():
    item = match("file_audit_observation")
    changed = replace(item, evidence=replace(item.evidence, native_id="c" * 64, sha256="d" * 64),
                      evaluation_mode="test", occurred_at_utc=NOW + timedelta(seconds=1))
    assert changed.match_id != item.match_id and changed.execution_sha256 == item.execution_sha256
    assert execution_pin_sha256(item.execution, rule_id=RULE) == item.execution_sha256
    scope = replace(item.evidence.scope, collection_scope_id="other-root")
    assert replace(item, evidence=replace(item.evidence, scope=scope)).execution_sha256 != item.execution_sha256


@pytest.mark.parametrize("selector", [{"rule_id": RULE}, {"rule_id": RULE, "execution": None},
    {"rule_id": RULE, "execution": {}}, {"rule_id": RULE, "execution": match().execution | {"extra": True}},
    {"rule_id": RULE, "execution": match().execution | {"rule_sha256": ""}},
    {"rule_id": RULE, "execution": match().execution | {"rule_id": "other"}},
    {"rule_id": RULE, "execution": match().execution | {"scope": {}}}])
def test_incomplete_or_unversioned_policy_pin_is_rejected(selector):
    with pytest.raises(ValueError, match="^sigma_detection_execution_pin_required$"):
        compile_risk_policy(policy(source_selector=selector))


def test_revocation_or_mode_change_blocks_already_queued_work_before_production_writes():
    item = match()
    cur = LifecycleCursor(item, [policy()])
    for state in ("validated", "test", "shadow"):
        cur.transition(1, state)
    cur.admit(1, True)
    job, = enqueue_detection_match_risk_jobs(cur, match=item)
    cur.admit(1, False)
    with pytest.raises(RuntimeError, match="no longer executable"):
        runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture")
    assert enqueue_detection_match_risk_jobs(cur, match=item) == ()
    assert not cur.scenarios and not cur.risks and not cur.findings and not cur.results
    cur.admit(1, True)
    assert enqueue_detection_match_risk_jobs(cur, match=item) == (job,)


def test_enabled_without_admission_is_rechecked_after_policy_lock():
    item = match()
    cur = Cursor((item.evidence,))
    job, = enqueue_detection_match_risk_jobs(cur, match=item)
    cur.admitted = None
    with pytest.raises(RuntimeError, match="^sigma_detection_admission_required$"):
        runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture")
    assert "for share of policy" in cur.calls[-2][0]
    assert cur.calls[-1][0].startswith("select enabled from semantic_policy_admission")
    assert not cur.scenarios and not cur.risks and not cur.findings


def test_test_job_cannot_run_after_transition_to_shadow():
    item = match(evaluation_mode="test")
    cur = LifecycleCursor(item, [policy()])
    cur.transition(1, "validated")
    cur.transition(1, "test")
    job, = enqueue_detection_match_risk_jobs(cur, match=item)
    cur.transition(1, "shadow")
    with pytest.raises(RuntimeError, match="policy admission changed"):
        runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture")
    assert not cur.results and not cur.scenarios and not cur.risks and not cur.findings


class MetricsCursor:
    def __init__(self, rows=()):
        self.rows = rows
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((" ".join(sql.split()).lower(), params))

    def fetchall(self):
        return self.rows


def test_operational_metrics_are_scoped_versioned_bounded_and_select_only():
    rows = [{"rule_id": RULE, "policy_version": n, "evaluation_mode": mode, "matches": 1,
             "queued": 1, "evaluated": 0} for n, mode in enumerate(("test", "shadow", "enabled"), 1)]
    cur = MetricsCursor(rows)
    scope = match().evidence.scope
    result = read_lifecycle_metrics(cur, scope=scope, since=NOW, until=NOW + timedelta(days=1), limit=2)
    assert result["rows"] == rows[:2] and result["truncated"]
    assert result["basis"] == "eligible_detection_inputs" and result["window_basis"] == "input_created_at"
    sql, params = cur.calls[0]
    assert json.loads(params[0]) == match().execution["scope"] and params[1:] == (NOW, NOW + timedelta(days=1), 3)
    assert sql.startswith("select ") and "detection.document_json#>'{evidence,scope}'=%s::jsonb" in sql
    assert "detection.created_at >= %s and detection.created_at < %s" in sql
    assert "count(distinct detection.match_id)" in sql and "job.source_kind='detection_match'" in sql
    assert "group by 1,2,3,4,5,6,7,8,9,10,11,12" in sql
    for field in ("rule_sha256", "manifest_sha256", "compiler_version", "mapping_version", "overlay_sha256",
                  "queued", "leased", "completed", "failed", "quarantined", "unqueued", "not_checked",
                  "degraded", "effective_mode", "admitted", "max_evaluation_ms"):
        assert field in sql
    assert "findings" not in sql and "last_error_detail" not in sql


def test_empty_metrics_do_not_claim_a_clean_telemetry_scan():
    result = read_lifecycle_metrics(MetricsCursor(), scope=match().evidence.scope,
                                    since=NOW, until=NOW + timedelta(seconds=1))
    assert result["rows"] == [] and result["truncated"] is False
    assert result["basis"] == "eligible_detection_inputs" and "scanned" not in result


@pytest.mark.parametrize("changes", [{"since": NOW.replace(tzinfo=None)}, {"until": NOW},
    {"until": NOW + timedelta(days=32)}, {"scope": None}, {"limit": 0}, {"limit": 201}, {"limit": True}])
def test_invalid_metric_window_or_scope_fails_before_query(changes):
    cur = MetricsCursor()
    with pytest.raises(ValueError, match="^sigma_lifecycle_metrics_request_invalid$"):
        read_lifecycle_metrics(cur, **({"scope": match().evidence.scope, "since": NOW,
                                       "until": NOW + timedelta(days=1)} | changes))
    assert not cur.calls


def test_backlog_and_lease_keep_execution_and_explicit_admission_gates():
    cur = MetricsCursor()
    assert runtime.enqueue_risk_backlog(cur) == ()
    assert runtime.claim_risk_evaluation_jobs(cur) == []
    backlog, claim = (sql for sql, _ in cur.calls)
    assert "policy.definition_json#>'{source_selector,execution}'=jsonb_build_object(" in backlog
    for field in ("rule_sha256", "manifest_sha256", "compiler_version", "mapping_version", "overlay_sha256", "scope"):
        assert field in backlog
    assert "detection.evaluation_mode<>'enabled' or exists(" in backlog
    # Enabled jobs require explicit admission for every source kind.
    assert "and (job.evaluation_mode<>'enabled' or exists(" in claim
    assert "admission.enabled is true" in backlog and "admission.enabled is true" in claim

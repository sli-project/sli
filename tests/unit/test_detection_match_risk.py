"""Stage 14 contracts: typed input -> policy -> durable scenario -> finding.

All persistence is an in-memory cursor; no database or source is contacted.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import re

import pytest

from server.sli.semantic import semantic_risk_repository as repository
from server.sli.semantic import semantic_risk_runtime_repository as runtime
from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
from server.sli.semantic.semantic_risk import ScenarioSourceKind, aggregate_risk
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition, compile_risk_policy
from server.sli.sigma.detection_input import (
    DetectionMatch, detection_match_proposal, enqueue_detection_match_risk_jobs,
    load_detection_match, scenario_detection_evidence,
)
from server.sli.storage.evidence_ref import EvidenceRefError
from tests.unit.test_finding_evidence_refs import KINDS, NativeCursor, reference

NOW = datetime(2026, 10, 17, 0, 5, tzinfo=timezone.utc)
RULE = "00000000-0000-0000-0000-000000000014"


def match(kind="workstation_observation", **changes):
    return replace(DetectionMatch(
        rule_id=RULE, rule_sha256="1" * 64, manifest_sha256="2" * 64,
        compiler_version="fixture-v1", mapping_version="fixture-v1", overlay_sha256="3" * 64,
        evidence=reference(kind), entity_key="4" * 64, occurred_at_utc=NOW, evaluation_mode="enabled",
    ), **changes)


def policy(version=1, *, execution=None, **changes):
    definition = {
        "type": "scenario_policy", "source_selector": {"rule_id": RULE, "execution": execution or match().execution},
        "scenario_kind": "sigma.fixture", "result_class": "security_incident",
        "merge_window_seconds": 1800, "title": "Detection requires review",
        "explanation": "An atomic expression matched; validate the security impact.",
        "risk": {"class": "medium", "raw_score": "25", "display_points": 25,
                 "rationale": "Explicit SLI policy qualification"},
    } | changes
    return RiskPolicyDefinition(policy_id="fixture-detection", policy_version=version,
                                source_kind=ScenarioSourceKind.DETECTION_MATCH, definition=definition)


class Cursor(NativeCursor):
    """Stateful PostgreSQL fake covering replay, aggregates and publication."""

    def __init__(self, refs=()):
        super().__init__(refs, legacy=False)
        self.matches = {}
        self.jobs = {}
        self.results = {}
        self.scenarios = {}
        self.steps = {}
        self.risks = {}
        self.findings = {}
        self.publications = {}
        self.policies = [(policy(execution=match(evidence=refs[0]).execution if refs else None), "enabled")]
        self.history = []
        self.acceptances = {}

    def _insert(self, sql, params, table, key, *, defaults=None):
        columns = re.search(r"insert into \w+\((.*?)\) values", sql)[1].split(",")
        row = dict(zip((column.strip() for column in columns), params))
        for name in list(row):
            if name.endswith("_json"):
                row[name] = json.loads(row[name])
        row = (defaults or {}) | row
        created = row[key] not in table
        table.setdefault(row[key], row)
        return row, created

    def execute(self, sql, params=()):
        sql = " ".join(sql.split()).lower()
        self.calls.append((sql, params))
        self.rows = []
        if "insert into semantic_detection_matches(" in sql:
            self._insert(sql, params, self.matches, "match_id")
        elif "select rule_id,evaluation_mode,occurred_at_utc,evidence_key,document_json" in sql:
            self.rows = [self.matches[params[0]]] if params[0] in self.matches else []
        elif "select match_id as source_id" in sql:
            row = self.matches[params[0]]
            self.rows = [{"source_id": row["match_id"], "selector_value": row["rule_id"],
                          "evaluation_mode": row["evaluation_mode"]}]
        elif "from semantic_risk_policy_subscriptions subscription" in sql:
            self.rows = [{"policy_id": item.policy_id, "policy_version": item.policy_version,
                          "definition_sha256": item.definition_sha256, "lifecycle_status": mode,
                          "detection_execution": item.definition["source_selector"].get("execution")}
                         for item, mode in self.policies if mode in params[2]
                         and compile_risk_policy(item).selector_value == params[1]
                         and item.definition["source_selector"].get("execution") == json.loads(params[3])
                         and (mode != "enabled" or self.admitted is True)]
        elif "insert into semantic_risk_evaluation_jobs(" in sql:
            self._insert(sql, params, self.jobs, "idempotency_key")
        elif "select job_id from semantic_risk_evaluation_jobs" in sql:
            self.rows = [self.jobs[params[0]]]
        elif "from schema_migrations" in sql:
            self.rows = [{"version": 52}]
        elif "select enabled from semantic_policy_admission" in sql:
            self.rows = [{"enabled": self.admitted}]
        elif "select job.*,policy.source_kind" in sql:
            row = next(row for row in self.jobs.values() if row["job_id"] == params[0])
            item, mode = next((p, mode) for p, mode in self.policies if p.policy_version == row["policy_version"])
            self.rows = [row | {"policy_source_kind": "detection_match", "lifecycle_status": mode,
                                "definition_json": item.definition, "definition_sha256": item.definition_sha256,
                                "policy_admitted": self.admitted,
                                "lease_token": params[1], "attempt_count": 1, "max_attempts": 5}]
        elif "select contribution.*,scenario.identity_key" in sql:
            if params[0] in self.risks:
                row = self.risks[params[0]]
                self.rows = [self.scenarios[row["scenario_id"]] | row]
        elif "select * from semantic_security_scenarios where identity_key=" in sql:
            self.rows = [row for row in self.scenarios.values() if row["identity_key"] == params[0]
                         and (row["scenario_status"] in ("open", "under_review") or params[1])]
        elif "insert into semantic_security_scenarios(" in sql:
            self._insert(sql, params, self.scenarios, "scenario_id", defaults={"scenario_status": "open"})
        elif "select scenario_id from semantic_security_scenarios where scenario_key=" in sql:
            self.rows = [row for row in self.scenarios.values() if row["scenario_key"] == params[0]]
        elif "select * from semantic_security_scenarios where scenario_key=" in sql:
            self.rows = [row for row in self.scenarios.values() if row["scenario_key"] == params[0]]
        elif "insert into semantic_scenario_steps(" in sql:
            self._insert(sql, params, self.steps, "step_key")
        elif "select * from semantic_scenario_steps where step_key=" in sql:
            self.rows = [self.steps[params[0]]]
        elif "insert into semantic_risk_contributions(" in sql:
            self._insert(sql, params, self.risks, "contribution_key")
        elif "select * from semantic_risk_contributions where contribution_key=" in sql:
            self.rows = [self.risks[params[0]]]
        elif "select contribution.source_kind," in sql:
            self.rows = [row | {"contribution_key_hex": key.hex(),
                                "evidence_key": self.matches[row["detection_match_id"]]["evidence_key"]}
                         for key, row in self.risks.items() if row["scenario_id"] == params[0]]
        elif "select confidence_factors_json from semantic_scenario_steps" in sql:
            self.rows = [row for row in self.steps.values() if row["scenario_id"] == params[0]]
        elif "from semantic_scenario_coverage_history" in sql:
            pass
        elif "select min(occurred_at_utc)" in sql:
            rows = [row for row in self.steps.values() if row["scenario_id"] == params[0]]
            self.rows = [{"first_seen_utc": min(row["occurred_at_utc"] for row in rows),
                          "last_seen_utc": max(row["occurred_at_utc"] for row in rows), "step_count": len(rows),
                          "evidence_count": len({self.matches[row["detection_match_id"]]["evidence_key"] for row in rows}),
                          "contribution_count": sum(row["scenario_id"] == params[0] for row in self.risks.values())}]
        elif "update semantic_security_scenarios set" in sql:
            columns = re.findall(r"(\w+)=%s", sql.split(" where ")[0])
            self.scenarios[params[-1]].update(dict(zip(columns, params)))
            self.rows = [self.scenarios[params[-1]]]
        elif "insert into semantic_risk_evaluation_results(" in sql:
            self._insert(sql, params, self.results, "job_id")
        elif "from semantic_risk_evaluation_results result" in sql:
            self.rows = [self.results[params[0]] | {"source_kind": "detection_match", "policy_admitted": self.admitted}]
        elif "from semantic_risk_contributions contribution" in sql:
            self.rows = self.contributions
        elif "select detection_match_id from semantic_scenario_steps" in sql:
            self.rows = [row for row in self.steps.values() if row["scenario_id"] == params[0]]
        elif "from semantic_security_scenarios where scenario_id=" in sql:
            self.rows = [self.scenarios[params[0]]]
        elif "insert into findings(" in sql:
            fingerprint = params[0]
            if fingerprint not in self.findings:
                self.findings[fingerprint] = {"id": len(self.findings) + 1, "rule_code": params[1],
                                               "status": "new", "status_reason": "initial"}
                self.rows = [self.findings[fingerprint]]
        elif "select id,rule_code from findings" in sql:
            self.rows = [self.findings[params[0]]]
        elif "update findings set" in sql:
            assert "status=" not in sql and "status_reason=" not in sql and "risk_accepted=" not in sql
        elif re.search(r"(?:insert into|update|delete from) semantic_suppressions\b", sql):
            raise AssertionError("publication must preserve finding risk-acceptance decisions")
        elif "insert into semantic_finding_publications(" in sql:
            row, _ = self._insert(sql, params, self.publications, "scenario_id")
            row["finding_fingerprint"] = params[3]
        elif "select finding_id,finding_fingerprint" in sql:
            self.rows = [self.publications[params[0]]]
        elif "insert into finding_status_history(" in sql:
            self.history.append(params)
        elif "update semantic_risk_evaluation_jobs" in sql:
            self.rows = [{"job_id": params[0]}]
        elif "pg_advisory_xact_lock" in sql:
            pass
        else:
            self.calls.pop()
            super().execute(sql, params)


def evaluate(cur, monkeypatch, item):
    monkeypatch.setattr(runtime, "record_scenario_identity_supersessions", lambda *a, **kw: None)
    monkeypatch.setattr(runtime, "record_finding_identity_supersessions", lambda *a, **kw: None)
    jobs = enqueue_detection_match_risk_jobs(cur, match=item)
    assert len(jobs) == 1
    work = runtime.load_risk_evaluation_work_item(cur, job_id=jobs[0], lease_token="fixture-lease")
    return runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)


@pytest.mark.parametrize("kind", KINDS)
def test_native_input_uses_policy_risk_and_standard_publication(kind, monkeypatch):
    item = match(kind)
    cur = Cursor((item.evidence,))
    result = evaluate(cur, monkeypatch, item)
    assert result.finding_created and result.finding_id == 1
    assert result.display_score == 25 and result.risk_class.value == "medium"
    assert len(cur.findings) == len(cur.links) == 1
    assert cur.scenarios[result.scenario_id]["evidence_count"] == 1
    assert all(row["canonical_action_id"] is None and row["control_reference"] is None
               for row in cur.steps.values())
    assert not any("insert into canonical_actions" in sql or "insert into normalized_events" in sql
                   for sql, _ in cur.calls)


@pytest.mark.parametrize("mode", ["test", "shadow"])
def test_test_and_shadow_never_persist_production_risk_or_findings(mode, monkeypatch):
    item = match(evaluation_mode=mode)
    cur = Cursor((item.evidence,))
    cur.policies = [(policy(), mode)]
    result = evaluate(cur, monkeypatch, item)
    assert result.scenario_id is None and result.finding_id is None
    assert not cur.scenarios and not cur.risks and not cur.findings and not cur.links
    assert cur.results[result.job_id]["evaluation_mode"] == mode


@pytest.mark.parametrize("mode", ["test", "shadow", "enabled"])
def test_detector_mode_must_equal_effective_policy_mode(mode):
    item = match(evaluation_mode=mode)
    cur = Cursor((item.evidence,))
    cur.policies = [(policy(1), "test"), (policy(2), "shadow"), (policy(3), "enabled")]
    jobs = enqueue_detection_match_risk_jobs(cur, match=item)
    assert len(jobs) == 1
    assert next(iter(cur.jobs.values()))["evaluation_mode"] == mode
    assert enqueue_detection_match_risk_jobs(cur, match=item) == jobs
    assert len(cur.jobs) == len(cur.matches) == 1


@pytest.mark.parametrize("changes", [{"quality": "unknown"}, {"quality": "degraded"},
    {"conclusion_state": "unknown"}, {"conclusion_state": "not_evaluable"}, {"suppressed": True}])
def test_unobserved_degraded_or_suppressed_input_cannot_create_jobs(changes):
    cur = Cursor()
    assert enqueue_detection_match_risk_jobs(cur, match=match(**changes)) == ()
    assert not cur.calls


def test_source_revocation_blocks_before_input_or_finding_writes(monkeypatch):
    item = match()
    cur = Cursor()
    with pytest.raises(EvidenceRefError):
        enqueue_detection_match_risk_jobs(cur, match=item)
    assert not cur.matches and not cur.jobs
    cur.allowed.add(item.evidence.params)
    evaluate(cur, monkeypatch, item)
    cur.allowed.clear()
    with pytest.raises(EvidenceRefError):
        publish_enabled_scenario_finding(cur, job_id=next(iter(cur.results)), scenario_id=next(iter(cur.scenarios)))


@pytest.mark.parametrize("status", ["confirmed", "false_positive", "closed"])
def test_replay_and_rule_policy_update_keep_problem_status_acceptance_and_single_score(status, monkeypatch):
    item = match()
    cur = Cursor((item.evidence,))
    first = evaluate(cur, monkeypatch, item)
    finding = next(iter(cur.findings.values()))
    finding.update(status=status, status_reason="Manual fixture decision")
    acceptance = {"kind": "risk_acceptance", "finding_id": first.finding_id, "state": "active"}
    cur.acceptances[first.finding_id] = acceptance.copy()
    cur.scenarios[first.scenario_id]["scenario_status"] = "resolved"
    replay = evaluate(cur, monkeypatch, item)
    assert not replay.finding_created and replay.finding_id == first.finding_id
    updated = replace(item, rule_sha256="5" * 64, manifest_sha256="6" * 64)
    cur.policies = [(policy(2, execution=updated.execution), "enabled")]
    second = evaluate(cur, monkeypatch, updated)
    assert second.scenario_id == first.scenario_id and second.finding_id == first.finding_id
    assert second.display_score == first.display_score == 25
    assert len(cur.scenarios) == len(cur.findings) == len(cur.links) == len(cur.history) == 1
    assert len(cur.risks) == 2  # Version provenance survives; the evidence scores once.
    assert finding["status"] == status and cur.acceptances[first.finding_id] == acceptance
    assert finding["status_reason"] == "Manual fixture decision"


@pytest.mark.parametrize("change", ["source", "entity", "episode"])
def test_distinct_scope_entity_or_episode_cannot_merge(change):
    original = match()
    other = replace(original, **{
        "source": {"evidence": replace(original.evidence, scope=replace(original.evidence.scope, source_generation="other"))},
        "entity": {"entity_key": "7" * 64},
        "episode": {"occurred_at_utc": NOW + timedelta(hours=1)},
    }[change])
    cur = Cursor((original.evidence, other.evidence))
    for item in (original, other):
        enqueue_detection_match_risk_jobs(cur, match=item)
    assert detection_match_proposal(cur, policy=compile_risk_policy(policy(execution=original.execution)),
                                    source_id=original.match_id).identity_sha256 != (
        detection_match_proposal(cur, policy=compile_risk_policy(policy(execution=other.execution)),
                                 source_id=other.match_id).identity_sha256)


def test_two_detectors_on_same_evidence_score_once_and_new_evidence_adds():
    first = match()
    second = replace(first, rule_sha256="5" * 64)
    other = replace(first, evidence=replace(first.evidence, native_id="c" * 64))
    cur = Cursor((first.evidence, other.evidence))
    proposals = []
    for item in (first, second, other):
        enqueue_detection_match_risk_jobs(cur, match=item)
        proposals.append(detection_match_proposal(cur, policy=compile_risk_policy(policy(execution=item.execution)),
                                                 source_id=item.match_id))
    assert aggregate_risk(tuple(p.contribution for p in proposals[:2])).display_score == 25
    assert aggregate_risk(tuple(p.contribution for p in proposals)).display_score == 50


@pytest.mark.parametrize("field,value", [("rule_id", "invalid"), ("entity_key", "display-name"),
    ("rule_sha256", ""), ("overlay_sha256", ""), ("compiler_version", ""),
    ("occurred_at_utc", NOW.replace(tzinfo=None)), ("suppressed", "false")])
def test_input_contract_rejects_invalid_identity_and_quality(field, value):
    with pytest.raises(ValueError, match="sigma_detection_input_invalid"):
        match(**{field: value})


def test_exact_match_document_and_selector_are_immutable():
    item = match()
    cur = Cursor((item.evidence,))
    enqueue_detection_match_risk_jobs(cur, match=item)
    cur.matches[item.match_id]["document_json"]["manifest_sha256"] = "f" * 64
    with pytest.raises(RuntimeError, match="sigma_detection_input_conflict"):
        load_detection_match(cur, match_id=item.match_id)
    with pytest.raises(ValueError):
        compile_risk_policy(policy(source_selector={"action_kind": "fake"}))


@pytest.mark.parametrize("column,value", [("evidence_key", "f" * 64), ("rule_id", "invalid"),
                                        ("occurred_at_utc", NOW + timedelta(seconds=1))])
def test_input_index_metadata_must_match_content_bound_document(column, value):
    item = match()
    cur = Cursor((item.evidence,))
    enqueue_detection_match_risk_jobs(cur, match=item)
    cur.matches[item.match_id][column] = value
    with pytest.raises(RuntimeError, match="^sigma_detection_input_conflict$"):
        load_detection_match(cur, match_id=item.match_id)


def test_invalid_stored_document_diagnostics_are_redacted():
    item = match()
    cur = Cursor((item.evidence,))
    enqueue_detection_match_risk_jobs(cur, match=item)
    cur.matches[item.match_id]["document_json"]["occurred_at_utc"] = "private fixture content"
    with pytest.raises(RuntimeError, match="^sigma_detection_input_conflict$") as error:
        load_detection_match(cur, match_id=item.match_id)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("admitted", [False, None])
def test_missing_admission_blocks_publication(admitted, monkeypatch):
    item = match()
    cur = Cursor((item.evidence,))
    cur.admitted = admitted
    assert enqueue_detection_match_risk_jobs(cur, match=item) == ()
    assert not cur.jobs and not cur.scenarios and not cur.risks and not cur.findings and not cur.links


@pytest.mark.parametrize("state", [None, "draft", "validated", "disabled", "deprecated"])
def test_nonexecutable_or_revoked_policy_cannot_enqueue(state):
    item = match()
    cur = Cursor((item.evidence,))
    cur.policies = [(policy(), state)]
    assert enqueue_detection_match_risk_jobs(cur, match=item) == ()
    assert not cur.jobs and not cur.findings


@pytest.mark.parametrize("overrides", [{"evaluation_mode": "test"}, {"evaluation_mode": "shadow"},
                                     {"conclusion_state": "not_checked"}, {"conclusion_state": "not_found"}])
def test_publication_requires_observed_enabled_result_before_writes(overrides):
    cur = Cursor()
    cur.results["fixture-job"] = {"evaluation_mode": "enabled", "conclusion_state": "observed",
                                   "scenario_id": "fixture-scenario"} | overrides
    with pytest.raises(RuntimeError, match="observed enabled result"):
        publish_enabled_scenario_finding(cur, job_id="fixture-job", scenario_id="fixture-scenario")
    assert len(cur.calls) == 1 and not cur.findings and not cur.links


def test_mismatched_source_cannot_persist_and_missing_evidence_fails_closed():
    item = match()
    cur = Cursor((item.evidence,))
    enqueue_detection_match_risk_jobs(cur, match=item)
    proposal = detection_match_proposal(cur, policy=compile_risk_policy(policy()), source_id=item.match_id)
    with pytest.raises(RuntimeError, match="sigma_detection_source_mismatch"):
        repository._verify_source_evidence(cur, proposal=replace(proposal, partition_key="other"))
    with pytest.raises(RuntimeError, match="sigma_detection_evidence_unavailable"):
        scenario_detection_evidence(cur, scenario_id="absent")

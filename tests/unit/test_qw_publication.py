"""N07 publication, episode and bounded native-evidence contracts with fakes."""
from dataclasses import replace
from datetime import timedelta

import pytest

from server.sli.semantic import qw_input as qw, semantic_risk_runtime_repository as runtime
from server.sli.semantic.semantic_risk_repository import _select_scenario
from server.sli.semantic.semantic_risk_policy import compile_risk_policy
from server.sli.storage.evidence_ref import EvidenceRefError
from tests.unit.test_qw_semantic_input import Cursor as InputCursor, signal


class Cursor(InputCursor):
    def __init__(self, item):
        super().__init__(item)
        self.outbox = set()

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if "with candidates as" in normalized:
            self.calls.append((normalized, params))
            assert "job.source_kind<>'qw_signal' or job.evaluation_mode<>'enabled'" not in normalized
            self.rows = list(self.jobs.values())
        elif "select contribution.source_kind," in normalized:
            self.calls.append((normalized, params))
            self.rows = [row | {"contribution_key_hex": key.hex(),
                                "evidence_key": qw.load_qw_signal(self, signal_id=row["qw_signal_id"]).evidence_key}
                         for key, row in self.risks.items() if row["scenario_id"] == params[0]]
        elif "select min(occurred_at_utc)" in normalized:
            self.calls.append((normalized, params))
            rows = [row for row in self.steps.values() if row["scenario_id"] == params[0]]
            self.rows = [{"first_seen_utc": min(row["occurred_at_utc"] for row in rows),
                          "last_seen_utc": max(row["occurred_at_utc"] for row in rows), "step_count": len(rows),
                          "evidence_count": len({ref for row in rows for ref in
                              qw.load_qw_signal(self, signal_id=row["qw_signal_id"]).evidence_refs}),
                          "expected_evidence_count": max((qw.load_qw_signal(self, signal_id=row["qw_signal_id"]).evidence_total
                                                         for row in rows), default=0),
                          "contribution_count": len(rows)}]
        elif "from semantic_risk_evaluation_results result" in normalized:
            self.calls.append((normalized, params))
            self.rows = [self.results[params[0]] | {"source_kind": "qw_signal", "policy_admitted": self.admitted}]
        elif "select step_id,qw_signal_id from semantic_scenario_steps" in normalized:
            self.calls.append((normalized, params))
            self.rows = sorted([row for row in self.steps.values()
                                if row["scenario_id"] == params[0] and row["step_id"] > params[1]],
                               key=lambda row: row["step_id"])[:32]
        elif "enqueue_qw_finding_notifications(" in normalized:
            self.calls.append((normalized, params))
            assert params[0] in self.publications
            self.outbox.add(params[0])
            self.rows = [{"enqueued": 1}]
        else:
            super().execute(sql, params)


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    from server.sli.core import database, postgres_runtime_pipeline
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected database connection")
    monkeypatch.setattr(database, "query_rows", forbidden)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", forbidden)
    monkeypatch.setattr(runtime, "record_scenario_identity_supersessions", lambda *a, **kw: None)
    monkeypatch.setattr(runtime, "record_finding_identity_supersessions", lambda *a, **kw: None)


def evaluate(cur, item):
    cur.allowed.update(ref.params for ref in item.evidence_refs)
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    work = runtime.load_risk_evaluation_work_item(cur, job_id=jobs[0], lease_token="fixture-lease")
    return runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)


def test_enabled_qw_job_can_be_claimed_for_publication():
    item = signal(evaluation_mode="enabled")
    cur = Cursor(item)
    job, = qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    claimed, = runtime.claim_risk_evaluation_jobs(cur)
    assert claimed["job_id"] == job
    assert not cur.scenarios and not cur.findings and not cur.outbox


@pytest.mark.parametrize("kind", ["core_event", "workstation_observation", "file_audit_observation"])
def test_enabled_publishes_one_queue_row_and_outbox_and_replay_preserves_manual_status(kind):
    item = signal(kind, evaluation_mode="enabled")
    cur = Cursor(item)
    first = evaluate(cur, item)
    assert runtime.claim_risk_evaluation_jobs(cur)
    finding = next(iter(cur.findings.values()))
    finding["status"] = "closed"
    replay = evaluate(cur, item)
    assert first.finding_created and not replay.finding_created
    assert first.finding_id == replay.finding_id
    assert len(cur.scenarios) == len(cur.findings) == len(cur.publications) == len(cur.outbox) == 1
    assert finding["status"] == "closed"
    assert len(cur.links) == 1
    assert all(row["qw_signal_id"] == item.signal_id and row["control_reference"] is None
               for row in cur.steps.values())
    assert not any("insert into finding_entities(" in sql for sql, _ in cur.calls)


def test_expanding_episode_keeps_identity_beyond_merge_window_and_closed_status():
    item = signal(evaluation_mode="enabled")
    cur = Cursor(item)
    first = evaluate(cur, item)
    cur.scenarios[first.scenario_id]["scenario_status"] = "resolved"
    other = replace(item, evidence_refs=(replace(item.evidence_refs[0], native_id="43"),),
                    occurred_at_utc=item.occurred_at_utc + timedelta(hours=2))
    second = evaluate(cur, other)
    assert second.scenario_id == first.scenario_id and second.finding_id == first.finding_id
    assert second.finding_created is False
    assert len(cur.links) == 2 and len(cur.outbox) == 1
    different = replace(other, episode_key="9" * 64)
    assert evaluate(cur, different).finding_id != first.finding_id


def test_episode_over_256_evidence_links_every_member_in_bounded_calls():
    item = signal(evaluation_mode="enabled")
    ref, = item.evidence_refs
    item = replace(item, evidence_refs=tuple(replace(ref, native_id=str(n)) for n in range(1, 257)))
    cur = Cursor(item)
    first = evaluate(cur, item)
    second = evaluate(cur, replace(item, evidence_refs=(replace(ref, native_id="257"),)))
    assert second.finding_id == first.finding_id
    assert len(cur.links) == 257
    count = next(params for sql, params in reversed(cur.calls) if "update findings set" in sql)
    assert count[-3] == 257
    assert len(cur.outbox) == 1


def test_bad_later_evidence_is_rejected_before_any_finding_or_outbox_write():
    item = signal(evaluation_mode="enabled")
    cur = Cursor(item)
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    work = runtime.load_risk_evaluation_work_item(cur, job_id=jobs[0], lease_token="fixture-lease")
    cur.allowed.clear()
    with pytest.raises(EvidenceRefError):
        runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)
    assert not cur.findings and not cur.publications and not cur.outbox


@pytest.mark.parametrize("mode", ["test", "shadow"])
def test_diagnostic_modes_never_publish_or_enqueue(mode):
    item = signal(evaluation_mode=mode)
    cur = Cursor(item)
    result = evaluate(cur, item)
    assert result.scenario_id is None and not cur.outbox and not cur.findings


def test_episode_key_is_independent_of_first_member_arrival_order():
    item = signal(evaluation_mode="enabled")
    other = replace(item, evidence_refs=(replace(item.evidence_refs[0], native_id="43"),))
    keys = []
    for initial in (item, other):
        cur = Cursor(initial)
        qw.enqueue_qw_signal_risk_jobs(cur, signal=initial)
        proposal = qw.qw_signal_proposal(cur, policy=compile_risk_policy(cur.policies[0][0]), source_id=initial.signal_id)
        keys.append(_select_scenario(cur, proposal=proposal)["scenario_key"])
    assert keys[0] == keys[1]


def test_known_multi_portion_input_remains_pending_until_all_evidence_arrives():
    item = signal(evaluation_mode="enabled", evidence_total=2)
    cur = Cursor(item)
    pending = evaluate(cur, item)
    assert pending.publication_state == "evidence_pending" and pending.finding_id is None
    assert not cur.findings and not cur.publications and not cur.outbox
    other = replace(item, evidence_refs=(replace(item.evidence_refs[0], native_id="43"),))
    published = evaluate(cur, other)
    assert published.publication_state == "ready" and published.finding_created
    assert len(cur.links) == 2 and len(cur.outbox) == 1


def test_non_observed_enabled_signal_is_diagnostic_without_a_finding_or_outbox():
    item = signal(evaluation_mode="enabled", conclusion_state="not_checked")
    cur = Cursor(item)
    result = evaluate(cur, item)
    assert result.finding_id is None and result.scenario_id is None
    assert not cur.outbox and not cur.findings


def test_enabled_pending_input_still_requires_explicit_publication_feature_gate():
    item = signal(evaluation_mode="enabled", evidence_total=2)
    cur = Cursor(item)
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=item)
    work = runtime.load_risk_evaluation_work_item(cur, job_id=jobs[0], lease_token="fixture-lease")
    with pytest.raises(RuntimeError, match="enabled semantic evaluation requires finding publication"):
        runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=False)
    assert not cur.scenarios and not cur.outbox

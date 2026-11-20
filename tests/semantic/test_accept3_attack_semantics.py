"""Synthetic ACCEPT_3 cohorts, without source access or database connections."""
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.semantic import semantic_worker_runtime as worker
from server.sli.semantic.semantic_correlation import aggregate_bruteforce_attempts
from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
from server.sli.semantic.semantic_processing import SemanticFeatureSettings
from server.sli.semantic.semantic_producer import select_semantic_queue_candidates


SID = "S-1-5-21-100-200-300"
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def sources(scenario):
    base = {"TargetUserSid": f"{SID}-1100", "TargetUserName": "fixture-user",
            "SubjectUserSid": f"{SID}-1200", "IpAddress": "192.0.2.20"}
    if scenario == "brute":
        rows = [(4625, {"Status": "0xc000006d", "SubStatus": "0xc000006a"})] * 20
        rows += [(4740, {}), (4767, {}), (4624, {"TargetLogonId": "0x42"}), (4634, {"TargetLogonId": "0x42"})]
    elif scenario == "spray":
        rows = [(4625, {"TargetUserSid": f"{SID}-{1300 + i}", "TargetUserName": f"fixture-{i}",
                        "Status": "0xc000006d", "SubStatus": "0xc000006a"}) for i in range(30)]
    elif scenario == "admin":
        membership = {"TargetSid": f"{SID}-512", "MemberSid": f"{SID}-1100"}
        rows = [(4728, membership), (5136, {}), (4729, membership), (5136, {})]
    elif scenario == "kerberos":
        rows = [(4769, {"ServiceName": f"fixture-service-{i}", "TicketEncryptionType": "0x17",
                        "Status": "0x0"}) for i in range(10)]
    elif scenario == "disabled":
        rows = [(4625, {"Status": "0xc000006e", "SubStatus": "0xc0000072"})]
    else:
        assert scenario == "task"
        rows = [(4698, {"TaskName": "\\fixture-task"}), (4699, {"TaskName": "\\fixture-task"})]
    return [{"id": i + 1, "event_id": code, "channel": "Security", "computer": "fixture-dc",
             "source_host_id": 1, "domain_id": 1, "event_record_id": i + 1,
             "provider_name": "Microsoft-Windows-Security-Auditing",
             "time_created_utc": START + timedelta(seconds=i), "event_data_json": base | data}
            for i, (code, data) in enumerate(rows)]


class Connection:
    def transaction(self):
        return nullcontext()

    def cursor(self):
        return nullcontext(object())


@pytest.mark.parametrize(("scenario", "ordinary_count", "action_kind"), [
    ("brute", 22, "authentication.session.failed"),
    ("spray", 30, "authentication.session.failed"),
    ("admin", 4, "group.member.added"),
    ("kerberos", 0, "authentication.kerberos.service_ticket.requested"),
    ("disabled", 1, "authentication.session.failed"),
    ("task", 2, "scheduled_task.created"),
])
def test_attack_cohorts_reach_normalization_assembly_and_dispatch_without_db(
    monkeypatch, scenario, ordinary_count, action_kind,
):
    cohort = sources(scenario)
    candidates = [{"source_event_id": row["id"], "event_key": str(row["event_id"]),
                   "stream": row["channel"], "provider_name": row["provider_name"]} for row in cohort]
    selected, _ = select_semantic_queue_candidates(candidates)
    assert len(selected) == ordinary_count
    # Explicit context selection proves the remaining evidence can normalize;
    # it does not change the ordinary producer or silently activate a detector.
    all_selected, _ = select_semantic_queue_candidates(candidates, include_context=True)
    assert len(all_selected) == len(cohort)
    jobs = [{"job_id": str(row["id"]), "job_kind": "normalize_event", "source_event_id": row["id"],
             "lease_token": "fixture-lease", "attempt_count": 1, "max_attempts": 5} for row in cohort]
    normalized, persisted_actions, dispatched, completed = [], [], [], []
    monkeypatch.setattr(worker, "claim_semantic_jobs", lambda *_a, **_k: [jobs.pop(0)] if jobs else [])
    monkeypatch.setattr(worker, "lock_semantic_source", lambda *_a, **_k: None)
    monkeypatch.setattr(worker, "load_semantic_source_event",
                        lambda *_a, source_event_id, **_k: cohort[source_event_id - 1])
    monkeypatch.setattr(worker, "load_identity_role_overrides", lambda *_a, **_k: {})
    monkeypatch.setattr(worker, "persist_normalized_event",
                        lambda *_a, event, **_k: normalized.append(event) or str(event.source_event_id))
    monkeypatch.setattr(worker, "persist_canonical_actions", lambda *_a, actions: persisted_actions.extend(actions))
    monkeypatch.setattr(worker, "enqueue_dispatch_jobs",
                        lambda *_a, normalized_event_id, **_k: dispatched.append(normalized_event_id))
    monkeypatch.setattr(worker, "complete_semantic_job", lambda *_a, job_id, **_k: completed.append(job_id))
    monkeypatch.setattr(worker, "fail_semantic_job", lambda *_a, **_k: pytest.fail("synthetic cohort failed"))

    result = worker.process_semantic_outbox(
        Connection(), archive=object(), limit=len(cohort),
        settings=SemanticFeatureSettings(normalization_enabled=True, assembly_enabled=True, correlation_enabled=True),
    )
    assert result["failed"] == 0
    assert result["completed"] == result["normalized"] == len(cohort)
    assert len(dispatched) == len(completed) == len(cohort)
    assert action_kind in {action.action_kind for action in persisted_actions}
    assert {event.source_event_id for event in normalized} == {row["id"] for row in cohort}
    if scenario == "brute":
        relations = aggregate_bruteforce_attempts(normalized)
        assert len(relations) == 1 and len(relations[0].source_event_ids) == 20
    elif scenario == "spray":
        # Thirty different targets must not become a single-target brute force.
        assert aggregate_bruteforce_attempts(normalized) == []
    elif scenario == "disabled":
        assert normalized[0].facts["failure_status"].casefold() == "0xc0000072"
    elif scenario == "kerberos":
        assert {event.facts["service_name"] for event in normalized} == {f"fixture-service-{i}" for i in range(10)}


@pytest.mark.parametrize("kind", ["group.member.added", "scheduled_task.created"])
def test_shadow_attack_policy_cannot_publish_a_finding(kind):
    class Cursor:
        def __init__(self):
            self.queries = []

        def execute(self, query, params):
            self.queries.append(query)

        def fetchone(self):
            return {"evaluation_mode": "shadow", "conclusion_state": "observed", "scenario_id": kind,
                    "policy_admitted": False}

    cur = Cursor()
    with pytest.raises(RuntimeError, match="observed enabled result"):
        publish_enabled_scenario_finding(cur, job_id="fixture-job", scenario_id=kind)
    assert len(cur.queries) == 1 and "insert into findings" not in cur.queries[0]

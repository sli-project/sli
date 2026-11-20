"""Quarantined current work can resume without expired source payloads."""
from contextlib import nullcontext
from copy import deepcopy
from datetime import timedelta

import pytest

from server.sli.semantic import semantic_worker_runtime as runtime
from server.sli.semantic.semantic_processing import (
    SemanticFeatureSettings,
    normalize_semantic_source_payload,
)
from server.sli.semantic.semantic_processing_repository import (
    load_retained_normalized_event,
    normalized_event_id,
)
from server.sli.storage.storage_v2_archive import ArchiveBlockUnavailableError, ArchiveIntegrityError
from tests.semantic.test_semantic_agent_source import evidence


def retained():
    core, _ = evidence(4624)
    event = normalize_semantic_source_payload({
        **core, "source_host_id": core["server_id"],
        "event_data_json": {"LogonType": "3", "TargetUserName": "fixture-account"},
        "source_event_sha256": core["normalized_hash"],
    })
    row = {
        "normalized_event_id": normalized_event_id(event),
        "source_event_sha256": core["normalized_hash"],
        "semantic_sha256": bytes.fromhex(event.semantic_sha256),
        "semantic_type": event.semantic_type, "occurred_at_utc": event.occurred_at_utc,
        "roles_json": dict(event.roles), "facts_json": dict(event.facts),
        "quality_json": dict(event.quality),
    }
    return core, event, row


class Cursor:
    def __init__(self, row):
        self.row = row
        self.queries = []

    def execute(self, sql, params=()):
        self.queries.append((sql, params))

    def fetchone(self):
        return self.row


def test_retained_normalization_requires_exact_current_contract_and_source():
    core, event, row = retained()
    cur = Cursor(row)
    assert load_retained_normalized_event(cur, source_event_id=7, source_identity=core) == event
    sql, params = cur.queries[0]
    assert "processing_status='normalized'" in sql
    assert "normalizer_id=%s and normalizer_version=%s" in sql
    assert params == (7, 1, "windows.named-eventdata", "1.4+identity-1.0")
    assert load_retained_normalized_event(Cursor(None), source_event_id=7, source_identity=core) is None


@pytest.mark.parametrize("changed", ["source_hash", "digest", "facts", "roles", "time", "id", "identity_version"])
def test_retained_normalization_conflicts_fail_closed(changed):
    core, _, row = retained()
    row = deepcopy(row)
    if changed == "source_hash":
        row["source_event_sha256"] = b"x" * 32
    elif changed == "digest":
        row["semantic_sha256"] = b"x" * 32
    elif changed == "facts":
        row["facts_json"]["LogonType"] = "10"
    elif changed == "roles":
        row["roles_json"]["source_host"] = "other-fixture"
    elif changed == "time":
        row["occurred_at_utc"] += timedelta(seconds=1)
    elif changed == "id":
        row["normalized_event_id"] = "different-id"
    else:
        row["quality_json"]["identity_resolution_version"] = "old"
    with pytest.raises(RuntimeError, match="retained normalization integrity conflict"):
        load_retained_normalized_event(Cursor(row), source_event_id=7, source_identity=core)


def test_retained_normalization_rejects_different_job_identity_before_read():
    core, _, row = retained()
    cur = Cursor(row)
    with pytest.raises(RuntimeError, match="source identity conflict"):
        load_retained_normalized_event(cur, source_event_id=8, source_identity=core)
    assert cur.queries == []


@pytest.mark.parametrize("source_error", [FileNotFoundError, ArchiveBlockUnavailableError])
@pytest.mark.parametrize("job_kind", ["normalize_event", "semantic_repair"])
def test_worker_resumes_only_ordinary_normalization_from_retained_facts(monkeypatch, source_error, job_kind):
    core, event, row = retained()
    cur = Cursor(row)
    jobs = [{"job_id": "fixture-job", "job_kind": job_kind, "source_event_id": 7,
             "lease_token": "fixture-lease", "attempt_count": 1, "max_attempts": 5,
             "source_identity_json": core}]

    class Connection:
        def transaction(self):
            return nullcontext()

        def cursor(self):
            return nullcontext(cur)

    def missing(*args, **kwargs):
        raise source_error("fixture source unavailable")

    writes = []
    monkeypatch.setattr(runtime, "claim_semantic_jobs", lambda *a, **k: [jobs.pop()] if jobs else [])
    monkeypatch.setattr(runtime, "lock_semantic_source", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "_validate_semantic_repair_job", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "load_semantic_source_event", missing)
    monkeypatch.setattr(runtime, "load_identity_role_overrides", lambda *a, **k: {})
    monkeypatch.setattr(runtime, "persist_normalized_event", lambda *a, **k: writes.append(k["event"]) or normalized_event_id(event))
    monkeypatch.setattr(runtime, "persist_canonical_actions", lambda *a, **k: writes.append("actions"))
    monkeypatch.setattr(runtime, "enqueue_dispatch_jobs", lambda *a, **k: writes.append("dispatch"))
    monkeypatch.setattr(runtime, "complete_semantic_job", lambda *a, **k: writes.append("completed"))
    monkeypatch.setattr(runtime, "fail_semantic_job", lambda *a, **k: writes.append("failed"))
    result = runtime.process_semantic_outbox(Connection(), archive=object(), limit=1,
        settings=SemanticFeatureSettings(normalization_enabled=True, assembly_enabled=True, correlation_enabled=True))
    if job_kind == "normalize_event":
        assert result == {"completed": 1, "failed": 0, "normalized": 1, "actions": 1, "claimed": 1}
        assert writes == [event, "actions", "dispatch", "completed"]
    else:
        assert result["completed"] == 0 and result["failed"] == 1
        assert writes == ["failed"]
        assert cur.queries == []


@pytest.mark.parametrize("source_error", [ArchiveIntegrityError, KeyError])
def test_integrity_failures_never_use_retained_normalization(monkeypatch, source_error):
    core, _, _ = retained()
    job = {"job_id": "fixture", "job_kind": "normalize_event", "source_event_id": 7,
           "source_identity_json": core, "lease_token": "fixture", "attempt_count": 1, "max_attempts": 5}

    def missing(*args, **kwargs):
        raise source_error("fixture integrity failure")

    class Connection:
        def transaction(self):
            return nullcontext()

        def cursor(self):
            return nullcontext(object())

    monkeypatch.setattr(runtime, "claim_semantic_jobs", lambda *a, **k: [job])
    monkeypatch.setattr(runtime, "lock_semantic_source", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "load_semantic_source_event", missing)
    monkeypatch.setattr(runtime, "load_retained_normalized_event", lambda *a, **k: pytest.fail("integrity bypass"))
    monkeypatch.setattr(runtime, "fail_semantic_job", lambda *a, **k: None)
    result = runtime.process_semantic_outbox(Connection(), archive=object(), limit=1,
        settings=SemanticFeatureSettings(normalization_enabled=True))
    assert result["completed"] == 0 and result["failed"] == 1


@pytest.mark.parametrize("retained_state", ["missing", "conflicting"])
def test_worker_requires_retained_proof_before_completion(monkeypatch, retained_state):
    core, _, row = retained()
    if retained_state == "missing":
        row = None
    else:
        row["source_event_sha256"] = b"x" * 32
    cur = Cursor(row)
    job = {"job_id": "fixture", "job_kind": "normalize_event", "source_event_id": 7,
           "source_identity_json": core, "lease_token": "fixture", "attempt_count": 1, "max_attempts": 5}

    def missing(*args, **kwargs):
        raise FileNotFoundError("fixture unavailable source")

    class Connection:
        def transaction(self):
            return nullcontext()

        def cursor(self):
            return nullcontext(cur)

    failures = []
    monkeypatch.setattr(runtime, "claim_semantic_jobs", lambda *a, **k: [job])
    monkeypatch.setattr(runtime, "lock_semantic_source", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "load_semantic_source_event", missing)
    monkeypatch.setattr(runtime, "fail_semantic_job", lambda *a, **k: failures.append(k["error_code"]))
    monkeypatch.setattr(runtime, "complete_semantic_job", lambda *a, **k: pytest.fail("completion without proof"))
    result = runtime.process_semantic_outbox(Connection(), archive=object(), limit=1,
        settings=SemanticFeatureSettings(normalization_enabled=True))
    assert result["completed"] == 0 and result["failed"] == 1
    assert failures == ["FileNotFoundError" if retained_state == "missing" else "RuntimeError"]

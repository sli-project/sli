from __future__ import annotations

from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import signal

import pytest

from server.sli.semantic.semantic_correlation import SemanticRelation
from server.sli.semantic.semantic_processing import (
    NormalizedEvent,
    SemanticFeatureSettings,
)
from server.sli.semantic.semantic_worker_runtime import (
    process_semantic_dispatch,
    process_semantic_outbox,
)


@pytest.fixture(autouse=True)
def _source_transaction_lock_is_external_to_unit_behavior(monkeypatch):
    """Repository lock SQL is covered separately; unit fakes have no DB cursor."""
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.lock_semantic_source",
        lambda _cur, *, source_event_id: None,
    )


class Connection:
    def __init__(self) -> None:
        self.cur = object()

    def transaction(self):
        return nullcontext()

    def cursor(self):
        return nullcontext(self.cur)


def test_processing_stage_normalizes_assembles_and_completes(monkeypatch) -> None:
    claimed = [
        {
            "job_id": "job-1",
            "job_kind": "normalize_event",
            "source_event_id": 7,
            "lease_token": "lease",
            "attempt_count": 1,
            "max_attempts": 5,
            "source_identity_json": {"id": 7},
        }
    ]
    source = {
        "id": 7,
        "event_id": 4719,
        "channel": "Security",
        "computer": "DC1",
        "source_host_id": 1,
        "time_created_utc": "2026-07-29T00:00:00Z",
        "event_data_json": {},
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "correlation_id": None,
    }
    normalized = NormalizedEvent(
        source_event_id=7,
        semantic_type="audit.policy.changed",
        occurred_at_utc=datetime(2026, 7, 29, tzinfo=timezone.utc),
        roles={"source_host": "1"},
        facts={},
        quality={},
        semantic_sha256="1" * 64,
    )
    calls: list[str] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.claim_semantic_jobs",
        lambda _cur, **_kwargs: [claimed.pop(0)] if claimed else [],
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.load_semantic_source_event",
        lambda _cur, *, source_event_id, archive, source_identity: source,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.normalize_semantic_source_payload",
        lambda _source: normalized,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.persist_normalized_event",
        lambda _cur, *, event, source_identity: calls.append("normalized") or "normalized-1",
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.assemble_canonical_actions",
        lambda _events: (),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.persist_canonical_actions",
        lambda _cur, *, actions: calls.append("actions"),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.enqueue_dispatch_jobs",
        lambda _cur, **_kwargs: calls.append("dispatch"),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.complete_semantic_job",
        lambda _cur, **_kwargs: calls.append("completed"),
    )

    result = process_semantic_outbox(
        Connection(),
        archive=object(),
        settings=SemanticFeatureSettings(
            normalization_enabled=True,
            assembly_enabled=True,
            correlation_enabled=True,
        ),
        limit=2,
    )

    assert result == {
        "completed": 1,
        "failed": 0,
        "normalized": 1,
        "actions": 0,
        "claimed": 1,
    }
    assert calls == ["normalized", "actions", "dispatch", "completed"]


def test_semantic_repair_validates_provenance_then_normalizes_as_current_work(monkeypatch) -> None:
    """Repair work is an appended job, never a mutation of its completed source job."""
    job = {
        "job_id": "repair-job",
        "job_kind": "semantic_repair",
        "source_event_id": 7,
        "processor_id": "semantic-shadow",
        "processor_version": "1.4+identity-1.0",
        "lease_token": "lease",
        "attempt_count": 1,
        "max_attempts": 5,
        "source_identity_json": {"id": 7},
        "payload_json": {
            "repair_plan_digest": "a" * 64,
            "history_plan_digest": "b" * 64,
            "original_job_id": "00000000-0000-0000-0000-000000000007",
            "original_source_hash": "c" * 64,
        },
    }
    normalized = NormalizedEvent(
        source_event_id=7,
        semantic_type="audit.policy.changed",
        occurred_at_utc=datetime(2026, 7, 29, tzinfo=timezone.utc),
        roles={}, facts={}, quality={}, semantic_sha256="1" * 64,
    )
    connection = Connection()
    calls: list[str] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.claim_semantic_jobs",
        lambda _cur, **_kwargs: [job],
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime._validate_semantic_repair_job",
        lambda cur, actual_job, payload: (
            calls.append("validated"),
            assert_same_repair_cursor(cur, connection.cur, actual_job, job, payload),
        ),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.load_semantic_source_event",
        lambda *_args, **_kwargs: {"id": 7},
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.normalize_semantic_source_payload",
        lambda _source: normalized,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.persist_normalized_event",
        lambda _cur, **_kwargs: calls.append("normalized") or "normalized-1",
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.complete_semantic_job",
        lambda _cur, **_kwargs: calls.append("completed"),
    )

    result = process_semantic_outbox(
        connection, archive=object(),
        settings=SemanticFeatureSettings(normalization_enabled=True), limit=1,
    )

    assert result == {"completed": 1, "failed": 0, "normalized": 1, "actions": 0, "claimed": 1}
    assert calls == ["validated", "normalized", "completed"]


def assert_same_repair_cursor(cur, expected_cur, actual_job, expected_job, payload) -> None:
    assert cur is expected_cur
    assert actual_job is expected_job
    assert payload is expected_job["payload_json"]


def test_context_expansion_job_publishes_one_bounded_page_and_defers(monkeypatch) -> None:
    claimed = [{
        "job_id": "context-job",
        "job_kind": "investigation_context",
        "source_event_id": 20,
        "lease_token": "lease",
        "attempt_count": 1,
        "max_attempts": 5,
    }]
    calls: list[object] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.claim_semantic_jobs",
        lambda _cur, **_kwargs: [claimed.pop(0)] if claimed else [],
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.select_investigation_context_expansion_ids",
        lambda _cur, *, reset_source_event_id, limit: (
            tuple(range(100, 100 + limit)), True,
        ),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.enqueue_semantic_job",
        lambda _cur, *, source_event_id, payload: calls.append(
            (source_event_id, dict(payload))
        ),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.defer_semantic_job",
        lambda _cur, **kwargs: calls.append(("deferred", kwargs)),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.complete_semantic_job",
        lambda *_args, **_kwargs: calls.append("unexpected-complete"),
    )

    result = process_semantic_outbox(
        Connection(),
        archive=object(),
        settings=SemanticFeatureSettings(normalization_enabled=True),
        limit=2,
    )

    assert result == {"completed": 0, "failed": 0, "normalized": 0, "actions": 0, "claimed": 1}
    assert calls[:2] == [
        (100, {"selection_reason": "late_related_context"}),
        (101, {"selection_reason": "late_related_context"}),
    ]
    assert len(calls) == 101
    assert calls[-1][0] == "deferred"


def test_identity_replay_uses_merge_version_and_records_old_to_new(monkeypatch) -> None:
    merge_id = "00000000-0000-4000-8000-000000000034"
    job = {
        "job_id": "00000000-0000-0000-0000-000000000007",
        "job_kind": "semantic_replay",
        "source_event_id": 7,
        "processor_version": "1.1+identity-1.0+r7-12a0dc8b420b",
        "payload_json": {"identity_merge_id": merge_id},
        "lease_token": "lease",
        "attempt_count": 1,
        "max_attempts": 5,
        "source_identity_json": {"id": 7},
    }
    claimed = [job]
    provisional = NormalizedEvent(
        source_event_id=7,
        semantic_type="group.membership.added",
        occurred_at_utc=datetime(2026, 7, 29, tzinfo=timezone.utc),
        roles={"affected_entity": "sam:corp:user"},
        facts={},
        quality={
            "identity_roles": {
                "affected_entity": {
                    "key": "sam:corp:user",
                    "state": "provisional",
                    "provisional": True,
                }
            }
        },
        semantic_sha256="1" * 64,
    )
    merged = NormalizedEvent(
        **{
            **provisional.__dict__,
            "roles": {"affected_entity": "sid:S-1-5-21-100000001-200000001-300000001-1001"},
            "semantic_sha256": "2" * 64,
        }
    )
    calls: list[str] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.claim_semantic_jobs",
        lambda _cur, *, limit: [claimed.pop(0)] if claimed else [],
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.load_semantic_source_event",
        lambda *_args, **_kwargs: {"id": 7},
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.normalize_semantic_source_payload",
        lambda _source: provisional,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.load_identity_role_overrides",
        lambda _cur, **kwargs: {
            "sam:corp:user": {
                "target_key": "sid:S-1-5-21-100000001-200000001-300000001-1001",
                "merge_id": kwargs["required_merge_id"],
            }
        },
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.prior_identity_normalized_events",
        lambda *_args, **_kwargs: ("00000000-0000-0000-0000-000000000001",),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.apply_identity_role_overrides",
        lambda _event, _overrides: merged,
    )

    def persist(_cur, *, event, normalizer_version, source_identity):
        assert event is merged
        assert normalizer_version == job["processor_version"]
        assert source_identity == {"id": 7}
        calls.append("normalized-v2")
        return "00000000-0000-0000-0000-000000000002"

    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.persist_normalized_event", persist,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.record_identity_semantic_replay",
        lambda _cur, **kwargs: calls.append(f"audit:{kwargs['merge_id']}"),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.enqueue_dispatch_jobs",
        lambda _cur, **_kwargs: calls.append("dispatch"),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.complete_semantic_job",
        lambda _cur, **_kwargs: calls.append("completed"),
    )

    result = process_semantic_outbox(
        Connection(),
        archive=object(),
        settings=SemanticFeatureSettings(
            normalization_enabled=True,
            correlation_enabled=True,
        ),
        limit=2,
    )

    assert result == {"completed": 1, "failed": 0, "normalized": 1, "actions": 0, "claimed": 1}
    assert calls == ["normalized-v2", f"audit:{merge_id}", "dispatch", "completed"]


def test_dispatch_stage_persists_relation_and_completes(monkeypatch) -> None:
    job = {
        "job_id": "dispatch-1",
        "lease_token": "lease",
        "attempt_count": 1,
        "max_attempts": 5,
    }
    claimed = [job]
    work = type(
        "Work",
        (),
        {
            "rule": object(),
                "events": (),
                "is_late": False,
                "trigger_source_event_id": 7,
                "evidence_contract": {},
            },
        )()
    relation = SemanticRelation(
        relation_kind="test",
        source_event_ids=(7,),
        contribution_key="test",
        confidence="low",
        explanation="test",
    )
    calls: list[str] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.claim_dispatch_jobs",
        lambda _cur, **_kwargs: [claimed.pop(0)] if claimed else [],
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.load_dispatch_work_item",
        lambda _cur, **_kwargs: work,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.match_compiled_rule",
        lambda _rule, _events: [relation],
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.persist_dispatched_relation",
        lambda _cur, **_kwargs: calls.append("relation"),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.complete_dispatch_job",
        lambda _cur, **_kwargs: calls.append("completed"),
    )

    result = process_semantic_dispatch(
        Connection(),
        archive=object(),
        settings=SemanticFeatureSettings(
            normalization_enabled=True,
            assembly_enabled=True,
            correlation_enabled=True,
        ),
        limit=2,
        complete_job=lambda _cur, **_kwargs: calls.append("recovery-completed"),
    )

    assert result == {"completed": 1, "failed": 0, "relations": 1, "claimed": 1}
    assert calls == ["relation", "recovery-completed"]


def test_processing_stage_forwards_exact_source_event_claim_scope(monkeypatch) -> None:
    claims: list[dict] = []

    def claim(_cur, **kwargs):
        claims.append(kwargs)
        return []

    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.claim_semantic_jobs",
        claim,
    )

    result = process_semantic_outbox(
        Connection(),
        archive=object(),
        settings=SemanticFeatureSettings(normalization_enabled=True),
        limit=16,
        source_event_ids=[9, 7],
    )

    assert result == {
        "completed": 0,
        "failed": 0,
        "normalized": 0,
        "actions": 0,
        "claimed": 0,
    }
    assert claims == [{"limit": 1, "source_event_ids": [9, 7]}]


def test_dispatch_accepts_bounded_claim_function(monkeypatch) -> None:
    claims: list[dict] = []

    def claim(_cur, **kwargs):
        claims.append(kwargs)
        return []

    result = process_semantic_dispatch(
        Connection(), archive=object(),
        settings=SemanticFeatureSettings(correlation_enabled=True),
        limit=1, allowed_job_ids=["job-1"], claim_jobs=claim,
    )

    assert result == {"completed": 0, "failed": 0, "relations": 0, "claimed": 0}
    assert claims == [{
        "limit": 1, "allowed_rule_ids": None,
        "allowed_rule_identities": None, "allowed_job_ids": ["job-1"],
    }]


@pytest.mark.parametrize("stage", ["processing", "dispatch"])
@pytest.mark.parametrize("queued,limit,expected", [(40, 40, 40), (140, 10000, 128), (20, 7, 7), (3, 128, 3)])
@pytest.mark.parametrize("sig", [None, signal.SIGTERM, signal.SIGINT])
def test_batches_keep_claim_process_complete_order(monkeypatch, stage, queued, limit, expected, sig):
    from types import SimpleNamespace
    from server.sli.ops import shutdown
    from server.sli.semantic import semantic_worker_runtime as runtime

    pending = list(range(1, queued + 1))
    calls = []

    def claim(_cur, **kwargs):
        assert kwargs["limit"] == 1
        if not pending:
            return []
        source_id = pending.pop(0)
        calls.append(("claim", source_id))
        return [{"job_id": str(source_id), "source_event_id": source_id,
                 "job_kind": "normalize_event", "lease_token": "lease",
                 "attempt_count": 1, "max_attempts": 5}]

    def persist(_cur, **kwargs):
        calls.append(("persist", kwargs["event"].source_event_id))
        if sig is not None:
            signal.raise_signal(sig)
        return "normalized"

    def complete(_cur, **kwargs):
        assert kwargs["lease_token"] == "lease"
        calls.append(("complete", int(kwargs["job_id"])))

    monkeypatch.setattr(runtime, "claim_semantic_jobs", claim)
    monkeypatch.setattr(runtime, "claim_dispatch_jobs", claim)
    monkeypatch.setattr(runtime, "load_semantic_source_event", lambda _cur, **kw: kw["source_event_id"])
    monkeypatch.setattr(runtime, "normalize_semantic_source_payload",
                        lambda source: SimpleNamespace(source_event_id=source))
    monkeypatch.setattr(runtime, "load_identity_role_overrides", lambda *args, **kw: {})
    monkeypatch.setattr(runtime, "apply_identity_role_overrides", lambda event, _overrides: event)
    monkeypatch.setattr(runtime, "persist_normalized_event", persist)
    monkeypatch.setattr(runtime, "complete_semantic_job", complete)
    monkeypatch.setattr(runtime, "complete_dispatch_job", complete)
    monkeypatch.setattr(runtime, "load_dispatch_work_item", lambda _cur, **kw: SimpleNamespace(
        rule=int(kw["job_id"]), events=(), is_late=False, evidence_contract={}))
    def match(rule, _events):
        calls.append(("persist", rule))
        if sig is not None:
            signal.raise_signal(sig)
        return []

    monkeypatch.setattr(runtime, "match_compiled_rule", match)
    process = runtime.process_semantic_outbox if stage == "processing" else runtime.process_semantic_dispatch
    with shutdown.graceful_shutdown():
        result = process(Connection(), archive=object(), limit=limit, settings=SemanticFeatureSettings(
            normalization_enabled=stage == "processing", correlation_enabled=stage == "dispatch"))

    if sig is not None:
        expected = 1

    assert result["completed"] == result["claimed"] == expected
    assert result["failed"] == 0
    assert calls == [(operation, source) for source in range(1, expected + 1)
                     for operation in ("claim", "persist", "complete")]
    assert pending == list(range(expected + 1, queued + 1))


def test_batch_rolls_back_failed_job_before_claiming_next(monkeypatch):
    from types import SimpleNamespace
    from server.sli.semantic import semantic_worker_runtime as runtime

    writes = []
    failed = []
    pending = [1, 2, 3]

    class TransactionalConnection(Connection):
        @contextmanager
        def transaction(self):
            before = writes[:]
            try:
                yield
            except Exception:
                writes[:] = before
                raise

    def claim(_cur, **kwargs):
        if not pending:
            return []
        source = pending.pop(0)
        if source == 3:
            assert writes == [("normalized", 1), ("completed", 1)]
            assert failed == [2]
        return [{"job_id": str(source), "source_event_id": source, "job_kind": "normalize_event",
                 "lease_token": "lease", "attempt_count": 1, "max_attempts": 5}]

    def complete(_cur, **kwargs):
        source = int(kwargs["job_id"])
        if source == 2:
            raise RuntimeError("fixture completion failure")
        writes.append(("completed", source))

    def fail(_cur, **kwargs):
        assert kwargs["lease_token"] == "lease"
        assert kwargs["attempt_count"] == 1
        assert kwargs["max_attempts"] == 5
        failed.append(int(kwargs["job_id"]))

    monkeypatch.setattr(runtime, "claim_semantic_jobs", claim)
    monkeypatch.setattr(runtime, "load_semantic_source_event", lambda _cur, **kw: kw["source_event_id"])
    monkeypatch.setattr(runtime, "normalize_semantic_source_payload",
                        lambda source: SimpleNamespace(source_event_id=source))
    monkeypatch.setattr(runtime, "load_identity_role_overrides", lambda *args, **kw: {})
    monkeypatch.setattr(runtime, "apply_identity_role_overrides", lambda event, _overrides: event)
    monkeypatch.setattr(runtime, "persist_normalized_event",
                        lambda _cur, **kw: writes.append(("normalized", kw["event"].source_event_id)))
    monkeypatch.setattr(runtime, "complete_semantic_job", complete)
    monkeypatch.setattr(runtime, "fail_semantic_job", fail)

    result = process_semantic_outbox(TransactionalConnection(), archive=object(), limit=128,
                                     settings=SemanticFeatureSettings(normalization_enabled=True))

    assert result == {"completed": 2, "failed": 1, "normalized": 2, "actions": 0, "claimed": 3}
    assert writes == [("normalized", 1), ("completed", 1), ("normalized", 3), ("completed", 3)]


@pytest.mark.parametrize("result,expected", [
    ({"completed": 1}, True),
    ({"failed": 1}, True),
    ({"risk_queued": 1}, True),
    ({"processing": {"claimed": 1, "completed": 0, "failed": 0}}, True),
    ({"dispatch": {"claimed": 1}}, True),
    ({"completed": 0, "failed": 0, "processing": {"claimed": 0}}, False),
])
def test_cycle_activity_includes_deferred_context_and_failures(result, expected):
    from server.sli.semantic.semantic_worker_runtime import semantic_cycle_has_work

    assert semantic_cycle_has_work(result) is expected

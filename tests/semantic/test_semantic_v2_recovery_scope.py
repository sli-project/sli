from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone

import pytest

from server.sli.semantic.semantic_processing import NormalizedEvent, SemanticFeatureSettings
from server.sli.semantic.semantic_worker_runtime import process_semantic_outbox


class Connection:
    def __init__(self) -> None:
        self.cur = object()
        self.closed = False

    def transaction(self):
        return nullcontext()

    def cursor(self):
        return nullcontext(self.cur)

    def close(self) -> None:
        self.closed = True


def _investigation_settings() -> SemanticFeatureSettings:
    return SemanticFeatureSettings(
        normalization_enabled=True,
        assembly_enabled=True,
        correlation_enabled=True,
        risk_engine_enabled=False,
        finding_creation_enabled=False,
    )


@pytest.mark.parametrize("limit,expected", [(1, 1), (128, 16)])
def test_recovery_only_outbox_claims_exact_digest_and_never_enqueues_dispatch(monkeypatch, limit, expected) -> None:
    from server.sli.semantic.semantic_processing_repository import SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND

    digest = "a" * 64
    job = {
        "job_id": "repair-job", "job_kind": SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
        "source_event_id": 7, "lease_token": "lease", "attempt_count": 1,
        "max_attempts": 5, "source_identity_json": {"id": 7},
        "payload_json": {"repair_plan_digest": digest},
    }
    normalized = NormalizedEvent(
        source_event_id=7, semantic_type="audit.policy.changed",
        occurred_at_utc=datetime(2026, 7, 29, tzinfo=timezone.utc),
        roles={}, facts={}, quality={}, semantic_sha256="1" * 64,
    )
    claimed: list[dict[str, object]] = []
    calls: list[str] = []
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.claim_semantic_jobs",
        lambda _cur, **kwargs: claimed.append(dict(kwargs)) or [job],
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.lock_semantic_source",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime._validate_semantic_v2_quarantine_repair_job",
        lambda *_args: calls.append("validated"),
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
        lambda *_args, **_kwargs: calls.append("normalized") or "normalized-1",
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.load_identity_role_overrides",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.apply_identity_role_overrides",
        lambda event, _overrides: event,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.enqueue_dispatch_jobs",
        lambda *_args, **_kwargs: pytest.fail("recovery-only path must not enqueue dispatch"),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.complete_semantic_job",
        lambda *_args, **_kwargs: calls.append("completed"),
    )

    result = process_semantic_outbox(
        Connection(), archive=object(),
        settings=SemanticFeatureSettings(normalization_enabled=True, correlation_enabled=True), limit=limit,
        repair_plan_digest=digest,
    )

    assert result == {"completed": expected, "failed": 0, "normalized": expected, "actions": 0, "claimed": expected}
    assert claimed == [{"limit": 1, "repair_plan_digest": digest}] * expected
    assert calls == ["validated", "normalized", "completed"] * expected


def test_recovery_only_outbox_rejects_claimed_job_with_another_digest_before_archive(monkeypatch) -> None:
    from server.sli.semantic.semantic_processing_repository import SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND

    job = {
        "job_id": "repair-job", "job_kind": SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
        "source_event_id": 7, "lease_token": "lease", "attempt_count": 1,
        "max_attempts": 5, "source_identity_json": {"id": 7},
        "payload_json": {"repair_plan_digest": "b" * 64},
    }
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.claim_semantic_jobs",
        lambda *_args, **_kwargs: [job],
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.lock_semantic_source",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.load_semantic_source_event",
        lambda *_args, **_kwargs: pytest.fail("wrong digest must fail before archive access"),
    )
    monkeypatch.setattr(
        "server.sli.semantic.semantic_worker_runtime.fail_semantic_job",
        lambda *_args, **_kwargs: "failed",
    )

    result = process_semantic_outbox(
        Connection(), archive=object(), settings=_investigation_settings(), limit=1,
        repair_plan_digest="a" * 64,
    )

    assert result == {"completed": 0, "failed": 1, "normalized": 0, "actions": 0, "claimed": 1}


@pytest.mark.parametrize("limit,expected", [(1, 1), (128, 16)])
def test_recovery_runtime_requires_investigation_and_skips_dispatch_risk_and_findings(monkeypatch, limit, expected) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    digest = "a" * 64
    connection = Connection()
    outbox_calls: list[dict[str, object]] = []
    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", runtime.INVESTIGATION_MODE)
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings, "from_env", classmethod(lambda cls: _investigation_settings()),
    )
    monkeypatch.setattr(runtime, "prepare_production_connection", lambda *_args, **_kwargs: _investigation_settings())
    monkeypatch.setattr(
        connection, "cursor",
        lambda: pytest.fail("scoped repair must not access finding governance"),
    )
    monkeypatch.setattr(
        runtime, "process_semantic_outbox",
        lambda *_args, **kwargs: outbox_calls.append(dict(kwargs)) or {
            "completed": 1, "failed": 0, "normalized": 1, "actions": 1,
        },
    )
    monkeypatch.setattr(runtime, "process_semantic_dispatch", lambda *_args, **_kwargs: pytest.fail("scoped repair must not dispatch"))
    monkeypatch.setattr(runtime, "enqueue_risk_backlog", lambda *_args, **_kwargs: pytest.fail("scoped repair must not queue risk"))

    result = runtime.run_once(
        limit=limit, connect_factory=lambda: connection, archive=object(), repair_plan_digest=digest,
    )

    assert outbox_calls[0]["repair_plan_digest"] == digest
    assert outbox_calls[0]["limit"] == expected
    assert runtime.MAX_LIMIT == 16
    assert result["repair_scope"] == {
        "job_kind": "semantic_v2_quarantine_repair", "repair_plan_digest": digest,
    }
    assert result["dispatch"] == {"completed": 0, "failed": 0, "relations": 0}
    assert result["risk_queued"] == 0
    assert result["findings_created"] == 0
    assert connection.closed is True


def test_recovery_runtime_rejects_non_investigation_mode_before_connect(monkeypatch) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", runtime.FACTS_MODE)

    with pytest.raises(RuntimeError, match="investigation"):
        runtime.run_once(
            limit=1,
            connect_factory=lambda: pytest.fail("scope check must precede connection"),
            archive=object(),
            repair_plan_digest="a" * 64,
        )


def test_recovery_heartbeat_and_controller_gate_bind_the_exact_scope_digest(monkeypatch) -> None:
    from scripts.maintenance import semantic_production_control as control
    from scripts.runtime import semantic_production_worker as worker

    digest = "a" * 64
    details = worker._details(
        limit=1, runtime_mode=control.INVESTIGATION_MODE, repair_plan_digest=digest,
    )
    assert details["repair_scope"] == {
        "job_kind": "semantic_v2_quarantine_repair", "repair_plan_digest": digest,
    }

    monkeypatch.setattr(control, "semantic_worker_release_fingerprint", lambda: "f" * 64)
    details["processing_contract"]["release_fingerprint"] = "f" * 64

    class Cursor:
        def execute(self, *_args, **_kwargs) -> None:
            return None

        def fetchone(self):
            return {"details_json": details}

    control._require_v2_repair_worker(Cursor(), repair_plan_digest=digest)
    with pytest.raises(RuntimeError, match="scope"):
        control._require_v2_repair_worker(Cursor(), repair_plan_digest="b" * 64)

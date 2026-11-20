from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
    issue_controller_authorization,
)


def _controller_authorization() -> CutoverAuthorization:
    return issue_controller_authorization("a" * 64)


def _queue_access() -> dict:
    return {"reports": [{"report_key": "security.queue", "allowed": True, "allowed_actions": ["view"],
                         "grants": [{"scope": {"kind": "all"}, "allowed_actions": ["view"], "field_categories": ["security"]}]}]}


def _patch_server_boot(monkeypatch, http_server, received: list[object]) -> None:
    from server.sli.semantic import findings_pg_pipeline
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.storage import storage_lifecycle

    class Server:
        adlog_tls_enabled = False

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            return None

    monkeypatch.delenv("ADLOG_RESTORE_SMOKE_MODE", raising=False)
    monkeypatch.setattr(http_server, "_load_server_tls_context", lambda: None)
    monkeypatch.setattr(http_server, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(http_server, "load_config", lambda: SimpleNamespace(db_backend="postgres"))
    monkeypatch.setattr(http_server, "require_postgres_runtime", lambda cfg: cfg)
    monkeypatch.setattr(postgres_runtime_pipeline, "ensure_cursor_audit_schema_pg", lambda: None)
    monkeypatch.setattr(http_server, "ensure_auth_schema", lambda: None)
    monkeypatch.setattr(
        findings_pg_pipeline,
        "ensure_findings_pg_schema",
        lambda **kwargs: received.append(kwargs.get("authorization")) or {"status": "unavailable"},
    )
    monkeypatch.setattr(storage_lifecycle, "ensure_storage_lifecycle_schema", lambda: {})
    monkeypatch.setattr(http_server, "recover_stale_post_collection_jobs", lambda: {})
    monkeypatch.setattr(http_server, "external_post_collection_worker_enabled", lambda: True)
    monkeypatch.setattr(http_server, "cleanup_post_collection_jobs", lambda: {})
    monkeypatch.setattr(http_server, "get_scheduler_runtime_status", lambda: {"scheduler_enabled": False})
    monkeypatch.setattr(http_server, "ProtectedHTTPServer", lambda *_args, **_kwargs: Server())
    monkeypatch.setattr(http_server, "warm_dashboard_snapshot_async", lambda: None)
    monkeypatch.setattr(http_server, "warm_system_health_storage_async", lambda: None)


def test_v2_authorized_http_startup_does_not_default_findings_bootstrap_to_v1(monkeypatch) -> None:
    """Changing run_server to omit this capability must fail this test."""
    from server.api import http_server

    received: list[object] = []
    _patch_server_boot(monkeypatch, http_server, received)
    authorization = _controller_authorization()

    http_server.run_server("127.0.0.1", 0, storage_route_authorization=authorization)

    assert received == [authorization]


def test_pre_cutover_http_startup_keeps_the_v1_default(monkeypatch) -> None:
    """Changing an absent capability into V2 selection must fail this test."""
    from server.api import http_server

    received: list[object] = []
    _patch_server_boot(monkeypatch, http_server, received)

    http_server.run_server("127.0.0.1", 0)

    assert received == [None]


def test_v2_authorized_background_findings_refresh_receives_the_same_capability(monkeypatch, tmp_path: Path) -> None:
    """Changing the post-collection caller to drop V2 authority must fail this test."""
    from server.jobs import collector

    authorization = _controller_authorization()
    now = collector.utc_now()
    job = collector.Job(
        id=9910,
        kind="post_collection",
        status="completed",
        servers=["DC1"],
        hours=1,
        max_events_per_channel=1,
        created_at=now,
        updated_at=now,
        collection_status="completed",
    )
    with collector._lock:
        collector._jobs[job.id] = job

    received: list[object] = []
    monkeypatch.setattr(collector, "update_post_collection_job", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(collector, "update_post_collection_findings", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(collector, "legacy_findings_enabled", lambda: True)
    monkeypatch.setattr(
        collector,
        "refresh_findings_from_events",
        lambda **kwargs: received.append(kwargs.get("authorization")) or {
            "status": "unavailable",
            "reason": "storage_v2_findings_evidence_adapter_unavailable",
        },
    )
    monkeypatch.setattr(collector, "_generate_report_with_heartbeat", lambda **_kwargs: tmp_path / "report.html")
    monkeypatch.setattr(collector, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(collector, "log_internal_error", lambda *_args, **_kwargs: "ERR")
    monkeypatch.setattr(collector, "log_performance_stage", lambda *_args, **_kwargs: None)

    try:
        collector._run_post_collection_job(
            job.id,
            job.servers,
            "trace",
            authorization=authorization,
        )
    finally:
        with collector._lock:
            collector._jobs.pop(job.id, None)

    assert received == [authorization]


def test_authorized_manual_analysis_forwards_route_to_report_generation(monkeypatch, tmp_path: Path) -> None:
    """The asynchronous analysis entry point must not drop a selected V2 route."""
    from server.jobs import collector

    authorization = _controller_authorization()
    now = collector.utc_now()
    job = collector.Job(
        id=9911,
        kind="analysis",
        status="queued",
        servers=["DC1"],
        hours=0,
        max_events_per_channel=0,
        created_at=now,
        updated_at=now,
    )
    report = tmp_path / "report.html"
    report.write_text("ok", encoding="utf-8")
    received: list[object] = []
    with collector._lock:
        collector._jobs[job.id] = job
    monkeypatch.setattr(
        collector,
        "generate_recommendation_report",
        lambda *_args, **kwargs: received.append(kwargs.get("authorization")) or report,
    )
    monkeypatch.setattr(collector, "log_event", lambda *_args, **_kwargs: None)

    try:
        collector._run_analysis_job(job.id, authorization=authorization)
    finally:
        with collector._lock:
            collector._jobs.pop(job.id, None)

    assert received == [authorization]


def test_pre_cutover_manual_analysis_passes_the_explicit_v1_selection(monkeypatch, tmp_path: Path) -> None:
    """The analysis caller must never erase its route-selection argument."""
    from server.jobs import collector

    now = collector.utc_now()
    job = collector.Job(
        id=9914,
        kind="analysis",
        status="queued",
        servers=["DC1"],
        hours=0,
        max_events_per_channel=0,
        created_at=now,
        updated_at=now,
    )
    report = tmp_path / "report.html"
    report.write_text("ok", encoding="utf-8")
    received: list[dict[str, object]] = []
    with collector._lock:
        collector._jobs[job.id] = job
    monkeypatch.setattr(
        collector,
        "generate_recommendation_report",
        lambda *_args, **kwargs: received.append(kwargs) or report,
    )
    monkeypatch.setattr(collector, "log_event", lambda *_args, **_kwargs: None)

    try:
        collector._run_analysis_job(job.id, authorization=None)
    finally:
        with collector._lock:
            collector._jobs.pop(job.id, None)

    assert received == [{"authorization": None}]


def test_authorized_post_collection_report_heartbeat_forwards_route(monkeypatch, tmp_path: Path) -> None:
    """The heartbeat wrapper is a report consumer and must preserve V2 ownership."""
    from server.jobs import collector

    authorization = _controller_authorization()
    report = tmp_path / "report.html"
    report.write_text("ok", encoding="utf-8")
    received: list[object] = []
    monkeypatch.setattr(
        collector,
        "generate_recommendation_report",
        lambda *_args, **kwargs: received.append(kwargs.get("authorization")) or report,
    )
    monkeypatch.setattr(collector, "heartbeat_post_collection_job", lambda *_args, **_kwargs: None)

    result = collector._generate_report_with_heartbeat(
        job_id=9912,
        servers=["DC1"],
        durable_job_id="durable-9912",
        worker_id="worker-9912",
        authorization=authorization,
    )

    assert result == report
    assert received == [authorization]


def test_pre_cutover_post_collection_report_passes_the_explicit_v1_selection(monkeypatch, tmp_path: Path) -> None:
    """The heartbeat wrapper must preserve the route argument even for V1."""
    from server.jobs import collector

    report = tmp_path / "report.html"
    report.write_text("ok", encoding="utf-8")
    received: list[dict[str, object]] = []
    monkeypatch.setattr(
        collector,
        "generate_recommendation_report",
        lambda *_args, **kwargs: received.append(kwargs) or report,
    )
    monkeypatch.setattr(collector, "heartbeat_post_collection_job", lambda *_args, **_kwargs: None)

    result = collector._generate_report_with_heartbeat(
        job_id=9915,
        servers=["DC1"],
        durable_job_id="durable-9915",
        worker_id="worker-9915",
        authorization=None,
    )

    assert result == report
    assert len(received) == 1
    assert received[0]["authorization"] is None
    assert callable(received[0]["report_writer"])


def test_authorized_external_post_collection_worker_forwards_route(monkeypatch) -> None:
    """The independent worker only forwards an explicitly supplied controller capability."""
    from scripts.runtime import post_collection_worker

    authorization = _controller_authorization()
    received: list[object] = []
    monkeypatch.setattr(post_collection_worker, "_worker_id", lambda: "worker-9913")
    monkeypatch.setattr(post_collection_worker, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(post_collection_worker, "record_worker_heartbeat", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        post_collection_worker,
        "run_persisted_post_collection_worker_once",
        lambda **kwargs: received.append(kwargs.get("authorization")) or {"claimed": 0, "completed": 0, "failed": 0},
    )

    assert post_collection_worker._run_locked(
        once=True,
        poll_seconds=1,
        limit=1,
        authorization=authorization,
    ) == 0
    assert received == [authorization]


def test_pre_cutover_external_worker_passes_the_explicit_v1_selection(monkeypatch) -> None:
    """The external durable-worker boundary must retain its route argument."""
    from scripts.runtime import post_collection_worker

    received: list[dict[str, object]] = []
    monkeypatch.setattr(post_collection_worker, "_worker_id", lambda: "worker-9916")
    monkeypatch.setattr(post_collection_worker, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(post_collection_worker, "record_worker_heartbeat", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        post_collection_worker,
        "run_persisted_post_collection_worker_once",
        lambda **kwargs: received.append(kwargs) or {"claimed": 0, "completed": 0, "failed": 0},
    )

    assert post_collection_worker._run_locked(
        once=True,
        poll_seconds=1,
        limit=1,
        authorization=None,
    ) == 0
    assert len(received) == 1
    assert received[0]["worker_id"] == "worker-9916"
    assert received[0]["limit"] == 1
    assert callable(received[0]["progress_callback"])
    assert received[0]["authorization"] is None


def test_external_post_collection_worker_rejects_unvalidated_transition(monkeypatch) -> None:
    """An unsealed transition value must stop before the worker can claim V1 work."""
    from scripts.runtime import post_collection_worker
    from server.sli.storage.runtime_storage import StorageRouteAuthorizationError

    monkeypatch.setattr(
        post_collection_worker,
        "run_persisted_post_collection_worker_once",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("V1 worker must not run")),
    )

    with pytest.raises(
        StorageRouteAuthorizationError,
        match="storage_transition_authorization_invalid",
    ):
        post_collection_worker._run_locked(
            once=True,
            poll_seconds=1,
            limit=1,
            authorization=object(),
        )


def test_findings_route_forwards_only_the_handler_controller_capability(monkeypatch) -> None:
    """A Findings request cannot choose a storage route from query parameters."""
    from server.api.routes import findings

    authorization = _controller_authorization()
    received: dict[str, object] = {}

    class Handler:
        storage_route_authorization = authorization

        def _access_decision(self):
            return _queue_access()

        def _send_json(self, payload, *_args) -> None:
            received["payload"] = payload

    monkeypatch.setattr(
        findings,
        "get_security_problems_data",
        lambda **kwargs: received.update(authorization=kwargs.get("authorization")) or {"items": []},
    )

    findings._handle_findings_api(Handler(), {"source": ["semantic-production"], "route": ["v1"]})

    assert received["authorization"] is authorization
    assert received["payload"] == {"items": []}


def test_pre_cutover_findings_route_passes_the_explicit_v1_selection(monkeypatch) -> None:
    """An unset handler route is an explicit pre-transition V1 selection."""
    from server.api.routes import findings

    received: dict[str, object] = {}

    class Handler:
        storage_route_authorization = None

        def _access_decision(self):
            return _queue_access()

        def _send_json(self, payload, *_args) -> None:
            received["payload"] = payload

    monkeypatch.setattr(
        findings,
        "get_security_problems_data",
        lambda **kwargs: received.update(kwargs=kwargs) or {"items": []},
    )

    findings._handle_findings_api(Handler(), {"source": ["semantic-production"]})

    assert received["kwargs"] == {
        "status": None,
        "severity": None,
        "q": None,
        "limit": 200,
        "time_from": None,
        "time_to": None,
        "risk": None,
        "domain_ids": None,
        "authorization": None,
    }


def test_findings_route_rejects_an_invalid_selected_transition_before_v1_read(monkeypatch) -> None:
    """A malformed server state cannot make Findings silently query V1."""
    from server.api.routes import findings
    from server.sli.storage.runtime_storage import StorageRouteAuthorizationError

    class Handler:
        storage_route_authorization = object()

        def _access_decision(self):
            return _queue_access()

    monkeypatch.setattr(
        findings,
        "get_security_problems_data",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("V1 Findings read must not run")),
    )

    with pytest.raises(
        StorageRouteAuthorizationError,
        match="storage_transition_authorization_invalid",
    ):
        findings._handle_findings_api(Handler(), {"source": ["semantic-production"]})


def test_v2_findings_read_uses_canonical_rows_without_v1_event_queries(monkeypatch) -> None:
    """Selected V2 reads canonical findings and enriches evidence from V2."""
    from server.sli.semantic import findings

    statements: list[str] = []

    def query_rows(sql, *_args, **_kwargs):
        normalized = " ".join(sql.lower().split())
        statements.append(normalized)
        return [{"id": 7, "status": "new", "severity": "high"}] if normalized.startswith(
            "select * from findings_active"
        ) else []

    monkeypatch.setattr(findings, "query_rows", query_rows)
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda *_args: True)
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_kwargs: {"status": "ok"})

    result = findings.get_findings_data(authorization=_controller_authorization())

    combined = "\n".join(statements)
    assert result["status"] == "ok"
    assert result["items"][0]["id"] == 7
    assert "events_v2_core" in combined
    assert "join events e" not in combined

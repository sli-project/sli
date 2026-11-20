from __future__ import annotations

from pathlib import Path

import pytest

from server.sli.semantic import findings_pg_pipeline as pipeline


def test_event_candidate_builds_stable_fingerprint_and_entities() -> None:
    row = {
        "id": 101,
        "event_id": 4740,
        "time_created_utc": "2026-07-12T00:00:00+00:00",
        "target_domain_name": "EXAMPLE",
        "target_user_name": "alice",
        "subject_domain_name": "EXAMPLE",
        "subject_user_name": "dc1$",
        "ip_address": "192.0.2.5",
        "workstation_name": "WS01",
        "computer": "DC1",
        "hostname": "DC1",
    }
    item = pipeline._event_candidate(
        row,
        rules={4740: ("account_lockout", "Lockout", "medium", "why")},
        event_label=lambda value: f"Event {value}",
        principal=lambda domain, user: f"{domain}\\{user}" if user else None,
        recommendation=lambda _rule: "check",
    )
    assert item is not None
    assert item["fingerprint"] == "account_lockout|EXAMPLE\\alice|DC1|4740"
    assert item["event_db_id"] == 101
    assert {entity["entity_role"] for entity in item["entities"]} == {"target", "actor", "source"}


class _FakeCursor:
    def __init__(self, conn: "_FakeConnection") -> None:
        self.conn = conn
        self.rows: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql: str, params=()):
        normalized = " ".join(sql.split()).lower()
        if "select * from findings_refresh_state" in normalized and "for update" in normalized:
            self.rows = [dict(self.conn.pending)]
        elif "from events_v2_core e" in normalized and "where e.id >" in normalized:
            self.rows = [{"id": 11, "event_id": 9999}]
        elif "update findings_refresh_state" in normalized and "set last_event_id=" in normalized:
            self.conn.pending["last_event_id"] = int(params[0])
            self.rows = []
        else:
            raise AssertionError(f"unexpected SQL in rollback test: {normalized}")
        return self

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)


class _FakeConnection:
    def __init__(self) -> None:
        self.persisted = {"pipeline_name": pipeline.PIPELINE_NAME, "last_event_id": 10}
        self.pending = dict(self.persisted)

    def __enter__(self):
        self.pending = dict(self.persisted)
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.persisted = dict(self.pending)
        return False

    def cursor(self):
        return _FakeCursor(self)


def test_legacy_event_rule_cannot_publish_without_admitted_policy(monkeypatch) -> None:
    from server.sli.core import postgres_runtime_pipeline

    class Cursor(_FakeCursor):
        def execute(self, sql, params=()):
            if "from events_v2_core e" in sql:
                self.rows = [{"id": 11, "event_id": 4740}]
                return self
            return super().execute(sql, params)

    class Connection(_FakeConnection):
        def cursor(self):
            return Cursor(self)

    conn = Connection()
    monkeypatch.setattr(pipeline, "ensure_findings_pg_schema", lambda **kwargs: {})
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: conn)
    monkeypatch.setattr(pipeline, "_record_failure", lambda **kwargs: None)
    monkeypatch.setattr(pipeline, "_v2_findings_route_selected", lambda *args: True)
    with pytest.raises(RuntimeError, match="admitted semantic policy"):
        pipeline.refresh_findings_postgres(
            rules={4740: ("test.lockout", "Test observation", "critical", "test hint")},
            event_label=str, principal=lambda *args: None, recommendation=lambda *args: "Review evidence")
    assert conn.persisted["last_event_id"] == 10


def test_failure_before_commit_does_not_advance_watermark(monkeypatch) -> None:
    from server.sli.core import postgres_runtime_pipeline

    conn = _FakeConnection()
    monkeypatch.setattr(pipeline, "ensure_findings_pg_schema", lambda **_kwargs: {})
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: conn)
    monkeypatch.setattr(pipeline, "_record_failure", lambda **_kwargs: None)
    monkeypatch.setattr(
        pipeline,
        "_before_findings_refresh_commit",
        lambda _result: (_ for _ in ()).throw(RuntimeError("before commit")),
    )

    with pytest.raises(RuntimeError, match="before commit"):
        pipeline.refresh_findings_postgres(
            rules={4740: ("account_lockout", "Lockout", "medium", "why")},
            event_label=str,
            principal=lambda _domain, _user: None,
            recommendation=lambda _rule: "check",
            limit=100,
        )

    assert conn.persisted["last_event_id"] == 10


def test_v2_refresh_scans_canonical_core_and_advances_same_bounded_watermark(monkeypatch) -> None:
    from server.sli.core import postgres_runtime_pipeline

    statements = []

    class Cursor(_FakeCursor):
        def execute(self, sql: str, params=()):
            normalized = " ".join(sql.split()).lower()
            statements.append(normalized)
            if "select * from findings_refresh_state" in normalized and "for update" in normalized:
                self.rows = [dict(self.conn.pending)]
            elif "from events_v2_core e" in normalized and "where e.id >" in normalized:
                self.rows = [{"id": 11, "event_id": 9999}]
            elif "update findings_refresh_state" in normalized and "set last_event_id=" in normalized:
                self.conn.pending["last_event_id"] = int(params[0])
                self.rows = []
            else:
                raise AssertionError(f"unexpected SQL in V2 refresh test: {normalized}")
            return self

    class Connection(_FakeConnection):
        def cursor(self):
            return Cursor(self)

    conn = Connection()
    authorization = object()
    monkeypatch.setattr(pipeline, "ensure_findings_pg_schema", lambda **_kwargs: {})
    monkeypatch.setattr(
        pipeline, "_v2_findings_route_selected", lambda value: value is authorization,
    )
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: conn)

    result = pipeline.refresh_findings_postgres(
        rules={}, event_label=str, principal=lambda _domain, _user: None,
        recommendation=lambda _rule: "check", limit=100,
        authorization=authorization,
    )

    assert result["status"] == "ok"
    assert result["watermark_after"] == 11
    assert conn.persisted["last_event_id"] == 11
    assert any("from events_v2_core e" in sql for sql in statements)
    assert all("from events e" not in sql for sql in statements)


def test_findings_failure_is_isolated_from_collection_and_report(monkeypatch, tmp_path: Path) -> None:
    from server.jobs import collector

    now = collector.utc_now()
    job = collector.Job(
        id=9901,
        kind="collect_all_dc_logs:scheduled",
        status="completed",
        servers=["DC1"],
        hours=1,
        max_events_per_channel=1000,
        created_at=now,
        updated_at=now,
        collection_status="completed",
    )
    with collector._lock:
        collector._jobs[job.id] = job

    monkeypatch.setattr(collector, "update_post_collection_job", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "update_post_collection_findings", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        collector,
        "heartbeat_post_collection_job",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("heartbeat unavailable")),
    )
    monkeypatch.setattr(collector, "legacy_findings_enabled", lambda: True)
    monkeypatch.setattr(collector, "refresh_findings_from_events", lambda: (_ for _ in ()).throw(RuntimeError("findings unavailable")))
    monkeypatch.setattr(collector, "generate_recommendation_report", lambda *args, **kwargs: tmp_path / "report.html")
    monkeypatch.setattr(
        collector,
        "_generate_report_with_heartbeat",
        lambda **_kwargs: tmp_path / "report.html",
    )
    monkeypatch.setattr(collector, "log_internal_error", lambda _component, code, *_args, **_kwargs: f"ERR-{code}")
    monkeypatch.setattr(collector, "log_performance_stage", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)

    collector._run_post_collection_job(job.id, job.servers, "trace")
    result = collector.get_job(job.id)

    assert result["status"] == "completed"
    assert result["collection_status"] == "completed"
    assert result["findings_status"] == "failed"
    assert result["report_status"] == "completed"
    assert result["analysis_status"] == "completed_with_findings_warning"


def test_outer_failure_moves_running_findings_to_terminal_failed(monkeypatch) -> None:
    from server.jobs import collector

    now = collector.utc_now()
    job = collector.Job(
        id=9902, kind="collect_all_dc_logs:scheduled", status="completed", servers=["DC1"],
        hours=1, max_events_per_channel=1000, created_at=now, updated_at=now,
        collection_status="completed",
    )
    with collector._lock:
        collector._jobs[job.id] = job

    monkeypatch.setattr(collector, "update_post_collection_job", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        collector, "update_post_collection_findings",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("durable findings update failed")),
    )
    monkeypatch.setattr(collector, "log_internal_error", lambda *_args, **_kwargs: "ERR-OUTER")
    monkeypatch.setattr(collector, "log_performance_stage", lambda *args, **kwargs: None)

    collector._run_post_collection_job(job.id, job.servers, "trace")
    result = collector.get_job(job.id)

    assert result["analysis_status"] == "failed"
    assert result["report_status"] == "failed"
    assert result["findings_status"] == "failed"
    assert result["findings_error_id"] == "ERR-OUTER"


def test_runtime_routes_do_not_refresh_findings_implicitly(monkeypatch) -> None:
    from server.api.routes import findings as findings_route
    from server.api.routes import workspace

    investigation = Path("server/sli/semantic/investigation.py").read_text(encoding="utf-8")
    roles = Path("server/sli/access/role_views.py").read_text(encoding="utf-8")
    findings = Path("server/sli/semantic/findings.py").read_text(encoding="utf-8")

    assert findings_route._findings_filters({"refresh": ["1"]})["refresh"] is False

    received: dict[str, object] = {}

    class Handler:
        storage_route_authorization = None

        def _send_json(self, payload) -> None:
            received["payload"] = payload

    monkeypatch.setattr(
        workspace,
        "get_role_views_data",
        lambda **kwargs: received.update(kwargs) or {"views": []},
    )
    workspace._handle_role_views_api(Handler(), {"refresh": ["1"]})

    assert received["refresh_findings"] is False
    assert '"refresh": False' in investigation
    assert "effective_refresh_findings = bool(refresh_findings)" in roles
    assert "refresh: bool = False" in findings
    assert "row_number() over" in findings


def test_schema_and_pipeline_include_incremental_state_and_metrics() -> None:
    schema = Path("config/postgres_schema.sql").read_text(encoding="utf-8")
    pipeline_source = Path("server/sli/semantic/findings_pg_pipeline.py").read_text(encoding="utf-8")
    post_source = Path("server/sli/sources/post_collection_pipeline.py").read_text(encoding="utf-8")

    assert "create table if not exists findings_refresh_state" in schema
    assert "findings_pg1_incremental_pipeline" in schema
    assert "where e.id > %s" in pipeline_source
    assert "order by e.id asc" in pipeline_source
    assert "for update" in pipeline_source
    assert "on conflict(finding_id, event_id, evidence_role) do nothing" in pipeline_source
    assert "last_manual_status_preserved" in pipeline_source
    assert "findings_watermark_before" in post_source
    assert "findings_result_json" in post_source
    # Phase updates cannot mint an attempt; only atomic claims increment it.
    update_source = post_source.split("def update_post_collection_job(", 1)[1].split(
        "def heartbeat_post_collection_job(", 1
    )[0]
    assert "attempt_count = %s" in update_source
    assert "attempt_count + 1" not in update_source
    assert "attempt_count=p.attempt_count + 1" in post_source
    assert "with deduplicated as" in Path("server/sli/semantic/findings.py").read_text(encoding="utf-8")

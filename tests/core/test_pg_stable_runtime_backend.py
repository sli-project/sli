from __future__ import annotations

from pathlib import Path


def test_missing_runtime_config_defaults_to_postgres(monkeypatch, tmp_path: Path) -> None:
    from server.sli.core.app_config import load_config

    monkeypatch.delenv("ADLOG_DB_BACKEND", raising=False)
    config = load_config(tmp_path / "missing-adlog-config.yaml")

    assert config.db_backend == "postgres"


def test_database_backend_detection_fails_closed_to_postgres(monkeypatch) -> None:
    from server.sli.core import database

    monkeypatch.setattr(database, "load_config", lambda: (_ for _ in ()).throw(RuntimeError("broken config")))

    assert database.active_backend() == "postgres"


def test_runtime_config_rejects_sqlite_unknown_backend_and_missing_dsn(tmp_path: Path) -> None:
    from dataclasses import replace

    from server.sli.core.app_config import load_config, require_postgres_runtime

    baseline = load_config(tmp_path / "missing-adlog-config.yaml")
    for backend in ("sqlite", "unknown", ""):
        try:
            require_postgres_runtime(replace(baseline, db_backend=backend, postgres_dsn="postgresql://configured"))
        except RuntimeError as exc:
            assert "only supported runtime backend" in str(exc)
        else:
            raise AssertionError(f"runtime backend must be rejected: {backend!r}")

    try:
        require_postgres_runtime(replace(baseline, db_backend="postgres", postgres_dsn=None))
    except RuntimeError as exc:
        assert "requires a non-empty" in str(exc)
    else:
        raise AssertionError("missing PostgreSQL DSN must be rejected")


def test_runtime_config_accepts_postgres_with_dsn(tmp_path: Path) -> None:
    from dataclasses import replace

    from server.sli.core.app_config import load_config, require_postgres_runtime

    baseline = load_config(tmp_path / "missing-adlog-config.yaml")
    resolved = require_postgres_runtime(replace(baseline, db_backend="postgres", postgres_dsn="postgresql://configured"))

    assert resolved.db_backend == "postgres"


def test_collector_health_uses_postgres_runtime_without_sqlite(monkeypatch, tmp_path: Path) -> None:
    from server.sli.sources import collector_health

    def fake_query_rows(sql: str, params: tuple = ()):
        normalized = " ".join(sql.split())
        if "from collection_channel_state" in normalized:
            return [
                {
                    "server_hostname": "DC1",
                    "channel": "Security",
                    "archive_start_utc": "2026-07-09T00:00:00+00:00",
                    "last_collection_start_utc": "2026-07-10T00:00:00+00:00",
                    "last_successful_collection_utc": "2026-07-10T00:01:00+00:00",
                    "last_event_time_utc": "2026-07-10T00:00:30+00:00",
                    "last_event_record_id": 123,
                    "backfill_completed": True,
                    "updated_at": "2026-07-10T00:01:00+00:00",
                    "event_count": 1,
                    "latest_event_time_utc": "2026-07-10T00:00:30+00:00",
                    "latest_event_record_id": 123,
                    "current_limit": 1000,
                    "recovery_mode": False,
                    "last_action": None,
                    "adaptive_last_status": None,
                    "last_lag_minutes": None,
                }
            ]
        if "with recent as" in normalized and "full outer join latest" in normalized:
            return [{
                "server": "DC1", "channel": "Security", "timeouts_24h": 0,
                "partial_timeouts_24h": 0, "inserted": 1, "skipped": 0,
                "last_partial_count": 0, "last_status": "completed",
                "query_duration_ms": 100, "import_duration_ms": 20,
                "import_queue_wait_ms": 0, "import_retry_count": 0,
                "total_duration_ms": 150, "events_per_second": 10,
                "last_record_id_delta": None, "lag_delta_minutes": None,
                "collection_mode": "current", "requested_collection_mode": "current",
                "cursor_strategy": "record_id", "cursor_fallback_reason": None,
                "collector_backend": "python", "backend_reason": None,
            }]
        return []

    monkeypatch.setattr(collector_health, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(collector_health, "query_rows", fake_query_rows)
    monkeypatch.setattr(collector_health, "get_post_collection_overview", lambda *, limit=10: {"backend": "postgres", "status": "ok", "summary": {}, "items": []})
    assert not hasattr(collector_health, "sqlite3"), "collector health must not import sqlite3"

    result = collector_health.get_collector_health(log_path=tmp_path / "missing.log")

    assert result["backend"] == "postgres"
    assert result["summary"]["channels_total"] == 1
    assert result["items"][0]["server"] == "DC1"
    assert result["items"][0]["collector_backend"] == "python"


def test_security_monitor_uses_backend_aware_query_rows(monkeypatch) -> None:
    from server.sli.events import security_events_monitor

    calls: list[str] = []

    def fake_query_rows(sql: str, params: tuple = ()):
        calls.append(sql)
        if "select e.id as event_db_id" in sql:
            return []
        if "select e.event_id, count(*)" in sql:
            return [{"event_id": 4625, "count": 7}]
        if 'count(*) as "important_total"' in sql:
            return [{"important_total": 7, "failed_logons": 7}]
        raise AssertionError(f"unexpected monitor query: {sql}")

    monkeypatch.setattr(security_events_monitor, "query_rows", fake_query_rows)
    result = security_events_monitor.get_security_events_monitor_data(limit=10)

    assert result["items"] == []
    assert len(calls) == 3
    assert result["summary"] == [{"event_id": 4625, "count": 7}]
    assert result["matched_total"] == 7
    assert result["category_counts"]["failed_logons"] == 7
    assert result["data_quality"]["aggregate_counts_exact"] is True
    assert any("count(*) as \"important_total\"" in sql for sql in calls)
    # Storage V2 is the only route (plan 6.5): the core is projected under alias e.
    assert all("from events_v2_core core" in call and ") e join servers s" in call for call in calls)


def test_findings_do_not_use_legacy_sqlite_in_postgres_runtime(monkeypatch, tmp_path: Path) -> None:
    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    assert not hasattr(findings, "sqlite3")

    monkeypatch.setattr(findings, "refresh_findings_from_events", lambda **kwargs: {"status": "ok"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda: {"status": "ok", "limitations": []})
    monkeypatch.setattr(findings, "query_rows", lambda *args, **kwargs: [])
    result = findings.get_findings_data(refresh=True)

    assert result["status"] == "ok"
    assert result["backend"] == "postgres"
    assert result["limitations"] == []


def test_findings_reject_non_postgres_backend(monkeypatch, tmp_path: Path) -> None:
    import pytest

    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: False)
    monkeypatch.setattr(findings, "query_rows", lambda *a, **k: pytest.fail("no data may be read on a non-PostgreSQL backend"))
    with pytest.raises(RuntimeError, match="requires_postgres|PostgreSQL-only"):
        findings.get_findings_data()
    with pytest.raises(RuntimeError, match="requires_postgres|PostgreSQL-only"):
        findings.get_findings_dashboard_data()
    with pytest.raises(RuntimeError, match="requires_postgres|PostgreSQL-only"):
        findings.refresh_findings_from_events()


def test_http_health_deep_routes_archive_status_by_runtime_backend() -> None:
    source = Path("server/api/routes/runtime.py").read_text(encoding="utf-8")
    assert "def _archive_status_for_runtime" in source
    assert "get_archive_status_pg" in source
    health_source = Path("server/api/routes/health.py").read_text(encoding="utf-8")
    deep_block = health_source.split("def _handle_health", 1)[1].split("def try_handle_liveness_get", 1)[0]
    assert "routes_runtime._archive_status_for_runtime()" in deep_block
    assert "get_archive_status()" not in deep_block


def test_http_server_requires_postgres_and_never_bootstraps_sqlite() -> None:
    source = Path("server/api/http_server.py").read_text(encoding="utf-8")
    run_block = source.split("def run_server", 1)[1]

    assert "cfg = require_postgres_runtime(load_config())" in run_block
    assert '"bootstrap_skipped"' in run_block
    assert "ensure_database()" not in run_block


def test_maintenance_run_command_is_hardened_against_pipe_leaks() -> None:
    source = Path("scripts/maintenance/bundle_common.py").read_text(encoding="utf-8")

    assert "subprocess.Popen" in source
    assert "pipe_reader_timeout" in source
    assert "_terminate_process_group" in source
    assert "start_new_session" in source or "CREATE_NEW_PROCESS_GROUP" in source

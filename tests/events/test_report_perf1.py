from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest


def _row(row_id: int, record_id: int, ts: str) -> dict:
    return {
        "id": row_id,
        "server": "DC1",
        "channel": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "event_id": 4624,
        "event_record_id": record_id,
        "time_created_utc": ts,
        "time_created_local": ts,
        "subject_user_name": "alice",
        "subject_domain_name": "EXAMPLE",
        "target_user_name": "alice",
        "target_domain_name": "EXAMPLE",
        "ip_address": "",
        "workstation_name": "WS01",
        "logon_id": "0x1",
        "message_text": "sample",
        "event_data_json": "{}",
    }


def test_relation_count_reads_storage_v2_link_blocks_and_degrades_on_timeout(monkeypatch) -> None:
    from server.sli.events import event_search

    calls: list[tuple[str, tuple]] = []

    def aggregate(sql, params=(), **_kwargs):
        calls.append((" ".join(sql.lower().split()), tuple(params)))
        return [{"event_db_id": 7, "relation_count": 4}]

    monkeypatch.setattr(event_search, "_v2_primary_read_enabled_for_request", lambda *_a, **_k: True)
    monkeypatch.setattr("server.sli.storage.permanent_fact_history.primary_read_enabled", lambda: False)
    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", aggregate)
    items = event_search._attach_relation_counts(
        [{"id": 7}, {"event_db_id": 8}], timeout_ms=8000
    )

    assert [item["relation_count"] for item in items] == [4, 0]
    assert all(item["relation_count_status"] == "exact" for item in items)
    assert calls[0][1] == (8, 7, 7, 8)
    assert "from event_entity_link_blocks_v2 block" in calls[0][0]
    assert "block.first_event_id <= ? and block.last_event_id >= ?" in calls[0][0]

    monkeypatch.setattr("server.sli.core.database.query_rows_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            event_search.QueryTimeoutError("slow relation index", timeout_ms=2000)
        ),
    )
    degraded = event_search._attach_relation_counts(
        [{"id": 7}], timeout_ms=8000
    )
    assert degraded == [{"id": 7, "relation_count": None, "relation_count_status": "unavailable"}]


def test_schema_declares_reverse_event_link_index() -> None:
    assert "idx_event_links_target on event_links(target_event_id)" in Path("config/postgres_schema.sql").read_text(encoding="utf-8")


def test_postgres_watchdog_cancels_and_releases_connection(monkeypatch) -> None:
    from server.sli.core import database
    from server.sli.core import postgres_runtime_pipeline

    cancelled = threading.Event()
    closed = {"connection": False, "cursor": False}

    class CancelledError(RuntimeError):
        sqlstate = "57014"

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            closed["cursor"] = True

        def execute(self, sql, params=()):
            if "pg_sleep" not in str(sql):
                return None
            while not cancelled.is_set():
                time.sleep(0.01)
            raise CancelledError("cancelled")

        def fetchall(self):
            return []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            closed["connection"] = True

        def cursor(self):
            return Cursor()

        def cancel(self):
            cancelled.set()

    monkeypatch.setattr(database, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: Connection())

    started = time.perf_counter()
    with pytest.raises(database.QueryTimeoutError):
        database.query_rows_bounded("select pg_sleep(5)", statement_timeout_ms=100, wall_timeout_ms=350)
    assert time.perf_counter() - started < 2
    assert cancelled.is_set()
    assert closed == {"connection": True, "cursor": True}


def test_system_health_uses_single_cached_snapshot(monkeypatch, tmp_path: Path) -> None:
    from server.sli.ops import system_health

    system_health.clear_system_health_cache()
    calls = {"db": 0, "runtime": 0}

    class Config:
        reports_dir = str(tmp_path / "reports")
        log_dir = str(tmp_path / "logs")

        def to_dict(self):
            return {"db_backend": "postgres"}

    def db_inventory(**kwargs):
        calls["db"] += 1
        return {
            "backend": "postgres", "path": "current_database()", "size_bytes": 100,
            "size_human": "100 Б", "events": 10, "servers": 2, "findings": 1,
            "counts_are_estimates": True, "count_source": "pg_class.reltuples",
        }

    def runtime_storage():
        calls["runtime"] += 1
        return {
            "generated_at_utc": "2026-07-22T00:00:00+00:00",
            "sizes": {key: {"bytes": value, "human": f"{value} Б"} for key, value in {"data": 10, "reports": 5, "logs": 2}.items()},
            "warnings": [], "counts": {}, "disk": {},
            "scan": {"scope": "project_tree", "complete_project_tree": True, "errors": 0},
        }

    monkeypatch.setenv("ADLOG_SYSTEM_HEALTH_CACHE_SECONDS", "60")
    monkeypatch.setattr(system_health, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(system_health, "load_config", lambda: Config())
    monkeypatch.setattr(system_health, "_db_inventory", db_inventory)
    monkeypatch.setattr(system_health, "get_collector_health", lambda: {"summary": {}})
    monkeypatch.setattr(system_health, "build_storage_cleanup_plan", lambda: {"total_candidates": 0, "total_bytes": 0})
    monkeypatch.setattr(system_health, "get_runtime_storage_summary", runtime_storage)

    first = system_health.get_system_health(force=True)
    second = system_health.get_system_health()

    assert first["cache"]["hit"] is False
    assert second["cache"]["hit"] is True
    assert calls == {"db": 1, "runtime": 1}
    assert first["storage"]["source"] == "full_project_runtime_storage_snapshot"
    assert first["db"]["counts_are_estimates"] is True


def test_system_health_returns_honest_warming_state_without_caching_partial_sizes(monkeypatch, tmp_path: Path) -> None:
    from server.sli.ops import system_health

    system_health.clear_system_health_cache()
    calls = {"db": 0}

    class Config:
        def to_dict(self):
            return {"db_backend": "postgres"}

    def db_inventory(**kwargs):
        calls["db"] += 1
        return {
            "backend": "postgres", "path": "current_database()", "size_bytes": 1,
            "size_human": "1 Б", "events": 1, "servers": 1, "findings": 1,
            "counts_are_estimates": True, "count_source": "pg_class.reltuples",
        }

    monkeypatch.setattr(system_health, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(system_health, "load_config", lambda: Config())
    monkeypatch.setattr(system_health, "_db_inventory", db_inventory)
    monkeypatch.setattr(system_health, "get_collector_health", lambda: {"summary": {}})
    monkeypatch.setattr(system_health, "build_storage_cleanup_plan", lambda: {"total_candidates": 0, "total_bytes": 0})
    monkeypatch.setattr(system_health, "warm_system_health_storage_async", lambda: True)

    first = system_health.get_system_health()
    second = system_health.get_system_health()

    assert first["runtime_storage"]["snapshot"]["status"] == "warming"
    assert first["storage"]["data_dir_bytes"] is None
    assert first["storage"]["data_dir_human"] == "—"
    assert first["status"] == "warn"
    assert second["cache"]["hit"] is False
    assert calls["db"] == 2


def test_runtime_storage_summary_uses_one_pass_and_preserves_category_totals(tmp_path: Path) -> None:
    from server.sli.storage.runtime_storage import get_runtime_storage_summary

    raw = tmp_path / "data" / "raw" / "dc1" / "events.jsonl"
    report = tmp_path / "data" / "reports" / "report.html"
    backup = tmp_path / "backups" / "source.zip"
    sqlite = tmp_path / "data" / "processed" / "ad_logs.sqlite"
    for path, content in ((raw, b"1234"), (report, b"123"), (backup, b"12"), (sqlite, b"1")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    data = get_runtime_storage_summary(root=tmp_path)

    assert data["scan"]["mode"] == "single_pass"
    assert data["scan"]["files_seen"] == 4
    assert data["sizes"]["project"]["bytes"] == 10
    assert data["sizes"]["data"]["bytes"] == 8
    assert data["sizes"]["raw"]["bytes"] == 4
    assert data["sizes"]["reports"]["bytes"] == 3
    assert data["sizes"]["backups"]["bytes"] == 2
    assert data["sizes"]["sqlite"]["bytes"] == 1
    assert data["counts"]["raw_files"] == 1
    assert data["counts"]["report_files"] == 1
    assert data["counts"]["backup_files"] == 1


def test_runtime_storage_summary_reports_unreadable_directories(monkeypatch, tmp_path: Path) -> None:
    from server.sli.storage import runtime_storage

    def denied_walk(root, *, followlinks, onerror):
        assert followlinks is False
        onerror(PermissionError(13, "denied", str(Path(root) / "closed")))
        return iter(())

    monkeypatch.setattr(runtime_storage.os, "walk", denied_walk)

    data = runtime_storage.get_runtime_storage_summary(root=tmp_path)

    assert data["scan"]["scope"] == "project_tree"
    assert data["scan"]["complete_project_tree"] is False
    assert data["scan"]["errors"] == 1
    assert data["scan"]["error_paths"] == [str(tmp_path / "closed")]
    assert any("снимок хранилища неполон" in warning.lower() for warning in data["warnings"])


def test_html_audit_2_separates_timeout_from_functional_failure(monkeypatch, tmp_path: Path) -> None:
    from server.sli.reporting import html_audit

    responses = [
        {"status": "failed", "status_code": None, "duration_ms": 1000, "size_bytes": 0, "headers": {}, "body": b"", "error_type": "TimeoutError", "error": "timed out"},
        {"status": "ok", "status_code": 200, "duration_ms": 5, "size_bytes": 90, "headers": {"Content-Type": "text/html"}, "body": b"<!doctype html><html><head><title>ok</title></head><body><h1>content content content content content content content content</h1><p>more report content for audit</p></body></html>", "error": None},
    ]

    monkeypatch.setattr(html_audit, "REGISTERED_PAGES", (html_audit.HtmlPageSpec("only", "/only.html", "Only", "test", slow_ms=10),))
    monkeypatch.setattr(html_audit, "_runtime_context", lambda *args, **kwargs: {"available": True, "background_load_detected": False})
    monkeypatch.setattr(html_audit, "_fetch_dynamic_report_inventory", lambda *args, **kwargs: ([], {"status": "ok"}))
    monkeypatch.setattr(html_audit, "discover_http_report_routes", lambda root: ["/only.html"])
    monkeypatch.setattr(html_audit, "discover_http_get_routes", lambda root: ["/only.html"])
    monkeypatch.setattr(html_audit, "discover_renderers", lambda root: [])
    monkeypatch.setattr(html_audit, "discover_html_files", lambda root: [])
    monkeypatch.setattr(html_audit, "_browser_audit", lambda *args, **kwargs: {"status": "ok", "pages": [], "available": False})
    monkeypatch.setattr(html_audit, "_read_url", lambda *args, **kwargs: responses.pop(0))

    result = html_audit.run_html_audit(base_url="http://127.0.0.1:8080", browser_mode="off", root=tmp_path)

    assert result["package_type"] == "HTML_AUDIT_2"
    assert result["status"] == "warning"
    assert result["summary"]["functional_failures"] == 0
    assert result["summary"]["performance_findings"] == 1
    page = result["pages"][0]
    assert page["retried"] is True
    assert "http_timeout" in page["performance_findings"]
    assert page["functional_findings"] == []


def test_system_health_deduplicates_storage_warnings_with_postgres_config(monkeypatch) -> None:
    from server.sli.ops import system_health

    system_health.clear_system_health_cache()

    class Config:
        def to_dict(self):
            return {"db_backend": "postgres"}

    monkeypatch.setattr(system_health, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(system_health, "load_config", lambda: Config())
    monkeypatch.setattr(
        system_health,
        "_db_inventory",
        lambda **kwargs: {
            "backend": "postgres", "path": "current_database()", "size_bytes": 1,
            "size_human": "1 Б", "events": 1, "servers": 1, "findings": 1,
            "counts_are_estimates": True, "count_source": "pg_class.reltuples",
        },
    )
    monkeypatch.setattr(system_health, "get_collector_health", lambda: {"summary": {}})
    monkeypatch.setattr(system_health, "build_storage_cleanup_plan", lambda: {"total_candidates": 0, "total_bytes": 0})
    monkeypatch.setattr(
        system_health,
        "get_runtime_storage_summary",
        lambda **kwargs: {"sizes": {}, "counts": {}, "disk": {}, "warnings": ["same warning"]},
    )

    result = system_health.get_system_health(force=True)

    assert result["warnings"] == ["same warning"]
    assert "db_path" not in result["config"]
    assert result["config"] == {"db_backend": "postgres"}


def test_v2_relation_counts_read_link_blocks_pruned_by_the_event_range(monkeypatch) -> None:
    """The V2 view unnests every block; the count must read blocks bounded by first/last_event_id."""
    from server.sli.events import event_search

    calls: list[tuple[str, tuple]] = []

    def aggregate(sql, params=(), **_kwargs):
        calls.append((" ".join(sql.lower().split()), tuple(params)))
        return [{"event_db_id": 30, "relation_count": 2}]

    monkeypatch.setattr(event_search, "_v2_primary_read_enabled_for_request", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("server.sli.core.database.query_rows_bounded", aggregate)
    items = event_search._attach_relation_counts(
        [{"event_db_id": 30}, {"event_db_id": 10}, {"event_db_id": 20}], timeout_ms=8000
    )

    assert [item["relation_count"] for item in items] == [2, 0, 0]
    sql, params = calls[0]
    assert "from event_entity_link_blocks_v2 block" in sql and "event_entity_links_v2" not in sql
    assert "block.first_event_id <= ? and block.last_event_id >= ?" in sql
    assert params == (30, 10, 30, 10, 20)

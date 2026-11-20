from __future__ import annotations

import json
import os
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


def test_dashboard_snapshot_computes_dependencies_once_and_uses_cache(monkeypatch):
    from server.sli.reporting import dashboard_snapshot as module

    calls: dict[str, int] = {}

    def counted(name, value):
        def fn(*args, **kwargs):
            calls[name] = calls.get(name, 0) + 1
            return value
        return fn

    monkeypatch.setattr(module, "get_dashboard_event_summary", counted("events", {"total_events": 1, "by_channel": [], "by_server": []}))
    monkeypatch.setattr(module, "get_dashboard_entity_summary", counted("entities", {"total_entities": 1}))
    monkeypatch.setattr(module, "get_collector_health", counted("collector", {"summary": {}, "items": []}))
    monkeypatch.setattr(module, "get_sources", counted("sources", []))
    monkeypatch.setattr(module, "get_findings_dashboard_data", counted("findings", {"items": []}))
    monkeypatch.setattr(module, "list_ai_runs", counted("ai", {"items": []}))
    monkeypatch.setattr(module, "list_jobs", counted("jobs", []))
    monkeypatch.setattr(module, "list_reports", counted("reports", []))
    monkeypatch.setattr(module, "get_role_views_data", counted("roles", {"views": []}))
    monkeypatch.setattr(module, "get_scheduler_runtime_status", counted("scheduler", {}))
    monkeypatch.setattr(module, "get_collection_runtime_status", counted("collection", {}))
    monkeypatch.setattr(module, "active_backend", lambda: "postgres")
    module.clear_dashboard_snapshot_cache()

    first = module.build_dashboard_snapshot(force=True)
    second = module.build_dashboard_snapshot()

    assert first["diagnostics"]["request_model"] == "parallel_bounded_snapshot"
    assert second["diagnostics"]["cache_hit"] is True
    assert all(value == 1 for value in calls.values())


def test_post_collection_overview_marks_stale_running(monkeypatch):
    from server.sli.sources import post_collection_pipeline as module

    old = datetime.now(timezone.utc) - timedelta(minutes=30)

    class Cursor:
        def __init__(self):
            self.query = ""

        def execute(self, sql, params=()):
            self.query = " ".join(sql.split()).lower()

        def fetchall(self):
            if "group by status" in self.query:
                return [{"status": "running", "count": 1}]
            if "order by id desc" in self.query:
                return [{"id": 1, "source_job_id": 7, "status": "running", "heartbeat_at": old, "updated_at": old}]
            return []

        def __enter__(self): return self
        def __exit__(self, *args): return False

    class Conn:
        def cursor(self): return Cursor()
        def __enter__(self): return self
        def __exit__(self, *args): return False

    monkeypatch.setattr(module, "_backend", lambda: "postgres")
    monkeypatch.setattr(module, "ensure_post_collection_schema", lambda: None)
    monkeypatch.setenv("ADLOG_POST_COLLECTION_STALE_MINUTES", "15")
    import server.sli.core.postgres_runtime_pipeline as pg
    monkeypatch.setattr(pg, "connect", lambda: Conn())

    data = module.get_post_collection_overview(limit=5)
    assert data["summary"]["stale_running"] == 1
    assert data["items"][0]["stale_running"] is True


def test_cursor_audit_rejects_failed_collection_without_state_commit(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline as module

    class Cursor:
        def __init__(self):
            self.executed = []
            self.last = ""

        def execute(self, sql, params=()):
            self.last = " ".join(sql.split()).lower()
            self.executed.append((self.last, params))

        def fetchone(self):
            if "from collection_channel_state" in self.last:
                return {"last_event_record_id": 100, "last_event_time_utc": "2026-07-10T00:00:00+00:00"}
            if "from events_v2_core e" in self.last:
                return {"event_record_id": 120, "time_created_utc": "2026-07-10T00:01:00+00:00"}
            return None

        def __enter__(self): return self
        def __exit__(self, *args): return False

    cursor = Cursor()

    class Conn:
        def cursor(self): return cursor
        def __enter__(self): return self
        def __exit__(self, *args): return False

    monkeypatch.setattr(module, "connect", lambda: Conn())
    monkeypatch.setattr(module, "_ensure_archive_start_pg", lambda: "2026-07-01T00:00:00+00:00")
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)

    module.update_collection_state_from_summary_pg(
        server="DC1",
        collection_start_utc="2026-07-10T00:00:00+00:00",
        summary={"channels": [{"channel": "Security", "status": "failed", "count": 0}]},
        import_stats={"Security": {"inserted": 0, "skipped": 0}},
        job_id=10,
        trace_id="trace-10",
    )
    state_writes = [sql for sql, _ in cursor.executed if "insert into collection_channel_state" in sql]
    audit = [(sql, params) for sql, params in cursor.executed if "insert into collector_cursor_audit" in sql]
    assert not state_writes
    assert len(audit) == 1
    assert audit[0][1][13] == "not_committed"
    assert audit[0][1][14] == "collection_status_not_eligible"


def test_cursor_audit_commits_only_forward_record_id(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline as module

    class Cursor:
        def __init__(self):
            self.executed = []
            self.last = ""
            self.state_reads = 0

        def execute(self, sql, params=()):
            self.last = " ".join(sql.split()).lower()
            self.executed.append((self.last, params))

        def fetchone(self):
            if "from collection_channel_state" in self.last:
                self.state_reads += 1
                record = 100 if self.state_reads == 1 else 120
                return {"last_event_record_id": record, "last_event_time_utc": "2026-07-10T00:01:00+00:00"}
            if "from events_v2_core e" in self.last:
                return {"event_record_id": 120, "time_created_utc": "2026-07-10T00:01:00+00:00"}
            return None

        def __enter__(self): return self
        def __exit__(self, *args): return False

    cursor = Cursor()

    class Conn:
        def cursor(self): return cursor
        def __enter__(self): return self
        def __exit__(self, *args): return False

    monkeypatch.setattr(module, "connect", lambda: Conn())
    monkeypatch.setattr(module, "_ensure_archive_start_pg", lambda: "2026-07-01T00:00:00+00:00")
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)
    module.update_collection_state_from_summary_pg(
        server="DC1",
        collection_start_utc="2026-07-10T00:00:00+00:00",
        summary={"finished_at": "2026-07-10T00:02:00+00:00", "channels": [{"channel": "Security", "status": "completed", "count": 1000, "channel_generation_identity": "generation-stable"}]},
        import_stats={"Security": {"inserted": 1000, "skipped": 0}},
        job_id=11,
        trace_id="trace-11",
    )
    assert any("insert into collection_channel_state" in sql for sql, _ in cursor.executed)
    audit = [(sql, params) for sql, params in cursor.executed if "insert into collector_cursor_audit" in sql]
    assert audit[0][1][13] == "committed"
    assert audit[0][1][14] == "completed_import_committed:published_only"
    generation_updates = [
        params for sql, params in cursor.executed
        if "set channel_generation_identity = %s" in sql
    ]
    assert generation_updates == [("generation-stable", "DC1", "Security")]


def test_storage_zip_is_verified_before_source_removal(tmp_path, monkeypatch):
    from server.sli.storage import storage_policy as module

    root = tmp_path
    raw = root / "data" / "raw"
    raw.mkdir(parents=True)
    source = raw / "old.jsonl"
    expected_bytes = b'{"event":1}\n'
    source.write_bytes(expected_bytes)
    old = time.time() - 5 * 86400
    os.utime(source, (old, old))
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "DATA_DIR", root / "data")
    monkeypatch.setattr(module, "RAW_ARCHIVE_DIR", root / "data" / "raw_archive")
    monkeypatch.setattr(module, "STORAGE_CLEANUP_LAST", root / "data" / "maintenance" / "last.json")
    monkeypatch.setenv("ADLOG_RAW_RETENTION_DAYS", "2")
    monkeypatch.setenv("ADLOG_RAW_ARCHIVE_ENABLED", "true")
    monkeypatch.setenv("ADLOG_RAW_ARCHIVE_COMPRESS", "true")
    monkeypatch.setattr(
        module,
        "_confirmed_imported_raw_paths",
        lambda paths: ({variant for path in paths for variant in module._raw_path_variants(path)}, {"status": "ok", "backend": "postgres"}),
    )

    plan = module.build_storage_cleanup_plan(limit=10)
    result = module.apply_storage_cleanup_plan(plan, apply=True, confirm_apply=True)

    assert result["status"] == "ok"
    assert source.exists() is False
    assert result["archive_verification"][0]["status"] == "verified"
    archive = Path(result["archive_verification"][0]["zip"])
    with zipfile.ZipFile(archive) as zf:
        assert zf.testzip() is None
        assert zf.read("old.jsonl") == expected_bytes


def test_confirmed_raw_is_deleted_when_archive_is_disabled(tmp_path, monkeypatch):
    from server.sli.storage import storage_policy as module

    raw = tmp_path / "data" / "raw"
    raw.mkdir(parents=True)
    source = raw / "old.jsonl"
    source.write_text("{}\n", encoding="utf-8")
    old = time.time() - 5 * 86400
    os.utime(source, (old, old))
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(module, "RAW_ARCHIVE_DIR", tmp_path / "data" / "raw_archive")
    monkeypatch.setenv("ADLOG_RAW_RETENTION_DAYS", "2")
    monkeypatch.setenv("ADLOG_RAW_ARCHIVE_ENABLED", "false")
    monkeypatch.setattr(module, "active_backend", lambda: "postgres")
    monkeypatch.setattr(module, "_confirmed_imported_raw_paths", lambda _paths: ({str(source)}, {"status": "ok"}))

    plan = module.build_storage_cleanup_plan(limit=10)
    result = module.apply_storage_cleanup_plan(plan, apply=True, confirm_apply=True)
    assert not source.exists()
    assert any(item.get("category") == "raw" and item.get("action") == "delete_file" for item in plan["actions"])
    assert any(item.get("action") == "delete_file" for item in result["applied"])


def test_dashboard_startup_probe_records_main_page_state(monkeypatch):
    from scripts.maintenance import dashboard_startup_probe as module

    def fake_probe_url(base_url: str, path: str, *, timeout: float):
        item = {
            "path": path,
            "url": base_url.rstrip("/") + path,
            "status": "ok",
            "http_status": 200,
            "duration_ms": 2,
            "bytes": 2,
            "content_type": "application/json" if path.startswith("/api/") else "text/html",
        }
        if path == "/api/dashboard/snapshot?force=1":
            item["duration_ms"] = 12
            item["snapshot_diagnostics"] = {"total_duration_ms": 12, "cache_hit": False}
        elif path == "/api/dashboard/snapshot":
            item["duration_ms"] = 1
            item["snapshot_diagnostics"] = {"total_duration_ms": 1, "cache_hit": True}
        return item

    monkeypatch.setattr(module, "probe_url", fake_probe_url)
    result = module.run_probe("http://127.0.0.1:18080", timeout=2, wait_health_seconds=1)
    assert result["status"] == "ok"
    assert result["summary"]["main_page_ready"] is True
    assert result["summary"]["forced_snapshot_ms"] == 12
    assert result["summary"]["cached_snapshot_ms"] == 1
    assert len(result["results"]) == 6


def test_collector_health_survives_post_collection_dependency_failure(monkeypatch):
    from server.sli.sources import collector_health as module

    monkeypatch.setattr(module, "get_post_collection_overview", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("postgres temporarily unavailable")))
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)
    result = module._safe_post_collection_overview(backend="postgres", limit=10)

    assert result["backend"] == "postgres"
    assert result["status"] == "unavailable"
    assert result["summary"] == {}
    assert result["items"] == []
    assert result["error_type"] == "RuntimeError"


def test_cursor_audit_rejects_record_id_rollback(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline as module

    class Cursor:
        def __init__(self):
            self.executed = []
            self.last = ""

        def execute(self, sql, params=()):
            self.last = " ".join(sql.split()).lower()
            self.executed.append((self.last, params))

        def fetchone(self):
            if "from collection_channel_state" in self.last:
                return {"last_event_record_id": 200, "last_event_time_utc": "2026-07-10T00:02:00+00:00"}
            if "from events_v2_core e" in self.last:
                return {"event_record_id": 150, "time_created_utc": "2026-07-10T00:01:00+00:00"}
            return None

        def __enter__(self): return self
        def __exit__(self, *args): return False

    cursor = Cursor()

    class Conn:
        def cursor(self): return cursor
        def __enter__(self): return self
        def __exit__(self, *args): return False

    monkeypatch.setattr(module, "connect", lambda: Conn())
    monkeypatch.setattr(module, "_ensure_archive_start_pg", lambda: "2026-07-01T00:00:00+00:00")
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)
    module.update_collection_state_from_summary_pg(
        server="DC1",
        collection_start_utc="2026-07-10T00:00:00+00:00",
        summary={"channels": [{"channel": "Security", "status": "completed", "count": 1000}]},
        import_stats={"Security": {"inserted": 1000, "skipped": 0}},
    )
    assert not any("insert into collection_channel_state" in sql for sql, _ in cursor.executed)
    successful_check_updates = [params for sql, params in cursor.executed if "update collection_channel_state" in sql]
    assert len(successful_check_updates) == 1
    assert successful_check_updates[0][0] == "2026-07-10T00:00:00+00:00"
    assert successful_check_updates[0][2] is True
    assert successful_check_updates[0][3:] == ("DC1", "Security")
    audit = [params for sql, params in cursor.executed if "insert into collector_cursor_audit" in sql][0]
    assert audit[13] == "rejected"
    assert audit[14] == "record_id_rollback_detected"
    assert audit[9] == 200


def test_cursor_audit_commits_only_proven_completed_epoch_reset(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline as module

    class Cursor:
        def __init__(self):
            self.executed = []
            self.last = ""

        def execute(self, sql, params=()):
            self.last = " ".join(sql.split()).lower()
            self.executed.append((self.last, params))

        def fetchone(self):
            if "from collection_channel_state" in self.last:
                return {
                    "last_event_record_id": 500_000,
                    "last_event_time_utc": "2026-07-10T00:02:00+00:00",
                }
            if "from events_v2_core e" in self.last:
                return {
                    "event_record_id": 42,
                    "time_created_utc": "2026-07-25T00:01:00+00:00",
                }
            return None

        def __enter__(self): return self
        def __exit__(self, *args): return False

    cursor = Cursor()

    class Conn:
        def cursor(self): return cursor
        def __enter__(self): return self
        def __exit__(self, *args): return False

    monkeypatch.setattr(module, "connect", lambda: Conn())
    monkeypatch.setattr(module, "_ensure_archive_start_pg", lambda: "2026-07-01T00:00:00+00:00")
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)

    module.update_collection_state_from_summary_pg(
        server="DC1",
        collection_start_utc="2026-07-25T00:00:00+00:00",
        summary={
            "channels": [{
                "channel": "Security",
                "status": "completed",
                "count": 12,
                "batch_max_record_id": 42,
                "channel_latest_record_id_before_read": 42,
                "cursor_strategy": "time_window_fallback",
                "cursor_fallback_reason": "latest_record_id_before_saved_cursor",
            }]
        },
        import_stats={"Security": {"inserted": 12, "skipped": 0}},
    )

    reset = [
        params for sql, params in cursor.executed
        if "update collection_channel_state" in sql
        and "last_event_record_id = %s" in sql
    ]
    assert len(reset) == 1
    assert reset[0][3] == 42
    audit = [
        params for sql, params in cursor.executed
        if "insert into collector_cursor_audit" in sql
    ][0]
    assert audit[13] == "committed"
    assert audit[14] == "completed_import_committed:cursor_epoch_reset"
    assert audit[9] == 42


def test_cursor_audit_does_not_reset_epoch_on_partial_read(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline as module

    class Cursor:
        def __init__(self):
            self.executed = []
            self.last = ""

        def execute(self, sql, params=()):
            self.last = " ".join(sql.split()).lower()
            self.executed.append((self.last, params))

        def fetchone(self):
            if "from collection_channel_state" in self.last:
                return {"last_event_record_id": 500_000, "last_event_time_utc": None}
            if "from events_v2_core e" in self.last:
                return {"event_record_id": 42, "time_created_utc": None}
            return None

        def __enter__(self): return self
        def __exit__(self, *args): return False

    cursor = Cursor()

    class Conn:
        def cursor(self): return cursor
        def __enter__(self): return self
        def __exit__(self, *args): return False

    monkeypatch.setattr(module, "connect", lambda: Conn())
    monkeypatch.setattr(module, "_ensure_archive_start_pg", lambda: "2026-07-01T00:00:00+00:00")
    monkeypatch.setattr(module, "log_event", lambda *args, **kwargs: None)

    module.update_collection_state_from_summary_pg(
        server="DC1",
        collection_start_utc="2026-07-25T00:00:00+00:00",
        summary={
            "channels": [{
                "channel": "Security",
                "status": "partial_timeout",
                "count": 12,
                "batch_max_record_id": 42,
                "channel_latest_record_id_before_read": 42,
                "cursor_strategy": "time_window_fallback",
                "cursor_fallback_reason": "latest_record_id_before_saved_cursor",
            }]
        },
        import_stats={"Security": {"inserted": 12, "skipped": 0}},
    )

    assert not any(
        "last_event_record_id = %s" in sql
        for sql, _ in cursor.executed
        if "update collection_channel_state" in sql
    )
    audit = [
        params for sql, params in cursor.executed
        if "insert into collector_cursor_audit" in sql
    ][0]
    assert audit[13] == "rejected"
    assert audit[14] == "record_id_rollback_detected"


def test_corrupt_zip_verification_preserves_raw_source(tmp_path, monkeypatch):
    from server.sli.storage import storage_policy as module

    raw = tmp_path / "data" / "raw"
    raw.mkdir(parents=True)
    source = raw / "old.jsonl"
    source.write_text("{}\n", encoding="utf-8")
    old = time.time() - 5 * 86400
    os.utime(source, (old, old))
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(module, "RAW_ARCHIVE_DIR", tmp_path / "data" / "raw_archive")
    monkeypatch.setattr(module, "STORAGE_CLEANUP_LAST", tmp_path / "data" / "maintenance" / "last.json")
    monkeypatch.setenv("ADLOG_RAW_RETENTION_DAYS", "2")
    monkeypatch.setattr(
        module,
        "_confirmed_imported_raw_paths",
        lambda paths: ({variant for path in paths for variant in module._raw_path_variants(path)}, {"status": "ok", "backend": "postgres"}),
    )

    real_zip = module.zipfile.ZipFile

    class BadVerificationZip(real_zip):
        def testzip(self):
            return "old.jsonl" if self.mode == "r" else super().testzip()

    monkeypatch.setattr(module.zipfile, "ZipFile", BadVerificationZip)
    plan = module.build_storage_cleanup_plan(limit=10)
    result = module.apply_storage_cleanup_plan(plan, apply=True, confirm_apply=True)
    assert source.exists()
    assert result["status"] == "warn"
    assert result["archive_verification"][0]["status"] == "failed"


def test_pg_startup_creates_cursor_audit_before_runtime_checks():
    text = Path("server/api/http_server.py").read_text(encoding="utf-8")
    startup = text.split("def run_server", 1)[1]
    assert "bootstrap_skipped" in startup
    assert "ensure_cursor_audit_schema_pg" in startup
    assert startup.index("ensure_cursor_audit_schema_pg") < startup.index("recover_stale_post_collection_jobs")


def test_apply_gate_does_not_require_cursor_table_before_first_restart():
    text = Path("scripts/maintenance/postgres_readiness.py").read_text(encoding="utf-8")
    expected = text.split("EXPECTED_TABLES = [", 1)[1].split("]", 1)[0]
    assert "collector_cursor_audit" not in expected
    assert "collector_cursor_audit" in Path("config/postgres_schema.sql").read_text(encoding="utf-8")

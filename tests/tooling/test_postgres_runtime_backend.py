from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_postgres_runtime_pipeline_exposes_archive_plan_and_status() -> None:
    source = (ROOT / "server" / "sli" / "core" / "postgres_runtime_pipeline.py").read_text(encoding="utf-8")
    assert "def get_archive_status_pg" in source
    assert "def get_collection_plan_for_server_pg" in source
    assert "from collection_channel_state" in source
    assert "where server_hostname = %s and channel = %s" in source


def test_run_dc_log_pilot_reads_postgres_watermarks_when_backend_is_postgres() -> None:
    source = (ROOT / "scripts" / "run_dc_log_pilot.py").read_text(encoding="utf-8")
    archive_block = source[source.index("if args.archive:"):source.index("if connect_address != args.server:")]
    assert "target_db_backend = runtime_db_backend()" in source
    assert "get_collection_plan_for_server_pg" in archive_block
    assert "archive_plan_backend = \"postgres\"" in archive_block
    assert "get_collection_plan_for_server(args.server" not in archive_block
    assert "sqlite" not in archive_block.lower()


def test_autocollection_status_uses_postgres_archive_status_in_postgres_backend() -> None:
    source = (ROOT / "server" / "jobs" / "collector.py").read_text(encoding="utf-8")
    func = source[source.index("def _archive_channel_summary_fast"):source.index("def _skipped_overlap_summary")]
    assert "if _runtime_db_backend() != \"postgres\"" in func
    assert "get_archive_status_pg" in func
    assert "get_archive_status()" not in func


def test_database_query_rows_is_backend_aware_for_core_ui_summaries() -> None:
    source = (ROOT / "server" / "sli" / "core" / "database.py").read_text(encoding="utf-8")
    assert "def _active_backend" in source
    assert "def is_postgres_runtime_db()" in source
    assert ("active_backend() == \"postgres\"" in source or "_active_backend() == \"postgres\"" in source)
    assert "_require_runtime_db()" in source
    assert "import sqlite3" not in source
    assert "from server.sli.core.postgres_runtime_pipeline import connect" in source
    assert "cur.execute(_pg_sql(sql), params)" in source
    assert "get_entity_summary" in source
    # Storage V2 is the only route (plan 6.5): summaries read the V2 projection.
    assert "query_rows(\"select count(*) as count from entities_v2\"" in source

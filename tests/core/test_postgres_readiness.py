from __future__ import annotations

from pathlib import Path


def test_postgres_schema_is_safe_and_contains_core_tables() -> None:
    text = Path("config/postgres_schema.sql").read_text(encoding="utf-8").lower()
    for table in (
        "schema_migrations",
        "log_sources",
        "collection_channel_state",
        "collector_channel_runs",
        "collector_stage_metrics",
        "events",
        "findings",
        "ai_api_runs",
    ):
        assert f"create table if not exists {table}" in text
    assert "datetime('now')" not in text
    assert "insert or ignore" not in text
    assert "on conflict" in text

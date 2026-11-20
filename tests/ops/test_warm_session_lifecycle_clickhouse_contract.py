from pathlib import Path


SQL = Path(
    "config/clickhouse/001_warm_session_lifecycle_revisions.sql"
).read_text(encoding="utf-8").lower()


def test_schema_is_append_only_and_effective_reads_fail_closed_on_conflict() -> None:
    assert "session_lifecycle_revisions" in SQL
    assert "event_session_placement_revisions" in SQL
    assert "sessions_effective_v1" in SQL
    assert "event_placement_effective_v1" in SQL
    assert "revision_rows=1" in SQL
    assert "session_lifecycle_conflicts_v1" in SQL
    assert "alter table" not in SQL
    assert " delete " not in SQL



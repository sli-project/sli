from __future__ import annotations

from pathlib import Path



ROOT = Path(__file__).resolve().parents[2]
CATALOG_VERSION = "2026-10-16-descriptor-v8-directory-change"


def test_migrations_are_online_phased_and_preserve_unclassified_rows() -> None:
    columns = (
        ROOT
        / "config/postgres_migrations/048_event_noise_classification_columns.sql"
    ).read_text(encoding="utf-8").lower()
    index = (
        ROOT
        / "config/postgres_migrations/049_event_noise_browse_index.sql"
    ).read_text(encoding="utf-8").lower()

    assert "noise_class text" in columns
    assert "default 'not_classified'" in columns
    assert "noise_catalog_version text" in columns
    assert "default 'pending-backfill'" in columns
    assert "update events_v2_core" not in columns
    assert "create index concurrently" in index
    assert "noise_catalog_version='pending-backfill'" in index
    assert "noise_class in ('signal', 'not_classified')" in index
    assert "(coalesce(event_record_id, -1)) desc" in index

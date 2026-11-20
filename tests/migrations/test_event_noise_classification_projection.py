from __future__ import annotations

from pathlib import Path

from server.sli.events.event_catalog import event_noise_classification
from server.sli.storage.storage_v2_models import event_core_from_v1
from server.sli.storage.storage_v2_repository import EVENT_V2_WRITE_COLUMNS


ROOT = Path(__file__).resolve().parents[2]
CATALOG_VERSION = "2026-10-16-descriptor-v8-directory-change"


def test_noise_classification_uses_channel_and_provider_not_event_id_alone() -> None:
    assert event_noise_classification(
        142,
        "System",
        "Microsoft-Windows-Time-Service",
    ) == ("context", CATALOG_VERSION)
    assert event_noise_classification(
        142,
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-TaskScheduler",
    ) == ("signal", CATALOG_VERSION)
    assert event_noise_classification(
        108,
        "System",
        "Application Management Group Policy",
    ) == ("signal", CATALOG_VERSION)
    assert event_noise_classification(
        108,
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-TaskScheduler",
    ) == ("context", CATALOG_VERSION)


def test_missing_catalogue_entry_is_explicit_and_versioned() -> None:
    assert event_noise_classification(
        999_999,
        "Security",
        "Unknown Provider",
    ) == ("not_classified", CATALOG_VERSION)


def test_storage_v2_write_projection_carries_class_and_catalogue_version() -> None:
    row = {
        "id": 1,
        "server_id": 1,
        "domain_id": 1,
        "log_source_id": 1,
        "event_id": 4624,
        "channel": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "time_created_utc": "2026-07-29T00:00:00Z",
        "normalized_at": "2026-07-29T00:00:01Z",
    }
    dictionaries = {
        "channel": {"Security": 1},
        "provider": {"Microsoft-Windows-Security-Auditing": 1},
    }

    projected = event_core_from_v1(row, dictionaries)

    assert projected.values["noise_class"] == "context"
    assert projected.values["noise_catalog_version"] == CATALOG_VERSION
    assert {"noise_class", "noise_catalog_version"} <= EVENT_V2_WRITE_COLUMNS


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





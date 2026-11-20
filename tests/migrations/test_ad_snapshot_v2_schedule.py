from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest


ROOT = Path(__file__).resolve().parents[2]
DOMAIN_SID = "S-1-5-21-111-222-333"


def _member(family: str, source_id: str, observed_at_utc: str, digest: str) -> dict[str, object]:
    return {
        "family": family,
        "contract_id": {
            "ad_context_base": "sli.windows.ad-context",
            "computers_v6": "sli.ad-computers.snapshot/2.0",
        }[family],
        "source_id": source_id,
        "observed_at_utc": observed_at_utc,
        "source_state": "complete",
        "payload_sha256": digest * 64,
        "reason_code": None,
    }


def _resolver(member: dict[str, object]) -> dict[str, object]:
    return {
        "family": member["family"],
        "contract_id": member["contract_id"],
        "source_id": member["source_id"],
        "domain_id": 7,
        "domain_sid": DOMAIN_SID,
        "domain_dns": "example.test",
        "observed_at_utc": member["observed_at_utc"],
        "source_state": member["source_state"],
        "payload_sha256": member["payload_sha256"],
        "import_state": "completed",
    }


def _manifest(*, contract_version: str, slot_start_utc: str, observed_at_utc: str, header: dict[str, object] | None = None) -> dict[str, object]:
    from server.ad_context.snapshot_manifest import canonical_manifest_sha256

    value: dict[str, object] = {
        "contract_version": contract_version,
        "manifest_id": "00000000-0000-4000-8000-000000000128",
        "domain_id": 7,
        "domain_sid": DOMAIN_SID,
        "domain_dns": "example.test",
        "slot_start_utc": slot_start_utc,
        "assembled_at_utc": observed_at_utc,
        "coverage_state": "complete",
        "members": [
            _member("ad_context_base", "00000000-0000-4000-8000-000000000121", observed_at_utc, "a"),
            _member("computers_v6", "00000000-0000-4000-8000-000000000122", observed_at_utc, "b"),
        ],
        **(header or {}),
    }
    value["manifest_sha256"] = canonical_manifest_sha256(value)
    return value


def test_v2_header_is_zone_bound_while_v1_rows_remain_valid() -> None:
    from server.ad_context.snapshot_manifest import (
        SCHEDULE_TIMEZONE,
        V1_CONTRACT_VERSION,
        V2_CONTRACT_VERSION,
        SnapshotManifestError,
        CONTRACT_VERSION,
        validate_snapshot_manifest,
    )

    assert CONTRACT_VERSION == V2_CONTRACT_VERSION

    legacy = _manifest(
        contract_version=V1_CONTRACT_VERSION,
        slot_start_utc="2026-09-01T12:00:00Z",
        observed_at_utc="2026-09-01T12:05:00Z",
    )
    assert validate_snapshot_manifest(legacy, resolve_source=_resolver)["contract_version"] == V1_CONTRACT_VERSION

    v2 = _manifest(
        contract_version=V2_CONTRACT_VERSION,
        slot_start_utc="2026-09-01T11:00:00Z",
        observed_at_utc="2026-09-01T11:05:00Z",
        header={
            "schedule_timezone": SCHEDULE_TIMEZONE,
            "scheduled_local_at": "2026-09-01T18:00:00",
        },
    )
    normalized = validate_snapshot_manifest(v2, resolve_source=_resolver)
    assert normalized["contract_version"] == V2_CONTRACT_VERSION
    assert normalized["schedule_timezone"] == "Asia/Novosibirsk"
    assert normalized["scheduled_local_at"] == "2026-09-01T18:00:00"

    wrong_slot = copy.deepcopy(v2)
    wrong_slot["slot_start_utc"] = "2026-09-01T12:00:00Z"
    wrong_slot["scheduled_local_at"] = "2026-09-01T19:00:00"
    with pytest.raises(SnapshotManifestError, match="slot|scheduled"):
        validate_snapshot_manifest(wrong_slot, resolve_source=_resolver)


def test_calendar_boundaries_map_through_zoneinfo_and_do_not_drift() -> None:
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker

    local_zone = ZoneInfo("Asia/Novosibirsk")
    morning = worker.scheduled_slot_from_local(datetime(2026, 9, 1, 6, tzinfo=local_zone))
    evening = worker.scheduled_slot_from_local(datetime(2026, 9, 1, 18, tzinfo=local_zone))
    assert morning.slot_start_utc == "2026-08-31T23:00:00Z"
    assert morning.scheduled_local_at == "2026-09-01T06:00:00"
    assert evening.slot_start_utc == "2026-09-01T11:00:00Z"
    assert evening.scheduled_local_at == "2026-09-01T18:00:00"

    resolved_slot, resolved_contract, resolved_header = worker._resolve_manifest_slot(
        evening.slot_start_utc,
        contract_version="sli.ad-snapshot-manifest/2.0",
        schedule_timezone=evening.schedule_timezone,
        scheduled_local_at=evening.scheduled_local_at,
    )
    assert resolved_slot == evening.slot_start_utc
    assert resolved_contract == "sli.ad-snapshot-manifest/2.0"
    assert resolved_header == evening

    worker_manifest = worker._exact_manifest(
        slot=resolved_slot,
        domain={"id": 7, "sid": DOMAIN_SID, "dns": "example.test"},
        members=[
            _member("ad_context_base", "00000000-0000-4000-8000-000000000121", "2026-09-01T11:05:00Z", "a"),
            _member("computers_v6", "00000000-0000-4000-8000-000000000122", "2026-09-01T11:05:00Z", "b"),
        ],
        assembled_at="2026-09-01T11:05:00Z",
        contract_version=resolved_contract,
        scheduled_slot=resolved_header,
    )
    assert worker_manifest["schedule_timezone"] == "Asia/Novosibirsk"
    assert worker_manifest["scheduled_local_at"] == "2026-09-01T18:00:00"

    before_evening = datetime(2026, 9, 1, 10, 59, 59, tzinfo=timezone.utc)
    assert worker.latest_due_scheduled_slot(before_evening).slot_start_utc == morning.slot_start_utc
    assert worker.next_scheduled_slot(before_evening).slot_start_utc == evening.slot_start_utc

    late_restart = datetime(2026, 9, 3, 15, 37, tzinfo=timezone.utc)
    assert worker.latest_due_scheduled_slot(late_restart).slot_start_utc == "2026-09-03T11:00:00Z"
    assert worker.next_scheduled_slot(late_restart).slot_start_utc == "2026-09-03T23:00:00Z"


def test_scheduler_selects_only_the_latest_due_slot_and_waits_by_calendar() -> None:
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker

    now = datetime(2026, 9, 3, 15, 37, tzinfo=timezone.utc)
    first = worker.latest_due_scheduled_slot(now)
    repeated = worker.latest_due_scheduled_slot(now)
    assert first == repeated
    assert first.slot_start_utc == "2026-09-03T11:00:00Z"
    assert worker.seconds_until_next_scheduled_slot(now) == 26_580

    source = (ROOT / "scripts/runtime/ad_snapshot_manifest_coordinator_worker.py").read_text(encoding="utf-8")
    assert "time.sleep(INTERVAL_SECONDS)" not in source
    assert "next_scheduled_slot" in source


def test_migration_128_and_schema_have_version_aware_schedule_contract() -> None:
    forward = (ROOT / "config/postgres_migrations/128_ad_snapshot_v2_schedule.sql").read_text(encoding="utf-8").casefold()
    rollback = (ROOT / "config/postgres_migrations/128_ad_snapshot_v2_schedule.rollback.sql").read_text(encoding="utf-8").casefold()
    schema = (ROOT / "config/postgres_schema.sql").read_text(encoding="utf-8").casefold()

    assert "migration 123 ad_snapshot_manifest_utc_slots is required" in forward
    assert "migration 127" not in forward
    assert "sli.ad-snapshot-manifest/1.0" in forward
    assert "sli.ad-snapshot-manifest/2.0" in forward
    assert "schedule_timezone" in forward
    assert "scheduled_local_at" in forward
    assert "at time zone 'asia/novosibirsk'" in forward
    assert "values (128, 'ad_snapshot_v2_schedule')" in forward
    assert "before insert" in forward
    assert "ad_snapshot_manifest_apply_v2_schedule_header" in forward
    for forbidden in ("drop table", "truncate", "delete from ad_snapshot_", "grant ", "revoke "):
        assert forbidden not in forward

    assert "v2 manifest rows exist" in rollback
    assert "delete from schema_migrations where version = 128" in rollback
    assert "drop column schedule_timezone" in rollback
    assert "drop column scheduled_local_at" in rollback
    for forbidden in ("drop table", "truncate", "delete from ad_snapshot_"):
        assert forbidden not in rollback

    assert "create table if not exists ad_snapshot_manifests" in schema
    assert "schedule_timezone text" in schema
    assert "scheduled_local_at timestamp without time zone" in schema
    assert "sli.ad-snapshot-manifest/2.0" in schema

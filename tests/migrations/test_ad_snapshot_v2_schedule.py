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

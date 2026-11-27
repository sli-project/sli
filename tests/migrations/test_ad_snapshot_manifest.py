from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest



ROOT = Path(__file__).resolve().parents[2]
SLOT = "2026-08-31T12:00:00Z"
DOMAIN_SID = "S-1-5-21-111-222-333"


def _members() -> list[dict[str, object]]:
    return [
        {
            "family": "ad_context_base",
            "contract_id": "sli.windows.ad-context",
            "source_id": "00000000-0000-4000-8000-000000000121",
            "observed_at_utc": "2026-08-31T12:05:00Z",
            "source_state": "complete",
            "payload_sha256": "a" * 64,
            "reason_code": None,
        },
        {
            "family": "computers_v6",
            "contract_id": "sli.ad-computers.snapshot/2.0",
            "source_id": "00000000-0000-4000-8000-000000000122",
            "observed_at_utc": "2026-08-31T12:06:00Z",
            "source_state": "complete",
            "payload_sha256": "b" * 64,
            "reason_code": None,
        },
        {
            "family": "gpo_v2",
            "contract_id": "sli.ad-gpo.snapshot/1.0",
            "source_id": "00000000-0000-4000-8000-000000000123",
            "observed_at_utc": "2026-08-31T12:07:00Z",
            "source_state": "partial",
            "payload_sha256": "c" * 64,
            "reason_code": "optional_source_partial",
        },
    ]


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


class _Cursor:
    def __init__(self, existing: dict[str, object] | None = None) -> None:
        self.existing = existing
        self.executed: list[tuple[str, object]] = []
        self._one = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if "from ad_snapshot_manifests" in sql:
            self._one = self.existing
        else:
            self._one = None

    def fetchone(self):
        return self._one


class _Connection:
    def __init__(self, existing: dict[str, object] | None = None) -> None:
        self.cursor_value = _Cursor(existing)

    def cursor(self):
        return self.cursor_value


def test_migration_is_additive_restrictive_and_rollback_is_fail_closed() -> None:
    forward = (ROOT / "config/postgres_migrations/121_ad_snapshot_manifest_foundation.sql").read_text(encoding="utf-8").casefold()
    rollback = (ROOT / "config/postgres_migrations/121_ad_snapshot_manifest_foundation.rollback.sql").read_text(encoding="utf-8").casefold()

    assert "create table if not exists ad_snapshot_manifests" in forward
    assert "create table if not exists ad_snapshot_manifest_sources" in forward
    assert "unique(domain_id,slot_start_utc,contract_version)" in forward.replace(" ", "")
    assert "payload_json" not in forward and "command" not in forward
    assert "on delete restrict" in forward and "on delete cascade" not in forward
    assert "ad_snapshot_manifest_reject_mutation" in forward
    assert forward.count("before update or delete or truncate") == 2
    assert forward.count("drop trigger if exists") == 2
    assert "create index if not exists idx_ad_snapshot_manifests_slot" in forward
    assert "revoke all on ad_snapshot_manifests from public" in forward
    grant_lines = [line.strip() for line in forward.splitlines() if "grant " in line]
    manifest_grants = [line for line in grant_lines if "projection_receipts" not in line]
    receipt_grants = [line for line in grant_lines if "projection_receipts" in line]
    assert manifest_grants and receipt_grants
    assert all("grant select, insert" in line for line in manifest_grants)
    assert all("update" not in line and "delete" not in line for line in manifest_grants)
    assert all("grant select, insert, update" in line and "delete" not in line for line in receipt_grants)
    assert "values(121,'ad_snapshot_manifest_foundation')" in forward.replace(" ", "")
    assert "raise exception" in rollback
    assert "manifest rows exist" in rollback
    assert "cascade" not in rollback and "delete from ad_snapshot" not in rollback


def test_migration_121_rejects_conflicting_version_before_ddl_and_exact_reapply_is_idempotent() -> None:
    forward = (ROOT / "config/postgres_migrations/121_ad_snapshot_manifest_foundation.sql").read_text(
        encoding="utf-8"
    ).casefold()
    guard = "name is distinct from 'ad_snapshot_manifest_foundation'"

    assert guard in forward
    assert forward.index(guard) < forward.index("create table")
    assert "on conflict(version) do nothing" in " ".join(forward.split())
    assert "on conflict(version) do update" not in " ".join(forward.split())

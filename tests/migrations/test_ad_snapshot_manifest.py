from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.ad_context.snapshot_manifest import (
    V1_CONTRACT_VERSION as CONTRACT_VERSION,
    SnapshotManifestError,
    canonical_manifest_sha256,
    validate_snapshot_manifest,
)
from server.ad_context.repository import publish_snapshot_manifest


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


def _manifest() -> dict[str, object]:
    value: dict[str, object] = {
        "contract_version": CONTRACT_VERSION,
        "manifest_id": "00000000-0000-4000-8000-000000000124",
        "domain_id": 7,
        "domain_sid": DOMAIN_SID,
        "domain_dns": "EXAMPLE.TEST",
        "slot_start_utc": SLOT,
        "assembled_at_utc": "2026-08-31T12:08:00Z",
        "coverage_state": "partial",
        "members": _members(),
    }
    value["manifest_sha256"] = canonical_manifest_sha256(value)
    return value


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


def test_manifest_canonicalizes_allowed_unique_members_and_hash() -> None:
    normalized = validate_snapshot_manifest(_manifest(), resolve_source=_resolver)

    assert normalized["domain_dns"] == "example.test"
    assert normalized["coverage_state"] == "partial"
    assert [member["family"] for member in normalized["members"]] == [
        "ad_context_base", "computers_v6", "gpo_v2"
    ]
    assert normalized["manifest_sha256"] == canonical_manifest_sha256(normalized)
    assert all(set(member) == {
        "family", "contract_id", "source_id", "observed_at_utc",
        "source_state", "payload_sha256", "reason_code",
    } for member in normalized["members"])


def test_agent_manifest_keeps_exact_minute_slot_and_source_readback():
    value = _manifest()
    value.update(contract_version="sli.ad-snapshot-manifest/3.0",
                 slot_start_utc="2026-08-31T11:45:00Z", schedule_timezone="UTC",
                 scheduled_local_at="2026-08-31T11:45:00")
    value["manifest_sha256"] = canonical_manifest_sha256(value)
    assert validate_snapshot_manifest(value, resolve_source=_resolver)["schedule_timezone"] == "UTC"
    value["scheduled_local_at"] = "2026-08-31T13:00:00"
    with pytest.raises(SnapshotManifestError, match="schedule header"):
        canonical_manifest_sha256(value)


@pytest.mark.parametrize("observed_at", ["2026-08-31T11:44:59Z", "2026-08-31T12:08:01Z"])
def test_agent_manifest_rejects_sources_outside_exact_cycle(observed_at):
    value = _manifest()
    value.update(contract_version="sli.ad-snapshot-manifest/3.0",
                 slot_start_utc="2026-08-31T11:45:00Z", schedule_timezone="UTC",
                 scheduled_local_at="2026-08-31T11:45:00")
    value["members"][0]["observed_at_utc"] = observed_at
    value["manifest_sha256"] = canonical_manifest_sha256(value)
    with pytest.raises(SnapshotManifestError, match="outside the agent cycle"):
        validate_snapshot_manifest(value, resolve_source=_resolver)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda value: value.update({"command": "collect"}), "unsupported"),
        (lambda value: value["members"].append(copy.deepcopy(value["members"][0])), "unique"),
        (lambda value: value["members"][0].update({"family": "radius"}), "family"),
        (lambda value: value["members"][0].update({"payload": {"copied": True}}), "unsupported"),
        (lambda value: value.update({"manifest_sha256": "0" * 64}), "hash"),
    ],
)
def test_manifest_rejects_unknown_duplicate_payload_or_hash_mismatch(mutate, match) -> None:
    value = _manifest()
    mutate(value)
    with pytest.raises(SnapshotManifestError, match=match):
        validate_snapshot_manifest(value, resolve_source=_resolver)


def test_manifest_rejects_cross_domain_out_of_window_or_nonimported_source() -> None:
    for field, replacement, match in (
        ("domain_id", 8, "domain"),
        ("observed_at_utc", "2026-09-01T00:00:00Z", "slot"),
        ("import_state", "importing", "completed"),
    ):
        def resolver(member, field=field, replacement=replacement):
            result = _resolver(member)
            result[field] = replacement
            return result

        with pytest.raises(SnapshotManifestError, match=match):
            validate_snapshot_manifest(_manifest(), resolve_source=resolver)


def test_manifest_rejects_source_hash_or_state_readback_mismatch() -> None:
    for field, replacement in (("payload_sha256", "d" * 64), ("source_state", "complete")):
        def resolver(member, field=field, replacement=replacement):
            result = _resolver(member)
            if member["family"] == "gpo_v2":
                result[field] = replacement
            return result

        with pytest.raises(SnapshotManifestError, match="readback"):
            validate_snapshot_manifest(_manifest(), resolve_source=resolver)


def test_complete_coverage_requires_complete_base_and_optional_members() -> None:
    value = _manifest()
    value["coverage_state"] = "complete"
    value["manifest_sha256"] = canonical_manifest_sha256(value)
    with pytest.raises(SnapshotManifestError, match="coverage"):
        validate_snapshot_manifest(value, resolve_source=_resolver)

    value["members"][2]["source_state"] = "complete"
    value["members"][2]["reason_code"] = None
    value["manifest_sha256"] = canonical_manifest_sha256(value)
    assert validate_snapshot_manifest(value, resolve_source=_resolver)["coverage_state"] == "complete"


def test_hard_failed_base_source_prevents_publication() -> None:
    value = _manifest()
    value["members"][1]["source_state"] = "failed"
    value["members"][1]["reason_code"] = "base_query_failed"
    value["manifest_sha256"] = canonical_manifest_sha256(value)

    with pytest.raises(SnapshotManifestError, match="base"):
        validate_snapshot_manifest(value, resolve_source=_resolver)


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


def test_publisher_exact_replay_is_idempotent_and_conflict_is_rejected() -> None:
    value = validate_snapshot_manifest(_manifest(), resolve_source=_resolver)
    exact = _Connection({
        "manifest_id": value["manifest_id"],
        "manifest_sha256": bytes.fromhex(value["manifest_sha256"]),
    })
    assert publish_snapshot_manifest(exact, value, resolve_source=_resolver) == {
        "manifest_id": value["manifest_id"], "replayed": 1
    }
    assert not any("insert into ad_snapshot" in sql for sql, _ in exact.cursor_value.executed)

    conflict = _Connection({
        "manifest_id": "00000000-0000-4000-8000-000000000999",
        "manifest_sha256": bytes.fromhex("f" * 64),
    })
    with pytest.raises(SnapshotManifestError, match="conflicting"):
        publish_snapshot_manifest(conflict, value, resolve_source=_resolver)


def test_publisher_inserts_metadata_receipt_and_member_references_only() -> None:
    conn = _Connection()
    value = _manifest()
    result = publish_snapshot_manifest(conn, value, resolve_source=_resolver)

    assert result == {"manifest_id": value["manifest_id"], "replayed": 0}
    sql = "\n".join(statement.casefold() for statement, _ in conn.cursor_value.executed)
    assert "insert into ad_snapshot_manifests" in sql
    assert sql.count("insert into ad_snapshot_manifest_sources") == len(value["members"])
    assert "payload_json" not in sql and "command" not in sql


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


def test_active_report_readers_and_writers_do_not_consume_manifest() -> None:
    active_paths = [
        ROOT / "server/sli/reports/users_v2_reporting.py",
        ROOT / "server/sli/reports/computers_v6_reporting.py",
        ROOT / "server/sli/reports/computers_v6_reporting_comparison.py",
        ROOT / "server/sli/reports/computers_v6_reporting_items.py",
        ROOT / "server/sli/reports/computers_v6_reporting_overlay.py",
        ROOT / "server/sli/plugins/gpo/reports/gpo_v2_reporting.py",
        ROOT / "server/api/routes/reports.py",
    ]
    assert all("ad_snapshot_manifest" not in path.read_text(encoding="utf-8").casefold() for path in active_paths)

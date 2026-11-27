from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest



ROOT = Path(__file__).resolve().parents[2]












NOW = datetime(2026, 8, 30, 2, 0, tzinfo=timezone.utc)


class _Cursor:
    def __init__(
        self,
        *,
        inserted: bool = True,
        readback_matches: bool = True,
    ) -> None:
        self.inserted = inserted
        self.readback_matches = readback_matches
        self.phase = ""
        self.statements: list[tuple[str, tuple]] = []
        self.rowcount = 0
        self.expected_count = 0
        self.expected_hash = b""
        self.expected_uuid = ""

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.statements.append((sql, params))
        normalized = " ".join(sql.casefold().split())
        if "select id from domains" in normalized:
            self.phase = "domain"
        elif "insert into computers_v6_source_snapshots" in normalized:
            self.phase = "insert"
            self.expected_uuid = str(params[1])
            self.expected_count = int(params[12])
            self.expected_hash = bytes(params[15])
        elif "select source_snapshot_id,object_count,payload_sha256,snapshot_uuid" in normalized:
            self.phase = "conflict_readback"
        elif "select object_count,payload_sha256,snapshot_uuid" in normalized:
            self.phase = "readback"
        elif "delete from computers_v6_source_snapshots" in normalized:
            self.phase = "delete"
            self.rowcount = 2

    def fetchone(self):
        if self.phase == "domain":
            return {"id": 7}
        if self.phase == "insert":
            return {"source_snapshot_id": 114} if self.inserted else None
        if self.phase in {"readback", "conflict_readback"}:
            row = {
                "object_count": (
                    self.expected_count
                    if self.readback_matches
                    else self.expected_count + 1
                ),
                "payload_sha256": self.expected_hash,
                "snapshot_uuid": self.expected_uuid,
            }
            if self.phase == "conflict_readback":
                row["source_snapshot_id"] = 114
            return row
        return None


class _Connection:
    def __init__(self, cursor: _Cursor) -> None:
        self.cursor_value = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        cursor = self.cursor_value

        class _Context:
            def __enter__(self):
                return cursor

            def __exit__(self, *_args):
                return False

        return _Context()


def _options() -> dict[str, object]:
    return {
        "server": "dc01.example.test",
        "search_base": None,
        "skip_dns": False,
        "collect_ad_site": True,
        "collect_exact_last_logon": True,
    }






def test_source_snapshot_migration_and_rollback_match_worker_contract() -> None:
    apply_path = (
        ROOT / "config/postgres_migrations/114_computers_v6_source_snapshot.sql"
    )
    rollback_path = (
        ROOT
        / "config/postgres_migrations/114_computers_v6_source_snapshot.rollback.sql"
    )
    assert apply_path.is_file(), "V6 source snapshot migration is missing"
    assert rollback_path.is_file(), "V6 source snapshot rollback is missing"

    apply = " ".join(apply_path.read_text(encoding="utf-8").casefold().split())
    rollback = " ".join(
        rollback_path.read_text(encoding="utf-8").casefold().split()
    )
    assert "version=113 and name='computers_report_v6'" in apply
    assert "create table computers_v6_source_snapshots" in apply
    for column in (
        "snapshot_uuid",
        "source_started_at_utc",
        "source_completed_at_utc",
        "captured_at_utc",
        "collector_sha256",
        "collection_status",
        "base_inventory_status",
        "source_options_json",
        "payload_json",
        "payload_sha256",
        "collector_exit_code",
    ):
        assert column in apply
    assert "object_count between 0 and 250000" in apply
    assert "octet_length(payload_json::text) <= 67108864" in apply
    assert "computers_v6_source" in apply
    assert "values(114,'computers_v6_source_snapshot')" in apply
    assert "drop table computers_v6_source_snapshots" in rollback
    assert "version=114 and name='computers_v6_source_snapshot'" in rollback
    assert "computers_v6_source" not in rollback.split(
        "add constraint runtime_worker_heartbeats_name check", 1
    )[1].split(");", 1)[0]






def test_collector_adapter_keeps_reference_immutable_and_bounds_exact_logon_fix() -> None:
    adapter = (
        ROOT / "scripts/ad_context/Export-ComputersV6ReferenceSnapshot.ps1"
    ).read_text(encoding="utf-8")
    assert "Get-FileHash -LiteralPath $ReferenceCollector -Algorithm SHA256" in adapter
    assert "$ExactLogonCastCount -ne 1" in adapter
    assert "$RawLastLogon = @($Row.lastLogon)" in adapter
    assert "$ReferenceSource.Replace($UnsafeExactLogonCast" in adapter
    assert "$DomainControllersAnchorCount -ne 1" in adapter
    assert "$ReferenceSource.Replace($TypedDomainControllers" in adapter
    assert "$GenericListArrayAnchorCount -ne 1" in adapter
    assert "$SuccessfulDcs.ToArray()" in adapter
    assert "$SubnetParameterAnchorCount -ne 1" in adapter
    assert "[AllowEmptyCollection()][object[]]$SubnetRecords" in adapter
    assert "$ObservedAtAnchorCount -ne 1" in adapter
    assert "[Nullable[datetime]]$ObservedAt" in adapter
    assert "$SpnProjectionAnchorCount -ne 1" in adapter
    assert "ForEach-Object { [string]$_ }" in adapter
    assert "$ObjectErrorsAnchorCount -ne 1" in adapter
    assert "$GlobalErrorsAnchorCount -ne 1" in adapter
    assert "$ObjectsAnchorCount -ne 1" in adapter
    assert "Reference collector failed" in adapter

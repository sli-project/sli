"""Recorded synthetic legacy dataset/report bytes for directory VPN v1."""
from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.sli.plugins.remote_access import entitlements
from server.sli.plugins.remote_access.reports import vpn_connections_reporting

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _bytes(value):
    return (json.dumps(value, ensure_ascii=False) + "\n").encode("utf-8")


class Cursor:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))

    def fetchall(self):
        return self.rows


def test_v1_adapter_preserves_recorded_legacy_rows_and_report_bytes():
    recorded = (FIXTURES / "vpn_entitlements_v1.rows.json").read_bytes()
    rows = json.loads(recorded)
    cursor = Cursor(rows)
    snapshot = entitlements.read_entitlements(cursor, source_domain_id=7)
    assert snapshot.contract_id == "directory.vpn_entitlements.v1"
    assert snapshot.source_domain_id == 7
    assert _bytes(snapshot.as_rows()) == recorded
    sql, params = cursor.calls[0]
    assert params == (7, 5_001)
    assert "source_entity.domain_id=%s" in sql
    assert "relation.valid_to_utc is null" in sql
    assert "relation.source_section='vpn_membership'" in sql
    assert "entity_v2_is_active(source_entity.id)" in sql
    assert "order by source_entity.id limit %s" in sql
    report = vpn_connections_reporting.compose_vpn_connections_report(
        source_domain_id=7, period_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        period_end=datetime(2026, 1, 2, tzinfo=timezone.utc), office_timezone="UTC",
        coverage={}, session_rows=[], identities={}, entitlement_rows=snapshot.as_rows(),
        failed_events=[], failed_collection_state="not_collected",
    )
    assert _bytes(report["entitlements"]) == (FIXTURES / "vpn_entitlements_v1.report.json").read_bytes()


def test_v1_snapshot_is_immutable_and_does_not_share_mutable_rows():
    rows = [{"entity_id": 11}]
    snapshot = entitlements.read_entitlements(Cursor(rows), source_domain_id=7)
    rows[0]["entity_id"] = 99
    snapshot.as_rows()[0]["entity_id"] = 29
    assert snapshot.entity_ids == (11,)
    with pytest.raises(FrozenInstanceError):
        snapshot.source_domain_id = 8


@pytest.mark.parametrize("count", [0, 5_000, 5_001])
def test_v1_adapter_keeps_the_existing_bound(count):
    cursor = Cursor([{"entity_id": entity_id} for entity_id in range(1, count + 1)])
    if count > entitlements.MAX_ENTITLEMENT_ROWS:
        with pytest.raises(ValueError, match="vpn_connections_entitlement_bound_exceeded"):
            entitlements.read_entitlements(cursor, source_domain_id=7)
    else:
        assert len(entitlements.read_entitlements(cursor, source_domain_id=7).entity_ids) == count

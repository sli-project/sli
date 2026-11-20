from __future__ import annotations

from types import SimpleNamespace

import pytest

from server.sli.reports import computers_v6_reporting as reporting


@pytest.fixture(autouse=True)
def _domains(monkeypatch):
    monkeypatch.setattr(reporting, "query_rows_bounded", lambda *a, **k: [{"id": 1, "fqdn": "synthetic.example.test"}])


def _source_snapshot() -> dict:
    state = lambda status, source, value=None: {
        "status": status,
        "source": source,
        "value": value,
        "observed_at": "2026-08-30T00:00:00Z" if status != "not_collected" else None,
        "error": None,
        "details": None,
    }
    return {
        "source_snapshot_id": 9,
        "domain_id": 1,
        "collection_status": "partial",
        "base_inventory_status": "observed",
        "snapshot": {
            "schema_version": "2.0",
            "metadata": {
                "snapshot_id": "00000000-0000-4000-8000-000000000009",
                "completed_at": "2026-08-30T00:00:00Z",
                "query_dc": "DC2",
                "collector_version": "reference-v2",
                "collection_status": "partial",
                "errors": [],
                "sources": [],
            },
            "objects": [{
                "objectGuid": "11111111-2222-3333-4444-555555555555",
                "ipv4s": ["10.20.30.40"],
                "ipv6s": ["2001:db8::10"],
                "adSite": "SITE-A",
                "exactLastLogon": "2026-08-29T00:00:00Z",
                "servicePack": "SP1",
                "classification": {"result": "server", "state": "observed", "rule_id": "dc-list", "rule_version": 1, "evidence": ["DC2"]},
                "roleHint": "domain_controller",
                "roleEvidence": ["dc-list"],
                "sources": {
                    "dns": state("observed", "dns", ["10.20.30.40", "2001:db8::10"]),
                    "site": state("observed", "site", "SITE-A"),
                    "exact_last_logon": state("observed", "exact_last_logon", "2026-08-29T00:00:00Z"),
                    "dc_events": state("not_collected", "dc_events"),
                },
                "collectionErrors": [],
            }],
        },
    }


def test_source_overlay_maps_by_object_guid_and_preserves_explicit_states(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reporting, "load_latest_computers_v6_source_snapshot", lambda _connection, *, domain_fqdn: _source_snapshot(), raising=False)
    monkeypatch.setattr(reporting, "connect", lambda: SimpleNamespace(close=lambda: None), raising=False)

    overlay = reporting._load_computers_v6_source_overlay([1])
    item = {
        "domain_id": 1,
        "object_guid": "11111111-2222-3333-4444-555555555555",
        "ip_addresses": [],
        "network": {"ad_site": {"state": "not_collected", "value": None}},
        "activity": {},
        "evidence": {},
    }
    reporting._apply_computers_v6_source_overlay(item, overlay)

    assert item["ip_addresses"] == ["10.20.30.40", "2001:db8::10"]
    assert item["ad_site"] == {"state": "observed", "value": "SITE-A"}
    assert item["activity"]["exact_last_logon"]["value"] == "2026-08-29T00:00:00Z"
    assert item["classification"]["rule_id"] == "dc-list"
    assert item["evidence"]["source_states"]["dns"]["status"] == "observed"
    assert item["evidence"]["source_states"]["dc_events"]["status"] == "not_collected"
    assert item["source_snapshot"]["query_dc"] == "DC2"


def test_failed_latest_source_is_explicit_and_does_not_replace_base_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    failed = {
        "source_snapshot_id": 10,
        "domain_id": 1,
        "collection_status": "failed",
        "base_inventory_status": "failed",
        "snapshot": {"metadata": {"completed_at": "2026-08-30T01:00:00Z", "query_dc": "DC2", "collector_version": "reference-v2", "errors": ["ad_failed"]}, "objects": []},
    }
    monkeypatch.setattr(reporting, "load_latest_computers_v6_source_snapshot", lambda _connection, *, domain_fqdn: failed, raising=False)
    monkeypatch.setattr(reporting, "connect", lambda: SimpleNamespace(close=lambda: None), raising=False)

    overlay = reporting._load_computers_v6_source_overlay([1])
    item = {"domain_id": 1, "object_guid": "base-guid", "display_name": "BASE"}
    reporting._apply_computers_v6_source_overlay(item, overlay)

    assert item["display_name"] == "BASE"
    assert item["source_snapshot"]["state"] == "failed"
    assert item["source_snapshot"]["errors"] == ["ad_failed"]

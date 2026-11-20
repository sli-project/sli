"""Synthetic SQL-boundary regressions; never open a database or contact AD."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.sli.plugins.ad.context import repository


@pytest.mark.parametrize("mode", ["full", "reconcile", "targeted"])
@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("status,inventory,expected", [
    ("partial", "access_denied", False),
    ("partial", "observed", False),
    ("complete", "failed", False),
    ("complete", None, False),
    ("failed", "observed", False),
    ("complete", "observed", True),
])
def test_empty_embedded_inventory_cannot_close_prior_gpos(monkeypatch, mode, status, inventory, expected, legacy):
    # Keep validation independent here: this test exercises import orchestration
    # with the normalized output of the wire validator, including older bundles
    # whose outer section incorrectly says complete.
    snapshot = {"collection_status": status, "source_states": {
        "gpc_directory": {"status": "observed"},
    }}
    if inventory is not None:
        snapshot["source_states"]["gpo_list"] = {"status": inventory}
    bundle = {
        "domain": {}, "run_id": "synthetic", "mode": mode,
        "observed_at_utc": "2026-10-22T00:00:00Z",
        "records": [], "scope": {}, "gpo_v2_snapshot": snapshot,
        "sections": [{"name": "gpo_governance", "status": "complete",
                      "record_count": 0, "duration_ms": 0, "error_code": None}],
    }
    if legacy:
        bundle.pop("gpo_v2_snapshot")
    original = deepcopy(bundle)
    monkeypatch.setattr(repository, "validate_bundle", lambda value: value)
    monkeypatch.setattr(repository, "_resolve_domain", lambda *_: 7)
    monkeypatch.setattr(repository, "_start_run", lambda *_: False)
    monkeypatch.setattr(repository, "_preload_existing_entity_ids", lambda *_: {})
    store = Mock()
    monkeypatch.setattr(repository, "_store_gpo_v2_snapshot", store)
    calls = []
    cursor = Mock(rowcount=3)
    cursor.execute.side_effect = lambda sql, params: calls.append((" ".join(sql.split()), params))
    cursor.__enter__ = Mock(return_value=cursor)
    cursor.__exit__ = Mock(return_value=False)
    result = repository.import_bundle(SimpleNamespace(cursor=lambda: cursor), bundle)
    closures = [(sql, params) for sql, params in calls if "update ad_context_entity_versions" in sql]
    inserted = [params for sql, params in calls if "insert into ad_context_sections" in sql]
    assert len(inserted) == 1
    assert inserted[0][2] == ("complete" if expected or legacy else "partial")
    should_close = (expected or legacy) and mode != "targeted"
    assert len(closures) == int(should_close)
    assert result["entities_closed"] == (3 if should_close else 0)
    if closures:
        assert closures[0][1][-1] == []  # Complete empty really removes prior inventory.
    assert store.call_count == int(not legacy)
    assert bundle == original


def test_exporter_propagates_native_acquisition_status():
    root = Path(__file__).resolve().parents[2]
    native = (root / "scripts/ad_context/Export-AdGpoV2Snapshot.ps1").read_text()
    outer = (root / "scripts/ad_context/Export-AdAuditContextBundle.ps1").read_text()
    projection = native.split('$compatibilityProjection = [pscustomobject][ordered]@{', 1)[1]
    assert 'collection_status = $collectionStatus' in projection
    branch = outer.split('if ($CollectionProfile -eq "gpo_governance_v4") {', 1)[1]
    assert '$gpoCompatibilityProjection.collection_status -eq "complete"' in branch
    assert '$gpoV2Snapshot.source_states.gpo_list.status -eq "observed"' in branch
    assert '$sectionStatus["gpo_governance"] = if ($gpoAcquisitionComplete)' in branch


@pytest.mark.parametrize("status,inventory", [("partial", "access_denied"), ("complete", "observed")])
def test_real_wire_validation_preserves_empty_inventory_acquisition_state(status, inventory):
    stamp = "2026-10-22T00:00:00Z"
    state = {"status": "observed", "source": "synthetic", "observed_at": stamp}
    snapshot = {
        "schema_version": "sli.ad-gpo.snapshot/1.0", "collector_version": "synthetic/1",
        "demo": False, "collection_status": status,
        **dict.fromkeys(("started_at", "completed_at", "observed_at"), stamp),
        "domain": {"dns_name": "example.test"}, "scope": {"domain": "example.test"},
        "source_states": {name: deepcopy(state) for name in (
            "gpo_list", "gpo_reports", "gpc_directory", "sysvol_gpt", "links", "permissions", "wmi_filters",
        )},
        **{name: [] for name in (
            "gpos", "scopes", "links", "settings", "permissions", "acl", "wmi_filters",
            "unresolved_links", "collection_errors",
        )},
    }
    snapshot["source_states"]["gpo_list"]["status"] = inventory
    bundle = {
        "schema_version": "ad-context-bundle/v1", "source_pack_id": "sli.windows.ad-context",
        "source_pack_version": "0.9.0", "run_id": "00000000-0000-4000-8000-000000000027",
        "mode": "full", "domain": {"sid": "S-1-5-21-1-2-3", "dns_name": "example.test"},
        "scope": {"search_base": "DC=example,DC=test", "collection_profile": "gpo_governance_v4"},
        "observed_at_utc": stamp,
        "sections": [{"name": "gpo_governance", "status": "complete", "record_count": 0,
                      "duration_ms": 0, "error_code": None}],
        "records": [], "gpo_v2_snapshot": snapshot,
    }
    normalized = repository.validate_bundle(bundle)
    assert normalized["gpo_v2_snapshot"]["collection_status"] == status
    assert normalized["gpo_v2_snapshot"]["source_states"]["gpo_list"]["status"] == inventory

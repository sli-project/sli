from __future__ import annotations


def test_legacy_product_routes_default_to_react_with_no_bypass() -> None:
    from server.sli.reporting.ui_route_parity import react_route_for_legacy, route_parity_manifest

    assert react_route_for_legacy("/reports/findings.html", {}) == "/app/scenarios"
    assert react_route_for_legacy("/reports/event-details.html", {"event_db_id": ["42"]}) == "/app/events/42"
    assert react_route_for_legacy("/vpn-report", {}) == "/app/vpn-report"
    # ?legacy=1 is no longer a bypass -- the redirect still happens.
    assert react_route_for_legacy("/reports/storage-health.html", {"legacy": ["1"]}) == "/app/operations"
    manifest = route_parity_manifest()
    assert manifest["status"] == "accepted"
    assert manifest["legacy_fallback"] == "removed"
    assert all(item["fallback"] is None for item in manifest["mapped_routes"])
    assert "/reports/ai-reports.html" in manifest["export_only_routes"]


def test_event_id_findings_are_disabled_by_default(monkeypatch) -> None:
    from server.jobs.collector import legacy_findings_enabled

    monkeypatch.delenv("ADLOG_LEGACY_FINDINGS_ENABLED", raising=False)
    assert legacy_findings_enabled() is False
    monkeypatch.setenv("ADLOG_LEGACY_FINDINGS_ENABLED", "1")
    assert legacy_findings_enabled() is True

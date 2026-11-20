"""Canonical agent computer snapshots remain readable without a legacy class field."""
from copy import deepcopy

import pytest

from test_agent_ad_snapshot import NOW, config, directory
from server.ad_context.contracts import validate_bundle
from server.sli.plugins.ad.reports import computers_v6_reporting as reporting
from sli_agent.ad_snapshot import normalize_capture


@pytest.mark.parametrize("legacy", [True, False])
@pytest.mark.parametrize("scope,expected", [([22], {1, 6}), ([11, 22], {1, 2, 6}), ([], set())])
def test_agent_computers_reach_report_with_scope_and_current_section_guards(monkeypatch, legacy, scope, expected):
    bundle = validate_bundle(normalize_capture(directory(1), config(), observed_at=NOW)["ad_context_base"][0])
    computer = next(record for record in bundle["records"] if record.get("identity", {}).get("kind") == "ad_computer")
    if legacy:
        computer["attributes"].pop("object_class")
    rows = []
    for entity_id, domain_id, kind, section, current, object_class in (
        (1, 22, "ad_computer", "directory_accounts", True, computer["attributes"].get("object_class")),
        (2, 11, "ad_computer", "directory_accounts", True, "computer"),
        (3, 22, "ad_user", "directory_accounts", True, None),
        (4, 22, "ad_computer", "domain_health", True, None),
        (5, 22, "ad_computer", "directory_accounts", False, None),
        (6, 22, "ad_computer", "directory_accounts", True, "user"),
    ):
        record = deepcopy(computer)
        if object_class is None:
            record["attributes"].pop("object_class", None)
        else:
            record["attributes"]["object_class"] = object_class
        rows.append({"entity_id": entity_id, "domain_id": domain_id, "domain_name": "synthetic.invalid",
                     "display_name": "Synthetic computer", "natural_key": str(entity_id), "identity": record["identity"],
                     "attributes": record, "observed_at_utc": NOW, "kind": kind, "section": section, "current": current})

    def query(sql, params, **kwargs):
        assert "entity_type.value='ad_computer'" in sql
        assert "entity.domain_id=any(?)" in sql
        assert "version.source_section='directory_accounts'" in sql
        assert "version.valid_to_utc is null" in sql
        # Main uses the canonical entity type; legacy attributes cannot veto it.
        assert "object_class" not in sql
        return [row for row in rows if row["domain_id"] in params[0] and row["kind"] == "ad_computer"
                and row["section"] == "directory_accounts" and row["current"]]

    monkeypatch.setattr(reporting, "query_rows_bounded", query)
    monkeypatch.setattr(reporting, "_coverage", lambda domains: {"state": "complete", "domains": []})
    monkeypatch.setattr(reporting, "_load_computers_v6_source_overlay", lambda domains: {})
    monkeypatch.setattr(reporting, "_load_snapshot_comparison", lambda domains: {"items": []})
    monkeypatch.setattr(reporting, "_semantic_rows", lambda items: [])
    payload = reporting.get_computers_v6_report(domain_ids=scope, view="all")
    assert {row["entity_id"] for row in payload["items"]} == expected
    assert payload["filtered_count"] == payload["summary"]["total_computers"] == len(expected)
    assert payload["state"] == ("available" if expected else "empty")

import pytest

from server.sli.access import access_control_v4 as access


def test_generic_grant_matches_only_the_complete_resource_scope():
    scope = {"mode": "restricted", "clauses": [{"plugin_ids": ["sli.fixture"], "source_instance_ids": ["source-1"]}]}
    assert access._scope_matches_resource(scope, {"plugin_id": "sli.fixture", "source_instance_id": "source-1"})
    assert not access._scope_matches_resource(scope, {"plugin_id": "sli.fixture", "source_instance_id": "source-2"})
    assert not access._scope_matches_resource(scope, {"kind": "domain", "id": 1})
    assert not access._scope_matches_resource({"mode": "restricted", "clauses": [{}]}, {})


def test_legacy_domain_resource_matches_generic_collection_adapter():
    scope = {"mode": "restricted", "clauses": [{"collection_scope_ids": ["ad-domain:1"]}]}
    assert access._scope_matches_resource(scope, {"kind": "domain", "id": 1})
    assert not access._scope_matches_resource(scope, {"kind": "domain", "id": 2})


class Cursor:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))

    def fetchall(self):
        return self.rows


def test_generic_assignments_validate_source_targets_against_observed_provenance():
    cursor = Cursor([{"value": "source-1"}])
    access._validate_scope_targets(cursor, "scope", {"mode": "restricted", "clauses": [{"source_instance_ids": ["source-1"]}]})
    assert "core_entity_scope_resources" in cursor.calls[0][0]
    assert cursor.calls[0][1] == (["source-1"],)
    with pytest.raises(ValueError, match="report_scope_target_not_found"):
        access._validate_scope_targets(cursor, "scope", {"mode": "restricted", "clauses": [{"source_instance_ids": ["source-2"]}]})


@pytest.mark.parametrize("scope,allowed", [
    ({"mode": "all", "clauses": []}, True),
    ({"mode": "none", "clauses": []}, False),
    ({"mode": "all", "clauses": [{}]}, False),
    ({"mode": [], "clauses": []}, False),
    ({}, False),
])
def test_explicit_generic_all_is_the_only_global_authorization(scope, allowed):
    decision = {"reports": [{"report_key": "fixture.generic", "allowed": True,
                             "grants": [{"scope": scope, "allowed_actions": ["view"]}]}]}
    assert access.report_action_decision(decision, "fixture.generic", "view", resource_groups=None)["allowed"] is allowed

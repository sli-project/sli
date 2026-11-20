"""Generic scopes reach every report query through the server context."""
from dataclasses import replace

import pytest

from server.api.routes import reports_v2 as routes
from server.sli.access.scope import AccessScope, ScopeClause
from server.sli.reporting.v2.access import ReportAccess, resolve_access_scope, resolve_domain_scope
from server.sli.reporting.v2.definition import AccessRequirement, AccessRule, Column, Detail, Param, QueryContext, ReportDefinition, result


def decision(scope, *, fields=("technical",), revision="policy-1"):
    return {"subject": {"id": 7, "type": "session"}, "policy_revision": revision,
            "reports": [{"report_key": "fixture.generic", "allowed": True, "allowed_actions": ["view", "export"],
                         "dataset_version": 1, "grants": [{"scope": scope, "field_categories": list(fields), "allowed_actions": ["view", "export"]}]}]}


def definition(query):
    return ReportDefinition(key="fixture.generic", section="reports/computers", title="Fixture", description="",
                            archetype="inventory-status", access=AccessRequirement("fixture.generic", frozenset({"technical"})),
                            params=(Param.text("source_instance_id", "Source"),), columns=(Column("id", "ID"),), query=query, row_key="id")


class Handler:
    def __init__(self, access):
        self.access = access
        self.sent = []

    def _access_decision(self):
        return self.access

    def _send_json(self, payload, status=200):
        self.sent.append((payload, int(status)))


def call(monkeypatch, report, access, query=None, suffix="data"):
    monkeypatch.setattr(routes, "get_report", lambda _key: report)
    handler = Handler(access)
    assert routes.try_handle_get(handler, f"/api/v2/reports/{report.key}/{suffix}", query or {})
    return handler.sent[-1]


def restricted(*clauses):
    return {"mode": "restricted", "clauses": list(clauses)}


def test_generic_report_queries_filter_source_without_ad(monkeypatch):
    rows = [{"id": 1, "plugin_id": "sli.fixture", "source_instance_id": "source-1"},
            {"id": 2, "plugin_id": "sli.fixture", "source_instance_id": "source-2"},
            {"id": 3, "plugin_id": "sli.other", "source_instance_id": "source-1"}]
    contexts = []

    def query(ctx):
        contexts.append(ctx)
        filtered = [row for row in rows if ctx.scope.allows(plugin_id=row["plugin_id"], source_instance_id=row["source_instance_id"])]
        return result(report, state="ok", items=filtered, filtered_count=len(filtered))

    report = definition(query)
    payload, status = call(monkeypatch, report, decision(restricted({"plugin_ids": ["sli.fixture"], "source_instance_ids": ["source-1"]})))
    assert status == 200 and payload["items"] == rows[:1] and payload["filtered_count"] == 1
    assert contexts[0].domain_ids is None and contexts[0].principal["id"] == 7
    assert contexts[0].policy_revision == "policy-1" and contexts[0].decision_id != "unissued"
    assert contexts[0].scope_filter({"plugin_ids": "o.plugin_id", "source_instance_ids": "o.source_instance_id"})[1] == [["sli.fixture"], ["source-1"]]


def test_request_intersects_server_scope_and_denies_other_sources_before_query(monkeypatch):
    report = definition(lambda _: pytest.fail("denied query executed"))
    payload, status = call(monkeypatch, report, decision(restricted({"source_instance_ids": ["source-1"]})), {"source_instance_id": ["source-2"]})
    assert status == 403 and payload["reason"] == "report_scope_not_executable"
    payload, status = call(monkeypatch, report, decision(restricted({"source_instance_ids": ["source-1"]})), {"scope": ["all"]})
    assert status == 400 and "report_parameter_unknown" in payload["error"]


@pytest.mark.parametrize("scope", [{}, {"mode": "none", "clauses": []}, {"mode": "restricted", "clauses": [{}]}])
def test_missing_empty_or_malformed_scope_never_means_all(scope):
    with pytest.raises(PermissionError, match="report_scope_not_executable"):
        resolve_access_scope(decision(scope), definition(None).access)


def test_existing_domain_assignments_preserve_their_union_and_field_coverage():
    access = decision({"kind": "domain", "ids": [1, 2]})
    report = replace(definition(None), access=AccessRule("fixture.generic", frozenset({"technical"})))
    for domain in (1, 2):
        access["reports"][0]["grants"].append({"scope": {"kind": "domain", "ids": [domain]},
                                               "field_categories": ["technical", "extra"], "allowed_actions": ["view"]})
    projection = ReportAccess(report, access)
    assert projection.domain_ids == [1, 2]
    assert projection.fields_allowed(frozenset({"extra"}))
    assert not projection.scope.allows(source_instance_id="domainless-source")
    assert resolve_domain_scope(decision({"kind": "all"}), report.access) is None


def test_old_ad_reader_rejects_unrepresentable_source_scope():
    with pytest.raises(PermissionError, match="report_scope_not_executable"):
        resolve_domain_scope(decision(restricted({"source_instance_ids": ["source-1"], "collection_scope_ids": ["ad-domain:1"]})), AccessRule("fixture.generic"))


def test_delegated_legacy_reader_does_not_ignore_generic_source_restriction(monkeypatch):
    report = replace(definition(lambda _: pytest.fail("unscoped legacy query executed")), access=AccessRule("fixture.generic", scope="delegated"))
    payload, status = call(monkeypatch, report, decision(restricted({"source_instance_ids": ["source-1"]})))
    assert status == 403 and payload["reason"] == "report_scope_not_executable"


def test_field_categories_remain_atomic_for_entire_generic_scope():
    access = decision(restricted({"source_instance_ids": ["source-1", "source-2"]}))
    access["reports"][0]["grants"].append({"scope": restricted({"source_instance_ids": ["source-1"]}),
                                           "field_categories": ["technical", "extra"], "allowed_actions": ["view"]})
    assert not ReportAccess(definition(None), access).fields_allowed(frozenset({"extra"}))


def test_required_capabilities_and_explicit_all_grant():
    report = replace(definition(None), access=AccessRequirement("fixture.generic", required_capabilities=frozenset({"fixture.read"})))
    access = decision({"kind": "all"})
    with pytest.raises(PermissionError, match="report_access_denied"):
        ReportAccess(report, access)
    access["capabilities"] = ["fixture.read"]
    assert ReportAccess(report, access).scope.mode == "all"


def test_scope_policy_and_dataset_version_bind_pagination(monkeypatch):
    calls = []

    def query(ctx):
        calls.append(ctx)
        return result(report, state="ok", items=[], has_more=True, next_cursor="position-2")

    report = definition(query)
    access = decision(restricted({"source_instance_ids": ["source-1"]}))
    payload, status = call(monkeypatch, report, access)
    assert status == 200
    cursor = payload["next_cursor"]
    assert cursor != "position-2"
    assert call(monkeypatch, report, access, {"cursor": [cursor]})[1] == 200
    assert calls[-1].cursor == "position-2"
    access["policy_revision"] = "policy-2"
    assert call(monkeypatch, report, access, {"cursor": [cursor]})[1] == 400
    assert len(calls) == 2
    access["policy_revision"] = "policy-1"
    access["reports"][0]["dataset_version"] = 2
    assert call(monkeypatch, report, access, {"cursor": [cursor]})[1] == 400


def test_detail_inherits_generic_scope_and_binds_cursor_to_row(monkeypatch):
    contexts = []

    def detail(ctx, row):
        contexts.append((ctx, row))
        return {"state": "ok", "items": [], "next_cursor": "position-2"}

    report = replace(definition(None), detail=Detail("Fixture", "id", (), query=detail))
    access = decision(restricted({"source_instance_ids": ["source-1"]}))
    payload, status = call(monkeypatch, report, access, suffix="rows/1/detail")
    assert status == 200 and contexts[0][0].scope.mode == "restricted"
    assert call(monkeypatch, report, access, {"cursor": [payload["next_cursor"]]}, suffix="rows/2/detail")[1] == 400


def test_scope_or_clauses_and_dimensions_intersect_without_widening():
    scope = AccessScope("restricted", (ScopeClause(plugin_ids=("sli.fixture",), source_instance_ids=("source-1",)), ScopeClause(entity_ids=(7,))))
    assert scope.allows(entity_id=7)
    assert not scope.allows(plugin_id="sli.other", source_instance_id="source-1")
    narrowed = scope.intersect(AccessScope("restricted", (ScopeClause(source_instance_ids=("source-2",)),)))
    assert not narrowed.allows(entity_id=7, source_instance_id="source-1")
    assert narrowed.allows(entity_id=7, source_instance_id="source-2")


def test_generic_context_requires_no_directory_and_defaults_to_no_access():
    context = QueryContext(access={}, params={})
    assert context.domain_ids is None and context.scope.mode == "none"
    assert context.scope_filter({}) == ("FALSE", [])

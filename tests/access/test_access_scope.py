import pytest

from server.sli.access.scope import AccessScope, ScopeClause, scope_from_grant


def test_scope_matches_or_clauses_and_and_dimensions():
    scope = AccessScope("restricted", (ScopeClause(plugin_ids=("sli.fixture",), source_instance_ids=("source-1",), entity_ids=(1, 2)),))
    assert scope.allows(plugin_id="sli.fixture", source_instance_id="source-1", entity_id=2)
    assert not scope.allows(plugin_id="sli.other", source_instance_id="source-1", entity_id=2)
    assert not scope.allows(plugin_id="sli.fixture", source_instance_id="source-2", entity_id=2)
    assert not scope.allows(plugin_id="sli.fixture", source_instance_id="source-1")


@pytest.mark.parametrize("mode,clauses", [("restricted", ()), ("all", (ScopeClause(entity_ids=(1,)),)), ("none", (ScopeClause(entity_ids=(1,)),))])
def test_scope_invariants(mode, clauses):
    with pytest.raises(ValueError):
        AccessScope(mode, clauses)


def test_empty_clause_is_invalid():
    with pytest.raises(ValueError):
        ScopeClause()


def test_domain_adapter_does_not_grant_domainless_devices():
    scope = scope_from_grant({"kind": "domain", "ids": [2, 1]})
    assert scope.domain_ids() == [1, 2]
    assert scope.allows(domain_id=1)
    assert not scope.allows(source_instance_id="source-1")
    assert not scope.allows(domain_id=3)
    assert scope_from_grant({"kind": "all"}).mode == "all"
    assert scope_from_grant({}).mode == "none"


def test_scope_intersection_never_widens_and_sql_is_parameterized():
    allowed = AccessScope("restricted", (ScopeClause(plugin_ids=("sli.fixture",), source_instance_ids=("source-1",)),))
    requested = AccessScope("restricted", (ScopeClause(source_instance_ids=("source-2",)),))
    assert allowed.intersect(requested).mode == "none"
    sql, params = allowed.sql_predicate({"plugin_ids": "r.plugin_id", "source_instance_ids": "r.source_instance_id"})
    assert sql == "((r.plugin_id = ANY(%s) AND r.source_instance_id = ANY(%s)))"
    assert params == [["sli.fixture"], ["source-1"]]
    with pytest.raises(PermissionError):
        allowed.sql_predicate({"source_instance_ids": "r.source_instance_id"})


def test_atomic_scope_coverage_does_not_borrow_other_sources():
    full = AccessScope("restricted", (ScopeClause(source_instance_ids=("source-1",)), ScopeClause(source_instance_ids=("source-2",))))
    partial = AccessScope("restricted", (ScopeClause(source_instance_ids=("source-1",)),))
    assert full.covers(partial)
    assert not partial.covers(full)


def test_domain_reader_rejects_source_restriction_instead_of_widening_it():
    scope = AccessScope("restricted", (ScopeClause(source_instance_ids=("source-1",), collection_scope_ids=("ad-domain:1",)),))
    with pytest.raises(PermissionError):
        scope.domain_ids()


@pytest.mark.parametrize("payload", [
    {"mode": "restricted", "clauses": [{}]},
    {"mode": "all", "clauses": [], "unexpected": True},
    {"mode": "restricted", "clauses": [{"entity_ids": [True]}]},
    {"mode": "restricted", "clauses": [{"source_instance_ids": "source-1"}]},
])
def test_malformed_grant_fails_closed(payload):
    with pytest.raises(ValueError):
        AccessScope.from_dict(payload)

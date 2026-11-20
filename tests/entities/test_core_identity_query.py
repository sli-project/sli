from server.sli.access.scope import AccessScope, ScopeClause
from server.sli.entities.core_identity_query import query_entities


class Cursor:
    def __init__(self, rows=()):
        self.rows = rows
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))

    def fetchall(self):
        return self.rows


def test_identity_reader_filters_scope_before_distinct_count_and_paging():
    cursor = Cursor([{"entity_id": 7, "filtered_count": 2}])
    scope = AccessScope("restricted", (ScopeClause(plugin_ids=("sli.fixture",), source_instance_ids=("fixture-source",)),))
    result = query_entities(cursor, scope, limit=1)
    sql, params = cursor.calls[0]
    assert sql.index("where ((r.plugin_id = ANY(%s) AND r.source_instance_id = ANY(%s)))") < sql.index("select distinct on") < sql.index("count(*) over()") < sql.index("limit %s")
    assert params == (["sli.fixture"], ["fixture-source"], 1, 0)
    assert "core_entity_scope_resources" in sql and "core_entity_observations" not in sql
    assert result == {"items": [{"entity_id": 7}], "filtered_count": 2, "has_more": True}


def test_domain_compatibility_filters_collection_and_none_is_false():
    cursor = Cursor()
    query_entities(cursor, AccessScope("restricted", (ScopeClause(collection_scope_ids=("ad-domain:1",)),)))
    assert "r.collection_scope_id = ANY(%s)" in cursor.calls[0][0]
    assert cursor.calls[0][1][0] == ["ad-domain:1"]
    query_entities(cursor, AccessScope())
    assert "where FALSE" in cursor.calls[-1][0]


def test_device_and_entity_restrictions_apply_to_shared_spine():
    cursor = Cursor()
    query_entities(cursor, AccessScope("restricted", (ScopeClause(device_ids=("core:fixture",), entity_ids=(7,)),)))
    assert cursor.calls[0][1][:2] == (["core:fixture"], [7])

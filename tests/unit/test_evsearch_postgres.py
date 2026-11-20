"""ES03 SQL/authorization contracts with synthetic PG and access fakes only."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.access.scope import AccessScope, ScopeClause
from server.sli.core.database import QueryTimeoutError
from server.sli.events import evsearch_postgres as reader
from server.sli.events.evsearch_contract import ContractError, SearchPolicy
from server.sli.events.evsearch_normalizer import normalize_request

NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
FIELDS = (*reader.SCALARS, "account", "source_station", "related_object", "q", "account_kind", "account_privileged", "privilege_grant_confirmed", "action")


def request(conditions=None, **overrides):
    return {"contract_version": "evsearch.v1", "conditions": conditions or [], **overrides}


def condition(field, operator="in", value=None, **kwargs):
    return {"field": field, "operator": operator, **({"value": value} if value is not None else {}), **kwargs}


def publication():
    return {
        "dataset_key": "events.v2",
        "fields_json": [{"key": key, "category": "technical" if key in {"id", "time_created_utc", "channel"} else "security"} for key in FIELDS],
        "definition_json": {"columns": list(FIELDS), "actions": ["view", "export"], "export_policy": "controlled",
                            "evsearch_questions": {"lockouts": ["event_id", "provider", "channel"]},
                            "evsearch_q_fields": ["message_sample"]},
    }


def access(*grants):
    return {"policy_revision": "synthetic-revision", "decision_id": "synthetic-decision", "capabilities": ["reports.export"],
            "reports": [{"report_key": "events.explorer", "version": 1, "allowed": True, "allowed_actions": ["view", "export"],
                         "grants": list(grants or [grant()])}]}


def grant(domain=7, categories=("technical", "security"), actions=("view", "export")):
    return {"scope": {"kind": "domain", "ids": [domain]}, "field_categories": list(categories), "allowed_actions": list(actions)}


class FakePG:
    """Small relational fake for the scope/time/limit reader contract.

    Reads the actual compiled bind positions; it does not reuse a search/policy
    object to prefilter the fixture. Other SQL shapes are asserted separately.
    """

    def __init__(self, published=None, rows=()):
        self.published = publication() if published is None else published
        self.rows = rows
        self.calls = []

    def __call__(self, sql, params, **budgets):
        self.calls.append((sql, params, budgets))
        assert budgets == {"statement_timeout_ms": 5000, "wall_timeout_ms": 6500}
        if "report_registry_v4" in sql:
            assert params == ("events.explorer", 1)
            assert "r.status='published'" in sql and "d.status='published'" in sql
            return [deepcopy(self.published)] if self.published else []
        assert "events_v2_core e" in sql
        assert "e.domain_id=?" in sql
        assert "e.time_created_utc>=?" in sql and "e.time_created_utc<?" in sql
        def bound(fragment):
            return params[sql[:sql.index(fragment)].count("?")]
        domain, start, end = (bound(fragment) for fragment in ("e.domain_id=?", "e.time_created_utc>=?", "e.time_created_utc<?"))
        rows = [row for row in self.rows if row["domain_id"] == domain and start <= row["time_created_utc"] < end]
        rows.sort(key=lambda row: (row["time_created_utc"], row["id"]), reverse="e.id desc" in sql)
        return rows[:params[-1]]


def install(monkeypatch, pg, issued=None):
    monkeypatch.setattr(reader, "effective_access", lambda principal: deepcopy(access() if issued is None else issued))
    monkeypatch.setattr(reader, "query_rows_bounded", pg)


def compile_request(raw=None, fields=("id",), scope=None, **kwargs):
    search = normalize_request(raw or request(), now=NOW)
    policy = SearchPolicy(scope or AccessScope("all"), frozenset(FIELDS), "view")
    return reader.compile_hot_query(search, policy, fields=fields, **kwargs)


@pytest.mark.parametrize("sort", ["time_desc", "count_desc"])
def test_full_capture_uses_one_scoped_statement_and_private_identity_without_page_truncation(sort):
    search = normalize_request(request(page_size=1, sort=sort), now=NOW)
    seen = []

    def query(sql, params, **budgets):
        seen.append((sql, params, budgets))
        return [{"id": event_id, "_evsearch_id": event_id,
                 "_evsearch_time": NOW - timedelta(hours=23),
                 "_evsearch_fingerprint": bytes.fromhex("AB" * 32), "hidden": "not projected"}
                for event_id in (1, 2, 3)]

    result = reader.read_hot_capture(search, access=access(), publication=publication(), fields=("id",), query_rows=query)
    assert result.items == ({"id": 1}, {"id": 2}, {"id": 3})
    assert [item.event_id for item in result.identities] == [1, 2, 3]
    assert all(item.fingerprint == "AB" * 32 for item in result.identities)
    assert result.exhaustive and len(seen) == 1
    sql, params, _ = seen[0]
    assert params[-1] == reader.MAX_EVENTS + 1
    assert 'e.normalized_hash as "_evsearch_fingerprint"' in sql
    assert "e.domain_id=?" in sql and params[0] == 7
    assert params[1:3] == (search.period.start, search.period.end)


def test_capture_applies_and_authorizes_stored_publication_predicate_before_query():
    published = publication()
    published["definition_json"]["filters"] = [{"field": "channel", "op": "eq", "value": "Security"}]
    seen = []

    def query(sql, params, **budgets):
        seen.append((sql, params))
        return []

    search = normalize_request(request(), now=NOW)
    reader.read_hot_capture(search, access=access(), publication=published, fields=("id",), query_rows=query)
    assert "channel.value=?" in seen[0][0] and seen[0][1][-2] == "Security"
    seen.clear()
    next(field for field in published["fields_json"] if field["key"] == "channel")["category"] = "ungranted"
    with pytest.raises(PermissionError):
        reader.read_hot_capture(search, access=access(), publication=published, fields=("id",), query_rows=query)
    assert not seen


@pytest.mark.parametrize("damage", ["overflow", "duplicate", "fingerprint", "timeout", "denied"])
def test_capture_failures_do_not_produce_a_mergeable_partial_result(damage):
    calls = []

    def query(*args, **kwargs):
        calls.append(True)
        if damage == "timeout":
            raise QueryTimeoutError("synthetic", timeout_ms=8000)
        row = {"id": 1, "_evsearch_id": 1, "_evsearch_time": NOW - timedelta(hours=1),
               "_evsearch_fingerprint": None if damage == "fingerprint" else "AB" * 32}
        return [row, row] if damage in {"overflow", "duplicate"} else [row]

    with pytest.raises((reader.OwnershipError, PermissionError)):
        reader.read_hot_capture(normalize_request(request(), now=NOW),
                                access={} if damage == "denied" else access(), publication=publication(),
                                fields=("id",), query_rows=query, limit=1 if damage == "overflow" else 10)
    if damage == "denied":
        assert not calls


def test_capture_rejects_oversize_projections_before_returning(monkeypatch):
    monkeypatch.setattr(reader, "MAX_SNAPSHOT_BYTES", 5)

    def query(*args, **kwargs):
        return [{"id": 1, "_evsearch_id": 1, "_evsearch_time": NOW - timedelta(hours=1),
                 "_evsearch_fingerprint": "AB" * 32}]

    with pytest.raises(reader.OwnershipError, match="storage_limit_exceeded"):
        reader.read_hot_capture(normalize_request(request(), now=NOW), access=access(),
                                publication=publication(), fields=("id",), query_rows=query)


@pytest.mark.parametrize("sort,expected", [("time_desc", [3, 2]), ("time_asc", [1, 2])])
def test_only_permitted_rows_affect_items_lookahead_and_returned_count(monkeypatch, sort, expected):
    rows = [{"id": i, "domain_id": 7, "time_created_utc": NOW - timedelta(hours=1), "message_sample": "synthetic-hidden"} for i in (1, 2, 3)]
    rows += [{"id": i, "domain_id": 8, "time_created_utc": NOW - timedelta(minutes=1)} for i in range(10, 40)]
    rows += [{"id": 40, "domain_id": 7, "time_created_utc": NOW},
             {"id": 41, "domain_id": 7, "time_created_utc": NOW - timedelta(days=2)}]
    pg = FakePG(rows=rows)
    install(monkeypatch, pg)
    result = reader.read_hot_page(request(page_size=2, sort=sort), None, fields=("id",), now=NOW)
    assert result.items == tuple({"id": i} for i in expected)
    assert result.returned_count == 2 and result.has_more
    assert pg.calls[-1][1][-1] == 3
    assert "message_sample" not in pg.calls[-1][0] and "event_facts_v2" not in pg.calls[-1][0]
    # Removing the one permitted lookahead row changes has_more; any number of
    # forbidden rows must never keep it true.
    pg.rows = [row for row in rows if row["id"] in {1, 2} or row["domain_id"] == 8]
    result = reader.read_hot_page(request(page_size=2), None, fields=("id",), now=NOW)
    assert result.returned_count == 2 and not result.has_more


def test_all_forbidden_rows_produce_an_empty_page_without_an_exact_total_claim(monkeypatch):
    pg = FakePG(rows=[{"id": 1, "domain_id": 8, "time_created_utc": NOW - timedelta(hours=1)}])
    install(monkeypatch, pg)
    page = reader.read_hot_page(request(), None, fields=("id",), now=NOW)
    assert page.items == () and page.returned_count == 0 and not page.has_more
    assert not hasattr(page, "total")


@pytest.mark.parametrize("change", ["output", "predicate", "q", "question", "split_grants", "export", "publication", "denied"])
def test_denied_fields_or_resources_never_reach_an_event_query(monkeypatch, change):
    published, issued, raw, fields, action = publication(), access(), request(), ("id",), "view"
    if change == "output":
        fields = ("message_sample",)
        published["definition_json"]["columns"].remove("message_sample")
    elif change == "predicate":
        raw = request([condition("provider", value=["synthetic-provider"])])
        published["definition_json"]["columns"].remove("provider")
    elif change == "q":
        raw = request(q="synthetic-text")
        published["definition_json"]["columns"].remove("message_sample")
    elif change == "question":
        raw = request(question_id="lockouts")
        # The publication understates dependencies; actual ES02 fields win.
        published["definition_json"]["evsearch_questions"]["lockouts"] = ["event_id"]
        published["definition_json"]["columns"].remove("provider")
    elif change == "split_grants":
        fields = ("message_sample",)
        issued = access(grant(categories=("technical",)), grant(8))
    elif change == "export":
        action = "export"
        issued = access(grant(actions=("view",)))
    elif change == "publication":
        published = {}
    else:
        issued = {"reports": []}
    pg = FakePG(published)
    install(monkeypatch, pg, issued)
    with pytest.raises(PermissionError, match="evsearch.policy_denied"):
        reader.read_hot_page(raw, None, fields=fields, action=action, now=NOW)
    assert all("events_v2_core" not in call[0] for call in pg.calls)


@pytest.mark.parametrize("operator,fragment,params", [
    ("in", "channel.value=any(?)", (["Security", "System"],)),
    ("not_in", "channel.value is null or not (channel.value=any(?))", (["Security", "System"],)),
    ("exists", "channel.value is not null", ()),
    ("missing", "channel.value is null", ()),
])
def test_scalar_conditions_bind_values_and_preserve_missing_semantics(operator, fragment, params):
    value = ["Security", "System"] if params else None
    query = compile_request(request([condition("channel", operator, value)]))
    assert fragment in query.sql
    assert query.params[2:-1] == params
    assert query.sql.index(fragment) < query.sql.index("order by") < query.sql.index("limit ?")


@pytest.mark.parametrize("field,role,fragment", [
    ("account", "actor", "role.value=?"), ("account", "target", "role.value=?"),
    ("account", "any", "role.value in ('actor','target')"),
    ("source_station", None, "role.value='source'"),
    ("related_object", None, "link.event_id=e.id"),
])
@pytest.mark.parametrize("operator", ["in", "not_in", "exists", "missing"])
def test_link_conditions_use_stable_ids_and_roles_without_multiplying_events(field, role, fragment, operator):
    query = compile_request(request([condition(field, operator, [11, 12] if operator in {"in", "not_in"} else None, **({"role": role} if role else {}))]))
    assert fragment in query.sql and "link.event_id=e.id" in query.sql
    assert ("not exists" in query.sql) == (operator in {"not_in", "missing"})
    assert ("link.entity_id=any(?)" in query.sql) == (operator in {"in", "not_in"})
    assert "display_name" not in query.sql and "natural_key" not in query.sql
    assert query.sql.startswith('select e.id as "id" from events_v2_core e')
    if role in {"actor", "target"}:
        assert role in query.params


def test_native_question_is_qualified_and_compiled_before_limit():
    query = compile_request(request(question_id="lockouts"))
    assert "provider.value=any(?)" in query.sql and "channel.value=any(?)" in query.sql
    assert query.params[2:-1] == (["Microsoft-Windows-Security-Auditing"], ["Security"], [4740])
    assert query.sql.index("e.event_id=any(?)") < query.sql.index("limit ?")


def test_failed_logons_compiles_both_native_branches_with_observed_4776_outcome():
    query = compile_request(request(question_id="failed_logons"))
    assert [4625, 4771, 6273] in query.params and [4776] in query.params
    assert [4740] not in query.params
    assert ["failure"] in query.params
    assert "left join event_facts_v2 facts" in query.sql
    assert "nullif(btrim(facts.result_code),'') is not null" in query.sql
    assert "('0','0x0','0x00000000','00000000')" in query.sql
    assert "e.event_id in (4624,6272) then 'success'" in query.sql
    assert "when e.event_id=4776" in query.sql
    assert "else 'success'" not in query.sql


@pytest.mark.parametrize("role", ["actor", "target", "any"])
def test_machine_switch_uses_confirmed_identity_in_the_selected_role_without_name_heuristics(role):
    raw = request(exclude_machine_system=True, entry_context={"kind": "entity", "entity_id": 11, "role": role})
    query = compile_request(raw)
    assert "not exists (select 1 from event_entity_links_v2" in query.sql
    assert "kind.value='ad_computer' or entity.natural_key ~* '^sid:.+:s-1-5-(18|19|20)$'" in query.sql
    assert "display_name" not in query.sql and "svc" not in query.sql
    assert (role in query.params) == (role != "any")


def test_authentication_question_machine_switch_uses_target_instead_of_machine_actor():
    query = compile_request(request(question_id="failed_logons", exclude_machine_system=True))
    assert query.params[2] == "target"


def test_scope_preserves_or_between_grants_and_and_within_each_grant():
    scope = AccessScope("restricted", (
        ScopeClause(device_ids=("server:9",), collection_scope_ids=("ad-domain:7", "channel:Security")),
        ScopeClause(entity_ids=(11,)),
    ))
    query = compile_request(scope=scope)
    assert "((e.server_id=any(?) and (e.domain_id=? or channel.value=?)) or (exists" in query.sql
    assert query.params[:4] == ([9], 7, "Security", [11])


@pytest.mark.parametrize("clause", [ScopeClause(plugin_ids=("synthetic-plugin",)), ScopeClause(source_instance_ids=("synthetic-source",)),
                                         ScopeClause(device_ids=("synthetic-device",)), ScopeClause(collection_scope_ids=("synthetic-collection",))])
def test_unsupported_scope_dimension_is_not_dropped_even_beside_an_executable_grant(clause):
    with pytest.raises(PermissionError, match="evsearch.policy_denied"):
        compile_request(scope=AccessScope("restricted", (ScopeClause(device_ids=("server:9",)), clause)))


def test_none_scope_compiles_to_false_not_a_missing_where_clause():
    assert "where (false) and" in compile_request(scope=AccessScope()).sql


def test_q_uses_only_authorized_published_backing_fields_and_binds_literal_text():
    query = compile_request(request(q="synthetic%' OR true --"), text_fields=("message_sample",))
    assert "strpos(lower(facts.message_sample),lower(?))>0" in query.sql
    assert "event_data_json" not in query.sql and "subject_user_name" not in query.sql
    assert "OR true" not in query.sql and query.params[-2] == "synthetic%' OR true --"
    assert "left join event_facts_v2" in query.sql


@pytest.mark.parametrize("raw", [request(q="synthetic"), request(sort="count_desc"),
                                     request([condition("action", value=["synthetic-action"])]), request(question_id="admin_logons"),
                                     request(question_id="new_admins")])
def test_unavailable_projection_is_rejected_never_silently_ignored(raw):
    with pytest.raises(ContractError):
        compile_request(raw)


def test_compiler_rechecks_actual_question_dependencies_against_the_issued_policy():
    search = normalize_request(request(question_id="lockouts"), now=NOW)
    policy = SearchPolicy(AccessScope("all"), frozenset({"id", "event_id"}), "view")
    with pytest.raises(PermissionError):
        reader.compile_hot_query(search, policy, fields=("id",))


def test_account_output_contains_only_stable_ids_and_roles():
    query = compile_request(fields=("account", "source_station", "related_object"))
    assert "select distinct jsonb_build_object('entity_id',link.entity_id,'role',role.value)" in query.sql
    assert "array(select distinct link.entity_id" in query.sql
    assert "display_name" not in query.sql and "attributes_json" not in query.sql


def test_timeout_is_propagated_without_a_broader_retry_or_false_empty_result(monkeypatch):
    pg = FakePG()
    def bounded(sql, params, **budgets):
        if "events_v2_core" in sql:
            raise QueryTimeoutError("synthetic timeout", timeout_ms=5000)
        return pg(sql, params, **budgets)
    install(monkeypatch, bounded)
    with pytest.raises(QueryTimeoutError):
        reader.read_hot_page(request(), None, fields=("id",), now=NOW)
    assert len(pg.calls) == 1

"""Read-model contract only; these tests never open a database connection."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from server.sli.access import access_control_v4, auth


@pytest.mark.parametrize("owner, reader", [
    (auth, auth.list_users),
    (access_control_v4, access_control_v4.list_access_subjects),
])
def test_inventory_reads_explicit_service_association_without_changing_accounts(monkeypatch, owner, reader):
    monkeypatch.setattr(access_control_v4, "require_table_columns", lambda *a, **kw: None)
    statements = []
    rows = [
        {"id": 1, "username": "report-key-person", "role": "viewer", "is_active": False, "is_service": False},
        {"id": 2, "username": "renamed-service", "role": "viewer", "is_active": False, "is_service": True},
    ]
    cursor = SimpleNamespace(
        execute=lambda statement, params=(): statements.append(" ".join(statement.lower().split())),
        fetchall=lambda: rows if len(statements) == 1 else [],
    )
    connection = SimpleNamespace(cursor=lambda: nullcontext(cursor))
    monkeypatch.setattr(owner, "_connect", lambda: nullcontext(connection))
    monkeypatch.setattr(owner, "ensure_auth_schema" if owner is auth else "ensure_access_schema", lambda: None)

    result = reader()

    assert (result if owner is auth else result["users"]) == rows
    query = statements[0]
    assert "(u.is_service or exists (select 1 from auth_api_keys k where k.report_subject_id = u.id)) as is_service" in query
    assert "from auth_users u" in query
    assert "like" not in query and "revoked_at" not in query and "expires_at" not in query
    assert "k.is_active" not in query and "join auth_api_keys" not in query
    assert "password_hash" not in query and "key_hash" not in query and "key_prefix" not in query
    assert all(statement.startswith("select ") for statement in statements)


@pytest.mark.parametrize("account_type, expected", [("all", None), ("people", False), ("service", True)])
def test_subject_class_predicate_is_applied_before_unchanged_limit(monkeypatch, account_type, expected):
    monkeypatch.setattr(access_control_v4, "require_table_columns", lambda *a, **kw: None)
    calls = []
    cursor = SimpleNamespace(execute=lambda sql, params=(): calls.append((" ".join(sql.split()), params)), fetchall=lambda: [])
    monkeypatch.setattr(access_control_v4, "_connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    monkeypatch.setattr(access_control_v4, "ensure_access_schema", lambda: None)
    access_control_v4.list_access_subjects(account_type=account_type)
    sql, params = calls[0]
    assert "where (%s::boolean is null or (u.is_service or exists (select 1 from auth_api_keys k where k.report_subject_id = u.id)) = %s)" in sql
    assert sql.index("where (%s") < sql.index("limit 500")
    assert params == (expected, expected)


@pytest.mark.parametrize("value", ["", "unknown", "SERVICE", None, 1])
def test_unknown_subject_class_is_rejected_before_database_access(monkeypatch, value):
    monkeypatch.setattr(access_control_v4, "_connect", lambda: pytest.fail("invalid filter reached database"))
    monkeypatch.setattr(access_control_v4, "ensure_access_schema", lambda: pytest.fail("invalid filter reached schema guard"))
    with pytest.raises(ValueError, match="invalid_account_type"):
        access_control_v4.list_access_subjects(account_type=value)


@pytest.mark.parametrize("query, expected", [({}, "all"), ({"account_type": ["all"]}, "all"),
                                              ({"account_type": ["people"]}, "people"), ({"account_type": ["service"]}, "service")])
def test_subject_route_preserves_default_and_forwards_explicit_class(monkeypatch, query, expected):
    from server.api.routes import access

    calls, responses = [], []
    handler = SimpleNamespace(_require_capability=lambda key: key == "access.manage", _send_json=lambda *args: responses.append(args))
    monkeypatch.setattr(access, "list_access_subjects", lambda **kwargs: calls.append(kwargs) or {"users": []})
    assert access.try_handle_get(handler, "/api/v1/access/subjects", query)
    assert calls == [{"account_type": expected}]
    assert responses == [({"users": []},)]


@pytest.mark.parametrize("query", [{"account_type": ["unknown"]}, {"account_type": [""]},
                                  {"account_type": ["people", "service"]}, {"account_type": []}])
def test_subject_route_rejects_unknown_or_ambiguous_filter(monkeypatch, query):
    from server.api.routes import access

    responses = []
    handler = SimpleNamespace(_require_capability=lambda _: True, _send_json=lambda *args: responses.append(args))
    monkeypatch.setattr(access, "list_access_subjects", lambda **kwargs: pytest.fail("invalid filter reached read model"))
    assert access.try_handle_get(handler, "/api/v1/access/subjects", query)
    assert responses == [({"error": "invalid_account_type"}, 400)]


def test_subject_filter_does_not_bypass_existing_capability_gate(monkeypatch):
    from server.api.routes import access

    handler = SimpleNamespace(_require_capability=lambda _: False, _send_json=lambda *args: pytest.fail("denied request sent data"))
    monkeypatch.setattr(access, "list_access_subjects", lambda **kwargs: pytest.fail("denied request reached read model"))
    assert access.try_handle_get(handler, "/api/v1/access/subjects", {"account_type": ["service"]})



def test_subject_inventory_keeps_service_marker_guard_before_read(monkeypatch):
    calls = []
    monkeypatch.setattr(access_control_v4, "ensure_access_schema", lambda: calls.append("access"))
    monkeypatch.setattr(access_control_v4, "_connect", lambda: pytest.fail("inventory read before marker guard"))

    def unavailable(table, columns, *, minimum_schema_version):
        assert calls == ["access"]
        assert (table, columns, minimum_schema_version) == ("auth_users", ("is_service",), 280)
        raise RuntimeError("synthetic missing service marker")

    monkeypatch.setattr(access_control_v4, "require_table_columns", unavailable)
    with pytest.raises(RuntimeError, match="synthetic missing service marker"):
        access_control_v4.list_access_subjects()

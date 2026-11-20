"""Студия отчётов, backend: жизненный цикл отчётов конструктора (только fake-БД)."""
from __future__ import annotations

from http import HTTPStatus

import pytest

from server.api import http_server
from server.api.routes import reports as routes_reports
from server.sli.access.access_control_v4 import route_capability
from server.sli.reporting import reporting_v4
from server.sli.sources.administrative_activity_producer import ACCESS_ACTIONS

DATASET = {
    "dataset_key": "entities.v2", "version": 1, "name": "Объекты", "object_type": "entity",
    "fields_json": [{"key": "display_name", "category": "identity_basic"}],
    "filters_json": [], "actions_json": ["export"], "status": "published",
}
DEFINITION = {
    "columns": ["display_name"], "filters": [], "sort": [], "actions": [],
    "required_capabilities": ["field.identity_basic"],
    "field_categories": ["identity_basic"],
}
PUBLISHER = {"capabilities": ["reports.design", "reports.publish", "field.identity_basic"]}


class FakeDb:
    """Scripted cursor: ``handler(sql, params)`` returns rows for each execute."""

    def __init__(self, handler):
        self.handler = handler
        self.executed: list[tuple[str, tuple]] = []
        self.rows: list[dict] = []

    def execute(self, sql, params=()):
        sql = " ".join(str(sql).split())
        self.executed.append((sql, tuple(params)))
        self.rows = list(self.handler(sql, tuple(params)) or [])

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return None

    def sql(self, needle):
        return [item for item in self.executed if needle in item[0]]


@pytest.fixture
def audit(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(reporting_v4, "record_access_audit_with_cursor", lambda **kw: calls.append(kw))
    monkeypatch.setattr(reporting_v4, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(reporting_v4, "code_defined_report_keys", lambda: frozenset({"ad.state"}))
    return calls


def _install(monkeypatch, handler) -> FakeDb:
    db = FakeDb(handler)
    monkeypatch.setattr(reporting_v4, "_connect", lambda: db)
    return db


def _publish_handler(previous=None, existing_version=0, grants=False):
    def handler(sql, _params):
        if "from report_registry_v4 r join report_datasets_v4 d" in sql and "status='published'" in sql:
            return [previous] if previous else []
        if "select id from report_datasets_v4" in sql:
            return [{"id": 5}]
        if "max(version)" in sql:
            return [{"version": existing_version + 1}]
        if "has_grants" in sql:
            return [{"has_grants": grants}]
        if sql.startswith("insert into report_registry_v4"):
            return [{"report_key": "my.report", "version": existing_version + 1}]
        return []
    return handler


def _payload(**extra):
    return {
        "report_key": "my.report", "name": "Мой", "purpose": "Проверка", "owner": "ИБ",
        "status": "published", "dataset_key": "entities.v2", "fields": ["display_name"],
        **extra,
    }


def _preview_ok(monkeypatch):
    monkeypatch.setattr(reporting_v4, "builder_preview", lambda payload, principal, access=None: {
        "dataset": {"key": payload["dataset_key"], "version": 1, "name": "Объекты"},
        "fields": [{"key": "display_name"}], "filters": [], "sort": [], "actions": ["view"],
        "required_capabilities": ["field.identity_basic"],
        "required_field_categories": ["identity_basic"], "dashboard_metrics": [],
    })


# --- publish_report -------------------------------------------------------------

def test_second_version_retires_previous_instead_of_archiving(monkeypatch, audit):
    _preview_ok(monkeypatch)
    previous = {"definition_json": DEFINITION, "discoverable": True, "requestable": True,
                "request_profile_json": {}, "dataset_key": "entities.v2"}
    db = _install(monkeypatch, _publish_handler(previous=previous, existing_version=1))

    reporting_v4.publish_report(_payload(), None, access=PUBLISHER)

    updates = db.sql("update report_registry_v4 set status=")
    assert len(updates) == 1 and "status='retired'" in updates[0][0]
    assert not any("archived" in sql for sql, _ in db.executed)
    assert audit[0]["action"] == "report_published"


def test_publish_is_private_by_default_and_explicit_values_work(monkeypatch, audit):
    _preview_ok(monkeypatch)
    db = _install(monkeypatch, _publish_handler())
    reporting_v4.publish_report(_payload(), None, access=PUBLISHER)
    insert = db.sql("insert into report_registry_v4")[0][1]
    assert insert[-3:-1] == (False, False)

    db = _install(monkeypatch, _publish_handler())
    reporting_v4.publish_report(_payload(discoverable=True, requestable=True), None, access=PUBLISHER)
    insert = db.sql("insert into report_registry_v4")[0][1]
    assert insert[-3:-1] == (True, True)


def test_publisher_without_design_gets_clear_error(monkeypatch, audit):
    with pytest.raises(PermissionError, match="report_design_capability_required"):
        reporting_v4.publish_report(_payload(), None, access={"capabilities": ["reports.publish"]})


def test_publish_requires_reports_publish(monkeypatch, audit):
    with pytest.raises(PermissionError, match="reports_publish_required"):
        reporting_v4.publish_report(_payload(), None, access={"capabilities": ["reports.design"]})


# --- promote --------------------------------------------------------------------

def _promote_handler(draft_status="draft", previous=None, grants=False, dataset="entities.v2"):
    def handler(sql, _params):
        if "r.report_key=%s and r.version=%s" in sql:
            return [{"id": 9, "status": draft_status, "definition_json": DEFINITION,
                     "dataset_key": dataset, "dataset_version": 1}]
        if "r.status='published' for update" in sql:
            return [previous] if previous else []
        if "has_grants" in sql:
            return [{"has_grants": grants}]
        if sql.startswith("update report_registry_v4 set status='published'"):
            return [{"report_key": "my.report", "version": 2, "status": "published"}]
        return []
    return handler


def test_promote_draft_retires_current_and_audits(monkeypatch, audit):
    _preview_ok(monkeypatch)
    previous = {"version": 1, "definition_json": DEFINITION, "dataset_key": "entities.v2"}
    db = _install(monkeypatch, _promote_handler(previous=previous))

    result = reporting_v4.promote_report_version("my.report", 2, None, access=PUBLISHER, remote_address="10.0.0.1")

    assert result["status"] == "published"
    assert db.sql("pg_advisory_xact_lock")
    assert any("status='retired'" in sql for sql, _ in db.executed)
    assert audit[0]["action"] == "report_version_promoted"
    assert audit[0]["target_key"] == "my.report"
    assert audit[0]["details"] == {"version": 2, "retired_version": 1}


def test_promote_revalidates_with_builder_preview(monkeypatch, audit):
    seen = []
    monkeypatch.setattr(reporting_v4, "builder_preview", lambda payload, principal, access=None: seen.append(payload) or {})
    _install(monkeypatch, _promote_handler())
    reporting_v4.promote_report_version("my.report", 2, None, access=PUBLISHER)
    assert seen[0]["dataset_key"] == "entities.v2" and seen[0]["fields"] == ["display_name"]


def test_promote_rejects_non_draft_and_unknown(monkeypatch, audit):
    _preview_ok(monkeypatch)
    _install(monkeypatch, _promote_handler(draft_status="retired"))
    with pytest.raises(ValueError, match="report_version_not_draft"):
        reporting_v4.promote_report_version("my.report", 2, None, access=PUBLISHER)
    _install(monkeypatch, lambda *_: [])
    with pytest.raises(LookupError, match="report_version_not_found"):
        reporting_v4.promote_report_version("my.report", 2, None, access=PUBLISHER)


def test_promote_requires_reapproval_when_security_expands(monkeypatch, audit):
    _preview_ok(monkeypatch)
    previous = {"version": 1, "definition_json": DEFINITION, "dataset_key": "other.dataset"}
    db = _install(monkeypatch, _promote_handler(previous=previous, grants=True))
    with pytest.raises(ValueError, match="report_security_reapproval_required"):
        reporting_v4.promote_report_version("my.report", 2, None, access=PUBLISHER)
    assert not any(sql.startswith("update report_registry_v4") for sql, _ in db.executed)
    assert not audit


def test_promote_forbidden_and_code_defined(monkeypatch, audit):
    with pytest.raises(PermissionError, match="reports_publish_required"):
        reporting_v4.promote_report_version("my.report", 2, None, access={"capabilities": ["reports.design"]})
    with pytest.raises(PermissionError, match="report_design_capability_required"):
        reporting_v4.promote_report_version("my.report", 2, None, access={"capabilities": ["reports.publish"]})
    with pytest.raises(ValueError, match="report_is_code_defined"):
        reporting_v4.promote_report_version("ad.state", 1, None, access=PUBLISHER)


# --- retire / visibility ------------------------------------------------------

def test_retire_published_version_audited(monkeypatch, audit):
    db = _install(monkeypatch, lambda sql, _p: [{"report_key": "my.report", "version": 3, "name": "x", "status": "retired"}]
                  if sql.startswith("update report_registry_v4 set status='retired'") else [])
    result = reporting_v4.retire_report("my.report", None, access=PUBLISHER)
    assert result["status"] == "retired"
    assert db.sql("pg_advisory_xact_lock")
    assert audit[0]["action"] == "report_retired"


def test_retire_without_published_version_and_guards(monkeypatch, audit):
    _install(monkeypatch, lambda *_: [])
    with pytest.raises(LookupError, match="report_not_published"):
        reporting_v4.retire_report("my.report", None, access=PUBLISHER)
    with pytest.raises(PermissionError, match="reports_publish_required"):
        reporting_v4.retire_report("my.report", None, access={"capabilities": []})
    with pytest.raises(ValueError, match="report_is_code_defined"):
        reporting_v4.retire_report("ad.state", None, access=PUBLISHER)
    assert not audit


def test_visibility_change_audited_and_validated(monkeypatch, audit):
    db = _install(monkeypatch, lambda sql, _p: [{"report_key": "my.report", "version": 3, "status": "published",
                                                 "discoverable": True, "requestable": False}]
                  if sql.startswith("update report_registry_v4 set discoverable") else [])
    result = reporting_v4.set_report_visibility(
        "my.report", {"discoverable": True, "requestable": False}, None, access=PUBLISHER)
    assert result["discoverable"] is True
    assert db.sql("update report_registry_v4 set discoverable")[0][1] == (True, False, "my.report")
    assert audit[0]["action"] == "report_visibility_changed"
    assert audit[0]["details"]["requestable"] is False
    for bad in ({"discoverable": "yes", "requestable": False}, {"discoverable": False, "requestable": True}, {}):
        with pytest.raises(ValueError):
            reporting_v4.set_report_visibility("my.report", bad, None, access=PUBLISHER)
    with pytest.raises(ValueError, match="report_is_code_defined"):
        reporting_v4.set_report_visibility("ad.state", {"discoverable": True, "requestable": True}, None, access=PUBLISHER)
    with pytest.raises(PermissionError):
        reporting_v4.set_report_visibility("my.report", {"discoverable": True, "requestable": True}, None, access={"capabilities": []})


# --- detail / list / datasets ---------------------------------------------------

def test_definition_detail_returns_versions_and_counts(monkeypatch, audit):
    versions = [{"report_key": "my.report", "version": 2, "status": "draft", "definition_json": DEFINITION,
                 "discoverable": False, "requestable": False, "dataset_key": "entities.v2",
                 "created_by": 1, "published_at": None, "name": "x", "owner_name": "y",
                 "purpose": "z", "sensitivity": "restricted"}]

    def handler(sql, _p):
        if "order by r.version desc" in sql:
            return versions
        if "access_report_assignments" in sql:
            return [{"n": 4}]
        if "access_package_reports" in sql:
            return [{"n": 2}]
        return []

    _install(monkeypatch, handler)
    result = reporting_v4.report_definition_detail("my.report", None, access={"capabilities": ["reports.publish"]})
    assert result["versions"] == versions
    assert (result["assignment_count"], result["package_count"], result["code_defined"]) == (4, 2, False)
    _install(monkeypatch, lambda *_: [])
    with pytest.raises(LookupError):
        reporting_v4.report_definition_detail("nope.report", None, access={"capabilities": ["reports.design"]})
    with pytest.raises(PermissionError):
        reporting_v4.report_definition_detail("my.report", None, access={"capabilities": []})


def test_definitions_list_has_lifecycle_fields(monkeypatch, audit):
    rows = [{"report_key": "ad.state", "discoverable": True, "requestable": False,
             "assignment_count": 1, "package_count": 0},
            {"report_key": "my.report", "discoverable": False, "requestable": False,
             "assignment_count": 0, "package_count": 0}]
    db = _install(monkeypatch, lambda *_: rows)
    result = reporting_v4.report_definitions(None, access={"capabilities": ["reports.design"]})
    assert [item["code_defined"] for item in result["items"]] == [True, False]
    sql = db.executed[0][0]
    assert all(token in sql for token in ("r.discoverable", "r.requestable", "assignment_count", "package_count"))


def test_dataset_registry_exposes_executable_flags(monkeypatch, audit):
    rows = [dict(DATASET), {**DATASET, "dataset_key": "ad.access.vpn"}]
    _install(monkeypatch, lambda *_: rows)
    result = reporting_v4.dataset_registry(None, access={"capabilities": ["reports.design"]})
    executable, other = result["items"]
    assert executable["executable"] is True
    assert "display_name" in executable["executable_filter_keys"]
    assert "id" in executable["executable_sort_keys"]
    assert other["executable"] is False
    assert other["executable_filter_keys"] == [] and other["executable_sort_keys"] == []


# --- routes -----------------------------------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("GET", "/api/v1/reports/definitions/my.report"),
    ("POST", "/api/v1/reports/definitions/my.report/retire"),
    ("POST", "/api/v1/reports/definitions/my.report/visibility"),
    ("POST", "/api/v1/reports/definitions/my.report/versions/2/publish"),
])
def test_lifecycle_routes_are_registered_and_capability_gated(method, path):
    assert any(m == method and (pattern.endswith("*") and path.startswith(pattern[:-1]))
               for m, pattern in routes_reports.ROUTES)
    assert route_capability(path) == "reports.design"


def test_new_audit_actions_are_mapped():
    for action in ("report_version_promoted", "report_retired", "report_visibility_changed"):
        assert ACCESS_ACTIONS[action][0] == "report_publication"


def _http(path):
    handler = object.__new__(http_server.RequestHandler)
    handler.path = path
    handler.client_address = ("127.0.0.1", 1)
    sent = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler._access_decision = lambda: PUBLISHER
    handler._read_json_body = lambda: {"discoverable": True, "requestable": True}
    return handler, sent


def test_http_lifecycle_requires_admin_and_publish_capability(monkeypatch):
    called = []
    monkeypatch.setattr(routes_reports, "retire_v4_report", lambda *a, **k: called.append(a) or {"status": "retired"})
    handler, sent = _http("/api/v1/reports/definitions/my.report/retire")
    roles = []
    handler._authorize_mutation = lambda **kw: roles.append(kw.get("required_role")) or True
    handler._require_capability = lambda cap, **_k: sent.append(cap) or False
    assert routes_reports.try_handle_post(handler, handler.path) is True
    assert roles == ["admin"] and sent == ["reports.publish"] and not called

    handler._require_capability = lambda cap, **_k: True
    assert routes_reports.try_handle_post(handler, handler.path) is True
    assert called and sent[-1] == ({"item": {"status": "retired"}}, HTTPStatus.OK)


@pytest.mark.parametrize("error,status", [
    (PermissionError("report_design_capability_required"), HTTPStatus.FORBIDDEN),
    (ValueError("report_is_code_defined"), HTTPStatus.BAD_REQUEST),
    (LookupError("report_not_published"), HTTPStatus.NOT_FOUND),
])
def test_http_lifecycle_maps_errors(monkeypatch, error, status):
    def boom(*_a, **_k):
        raise error
    monkeypatch.setattr(routes_reports, "promote_v4_report_version", boom)
    handler, sent = _http("/api/v1/reports/definitions/my.report/versions/2/publish")
    handler._authorize_mutation = lambda **_k: True
    handler._require_capability = lambda *_a, **_k: True
    assert routes_reports.try_handle_post(handler, handler.path) is True
    assert sent == [({"error": str(error)}, status)]


def test_http_unknown_definition_subpath_is_not_handled():
    handler, sent = _http("/api/v1/reports/definitions/my.report/unknown")
    assert routes_reports.try_handle_post(handler, handler.path) is False


def test_http_detail_get(monkeypatch):
    monkeypatch.setattr(routes_reports, "get_v4_report_definition_detail",
                        lambda key, principal, access=None: {"report_key": key})
    handler, sent = _http("/api/v1/reports/definitions/my.report")
    assert routes_reports.try_handle_get(handler, handler.path, {}) is True
    assert sent == [({"report_key": "my.report"}, HTTPStatus.OK)]

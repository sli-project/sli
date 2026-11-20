"""N10 presentation contracts: fake PostgreSQL only, no provider calls."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from server.sli.core import notification_workspace as subject
from server.sli.core.database import query_rows as runtime_query_rows
from tests.unit.test_notification_channels import access, row


def decision():
    result = access()
    result["reports"].append({**result["reports"][0], "report_key": "notifications.deliveries"})
    return result


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    monkeypatch.setattr(subject.database, "query_rows", lambda *args: pytest.fail("unexpected database read"))


def test_denied_before_any_read():
    with pytest.raises(PermissionError):
        subject.workspace(access(), days=7)
    with pytest.raises(PermissionError):
        subject.workspace({**decision(), "capabilities": []}, days=7)


@pytest.mark.parametrize("days", [0, True, "7", 8, 31])
def test_period_is_allowlisted(days):
    with pytest.raises(ValueError):
        subject.workspace(decision(), days=days)


def test_counts_are_not_derived_from_page_and_unknowns_stay_null(monkeypatch):
    calls = []
    def query(sql, params=()):
        calls.append((sql, params))
        if "count(*)" in sql:
            return [{"total": 401, "accepted": 390, "errors": 4, "waiting": 3, "other": 4, "new_count": None}]
        if "from notification_channels" in sql:
            return [row()]
        if "from notification_subscriptions" in sql:
            return []
        return []
    monkeypatch.setattr(subject.database, "query_rows", query)
    result = subject.workspace(decision(), days=7)
    assert result["counts"] == {"total": 401, "accepted": 390, "errors": 4, "waiting": 3, "other": 4, "new_count": None}
    assert result["channels"][0]["last_accepted_at"] is None
    assert result["channels"][0]["secret_status"] is None
    assert result["items"] == [] and result["has_more"] is False
    assert result["previous_login_at"] is None
    assert any("created_at" in sql and "order by" in sql for sql, _ in calls)


def test_pagination_filters_are_bound_and_results_are_allowlisted(monkeypatch):
    stamp = datetime(2026, 10, 18, tzinfo=timezone.utc)
    job = {"id": "00000000-0000-4000-8000-000000000001", "channel": "smtp", "state": "retry",
           "created_at": stamp, "updated_at": stamp, "attempts": 2, "result_code": "smtp_unavailable",
           "available_at": stamp, "object_id": "00000000-0000-4000-8000-000000000002",
           "object_kind": "test_problem", "object_severity": None, "subscription_id": "fixture-subscription",
           "password": "MUST_NOT_LEAK", "recipient": "MUST_NOT_LEAK"}
    calls = []
    def query(sql, params=()):
        calls.append((sql, params))
        if "count(*)" in sql:
            return [{"total": 201, "accepted": 0, "errors": 0, "waiting": 201, "other": 0, "new_count": 201}]
        if "from notification_channels" in sql or "from notification_subscriptions" in sql:
            return []
        return [job] * 101
    monkeypatch.setattr(subject.database, "query_rows", query)
    result = subject.workspace(decision(), days=30, channel="smtp", status="waiting", since=stamp.isoformat())
    assert len(result["items"]) == 100 and result["has_more"]
    assert result["next_cursor"]
    assert "MUST_NOT_LEAK" not in str(result)
    assert all("MUST_NOT_LEAK" not in str(call) for call in calls)
    assert result["counts"]["new_count"] == 201
    assert any("smtp" in params for _, params in calls)


@pytest.mark.parametrize("kwargs", [{"channel": "evil"}, {"status": "evil"}, {"cursor": "evil"}, {"since": "evil"}])
def test_invalid_filter_is_rejected(kwargs):
    with pytest.raises(ValueError):
        subject.workspace(decision(), **kwargs)


def test_workspace_route_rechecks_both_grants_before_login_read(monkeypatch):
    from server.api.routes import notification_channels as routes
    from tests.unit.test_notification_channels import Handler

    monkeypatch.setattr("server.sli.access.auth.previous_login", lambda *args: pytest.fail("unauthorized baseline read"))
    handler = Handler(access())
    assert routes.try_handle_get(handler, routes.PREFIX + "/workspace", {})
    assert handler.status == 403


def test_workspace_route_masks_unavailable_details(monkeypatch):
    from server.api.routes import notification_channels as routes
    from tests.unit.test_notification_channels import Handler

    monkeypatch.setattr("server.sli.access.auth.previous_login", lambda *args: None)
    def unavailable(*args, **kwargs):
        raise RuntimeError("MUST_NOT_LEAK")
    monkeypatch.setattr(subject, "workspace", unavailable)
    handler = Handler(decision())
    assert routes.try_handle_get(handler, routes.PREFIX + "/workspace", {})
    assert handler.status == 503
    assert "MUST_NOT_LEAK" not in str(handler.response)


def test_finding_filter_needs_global_queue_access():
    with pytest.raises(PermissionError):
        subject.workspace(decision(), finding_id=11)


def test_workspace_queries_pass_through_runtime_adapter_without_transport_columns(monkeypatch):
    """Exercise binding conversion and projection, which query_rows fakes bypass."""
    from server.api.routes import notification_channels as routes
    from tests.unit.test_notification_channels import Handler

    stamp = datetime(2026, 10, 18, tzinfo=timezone.utc)
    job = {field: None for field in subject.FIELDS}
    job.update(id="00000000-0000-4000-8000-000000000001", created_at=stamp,
               channel="telegram", state="retry", finding_id=11)
    calls = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, sql, params):
            calls.append((sql, params))
            assert "%%s" not in sql
            assert sql.count("%s") == len(params)
            if "from notification_channels" in sql:
                # Migration 227 adds next_delivery_at with default -infinity.
                # psycopg cannot decode it, and the workspace does not need it.
                assert "c.*" not in sql and "next_delivery_at" not in sql
                assert all(f"c.{field}" in sql for field in subject.channels.FIELDS)
                self.rows = [row(), row("telegram")]
            elif "count(*)" in sql:
                self.rows = [{"total": 101, "waiting": 101, "new_count": 101}]
            elif "from notification_subscriptions" in sql:
                self.rows = []
            else:
                self.rows = [job] * 101

        def fetchall(self):
            return self.rows

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(subject.database, "query_rows", runtime_query_rows)
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", Connection)
    monkeypatch.setattr(subject.outbox, "queue_access", lambda _: SimpleNamespace(scope=SimpleNamespace(mode="all")))
    monkeypatch.setattr("server.sli.access.auth.previous_login", lambda _: stamp.isoformat())
    handler = Handler(decision())
    query = {"days": ["7"], "channel": ["telegram"], "status": ["waiting"], "finding_id": ["11"]}
    assert routes.try_handle_get(handler, routes.PREFIX + "/workspace", query)
    assert handler.status == 200
    assert [item["kind"] for item in handler.response["channels"]] == ["smtp", "telegram"]
    assert handler.response["has_more"] and handler.response["next_cursor"]
    first_counts = next(params for sql, params in calls if "count(*)" in sql)
    assert first_counts == (stamp.isoformat(), stamp.isoformat(), 7, 11, "telegram")
    query["cursor"] = [handler.response["next_cursor"]]
    assert routes.try_handle_get(handler, routes.PREFIX + "/workspace", query)
    assert handler.status == 200
    assert any("(created_at,id)<(%s::timestamptz,%s::uuid)" in sql for sql, _ in calls)

"""N09 isolated calendar, snapshot, permission and API contracts."""

from dataclasses import replace
from datetime import datetime, timezone
from http import HTTPStatus
from uuid import uuid4
from urllib.parse import parse_qs, urlsplit

import pytest

from server.api.routes import notification_outbox as routes
from server.sli.core import notification_outbox as outbox, report_schedules as schedules
from server.sli.plugins.file_audit.reports import REPORTS as FILE_REPORTS
from server.sli.reporting.v2.reports.security_problems import REPORT as SECURITY
from tests.unit.test_notification_outbox import Handler, access, store as store

UTC = timezone.utc
FILE = next(r for r in FILE_REPORTS if r.key == "file-audit.mass-operations")


def moment(text):
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def config(**overrides):
    return dict(report_key=SECURITY.key, filters={}, timezone="UTC", local_time="09:00", weekday=None,
                period_days=1, language="en", enabled=True, subscription_ids=[str(uuid4())], **overrides)


def schedule(**overrides):
    row = {**config(), "id": str(uuid4()), "owner_user_id": 1, "revision": 1,
           "created_at": moment("2026-01-01T00:00:00")}
    return {**row, **overrides}


def report_grants(definition, *, scope=None, export=True):
    fields = definition.access.required_fields
    actions = ["view", "export"] if export else ["view"]
    return {"subject": {"coarse_role": "admin"},
            "capabilities": list(definition.access.required_capabilities) + ["file-audit.export"]
                            + ["field." + f for f in fields],
            "reports": [{"report_key": definition.access.report_key, "allowed": True,
                         "allowed_actions": actions, "grants": [{"scope": scope or {"kind": "all"},
                         "allowed_actions": actions, "field_categories": list(fields)}]}]}


def sample_run(**overrides):
    start, end = moment("2026-10-17T09:00:00"), moment("2026-10-18T09:00:00")
    return {"id": str(uuid4()), "schedule_id": str(uuid4()), "schedule_revision": 1,
            "report_key": SECURITY.key, "slot": end, "period_from": start, "period_to": end,
            "generated_at": end, "quality": "partial", "item_count": None, "truncated": False,
            "delayed": False, "language": "en", "filters": {}, "timezone": "UTC", **overrides}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setattr(schedules, "get_report", lambda key: {SECURITY.key: SECURITY, FILE.key: FILE}.get(key))
    monkeypatch.setattr(outbox, "recipient_access", lambda _: report_grants(SECURITY))
    monkeypatch.setattr(outbox, "connect", lambda: pytest.fail("unexpected database connection"))
    monkeypatch.setattr(outbox.database, "query_rows", lambda *_: pytest.fail("unexpected database query"))


@pytest.mark.parametrize("patch", [{"report_key": "other"}, {"report_key": []}, {"filters": {"q": "synthetic-private"}},
    {"filters": {"severity": "other"}}, {"filters": {"severity": "high,critical"}},
    {"filters": {"severity": ">=high"}}, {"filters": {"domain": "private"}},
    {"timezone": "missing/zone"}, {"local_time": "9:00"},
    {"local_time": "09:00:00"}, {"local_time": []}, {"weekday": True}, {"weekday": 7},
    {"period_days": True}, {"period_days": 90}, {"language": "other"}, {"enabled": 1},
    {"subscription_ids": []}, {"subscription_ids": ["invalid"]}, {"token": "synthetic-secret"}])
def test_invalid_configuration_never_echoes_values(patch):
    with pytest.raises(ValueError, match="^invalid_notification_request$"):
        schedules.validate({**config(), **patch})


@pytest.mark.parametrize("key,filters", [(SECURITY.key, {"severity": "high"}),
    (FILE.key, {"source_kind": "server", "operation": "write"})])
def test_only_declared_nonpersonal_filters(key, filters):
    body = {**config(), "report_key": key, "filters": filters}
    assert schedules.validate(body) == body


def test_calendar_daily_weekly_and_latest_missed_slot():
    daily = schedule()
    assert schedules.latest_slot(daily, moment("2026-10-18T08:59:59")) == moment("2026-10-17T09:00:00")
    assert schedules.latest_slot(daily, moment("2026-10-18T09:00:00")) == moment("2026-10-18T09:00:00")
    weekly = {**daily, "weekday": 0}
    assert schedules.latest_slot(weekly, moment("2026-10-18T09:00:00")) == moment("2026-10-12T09:00:00")
    assert schedules.latest_slot({**daily, "created_at": moment("2026-10-18T09:01:00")},
                                  moment("2026-10-18T10:00:00")) is None


def test_dst_gap_advances_and_fold_does_not_repeat():
    row = schedule(timezone="America/New_York", local_time="02:30")
    assert schedules.latest_slot(row, moment("2026-03-08T07:05:00")) == moment("2026-03-08T07:00:00")
    row["local_time"] = "01:30"
    assert schedules.latest_slot(row, moment("2026-11-01T05:40:00")) == moment("2026-11-01T05:30:00")
    assert schedules.latest_slot(row, moment("2026-11-01T06:40:00")) == moment("2026-11-01T05:30:00")


@pytest.mark.parametrize("definition", [SECURITY, FILE])
@pytest.mark.parametrize("scope", [{"kind": "domain", "ids": [1]}, {"kind": "domain", "ids": [2]}])
def test_report_scope_is_checked_for_each_user(definition, scope, monkeypatch):
    monkeypatch.setattr(outbox, "recipient_access", lambda _: report_grants(definition, scope=scope))
    with pytest.raises(PermissionError):
        schedules.report_access(2, definition.key)


@pytest.mark.parametrize("quality", ["ok", "partial", "stale", "not_collected", "denied", "error"])
@pytest.mark.parametrize("definition", [SECURITY, FILE])
def test_snapshot_keeps_quality_period_and_export_intersection(quality, definition, monkeypatch):
    contexts = []
    def query(context):
        contexts.append(context)
        return {"state": quality, "items": [{"private": "synthetic-private"}], "filtered_count": 4,
                "has_more": False, "limitations": []}
    definition = replace(definition, query=query)
    monkeypatch.setattr(schedules, "get_report", lambda _: definition)
    monkeypatch.setattr(outbox, "recipient_access", lambda _: report_grants(definition))
    for user in (1, 2):
        assert schedules.report_access(user, definition.key, export=True)[2].scope.mode == "all"
    row = schedule(report_key=definition.key)
    end = moment("2026-10-18T09:00:00")
    run = schedules.snapshot(row, end, {1, 2}, end)
    assert run["quality"] == quality
    assert run["item_count"] == (4 if quality in {"ok", "partial", "stale"} else None)
    assert "synthetic-private" not in str(run)
    if definition.key == FILE.key:
        assert datetime.fromisoformat(contexts[0].params["period"]["from_utc"]) == run["period_from"]
        assert datetime.fromisoformat(contexts[0].params["period"]["to_utc"]) == end
    else:
        assert contexts[0].params["time_to"] == end.isoformat()
    for denied_user in (1, 2):
        monkeypatch.setattr(outbox, "recipient_access", lambda user: report_grants(definition, export=user != denied_user))
        assert schedules.snapshot(row, end, {1, 2}, end)["item_count"] is None


def test_snapshot_calendar_period_dst_and_truncation(monkeypatch):
    definition = replace(FILE, query=lambda _: {"state": "ok", "items": [], "filtered_count": 100, "has_more": True})
    monkeypatch.setattr(schedules, "get_report", lambda _: definition)
    monkeypatch.setattr(outbox, "recipient_access", lambda _: report_grants(definition))
    end = moment("2026-03-08T13:00:00")
    run = schedules.snapshot(schedule(report_key=FILE.key, timezone="America/New_York"), end, {1, 2}, end)
    assert (run["period_to"] - run["period_from"]).total_seconds() == 23 * 3600
    assert run["quality"] == "partial" and run["truncated"] and run["item_count"] == 100


def test_revoked_recipient_suppresses_aggregates_and_revoked_owner_records_denied(monkeypatch):
    definition = replace(FILE, query=lambda _: {"state": "partial", "items": [], "filtered_count": 42})
    monkeypatch.setattr(schedules, "get_report", lambda _: definition)
    monkeypatch.setattr(outbox, "recipient_access", lambda user: report_grants(definition) if user == 1 else {})
    end = moment("2026-10-18T09:00:00")
    run = schedules.snapshot(schedule(report_key=FILE.key), end, {1, 2}, end)
    assert run["item_count"] is None and run["quality"] == "partial"
    monkeypatch.setattr(outbox, "recipient_access", lambda _: {})
    run = schedules.snapshot(schedule(report_key=FILE.key), end, {1, 2}, end)
    assert run["quality"] == "denied" and run["item_count"] is None


def test_query_exception_has_fixed_quality_and_no_logs(monkeypatch, caplog, capsys):
    def broken(_):
        raise RuntimeError("synthetic-secret")
    monkeypatch.setattr(schedules, "get_report", lambda _: replace(SECURITY, query=broken))
    end = moment("2026-10-18T09:00:00")
    run = schedules.snapshot(schedule(), end, {1, 2}, end)
    assert run["quality"] == "error" and run["item_count"] is None
    assert "synthetic-secret" not in str(run) + caplog.text + capsys.readouterr().out


@pytest.mark.parametrize("key", [SECURITY.key, FILE.key])
@pytest.mark.parametrize("language", ["en", "ru"])
def test_digest_contains_only_safe_metadata_and_authenticated_period_link(key, language):
    filters = ({"severity": "high", "status": "active", "population": "all"} if key == SECURITY.key else
               {"operation": "write", "source_kind": "server"})
    run = sample_run(report_key=key, language=language, filters={**filters, "q": "synthetic-private"})
    title, text = schedules.digest({"id": str(uuid4()), "report_run": run, "private": "synthetic-private"},
                                    "https://sli.example.invalid/app")
    assert title and key in text and "partial" in text and "unavailable" in text
    assert str(run["id"]) in text and "2026-10-17T09:00:00+00:00" in text
    assert "2026-10-18T09:00:00+00:00" in text and "/app/report/" in text
    assert "synthetic-private" not in text and "token=" not in text
    query = parse_qs(urlsplit(text.splitlines()[-1]).query)
    assert all(query[name] == [value] for name, value in filters.items())
    assert "q" not in query and query["tz"] == [run["timezone"]]


def test_prepare_uses_fixed_lease_accessor_and_denies_missing_fence():
    calls = []
    class Cursor:
        def execute(self, sql, params):
            calls.append((sql, params))
        def fetchone(self):
            return {'prepared': None}
    job = {'id': str(uuid4()), 'lease_token': str(uuid4())}
    with pytest.raises(PermissionError):
        schedules.prepare_delivery(Cursor(), job, {})
    assert len(calls) == 2
    assert 'set_config' in calls[0][0]
    assert calls[1] == ('select public.report_schedule_delivery(%s::uuid,%s::uuid) as prepared',
                        (job['id'], job['lease_token']))


def test_schedule_api_admin_csrf_validation_and_fixed_errors(monkeypatch):
    path = routes.PREFIX + "/schedules"
    handler = Handler(csrf=False)
    assert routes.try_handle_post(handler, path) and handler.reads == 0
    handler = Handler(decision=access(role="viewer"))
    routes.try_handle_post(handler, path)
    assert handler.status == HTTPStatus.FORBIDDEN and handler.reads == 0
    handler = Handler(body={"token": "synthetic-secret"})
    routes.try_handle_post(handler, path)
    assert handler.response == {"error": "invalid_notification_request"}
    def unavailable(*_, **__):
        raise RuntimeError("synthetic-secret")
    monkeypatch.setattr(schedules, "save", unavailable)
    routes.try_handle_post(handler, path)
    assert handler.response == {"error": "notifications_unavailable"}
    def conflict(*_, **__):
        raise LookupError("synthetic-private")
    monkeypatch.setattr(schedules, "save", conflict)
    routes.try_handle_post(handler, path + "/" + str(uuid4()))
    assert handler.status == HTTPStatus.CONFLICT and handler.response == {"error": "notification_schedule_conflict"}
    monkeypatch.setattr(schedules, "listing", lambda _, **kwargs: [{"runs": kwargs["runs"]}])
    routes.try_handle_get(handler, routes.PREFIX + "/runs", {})
    assert handler.response == {"items": [{"runs": True}]}


def test_schedule_routes_and_worker_cli_registered(monkeypatch):
    from server.api.http_server import create_app
    from server.sli.access.access_control_v4 import route_capability
    path = routes.PREFIX + "/schedules"
    assert route_capability(path) == "access.manage"
    assert routes in create_app().candidates("GET", path)
    monkeypatch.setattr("sys.argv", ["notification_outbox", "--schedules", "--smtp", "--telegram", "--limit", "1"])
    calls = []
    monkeypatch.setattr(schedules, "tick", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(outbox, "process_one", lambda **kwargs: calls.append(kwargs) or False)
    assert outbox.main() == 1
    assert calls == []


def test_report_worker_uses_report_permissions_and_prepared_run(store, monkeypatch):
    from server.sli.core import notification_smtp as smtp
    from server.sli.core import report_schedule_delivery as delivery
    from tests.unit.test_notification_outbox import enqueue
    job = enqueue(store)
    store.jobs[job["id"]]["object_kind"] = "report_schedule"
    monkeypatch.setattr(delivery, 'load', lambda cur, job: {'subscription': store.subscriptions[job['subscription_id']]})
    def prepare(cur, job, subscription, *, prepared):
        assert prepared['subscription'] == subscription
        return {**job, "report_run": sample_run(), 'report_channel_revision': 1}
    monkeypatch.setattr(schedules, "prepare_delivery", prepare)
    monkeypatch.setattr(outbox, "require_recipient", lambda _: pytest.fail("queue-only permission used for a report"))
    received = []
    monkeypatch.setattr(smtp, "send", lambda job, channel: received.append(job) or "accepted")
    assert outbox.process_one(smtp=True, telegram=True, notification_only=True, include_reports=True)
    assert received[0]["report_run"]["quality"] == "partial"
    assert store.jobs[job["id"]]["state"] == "accepted"


def test_report_worker_denies_revoked_access_before_transport(store, monkeypatch):
    from server.sli.core import notification_smtp as smtp
    from server.sli.core import report_schedule_delivery as delivery
    from tests.unit.test_notification_outbox import enqueue
    job = enqueue(store)
    store.jobs[job["id"]]["object_kind"] = "report_schedule"
    monkeypatch.setattr(delivery, 'load', lambda cur, job: {'subscription': store.subscriptions[job['subscription_id']]})
    def denied(*_, **__):
        raise PermissionError("synthetic-private")
    monkeypatch.setattr(schedules, "prepare_delivery", denied)
    monkeypatch.setattr(smtp, "send", lambda *_: pytest.fail("revoked dispatch"))
    assert outbox.process_one(smtp=True, telegram=True, notification_only=True, include_reports=True)
    assert store.jobs[job["id"]]["state"] == "blocked"
    assert store.jobs[job["id"]]["result_code"] == "recipient_denied"


def test_run_listing_excludes_source_counts_and_private_values(monkeypatch):
    calls = []
    row = {**sample_run(item_count=42), "private": "synthetic-private"}
    def query(sql):
        calls.append(sql)
        return [row]
    monkeypatch.setattr(outbox.database, "query_rows", query)
    items = schedules.listing(access(), runs=True)
    assert "item_count" not in items[0] and "private" not in items[0]
    assert "item_count" not in calls[0]
    assert "synthetic-private" not in str(items)


def test_schedule_listing_roundtrips_approved_subscription_ids(monkeypatch):
    ids = [uuid4(), uuid4()]
    monkeypatch.setattr(outbox.database, "query_rows", lambda *_: [{**schedule(), "subscription_ids": ids}])
    assert schedules.listing(access())[0]["subscription_ids"] == [str(v) for v in ids]


@pytest.mark.parametrize("decision", [access(role="viewer"), access(scope={"kind": "domain", "ids": [1]}),
    access(scope={"kind": "domain", "ids": [2]}), access(actions=("view",))])
def test_schedule_write_denies_unprivileged_and_other_scopes_before_database(decision):
    with pytest.raises(PermissionError):
        schedules.save(decision, 1, config(), audit=lambda *_: None)

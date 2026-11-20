"""N09: bounded calendar releases, immutable period snapshots and safe digests."""

from __future__ import annotations

from server.sli.core.report_schedule_calendar import local_instant, latest_slot, period_start

from datetime import datetime, time, timedelta, timezone
import json
from urllib.parse import urlencode
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from server.sli.core import notification_channels as channels, notification_outbox as outbox
from server.sli.reporting.v2.access import ReportAccess, resolve_access_scope
from server.sli.reporting.v2.definition import QueryContext, parse_params, source_state
from server.sli.reporting.v2.registry import get_report

UTC = timezone.utc
REPORTS = {
    "security.problems": {"severity", "status", "population"},
    "file-audit.mass-operations": {"operation", "source_kind"},
}
SCHEDULE_FIELDS = ("id", "owner_user_id", "report_key", "filters", "timezone", "local_time", "weekday",
                   "period_days", "language", "enabled", "revision", "created_at")
RUN_FIELDS = ("id", "schedule_id", "schedule_revision", "report_key", "slot", "period_from", "period_to",
              "generated_at", "quality", "item_count", "truncated", "delayed", "language")


def validate(body):
    expected = {"report_key", "filters", "timezone", "local_time", "weekday", "period_days", "language",
                "enabled", "subscription_ids"}
    try:
        if not isinstance(body, dict) or set(body) != expected:
            raise ValueError
        definition = get_report(body["report_key"]) if body["report_key"] in REPORTS else None
        if definition is None or not isinstance(body["filters"], dict) or not set(body["filters"]) <= REPORTS[definition.key]:
            raise ValueError
        choices = {p.key: {v for v, _ in p.options} for p in definition.params}
        if any(not isinstance(v, str) or v not in choices[k] for k, v in body["filters"].items()):
            raise ValueError
        if not isinstance(body["timezone"], str) or len(body["timezone"]) > 100:
            raise ValueError
        ZoneInfo(body["timezone"])
        if not isinstance(body["local_time"], str) or time.fromisoformat(body["local_time"]).strftime("%H:%M") != body["local_time"]:
            raise ValueError
        if body["weekday"] is not None and (type(body["weekday"]) is not int or not 0 <= body["weekday"] <= 6):
            raise ValueError
        if type(body["period_days"]) is not int or body["period_days"] not in (1, 7, 30):
            raise ValueError
        if body["language"] not in ("ru", "en") or type(body["enabled"]) is not bool:
            raise ValueError
        ids = body["subscription_ids"]
        if not isinstance(ids, list) or not 1 <= len(ids) <= 100:
            raise ValueError
        ids = [outbox.identifier(value) for value in ids]
        if len(set(ids)) != len(ids):
            raise ValueError
    except (KeyError, TypeError, ValueError, ZoneInfoNotFoundError):
        raise ValueError("invalid_notification_request") from None
    return {**body, "subscription_ids": ids}


def report_access(user_id, report_key, *, export=False):
    """Conservative first release: explicit global scope for every participant."""
    access = outbox.recipient_access(user_id)
    definition = get_report(report_key)
    if definition is None or report_key not in REPORTS:
        raise PermissionError("notification_recipient_denied")
    action = definition.access.export_action if export else "view"
    if export and report_key.startswith("file-audit.") and (
            "file-audit.export" not in set(access.get("capabilities") or [])):
        raise PermissionError("notification_recipient_denied")
    scope = resolve_access_scope(access, definition.access, action)
    if scope.mode != "all":
        raise PermissionError("notification_recipient_denied")
    return definition, access, ReportAccess(definition, access, action)


def save(access, owner_user_id, body, *, audit, schedule_id=None):
    channels.require_access(access, action="configure_channel")
    owner_user_id = outbox._positive(owner_user_id)
    revision = None
    if schedule_id:
        schedule_id = outbox.identifier(schedule_id)
        if not isinstance(body, dict):
            raise ValueError("invalid_notification_request")
        body = dict(body)
        revision = outbox._positive(body.pop("revision", None))
    body = validate(body)
    schedule_id = schedule_id or str(uuid4())
    with outbox.connect() as conn, conn.cursor() as cur:
        if revision:
            cur.execute("select * from report_schedules where id=%s for update", (schedule_id,))
            old = cur.fetchone()
            if not old or old["revision"] != revision:
                raise LookupError("notification_schedule_conflict")
            owner_user_id = old["owner_user_id"]
        subscriptions = []
        for identifier in sorted(body["subscription_ids"]):
            cur.execute("select * from notification_subscriptions where id=%s for share", (identifier,))
            row = cur.fetchone()
            if not row or row["owner_user_id"] != owner_user_id or (body["enabled"] and not row["enabled"]):
                raise PermissionError("notification_recipient_denied")
            subscriptions.append(row)
        if body["enabled"]:
            for user_id in {owner_user_id, *(s["recipient_user_id"] for s in subscriptions)}:
                report_access(user_id, body["report_key"])
        values = (body["report_key"], json.dumps(body["filters"]), body["timezone"], body["local_time"],
                  body["weekday"], body["period_days"], body["language"], body["enabled"])
        if revision:
            cur.execute("""update report_schedules set report_key=%s,filters=%s::jsonb,timezone=%s,local_time=%s,
                weekday=%s,period_days=%s,language=%s,enabled=%s,revision=revision+1 where id=%s returning *""",
                (*values, schedule_id))
        else:
            cur.execute("""insert into report_schedules(report_key,filters,timezone,local_time,weekday,period_days,
                language,enabled,id,owner_user_id) values(%s,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s) returning *""",
                (*values, schedule_id, owner_user_id))
        saved = cur.fetchone()
        cur.execute("delete from report_schedule_subscriptions where schedule_id=%s", (schedule_id,))
        for subscription in subscriptions:
            cur.execute("insert into report_schedule_subscriptions(schedule_id,subscription_id) values(%s,%s)",
                        (schedule_id, subscription["id"]))
        audit(cur, {"id": schedule_id, "revision": saved["revision"]})
        conn.commit()
    return {**outbox._project(saved, SCHEDULE_FIELDS), "subscription_ids": body["subscription_ids"]}






def snapshot(schedule, slot, users, now):
    start = period_start(schedule, slot)
    run = dict(id=str(uuid4()), schedule_id=str(schedule["id"]), schedule_revision=schedule["revision"],
               report_key=schedule["report_key"], slot=slot, period_from=start, period_to=slot,
               generated_at=now, quality="error", item_count=None, truncated=False,
               delayed=now - slot >= timedelta(minutes=1), language=schedule["language"])
    try:
        definition, access, projection = report_access(schedule["owner_user_id"], schedule["report_key"])
    except (PermissionError, ValueError):
        run["quality"] = "denied"
        return run
    can_export = True
    for user in users:
        try:
            report_access(user, schedule["report_key"])
            report_access(user, schedule["report_key"], export=True)
        except (PermissionError, ValueError):
            can_export = False
    query = {k: [v] for k, v in schedule["filters"].items()}
    query["tz"] = [schedule["timezone"]]
    if schedule["report_key"] == "security.problems":
        query.update(time_from=[start.isoformat()], time_to=[slot.isoformat()])
    else:
        query.update(period=["custom"], **{"from": [start.isoformat()], "to": [slot.isoformat()]})
    params, _ = parse_params(definition, query)
    context = QueryContext(access=access, params=params, timezone=schedule["timezone"],
                           domain_ids=projection.domain_ids, scope=resolve_access_scope(access, definition.access),
                           field_access=projection.fields_allowed, limit=definition.default_limit)
    try:
        data = projection.result(definition.query(context))
        run["quality"] = source_state(data.get("state"))
        run["truncated"] = bool(data.get("has_more"))
        if (run["truncated"] or data.get("limitations")) and run["quality"] in ("ok", "empty"):
            run["quality"] = "partial"
        count = data.get("filtered_count")
        if can_export and run["quality"] in ("ok", "empty", "partial", "stale") and type(count) is int and count >= 0:
            run["item_count"] = count
    except PermissionError:
        run["quality"] = "denied"
    except Exception:
        pass  # Fixed quality only; query errors may contain private source values.
    return run


def release(schedule_id, *, now=None):
    now = now or datetime.now(UTC)
    with outbox.connect() as conn, conn.cursor() as cur:
        cur.execute("select * from report_schedules where id=%s and enabled for update skip locked", (schedule_id,))
        schedule = cur.fetchone()
        if not schedule:
            return False
        slot = latest_slot(schedule, now)
        if slot is None:
            return False
        cur.execute("select id from report_schedule_runs where schedule_id=%s and schedule_revision=%s and slot=%s",
                    (schedule_id, schedule["revision"], slot))
        if cur.fetchone():
            return False
        cur.execute("""select s.* from notification_subscriptions s join report_schedule_subscriptions b
            on b.subscription_id=s.id where b.schedule_id=%s order by s.id for share of s""", (schedule_id,))
        subscriptions = [s for s in cur.fetchall() if s["enabled"]]
        if not subscriptions:
            return False
        users = {schedule["owner_user_id"], *(s["recipient_user_id"] for s in subscriptions)}
        # One release per recipient/channel even if two approved bindings coincide.
        subscriptions = list({(s["recipient_user_id"], s["channel"]): s for s in subscriptions}.values())
        run = snapshot(schedule, slot, users, now)
        cur.execute("select pg_advisory_xact_lock(hashtext('notification_outbox_admission'))")
        cur.execute("select count(*) as total from notification_outbox where state in ('pending','sending','retry')")
        if cur.fetchone()["total"] + len(subscriptions) > outbox.MAX_PENDING:
            raise ValueError("notification_queue_full")
        cur.execute("insert into report_schedule_runs(" + ",".join(RUN_FIELDS) + ") values("
                    + ",".join(["%s"] * len(RUN_FIELDS)) + ")", tuple(run[key] for key in RUN_FIELDS))
        for s in subscriptions:
            cur.execute("""insert into notification_outbox(id,subscription_id,subscription_revision,object_kind,
                object_id,recipient_user_id,channel) values(%s,%s,%s,'report_schedule',%s,%s,%s)""",
                (str(uuid4()), s["id"], s["revision"], run["id"], s["recipient_user_id"], s["channel"]))
        conn.commit()
    return True


def tick(*, limit=50):
    for row in outbox.database.query_rows("select id from report_schedules where enabled order by last_checked_at,id limit ?", (limit,)):
        try:
            release(row["id"])
        except (PermissionError, ValueError):
            pass
        finally:
            with outbox.connect() as conn, conn.cursor() as cur:
                cur.execute("update report_schedules set last_checked_at=clock_timestamp() where id=%s", (row["id"],))
                conn.commit()


def prepare_delivery(cur, job, subscription, *, prepared=None):
    from server.sli.core.report_schedule_delivery import load, authorize
    return authorize(job, prepared if prepared is not None else load(cur, job))


def digest(job, base_url):
    """Render worker-prepared metadata only; never pass report rows to a channel."""
    run = job["report_run"]
    key = run["report_key"]
    if key not in REPORTS:
        raise ValueError("invalid_notification_request")
    start, end = (run[k].isoformat() for k in ("period_from", "period_to"))
    params = {name: value for name, value in run["filters"].items() if name in REPORTS[key]}
    params.update(tz=run["timezone"])
    params.update({"time_from": start, "time_to": end} if key == "security.problems"
                  else {"period": "custom", "from": start, "to": end})
    link = f"{base_url.rstrip('/')}/report/{key}?{urlencode(params)}"
    ru = run["language"] == "ru"
    title = {"security.problems": ("Проблемы безопасности", "Security problems"),
             "file-audit.mass-operations": ("Массовые файловые операции", "Mass file operations")}[key][0 if ru else 1]
    labels = ("Период [от, до)", "Качество", "Количество", "Сформировано", "Усечение", "Задержка", "Выпуск") if ru else (
              "Period [from, to)", "Quality", "Count", "Generated", "Truncated", "Delayed", "Run")
    values = (f"[{start}, {end})", run["quality"], run["item_count"] if run["item_count"] is not None else "unavailable",
              run["generated_at"].isoformat(), str(run["truncated"]).lower(), str(run["delayed"]).lower(), str(run["id"]))
    return title, title + "\n" + "\n".join(f"{label}: {value}" for label, value in zip(labels, values)) + f"\nJob: {job['id']}\n{link}\n"


def listing(access, *, runs=False):
    channels.require_access(access)
    # Configuration auditors see technical metadata, never source aggregates.
    fields, table = (tuple(k for k in RUN_FIELDS if k != "item_count"), "report_schedule_runs") if runs else (
                     SCHEDULE_FIELDS, "report_schedules")
    bindings = "" if runs else """,array(select subscription_id from report_schedule_subscriptions b
        where b.schedule_id=report_schedules.id order by subscription_id) as subscription_ids"""
    rows = outbox.database.query_rows("select " + ",".join(fields) + bindings + " from " + table
        + " order by " + ("generated_at desc,id" if runs else "id") + " limit 200")
    return [{**outbox._project(row, fields), **({"subscription_ids": [str(v) for v in row["subscription_ids"]]} if not runs else {})}
            for row in rows]

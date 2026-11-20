"""N10 value-free presentation of the existing notification registry/outbox."""
from dataclasses import replace
from datetime import datetime

from server.sli.core import database, notification_channels as channels, notification_outbox as outbox
from server.sli.core.keyset_cursor import decode_cursor, encode_cursor
from server.sli.reporting.v2.access import resolve_access_scope

ACCESS = replace(channels.ACCESS, access_key="notifications.deliveries")
STATES = {
    "accepted": ("accepted",),
    "errors": ("failed", "blocked", "delivery_unknown"),
    "waiting": ("pending", "sending", "retry"),
    "other": ("dry_run", "cancelled"),
}
FIELDS = (*outbox.JOB_FIELDS, "object_kind", "object_severity", "available_at", "finding_id")


def _time(value):
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError
        return stamp.isoformat()
    except (AttributeError, TypeError, ValueError):
        raise ValueError("invalid_notification_request") from None


def workspace(access, *, days=7, channel=None, status=None, cursor=None, since=None, finding_id=None):
    # A single snapshot must not bypass either report's independent grant.
    channels.require_access(access)
    resolve_access_scope(access, ACCESS)
    if (type(days) is not int or days not in {1, 7, 30}
            or channel not in {None, "smtp", "telegram"} or status not in {None, *STATES}):
        raise ValueError("invalid_notification_request")
    since = _time(since) if since is not None else None
    binding = [days, channel, status, finding_id]
    position = decode_cursor(cursor, binding) if cursor else None
    boundary = (_time(position.get("time")), outbox.identifier(position.get("id"))) if position is not None else None
    clauses, params = ["created_at >= clock_timestamp() - (? * interval '1 day')"], [days]
    # Object links require the queue grant too, independently of journal access.
    can_link = False
    try:
        can_link = outbox.queue_access(access).scope.mode == "all"
    except PermissionError:
        pass
    if finding_id is not None:
        if type(finding_id) is not int or not 0 < finding_id < 2**63:
            raise ValueError("invalid_notification_request")
        if not can_link:
            raise PermissionError("notifications_access_denied")
        clauses.append("object_kind='semantic_finding' and public.notification_finding_object(object_id)=?")
        params.append(finding_id)
    if channel:
        clauses.append("channel=?")
        params.append(channel)
    where = " and ".join(clauses)
    # Counts intentionally ignore the selected status and page boundary.
    counts = database.query_rows(
        """select count(*) as total,
        count(*) filter(where state='accepted') as accepted,
        count(*) filter(where state in ('failed','blocked','delivery_unknown')) as errors,
        count(*) filter(where state in ('pending','sending','retry')) as waiting,
        count(*) filter(where state in ('dry_run','cancelled')) as other,
        case when ?::timestamptz is null then null
             else count(*) filter(where created_at>?::timestamptz) end as new_count
        from notification_outbox where """ + where, (since, since, *params),
    )[0]
    if status:
        clauses.append("state=any(?)")
        params.append(list(STATES[status]))
    if boundary:
        clauses.append("(created_at,id)<(?::timestamptz,?::uuid)")
        params.extend(boundary)
    link = "case when object_kind='semantic_finding' then public.notification_finding_object(object_id) end" if can_link else "null::bigint"
    rows = database.query_rows(
        "select " + ",".join(field for field in FIELDS if field != "finding_id")
        + f",{link} as finding_id from notification_outbox where " + " and ".join(clauses)
        + " order by created_at desc,id desc limit 101", tuple(params),
    )
    items = [{field: row.get(field) for field in FIELDS} for row in rows[:100]]
    more = len(rows) > 100
    registry = database.query_rows(
        # Transport scheduling columns can contain PostgreSQL infinity values;
        # fetch only the metadata exposed by this workspace.
        "select " + ",".join(f"c.{field}" for field in channels.FIELDS) + """,
        (select max(updated_at) from notification_outbox where channel=c.kind and state='accepted') as last_accepted_at,
        (select result_code from notification_outbox where channel=c.kind order by updated_at desc,id desc limit 1) as last_result_code
        from notification_channels c order by kind""",
    )
    metadata = [{**{field: row[field] for field in channels.FIELDS},
                 "last_accepted_at": row.get("last_accepted_at"), "last_result_code": row.get("last_result_code"),
                 # N02 secrets are mounted only into the delivery service. The
                 # web process cannot infer their presence from enabled=true.
                 "secret_status": None} for row in registry]
    try:
        channels.require_access(access, action="configure_channel")
        can_configure = True
    except PermissionError:
        can_configure = False
    return {"channels": metadata, "subscriptions": outbox.list_subscriptions(access),
            "counts": {key: counts.get(key) for key in ("total", *STATES, "new_count")},
            "items": items, "has_more": more, "previous_login_at": since,
            "can_configure": can_configure,
            "next_cursor": encode_cursor(binding, {"time": items[-1]["created_at"], "id": items[-1]["id"]}) if more else None}

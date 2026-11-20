"""Fixed-accessor report delivery preparation."""

from datetime import datetime

from server.sli.plugins.file_audit.access import require_access
from server.sli.reporting.read_timeout import report_read_budget, remaining_read_ms


def load(cur, job):
    """Acquire the schedule/job fence before ordinary subscription row locks."""
    cur.execute("select pg_catalog.set_config('statement_timeout',%s,true), "
                "pg_catalog.set_config('lock_timeout',%s,true)", ("2000ms", "500ms"))
    cur.execute("select public.report_schedule_delivery(%s::uuid,%s::uuid) as prepared",
                (job["id"], job["lease_token"]))
    row = cur.fetchone()
    return row["prepared"] if row else None


def authorize(job, payload, *, definition=None, actor_access=None, authority_factory=None):
    """Retain current owner/recipient policy checks before either transport."""
    if not payload:
        raise PermissionError("notification_recipient_denied")
    subscription, run = payload["subscription"], dict(payload["run"])
    if (str(run["id"]) != str(job["object_id"]) or str(subscription["id"]) != str(job["subscription_id"])
            or subscription["recipient_user_id"] != job["recipient_user_id"] or subscription["channel"] != job["channel"]
            or subscription["owner_user_id"] != payload["owner_user_id"] or not subscription["enabled"]):
        raise PermissionError("notification_recipient_denied")
    if definition is None:
        from server.sli.reporting.v2.registry import get_report
        definition = get_report(run["report_key"])
    if authority_factory is None:
        from server.sli.reporting.v2.access import ReportAccess
        authority_factory = ReportAccess
    if actor_access is None:
        from server.sli.core.notification_outbox import recipient_access
        actor_access = recipient_access
    key = run["report_key"]
    if definition is None or definition.key != key or key not in {"security.problems", "file-audit.mass-operations"}:
        raise PermissionError("notification_recipient_denied")
    roots = payload["root_scope"]
    if not isinstance(roots, list) or len(roots) > 1000:
        raise PermissionError("notification_recipient_denied")
    # An explicit worker budget also caps the resolver's own connections. It
    # does not rely on an HTTP request having installed a ContextVar deadline.
    with report_read_budget(timeout_ms=5000):
        for user in {payload["owner_user_id"], subscription["owner_user_id"], job["recipient_user_id"]}:
            remaining_read_ms()
            access = actor_access(user)
            view = authority_factory(definition, access)
            if view.scope is None or view.scope.mode != "all":
                raise PermissionError("notification_recipient_denied")
            if run["item_count"] is None:
                continue
            export = authority_factory(definition, access, "export")
            if export.scope is None or export.scope.mode != "all":
                raise PermissionError("notification_recipient_denied")
            if key == "security.problems" and user == payload["owner_user_id"]:
                if payload["selection"].get("variant") == "cohorts" and not view.fields_allowed(frozenset({"identity_basic"})):
                    raise PermissionError("notification_recipient_denied")
            if key.startswith("file-audit."):
                if "file-audit.export" not in set(access.get("capabilities") or []):
                    raise PermissionError("notification_recipient_denied")
                for root in roots:
                    remaining_read_ms()
                    if not isinstance(root, dict) or set(root) != {"agent_id", "source_instance_id", "collection_scope_id"}:
                        raise PermissionError("notification_recipient_denied")
                    require_access(access, action="view", **root)
                    require_access(access, action="export", **root)
    for field in ("slot", "period_from", "period_to", "generated_at"):
        if isinstance(run[field], str):
            run[field] = datetime.fromisoformat(run[field].replace("Z", "+00:00"))
    return {**job, "report_run": run, "report_channel_revision": payload["channel_revision"]}

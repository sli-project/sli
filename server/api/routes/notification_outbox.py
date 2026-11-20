"""N03 administrative subscriptions and explicit simulated test problems."""

from http import HTTPStatus

from server.sli.access.access_control_v4 import record_access_audit_with_cursor
from server.sli.core import notification_channels as channels, notification_outbox as outbox, report_schedules

PREFIX = "/api/v1/notification-subscriptions"
ROUTES = (
    ("GET", "/api/v1/notification-subscriptions"),
    ("GET", "/api/v1/notification-subscriptions/schedules"),
    ("GET", "/api/v1/notification-subscriptions/runs"),
    ("POST", "/api/v1/notification-subscriptions"),
    ("POST", "/api/v1/notification-subscriptions/*"),
)


def try_handle_get(handler, path, query):
    if path in {PREFIX, "/api/v1/notification-subscriptions/schedules", "/api/v1/notification-subscriptions/runs"}:
        try:
            access = handler._access_decision()
            items = (outbox.list_subscriptions(access) if path == PREFIX else
                     report_schedules.listing(access, runs=path.endswith("/runs")))
        except PermissionError:
            handler._send_json({"error": "notifications_access_denied"}, HTTPStatus.FORBIDDEN)
        except Exception:
            handler._send_json({"error": "notifications_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
        else:
            handler._send_json({"items": items})
        return True
    return False


def try_handle_post(handler, path):
    if not (path == PREFIX or path.startswith("/api/v1/notification-subscriptions/")):
        return False
    if not handler._authorize_mutation(required_role="admin"):
        return True
    suffix = path.removeprefix(PREFIX).strip("/")
    is_schedule = suffix == "schedules" or suffix.startswith("schedules/")

    def audit(cursor, details):
        record_access_audit_with_cursor(
            cursor=cursor, actor=getattr(handler, "_principal", None),
            action=("notification_schedule_update" if is_schedule else
                    "notification_test_enqueue" if details.get("simulated") else "notification_subscription_update"),
            target_type="notification", target_key=details["id"], details=details,
        )

    try:
        access = handler._access_decision()
        channels.require_access(access, action="configure_channel")
        if is_schedule:
            principal = getattr(handler, "_principal", None) or {}
            if principal.get("type") != "session":
                raise PermissionError("notifications_access_denied")
            item = report_schedules.save(access, principal.get("id"), handler._read_json_body(), audit=audit,
                                         schedule_id=suffix.removeprefix("schedules/") if suffix != "schedules" else None)
        elif suffix.endswith("/test"):
            item = outbox.enqueue_test_problem(access, suffix.removesuffix("/test"), handler._read_json_body(), audit=audit)
        else:
            principal = getattr(handler, "_principal", None) or {}
            if principal.get("type") != "session":
                raise PermissionError("notifications_access_denied")
            item = outbox.save_subscription(access, principal.get("id"), handler._read_json_body(),
                                            audit=audit, subscription_id=suffix or None)
    except PermissionError:
        handler._send_json({"error": "notifications_access_denied"}, HTTPStatus.FORBIDDEN)
    except ValueError as exc:
        full = str(exc) == "notification_queue_full"
        handler._send_json({"error": "notification_queue_full" if full else "invalid_notification_request"},
                           HTTPStatus.TOO_MANY_REQUESTS if full else HTTPStatus.BAD_REQUEST)
    except LookupError:
        code = "notification_schedule_conflict" if is_schedule else "notification_subscription_conflict"
        handler._send_json({"error": code}, HTTPStatus.CONFLICT)
    except Exception:
        handler._send_json({"error": "notifications_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
    else:
        handler._send_json({"item": item})
    return True

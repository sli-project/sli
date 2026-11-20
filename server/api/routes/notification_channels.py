"""Admin-only metadata API. No secret reads, imports or transport calls."""

from http import HTTPStatus

from server.sli.access.access_control_v4 import record_access_audit_with_cursor
from server.sli.core import notification_channels as channels
from server.sli.core.telegram_setup import TelegramSetupError
from server.sli.core.smtp_setup import SMTPSetupError

PREFIX = "/api/v1/notification-channels"
ROUTES = (("GET", "/api/v1/notification-channels"),
          ("GET", "/api/v1/notification-channels/workspace"),
          ("POST", "/api/v1/notification-channels/*"),
          ("POST", "/api/v1/notification-channels/telegram/setup/*"),
          ("POST", "/api/v1/notification-channels/smtp/setup/*"))


def try_handle_get(handler, path, query):
    if path == "/api/v1/notification-channels/workspace":
        from server.sli.access.auth import previous_login
        from server.sli.core.notification_workspace import workspace

        try:
            access = handler._access_decision()
            # Resolve both grants before the login-baseline database read.
            from server.sli.core.notification_workspace import ACCESS, resolve_access_scope
            channels.require_access(access)
            resolve_access_scope(access, ACCESS)
            payload = workspace(
                access, days=int((query.get("days") or ["7"])[0]),
                channel=(query.get("channel") or [None])[0], status=(query.get("status") or [None])[0],
                cursor=(query.get("cursor") or [None])[0],
                since=previous_login(getattr(handler, "_principal", None) or {}),
                finding_id=int(query["finding_id"][0]) if query.get("finding_id") else None,
            )
        except PermissionError:
            handler._send_json({"error": "notification_channels_access_denied"}, HTTPStatus.FORBIDDEN)
        except ValueError:
            handler._send_json({"error": "invalid_notification_request"}, HTTPStatus.BAD_REQUEST)
        except Exception:
            handler._send_json({"error": "notification_channels_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
        else:
            handler._send_json(payload)
        return True
    if path == PREFIX:
        try:
            items = channels.list_channels(handler._access_decision())
        except PermissionError:
            handler._send_json({"error": "notification_channels_access_denied"}, HTTPStatus.FORBIDDEN)
        except Exception:
            handler._send_json({"error": "notification_channels_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
        else:
            handler._send_json({"items": items})
        return True
    return False


def try_handle_post(handler, path):
    if not path.startswith("/api/v1/notification-channels/"):
        return False
    if not handler._authorize_mutation(required_role="admin"):
        return True
    access = handler._access_decision()

    def audit(cursor, details):
        record_access_audit_with_cursor(
            cursor=cursor, actor=getattr(handler, "_principal", None),
            action="notification_channel_update", target_type="notification_channel",
            target_key=details.get("kind", "telegram"), details=details,
        )

    try:
        channels.require_access(access, action="configure_channel")
        if path.startswith("/api/v1/notification-channels/smtp/setup/"):
            from server.api.smtp_setup import configure

            handler._send_json(configure(handler, path.removeprefix(PREFIX + "/smtp/setup/"), audit))
            return True
        if path.startswith("/api/v1/notification-channels/telegram/setup/"):
            from server.api.telegram_setup import configure

            result = configure(handler, path.removeprefix(PREFIX + "/telegram/setup/"), audit)
            handler._send_json(result)
            return True
        item = channels.update_channel(access, path.removeprefix(PREFIX + "/"), handler._read_json_body(), audit=audit)
    except PermissionError:
        handler._send_json({"error": "notification_channels_access_denied"}, HTTPStatus.FORBIDDEN)
    except SMTPSetupError as exc:
        from server.sli.core.messages import message

        handler._send_json({"error": exc.code, "message": message("notifications.smtp.setup." + exc.code.removeprefix("smtp_setup_"))}, exc.status)
    except TelegramSetupError as exc:
        handler._send_json({"error": exc.code.value}, exc.status)
    except ValueError:
        handler._send_json({"error": "invalid_notification_channel_metadata"}, HTTPStatus.BAD_REQUEST)
    except LookupError as exc:
        conflict = str(exc) == "notification_channel_revision_conflict"
        handler._send_json({"error": "notification_channel_revision_conflict" if conflict else "notification_channel_not_found"},
                           HTTPStatus.CONFLICT if conflict else HTTPStatus.NOT_FOUND)
    except Exception:
        handler._send_json({"error": "notification_channels_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
    else:
        handler._send_json({"item": item})
    return True


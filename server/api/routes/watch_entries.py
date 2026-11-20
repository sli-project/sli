"""Account watch registry API; configuration and audit commit together."""
from http import HTTPStatus

from server.sli.access.access_control_v4 import record_access_audit_with_cursor
from server.sli.core import watch_entries as registry
from server.sli.core.messages import message, select_locale

PREFIX = "/api/v1/watch"
ENTRY_PREFIX = "/api/v1/watch/"
ROUTES = (
    ("GET", "/api/v1/watch"),
    ("POST", "/api/v1/watch"),
    ("POST", "/api/v1/watch/*"),
)


def is_resource_aware(path):
    return path == PREFIX


def _error(handler, exc):
    if isinstance(exc, PermissionError):
        code, status, key = "watch_access_denied", HTTPStatus.FORBIDDEN, "watch.denied"
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        code, status, key = "watch_invalid", HTTPStatus.BAD_REQUEST, "watch.failed"
    elif isinstance(exc, LookupError) or getattr(exc, "sqlstate", None) == "23505":
        code, status, key = "watch_revision_conflict", HTTPStatus.CONFLICT, "watch.conflict"
    else:
        code, status, key = "watch_unavailable", HTTPStatus.SERVICE_UNAVAILABLE, "watch.failed"
    locale = select_locale(getattr(handler, "headers", {}).get("Accept-Language"))
    handler._send_json({"error": code, "message": message(key, locale=locale)}, status)


def try_handle_get(handler, path, query):
    if path == PREFIX:
        try:
            access = handler._access_decision()
            registry.require_access(access)
            entity = (query.get("entity_id") or [None])[0]
            entity_id = int(entity) if entity is not None and entity.isdigit() else None
            if entity is not None and entity_id is None:
                raise ValueError("watch_invalid")
            from server.sli.core.postgres_runtime_pipeline import connect
            with connect() as conn, conn.cursor() as cur:
                result = registry.list_entries(cur, access, principal=getattr(handler, "_principal", None),
                                               entity_id=entity_id, entry_id=(query.get("id") or [None])[0],
                                               after=(query.get("cursor") or [None])[0])
        except Exception as exc:
            _error(handler, exc)
        else:
            handler._send_json(result)
        return True
    return False


def try_handle_post(handler, path):
    if not (path == PREFIX or path.startswith(ENTRY_PREFIX)):
        return False
    if not handler._authorize_mutation():
        return True
    try:
        access = handler._access_decision()
        registry.require_access(access)
        body = handler._read_json_body()
        principal = getattr(handler, "_principal", None)
        from server.sli.core.postgres_runtime_pipeline import connect

        def audit(cur, details):
            record_access_audit_with_cursor(cursor=cur, actor=principal, action="watch_entry_update",
                                           target_type="watch_entry", target_key=details["id"], details=details)

        with connect() as conn, conn.cursor() as cur:
            item = registry.save_entry(cur, access, body, principal=principal, audit=audit,
                                       entry_id=path.removeprefix(ENTRY_PREFIX) if path != PREFIX else None)
            conn.commit()
    except Exception as exc:
        _error(handler, exc)
    else:
        handler._send_json({"item": item})
    return True

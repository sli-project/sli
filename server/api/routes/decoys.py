"""Scoped decoy label registry; all writes and access audit share a transaction."""
from http import HTTPStatus

from server.sli.access.access_control_v4 import record_access_audit_with_cursor
from server.sli.core import decoys
from server.sli.core.messages import message, select_locale

PREFIX = "/api/v1/decoys"
LABEL_PREFIX = "/api/v1/decoys/"
ROUTES = (
    ("GET", "/api/v1/decoys"),
    ("POST", "/api/v1/decoys"),
    ("POST", "/api/v1/decoys/*"),
)


def is_resource_aware(path):
    return path == PREFIX


def _error(handler, exc):
    if isinstance(exc, PermissionError):
        code, status = "decoy_access_denied", HTTPStatus.FORBIDDEN
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        code, status = "decoy_invalid", HTTPStatus.BAD_REQUEST
    elif isinstance(exc, LookupError):
        code, status = "decoy_revision_conflict", HTTPStatus.CONFLICT
    elif getattr(exc, "sqlstate", None) == "23505":
        code, status = "decoy_duplicate", HTTPStatus.CONFLICT
    else:
        code, status = "decoy_unavailable", HTTPStatus.SERVICE_UNAVAILABLE
    key = "decoys.denied" if status == HTTPStatus.FORBIDDEN else "decoys.conflict" if status == HTTPStatus.CONFLICT else "decoys.failed"
    locale = select_locale(getattr(handler, "headers", {}).get("Accept-Language"))
    handler._send_json({"error": code, "message": message(key, locale=locale)}, status)


def try_handle_get(handler, path, query):
    if path == PREFIX:
        try:
            access = handler._access_decision()
            decoys.require_access(access)
            from server.sli.core.postgres_runtime_pipeline import connect
            with connect() as conn, conn.cursor() as cur:
                if "touches" in query:
                    result = decoys.list_touches(cur, access, label_id=query["touches"][0],
                                                revision=(query.get("revision") or [None])[0],
                                                after=(query.get("cursor") or [None])[0])
                else:
                    result = decoys.list_labels(cur, access, principal=getattr(handler, "_principal", None),
                                                after=(query.get("cursor") or [None])[0],
                                                label_id=(query.get("id") or [None])[0],
                                                revision=(query.get("revision") or [None])[0])
        except Exception as exc:
            _error(handler, exc)
        else:
            handler._send_json(result)
        return True
    return False


def try_handle_post(handler, path):
    if not (path == PREFIX or path.startswith(LABEL_PREFIX)):
        return False
    if not handler._authorize_mutation(required_role="admin"):
        return True
    try:
        access = handler._access_decision()
        decoys.require_access(access)
        body = handler._read_json_body()
        principal = getattr(handler, "_principal", None)
        value = decoys.validate(body)
        decoys.require_access(access, value, manage=True, principal=principal)
        from server.sli.core.postgres_runtime_pipeline import connect

        def audit(cur, details):
            record_access_audit_with_cursor(cursor=cur, actor=principal, action="decoy_label_update",
                                            target_type="decoy_label", target_key=details["id"], details=details)

        with connect() as conn, conn.cursor() as cur:
            item = decoys.save_label(cur, access, body, principal=principal, audit=audit,
                                     label_id=path.removeprefix(LABEL_PREFIX) if path != PREFIX else None)
            conn.commit()
    except Exception as exc:
        _error(handler, exc)
    else:
        handler._send_json({"item": item})
    return True

"""DC setup responses and audit callbacks; authorization stays in core."""
from __future__ import annotations

from http import HTTPStatus
from urllib.parse import unquote

from server.sli.plugins.ad.setup import DomainControllerConflictError, DomainControllerNotFoundError

CONTROLLERS = "/api/v1/setup/domain-controllers"
CONTROLLERS_PREFIX = "/api/v1/setup/domain-controllers/"


def handle_controller_post(
    handler, path: str, *, add_target, set_enabled, record_access_audit_with_cursor,
) -> None:
    body = handler._read_json_body() or {}
    principal = getattr(handler, "_principal", None) or {}
    actor = str(principal.get("username") or f"{principal.get('type') or 'local'}:{principal.get('id')}")

    def audit(action: str):
        def write(cursor, result) -> None:
            record_access_audit_with_cursor(
                cursor=cursor,
                actor=principal,
                action=action,
                target_type="domain_controller",
                target_key=result["hostname"],
                details={key: value for key, value in result.items() if key != "hostname"},
                remote_address=handler.client_address[0],
            )
        return write

    try:
        if path == CONTROLLERS:
            item = add_target(
                str(body.get("hostname") or ""), str(body.get("domain") or ""),
                actor=actor, audit=audit("setup_dc_add"),
            )
            handler._send_json({"item": item}, HTTPStatus.CREATED)
        else:
            hostname = unquote(path.removeprefix(CONTROLLERS_PREFIX)).strip("/")
            handler._send_json({"item": set_enabled(hostname, body.get("enabled"), actor=actor, audit=audit("setup_dc_update"))})
    except DomainControllerConflictError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
    except DomainControllerNotFoundError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


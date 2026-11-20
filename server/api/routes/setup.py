"""«Первичная настройка»: first-run checklist and its editable AD domains.

GET  /api/v1/setup/status          statuses of the setup steps (domains, controllers,
                                   sources, first collection); access.manage via the
                                   capability map. Never starts collection.
GET  /api/v1/setup/domains         registered AD domains
POST /api/v1/setup/domains         {"fqdn", "netbios_name"?, "forest"?}; admin role +
                                   access.manage, written to the access audit journal
POST /api/v1/setup/domains/{fqdn}  {"netbios_name"}; same guard. Domains are never deleted.
GET  /api/v1/setup/domain-controllers          {"source": db|file|none, "items": [...]}
POST /api/v1/setup/domain-controllers          {"hostname" (FQDN), "domain"}; same guard
POST /api/v1/setup/domain-controllers/{host}   {"enabled": bool}; same guard. Never deleted.
"""

from __future__ import annotations

from http import HTTPStatus
from urllib.parse import unquote

from server.sli.access.access_control_v4 import record_access_audit_with_cursor
from server.sli.plugins.registry import require_plugin
from server.sli.core.setup_domains import (
    DomainConflictError,
    DomainNotFoundError,
    add_domain,
    list_domains,
    update_netbios,
    update_archive,
)
from server.sli.core.setup_status import build_setup_status

DOMAINS = "/api/v1/setup/domains"
DOMAINS_PREFIX = "/api/v1/setup/domains/"
CONTROLLERS = "/api/v1/setup/domain-controllers"
CONTROLLERS_PREFIX = "/api/v1/setup/domain-controllers/"

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v1/setup/status"),
    ("GET", "/api/v1/setup/domains"),
    ("POST", "/api/v1/setup/domains"),
    ("POST", "/api/v1/setup/domains/*"),
    ("GET", "/api/v1/setup/domain-controllers"),
    ("POST", "/api/v1/setup/domain-controllers"),
    ("POST", "/api/v1/setup/domain-controllers/*"),
)


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/v1/setup/status":
        handler._send_json(build_setup_status())
        return True
    if path == DOMAINS:
        handler._send_json({"items": list_domains()})
        return True
    if path == CONTROLLERS:
        handler._send_json(list_targets())
        return True
    return False


def list_targets():
    return require_plugin("sli.ad", "list_targets")


def add_target(*args, **kwargs):
    return require_plugin("sli.ad", "add_target", *args, **kwargs)


def set_enabled(*args, **kwargs):
    return require_plugin("sli.ad", "set_enabled", *args, **kwargs)


def _handle_controller_post(handler, path: str) -> None:
    require_plugin(
        "sli.ad", "handle_controller_post", handler, path,
        add_target=add_target, set_enabled=set_enabled,
        record_access_audit_with_cursor=record_access_audit_with_cursor,
    )


def try_handle_post(handler, path: str) -> bool:
    if path == CONTROLLERS or path.startswith(CONTROLLERS_PREFIX):
        if not handler._authorize_mutation(required_role="admin") or not handler._require_capability("access.manage"):
            return True
        _handle_controller_post(handler, path)
        return True
    if not (path == DOMAINS or path.startswith(DOMAINS_PREFIX)):
        return False
    if not handler._authorize_mutation(required_role="admin") or not handler._require_capability("access.manage"):
        return True
    body = handler._read_json_body() or {}
    principal = getattr(handler, "_principal", None) or {}

    def audit(action: str):
        def write(cursor, result) -> None:
            record_access_audit_with_cursor(
                cursor=cursor,
                actor=principal,
                action=action,
                target_type="ad_domain",
                target_key=result["fqdn"],
                details={key: value for key, value in result.items() if key != "fqdn"},
                remote_address=handler.client_address[0],
            )
        return write

    try:
        if path == DOMAINS:
            item = add_domain(
                str(body.get("fqdn") or ""), body.get("netbios_name"), body.get("forest"),
                audit=audit("setup_domain_add"),
            )
            handler._send_json({"item": item}, HTTPStatus.CREATED)
        else:
            fqdn = unquote(path.removeprefix(DOMAINS_PREFIX)).strip("/")
            if "is_archived" in body:
                if set(body) != {"is_archived"}:
                    raise ValueError("domain_archive_update_fields_invalid")
                item = update_archive(fqdn, body["is_archived"], audit=audit("setup_domain_update"))
            else:
                item = update_netbios(fqdn, body.get("netbios_name"), audit=audit("setup_domain_update"))
            handler._send_json({"item": item})
    except DomainConflictError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
    except DomainNotFoundError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
    return True

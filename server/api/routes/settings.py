"""«Настройки платформы»: installation-wide settings edited by an administrator.

GET  /api/v1/platform-settings          every declared setting, its value and source
POST /api/v1/platform-settings/{key}    {"value": "..."}; admin role + access.manage,
                                        written to the access audit journal
"""

from __future__ import annotations

from http import HTTPStatus
from urllib.parse import unquote

from server.sli.access.access_control_v4 import record_access_audit_with_cursor
from server.sli.core.platform_settings import SETTINGS, list_settings, set_setting
from server.sli.semantic import semantic_governance
from server.sli.plugins import settings as plugin_settings

PREFIX = "/api/v1/platform-settings"

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/plugins/{}/settings"),
    ("PUT", "/api/plugins/{}/settings"),
    ("GET", "/api/v1/platform-settings"),
    ("GET", "/api/v1/platform-settings/semantic-control"),
    ("POST", "/api/v1/platform-settings/semantic-control"),
    ("POST", "/api/v1/platform-settings/*"),
)


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path.startswith("/api/plugins/") and path.endswith("/settings"):
        if not handler._require_capability("access.manage"):
            return True
        plugin_id = path[len("/api/plugins/"):-len("/settings")]
        try:
            handler._send_json(plugin_settings.read_settings(plugin_id))
        except LookupError:
            handler._send_json({"error": "plugin_settings_not_found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, OSError):
            handler._send_json({"error": "plugin_settings_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
        return True
    if path == "/api/v1/platform-settings/semantic-control":
        if not _owner_access(handler):
            return True
        from server.sli.core.postgres_runtime_pipeline import connect

        with connect() as conn, conn.cursor() as cur:
            handler._send_json(semantic_governance.list_controls(cur))
        return True
    if path == "/api/v1/platform-settings":
        handler._send_json({"items": list_settings()})
        return True
    return False


def try_handle_put(handler, path: str) -> bool:
    if path.startswith("/api/plugins/") and path.endswith("/settings"):
        if not handler._authorize_mutation(required_role="admin") or not handler._require_capability("access.manage"):
            return True
        plugin_id = path[len("/api/plugins/"):-len("/settings")]
        body = handler._read_json_body()
        principal = getattr(handler, "_principal", None) or {}

        def audit(cursor, result):
            record_access_audit_with_cursor(
                cursor=cursor, actor=principal, action="platform_setting_update",
                target_type="platform_setting", target_key=result["key"],
                details={"plugin_id": plugin_id, "key": result["key"]},
                remote_address=handler.client_address[0],
            )

        try:
            key, value, node = plugin_settings.encode_update(plugin_id, body)
            result = set_setting(key, value, actor=str(principal.get("username") or ""), audit=audit)
        except LookupError:
            handler._send_json({"error": "plugin_settings_not_found"}, HTTPStatus.NOT_FOUND)
            return True
        except ValueError:
            handler._send_json({"error": "invalid_plugin_setting_value"}, HTTPStatus.BAD_REQUEST)
            return True
        handler._send_json({"plugin_id": plugin_id, "key": key,
                            "value": plugin_settings.typed_value(result["value"], node)})
        return True
    return False


def try_handle_post(handler, path: str) -> bool:
    if path == "/api/v1/platform-settings/semantic-control":
        if not handler._authorize_mutation(required_role="viewer") or not _owner_access(handler):
            return True
        _handle_semantic_control(handler)
        return True
    if path.startswith("/api/v1/platform-settings/"):
        if not handler._authorize_mutation(required_role="admin") or not handler._require_capability("access.manage"):
            return True
        _handle_setting_update(handler, unquote(path.removeprefix(PREFIX + "/")).strip("/"))
        return True
    return False


def _owner_access(handler) -> bool:
    if not handler._access_decision().get("platform_owner"):
        handler._send_json({"error": "platform_owner_required"}, HTTPStatus.FORBIDDEN)
        return False
    return True


def _handle_semantic_control(handler) -> None:
    from server.sli.core.postgres_runtime_pipeline import connect

    body = handler._read_json_body() or {}
    principal = getattr(handler, "_principal", None) or {}

    def audit(cursor, action, target, details):
        record_access_audit_with_cursor(cursor=cursor, actor=principal, action=action,
            target_type="semantic_control", target_key=target, reason=details.get("reason"), details=details,
            remote_address=handler.client_address[0])

    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("select expire_semantic_suppressions_v160()")
            if body.get("action") == "create_suppression":
                semantic_governance.create_suppression(cur, body, actor=principal.get("username"), audit=audit)
            elif body.get("action") == "revoke_suppression":
                rule_id = body.get("id")
                if type(rule_id) is not int or rule_id < 1:
                    raise ValueError("invalid_suppression")
                semantic_governance.revoke_suppression(cur, rule_id, actor=principal.get("username"), audit=audit, reason=body.get("reason"))
            elif body.get("action") == "policy_admission":
                semantic_governance.set_policy_admission(cur, body.get("policy_id"), body.get("policy_version"),
                    body.get("enabled"), actor=principal.get("username"), audit=audit, reason=body.get("reason"))
            else:
                raise ValueError("invalid_semantic_control_action")
            conn.commit()
    except (ValueError, LookupError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"status": "ok"})


def _handle_setting_update(handler, key: str) -> None:
    if key not in SETTINGS:
        handler._send_json({"error": "unknown_setting"}, HTTPStatus.NOT_FOUND)
        return
    body = handler._read_json_body()
    principal = getattr(handler, "_principal", None) or {}

    def audit(cursor, result) -> None:
        record_access_audit_with_cursor(
            cursor=cursor,
            actor=principal,
            action="platform_setting_update",
            target_type="platform_setting",
            target_key=key,
            details={"previous": result["previous"], "value": result["value"]},
            remote_address=handler.client_address[0],
        )

    try:
        set_setting(key, str((body or {}).get("value") or ""), actor=str(principal.get("username") or ""), audit=audit)
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"item": next(item for item in list_settings() if item["key"] == key)})

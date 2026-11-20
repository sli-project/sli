"""Durable plugin state backed by the existing installation/admission registry."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from psycopg import Error
from psycopg.errors import InsufficientPrivilege, RaiseException

from server.sli.access.access_control_v4 import capability_decision
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.plugins.registry import plugin_hook, plugin_installed
from server.sli.sources.plugin_receipts import read_plugin_receipts


# Only fixed public reason codes may cross the database/API boundary.
_STATE_CONFLICT_REASONS = frozenset({
    "plugin_state_conflict", "plugin_revision_conflict", "plugin_not_installed",
    "plugin_not_configured", "plugin_runtime_not_stopped", "plugin_runtime_not_running",
    "plugin_queue_not_drained", "plugin_active_leases", "plugin_runtime_transition_unsupported",
    "plugin_runtime_precondition_failed",
})


class PluginStateConflict(ValueError):
    def __init__(self, reason: str):
        self.reason = reason if reason in _STATE_CONFLICT_REASONS else "plugin_state_conflict"
        super().__init__(self.reason)


@dataclass(frozen=True)
class PluginState:
    plugin_id: str
    package_version: str
    installed: bool
    configured: bool
    enabled: bool
    receiving_data: bool
    component_runtime: str
    queue_state: str
    revision: int
    last_data_at_utc: str | None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> PluginState:
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


def can_manage_plugins(principal: Mapping[str, Any] | None, access: Mapping[str, Any]) -> bool:
    """A delegated capability alone never grants lifecycle mutation authority."""
    return bool(
        principal and principal.get("id")
        and capability_decision(access, "plugins.manage")["allowed"]
        and principal.get("type") in {"session", "api_key"}
        and (principal.get("role") == "admin" or (
            principal.get("type") == "session" and access.get("platform_owner") is True
        ))
    )


def remote_access_configured() -> bool:
    hook = plugin_hook("sli.remote-access", "configured")
    return bool(hook and hook())


def list_plugin_states() -> list[dict[str, Any]]:
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select * from read_plugin_states_v1()")
        rows = cur.fetchall()
    items = [PluginState.from_row(row).public_dict() for row in rows]
    receipts = read_plugin_receipts([item["plugin_id"] for item in items])
    for item in items:
        item["data_receipts"] = receipts[item["plugin_id"]]
        if item["plugin_id"] == "sli.remote-access":
            item["configured"] = remote_access_configured()
    return items


def set_plugin_enabled(
    plugin_id: str, body: Mapping[str, Any], *,
    principal: Mapping[str, Any] | None, access: Mapping[str, Any],
) -> dict[str, Any]:
    if not can_manage_plugins(principal, access):
        raise PermissionError("plugin_management_owner_or_admin_required")
    revision = body.get("expected_revision")
    enabled = body.get("enabled")
    if (
        set(body) != {"enabled", "expected_revision"}
        or type(enabled) is not bool or type(revision) is not int or revision < 1
    ):
        raise ValueError("plugin_state_request_invalid")
    # Other plugins use their server-owned configuration under the SQL lock.
    configured = remote_access_configured() if plugin_id == "sli.remote-access" else None
    if enabled and configured is False:
        raise PluginStateConflict("plugin_not_configured")
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "select * from set_plugin_enabled_v1(%s,%s,%s,%s,%s,%s)",
                (plugin_id, enabled, revision, principal["type"], principal["id"], configured),
            )
            row = cur.fetchone()
            if row is None:
                raise PluginStateConflict("plugin_state_conflict")
            item = PluginState.from_row(row).public_dict()
            conn.commit()
    except InsufficientPrivilege as exc:
        raise PermissionError("plugin_management_owner_or_admin_required") from exc
    except RaiseException as exc:
        reason = exc.diag.message_primary or str(exc)
        if reason == "plugin_not_found":
            raise LookupError(reason) from exc
        if reason == "plugin_state_request_invalid":
            raise ValueError(reason) from exc
        if reason in {
            "plugin enable precondition failed", "plugin drain precondition failed",
            "plugin disable precondition failed",
        }:
            reason = "plugin_runtime_precondition_failed"
        raise PluginStateConflict(reason) from exc
    return item


def report_plugin_state(report_key: str) -> dict[str, Any] | None:
    if report_key not in {"vpn.audit", "vpn.accounts", "vpn.connections"}:
        return None
    if not plugin_installed("sli.remote-access"):
        return {"plugin_id": "sli.remote-access", "state": "not_installed", "read_only": True}
    try:
        item = next(item for item in list_plugin_states() if item["plugin_id"] == "sli.remote-access")
    except (Error, RuntimeError, StopIteration):
        # State observation must not make retained reports unreadable.
        return {"plugin_id": "sli.remote-access", "state": "unknown", "read_only": True}
    return {
        "plugin_id": item["plugin_id"],
        "state": "enabled" if item["enabled"] else "disabled",
        "read_only": not item["enabled"],
    }


def annotate_plugin_report(report_key: str, payload: dict[str, Any], *, legacy: bool = False) -> None:
    """Retain historical rows and distinguish stopped collection from an empty result."""
    plugin = report_plugin_state(report_key)
    if plugin is None:
        return
    payload["plugin"] = plugin
    if plugin["state"] == "disabled" and payload.get("state") == "empty" and not payload.get("items"):
        payload["state"] = "not_collected" if legacy else "unavailable"
        payload["reason"] = "not_collected"
        if isinstance(payload.get("coverage"), dict) and payload["coverage"].get("state") == "empty":
            payload["coverage"] = {**payload["coverage"], "state": payload["state"], "reason": "not_collected"}

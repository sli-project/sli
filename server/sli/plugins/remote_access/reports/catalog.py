"""Legacy catalogue metadata owned by sli.remote-access."""

from __future__ import annotations

from typing import Any, Mapping


def _vpn_connections_catalog_item(
    vpn_audit: Mapping[str, Any],
    *,
    capabilities: set[str],
) -> dict[str, Any]:
    missing = {str(item) for item in vpn_audit.get("missing_capabilities") or []}
    if "vpn.sessions.view" not in capabilities:
        missing.add("vpn.sessions.view")
    allowed = bool(vpn_audit.get("allowed")) and not missing
    item = dict(vpn_audit)
    item.update({
        "report_key": "vpn.connections",
        "version": 1,
        "name": "VPN — подключения и доступы",
        "purpose": (
            "Сотрудники, подтверждённые RADIUS Accounting сессии, "
            "текущие AD-доступы и durable NPS 6273."
        ),
        "dataset_key": "vpn.sessions",
        "dataset_version": 1,
        "target_path": "/report/vpn.connections",
        "allowed": allowed,
        "explanation": (
            "Использует существующее назначение vpn.audit; session-ветка "
            "дополнительно проверяется сервером по vpn.sessions.view и domain scope."
        ),
        "missing_capabilities": sorted(missing),
        "discoverable": True,
        "requestable": False,
        "access_state": (
            "available_until"
            if allowed and vpn_audit.get("access_valid_until")
            else "available" if allowed else "request_unavailable"
        ),
        "request": None,
        "resource_context_required": True,
        "allowed_actions": ["view"] if allowed else [],
        "pinned": False,
        "preference_supported": False,
        "preference_updated_at": None,
        "dashboard_metrics": [],
        "selected_optional_metric_keys": [],
        "focus_preference_configured": False,
    })
    return item



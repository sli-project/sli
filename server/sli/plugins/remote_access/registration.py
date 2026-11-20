"""VPN-owned adapters for the existing core registration seams."""
from __future__ import annotations

import importlib


def _deferred(module_name, attribute):
    def invoke(*args, **kwargs):
        return getattr(importlib.import_module(module_name), attribute)(*args, **kwargs)
    return invoke


def _reports():
    from server.sli.plugins.remote_access.reports.vpn_audit import REPORT as accounts
    from server.sli.plugins.remote_access.reports.vpn_connections import REPORT as connections

    return accounts, connections


def _configured():
    from server.source_packs.radius.collection_routes import RadiusCollectionRouteError, load_radius_collection_routes

    try:
        return load_radius_collection_routes()["accounting_ready"] is True
    except (RadiusCollectionRouteError, OSError, ValueError, TypeError, KeyError):
        return False


def _evidence_allowed(access, *, source_domain_id, action="view"):
    from server.sli.plugins.remote_access.reports.vpn_report_composition import vpn_report_composition_decision

    return vpn_report_composition_decision(
        access, source_domain_id=source_domain_id, action=action,
    ).session_evidence.allowed


def register(contribution):
    contribution.hooks.update({
        "health": _health,
        "default_detections": _deferred("server.sli.plugins.remote_access.native_detections", "run_once"),
        "configured": _configured,
        "nps_source": _nps_source,
        "nps_agent_policy": _deferred("sli_agent.nps", "policy"),
        "nps_agent_rows": _deferred("server.sli.agents.nps_ingest", "admitted_nps_rows"),
        "import_nps_agent_packet": _import_nps_agent_packet,
        "run_accounting_import_once": _deferred("server.sli.sources.nps_agent_import", "run_accounting_import_once"),
        "normalizer:windows-nps-radius-v1": _deferred("server.sli.plugins.remote_access.normalizers", "normalizer"),
        "source_configuration": source_configuration,
        "reports": _reports,
        "accounts_dataset": _deferred("server.sli.plugins.remote_access.reports.accounts_dataset", "read_accounts"),
        "accounts_summary": _deferred("server.sli.plugins.remote_access.reports.accounts_dataset", "_vpn_account_summary"),
        "connections_catalog": _deferred("server.sli.plugins.remote_access.reports.catalog", "_vpn_connections_catalog_item"),
        "source_data": _deferred("server.sli.plugins.remote_access.setup", "source_data"),
        "session_exists": _deferred("server.sli.plugins.remote_access.investigation", "_vpn_session_exists"),
        "revocation_sessions": _deferred("server.sli.plugins.remote_access.revocation", "_read_sessions"),
        "evidence_allowed": _evidence_allowed,
    })
    modules = {
        "server.sli.plugins.remote_access.reports.vpn_session_reporting": (
            "get_vpn_session_evidence", "get_vpn_session_report", "get_vpn_session_sources",
        ),
        "server.sli.plugins.remote_access.reports.vpn_connections_reporting": (
            "get_vpn_authorization_timeline", "get_vpn_failed_authorization_series",
        ),
        "server.sli.plugins.remote_access.reports.entity_vpn_reporting": ("get_entity_vpn_sessions",),
        "server.sli.sources.radius_vpn_operations": ("get_radius_vpn_operations",),
        "server.source_packs.radius.collection_routes": ("load_radius_collection_routes",),
        "server.source_packs.nps_eventlog_runtime": (
            "resolve_nps_eventlog_endpoint", "validate_continuous_nps_admission",
        ),
    }
    for module_name, names in modules.items():
        for name in names:
            contribution.hooks[name] = _deferred(module_name, name)
    for handler_id in ("radius-session-observation", "radius-acquisition"):
        contribution.jobs[handler_id] = (
            _deferred("server.sli.plugins.remote_access.jobs", "stage_radius"),
            _deferred("server.sli.plugins.remote_access.jobs", "apply_radius"),
        )


def _health():
    from server.sli.plugins.remote_access.jobs import stage_radius, apply_radius
    return callable(stage_radius) and callable(apply_radius) and len(_reports()) == 2


def _import_nps_agent_packet(*args, **kwargs):
    from server.sli.agents.import_authorization import PacketPending
    from server.sli.sources.nps_agent_import import agent_import_enabled, import_nps_agent_packet

    if not agent_import_enabled():
        raise PacketPending("agent_nps_import_disabled")
    return import_nps_agent_packet(*args, **kwargs)


def _nps_source():
    from server.source_packs.radius.collection_routes import load_radius_collection_routes
    from server.source_packs.nps_eventlog_runtime import resolve_nps_eventlog_endpoint

    route = load_radius_collection_routes()
    return resolve_nps_eventlog_endpoint(
        str(route.get("source_name") or ""), route_loader=lambda: route,
    )


def source_configuration():
    from server.sli.core import database
    from server.sli.core.setup_status import _safe
    from server.source_packs.radius.collection_routes import (
        load_radius_collection_routes,
    )

    route = _safe(load_radius_collection_routes)
    rows = _safe(lambda: database.query_rows(
        """
        select source_instance_id,
               bool_or(source_activation = 'manual_enabled'
                        and subscription_activation = 'manual_enabled') as enabled
        from radius_vpn_operations_v1
        group by source_instance_id order by source_instance_id
        """,
    ))
    if not rows and route is None:
        return None
    items = [{
        "source_instance_id": row["source_instance_id"],
        "configured": True, "enabled": bool(row["enabled"]),
    } for row in rows or []]
    if route and route.get("event_log_ready"):
        item = next((item for item in items if item["source_instance_id"].casefold() == route["source_instance_id"].casefold()), None)
        if item is None:
            item = {"source_instance_id": route["source_instance_id"], "configured": True, "enabled": None}
            items.append(item)
        item["collection_target"] = route["source_name"]
    return items

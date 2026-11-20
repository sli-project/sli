"""Reviewed AD entry point; no acquisition, DDL or background work."""
from __future__ import annotations

import importlib


def _deferred(module_name, attribute):
    def invoke(*args, **kwargs):
        return getattr(importlib.import_module(module_name), attribute)(*args, **kwargs)
    return invoke


def register(contribution):
    contribution.hooks["health"] = _health
    contribution.hooks["semantic_capabilities"] = _semantic_capabilities
    contribution.hooks.update({
        "reports": _reports,
        "import_snapshot_cycle": _deferred("server.sli.plugins.ad.snapshot_import", "import_ad_cycle"),
        "ad_agent_policy": _deferred("server.sli.plugins.ad.agent_policy", "build_ad_policy"),
        "ad_agent_rows": _deferred("server.sli.plugins.ad.agent_policy", "dc_event_rows"),
        "import_ad_agent_packet": _deferred("server.sli.plugins.ad.event_import", "import_ad_agent_packet"),
        "file_audit_principals": _deferred("server.sli.plugins.ad.file_audit_enrichment", "principals"),
        "run_agent_import_once": _deferred("server.sli.plugins.ad.event_import", "run_agent_import_once"),
        "normalizer:windows-ad-dc-v1": _normalizer,
        "schedule_jobs": _deferred("server.sli.plugins.ad.jobs", "schedule_ad"),
        "job_source": _deferred("server.sli.plugins.ad.jobs", "job_source"),
        "get_runtime_entity_context_evidence": _deferred(
            "server.sli.plugins.ad.context.integration", "get_runtime_entity_context_evidence",
        ),
    })
    modules = {
        "server.sli.plugins.ad.setup": ("list_targets", "add_target", "set_enabled", "import_from_file"),
        "server.sli.plugins.ad.targets": (
            "stored_enabled_targets", "get_configured_domain_controller_targets", "discover_domain_controllers",
            "configured_server_names", "configured_source_addresses",
        ),
        "server.sli.plugins.ad.onboarding": ("plan_dc_onboarding",),
        "server.sli.plugins.ad.setup_status": ("domain_controllers", "source_configuration", "source_data", "context_interval"),
        "server.sli.plugins.ad.api.setup": ("handle_controller_post",),
        "server.sli.plugins.ad.reports.ad_account_state_reporting": (
            "get_ad_account_change_history", "get_ad_account_change_sources",
            "account_change_observation", "apply_observed_account_history",
        ),
        "server.sli.plugins.ad.reports.ad_group_membership_reporting": ("get_ad_group_membership_history",),
        "server.sli.plugins.ad.reports.dc_powershell_reporting": ("get_dc_powershell_activity",),
        "server.sli.plugins.ad.api.reports": (
            "handle_dc_powershell_activity_api", "handle_ad_account_change_history_api",
            "handle_ad_account_change_sources_api", "handle_security_event_sources_api",
            "handle_security_events_api", "handle_security_events_export_api", "handle_ad_group_membership_history_api",
        ),
    }
    for module_name, names in modules.items():
        for name in names:
            contribution.hooks[name] = _deferred(module_name, name)
    contribution.hooks["security_event_arguments"] = _deferred(
        "server.sli.plugins.ad.api.reports", "_security_event_arguments",
    )
    for handler_id in ("ad-snapshot-manifest-coordinator", "ad-snapshot-projection",
                       "ad-context-snapshot", "computers-v6-source", "users-report-v2-snapshot"):
        contribution.jobs[handler_id] = (
            _deferred("server.sli.plugins.ad.jobs", "stage"),
            _deferred("server.sli.plugins.ad.jobs", "apply"),
        )


def _reports():
    return tuple(importlib.import_module(f"server.sli.plugins.ad.reports.definitions.{name}").REPORT
                 for name in ("ad_state", "users", "computers", "computer_logons", "new_logon_pairs"))


def _health():
    """Registration readiness only: no acquisition, DDL or background work."""
    return True


def _semantic_capabilities():
    return {"sli.ad.process-episode.v1": "1.0.0"}


def _normalizer():
    from server.sli.plugins.ad.windows_ad_dc import normalizer

    return normalizer

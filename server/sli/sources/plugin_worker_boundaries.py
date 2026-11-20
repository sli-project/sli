"""Fail-closed source contract for isolated bundled plugin worker cells."""
from __future__ import annotations

from typing import Any, Mapping


class PluginWorkerBoundaryError(ValueError):
    """Raised when the worker isolation contract becomes ambiguous or weaker."""


EXPECTED_CELLS = {
    "radius-acquisition": {
        "component_id": "radius-acquisition",
        "handler_id": "stage9-radius-manual-worker",
        "membership_role": "adlog_radius_accounting_worker",
        "network": {
            "radius_accounting_read_endpoint",
            "plugin_postgres_exact_endpoint",
        },
    },
    "radius-session-observation": {
        "component_id": "radius-session-observation",
        "handler_id": "stage9-radius-session-consumer-manual",
        "membership_role": "adlog_radius_session_consumer",
        "network": {"plugin_postgres_exact_endpoint"},
    },
}


def _require_false(value: Mapping[str, Any], key: str) -> None:
    if value.get(key) is not False:
        raise PluginWorkerBoundaryError(f"{key}_must_be_false")


def validate_plugin_worker_boundaries(value: Mapping[str, Any]) -> dict[str, Any]:
    expected_header = {
        "schema_version": 1,
        "contract_id": "sli.plugin-worker-boundaries.v1",
        "status": "prepared_source_contract_with_external_blockers",
        "architecture_decision_id": "sli.plugin-architecture.v2",
        "plugin_id": "sli.remote-access",
    }
    for key, expected in expected_header.items():
        if value.get(key) != expected:
            raise PluginWorkerBoundaryError(f"{key}_invalid")
    for key in (
        "runtime_enabled",
        "autostart_enabled",
        "source_contact_allowed",
        "production_configuration_changed",
    ):
        _require_false(value, key)

    isolation = value.get("isolation_model")
    if not isinstance(isolation, dict) or not isolation or not all(
        item is True for item in isolation.values()
    ):
        raise PluginWorkerBoundaryError("isolation_model_incomplete")

    cells = value.get("execution_cells")
    if not isinstance(cells, list) or len(cells) != len(EXPECTED_CELLS):
        raise PluginWorkerBoundaryError("exact_execution_cells_required")
    indexed: dict[str, Mapping[str, Any]] = {}
    for cell in cells:
        if not isinstance(cell, dict):
            raise PluginWorkerBoundaryError("execution_cell_object_required")
        cell_id = str(cell.get("cell_id") or "")
        if cell_id not in EXPECTED_CELLS or cell_id in indexed:
            raise PluginWorkerBoundaryError("execution_cell_id_invalid")
        indexed[cell_id] = cell

    summaries = []
    for cell_id, expected in EXPECTED_CELLS.items():
        cell = indexed[cell_id]
        if cell.get("component_id") != expected["component_id"]:
            raise PluginWorkerBoundaryError(f"{cell_id}_component_invalid")
        if cell.get("handler_id") != expected["handler_id"]:
            raise PluginWorkerBoundaryError(f"{cell_id}_handler_invalid")
        if cell.get("runtime_argv") != ["--internal"]:
            raise PluginWorkerBoundaryError(f"{cell_id}_runtime_argv_invalid")

        windows = cell.get("windows_boundary")
        other = (
            "radius-session-observation"
            if cell_id == "radius-acquisition"
            else "radius-acquisition"
        )
        if not isinstance(windows, dict) or not (
            windows.get("principal_kind") == "domain_gmsa"
            and windows.get("exact_principal") is None
            and windows.get("windows_service_name") is None
            and windows.get("service_sid") is None
            and windows.get("provisioning_state") == "unprovisioned"
            and windows.get("must_be_distinct_from") == other
        ):
            raise PluginWorkerBoundaryError(f"{cell_id}_windows_boundary_invalid")

        filesystem = cell.get("filesystem_boundary")
        if not isinstance(filesystem, dict) or not (
            filesystem.get("dedicated_working_directory") is None
            and filesystem.get("working_directory_acl_proven") is False
            and filesystem.get("project_tree_write_allowed") is False
            and filesystem.get("shared_plugin_working_directory_allowed") is False
        ):
            raise PluginWorkerBoundaryError(f"{cell_id}_filesystem_boundary_invalid")

        network = cell.get("network_boundary")
        capabilities = set(network.get("allowed_capabilities") or []) if isinstance(network, dict) else set()
        if not isinstance(network, dict) or not (
            network.get("default_deny") is True
            and capabilities == expected["network"]
            and network.get("administrative_share_allowed") is False
            and network.get("remote_registry_allowed") is False
            and network.get("firewall_rules_proven") is False
        ):
            raise PluginWorkerBoundaryError(f"{cell_id}_network_boundary_invalid")

        postgres = cell.get("postgres_boundary")
        if not isinstance(postgres, dict) or not (
            postgres.get("membership_role") == expected["membership_role"]
            and postgres.get("login_role") is None
            and postgres.get("credential_scope") == "plugin_postgres"
            and postgres.get("credential_materialization") == "SLI_PLUGIN_PG_DSN"
            and postgres.get("admin_environment_allowed") is False
            and postgres.get("runtime_login_proven") is False
        ):
            raise PluginWorkerBoundaryError(f"{cell_id}_postgres_boundary_invalid")

        process = cell.get("process_boundary")
        if not isinstance(process, dict) or not (
            process.get("job_object_required") is True
            and process.get("normal_resource_profile_id") is None
            and process.get("normal_resource_profile_proven") is False
        ):
            raise PluginWorkerBoundaryError(f"{cell_id}_process_boundary_invalid")
        summaries.append(
            {
                "cell_id": cell_id,
                "handler_id": expected["handler_id"],
                "network_capabilities": sorted(capabilities),
                "ready": False,
            }
        )

    acquisition = indexed["radius-acquisition"]
    source = acquisition.get("source_preconditions")
    network = acquisition["network_boundary"]
    if not isinstance(source, dict) or not (
        source.get("dedicated_read_only_share_configured") is True
        and source.get("static_timezone_descriptor_replaces_remote_registry") is True
        and source.get("timezone_drift_check_accepted") is False
        and source.get("timezone_owner_assumption_active") is True
        and network.get("source_endpoint") == "192.0.2.15"
        and network.get("source_transport") == "dedicated_read_only_smb_share"
    ):
        raise PluginWorkerBoundaryError("radius_source_preconditions_invalid")
    consumer = indexed["radius-session-observation"]["network_boundary"]
    if consumer.get("source_endpoint") is not None or consumer.get("source_transport") != "none":
        raise PluginWorkerBoundaryError("consumer_source_network_forbidden")

    prohibited = value.get("prohibited_environment_names")
    if prohibited != [
        "ADLOG_PG_DSN",
        "ADLOG_PG_ADMIN_USER",
        "ADLOG_PG_ADMIN_PASSWORD",
    ]:
        raise PluginWorkerBoundaryError("prohibited_environment_names_invalid")
    blockers = value.get("blockers")
    if not isinstance(blockers, list) or len(blockers) != 6 or len(set(blockers)) != 6:
        raise PluginWorkerBoundaryError("exact_blockers_required")
    return {
        "contract_id": expected_header["contract_id"],
        "plugin_id": expected_header["plugin_id"],
        "cell_count": len(summaries),
        "cells": summaries,
        "ready_for_live_runtime": False,
        "blockers": list(blockers),
    }

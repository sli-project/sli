"""Non-secret daily AD computer posture and versioned Microsoft lifecycle rules."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from server.sli.plugins.ad.reports.computers_reporting import (
    OS_SUPPORT_CATALOG_VERSION, evaluate_operating_system_support,
)

OS_SUPPORT_POLICY_VERSION = OS_SUPPORT_CATALOG_VERSION


def unsupported_os(os_name: Any, version: Any, evaluated: datetime | None) -> str | None:
    """Unknown editions remain unassessed; never apply client rules to servers."""
    name = str(os_name or "").casefold()
    if not evaluated or any(value in name for value in ("embedded", "iot", "ltsb")):
        return None
    end = evaluate_operating_system_support(os_name, version).get("support_end_date")
    return end if end and evaluated.date().isoformat() > end else None


def computer_posture(item: dict[str, Any], attrs: Mapping[str, Any], observed: datetime | None, parse) -> None:
    uac = attrs.get("user_account_control")
    if isinstance(uac, int) and uac & 8192:
        item["computer_type"] = "domain_controller"
    item["delegation"] = {
        "unconstrained": bool(uac & 524288) if isinstance(uac, int) else attrs.get("trusted_for_delegation"),
        "constrained": bool(attrs["allowed_to_delegate_to"]) if attrs.get("allowed_to_delegate_to") is not None else None,
        "resource_based": attrs.get("resource_based_delegation_present"),
    }
    item["trusted_for_delegation"] = item["delegation"]["unconstrained"]
    item["allowed_to_delegate_to"] = attrs.get("allowed_to_delegate_to")
    item["resource_based_delegation_present"] = attrs.get("resource_based_delegation_present")
    for key in ("resource_based_delegation_sids", "resource_based_delegation_status",
                "resource_based_delegation_descriptor_sha256", "password_last_set_status",
                "laps_password_expiration_status", "legacy_laps_password_expiration_status"):
        item[key] = attrs.get(key)
    modern = attrs.get("laps_password_expiration_utc")
    legacy = attrs.get("legacy_laps_password_expiration_utc")
    item["laps_password_expiration_utc"] = modern
    item["legacy_laps_password_expiration_utc"] = legacy
    # Modern LAPS metadata takes precedence when both generations are present.
    expiration = parse(modern) or parse(legacy)
    item["laps"] = {"state": "unknown" if not expiration else
                    "expired" if observed and expiration < observed else "metadata_present",
                    "expiration_utc": expiration.isoformat() if expiration else None,
                    "source_attribute": "msLAPS-PasswordExpirationTime" if parse(modern) else
                    "ms-Mcs-AdmPwdExpirationTime" if expiration else None}
    item["laps_state"] = item["laps"]["state"]
    item["constrained_delegation"] = item["delegation"]["constrained"]

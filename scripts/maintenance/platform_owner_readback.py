#!/usr/bin/env python3
"""Read-only PostgreSQL proof of the effective access for the exact SLI owner."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.access.access_control_v4 import effective_access  # noqa: E402
from server.sli.core.app_config import load_config  # noqa: E402


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value.strip():
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    return []


def readback() -> dict[str, Any]:
    import psycopg
    from psycopg.rows import dict_row

    with psycopg.connect(
        load_config().postgres_dsn,
        application_name="adlog_platform_owner_readback",
        row_factory=dict_row,
    ) as conn, conn.cursor() as cur:
        cur.execute("select id,username from auth_users where lower(username)=%s and is_active=true", ("platform-owner",))
        subject = cur.fetchone()
        if not subject:
            raise RuntimeError("active owner account platform-owner was not found")
        cur.execute("select package_key from access_packages order by package_key")
        expected_packages = [str(row["package_key"]) for row in cur.fetchall()]
        cur.execute("select capability_key from access_capabilities order by capability_key")
        expected_capabilities = [str(row["capability_key"]) for row in cur.fetchall()]
        cur.execute(
            """select distinct on (registry.report_key)
                      registry.report_key,registry.definition_json,dataset.actions_json
               from report_registry_v4 registry
               join report_datasets_v4 dataset on dataset.id=registry.dataset_id
               where registry.status='published'
               order by registry.report_key,registry.version desc"""
        )
        expected_report_actions: dict[str, list[str]] = {}
        for row in cur.fetchall():
            definition_actions = {str(item) for item in _object(row["definition_json"]).get("actions", [])}
            dataset_actions = {str(item) for item in _list(row["actions_json"])}
            expected_report_actions[str(row["report_key"])] = sorted(definition_actions & dataset_actions)

    access = effective_access(None, preview_user_id=int(subject["id"]))
    actual_packages = sorted(str(item["key"]) for item in access["packages"])
    actual_capabilities = sorted(str(item) for item in access["capabilities"])
    actual_reports = {str(item["report_key"]): item for item in access["reports"]}
    action_match = all(
        sorted(actual_reports.get(key, {}).get("allowed_actions", [])) == actions
        for key, actions in expected_report_actions.items()
    )
    checks = {
        "exact_subject": str(access["subject"]["username"]).lower() == "platform-owner",
        "platform_owner": access.get("platform_owner") is True,
        "full_product_access": access.get("owner_policy", {}).get("full_product_access") is True,
        "surveyed_system_write_disabled": access.get("owner_policy", {}).get("surveyed_system_write_access") is False,
        "all_packages": actual_packages == expected_packages,
        "all_capabilities": actual_capabilities == expected_capabilities,
        "all_published_reports": set(actual_reports) == set(expected_report_actions),
        "all_reports_allowed": all(bool(item.get("allowed")) for item in actual_reports.values()),
        "all_registered_report_actions": action_match,
        "no_effective_denies": not any(access.get("explicit_denies", {}).values()),
    }
    return {
        "status": "ok" if all(checks.values()) else "failed",
        "subject": access["subject"],
        "checks": checks,
        "counts": {
            "packages": len(actual_packages),
            "capabilities": len(actual_capabilities),
            "published_reports": len(actual_reports),
            "navigation_sections": len(access["navigation"]),
        },
        "report_actions": {key: actual_reports[key]["allowed_actions"] for key in sorted(actual_reports)},
        "ignored_denies": access.get("ignored_denies", {}),
    }


def main() -> int:
    try:
        result = readback()
    except Exception as exc:
        result = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

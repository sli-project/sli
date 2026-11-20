from __future__ import annotations

from typing import Any

from server.sli.core.app_config import AdLogConfig


def apply_retention(*, apply: bool = False, config: AdLogConfig | None = None) -> dict[str, Any]:
    """Compatibility entry point backed by the canonical storage policy."""
    from server.sli.storage.storage_policy import build_storage_cleanup_plan, load_storage_policy

    plan = build_storage_cleanup_plan(policy=load_storage_policy(config), deep=False)
    deleted: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if apply:
        # This legacy path only knows file age and cannot prove PostgreSQL
        # import, archive integrity, evidence holds or an independent copy.
        # Keep its planning compatibility for old health consumers, but make
        # mutation fail closed. The verified replacement is storage_cleanup.py.
        errors.append({
            "code": "legacy_retention_apply_disabled",
            "error": "Legacy retention apply is disabled; use the verified storage cleanup workflow.",
        })
        plan["status"] = "blocked"
    else:
        plan["status"] = "ok"
    plan["mode"] = "blocked" if apply else "dry_run"
    plan["apply_supported"] = False
    plan["legacy_planner_retired"] = True
    plan["replacement"] = "scripts/maintenance/storage_cleanup.py"
    plan["deleted"] = deleted
    plan["errors"] = errors
    return plan

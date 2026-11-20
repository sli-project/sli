"""Быстрая структурная проверка UI/навигации (in-process, без scripts.maintenance).

Используется diagnostics_report и CLI scripts/maintenance/ui_nav_check.py.
"""

from __future__ import annotations

import time
from typing import Any

from server.sli.ops.diagnostics_support import PROJECT_ROOT
from server.sli.reporting.reports import list_reports
from server.sli.access.role_views import ROLE_VIEW_META, ROLE_VIEW_ORDER
from server.sli.reporting.ui_navigation import get_ui_navigation_data
from server.sli.ops.version import get_release_metadata

REQUIRED_REPORTS = {
    "collector-health.html",
    "autocollection.html",
    "system-health.html",
    "db-status.html",
    "findings.html",
    "investigation.html",
    "role-overview.html",
    "ui-navigation.html",
    "security-events-monitor.html",
    "ai-redaction-preview.html",
    "ai-prompt-preview.html",
    "ai-reports.html",
}
REQUIRED_ROLES = {"security", "it", "technical"}


def run_ui_nav_check() -> dict[str, Any]:
    started = time.monotonic()
    reports = list_reports()
    report_names = {str(item.get("name")) for item in reports}
    report_urls = {str(item.get("url")) for item in reports}
    navigation = get_ui_navigation_data()
    role_ids = set(ROLE_VIEW_ORDER)
    missing_reports = sorted(REQUIRED_REPORTS - report_names)
    missing_roles = sorted(REQUIRED_ROLES - role_ids)
    role_meta_missing = [role for role in ROLE_VIEW_ORDER if role not in ROLE_VIEW_META]
    warnings: list[str] = []
    if missing_reports:
        warnings.append("Missing required dynamic reports: " + ", ".join(missing_reports))
    if missing_roles or role_meta_missing:
        warnings.append("Role view metadata is incomplete")
    nav_items = navigation.get("items") or []
    nav_roles = {role.get("id") for role in navigation.get("roles") or []}
    if not REQUIRED_ROLES.issubset(nav_roles):
        warnings.append("UI navigation role coverage is incomplete")
    allowed_dynamic_prefixes = ("/reports/search.html", "/reports/event-details.html", "/reports/entity-details.html", "/reports/account-timeline.html")
    broken_urls: list[str] = []
    for item in nav_items:
        url = str(item.get("url") or "")
        base_url = url.split("?", 1)[0]
        if url == "/" or url.startswith("/#") or base_url in report_urls or base_url.startswith(allowed_dynamic_prefixes):
            continue
        broken_urls.append(url)
    if broken_urls:
        warnings.append("UI navigation has unresolved routes: " + ", ".join(sorted(set(broken_urls))))
    return {
        "package_type": "UI_NAV_CHECK",
        "status": "warn" if warnings else "ok",
        "duration_ms": int((time.monotonic() - started) * 1000),
        "release_metadata": get_release_metadata(PROJECT_ROOT),
        "role_views": list(ROLE_VIEW_ORDER),
        "ui_navigation_items": len(navigation.get("items") or []),
        "reports": sorted(report_names),
        "required_reports": sorted(REQUIRED_REPORTS),
        "warnings": warnings,
    }

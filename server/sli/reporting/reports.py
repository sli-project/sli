from __future__ import annotations

from pathlib import Path

from server.sli.core.paths import REPORTS_DIR, ROOT
from server.sli.reporting.ui_navigation import NAV_ITEMS


def _is_visible_report(path: Path) -> bool:
    name = path.name
    return (
        name == "domain-security-overview.html"
        or name in {"collector-health.html", "autocollection.html", "system-health.html", "storage-health.html", "db-status.html", "diagnostics.html", "findings.html", "investigation.html", "role-overview.html", "ui-navigation.html", "security-events-monitor.html", "ai-redaction-preview.html", "ai-prompt-preview.html", "ai-reports.html", "ai-analysis.html", "ai-openai-analysis.html"}
        or name.endswith("-security-profile.html")
    )


def list_reports() -> list[dict]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    reports = []
    visible_paths = [path for path in REPORTS_DIR.glob("*.html") if _is_visible_report(path)]
    for path in sorted(visible_paths, key=lambda p: p.stat().st_mtime, reverse=True):
        metadata = _report_metadata(path.name)
        try:
            display_path = str(path.relative_to(ROOT))
        except ValueError:
            display_path = str(path)
        reports.append(
            {
                "name": path.name,
                "path": display_path,
                "size_bytes": path.stat().st_size,
                "updated_at": path.stat().st_mtime,
                "url": f"/reports/{path.name}",
                **metadata,
                **_navigation_metadata(path.name),
            }
        )
    dynamic_reports = [
        ("collector-health.html", "collector_health", "Состояние сбора"),
        ("autocollection.html", "autocollection", "Состояние автосбора"),
        ("system-health.html", "system_health", "Состояние системы"),
        ("storage-health.html", "storage_health", "Storage Health"),
        ("db-status.html", "db_status", "DB Backend Status"),
        ("diagnostics.html", "diagnostics", "Диагностика"),
        ("findings.html", "findings", "Findings"),
        ("investigation.html", "investigation", "Рабочее место расследования"),
        ("role-overview.html", "role_overview", "Ролевые представления ИБ/ИТ"),
        ("ui-navigation.html", "ui_navigation", "Карта навигации"),
        ("security-events-monitor.html", "security_events", "ИБ-мониторинг событий"),
        ("ai-redaction-preview.html", "ai_safety", "AI preview: безопасная подготовка"),
        ("ai-prompt-preview.html", "ai_prompt", "AI prompt: OpenAI API"),
        ("ai-reports.html", "ai_analysis", "AI-отчеты"),
    ]
    existing = {item["name"] for item in reports}
    for name, kind, title in reversed(dynamic_reports):
        if name not in existing:
            reports.insert(0, {
                "name": name,
                "path": f"dynamic:/reports/{name}",
                "size_bytes": None,
                "updated_at": None,
                "url": f"/reports/{name}",
                "kind": kind,
                "server": None,
                "title": title,
                "dynamic": True,
                **_navigation_metadata(name),
            })
    return reports


def resolve_report(name: str) -> Path | None:
    candidate = REPORTS_DIR / name
    try:
        candidate.resolve().relative_to(REPORTS_DIR.resolve())
    except ValueError:
        return None
    if candidate.is_file() and candidate.suffix.lower() == ".html" and _is_visible_report(candidate):
        return candidate
    return None


def _navigation_metadata(name: str) -> dict:
    url = f"/reports/{name}"
    matches = [item for item in NAV_ITEMS if str(item.get("url", "")).split("?", 1)[0] == url]
    if not matches:
        return {"roles": ["security", "it", "technical"], "focus_group": "shared", "navigation_priority": 1000}
    item = sorted(matches, key=lambda row: int(row.get("priority") or 1000))[0]
    return {
        "roles": list(item.get("roles") or ["security", "it", "technical"]),
        "focus_group": str(item.get("group") or "shared"),
        "navigation_priority": int(item.get("priority") or 1000),
        "description": str(item.get("description") or ""),
    }


def _report_metadata(name: str) -> dict:
    if name == "collector-health.html":
        return {"kind": "collector_health", "server": None, "title": "Состояние сбора"}
    if name == "autocollection.html":
        return {"kind": "autocollection", "server": None, "title": "Состояние автосбора"}
    if name == "system-health.html":
        return {"kind": "system_health", "server": None, "title": "Состояние системы"}
    if name == "storage-health.html":
        return {"kind": "storage_health", "server": None, "title": "Storage Health"}
    if name == "db-status.html":
        return {"kind": "db_status", "server": None, "title": "DB Backend Status"}
    if name == "diagnostics.html":
        return {"kind": "diagnostics", "server": None, "title": "Диагностика"}
    if name == "findings.html":
        return {"kind": "findings", "server": None, "title": "Findings"}
    if name == "investigation.html":
        return {"kind": "investigation", "server": None, "title": "Рабочее место расследования"}
    if name == "role-overview.html":
        return {"kind": "role_overview", "server": None, "title": "Ролевые представления ИБ/ИТ"}
    if name == "ui-navigation.html":
        return {"kind": "ui_navigation", "server": None, "title": "Карта навигации"}
    if name == "security-events-monitor.html":
        return {"kind": "security_events", "server": None, "title": "ИБ-мониторинг событий"}
    if name == "ai-redaction-preview.html":
        return {"kind": "ai_safety", "server": None, "title": "AI preview: безопасная подготовка"}
    if name == "ai-prompt-preview.html":
        return {"kind": "ai_prompt", "server": None, "title": "AI prompt: OpenAI API"}
    if name == "ai-reports.html":
        return {"kind": "ai_analysis", "server": None, "title": "AI-отчеты"}
    if name == "ai-analysis.html":
        return {"kind": "ai_analysis", "server": None, "title": "AI-отчет"}
    if name == "ai-openai-analysis.html":
        return {"kind": "ai_analysis", "server": None, "title": "AI-анализ OpenAI"}
    if name == "domain-security-overview.html":
        return {"kind": "domain_overview", "server": None, "title": "Обзор безопасности домена"}
    suffix = "-security-profile.html"
    if name.startswith("server-") and name.endswith(suffix):
        server = name[len("server-") : -len(suffix)]
        return {"kind": "server_security_profile", "server": server, "title": f"Профиль безопасности {server}"}
    return {"kind": "html_report", "server": None, "title": name}

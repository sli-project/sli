from __future__ import annotations

from server.sli.reporting.reports import list_reports
from server.sli.reporting.ui_navigation import get_ui_navigation_data, render_ui_navigation_report


def test_stage4_ui_navigation_catalog_has_all_roles_and_known_routes() -> None:
    data = get_ui_navigation_data()
    assert data["status"] == "ok"
    project_version = data["release_metadata"]["project_version"]
    assert project_version.startswith("2026.")
    assert any(marker in project_version for marker in ("stage4-", "db0", "pg-stable", "pg-product"))
    role_ids = {role["id"] for role in data["roles"]}
    assert role_ids == {"security", "it", "technical"}
    items = data["items"]
    assert any(item["url"] == "/reports/ui-navigation.html" for item in items)
    assert any(item["url"] == "/reports/autocollection.html" and "it" in item["roles"] for item in items)
    assert any(item["url"] == "/reports/storage-health.html" and item["roles"] == ["it"] for item in items)
    assert any(item["url"] == "/reports/db-status.html" and "technical" in item["roles"] for item in items)
    assert not any("db-migration" in item["url"] for item in items)
    for item in items:
        assert item["url"].startswith(("/", "#"))
        assert item["roles"]


def test_stage4_dynamic_reports_include_navigation_roles() -> None:
    reports = list_reports()
    by_name = {report["name"]: report for report in reports}
    assert "ui-navigation.html" in by_name
    assert by_name["ui-navigation.html"]["kind"] == "ui_navigation"
    assert set(by_name["ui-navigation.html"]["roles"]) == {"security", "it", "technical"}
    assert by_name["storage-health.html"]["roles"] == ["it"]
    assert "it" in by_name["autocollection.html"]["roles"]


def test_stage4_ui_navigation_report_renders_role_matrix() -> None:
    html = render_ui_navigation_report()
    assert "Карта навигации ИБ / ИТ / Технический" in html
    assert "/reports/ui-navigation.html" in html
    assert "/reports/autocollection.html" in html
    assert "ui_nav_check.py" in html


def test_stage4_ui_nav_check_validates_navigation_without_warnings() -> None:
    from scripts.maintenance.ui_nav_check import run_ui_nav_check

    result = run_ui_nav_check()
    assert result["status"] == "ok"
    assert result["ui_navigation_items"] >= 10
    assert "ui-navigation.html" in result["reports"]
    assert result["warnings"] == []

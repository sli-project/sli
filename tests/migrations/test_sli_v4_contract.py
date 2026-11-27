from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest



ROOT = Path(__file__).resolve().parents[2]


def test_stage6_dashboard_metric_migration_has_bounded_rollback() -> None:
    migration = (ROOT / "config/postgres_migrations/039_stage6_dashboard_metrics.sql").read_text(encoding="utf-8")
    rollback = (ROOT / "config/postgres_migrations/039_stage6_dashboard_metrics.rollback.sql").read_text(encoding="utf-8")

    assert "dashboard_metrics" in migration
    assert "security.open_problems" in migration
    assert "ad.vpn_disabled_accounts" in migration
    assert "insert into schema_migrations(version,name)" in migration
    assert "definition_json - 'dashboard_metrics'" in rollback
    assert "drop " not in rollback.lower()






def test_migration_035_contains_composite_access_and_registered_reports() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "035_sli_v4_access_reports_objects.sql").read_text(encoding="utf-8").lower()
    for table in (
        "access_packages", "access_group_members", "access_subject_packages",
        "access_capability_assignments", "access_report_assignments",
        "report_datasets_v4", "report_registry_v4", "access_audit_v4",
        "object_identity_links",
    ):
        assert f"create table if not exists {table}" in sql
    assert "reports.export" in sql
    assert "on conflict" in sql


def test_migration_036_registers_vpn_dataset_report_and_ad_auditor_access() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "036_ad_audit_vpn_gpo_source.sql").read_text(encoding="utf-8").lower()
    rollback = (ROOT / "config" / "postgres_migrations" / "036_ad_audit_vpn_gpo_source.rollback.sql").read_text(encoding="utf-8").lower()
    assert "'ad.accounts.vpn'" in sql
    assert "'vpn.audit'" in sql
    assert "package.package_key='ad_auditor'" in sql
    assert "array['identity_basic','technical','security','privilege','hr','contact']" in sql
    assert "insert into schema_migrations(version,name) values(36" in sql
    assert "delete from schema_migrations where version=36" in rollback


def test_migration_037_registers_exact_platform_owner_without_role_widening() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "037_platform_owner_access.sql").read_text(encoding="utf-8").lower()
    rollback = (ROOT / "config" / "postgres_migrations" / "037_platform_owner_access.rollback.sql").read_text(encoding="utf-8").lower()
    assert "create table if not exists access_platform_owners" in sql
    assert "lower(username)='platform-owner'" in sql
    assert "owner_key='primary'" in sql
    assert "insert into schema_migrations(version,name) values(37,'platform_owner_access')" in sql
    assert "access_role_packages" not in sql
    assert "delete from schema_migrations where version=37" in rollback


def test_stage6_access_request_migration_is_bounded_and_reversible() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "040_stage6_report_access_requests.sql").read_text(encoding="utf-8").lower()
    rollback = (ROOT / "config" / "postgres_migrations" / "040_stage6_report_access_requests.rollback.sql").read_text(encoding="utf-8").lower()
    assert "create table if not exists report_access_requests_v4" in sql
    assert "report_access_requests_v4_active_unique" in sql
    assert "requested_scope_json" in sql
    assert "request_profile_json" in sql
    assert "insert into schema_migrations(version,name)" in sql
    assert "drop table if exists report_access_requests_v4" in rollback
    assert "delete from schema_migrations" in rollback


def test_stage6_report_workspace_migration_registers_entity_links_and_gpo_sections() -> None:
    sql = (ROOT / "config" / "postgres_migrations" / "041_stage6_report_workspaces.sql").read_text(encoding="utf-8").lower()
    rollback = (ROOT / "config" / "postgres_migrations" / "041_stage6_report_workspaces.rollback.sql").read_text(encoding="utf-8").lower()
    assert sql.count('"key":"object_id"') == 4
    for field in (
        "application_state", "link_count", "scope", "purpose",
        "review_reason", "settings", "signals", "next_steps",
    ):
        assert f'"key":"{field}"' in sql
    assert "report.report_key in ('ad.state','ad.privileged','vpn.audit','ad.gpo.review')" in sql
    assert "values(41,'stage6_report_workspaces')" in sql
    assert "delete from schema_migrations" in rollback




@pytest.mark.legacy
def test_production_object_route_redirects_to_the_single_entity_card() -> None:
    source = (ROOT / "frontend" / "src" / "product-main.tsx").read_text(encoding="utf-8")
    assert "sli-parity" not in source
    assert "styles.css" not in source
    assert "product-parity.css" not in source
    assert "ObjectDetailV4ExactPage" not in source
    assert "ObjectDetailV4Page" not in source
    assert 'path: "/entities/$entityId", component: EntityCardPage' in source
    assert 'path: "/objects/$objectType/$objectId", beforeLoad' in source
    assert "objectRouteRedirect(params.objectId, location.search" in source


@pytest.mark.legacy
def test_prototype_object_identifiers_are_isolated_from_live_page_source() -> None:
    live_pages = "".join(
        (ROOT / "frontend" / "src" / "app" / name).read_text(encoding="utf-8")
        for name in ("reports-catalog.tsx", "report-viewer.tsx", "report-labels.ts")
    ).casefold()
    fixture_entry = (ROOT / "frontend" / "src" / "sli-v4" / "fixture-main.tsx").read_text(encoding="utf-8").casefold()

    for marker in ("ivanov", "vpnl2tp", "adm-kuznetsov", "svc-backup"):
        assert marker not in live_pages
        assert marker in fixture_entry
    objects_page = (ROOT / "frontend" / "src" / "app" / "objects.tsx").read_text(encoding="utf-8").casefold()
    for marker in ("ivanov", "vpnl2tp", "adm-kuznetsov", "svc-backup"):
        assert marker not in objects_page
    assert "__sli_v4_fixture_presentation__" not in live_pages
    assert "__sli_v4_fixture_presentation__" not in objects_page
    assert "__sli_v4_fixture_presentation__" in fixture_entry

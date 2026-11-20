"""Static migration contract; runtime execution belongs to the final gate."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/159_workstation_security.sql"
SQL = PATH.read_text(encoding="utf-8")
ROLLBACK = (ROOT / "config/postgres_migrations/159_workstation_security.rollback.sql").read_text(encoding="utf-8")


def test_migration_has_exact_prerequisite_and_reserved_number():
    assert "version=158 and name='ad_gpo_core_jobs'" in SQL
    assert "or exists(select 1 from public.schema_migrations where version>158)" in SQL
    assert "migration 159 requires exact migration 158 ad_gpo_core_jobs" in SQL
    assert "values(159,'workstation_security')" in SQL
    assert "where version=159" in SQL
    assert "migration 159 already recorded" in SQL
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.workstations.json").read_text(encoding="utf-8"))
    migration = manifest["data"]["migrations"][0]
    assert migration["version"] == 159
    assert migration["path"] == PATH.relative_to(ROOT).as_posix()
    assert migration["core_prerequisites"] == [158]
    assert migration["sha256"] == hashlib.sha256(PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_owned_schema_keeps_evidence_immutable_and_retention_rights_separate():
    assert "create schema sli_plugin_workstations authorization adlog_storage_owner" in SQL
    assert "nologin noinherit" in SQL
    assert "grant select,delete" in SQL and "to adlog_workstations_retention" in SQL
    assert "grant insert on sli_plugin_workstations.observations to adlog_user" in SQL
    assert "grant update" not in SQL.lower()
    assert "grant delete" not in SQL.lower()
    assert "grant adlog_workstations_retention" not in SQL
    assert "source_xml text not null" in SQL
    assert "where family in ('processes','usb')" in SQL
    assert "create table core_" not in SQL


def test_report_registry_has_categories_actions_and_no_automatic_grants():
    for family in ("logons", "processes", "usb", "protection"):
        assert f"'workstations.{family}'" in SQL
    assert '"field_categories"' in SQL and '"actions":["view"]' in SQL
    assert '"category":"security"' in SQL
    assert "insert into access_package" not in SQL
    assert "insert into access_report_assignments" not in SQL


def test_forward_and_rollback_share_the_renumbered_advisory_lock():
    lock = "pg_advisory_xact_lock(hashtext('sli_workstation_security_v159'))"
    assert lock in SQL and lock in ROLLBACK
    assert "sli_workstation_security_v158" not in SQL + ROLLBACK


def test_rollback_refuses_observations_and_report_grants():
    assert "version>159" in ROLLBACK
    assert "version=159 and name='workstation_security'" in ROLLBACK
    assert "rollback 159 prerequisites failed" in ROLLBACK
    assert "delete from public.schema_migrations where version=159 and name='workstation_security'" in ROLLBACK
    assert "158" not in ROLLBACK
    assert "exists(select 1 from sli_plugin_workstations.observations)" in ROLLBACK
    assert "public.access_report_assignments" in ROLLBACK
    assert "public.access_package_reports" in ROLLBACK
    assert "delete from sli_plugin_workstations.observations" not in ROLLBACK

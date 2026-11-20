"""WR03 registration is additive and never grants authority implicitly."""

import json
import re
from pathlib import Path

from server.sli.plugins.workstations.access import CAPABILITIES, REPORT_KEY

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/251_workstation_access.sql"
SQL = PATH.read_text("utf-8")


def test_workstation_access_registers_exact_capabilities_without_assignments():
    declaration = SQL.split("insert into public.access_capabilities", 1)[1].split(";", 1)[0]
    assert set(re.findall(r"\('([^']+)'", declaration)) == set(CAPABILITIES.values())
    for table in ("access_package_capabilities", "access_role_packages", "access_subject_packages",
                  "access_capability_assignments", "access_package_reports", "access_report_assignments"):
        assert table not in SQL
    assert "update " not in SQL.lower() and "delete " not in SQL.lower() and "alter " not in SQL.lower()


def test_workspace_read_registration_does_not_rewrite_legacy_grants_or_fields():
    assert f"select '{REPORT_KEY}',1" in SQL
    definition = json.loads(re.search(r"'({\"field_categories\".*?})'::jsonb", SQL).group(1))
    assert set(definition["field_categories"]) == {"identity_basic", "technical", "security", "privilege"}
    assert definition["actions"] == ["view"]
    assert "dataset_key='workstations.security' and version=1" in SQL
    assert "'workstations.logons'" not in SQL and "'workstations.protection'" not in SQL


def test_migration_is_atomic_with_explicit_current_main_predecessor():
    assert "version=249 and name='watch_registry'" in SQL
    assert "version>=251" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "values(251,'workstation_access')" in SQL

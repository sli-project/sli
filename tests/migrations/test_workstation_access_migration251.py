"""WR03 registration is additive and never grants authority implicitly."""

import json
import re
from pathlib import Path


PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/251_workstation_access.sql"
SQL = PATH.read_text("utf-8")


def test_migration_is_atomic_with_explicit_current_main_predecessor():
    assert "version=249 and name='watch_registry'" in SQL
    assert "version>=251" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "values(251,'workstation_access')" in SQL

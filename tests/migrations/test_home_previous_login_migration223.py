from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest



def test_migration_only_adds_nullable_baseline_and_records_version():
    sql = Path("config/postgres_migrations/223_home_previous_login.sql").read_text("utf-8")
    assert "alter table public.auth_users add column previous_login_at timestamptz;" in sql
    assert "version=222 and name='sigma_attack_coverage'" in sql
    assert "version>=223" in sql and "pg_advisory_xact_lock" in sql
    assert "values(223,'home_previous_login')" in sql
    assert "\nbegin;" in sql and sql.rstrip().endswith("commit;")
    assert "update auth_users" not in sql and "default" not in sql

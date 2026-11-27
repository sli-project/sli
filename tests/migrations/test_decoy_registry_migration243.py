"""D01 additive migration and isolated PostgreSQL ACL/interval contracts."""
from datetime import timedelta
import json
import os
from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/243_decoy_registry.sql"
SQL = PATH.read_text("utf-8")


def test_migration_is_additive_transactional_scoped_and_uses_main_predecessor():
    inventory = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    assert inventory.count((243, "decoy_registry")) == 1
    assert list(PATH.parent.glob("243_*.sql")) == [PATH]
    # D02 already shipped this prerequisite in main. Keep its applied SQL intact.
    assert "version=242 and name='gpo_plan_credentials'" in SQL and "where version>=243" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "grant update(active_to)" in SQL and "grant select,insert" in SQL
    assert "decoy_interval_immutable" in SQL and "decoy_active_identity" in SQL
    assert "decoys.manage" in SQL and "array['view','manage_decoy']" in SQL
    assert "insert into public.finding_evidence_source_bindings" not in SQL
    assert "update public.sli_agents" not in SQL and "grant delete" not in SQL
    assert "set search_path=pg_catalog,pg_temp" in SQL

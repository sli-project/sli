"""Host-only authority and exact predecessor/number contracts."""
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/179_installed_release.sql").read_text("utf-8")


def test_exact_predecessor_and_unique_forward_number():
    assert "version=178 and name='agent_onboarding'" in SQL
    assert "version>=179" in SQL
    assert "migration 179 requires exact migration 178 and unused version 179" in SQL
    assert "sli_installed_release_v179" in SQL
    assert "values(179,'installed_release')" in SQL
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [item.name for item in inventory if item.version == 178] == ["agent_onboarding"]
    assert [item.name for item in inventory if item.version == 179] == ["installed_release"]
    assert len({item.version for item in inventory}) == len(inventory)


def test_authority_is_host_only_without_enabling_or_rewriting_history():
    assert "add column sha256 text" in SQL
    assert "installation_key ~ '^[a-f0-9]{64}$'" in SQL
    assert "operation ~ '^[a-f0-9]{32}$'" in SQL
    assert "revoke all on public.installed_release_v1 from public,adlog_user" in SQL
    assert "owner to adlog_storage_owner" in SQL
    assert not re.search(r"update\s+public\.schema_migrations|update\s+.*plugin_installations|grant\s+.*to\s+(?:public|adlog_user)", SQL, re.I)

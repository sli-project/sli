from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]


def test_migration_38_defines_singleton_fail_closed_block() -> None:
    sql = (ROOT / "config/postgres_migrations/038_runtime_collection_blocks.sql").read_text(encoding="utf-8")

    assert "runtime_collection_blocks" in sql
    assert "singleton_id = 1" in sql
    assert "operator_recovery_required" not in sql  # runtime policy, not mutable seed data
    assert "observed_count" in sql
    assert "last_probe_result" in sql
    assert "values (38,'runtime_collection_blocks')" in sql
    assert "version=37 and name='platform_owner_access'" in sql
    assert "version=38 and name<>'runtime_collection_blocks'" in sql
    assert "on conflict(version) do nothing" in sql

    rollback = (ROOT / "config/postgres_migrations/038_runtime_collection_blocks.rollback.sql").read_text(encoding="utf-8")
    assert "rollback 038 refused" in rollback
    assert "exists(select 1 from runtime_collection_blocks)" in rollback

"""Actual migrated PostgreSQL archive control, audit and authorized scope.

Collected by the existing postgres CI job. Never uses a non-disposable DB.
"""
import os
from pathlib import Path

import pytest

from tests.postgres_integration_guard import assert_disposable_database


def test_archive_migration_is_discoverable_and_records_atomic_ledger():
    from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

    root = Path(__file__).resolve().parents[2] / "config" / "postgres_migrations"
    migration = next(item for item in forward_migration_inventory(root) if item.version == 277)
    assert migration.name == "domain_archive_selection"
    sql = migration.path.read_text(encoding="utf-8").lower()
    assert sql.count("insert into public.schema_migrations") == 1
    assert sql.index("begin;") < sql.index("alter table domains")
    assert sql.index("alter table domains") < sql.index("insert into public.schema_migrations") < sql.index("commit;")

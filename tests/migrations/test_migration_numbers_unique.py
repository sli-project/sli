"""Every forward PostgreSQL migration owns a distinct version number."""
from collections import Counter
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

MIGRATIONS = Path(__file__).resolve().parents[2] / "config/postgres_migrations"


def test_forward_migration_versions_are_unique():
    versions = Counter(row.version for row in forward_migration_inventory(MIGRATIONS))
    assert [version for version, count in versions.items() if count > 1] == []

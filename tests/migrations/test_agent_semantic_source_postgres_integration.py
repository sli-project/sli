import json
import os
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.postgres_integration_guard import assert_disposable_database

MIGRATION = Path(__file__).resolve().parents[2] / "config/postgres_migrations/190_agent_semantic_source.sql"


def test_migration_has_exact_predecessor_and_unique_version():
    inventory = forward_migration_inventory(MIGRATION.parent)
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((190, "agent_semantic_source"))
    assert pairs[position - 1:position + 1] == [
        (189, "agent_snapshot_publication_health"), (190, "agent_semantic_source"),
    ]
    assert max(version for version, _ in pairs[:position]) + 1 == 190
    assert len(pairs) == len({version for version, _ in pairs})
    assert inventory[position].path == MIGRATION
    assert list(MIGRATION.parent.glob("190_*.sql")) == [MIGRATION]
    sql = MIGRATION.read_text("utf-8")
    assert "version=189 and name='agent_snapshot_publication_health'" in sql
    assert "version>=190" in sql
    assert "values(190,'agent_semantic_source')" in sql


def test_file_source_upgrade_follows_200_without_rewriting_190():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(MIGRATION.parent)]
    index = pairs.index((201, 'file_audit_semantic_source'))
    assert pairs[index - 1] == (200, 'agent_gpo_change_history')


def test_timestamp_precision_upgrade_has_exact_predecessor_and_unique_version():
    inventory = forward_migration_inventory(MIGRATION.parent)
    pairs = [(item.version, item.name) for item in inventory]
    index = pairs.index((203, 'agent_semantic_timestamp_precision'))
    assert pairs[index - 1] == (202, 'agent_gpo_history_expiry_fence')
    assert len(pairs) == len({version for version, _ in pairs})

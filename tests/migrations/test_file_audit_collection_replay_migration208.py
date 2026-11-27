"""Immutable replay uses an admitted count-only read on disposable PostgreSQL."""
from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.historical_postgres import historical_connection
from tests.migrations.test_file_audit_catalog_revision_migration206 import store_historical_file_packet

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/208_file_audit_collection_replay.sql"


def test_replay_migration_is_next_unique_version():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    position = pairs.index((208, "file_audit_collection_replay"))
    assert pairs[position - 1] == (207, "agent_packet_projection_recovery")
    assert len(pairs) == len({version for version, _ in pairs})

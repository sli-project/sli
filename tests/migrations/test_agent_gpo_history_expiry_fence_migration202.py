import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.test_agent_gpo_change_history_migration200 import gpo_database as gpo_database
from tests.migrations.test_ad_snapshot_history_composition_migration195 import history_database as history_database

PATH = Path(__file__).resolve().parents[2] / 'config/postgres_migrations/202_agent_gpo_history_expiry_fence.sql'


def test_expiry_fence_follows_exact_201():
    pairs = [(x.version,x.name) for x in forward_migration_inventory(PATH.parent)]
    n = pairs.index((202,'agent_gpo_history_expiry_fence'))
    assert pairs[n-1] == (201,'file_audit_semantic_source')

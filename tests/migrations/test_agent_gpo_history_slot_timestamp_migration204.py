import os
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.test_ad_snapshot_history_composition_migration195 import (
    history_database as history_database,  # noqa: PLC0414 -- register shared pytest fixture
)
from tests.migrations.test_agent_gpo_change_history_migration200 import (
    gpo_database as gpo_database,  # noqa: PLC0414 -- register shared pytest fixture
)

PATH = Path(__file__).resolve().parents[2] / 'config/postgres_migrations/204_agent_gpo_history_slot_timestamp.sql'
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)


def test_slot_repair_follows_exact_203():
    pairs = [(x.version, x.name) for x in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((204, 'agent_gpo_history_slot_timestamp')) - 1] == (
        203, 'agent_semantic_timestamp_precision')


@pytest.fixture
def text_slot_database(gpo_database):
    # Match migration 170 and the installed DB, not the old test's timestamptz.
    gpo_database.execute('alter table sli_agent_snapshot_cycles alter column slot_start_utc type text')
    return gpo_database


def runtime_connection():
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    return psycopg.connect(make_conninfo(os.environ['ADLOG_TEST_PG_DSN'], user='adlog_user'), row_factory=dict_row)

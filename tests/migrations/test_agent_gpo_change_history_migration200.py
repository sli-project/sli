import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.test_ad_snapshot_history_composition_migration195 import (
    history_database as history_database,  # noqa: PLC0414 -- register shared pytest fixture
)

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config/postgres_migrations/200_agent_gpo_change_history.sql'


def test_forward_inventory_follows_exact_199():
    items = [(x.version, x.name) for x in forward_migration_inventory(PATH.parent)]
    n = items.index((200, 'agent_gpo_change_history'))
    assert items[n - 1] == (199, 'bundled_plugin_defaults')


@pytest.fixture
def gpo_database(history_database):
    c = history_database
    c.execute("""alter table public.gpo_report_v2_source_snapshots
        add column payload_sha256 bytea,add column import_status text default 'completed',add column payload_json jsonb;
        create table public.sli_agent_snapshot_cycles(cycle_id uuid primary key,agent_id uuid,module_id text,
            slot_start_utc timestamptz,policy jsonb,publication_state text,gpo_source_run_id uuid,domain_sid text default 'synthetic');
        create table public.domains(id bigint primary key,domain_sid text,fqdn text);
        insert into public.domains values(1,'synthetic','synthetic.invalid'),(2,'other','other.invalid');
        grant select on public.sli_agent_snapshot_cycles,public.gpo_report_v2_source_snapshots,public.domains to adlog_user;
        insert into public.schema_migrations values(199,'bundled_plugin_defaults');""")
    c.execute(PATH.read_text('utf-8'))
    return c

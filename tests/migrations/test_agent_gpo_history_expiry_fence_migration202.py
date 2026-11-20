import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.storage import ad_snapshot_change_history as history
from tests.migrations.test_agent_gpo_change_history_migration200 import gpo_database as gpo_database
from tests.migrations.test_ad_snapshot_history_composition_migration195 import history_database as history_database

PATH = Path(__file__).resolve().parents[2] / 'config/postgres_migrations/202_agent_gpo_history_expiry_fence.sql'


def test_expiry_fence_follows_exact_201():
    pairs = [(x.version,x.name) for x in forward_migration_inventory(PATH.parent)]
    n = pairs.index((202,'agent_gpo_history_expiry_fence'))
    assert pairs[n-1] == (201,'file_audit_semantic_source')


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_expiry_waits_for_source_and_published_successor_receipts(gpo_database, monkeypatch):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
    c=gpo_database
    c.execute("insert into schema_migrations values(201,'file_audit_semantic_source')")
    c.execute(PATH.read_text('utf-8'))
    c.execute('grant delete on gpo_report_v2_source_snapshots to adlog_user')
    now=datetime(2026,10,11,tzinfo=timezone.utc)
    agent=str(uuid4()); sources=[]; cycles=[]
    payload={'collection_status':'complete','gpos':[],'links':[]}
    digest=history.canonical_output_sha256(payload)
    policy={'domain_sid':'synthetic','domain_dns':'synthetic.invalid','source_instance_id':'synthetic','scope':'domain'}
    for n in range(2):
        source,cycle=str(uuid4()),str(uuid4());sources.append(source);cycles.append(cycle)
        c.execute("insert into gpo_report_v2_source_snapshots values(%s,1,%s,%s,'completed',%s)",
                  (source,now+timedelta(hours=n),bytes.fromhex(digest),Jsonb(payload)))
        c.execute("insert into sli_agent_snapshot_cycles values(%s,%s,'sli.gpo-snapshot',%s,%s,'published',%s)",
                  (cycle,agent,now+timedelta(hours=n),Jsonb(policy),source))
    # Same run UUID in another domain is independent from this agent's receipts.
    c.execute("insert into gpo_report_v2_source_snapshots values(%s,2,%s,%s,'completed',%s)",
              (sources[0],now,bytes.fromhex(digest),Jsonb(payload)))
    monkeypatch.setattr(history,'publish_batch',lambda *a:None)
    dsn=make_conninfo(os.environ['ADLOG_TEST_PG_DSN'],user='adlog_user')
    with psycopg.connect(dsn,row_factory=dict_row) as runtime:
        for source in sources:
            with pytest.raises(psycopg.Error,match='requires confirmed'):
                with runtime.transaction():runtime.execute('delete from gpo_report_v2_source_snapshots where domain_id=1 and source_run_id=%s',(source,))
        runtime.execute('delete from gpo_report_v2_source_snapshots where domain_id=2')
        history.publish_agent_gpo_cycle(runtime,8123,cycles[0])
        with pytest.raises(psycopg.Error,match='requires confirmed'):
            with runtime.transaction():runtime.execute('delete from gpo_report_v2_source_snapshots where source_run_id=%s',(sources[0],))
        history.publish_agent_gpo_cycle(runtime,8123,cycles[1])
        runtime.execute('delete from gpo_report_v2_source_snapshots')
        runtime.commit()
    assert c.execute('select count(*) as n from gpo_report_v2_source_snapshots').fetchone()['n']==0
    assert c.execute('select count(*) as n from ad_snapshot_history_confirmations').fetchone()['n']==2
    with pytest.raises(psycopg.Error,match='cannot be truncated'):c.execute('truncate gpo_report_v2_source_snapshots')

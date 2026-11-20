"""T004 diagnostic only: compact synthetic receipt plans, never a stand SLA."""
from __future__ import annotations

import json
import os
import time

import pytest

from server.sli.sources.plugin_receipts import PLUGIN_MODULES, _RECEIPTS_SQL
from server.sli.core.database import _pg_sql
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
MODULES = sorted({module for values in PLUGIN_MODULES.values() for module in values})

# Historical runtime oracle from ca76525a, retained for exact parity and manual
# measurement. Candidate is the actual runtime SQL, byte-identical to the
# successfully measured prefix/fallback query from head28cb4b2c.
BASELINE_SQL = """
select module_id,max(last_received_at) as last_received_at,
       max(last_imported_at) as last_imported_at,
       max(last_snapshot_completed_at) as last_snapshot_completed_at
from (
    select r.module_id,max(r.received_at) as last_received_at,
           max(i.imported_at) filter(where r.module_id not in ('sli.ad-snapshot','sli.gpo-snapshot')) as last_imported_at,
           null::timestamptz as last_snapshot_completed_at
    from sli_agent_receipts r left join sli_agent_packet_inbox i using(packet_id)
    where r.module_id=any(%s)
    group by r.module_id
    union all
    select module_id,null::timestamptz,
           max(published_at) filter(where publication_state='published'),
           max(completed_at) filter(where transport_state='complete')
    from sli_agent_snapshot_cycles where module_id=any(%s)
    group by module_id
) facts group by module_id
"""
SPLIT_CANDIDATE = _pg_sql(_RECEIPTS_SQL)

@pytest.fixture
def database():
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('Disposable PostgreSQL required')
    # The suite's autouse fixture replaces the DSN with an empty per-test clone.
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("set statement_timeout='60s'")
        conn.execute("set lock_timeout='5s'")
        conn.execute("set work_mem='4MB'")
        conn.execute("set time zone 'UTC'")
        # Queried types and relevant 157/237 indexes, but no JSON payloads: this
        # intentionally does NOT model the reported 1.7 GB table/TOAST/cache.
        conn.execute('''create temporary table sli_agent_receipts(
            agent_id uuid not null,module_id text not null,sequence bigint not null,
            packet_id uuid not null unique,received_at timestamptz not null,
            primary key(agent_id,module_id,sequence));
            create temporary table sli_agent_packet_inbox(
                packet_id uuid primary key,received_at timestamptz not null,
                imported_at timestamptz,collection_revision text,
                collection_channel text,collection_read_error boolean);
            create temporary table sli_agent_snapshot_cycles(
                module_id text not null,transport_state text not null,
                completed_at timestamptz,publication_state text not null,published_at timestamptz);
            create index receipt_existing on sli_agent_receipts(agent_id,received_at desc)
                include(packet_id,module_id,sequence);
            create index inbox_existing on sli_agent_packet_inbox(packet_id)
                include(collection_revision,collection_channel,collection_read_error,imported_at);
            create index inbox_pending on sli_agent_packet_inbox(received_at,packet_id)
                where imported_at is null;''')
        yield conn


def _rows(conn, query, modules):
    return sorted(conn.execute(query, (modules, modules)).fetchall(), key=lambda row: row['module_id'])


def test_split_candidate_preserves_exact_receipt_import_snapshot_facts(database):
    # Duplicate timestamps, old late import, pending newest packet, absent inbox,
    # snapshots whose chunks imported but cycle is unpublished, and cycle-only
    # modules must preserve all three independent timestamps and absent rows.
    database.execute('''insert into sli_agent_receipts values
      ('00000000-0000-4000-8000-000000000001','sli.windows.ad-dc',1,md5('old')::uuid,'2026-01-01'),
      ('00000000-0000-4000-8000-000000000001','sli.windows.ad-dc',2,md5('new')::uuid,'2026-01-03'),
      ('00000000-0000-4000-8000-000000000002','sli.windows.ad-dc',1,md5('tie')::uuid,'2026-01-03'),
      ('00000000-0000-4000-8000-000000000001','sli.ad-snapshot',1,md5('chunk')::uuid,'2026-01-05'),
      ('00000000-0000-4000-8000-000000000001','sli.file-audit',1,md5('orphan')::uuid,'2026-01-06');
      insert into sli_agent_packet_inbox(packet_id,received_at,imported_at) values
        (md5('old')::uuid,'2026-01-01','2026-02-01'),
        (md5('new')::uuid,'2026-01-03',null),
        (md5('tie')::uuid,'2026-01-03','2026-01-04'),
        (md5('chunk')::uuid,'2026-01-05','2026-03-01');
      insert into sli_agent_snapshot_cycles values
        ('sli.ad-snapshot','complete','2026-01-05','pending',null),
        ('sli.ad-snapshot','complete','2026-01-04','published','2026-01-07'),
        ('sli.gpo-snapshot','complete','2026-01-06','superseded',null),
        ('sli.gpo-snapshot','pending',null,'pending',null);''')
    for scope in ([], MODULES, ['sli.windows.ad-dc'], ['sli.ad-snapshot'],
                  ['sli.gpo-snapshot'], ['sli.workstations'],
                  ['sli.windows.ad-dc', 'sli.windows.ad-dc', 'unknown']):
        assert _rows(database, SPLIT_CANDIDATE, scope) == _rows(database, BASELINE_SQL, scope)
    facts = {row['module_id']: row for row in _rows(database, SPLIT_CANDIDATE, MODULES)}
    assert facts['sli.windows.ad-dc']['last_imported_at'].isoformat().startswith('2026-02-01')
    assert facts['sli.ad-snapshot']['last_imported_at'].isoformat().startswith('2026-01-07')
    assert facts['sli.gpo-snapshot']['last_imported_at'] is None
    assert facts['sli.file-audit']['last_imported_at'] is None
    assert 'sli.workstations' not in facts


    # 1100 newer unrequested packets consume the entire fixed 1024 prefix.
    # Requested imports outside it must still be recovered by full fallback.
    database.execute('''insert into sli_agent_receipts
        select '00000000-0000-4000-8000-000000000003'::uuid,'unrequested',n,
          md5('unrequested-'||n)::uuid,'2026-01-01'::timestamptz
        from generate_series(1,1100) n;
      insert into sli_agent_packet_inbox(packet_id,received_at,imported_at)
        select packet_id,received_at,'2032-01-01'::timestamptz
        from sli_agent_receipts where module_id='unrequested';
      insert into sli_agent_receipts values
        ('00000000-0000-4000-8000-000000000004','sli.workstations',1,md5('pending')::uuid,'2026-01-01');
      insert into sli_agent_packet_inbox(packet_id,received_at,imported_at)
        values(md5('pending')::uuid,'2026-01-01',null);''')
    for scope in (MODULES, ['sli.workstations'], ['sli.windows.ad-dc'], ['absent'], []):
        assert _rows(database, SPLIT_CANDIDATE, scope) == _rows(database, BASELINE_SQL, scope)

    # Ties extend across the prefix boundary: MAX must not depend on packet ID.
    database.execute("update sli_agent_packet_inbox set imported_at='2032-01-01' where packet_id=md5('old')::uuid")
    assert _rows(database, SPLIT_CANDIDATE, MODULES) == _rows(database, BASELINE_SQL, MODULES)
    # A previously old receipt becomes the newest successful import.
    database.execute("update sli_agent_packet_inbox set imported_at='2033-01-01' where packet_id=md5('old')::uuid")
    assert _rows(database, SPLIT_CANDIDATE, MODULES) == _rows(database, BASELINE_SQL, MODULES)
    # Adversarial legacy/orphan fixture (production FK normally forbids this):
    # global prefix may be consumed without a corresponding receipt join.
    database.execute("delete from sli_agent_receipts where module_id='unrequested'")
    database.execute("""update sli_agent_packet_inbox i set imported_at='2034-01-01'
        where not exists(select 1 from sli_agent_receipts r where r.packet_id=i.packet_id)""")
    for scope in (MODULES, ['sli.workstations'], ['sli.gpo-snapshot'], ['absent']):
        assert _rows(database, SPLIT_CANDIDATE, scope) == _rows(database, BASELINE_SQL, scope)


def _nodes(node):
    fields = ('Node Type', 'Relation Name', 'Alias', 'Subplan Name', 'Parent Relationship',
              'One-Time Filter', 'Index Name', 'Actual Rows', 'Actual Loops',
              'Rows Removed by Filter', 'Heap Fetches', 'Shared Hit Blocks', 'Shared Read Blocks',
              'Local Hit Blocks', 'Local Read Blocks', 'Temp Read Blocks', 'Temp Written Blocks',
              'Sort Method', 'Sort Space Used', 'Sort Space Type', 'Peak Memory Usage', 'HashAgg Batches')
    return [{key: node[key] for key in fields if key in node}] + [
        value for child in node.get('Plans', []) for value in _nodes(child)]


def _measure(conn, query, modules):
    started = time.perf_counter()
    rows = _rows(conn, query, modules)
    wall_ms = (time.perf_counter() - started) * 1000
    plan = conn.execute('explain (analyze,buffers,format json) ' + query,
                        (modules, modules)).fetchone()['QUERY PLAN'][0]
    return rows, dict(wall_ms=wall_ms, planning_ms=plan['Planning Time'],
                      execution_ms=plan['Execution Time'], nodes=_nodes(plan['Plan']))


def test_volume_plans_compare_runtime_and_exact_prefix_fallback(database):
    count = 750_000
    database.execute('''insert into sli_agent_receipts
        select ('00000000-0000-4000-8000-'||lpad((n %% 16+1)::text,12,'0'))::uuid,
          case when n %% 20 < 12 then 'sli.windows.ad-dc'
               else (array['sli.file-audit','sli.workstations','sli.vpn-nps','sli.radius-accounting',
                           'sli.windows.ad-dc-history','sli.ad-snapshot','sli.gpo-snapshot','unknown'])[(n %% 20-11)::int] end,
          n,md5(n::text)::uuid,'2026-01-01'::timestamptz+(n/2)*interval '1 second'
        from generate_series(1,%s) n''', (count,))
    database.execute('''insert into sli_agent_packet_inbox
        select packet_id,received_at,
          case when sequence % 5=0 then null
               when sequence % 101=0 then '2027-01-01'::timestamptz
               else received_at+interval '1 second' end,
          '1','Security',false from sli_agent_receipts;
        insert into sli_agent_snapshot_cycles
        select module,'complete','2026-01-01'::timestamptz+n*interval '1 hour',
          case when n % 3=0 then 'published' else 'pending' end,
          case when n % 3=0 then '2026-01-01'::timestamptz+n*interval '2 hours' end
        from unnest(array['sli.ad-snapshot','sli.gpo-snapshot']) module cross join generate_series(1,250) n;''')
    for table in ('sli_agent_receipts', 'sli_agent_packet_inbox', 'sli_agent_snapshot_cycles'):
        database.execute(f'vacuum (analyze) {table}')
    assert database.execute('select count(*) as n from sli_agent_receipts').fetchone()['n'] == count
    scopes = {'all': MODULES, 'single_sparse': ['sli.file-audit'],
              'single_dominant': ['sli.windows.ad-dc'], 'absent': ['not-present']}
    expected = {}
    measurements = {}
    for name, modules in scopes.items():
        expected[name], measurements[name] = _measure(database, BASELINE_SQL, modules)
    print('T004 synthetic receipt experiment: ' + json.dumps(dict(
        stage='existing_indexes', rows=count, scopes=measurements,
        scope='compact synthetic tables, warmed measurements; not 1.7GB stand, cold-cache or SLA'), sort_keys=True))
    builds = {}
    for name, ddl in (
        ('receipt_candidate', 'create index receipt_candidate on sli_agent_receipts(module_id,received_at desc) include(packet_id)'),
        ('inbox_import_candidate', 'create index inbox_import_candidate on sli_agent_packet_inbox(imported_at desc,packet_id) where imported_at is not null'),
    ):
        started = time.perf_counter()
        database.execute(ddl)
        builds[name] = dict(
            wall_ms=(time.perf_counter()-started)*1000,
            bytes=database.execute("select pg_relation_size(%s) as bytes", (name,)).fetchone()['bytes'])
    print('T004 prefix indexes: ' + json.dumps(builds, sort_keys=True))

    def compare(stage, selected):
        # Re-analyze after fixture-only mutations; never run against real data.
        for table in ('sli_agent_receipts', 'sli_agent_packet_inbox'):
            database.execute(f'vacuum (analyze) {table}')
        result = {}
        for name, modules in selected.items():
            original, original_plan = _measure(database, BASELINE_SQL, modules)
            candidate, candidate_plan = _measure(database, SPLIT_CANDIDATE, modules)
            assert original == candidate
            ctes = SPLIT_CANDIDATE.split("SELECT module_id,max(last_received_at)", 1)[0]
            counts = database.execute(ctes + """SELECT
                (select count(*) from import_prefix) AS prefix_rows,
                (select count(*) from prefix_imports) AS matched_modules,
                (select count(*) from missing_imports) AS fallback_modules""",
                (modules,)).fetchone()
            if stage == 'all_modules_inside_prefix':
                assert counts['fallback_modules'] == 0
            result[name] = dict(runtime=original_plan, prefix=candidate_plan, scope_counts=counts)
        print('T004 prefix experiment: ' + json.dumps(dict(
            stage=stage, rows=count, scopes=result,
            scope='compact warmed synthetic; full fallback; not 1.7GB stand or SLA'), sort_keys=True))
        return result

    # Ensure the favorable case really contains each requested non-snapshot
    # module in the newest prefix; do not infer this from random distribution.
    database.execute('''update sli_agent_packet_inbox set imported_at='2029-01-01'
      where packet_id in (
        select distinct on(module_id) packet_id from sli_agent_receipts
        where module_id=any(%s) and module_id not in ('sli.ad-snapshot','sli.gpo-snapshot')
        order by module_id,sequence)''', (MODULES,))
    compare('all_modules_inside_prefix', scopes)

    database.execute('''update sli_agent_packet_inbox i set imported_at=null
        from sli_agent_receipts r where i.packet_id=r.packet_id and r.module_id='sli.workstations'
        ''')
    compare('pending_only', {'all': MODULES, 'pending': ['sli.workstations']})

    database.execute('''update sli_agent_packet_inbox i set imported_at=null
        from sli_agent_receipts r where i.packet_id=r.packet_id and r.module_id='sli.file-audit';
      update sli_agent_packet_inbox set imported_at='2025-01-01'
        where packet_id=(select packet_id from sli_agent_receipts
                         where module_id='sli.file-audit' order by sequence limit 1)''')
    compare('sole_rare_import_outside_prefix', {'all': MODULES, 'rare': ['sli.file-audit']})

    database.execute('''update sli_agent_packet_inbox set imported_at='2030-01-01'
        where packet_id=(select packet_id from sli_agent_receipts
                         where module_id='sli.file-audit' order by sequence limit 1)''')
    compare('old_receipt_late_import', {'all': MODULES, 'rare': ['sli.file-audit']})

    database.execute('''update sli_agent_packet_inbox i set imported_at='2031-01-01'
        from sli_agent_receipts r where i.packet_id=r.packet_id and r.module_id='unknown'
        ''')
    compare('unrequested_module_dominates_prefix', {'all': MODULES, 'absent': ['absent']})

    database.execute('''insert into sli_agent_packet_inbox(packet_id,received_at,imported_at)
        select md5('orphan-'||n)::uuid,'2026-01-01'::timestamptz,'2032-01-01'::timestamptz
        from generate_series(1,1100) n''')
    compare('orphans_consume_prefix', {'all': MODULES, 'rare': ['sli.file-audit']})

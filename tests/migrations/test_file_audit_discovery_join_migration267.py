"""Full-history file discovery join on real relevant PostgreSQL fixtures."""
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import monotonic, sleep
from uuid import uuid4

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg

from tests.migrations.test_file_audit_source_lookup_index_migration266 import AGENT, MODULE, OTHER_AGENT, authority_state, defaults_pg as defaults_pg, lookup_pg as lookup_pg, enumerate_sources, function_state, migration_source, observe, plan_nodes, pg as pg, receipt

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'config/postgres_migrations/267_file_audit_discovery_join.sql'
HELPER = 'public.file_audit_discovery_witness_v267'


@pytest.fixture
def join_pg(lookup_pg):
    import psycopg

    with psycopg.connect(lookup_pg, autocommit=True) as conn:
        conn.execute((ROOT / 'config/postgres_migrations/266_file_audit_source_lookup_index.sql').read_text('utf-8'))
    return lookup_pg


def apply_if_present(conn):
    # Meaningful pre-implementation RED reaches the absent native helper.
    if MIGRATION.exists():
        conn.execute(MIGRATION.read_text('utf-8'))


def witness(conn, agent=AGENT, root='selected-root', revision=2):
    conn.execute('set role adlog_storage_owner')
    try:
        return conn.execute(f'select * from {HELPER}(%s::uuid,%s::text,%s::bigint)',
                            (agent, root, revision)).fetchall()
    finally:
        conn.execute('reset role')


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_witness_beyond_two_fully_filtered_raw_pages(join_pg):
    import psycopg

    with psycopg.connect(join_pg, autocommit=True) as conn:
        conn.execute("insert into sli_agents values(%s,'active','[]')", (AGENT,))
        observe(conn, 1)
        receipt(conn, 1)
        for n in range(2, 386):
            receipt(conn, n, source='unrelated-source', generation='unrelated-generation')
        apply_if_present(conn)
        assert witness(conn) == [('selected-source', 'generation-2')]


def raw_receipt(conn, n, *, agent=AGENT, module=MODULE, source='selected-source',
                generation='generation-2', imported=True, inbox=True, mismatch=False,
                status='committed'):
    packet = str(uuid4())
    envelope = {'source_instance_id': source, 'generation': generation}
    conn.execute('''insert into public.sli_agent_receipts
        (agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
        values(%s,%s,%s,%s,repeat('a',64),%s::jsonb,%s::jsonb)''',
        (agent, module, n, packet, json.dumps(envelope), json.dumps({'status': status})))
    if inbox:
        conn.execute('''insert into public.sli_agent_packet_inbox
            (packet_id,envelope,packet,event_rows,imported_at)
            values(%s,%s::jsonb,'{"contract":"sli.collection-packet.v1"}','[]',%s)''',
            (packet, json.dumps(envelope | ({'forged': True} if mismatch else {})),
             '2026-01-01T00:00:00Z' if imported else None))


OLD_WITNESS = '''select obs.source_instance_id,obs.generation
    from sli_plugin_file_audit.observations obs
    join public.sli_agent_receipts r on r.agent_id=%s and r.module_id='sli.file-audit'
      and r.envelope->>'source_instance_id'=obs.source_instance_id
      and r.envelope->>'generation'=obs.generation
    join public.sli_agent_packet_inbox inbox on inbox.packet_id=r.packet_id
    where obs.agent_id=%s and obs.collection_scope_id=%s and obs.policy_revision=%s
      and r.receipt->>'status'='committed' and inbox.imported_at is not null
      and inbox.envelope=r.envelope
    order by r.sequence desc limit 1'''


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_all_native_identity_filters_duplicates_eof_and_bigint(join_pg):
    import psycopg

    with psycopg.connect(join_pg, autocommit=True) as conn:
        conn.execute("insert into sli_agents values(%s,'active','[]'),(%s,'active','[]')", (AGENT, OTHER_AGENT))
        observe(conn, 1)
        observe(conn, 2)  # Duplicate witness identity cannot multiply the result.
        observe(conn, 3, root='foreign-root', source='foreign-root')
        observe(conn, 4, revision=1, source='foreign-revision')
        observe(conn, 5, agent=OTHER_AGENT, source='foreign-agent')
        receipt(conn, 1)
        raw_receipt(conn, 2, source='foreign-root')
        raw_receipt(conn, 3, source='foreign-revision')
        raw_receipt(conn, 4, source='foreign-agent')
        raw_receipt(conn, 5, generation='foreign-generation')
        raw_receipt(conn, 6, imported=False)
        raw_receipt(conn, 7, mismatch=True)
        raw_receipt(conn, 8, inbox=False)
        raw_receipt(conn, 9, module='foreign-module')
        raw_receipt(conn, 10, agent=OTHER_AGENT)
        apply_if_present(conn)
        expected = conn.execute(OLD_WITNESS, (AGENT, AGENT, 'selected-root', 2)).fetchall()
        assert expected == [('selected-source', 'generation-2')]
        assert witness(conn) == expected
        assert witness(conn, root='absent') == []
        assert witness(conn, revision=900) == []
        for args in ((None, 'selected-root', 2), (AGENT, None, 2), (AGENT, 'selected-root', None)):
            assert witness(conn, *args) == []
        # A legitimate observation with no raw receipt reaches raw EOF.
        assert witness(conn, agent=OTHER_AGENT, root='absent') == []
        conn.execute('delete from sli_agent_packet_inbox')
        conn.execute('delete from sli_agent_receipts')
        assert witness(conn) == []
        # Exact maximum bigint needs neither a sentinel nor +/- arithmetic.
        receipt(conn, 9223372036854775807, imported=False)
        receipt(conn, 1)
        assert witness(conn) == expected
        conn.execute('update sli_agent_packet_inbox set imported_at=now()')
        assert witness(conn) == expected
        with pytest.raises(psycopg.errors.CheckViolation):
            raw_receipt(conn, 12, status='pending')
        with pytest.raises(psycopg.errors.CheckViolation):
            raw_receipt(conn, 0)
        with pytest.raises(psycopg.errors.UniqueViolation):
            receipt(conn, 1)  # Receipt PK makes sequence ties impossible within the stream.


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('disabled,duplicate_config', [(False, False), (True, False), (False, True)])
def test_public_sources_equivalent_physical_login_and_latest_bound(join_pg, request, disabled, duplicate_config):
    import psycopg

    worker_dsn = request.getfixturevalue('postgres_semantic_worker_dsn')
    with psycopg.connect(join_pg, autocommit=True) as admin:
        config = {'policy_revision': '2', 'roots': [
            {'collection_scope_id': root} for root in
            ('selected-root', 'selected-root', 'latest-bound', 'old-revision', 'absent')]}
        modules = [{'module_id': MODULE, 'enabled': not disabled, 'config': config}]
        if duplicate_config:
            modules *= 2
        admin.execute("insert into sli_agents values(%s,'active',%s::jsonb)", (AGENT, json.dumps(modules)))
        observe(admin, 1)
        observe(admin, 2)
        observe(admin, 3, root='latest-bound', source='bound-source', generation='old')
        observe(admin, 4, root='latest-bound', source='bound-source', generation='new')
        observe(admin, 5, root='old-revision', revision=1, source='wrong-revision')
        receipt(admin, 1)
        receipt(admin, 2, source='bound-source', generation='old')
        receipt(admin, 3, source='bound-source', generation='new')
        for n in range(4, 263):
            receipt(admin, n, source='unrelated-source')
        before_function, before_authority = function_state(admin), authority_state(admin)
        with psycopg.connect(worker_dsn, autocommit=True) as worker:
            principal = worker.execute('''select session_user,current_user,oid,rolsuper,rolbypassrls
                from pg_roles where rolname=session_user''').fetchone()
            assert principal[0] == principal[1] and principal[3:] == (False, False)
            assert not worker.execute("select pg_has_role(session_user,'adlog_storage_owner','MEMBER')").fetchone()[0]
            worker.execute('set role adlog_semantic_worker')
            installation = admin.execute('select installation_id from semantic_default_installation').fetchone()[0]
            admin.execute('''insert into finding_evidence_source_bindings
                (principal_oid,principal_name,installation_id,plugin_id,source_instance_id,
                 source_generation,collection_scope_id,storage_kind,agent_id)
                values(%s,%s,%s,%s,'bound-source','new','latest-bound','file_audit_observation',%s)''',
                (principal[2], principal[0], installation, MODULE, AGENT))
            with worker.transaction(force_rollback=True):
                before = enumerate_sources(worker)
            apply_if_present(admin)
            with worker.transaction(force_rollback=True):
                after = enumerate_sources(worker)
                assert enumerate_sources(worker) == after
            assert before == after
            scopes = [(row['scope']['source_instance_id'], row['scope']['source_generation'],
                       row['scope']['collection_scope_id']) for row in after]
            expected = ([] if disabled else [
                ('bound-source', 'new', 'latest-bound'),
                ('selected-source', 'generation-2', 'selected-root')])
            assert sorted(scopes) == sorted(expected * (2 if duplicate_config else 1))
            assert all(row['agent_id'] == AGENT and row['config'] == config for row in after)
            for query in (f'select * from {HELPER}(%s,%s,%s)',
                          'select * from sli_plugin_file_audit.observations',
                          'select * from finding_evidence_source_bindings'):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    worker.execute(query, (AGENT, 'selected-root', 2) if HELPER in query else None)
        assert function_state(admin)[:5] == before_function[:5]
        assert authority_state(admin) == before_authority
        assert admin.execute('select count(*) from finding_evidence_source_bindings').fetchone() == (1,)
        for role in ('adlog_user', 'adlog_storage_worker', 'adlog_semantic_worker'):
            assert not admin.execute('select has_function_privilege(%s,%s,\'EXECUTE\')',
                                     (role, HELPER + '(uuid,text,bigint)')).fetchone()[0]
        helper = admin.execute('''select p.provolatile,p.prosecdef,p.proisstrict,p.proconfig,
            pg_get_userbyid(p.proowner) from pg_proc p where p.oid=%s::regprocedure''',
            (HELPER + '(uuid,text,bigint)',)).fetchone()
        assert helper == ('s', False, True, ['search_path=pg_catalog, pg_temp'], 'adlog_storage_owner')


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('bad', ['agent', 'module', 'root', 'revision', 'generation', 'source',
                               'envelope', 'unimported', 'missing_inbox', 'null_status',
                               'missing_status', 'null_source', 'null_generation'])
def test_each_ineligible_newer_witness_cannot_replace_older(join_pg, bad):
    import psycopg

    with psycopg.connect(join_pg, autocommit=True) as conn:
        conn.execute("insert into sli_agents values(%s,'active','[]'),(%s,'active','[]')", (AGENT, OTHER_AGENT))
        observe(conn, 1)
        receipt(conn, 1)
        obs = {'source': 'new-source', 'generation': 'new-generation'}
        if bad == 'agent':
            obs['agent'] = OTHER_AGENT
        if bad == 'root':
            obs['root'] = 'other-root'
        if bad == 'revision':
            obs['revision'] = 1
        observe(conn, 2, **obs)
        raw = {'source': 'new-source', 'generation': 'new-generation'}
        if bad == 'module':
            raw['module'] = 'another-module'
        if bad == 'generation':
            raw['generation'] = 'different-generation'
        if bad == 'source':
            raw['source'] = 'different-source'
        if bad == 'null_source':
            raw['source'] = None
        if bad == 'null_generation':
            raw['generation'] = None
        if bad == 'envelope':
            raw['mismatch'] = True
        if bad == 'unimported':
            raw['imported'] = False
        if bad == 'missing_inbox':
            raw['inbox'] = False
        if bad == 'null_status':
            raw['status'] = None
        raw_receipt(conn, 2, **raw)
        if bad == 'missing_status':
            # Real 157 CHECK admits SQL NULL; both implementations must still
            # require the positive status='committed' predicate at read time.
            conn.execute("update sli_agent_receipts set receipt='{}' where sequence=2")
        apply_if_present(conn)
        assert conn.execute(OLD_WITNESS, (AGENT, AGENT, 'selected-root', 2)).fetchall() == [
            ('selected-source', 'generation-2')]
        assert witness(conn) == [('selected-source', 'generation-2')]
        conn.execute('delete from sli_agent_packet_inbox where packet_id in '
                     '(select packet_id from sli_agent_receipts where sequence=1)')
        conn.execute('delete from sli_agent_receipts where sequence=1')
        assert witness(conn) == []  # Exhaustion after filtering cannot return partial data.


def current_state(conn):
    return (function_state(conn), authority_state(conn),
            conn.execute('select * from schema_migrations order by version').fetchall(),
            conn.execute('select to_regprocedure(%s)', (HELPER + '(uuid,text,bigint)',)).fetchone())


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('guard', ['wrong_predecessor', 'occupied', 'not_owner', 'rollback'])
def test_guard_and_failed_migration_atomic(join_pg, guard):
    import psycopg
    from psycopg import sql

    with psycopg.connect(join_pg, autocommit=True) as conn:
        if guard == 'wrong_predecessor':
            conn.execute("update schema_migrations set name='wrong' where version=266")
        if guard == 'occupied':
            conn.execute("insert into schema_migrations values(268,'occupied')")
        before = current_state(conn)
        login = 'sli_join267_' + uuid4().hex
        if guard == 'not_owner':
            conn.execute(sql.SQL('create role {} login').format(sql.Identifier(login)))
            conn.execute(sql.SQL('grant select on schema_migrations to {}').format(sql.Identifier(login)))
            conn.execute(sql.SQL('set session authorization {}').format(sql.Identifier(login)))
        source = MIGRATION.read_text('utf-8')
        if guard == 'rollback':
            source = source.replace('insert into public.schema_migrations(version,name)',
                                    "do $$ begin raise exception 'injected rollback'; end $$;\ninsert into public.schema_migrations(version,name)")
        try:
            with pytest.raises(psycopg.errors.RaiseException,
                               match='injected rollback' if guard == 'rollback' else 'migration 267 prerequisites failed'):
                conn.execute(source)
            conn.execute('rollback')
        finally:
            conn.execute('reset session authorization; reset role')
            if guard == 'not_owner':
                conn.execute(sql.SQL('drop owned by {}').format(sql.Identifier(login)))
                conn.execute(sql.SQL('drop role {}').format(sql.Identifier(login)))
        assert current_state(conn) == before


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_repeat_and_nonfile_body_exact(join_pg):
    import psycopg

    with psycopg.connect(join_pg, autocommit=True) as conn:
        old = function_state(conn)
        apply_if_present(conn)
        before = current_state(conn)
        with pytest.raises(psycopg.errors.RaiseException, match='migration 267 prerequisites failed'):
            conn.execute(MIGRATION.read_text('utf-8'))
        conn.execute('rollback')
        assert current_state(conn) == before
        new = function_state(conn)
        # Compare both surrounding function segments, not a reconstructed non-file implementation.
        start = '    cross join lateral (\n        select obs.source_instance_id,obs.generation'
        original = migration_source(263, 'native_source_lookup_index')
        begin = original.index(start)
        end = original.index("    where agent.status='active' and m->>'module_id'='sli.file-audit'", begin)
        old_fragment = original[begin:end]
        replacement_start = '    cross join lateral public.file_audit_discovery_witness_v267('
        installed = MIGRATION.read_text('utf-8')
        begin = installed.index(replacement_start)
        end = installed.index("    where agent.status='active' and m->>'module_id'='sli.file-audit'", begin)
        assert new[5] == old[5].replace(old_fragment, installed[begin:end])
        assert new[:5] == old[:5]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_raw_page_natural_primary_key_plan(join_pg):
    import psycopg

    with psycopg.connect(join_pg, autocommit=True) as conn:
        conn.execute("insert into sli_agents values(%s,'active','[]')", (AGENT,))
        # Enough raw history that a PK page is a real choice; no planner switches/hints.
        conn.execute('''insert into sli_agent_receipts
            (agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            select %s,'sli.file-audit',n,gen_random_uuid(),repeat('a',64),'{}','{"status":"committed"}'
            from generate_series(1,4096) n''', (AGENT,))
        conn.execute('analyze sli_agent_receipts')
        evidence = []
        for cursor in (None, 2048):
            query = '''select r.sequence from public.sli_agent_receipts r
                where r.agent_id=%s and r.module_id='sli.file-audit' '''
            params = (AGENT,)
            if cursor is not None:
                query += 'and r.sequence<%s '
                params += (cursor,)
            query += 'order by r.sequence desc limit 128'
            plan = conn.execute('explain(format json) ' + query, params).fetchone()[0]
            nodes = list(plan_nodes(plan))
            assert any(node.get('Index Name') == 'sli_agent_receipts_pkey'
                       and node.get('Scan Direction') == 'Backward' for node in nodes)
            assert all(node['Node Type'] not in ('Sort', 'Bitmap Heap Scan') for node in nodes)
            keys = ('Node Type', 'Index Name', 'Scan Direction', 'Plan Rows', 'Startup Cost', 'Total Cost')
            evidence.append([{key: node[key] for key in keys if key in node} for node in nodes])
        print('raw_page_natural_plan=' + json.dumps(evidence, sort_keys=True))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_stable_same_statement_snapshot_during_concurrent_commit(join_pg):
    import psycopg

    key = 2671020
    blocked = Event()
    with psycopg.connect(join_pg, autocommit=True) as admin:
        admin.execute("insert into sli_agents values(%s,'active','[]')", (AGENT,))
        observe(admin, 1)
        observe(admin, 2, generation='new-generation')
        receipt(admin, 1)
        apply_if_present(admin)
        # A disposable volatile argument gate pauses evaluation after the outer
        # statement snapshot, without changing the native helper or its tables.
        admin.execute('''create function public.join267_snapshot_gate(a uuid,k bigint) returns uuid
            language plpgsql volatile as $$ begin perform pg_advisory_xact_lock(k); return a; end $$''')
        admin.execute('grant execute on function public.join267_snapshot_gate(uuid,bigint) to adlog_storage_owner')
        admin.execute('select pg_advisory_lock(%s)', (key,))
        def read_during_commit():
            with psycopg.connect(join_pg, autocommit=True) as reader:
                pid = reader.info.backend_pid
                reader.execute('set role adlog_storage_owner')
                reader.execute('create temp table join267_snapshot_result(source text,generation text)')
                blocked.pid = pid
                blocked.set()
                return reader.execute(f'''insert into join267_snapshot_result
                    select * from {HELPER}(
                    public.join267_snapshot_gate(%s::uuid,%s::bigint),'selected-root',2)
                    returning source,generation''',
                    (AGENT, key)).fetchall()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(read_during_commit)
            try:
                assert blocked.wait(5)
                deadline = monotonic() + 5
                while monotonic() < deadline:
                    wait = admin.execute('select wait_event from pg_stat_activity where pid=%s', (blocked.pid,)).fetchone()
                    if wait == ('advisory',):
                        break
                    sleep(0.01)
                else:
                    pytest.fail('reader did not reach controlled advisory gate')
                receipt(admin, 2, generation='new-generation')
            finally:
                admin.execute('select pg_advisory_unlock(%s)', (key,))
            assert result.result(timeout=5) == [('selected-source', 'generation-2')]
        assert witness(admin) == [('selected-source', 'new-generation')]

"""Prospective normal AD issuer on real disposable273/274; no native source calls."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
from threading import Event
from time import monotonic, sleep
from uuid import uuid4

import pytest

from server.sli.agents import policies
from tests.migrations.test_password_coverage_domain_migration import (
    coverage_pg as coverage_pg, password_base_pg as password_base_pg,
    coordinator_pg as coordinator_pg, reservation_pg as reservation_pg,
    password_pg as password_pg, native_pg as native_pg, acl_pg as acl_pg,
    original_base as original_base,
    AGENT, HOST,
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config/postgres_migrations/274_agent_ad_binding_issuer.sql'
CONFIG = dict(source_name='fixture-dc', connect_address='fixture-endpoint')


@pytest.fixture
def issuer_base(coverage_pg):
    """Real273 candidate with unrelated269/270/271/272 synthetic predecessor markers; restore exact169 history and assignment grants."""
    dsn = coverage_pg[0][0]
    import psycopg
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute('delete from finding_evidence_source_bindings')
        admin.execute('delete from sli_agent_module_bindings')
        admin.execute("update sli_agents set assigned_modules='[]',policy_revision=1")
        admin.execute('set role adlog_storage_owner')
        source = (PATH.parent / '169_agent_collection_control.sql').read_text('utf-8-sig')
        admin.execute(source[source.index('create table public.sli_agent_policy_history'):source.index('-- Preserve actions')])
        admin.execute('grant select on sli_agents to adlog_user')
        admin.execute('grant update(assigned_modules,policy_revision) on sli_agents to adlog_user')
        # Existing163/169 audit choices, preserving actual273 added choice.
        admin.execute("""do $$ declare prior text; begin
          select pg_get_expr(conbin,conrelid) into strict prior from pg_constraint
          where conrelid='sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
          alter table sli_agent_audit drop constraint sli_agent_audit_action_check;
          execute format('alter table sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action=''module_assign'')',prior);
          end $$""")
        admin.execute('reset role')
    return dsn, coverage_pg[1], coverage_pg[0][1]


@pytest.fixture
def issuer_pg(issuer_base):
    import psycopg
    if PATH.exists():
        with psycopg.connect(issuer_base[0], autocommit=True) as admin:
            admin.execute(PATH.read_text('utf-8-sig'))
    return issuer_base


@contextmanager
def connection(source, *, web=False, semantic=False):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    login = source[2] if semantic else source[1]
    dsn = make_conninfo(source[0], user=login) if web or semantic else source[0]
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        if web or semantic:
            assert conn.execute('select session_user as u').fetchone()['u'] == login
        if semantic:
            conn.execute('set role adlog_semantic_worker')
        yield conn


def issue(conn, *, agent=AGENT, revision=1, enabled=True, config=None):
    with conn.transaction(), conn.cursor() as cur:
        return policies.assign_module(cur, dict(agent_id=agent, module_id='sli.windows.ad-dc',
            expected_revision=revision, enabled=enabled, config=CONFIG if config is None else config), actor='session:42')


def test_normal_owner_issuance_creates_exact_durable_binding(issuer_pg):
    with connection(issuer_pg, web=True) as web:
        result = issue(web)
    with connection(issuer_pg) as admin:
        row = admin.execute('select * from sli_agent_module_bindings where agent_id=%s', (AGENT,)).fetchone()
        assert row is not None, 'normal enabled AD assignment lacks durable source authority'
        assert row['policy_revision'] == '2' and row['source_instance_id'] == HOST
        assert row['source_name'] == CONFIG['source_name'] and row['password_detection_domain_id'] is None
        assert result['assigned_modules'][0]['config']['policy_revision'] == '2'
        assert admin.execute('select staged_xact_id is not null as stamped from sli_agent_policy_history where agent_id=%s and revision=2', (AGENT,)).fetchone()['stamped']
        assert admin.execute('select count(*) as n from finding_evidence_source_bindings').fetchone()['n'] == 0
        assert admin.execute("select actor from sli_agent_audit where action='module_assign'").fetchone()['actor'] == 'session:42'


@pytest.mark.parametrize('savepoint', ['active', 'released', 'rollback_retry'])
def test_current_parent_stamp_supports_savepoints(issuer_pg, savepoint):
    with connection(issuer_pg, web=True) as web:
        with web.transaction():
            parent = web.execute('select pg_current_xact_id()::text as x').fetchone()['x']
            if savepoint == 'rollback_retry':
                class Retry(Exception):
                    pass
                with pytest.raises(Retry), web.transaction():
                    issue(web)
                    raise Retry
                assert web.execute('select count(*) as n from sli_agent_module_bindings').fetchone()['n'] == 0
            with web.transaction():
                issue(web)
                if savepoint == 'active':
                    assert web.execute('select staged_xact_id::text as x from sli_agent_policy_history where revision=2').fetchone()['x'] == parent
            assert web.execute('select staged_xact_id::text as x from sli_agent_policy_history where revision=2').fetchone()['x'] == parent


@pytest.mark.parametrize('old', ['null', 'committed', 'future_other', 'wrong_payload'])
def test_preexisting_future_snapshot_cannot_be_freshened(issuer_pg, old):
    import psycopg
    from sli_agent.ad_dc import ADDCModule
    modules = [dict(module_id='sli.windows.ad-dc', enabled=True, config=ADDCModule(HOST, {**CONFIG, 'policy_revision': '2'}).config)]
    with connection(issuer_pg) as admin:
        if old == 'null':
            admin.execute('alter table sli_agent_policy_history disable trigger agent_ad_history_stamp')
        if old == 'wrong_payload':
            modules[0]['config']['source_name'] = 'other'
        admin.execute("insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) values(%s,%s,%s::jsonb,'{}')",
                      (AGENT, 3 if old == 'future_other' else 2, json.dumps(modules)))
        if old == 'null':
            admin.execute('alter table sli_agent_policy_history enable always trigger agent_ad_history_stamp')
    with connection(issuer_pg, web=True) as web:
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_'):
            issue(web)
    with connection(issuer_pg) as admin:
        assert admin.execute('select count(*) as n from sli_agent_module_bindings').fetchone()['n'] == 0
        assert admin.execute('select policy_revision from sli_agents where id=%s', (AGENT,)).fetchone()['policy_revision'] == 1


def test_full_stamp_overrides_forgery_and_preserves_old_columns(issuer_pg):
    with connection(issuer_pg, web=True) as web:
        with web.transaction():
            parent = web.execute('select pg_current_xact_id()::text as x').fetchone()['x']
            web.execute("insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy,staged_xact_id) values(%s,9,'[]','{}','1'::xid8)", (AGENT,))
            assert web.execute('select staged_xact_id::text as x from sli_agent_policy_history where revision=9').fetchone()['x'] == parent
            web.execute("insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) values(%s,9,'[]','{}') on conflict do nothing", (AGENT,))
        assert web.execute('select staged_xact_id::text as x from sli_agent_policy_history where revision=9').fetchone()['x'] == parent
        assert web.execute('select staged_xact_id from sli_agent_policy_history where revision=1').fetchone()['staged_xact_id'] is None


def test_existing_reissue_disable_retarg_noop_and_domain(issuer_pg):
    import psycopg
    with connection(issuer_pg, web=True) as web:
        issue(web)
        issue(web, revision=2)
        issue(web, revision=3, enabled=False)
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_identity'):
            issue(web, revision=4, enabled=False, config={**CONFIG, 'source_name': 'other'})
        issue(web, revision=4)
        with web.transaction():
            web.execute('update sli_agents set assigned_modules=assigned_modules,policy_revision=6 where id=%s', (AGENT,))
    with connection(issuer_pg) as admin:
        row = admin.execute('select * from sli_agent_module_bindings').fetchone()
        assert row['policy_revision'] == '5'
        assert row['source_name'] == CONFIG['source_name']


@pytest.mark.parametrize('legacy', ['enabled', 'disabled_history', 'string', 'duplicate'])
def test_missing_old_authority_is_never_repaired(issuer_pg, legacy):
    import psycopg
    from sli_agent.ad_dc import ADDCModule
    module = dict(module_id='sli.windows.ad-dc', enabled=legacy != 'disabled_history', config=ADDCModule(HOST, CONFIG).config)
    modules = ['sli.windows.ad-dc'] if legacy == 'string' else [module, module] if legacy == 'duplicate' else [module]
    with connection(issuer_pg) as admin:
        admin.execute('alter table sli_agents disable trigger agent_ad_binding_issuer')
        admin.execute('update sli_agents set assigned_modules=%s::jsonb where id=%s', (json.dumps(modules), AGENT))
        admin.execute('alter table sli_agents enable always trigger agent_ad_binding_issuer')
        if legacy == 'disabled_history':
            module['enabled'] = True
            admin.execute('update sli_agent_policy_history set assigned_modules=%s::jsonb where revision=1', (json.dumps([module]),))
            admin.execute('update sli_agents set policy_revision=7 where id=%s', (AGENT,))
    with connection(issuer_pg, web=True) as web:
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_'):
            issue(web, revision=7 if legacy == 'disabled_history' else 1)


def _seed_disabled_history(source, *, path=(), value=None, boundary=False, old_module_revision=False):
    """Legacy G1 and valid current G2 exist before274; only G1 is corrupted."""
    module = dict(module_id='sli.windows.ad-dc', enabled=False, config=dict(
        source_name='fixture-dc', connect_address='fixture-endpoint', policy_revision='1',
        batch_size=32, channels={'Security': True, 'System': True, 'Directory Service': True},
        channel_generations={}, allow_event_ids=None, initial_read_hours=24))
    if boundary:
        module['config'].update(batch_size=128, initial_read_hours=876000, allow_event_ids=[],
                                channel_generations={'Security': 'g' * 128})
    current = json.loads(json.dumps(module))
    current['config']['policy_revision'] = '1' if old_module_revision else '2'
    if path:
        parent = module
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = value
    with connection(source) as admin:
        admin.execute('update sli_agent_policy_history set assigned_modules=%s::jsonb where agent_id=%s and revision=1',
                      (json.dumps([module]), AGENT))
        admin.execute('update sli_agents set assigned_modules=%s::jsonb,policy_revision=2 where id=%s',
                      (json.dumps([current]), AGENT))
        admin.execute('insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) '
                      'select id,policy_revision,assigned_modules,collection_policy from sli_agents where id=%s', (AGENT,))
        admin.execute(PATH.read_text('utf-8-sig'))


def _issuer_assignment_state(source):
    with connection(source) as admin:
        return dict(
            agent=admin.execute('select assigned_modules,policy_revision from sli_agents where id=%s', (AGENT,)).fetchone(),
            bindings=admin.execute('select * from sli_agent_module_bindings order by agent_id,module_id').fetchall(),
            history=admin.execute('select * from sli_agent_policy_history order by agent_id,revision').fetchall(),
            audit=admin.execute('select * from sli_agent_audit order by id').fetchall())


@pytest.mark.parametrize(('path', 'value'), [
    pytest.param(('config', 'batch_size'), 'bad', id='batch-string'),
    pytest.param(('config', 'batch_size'), 0, id='batch-zero'),
    pytest.param(('config', 'batch_size'), 129, id='batch-overflow'),
    pytest.param(('config', 'batch_size'), True, id='batch-boolean'),
    pytest.param(('extra',), True, id='module-extra-key'),
    pytest.param(('enabled',), 'false', id='enabled-string'),
    pytest.param(('config', 'extra'), True, id='config-extra-key'),
    pytest.param(('config',), [], id='config-array'),
    pytest.param(('config', 'source_name'), '', id='source-empty'),
    pytest.param(('config', 'source_name'), '   ', id='source-blank'),
    pytest.param(('config', 'source_name'), 's' * 129, id='source-overflow'),
    pytest.param(('config', 'connect_address'), '', id='address-empty'),
    pytest.param(('config', 'connect_address'), '   ', id='address-blank'),
    pytest.param(('config', 'connect_address'), 'a' * 129, id='address-overflow'),
    pytest.param(('config', 'policy_revision'), '2', id='module-revision-after-history'),
    pytest.param(('config', 'channels'), {'Security': True}, id='channels-missing-key'),
    pytest.param(('config', 'channels'), {'Security': True, 'System': True, 'Directory Service': True, 'other': True}, id='channels-extra-key'),
    pytest.param(('config', 'channels', 'Security'), 'true', id='channel-value-string'),
    pytest.param(('config', 'channel_generations'), {'other': 'g'}, id='generation-extra-key'),
    pytest.param(('config', 'channel_generations'), {'Security': 1}, id='generation-value-number'),
    pytest.param(('config', 'channel_generations'), {'Security': ''}, id='generation-empty'),
    pytest.param(('config', 'channel_generations'), {'Security': 'g' * 129}, id='generation-overflow'),
    pytest.param(('config', 'allow_event_ids'), {}, id='allow-object'),
    pytest.param(('config', 'allow_event_ids'), [True], id='allow-boolean-item'),
    pytest.param(('config', 'allow_event_ids'), [4624.5], id='allow-fraction-item'),
    pytest.param(('config', 'allow_event_ids'), [-1], id='allow-negative-item'),
    pytest.param(('config', 'allow_event_ids'), [4624] * 513, id='allow-overflow'),
    pytest.param(('config', 'initial_read_hours'), 'bad', id='hours-string'),
    pytest.param(('config', 'initial_read_hours'), True, id='hours-boolean'),
    pytest.param(('config', 'initial_read_hours'), -1, id='hours-negative'),
    pytest.param(('config', 'initial_read_hours'), 24.5, id='hours-fraction'),
    pytest.param(('config', 'initial_read_hours'), 876001, id='hours-overflow'),
])
def test_malformed_disabled_history_denies_initial_issuance_atomically(issuer_base, path, value):
    import psycopg
    _seed_disabled_history(issuer_base, path=path, value=value)
    before = _issuer_assignment_state(issuer_base)
    assert before['agent']['policy_revision'] == 2 and before['bindings'] == []
    assert [row['revision'] for row in before['history']] == [1, 2]
    assert all(row['staged_xact_id'] is None for row in before['history'])
    with connection(issuer_base, web=True) as web:
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_legacy_unavailable'):
            issue(web, revision=2)
    # Includes exact legacy metadata, new G3 snapshot/stamp, desired revision and audit.
    assert _issuer_assignment_state(issuer_base) == before


@pytest.mark.parametrize('variant', ['ordinary', 'bounds', 'older-module-revision'])
def test_valid_disabled_history_allows_prospective_initial_issuance(issuer_base, variant):
    _seed_disabled_history(issuer_base, boundary=variant == 'bounds',
                           old_module_revision=variant == 'older-module-revision')
    before = _issuer_assignment_state(issuer_base)
    assert before['bindings'] == []
    with connection(issuer_base, web=True) as web:
        result = issue(web, revision=2)
    after = _issuer_assignment_state(issuer_base)
    assert after['agent']['policy_revision'] == 3
    assert after['agent']['assigned_modules'] == result['assigned_modules']
    assert len(after['bindings']) == 1
    binding = after['bindings'][0]
    assert binding['policy_revision'] == '3' and binding['source_instance_id'] == HOST
    assert binding['source_name'] == 'fixture-dc' and binding['password_detection_domain_id'] is None
    assert after['history'][:2] == before['history']
    assert [row['revision'] for row in after['history']] == [1, 2, 3]
    assert after['history'][2]['assigned_modules'] == result['assigned_modules']
    assert after['history'][2]['staged_xact_id'] is not None
    assert len(after['audit']) == len(before['audit']) + 1
    assert after['audit'][-1]['action'] == 'module_assign' and after['audit'][-1]['actor'] == 'session:42'


@pytest.mark.parametrize('mode', ['repeatable read', 'serializable'])
def test_non_rc_issuance_fails_closed(issuer_pg, mode):
    import psycopg
    with connection(issuer_pg, web=True) as web:
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_isolation'), web.transaction():
            web.execute('set transaction isolation level ' + mode)
            issue(web)


def test_same_c_concurrent_agents_one_winner_after_observed_lock(issuer_pg):
    import psycopg
    other = str(uuid4())
    with connection(issuer_pg) as admin:
        admin.execute("insert into sli_agents(id,host_id,status,assigned_modules,policy_revision,collection_policy,rights_probe) values(%s,%s,'active','[]',1,'{}','{}')", (other, HOST))
    started, pids = Event(), []
    def loser():
        with connection(issuer_pg, web=True) as web:
            pids.append(web.execute('select pg_backend_pid() as p').fetchone()['p'])
            started.set()
            return issue(web, agent=other)
    with ThreadPoolExecutor(max_workers=1) as pool, connection(issuer_pg, web=True) as winner:
        with winner.transaction():
            issue(winner)
            future = pool.submit(loser)
            assert started.wait(3)
            with connection(issuer_pg) as observer:
                deadline = monotonic() + 3
                while monotonic() < deadline:
                    row = observer.execute('select wait_event_type from pg_stat_activity where pid=%s', (pids[0],)).fetchone()
                    if row and row['wait_event_type'] == 'Lock':
                        break
                    sleep(0.01)
                else:
                    pytest.fail('second issuer did not wait on the common source lock')
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_claim'):
            future.result(timeout=8)
    with connection(issuer_pg) as admin:
        assert admin.execute('select count(*) as n from sli_agent_module_bindings').fetchone()['n'] == 1
        assert admin.execute('select policy_revision from sli_agents where id=%s', (other,)).fetchone()['policy_revision'] == 1
        assert admin.execute('select count(*) as n from sli_agent_policy_history where agent_id=%s', (other,)).fetchone()['n'] == 0


@pytest.mark.parametrize('table', ['sli_agent_audit', 'sli_agent_module_bindings'])
def test_later_failure_rolls_back_binding_stamp_snapshot_and_agent(issuer_pg, table):
    import psycopg
    from psycopg import sql
    with connection(issuer_pg) as admin:
        admin.execute("create function public.fixture_issue_fail() returns trigger language plpgsql as $$begin raise exception 'injected issuance failure'; end$$")
        admin.execute(sql.SQL('create trigger fixture_issue_fail before insert on {} for each row execute function public.fixture_issue_fail()').format(sql.Identifier(table)))
    with connection(issuer_pg, web=True) as web:
        with pytest.raises(psycopg.Error, match='injected issuance failure'):
            issue(web)
    with connection(issuer_pg) as admin:
        assert admin.execute('select count(*) as n from sli_agent_module_bindings').fetchone()['n'] == 0
        assert admin.execute('select count(*) as n from sli_agent_policy_history').fetchone()['n'] == 1
        assert admin.execute('select policy_revision from sli_agents where id=%s', (AGENT,)).fetchone()['policy_revision'] == 1


def test_private_roles_triggers_and_old_payload(issuer_pg):
    import psycopg
    from server.sli.agents.policies import check_in
    with connection(issuer_pg) as admin:
        rows = admin.execute("select tgname,tgenabled from pg_trigger where tgname in ('agent_ad_history_stamp','agent_ad_binding_issuer') order by tgname").fetchall()
        assert [row['tgenabled'] for row in rows] == ['A', 'A']
    with connection(issuer_pg, web=True) as web:
        for statement in ["update sli_agent_policy_history set staged_xact_id='1'", 'delete from sli_agent_policy_history',
                          'truncate sli_agent_policy_history', 'alter table sli_agent_policy_history disable trigger agent_ad_history_stamp',
                          'select agent_ad_stamp_history()', 'select agent_ad_issue_binding()']:
            with pytest.raises(psycopg.errors.InsufficientPrivilege), web.transaction():
                web.execute(statement)
        result = issue(web)
        agent = web.execute('select * from sli_agents where id=%s', (AGENT,)).fetchone()
        assert 'staged_xact_id' not in json.dumps(check_in(agent))
        assert 'staged_xact_id' not in json.dumps(result)

@pytest.mark.parametrize('case', ['owner', 'manager', 'viewer', 'unauthenticated', 'origin'])
def test_real_owner_http_assignment_boundary(issuer_pg, monkeypatch, case):
    from contextlib import contextmanager
    from email.message import Message
    from http import HTTPStatus
    import io
    from server.api import http_server
    from server.api.routes import agents
    raw = json.dumps(dict(agent_id=AGENT, module_id='sli.windows.ad-dc', expected_revision=1,
                          enabled=True, config=CONFIG)).encode()
    @contextmanager
    def runtime():
        with connection(issuer_pg, web=True) as web:
            web.autocommit = False
            yield web
    monkeypatch.setattr(agents, 'connect', runtime)
    monkeypatch.setattr(http_server, 'auth_required', lambda: True)
    monkeypatch.setattr(http_server, 'principal_from_headers', lambda _: None if case == 'unauthenticated' else {'type': 'session', 'id': 42, 'role': 'admin'})
    handler = object.__new__(http_server.RequestHandler)
    handler.headers = Message()
    handler.headers['Content-Length'] = str(len(raw))
    handler.headers['Content-Type'] = 'application/json'
    if case == 'origin':
        handler.headers['Origin'] = 'https://fixture.invalid'
        handler.headers['Origin'] = 'https://other.invalid'
    class Socket:
        def gettimeout(self):
            return None
        def settimeout(self, _):
            pass
    handler.connection = Socket()
    handler.rfile = io.BufferedReader(io.BytesIO(raw))
    handler._effective_access_cache = dict(platform_owner=case == 'owner', capabilities=['access.manage'] if case == 'manager' else [])
    responses = []
    handler._send_json = lambda value, status=HTTPStatus.OK, **_: responses.append((int(status), value))
    assert agents.try_handle_post(handler, '/api/v1/admin/agents/modules')
    assert responses[-1][0] == {'viewer': 403, 'unauthenticated': 401, 'origin': 403}.get(case, 200)
    with connection(issuer_pg) as admin:
        assert admin.execute('select count(*) as n from sli_agent_module_bindings').fetchone()['n'] == int(case in ('owner', 'manager'))
        assert admin.execute("select count(*) as n from sli_agent_audit where action='module_assign'").fetchone()['n'] == int(case in ('owner', 'manager'))


@pytest.mark.parametrize('unsafe', ['grant', 'trigger'])
def test_migration_rejects_unexpected_history_mutability(issuer_base, unsafe):
    import psycopg
    with connection(issuer_base) as admin:
        if unsafe == 'grant':
            admin.execute('grant update on sli_agent_policy_history to adlog_user')
        else:
            admin.execute("create function fixture_history_writer() returns trigger language plpgsql as $$begin return new;end$$")
            admin.execute('create trigger fixture_history_writer before insert on sli_agent_policy_history for each row execute function fixture_history_writer()')
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_preflight'):
            admin.execute(PATH.read_text('utf-8-sig'))
        admin.execute('rollback')
        assert not admin.execute('select 1 from schema_migrations where version=274').fetchone()
        assert not admin.execute("select 1 from pg_attribute where attrelid='sli_agent_policy_history'::regclass and attname='staged_xact_id'").fetchone()


def test_nonempty_retained_and_acknowledged_packets_survive_reissue(issuer_pg, monkeypatch):
    """Real receipt/import authority; explicit durable publication seam, not full StorageV2."""
    from datetime import datetime, timezone
    import importlib
    from cryptography.hazmat.primitives.asymmetric import ec
    from server.sli.agent_ingest import PostgresLedger, receive_packet
    from server.sli.plugins.ad import event_import
    from server.sli.sources.collection_packet_import import event_rows_from_packet
    from sli_agent.ad_dc import ADDCModule
    from sli_agent.envelope import make_packet
    from tests.unit.test_ad_dc_agent_import import event_xml
    importer = importlib.import_module('scripts.import.import_event_jsonl_to_postgres')
    now = datetime(2026, 10, 7, tzinfo=timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    with connection(issuer_pg) as admin:
        # Restore actual157 receipt columns/ACL omitted by reduced native fixture.
        admin.execute('alter table sli_agent_receipts add column agent_id uuid,add column sequence bigint,add column envelope_sha256 text')
        admin.execute('grant select,insert on sli_agent_receipts,sli_agent_packet_inbox to adlog_user')
        quota = (PATH.parent / '217_agent_inbox_quota_payload_bytes.sql').read_text('utf-8-sig')
        admin.execute(quota[quota.index('alter table public.sli_agent_packet_inbox'):quota.index('insert into public.schema_migrations')])
        admin.execute('alter table servers add column id bigserial,add column role text,add column site_id bigint')
        admin.execute("insert into servers(hostname,is_active,domain_id,role) select 'fixture-dc',true,id,'domain_controller' from domains limit 1")
        lifecycle = (PATH.parent / '073_plugin_lifecycle_registry.sql').read_text('utf-8-sig')
        admin.execute(lifecycle[lifecycle.index('create table plugin_installations_v1'):lifecycle.index('create table plugin_lifecycle_operations_v1')])
        state = (PATH.parent / '152_plugin_state.sql').read_text('utf-8-sig')
        admin.execute(state[state.index('create table plugin_state_v1'):state.index('insert into plugin_state_v1')])
        start = state.index('create function read_plugin_states_v1()')
        admin.execute(state[start:state.index('$$;', start) + 3])
        admin.execute('revoke all on function read_plugin_states_v1() from public;grant execute on function read_plugin_states_v1() to adlog_user')
        admin.execute("""insert into plugin_installations_v1(plugin_id,manifest_id,manifest_sha256,package_version,
          package_lifecycle,desired_activation,observed_health,component_runtime,queue_state,revision,immutable_evidence_count)
          values('sli.ad','fixture',repeat('0',64),'1.0.0','registered','enabled_manual','unknown','running','drained',1,1)""")
        admin.execute('create table fixture_ad_imported(packet_id uuid primary key,policy_revision text,event_rows jsonb)')
        admin.execute('grant insert,select on fixture_ad_imported to adlog_user')
    with connection(issuer_pg, web=True) as web:
        assignment = issue(web)['assigned_modules'][0]
        def sample(record, captured=None, settings=None):
            raw = event_xml('Security', 'Microsoft-Windows-Security-Auditing', 4624, record)
            return ADDCModule(HOST, settings or assignment['config'], reader=lambda *_: [(raw, f'bookmark-{record}')]).collect(
                captured=captured, now=now, channel='Security')
        first = sample(1)
        second = sample(2, {'generation': HOST, 'cursor_after': first.cursor_after})
        packets = [make_packet(key, agent_id=AGENT, sequence=i, sample=value, now=now)
                   for i, value in enumerate((first, second), 1)]
        def admit(value):
            with web.transaction(), web.cursor() as cur:
                identity = policies._agent(cur, AGENT)
                return receive_packet(PostgresLedger(cur), identity=identity, public_key=key.public_key(), value=value, now=now)
        assert admit(packets[0])['status'] == 'committed'
        old = web.execute('select assigned_modules from sli_agent_policy_history where revision=2').fetchone()['assigned_modules']
        current = issue(web, revision=2)['assigned_modules'][0]
        assert admit(packets[0])['status'] == 'duplicate'
        assert admit(packets[1])['status'] == 'committed'  # previously captured R2 through retained history
        third = sample(3, {'generation': HOST, 'cursor_after': second.cursor_after}, current['config'])
        packet3 = make_packet(key, agent_id=AGENT, sequence=3, sample=third, now=now)
        assert admit(packet3)['status'] == 'committed'
        assert web.execute('select assigned_modules from sli_agent_policy_history where revision=2').fetchone()['assigned_modules'] == old
        assert web.execute('select policy_revision from sli_agent_module_bindings').fetchone()['policy_revision'] == '3'
        # Only downstream StorageV2 authorization/publication is substituted.
        # Receipt digest, plugin SQL, source binding and signed native validator are REAL.
        runtime = object()
        monkeypatch.setattr(importer, 'is_authorized_direct_runtime', lambda value: value is runtime)
        def publish(cur, rows, *, source, header, envelope, direct_runtime, **_):
            assert direct_runtime is runtime and rows and source['server_id'] > 0
            cur.execute('insert into fixture_ad_imported values(%s,%s,%s::jsonb)',
                        (envelope['packet_id'], envelope['policy_revision'], json.dumps(rows)))
            return dict(inserted=len(rows), skipped=0)
        monkeypatch.setattr(event_import, 'import_event_rows', publish)
        for value in [*packets, packet3]:
            rows = event_rows_from_packet(value['payload'])
            assert len(rows) == 1
            with web.transaction():
                assert event_import.import_ad_dc_packet(web, rows, packet=value['payload'], envelope=value['envelope'],
                    direct_runtime=runtime) == dict(inserted=1, skipped=0)
        stored = web.execute('select policy_revision,event_rows from fixture_ad_imported order by packet_id').fetchall()
        assert sorted(row['policy_revision'] for row in stored) == ['2', '2', '3']
        assert all(len(row['event_rows']) == 1 for row in stored)
        from server.sli.agents.import_authorization import PacketPending
        broken = dict(packet3['envelope'], payload_sha256='0' * 64)
        with pytest.raises(PacketPending, match='agent_packet_attestation_invalid'), web.transaction():
            event_import.import_ad_dc_packet(web, event_rows_from_packet(packet3['payload']), packet=packet3['payload'], envelope=broken, direct_runtime=runtime)


@pytest.mark.parametrize('worker_first', [True, False])
def test_actual_worker_source_lock_and_issuer_preserve_mapped_domain(issuer_pg, worker_first):
    from tests.migrations.test_password_coverage_domain_migration import _begin, SCOPE
    with connection(issuer_pg, web=True) as web:
        issue(web)
    with connection(issuer_pg) as admin:
        domain = admin.execute('select id from domains limit 1').fetchone()['id']
        admin.execute('update sli_agent_module_bindings set password_detection_domain_id=%s', (domain,))
        admin.execute("""insert into finding_evidence_source_bindings
          select oid,rolname,%s,'sli.windows.ad-dc',%s,%s,'','core_event',7,null,%s
          from pg_roles where rolname=%s""", (SCOPE.installation_id, HOST, HOST, AGENT, issuer_pg[2]))
    ready, pids = Event(), []
    def competing():
        with connection(issuer_pg, web=worker_first, semantic=not worker_first) as other:
            pids.append(other.execute('select pg_backend_pid() as p').fetchone()['p'])
            ready.set()
            with other.transaction():
                return issue(other, revision=2) if worker_first else _begin(other)
    with connection(issuer_pg, web=not worker_first, semantic=worker_first) as first, ThreadPoolExecutor(max_workers=1) as pool:
        with first.transaction():
            _begin(first) if worker_first else issue(first, revision=2)
            future = pool.submit(competing)
            assert ready.wait(3)
            with connection(issuer_pg) as observer:
                deadline = monotonic() + 3
                while monotonic() < deadline:
                    row = observer.execute('select wait_event_type from pg_stat_activity where pid=%s', (pids[0],)).fetchone()
                    if row and row['wait_event_type'] == 'Lock':
                        break
                    sleep(0.01)
                else:
                    pytest.fail('competitor never waited for the canonical source lock')
                if worker_first:
                    # Owner observer demonstrates no agent lock needed while worker owns source/CP.
                    observer.execute('select public.password_v2_configured_identity(%s)', (AGENT,)).fetchone()
        future.result(timeout=8)
    with connection(issuer_pg) as admin:
        assert admin.execute('select password_detection_domain_id from sli_agent_module_bindings').fetchone()['password_detection_domain_id'] == domain
        assert admin.execute('select owner_domain_id from semantic_password_checkpoints').fetchone()['owner_domain_id'] == domain

def test_exact_same_parent_staged_conflict_is_not_old_history(issuer_pg):
    from sli_agent.ad_dc import ADDCModule
    with connection(issuer_pg, web=True) as web:
        with web.transaction():
            module = dict(module_id='sli.windows.ad-dc', enabled=True, config=ADDCModule(HOST, {**CONFIG, 'policy_revision': '2'}).config)
            web.execute("insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) values(%s,2,%s::jsonb,'{}')", (AGENT, json.dumps([module])))
            issue(web)
        assert web.execute('select policy_revision from sli_agent_module_bindings').fetchone()['policy_revision'] == '2'


def test_column_and_private_function_contract(issuer_pg):
    with connection(issuer_pg) as admin:
        row = admin.execute("""select a.atttypid='xid8'::regtype as correct,not a.attnotnull as nullable,d.oid is null as no_default
          from pg_attribute a left join pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum
          where a.attrelid='sli_agent_policy_history'::regclass and a.attname='staged_xact_id'""").fetchone()
        assert row == dict(correct=True, nullable=True, no_default=True)
        assert not admin.execute("""select 1 from pg_proc p cross join lateral aclexplode(p.proacl) a
          where p.proname in('agent_ad_stamp_history','agent_ad_issue_binding') and a.grantee<>p.proowner""").fetchone()
        assert all(row['ok'] for row in admin.execute("""select prosecdef and provolatile='v' and proowner='adlog_storage_owner'::regrole
          and proconfig=array['search_path=pg_catalog, pg_temp'] as ok from pg_proc where proname in('agent_ad_stamp_history','agent_ad_issue_binding')""").fetchall())


@pytest.mark.parametrize('missing', ['installation', 'raw_staging'])
def test_missing_issuance_prerequisites_are_unavailable(issuer_pg, missing):
    import psycopg
    from sli_agent.ad_dc import ADDCModule
    if missing == 'installation':
        with connection(issuer_pg) as admin:
            admin.execute('delete from semantic_default_installation')
    with connection(issuer_pg, web=True) as web:
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_'):
            if missing == 'installation':
                issue(web)
            else:
                module = dict(module_id='sli.windows.ad-dc', enabled=True, config=ADDCModule(HOST, {**CONFIG, 'policy_revision': '2'}).config)
                web.execute('update sli_agents set assigned_modules=%s::jsonb,policy_revision=2 where id=%s', (json.dumps([module]), AGENT))


def test_disabled_inactive_other_owner_still_claims_same_c(issuer_pg):
    import psycopg
    other = str(uuid4())
    with connection(issuer_pg, web=True) as web:
        issue(web)
        issue(web, revision=2, enabled=False)
    with connection(issuer_pg) as admin:
        admin.execute("update sli_agents set status='disabled' where id=%s", (AGENT,))
        admin.execute("insert into sli_agents(id,host_id,status,assigned_modules,policy_revision,collection_policy,rights_probe) values(%s,%s,'active','[]',1,'{}','{}')", (other, HOST))
    with connection(issuer_pg, web=True) as web:
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_claim'):
            issue(web, agent=other)


@pytest.mark.parametrize('guard', ['missing273', 'unauthorized'])
def test_migration_predecessor_and_runtime_install_denial(issuer_base, guard):
    import psycopg
    with connection(issuer_base) as admin:
        if guard == 'missing273':
            admin.execute('delete from schema_migrations where version=273')
    with connection(issuer_base, web=guard == 'unauthorized') as conn:
        with pytest.raises(psycopg.Error):
            conn.execute(PATH.read_text('utf-8-sig'))
        conn.execute('rollback')
    with connection(issuer_base) as admin:
        assert not admin.execute('select 1 from schema_migrations where version=274').fetchone()
        assert not admin.execute("select 1 from pg_attribute where attrelid='sli_agent_policy_history'::regclass and attname='staged_xact_id'").fetchone()


def test_foreign_current_snapshot_commit_stays_foreign(issuer_pg):
    import psycopg
    from sli_agent.ad_dc import ADDCModule
    ready, pids = Event(), []
    def competing():
        with connection(issuer_pg, web=True) as web:
            pids.append(web.execute('select pg_backend_pid() as p').fetchone()['p'])
            ready.set()
            return issue(web)
    module = dict(module_id='sli.windows.ad-dc', enabled=True, config=ADDCModule(HOST, {**CONFIG, 'policy_revision': '2'}).config)
    with ThreadPoolExecutor(max_workers=1) as pool, connection(issuer_pg, web=True) as foreign:
        with foreign.transaction():
            foreign.execute("insert into sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy) values(%s,2,%s::jsonb,'{}')", (AGENT, json.dumps([module])))
            foreign_id = foreign.execute('select pg_current_xact_id()::text as x').fetchone()['x']
            future = pool.submit(competing)
            assert ready.wait(3)
            with connection(issuer_pg) as observer:
                deadline = monotonic() + 3
                while monotonic() < deadline:
                    row = observer.execute('select wait_event_type from pg_stat_activity where pid=%s', (pids[0],)).fetchone()
                    if row and row['wait_event_type'] == 'Lock':
                        break
                    sleep(0.01)
                else:
                    pytest.fail('issuance did not wait for conflicting foreign staged snapshot')
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_staging'):
            future.result(timeout=8)
    with connection(issuer_pg) as admin:
        assert admin.execute('select staged_xact_id::text as x from sli_agent_policy_history where revision=2').fetchone()['x'] == foreign_id
        assert admin.execute('select count(*) as n from sli_agent_module_bindings').fetchone()['n'] == 0


@pytest.mark.parametrize('mapping_first', [True, False])
def test_actual_mapping_writer_and_issuer_both_orderings(issuer_pg, mapping_first):
    from tests.migrations.test_password_coverage_domain_migration import _save, SCOPE
    with connection(issuer_pg, web=True) as web:
        issue(web)
    with connection(issuer_pg) as admin:
        admin.execute("""insert into finding_evidence_source_bindings
          select oid,rolname,%s,'sli.windows.ad-dc',%s,%s,'','core_event',7,null,%s
          from pg_roles where rolname=%s""", (SCOPE.installation_id, HOST, HOST, AGENT, issuer_pg[1]))
    started, pids = Event(), []
    def competing():
        with connection(issuer_pg, web=True) as web:
            pids.append(web.execute('select pg_backend_pid() as p').fetchone()['p'])
            started.set()
            with web.transaction():
                return issue(web, revision=2) if mapping_first else _save(web, revision=3)
    with connection(issuer_pg, web=True) as first, ThreadPoolExecutor(max_workers=1) as pool:
        with first.transaction():
            _save(first, revision=2) if mapping_first else issue(first, revision=2)
            future = pool.submit(competing)
            assert started.wait(3)
            with connection(issuer_pg) as observer:
                deadline = monotonic() + 3
                while monotonic() < deadline:
                    row = observer.execute('select wait_event_type from pg_stat_activity where pid=%s', (pids[0],)).fetchone()
                    if row and row['wait_event_type'] == 'Lock':
                        break
                    sleep(0.01)
                else:
                    pytest.fail('competing mapping/issuance never waited on the serialized agent')
        future.result(timeout=8)
    with connection(issuer_pg) as admin:
        row = admin.execute('select m.policy_revision,m.password_detection_domain_id,a.policy_revision as global_revision from sli_agent_module_bindings m join sli_agents a on a.id=m.agent_id').fetchone()
        assert row['policy_revision'] == '3' and row['global_revision'] == 3
        assert row['password_detection_domain_id'] is not None
        assert admin.execute('select count(*) as n from semantic_password_checkpoints').fetchone()['n'] == 0

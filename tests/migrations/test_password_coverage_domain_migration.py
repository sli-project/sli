"""Existing issued authority only; seeded bindings are disposable setup, not an issuer."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.semantic import password_attack_v2 as pure
from server.sli.storage.evidence_ref import EvidenceScope
from tests.migrations.test_password_attacks_v2_coordinator_migration import (
    coordinator_pg as coordinator_pg,
    reservation_pg as reservation_pg,
    password_pg as password_pg,
    native_pg as native_pg,
    acl_pg as acl_pg,
    _connection, _j,
)
from tests.migrations.test_password_attacks_v2_migration import password_base_pg as original_base

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
ROOT = Path(__file__).resolve().parents[2]
AGENT = '00000000-0000-4000-8000-000000000096'
HOST = '00000000-0000-4000-8000-000000000097'
INSTALLATION = '00000000-0000-4000-8000-000000000099'
SCOPE = EvidenceScope(INSTALLATION, 'sli.windows.ad-dc', HOST, HOST)
RULE = pure.Rule(SCOPE, 'brute')


@pytest.fixture
def password_base_pg(original_base):
    """Only inventory readback fields; shared base restores empty actual prerequisites."""
    import psycopg
    with psycopg.connect(original_base, autocommit=True) as conn:
        agent = (ROOT / 'config/postgres_migrations/156_agent_registry.sql').read_text('utf-8-sig')
        conn.execute("""alter table sli_agents add column key_fingerprint text not null default repeat('0',64),
          add column last_seen timestamptz,add column created_at timestamptz not null default clock_timestamp(),
          add column instance_name text,add column registration_host_name text,add column applied_policy_revision bigint not null default 0,
          add column rights_probe jsonb not null default '{}',add column collection_policy jsonb not null default '{}',
          add column applied_collection_state text not null default 'unknown',add column windows_audit jsonb not null default '{}'""")
        conn.execute(agent[agent.index('create table sli_agent_certificates'):agent.index('create index sli_agent_certificates_agent')])
        removal = (ROOT / 'config/postgres_migrations/177_agent_removal.sql').read_text('utf-8-sig')
        conn.execute(removal[removal.index('create table public.sli_agent_removals'):removal.index('create index sli_agent_removals_operation')])
        conn.execute("grant select on sli_agents,sli_agent_certificates,sli_agent_removals to adlog_user")
        # This reduced password fixture omits unrelated enrollment/AD tables.
        # Empty readback prerequisites exercise the real inventory SELECT and
        # configured-name fallback; the enrollment chain itself is covered by
        # test_agent_group_enrollment_postgres_integration with migration DDL.
        conn.execute("""create table public.sli_agent_group_approval_links
              (request_id uuid,enrollment_token_id uuid);
            create table public.sli_agent_group_requests
              (id uuid primary key,computer_version_id bigint);
            create table public.ad_context_entity_versions
              (id bigint primary key,attributes_json jsonb);
            grant select on public.sli_agent_group_approval_links,
              public.sli_agent_group_requests,public.ad_context_entity_versions to adlog_user;""")
        conn.execute("insert into forests(name) values('fixture.invalid') on conflict do nothing")
        conn.execute("insert into domains(forest_id,fqdn) select id,'fixture.invalid' from forests where name='fixture.invalid'")
        conn.execute("insert into domains(forest_id,fqdn) select id,'other.invalid' from forests where name='fixture.invalid'")
    return original_base


@pytest.fixture
def coverage_pg(coordinator_pg):
    from psycopg import sql
    web = 'sli_test_password_coverage_' + uuid4().hex
    config = dict(source_name='fixture-issued', connect_address='fixture-issued', policy_revision='2',
                  channels={'Security': True}, channel_generations={})
    with _connection(coordinator_pg) as admin:
        admin.execute(sql.SQL('create role {} login').format(sql.Identifier(web)))
        admin.execute(sql.SQL('grant adlog_user to {}').format(sql.Identifier(web)))
        admin.execute("insert into sli_agents(id,host_id,status,assigned_modules,policy_revision) values(%s,%s,'active',%s::jsonb,7)",
                      (AGENT, HOST, _j([dict(module_id='sli.windows.ad-dc', enabled=True, config=config)])))
        admin.execute("insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision) values(%s,'sli.windows.ad-dc',%s,'fixture-issued','ad-dc','1.0.0','2')", (AGENT, HOST))
        admin.execute("update semantic_default_installation set installation_id=%s", (INSTALLATION,))
        admin.execute("insert into finding_evidence_source_bindings select oid,rolname,%s,'sli.windows.ad-dc',%s,%s,'','core_event',7,null,%s from pg_roles where rolname=%s",
                      (INSTALLATION, HOST, HOST, AGENT, coordinator_pg[1]))
    try:
        yield coordinator_pg, web
    finally:
        with _connection(coordinator_pg) as admin:
            admin.execute(sql.SQL('drop role {}').format(sql.Identifier(web)))


@contextmanager
def _web(source):
    from psycopg import sql
    with _connection(source[0]) as conn:
        conn.execute(sql.SQL('set session authorization {}').format(sql.Identifier(source[1])))
        yield conn


def _save(conn, expected=None, fqdn='fixture.invalid', revision=7, actor='session:1'):
    return conn.execute('select provision_password_detection_domain_v2(%s,%s,%s,%s,%s) as v',
                        (AGENT, revision, expected, fqdn, actor)).fetchone()['v']


def _domain(admin, fqdn='fixture.invalid'):
    return admin.execute('select id from domains where fqdn=%s', (fqdn,)).fetchone()['id']


def _page(web, domains):
    from server.sli.reporting.read_timeout import report_read_budget, remaining_read_ms, watch_read_connection
    with report_read_budget(), web.transaction():
        watch_read_connection(web)
        web.execute("select set_config('statement_timeout',%s,true),set_config('lock_timeout',%s,true)",
                    (str(remaining_read_ms()), str(min(1000, remaining_read_ms()))))
        return web.execute('select read_password_detection_coverage(%s::bigint[]) as v', (domains,)).fetchone()['v']


def _begin(conn, rule=RULE):
    return conn.execute('select begin_password_attempt(%s::jsonb,%s::jsonb) as v',
                        (_j(asdict(rule.scope)), _j(rule.execution))).fetchone()['v']


def test_existing_binding_owner_mapping_exact_pins_without_checkpoint(coverage_pg):
    with _connection(coverage_pg[0]) as admin:
        domain = _domain(admin)
        before = admin.execute('select assigned_modules,policy_revision from sli_agents where id=%s', (AGENT,)).fetchone()
    with _web(coverage_pg) as web:
        assert _save(web) == dict(status='configured', domain_id=domain, domain_fqdn='fixture.invalid')
        page = _page(web, [domain])
        assert len(page['rows']) == 2 and not page['has_more']
        assert {row['rule_id'] for row in page['rows']} == {'qw.password-brute-force', 'qw.password-spray'}
        digest = bytes.fromhex(pure._digest(asdict(SCOPE)))
        assert {row['scope_ref'] for row in page['rows']} == {
            sha256(digest + bytes.fromhex(pure.Rule(SCOPE, kind).pin)).hexdigest() for kind in ('brute', 'spray')}
        assert all(row['status'] == 'unknown' and row['policy_state'] == 'unknown' for row in page['rows'])
        assert all(row['last_completed_at'] is None and row['loss'] == {} for row in page['rows'])
        assert _save(web, domain)['status'] == 'unchanged'
        assert _page(web, [])['rows'] == []
    with _connection(coverage_pg[0]) as admin:
        assert admin.execute('select assigned_modules,policy_revision from sli_agents where id=%s', (AGENT,)).fetchone() == before
        assert admin.execute('select count(*) as n from semantic_password_checkpoints').fetchone()['n'] == 0
        assert admin.execute("select count(*) as n from sli_agent_audit where action='password_domain_bind'").fetchone()['n'] == 1


@pytest.mark.parametrize('missing', ['module', 'native', 'installation', 'issued'])
def test_missing_authority_never_creates_or_reconstructs_source(coverage_pg, missing):
    with _connection(coverage_pg[0]) as admin:
        statement = {'module': 'delete from sli_agent_module_bindings where agent_id=%s',
                     'native': 'delete from finding_evidence_source_bindings where agent_id=%s',
                     'issued': "update sli_agents set assigned_modules='[]' where id=%s",
                     'installation': 'delete from semantic_default_installation'}[missing]
        admin.execute(statement, () if missing == 'installation' else (AGENT,))
    with _web(coverage_pg) as web:
        assert _save(web)['status'] == 'unavailable'
    with _connection(coverage_pg[0]) as admin:
        assert admin.execute("select count(*) as n from sli_agent_audit where action='password_domain_bind'").fetchone()['n'] == 0


def test_mapping_cas_no_transfer_and_cp_creation_copy(coverage_pg):
    import psycopg
    with _web(coverage_pg) as web:
        domain = _save(web)['domain_id']
        with pytest.raises(psycopg.errors.SerializationFailure, match='domain_conflict'):
            _save(web)
        with pytest.raises(psycopg.errors.SerializationFailure, match='revision_conflict'):
            _save(web, domain, revision=2)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match='ownership_immutable'):
            _save(web, domain, fqdn='other.invalid')
    with _connection(coverage_pg[0], worker=True) as worker:
        _begin(worker)
    with _connection(coverage_pg[0]) as admin:
        assert admin.execute('select owner_domain_id from semantic_password_checkpoints').fetchone()['owner_domain_id'] == domain


def test_reader_and_writer_narrow_real_role_privileges(coverage_pg):
    import psycopg
    with _web(coverage_pg) as web:
        _save(web)
        for statement in ('select * from semantic_password_checkpoints', 'select * from semantic_password_episode_budgets',
                          'select * from finding_evidence_source_bindings', "update sli_agent_module_bindings set source_name='forged'"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                web.execute(statement)
    with _connection(coverage_pg[0], worker=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _save(worker)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _page(worker, [])


def test_explicit_null_adoption_and_both_columns_immutable_in_database(coverage_pg):
    import psycopg
    with _connection(coverage_pg[0], worker=True) as worker:
        _begin(worker)
    with _connection(coverage_pg[0]) as admin:
        before = admin.execute('select to_jsonb(c) as v from semantic_password_checkpoints c').fetchone()['v']
        assert before['owner_domain_id'] is None
    with _web(coverage_pg) as web:
        domain = _save(web)['domain_id']
    with _connection(coverage_pg[0]) as admin:
        after = admin.execute('select to_jsonb(c) as v from semantic_password_checkpoints c').fetchone()['v']
        assert {**before, 'owner_domain_id': domain} == after
        for table, column in [('semantic_password_checkpoints', 'owner_domain_id'), ('sli_agent_module_bindings', 'password_detection_domain_id')]:
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match='ownership_immutable'):
                admin.execute(f'update {table} set {column}=null')


@pytest.mark.parametrize('owner_first', [False, True])
def test_source_lock_serializes_copy_and_explicit_adoption_both_directions(coverage_pg, owner_first):
    import time
    from threading import Event

    started = Event()
    def concurrent():
        with (_connection(coverage_pg[0], worker=True) if owner_first else _web(coverage_pg)) as other:
            started.set()
            return _begin(other) if owner_first else _save(other)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with (_web(coverage_pg) if owner_first else _connection(coverage_pg[0], worker=True)) as first:
            with first.transaction():
                _save(first) if owner_first else _begin(first)
                task = pool.submit(concurrent)
                assert started.wait(2)
                with _connection(coverage_pg[0]) as admin:
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        waiting = admin.execute("select exists(select 1 from pg_locks where locktype='advisory' and not granted) as v").fetchone()['v']
                        if waiting:
                            break
                        time.sleep(0.02)
                    assert waiting and not task.done()
            task.result(timeout=4)
    with _connection(coverage_pg[0]) as admin:
        assert admin.execute('select owner_domain_id from semantic_password_checkpoints').fetchone()['owner_domain_id'] == _domain(admin)


def test_audit_failure_rolls_back_mapping_and_null_adoption(coverage_pg):
    import psycopg
    with _connection(coverage_pg[0], worker=True) as worker:
        _begin(worker)
    with _connection(coverage_pg[0]) as admin:
        admin.execute("create function fixture_reject_domain_audit() returns trigger language plpgsql as $$ begin raise exception 'fixture_audit_rejected'; end $$")
        admin.execute('create trigger fixture_reject_domain_audit before insert on sli_agent_audit for each row execute function fixture_reject_domain_audit()')
    with _web(coverage_pg) as web:
        with pytest.raises(psycopg.errors.RaiseException, match='fixture_audit_rejected'):
            _save(web)
    with _connection(coverage_pg[0]) as admin:
        assert admin.execute('select owner_domain_id from semantic_password_checkpoints').fetchone()['owner_domain_id'] is None
        assert admin.execute('select password_detection_domain_id from sli_agent_module_bindings').fetchone()['password_detection_domain_id'] is None


@pytest.mark.parametrize('conflict', ['native', 'principal', 'issued_R', 'generation'])
def test_mapped_source_missing_or_conflicting_identity_fails_whole_projection(coverage_pg, conflict):
    import psycopg
    with _web(coverage_pg) as web:
        domain = _save(web)['domain_id']
    with _connection(coverage_pg[0]) as admin:
        if conflict == 'native':
            admin.execute("insert into finding_evidence_source_bindings select r.oid,r.rolname,b.installation_id,b.plugin_id,b.source_instance_id,b.source_generation,b.collection_scope_id,b.storage_kind,8,null,b.agent_id from finding_evidence_source_bindings b cross join pg_roles r where b.agent_id=%s and r.rolname=session_user", (AGENT,))
        elif conflict == 'principal':
            admin.execute("update finding_evidence_source_bindings set principal_name='fixture_stale' where agent_id=%s", (AGENT,))
        elif conflict == 'issued_R':
            admin.execute("update sli_agent_module_bindings set policy_revision='7' where agent_id=%s", (AGENT,))
        else:
            admin.execute("update finding_evidence_source_bindings set source_generation='fixture-other-generation' where agent_id=%s", (AGENT,))
    with _web(coverage_pg) as web:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match='metadata_unavailable'):
            _page(web, [domain])
        assert _page(web, [])['rows'] == []


def _policy(admin, rule=RULE, *, name='fixture-current-v2', enabled=True):
    definition = {'source_selector': {'execution': rule.execution}}
    digest = bytes.fromhex(pure._digest(definition))
    admin.execute("insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256) values(%s,1,'qw_signal','draft',%s::jsonb,%s)", (name, _j(definition), digest))
    admin.execute("insert into semantic_risk_policy_subscriptions values(%s,1,'qw_signal',%s,%s)", (name, rule.execution['rule_id'], digest))
    admin.execute("update semantic_risk_policies set lifecycle_status='enabled' where policy_id=%s", (name,))
    admin.execute('insert into semantic_policy_admission(policy_id,policy_version,enabled) values(%s,1,%s)', (name, enabled))


def _healthy(admin, *, age=0):
    admin.execute("update semantic_password_checkpoints set health_status='healthy',health_reason=null,last_completed_at=clock_timestamp()-(%s*interval '1 second') where pin=%s", (age, RULE.pin))


def test_current_policy_disable_precedence_ttl_loss_large_decimal_and_no_null_coalesce(coverage_pg):
    from server.sli.semantic import findings
    with _connection(coverage_pg[0], worker=True) as worker:
        _begin(worker)
    with _connection(coverage_pg[0]) as admin:
        domain = _domain(admin)
        # Owner setup isolates missing adoption: a module FK alone cannot expose CP data.
        admin.execute('update sli_agent_module_bindings set password_detection_domain_id=%s where agent_id=%s', (domain, AGENT))
        _policy(admin)
        _healthy(admin)
    with _web(coverage_pg) as web:
        page = _page(web, [domain])
        brute = next(row for row in page['rows'] if row['rule_id'] == RULE.execution['rule_id'])
        assert brute['last_completed_at'] is None and brute['status'] == 'unknown'
        _save(web, domain)  # explicit exact-current-C NULL adoption
        before = _page(web, [domain])
        assert next(row for row in before['rows'] if row['rule_id'] == RULE.execution['rule_id'])['status'] == 'healthy'
    with _connection(coverage_pg[0]) as admin:
        _healthy(admin, age=300)
    with _web(coverage_pg) as web:
        brute = next(row for row in _page(web, [domain])['rows'] if row['rule_id'] == RULE.execution['rule_id'])
        assert brute['status'] == 'stale' and brute['reason'] == 'attempt_stale'
    with _connection(coverage_pg[0]) as admin:
        _healthy(admin)
        admin.execute("""update semantic_password_checkpoints set loss_buckets=jsonb_build_object('missing_target',
          jsonb_build_array(jsonb_build_object('count',9007199254740993,'hour',1,'observed_min',public.password_v2_iso(clock_timestamp()-interval '1 hour'),
          'observed_max',public.password_v2_iso(clock_timestamp()),'from',null,'to',null)) || (select jsonb_agg(null::jsonb) from generate_series(1,24))) where pin=%s""", (RULE.pin,))
    with _web(coverage_pg) as web:
        page = _page(web, [domain])
        parsed = findings._password_coverage_page(page, {domain})
        brute = next(row for row in parsed['rows'] if row['rule_id'] == RULE.execution['rule_id'])
        assert brute['status'] == 'partial' and brute['loss']['missing_target']['count_lower_bound'] == '9007199254740993'
    with _connection(coverage_pg[0]) as admin:
        _policy(admin, name='fixture-custom-disabled', enabled=False)
    with _web(coverage_pg) as web:
        assert next(row for row in _page(web, [domain])['rows'] if row['rule_id'] == RULE.execution['rule_id'])['policy_state'] == 'disabled'


def test_retained_owned_frozen_scope_survives_retirement_and_loss_aging(coverage_pg):
    from dataclasses import replace
    from tests.migrations.test_password_attacks_v2_reservation_migration import _historical, _root
    with _web(coverage_pg) as web:
        domain = _save(web)['domain_id']
    with _connection(coverage_pg[0]) as admin:
        root = _root()
        _historical(admin, [root])
        old = pure.State.from_document(admin.execute('select state_document from semantic_password_checkpoints').fetchone()['state_document'])
        frozen = replace(old, episodes=(replace(old.episodes[0], frozen=True),))
        # Historical fixture only; public B2 behavior has its independent gate.
        from tests.migrations.test_password_attacks_v2_reservation_migration import _begin as old_begin
        token = old_begin(admin)
        with admin.transaction():
            admin.execute("update semantic_password_episode_budgets set frozen=true,frozen_at=clock_timestamp(),frozen_reason='episode_evidence_budget_exhausted',barrier_unresolved=true,tracking_endpoint=last_admitted_endpoint,tracking_epoch=0,tracking_through=(last_admitted_endpoint->>'at')::timestamptz")
            admin.execute("update semantic_password_checkpoints set owner_domain_id=%s,state_document=%s::jsonb,state_revision=state_revision+1,last_observed_token=%s,last_completed_at=clock_timestamp()-interval '25 hours'", (domain, _j(frozen.document), token['token']))
        snapshot = admin.execute('select last_admitted_as_of from semantic_password_episode_budgets').fetchone()['last_admitted_as_of']
    with _web(coverage_pg) as web:
        page = _page(web, [domain])
        assert len(page['rows']) == 3
        retained = next(row for row in page['rows'] if row['frozen_episode_count'])
        assert retained['status'] == 'frozen' and retained['policy_state'] == 'unknown'
        assert retained['frozen_episode_count'] == 1
        assert retained['evidence_snapshot_as_of'] == snapshot.isoformat()
        assert _page(web, [domain + 10000])['rows'] == []


def test_real_report_budget_cancels_locked_projection_and_b4_returns_unavailable(coverage_pg, monkeypatch):
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.semantic import findings
    from server.sli.reporting.read_timeout import report_read_budget
    import time

    with _web(coverage_pg) as web:
        domain = _save(web)['domain_id']
    @contextmanager
    def connection():
        with _web(coverage_pg) as web, web.transaction():
            yield web
    monkeypatch.setattr(postgres_runtime_pipeline, 'connect', connection)
    monkeypatch.setenv('ADLOG_REPORT_READ_TIMEOUT_MS', '150')
    with _connection(coverage_pg[0]) as admin, admin.transaction():
        admin.execute('lock table semantic_password_episode_budgets in access exclusive mode')
        started = time.monotonic()
        with report_read_budget():
            result = findings._read_password_detection_coverage([domain])
        assert time.monotonic() - started < 3
        assert result == dict(availability='unavailable', as_of=None, rows=[], has_more=False)


@pytest.mark.parametrize('case', ['owner', 'manager', 'viewer', 'unauthenticated', 'origin', 'cas', 'unavailable',
    'api_key_manager', 'api_key_denied', 'report_key_denied', 'forged_actor'])
def test_same_ui_fixture_through_real_http_owner_dispatch_sql_and_inventory(coverage_pg, monkeypatch, case):
    """No HTTP socket/session store: principal loader only is shimmed; real guards/parser/dispatch/SQL run."""
    import io
    from email.message import Message
    from http import HTTPStatus
    from server.api import http_server
    from server.api.routes import agents

    raw = (ROOT / 'frontend/src/test-fixtures/password_detection_domain_ui_request.json').read_bytes()
    assert sha256(raw.replace(b'\r\n', b'\n')).hexdigest() == '9cdeebd1bbf8975a361d56e38fd13ea2857dc3d4e0fc1c842b62d8424f412a26'
    body = json.loads(raw)
    request_raw = json.dumps({**body, 'actor': 'api_key:999'}).encode() if case == 'forged_actor' else raw
    with _connection(coverage_pg[0]) as admin:
        admin.execute('insert into sli_agents(id,host_id,status,assigned_modules,policy_revision) select %s,host_id,status,assigned_modules,policy_revision from sli_agents where id=%s', (body['agent_id'], AGENT))
        admin.execute('update sli_agent_module_bindings set agent_id=%s where agent_id=%s', (body['agent_id'], AGENT))
        admin.execute('update finding_evidence_source_bindings set agent_id=%s where agent_id=%s', (body['agent_id'], AGENT))
        admin.execute('delete from sli_agents where id=%s', (AGENT,))
        admin.execute('update domains set fqdn=%s where fqdn=%s', (body['password_detection_domain']['fqdn'], 'fixture.invalid'))
        if case == 'cas':
            admin.execute('update sli_agents set policy_revision=8 where id=%s', (body['agent_id'],))
        if case == 'unavailable':
            admin.execute('delete from sli_agent_module_bindings where agent_id=%s', (body['agent_id'],))
    @contextmanager
    def connection():
        with _web(coverage_pg) as web:
            # Actual _execute owns commit/rollback; no nested Transaction proxy.
            web.autocommit = False
            assert web.execute('select session_user as u').fetchone()['u'] == coverage_pg[1]
            yield web
    monkeypatch.setattr(agents, 'connect', connection)
    monkeypatch.setattr(http_server, 'auth_required', lambda: True)
    key_case = case in {'api_key_manager', 'api_key_denied', 'report_key_denied', 'forged_actor'}
    principal = {'type': 'api_key' if key_case else 'session', 'id': 42, 'role': 'admin'}
    if case == 'report_key_denied':
        principal.update(role='viewer', report_subject_id=99)
    monkeypatch.setattr(http_server, 'principal_from_headers', lambda _: None if case == 'unauthenticated' else principal)
    handler = object.__new__(http_server.RequestHandler)
    handler.headers = Message()
    handler.command = 'POST'
    handler.headers['Content-Length'] = str(len(request_raw))
    if key_case:
        handler.headers['Authorization'] = 'Bearer fixture-not-a-real-key'
    handler.headers['Content-Type'] = 'application/json'
    if case == 'origin':
        # Duplicate Origin uses the real guard and needs no request/server reconstruction.
        handler.headers['Origin'] = 'https://fixture.invalid'
        handler.headers['Origin'] = 'https://other.invalid'
    class Socket:
        def gettimeout(self):
            return None
        def settimeout(self, _):
            pass
    handler.connection = Socket()
    handler.rfile = io.BufferedReader(io.BytesIO(request_raw))
    handler._effective_access_cache = {'platform_owner': case in {'owner', 'cas', 'unavailable'},
        'capabilities': ['access.manage'] if case in {'manager', 'api_key_manager', 'report_key_denied', 'forged_actor'} else []}
    responses = []
    handler._send_json = lambda value, status=HTTPStatus.OK, **_: responses.append((int(status), value))
    # The existing outer key-route guard runs before the unchanged agent dispatcher.
    if handler._require_secure_api_transport('/api/v1/admin/agents/modules'):
        assert agents.try_handle_post(handler, '/api/v1/admin/agents/modules')
    expected = {'viewer': 403, 'unauthenticated': 401, 'origin': 403, 'cas': 409,
        'api_key_denied': 403, 'report_key_denied': 403, 'forged_actor': 400}.get(case, 200)
    assert responses[-1][0] == expected
    if case in {'owner', 'manager', 'api_key_manager'}:
        assert responses[-1][1]['password_detection_domain']['status'] == 'configured'
        assert agents.try_handle_get(handler, '/api/v1/admin/agents', {'agent_id': [body['agent_id']]})
        assert responses[-1][0] == 200
        assert responses[-1][1]['items'][0]['host_name'] == 'fixture-issued'
        item = responses[-1][1]['items'][0]
        assert item['password_detection_domain']['domain_fqdn'] == body['password_detection_domain']['fqdn']
        assert 'password_detection_domain' not in item['assigned_modules'][0]
        assert item['policy_revision'] == 7 and item['assigned_modules'][0]['config']['policy_revision'] == '2'
        with _connection(coverage_pg[0]) as admin:
            assert admin.execute("select actor from sli_agent_audit where action='password_domain_bind'").fetchone()['actor'] == f"{principal['type']}:42"
    elif case == 'unavailable':
        assert responses[-1][1]['password_detection_domain']['status'] == 'unavailable'
    else:
        with _connection(coverage_pg[0]) as admin:
            assert admin.execute("select count(*) as n from sli_agent_audit where action='password_domain_bind'").fetchone()['n'] == 0


def test_projection_filters_domains_before_257_sentinel_and_retains_exact_pin_rows(coverage_pg):
    with _web(coverage_pg) as web:
        domain = _save(web)['domain_id']
    with _connection(coverage_pg[0]) as admin:
        # Already-issued synthetic authority only; fixture does not implement issuance.
        admin.execute("""with extra as (select gen_random_uuid() as id,gen_random_uuid()::text as host from generate_series(1,128))
          insert into sli_agents(id,host_id,status,assigned_modules,policy_revision)
          select id,host,'active',(select assigned_modules from sli_agents where id=%s),7 from extra""", (AGENT,))
        admin.execute("""insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision,password_detection_domain_id)
          select a.id,'sli.windows.ad-dc',a.host_id,'fixture-issued','ad-dc','1.0.0','2',%s from sli_agents a
          where a.id<>%s and not exists(select 1 from sli_agent_module_bindings m where m.agent_id=a.id) and a.policy_revision=7""", (domain, AGENT))
        admin.execute("""insert into finding_evidence_source_bindings
          select r.oid,r.rolname,%s,'sli.windows.ad-dc',m.source_instance_id,m.source_instance_id,'','core_event',7,null,m.agent_id
          from sli_agent_module_bindings m cross join pg_roles r
          where m.agent_id<>%s and m.password_detection_domain_id=%s and r.rolname=%s""", (INSTALLATION, AGENT, domain, coverage_pg[0][1]))
    with _web(coverage_pg) as web:
        page = _page(web, [domain])
        assert len(page['rows']) == 256 and page['has_more'] is True
        assert all(row['domain_id'] == domain for row in page['rows'])
        empty = _page(web, [domain + 10000])
        assert empty['rows'] == [] and empty['has_more'] is False


def test_public_empty_producer_completion_preserves_24h_loss_then_ages_it_honestly(coverage_pg):
    from server.sli.semantic.password_attack_producer import run_password_producer
    from server.sli.semantic import findings
    with _web(coverage_pg) as web:
        domain = _save(web)['domain_id']
    with _connection(coverage_pg[0]) as admin:
        _policy(admin)
    with _connection(coverage_pg[0], worker=True) as worker:
        completed = run_password_producer(worker, rule=RULE)
        assert completed.status == 'committed' and not completed.failed and completed.jobs == 0
    with _connection(coverage_pg[0]) as admin:
        admin.execute("""update semantic_password_checkpoints set loss_buckets=jsonb_build_object('too_late',
          jsonb_build_array(jsonb_build_object('count',9007199254740993,'hour',1,'observed_min',public.password_v2_iso(clock_timestamp()-interval '1 hour'),
          'observed_max',public.password_v2_iso(clock_timestamp()),'from',null,'to',null),
          jsonb_build_object('count',400,'hour',2,'observed_min',public.password_v2_iso(clock_timestamp()-interval '25 hours'),
          'observed_max',public.password_v2_iso(clock_timestamp()-interval '23 hours'),'from',null,'to',null))
          || (select jsonb_agg(null::jsonb) from generate_series(1,23))) where pin=%s""", (RULE.pin,))
    with _connection(coverage_pg[0], worker=True) as worker:
        assert run_password_producer(worker, rule=RULE).status == 'committed'
    with _web(coverage_pg) as web:
        page = findings._password_coverage_page(_page(web, [domain]), {domain})
        row = next(row for row in page['rows'] if row['rule_id'] == RULE.execution['rule_id'])
        assert row['status'] == 'partial'
        assert row['loss']['too_late']['count_lower_bound'] == '9007199254740994'
        assert row['loss']['too_late']['count_exact'] is False
    with _connection(coverage_pg[0]) as admin:
        admin.execute("""update semantic_password_checkpoints set loss_buckets=jsonb_build_object('too_late',
          jsonb_build_array(jsonb_build_object('count',1,'hour',1,'observed_min',public.password_v2_iso(clock_timestamp()-interval '25 hours'),
          'observed_max',public.password_v2_iso(clock_timestamp()-interval '25 hours'),'from',null,'to',null))
          || (select jsonb_agg(null::jsonb) from generate_series(1,24))) where pin=%s""", (RULE.pin,))
    with _connection(coverage_pg[0], worker=True) as worker:
        assert run_password_producer(worker, rule=RULE).status == 'committed'
    with _web(coverage_pg) as web:
        row = next(row for row in _page(web, [domain])['rows'] if row['rule_id'] == RULE.execution['rule_id'])
        assert row['status'] == 'healthy' and row['loss'] == {}


@pytest.mark.parametrize('domains', [None, [None], [0], [-1]])
def test_sql_null_or_invalid_allowed_domain_argument_rejects(coverage_pg, domains):
    import psycopg
    with _web(coverage_pg) as web:
        with pytest.raises(psycopg.errors.InvalidParameterValue, match='arguments_invalid'):
            _page(web, domains)


def test_identical_live_principal_metadata_copies_dedup_without_forking_scope(coverage_pg):
    with _web(coverage_pg) as web:
        domain = _save(web)['domain_id']
        before = _page(web, [domain])['rows']
    with _connection(coverage_pg[0]) as admin:
        admin.execute("insert into finding_evidence_source_bindings select r.oid,r.rolname,b.installation_id,b.plugin_id,b.source_instance_id,b.source_generation,b.collection_scope_id,b.storage_kind,b.log_source_id,b.agent_key,b.agent_id from finding_evidence_source_bindings b cross join pg_roles r where b.agent_id=%s and r.rolname=session_user", (AGENT,))
    with _web(coverage_pg) as web:
        assert _page(web, [domain])['rows'] == before


def test_v1_only_policy_and_heartbeat_never_certify_v2_health(coverage_pg):
    from types import SimpleNamespace
    with _web(coverage_pg) as web:
        domain = _save(web)['domain_id']
    with _connection(coverage_pg[0], worker=True) as worker:
        _begin(worker)
    with _connection(coverage_pg[0]) as admin:
        _policy(admin, rule=SimpleNamespace(execution={**RULE.execution, 'rule_version': 1}), name='fixture-v1-only')
        _healthy(admin)
    with _web(coverage_pg) as web:
        row = next(row for row in _page(web, [domain])['rows'] if row['rule_id'] == RULE.execution['rule_id'])
        assert row['policy_state'] == 'unknown' and row['status'] == 'unknown' and row['reason'] == 'policy_unconfirmed'


@pytest.mark.parametrize('actor', ['service:42', 'session:0', 'api_key:0', 'api_key:-1', 'api_key:01',
    'session:+1', 'api_key:42suffix', None, ' session:42', 'api_key:42\n', 'api_key:' + '1' * 128])
def test_writer_rejects_non_server_actor_forms_without_mapping_or_audit(coverage_pg, actor):
    import psycopg
    with _web(coverage_pg) as web:
        with pytest.raises(psycopg.errors.InvalidParameterValue, match='arguments_invalid'):
            _save(web, actor=actor)
    with _connection(coverage_pg[0]) as admin:
        assert admin.execute('select password_detection_domain_id from sli_agent_module_bindings').fetchone()['password_detection_domain_id'] is None
        assert admin.execute("select count(*) as n from sli_agent_audit where action='password_domain_bind'").fetchone()['n'] == 0

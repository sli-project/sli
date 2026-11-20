"""Managed password metadata on disposable PG, physical semantic/web LOGINs.

Reuses actual265/273 source authority. Existing issued bindings/domain are fixture
setup; unrelated274 marker is synthetic, not normal issuer/bootstrap acceptance.
No native reader, CP, producer, queue, real source or owner route is invoked.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from threading import Event
from time import monotonic, sleep
from uuid import uuid4

import pytest

from server.sli.semantic import password_attacks
from server.sli.semantic.password_attack_v2 import Rule
from server.sli.semantic.semantic_governance import set_policy_admission
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition
from server.sli.semantic.semantic_risk_runtime_repository import register_risk_policy, transition_risk_policy
from tests.migrations.test_password_coverage_domain_migration import (
    AGENT, SCOPE,
    coverage_pg as coverage_pg, password_base_pg as password_base_pg,
    coordinator_pg as coordinator_pg, reservation_pg as reservation_pg,
    password_pg as password_pg, native_pg as native_pg, acl_pg as acl_pg,
    original_base as original_base,
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config/postgres_migrations/275_password_policy_management.sql'


def policy(kind='brute', *, legacy=False, custom=None):
    execution = password_attacks.execution(SCOPE, 'qw.password-brute-force' if kind == 'brute' else 'qw.password-spray') if legacy else Rule(SCOPE, kind).execution
    identifier = custom or 'default:' + execution['rule_id'] + ':' + sha256(
        json.dumps(execution, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:32]
    old = password_attacks.risk_policy(SCOPE, execution['rule_id'], policy_id=identifier)
    document = deepcopy(dict(old.definition))
    document['source_selector']['execution'] = execution
    document['merge_window_seconds'] = 300 if legacy else 600
    return RiskPolicyDefinition(policy_id=identifier, policy_version=1, source_kind=old.source_kind, definition=document)


@contextmanager
def connection(source, *, worker=False, web=False, writer=False):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    login = source[1] if worker else source[2] if web else source[3] if writer else None
    with psycopg.connect(make_conninfo(source[0], user=login) if login else source[0],
                         autocommit=True, row_factory=dict_row) as conn:
        if login:
            roles = conn.execute("select session_user as login,current_user as role,"
                "pg_has_role(session_user,'adlog_storage_owner','MEMBER') as owner,"
                "pg_has_role(session_user,'adlog_user','MEMBER') as app,"
                "pg_has_role(session_user,'adlog_semantic_worker','MEMBER') as semantic").fetchone()
            assert roles['login'] == login and roles['role'] == login and not roles['owner']
            assert roles['app'] is web and roles['semantic'] is worker
        yield conn


@pytest.fixture
def managed_base_pg(coverage_pg, request):
    import psycopg
    from psycopg import sql
    writer = 'sli_test_password_writer_' + uuid4().hex
    source = coverage_pg[0][0], coverage_pg[0][1], coverage_pg[1], writer
    with psycopg.connect(source[0], autocommit=True) as admin:
        admin.execute("insert into schema_migrations values(274,'agent_ad_binding_issuer')")
        # Restore actual153 metadata/default and050/029/153 grants omitted by
        # the reduced265 queue fixture, with no fabricated source verifier.
        admin.execute("alter table semantic_policy_admission add column updated_at timestamptz not null default now()")
        admin.execute("alter table semantic_control_audit alter occurred_at set default clock_timestamp()")
        admin.execute("grant select on semantic_risk_policies,semantic_policy_admission,semantic_risk_policy_subscriptions to adlog_semantic_worker,adlog_user")
        admin.execute("grant select,insert,update on semantic_risk_policies to adlog_semantic_worker")
        admin.execute("grant select,insert,update on semantic_policy_admission to adlog_user")
        admin.execute("grant select on semantic_control_audit to adlog_user")
        admin.execute("grant update(updated_at) on semantic_risk_policies to adlog_user")
        # Actual029 storage writer surface, on the same disposable reduced tables.
        admin.execute('grant select,insert,update on semantic_risk_policies,semantic_risk_policy_subscriptions to adlog_storage_worker')
        admin.execute('grant delete on semantic_risk_policy_subscriptions to adlog_storage_worker')
        admin.execute(sql.SQL('create role {} login').format(sql.Identifier(writer)))
        admin.execute(sql.SQL('grant adlog_storage_worker to {}').format(sql.Identifier(writer)))
        if getattr(request.node, 'callspec', None) is None or request.node.callspec.params.get('missing') != 'domain':
            admin.execute('update sli_agent_module_bindings set password_detection_domain_id=%s where agent_id=%s',
                          (_domain_query(admin), AGENT))
    try:
        yield source
    finally:
        with psycopg.connect(source[0], autocommit=True) as admin:
            admin.execute(sql.SQL('drop role {}').format(sql.Identifier(writer)))


@pytest.fixture
def managed_pg(managed_base_pg):
    with connection(managed_base_pg) as admin:
        if PATH.exists():
            admin.execute(PATH.read_text('utf-8-sig'))
    return managed_base_pg


def _domain_query(conn):
    return conn.execute("select id from domains where fqdn='fixture.invalid'").fetchone()[0]


def _count(conn):
    return conn.execute("select count(*) as n from semantic_risk_policies where definition_json#>'{source_selector,execution,scope}'=%s::jsonb",
                        (json.dumps(asdict(SCOPE)),)).fetchone()['n']


def ensure(conn, item=None):
    item = item or policy()
    return conn.execute('select public.ensure_default_qw_policy(%s,%s,%s) as v',
                        (item.policy_id, item.policy_version, item.definition_json)).fetchone()['v']


def decision(source, item=None):
    item = item or policy()
    with connection(source) as admin:
        return admin.execute('select password_v2_coverage_policy(%s::jsonb) as v',
                             (json.dumps(item.definition['source_selector']['execution']),)).fetchone()['v']


def owner_choice(source, item, enabled, *, audit=None):
    with connection(source, web=True) as web, web.transaction(), web.cursor() as cur:
        set_policy_admission(cur, item.policy_id, item.policy_version, enabled, actor='session:42',
                             reason='Synthetic owner choice', audit=audit or (lambda *args: None))


def custom(source, item, *, state='shadow'):
    # Existing custom policy metadata only, equivalent029 register/subscribe.
    # Actual owner governance entry below supplies the decision and real153 audit.
    with connection(source) as admin:
        admin.execute('set role adlog_storage_owner')
        admin.execute("insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256) values(%s,1,'qw_signal','draft',%s::jsonb,%s)",
                      (item.policy_id, item.definition_json, item.definition_sha256))
        admin.execute("insert into semantic_risk_policy_subscriptions values(%s,1,'qw_signal',%s,%s)",
                      (item.policy_id, item.definition['source_selector']['rule_id'], item.definition_sha256))
        admin.execute('update semantic_risk_policies set lifecycle_status=%s where policy_id=%s', (state, item.policy_id))


@pytest.mark.parametrize('change', ['title', 'extra', 'merge', 'id', 'pin'])
def test_strict_canonical_managed_document(managed_pg, change):
    import psycopg
    good = policy()
    document = deepcopy(dict(good.definition))
    identifier = good.policy_id
    if change == 'id':
        identifier = 'default:qw.password-brute-force:wrong'
    elif change == 'pin':
        document['source_selector']['execution']['rule_sha256'] = '0' * 64
    elif change == 'extra':
        document['unexpected'] = True
    elif change == 'merge':
        document['merge_window_seconds'] = 300
    else:
        document['title'] = 'Untrusted substitute'
    bad = RiskPolicyDefinition(policy_id=identifier, policy_version=1, source_kind=good.source_kind, definition=document)
    with connection(managed_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match='password_policy_denied'):
            ensure(worker, bad)
    with connection(managed_pg) as admin:
        assert _count(admin) == 0


@pytest.mark.parametrize('kind', ['brute', 'spray'])
def test_seed_exact_body_hash_and_no_authority_or_cp_creation(managed_pg, kind):
    item = policy(kind)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker, item) is True
        assert ensure(worker, item) is True
    assert decision(managed_pg, item) == 'enabled'
    with connection(managed_pg) as admin:
        row = admin.execute('select * from semantic_risk_policies where policy_id=%s', (item.policy_id,)).fetchone()
        assert row['definition_json'] == item.definition and bytes(row['definition_sha256']) == item.definition_sha256
        assert admin.execute('select count(*) as n from semantic_control_audit where action=\'password_policy_managed\'').fetchone()['n'] == 1
        assert admin.execute('select count(*) as n from semantic_password_checkpoints').fetchone()['n'] == 0
        assert admin.execute('select count(*) as n from sli_agent_module_bindings').fetchone()['n'] == 1
        assert admin.execute('select count(*) as n from finding_evidence_source_bindings where source_instance_id=%s', (SCOPE.source_instance_id,)).fetchone()['n'] == 1


@pytest.mark.parametrize('missing', ['domain', 'issued', 'native', 'oid', 'source_name', 'active'])
def test_current_source_domain_authority_remains_mandatory(managed_pg, missing):
    import psycopg
    with connection(managed_pg) as admin:
        statements = {
            'domain': 'select 1',
            'issued': 'delete from sli_agent_module_bindings',
            'native': 'delete from finding_evidence_source_bindings',
            'oid': "update finding_evidence_source_bindings set principal_name='absent-fixture-login'",
            'source_name': "update sli_agent_module_bindings set source_name='different-fixture'",
            'active': "update sli_agents set status='revoked'",
        }
        admin.execute(statements[missing])
    with connection(managed_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match='password_(policy_source_unavailable|v2_source_denied)'):
            ensure(worker)
    with connection(managed_pg) as admin:
        assert _count(admin) == 0


def test_managed_v1_retirement_exact_provenance_and_later_owner_deny(managed_pg):
    old = policy(legacy=True)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker, old) is True
        assert ensure(worker) is True
        assert ensure(worker) is True
    assert decision(managed_pg) == 'enabled'
    with connection(managed_pg) as admin:
        assert admin.execute('select lifecycle_status from semantic_risk_policies where policy_id=%s', (old.policy_id,)).fetchone()['lifecycle_status'] == 'deprecated'
        assert admin.execute("select count(*) as n from semantic_control_audit where details->>'kind'='retirement'").fetchone()['n'] == 1
    owner_choice(managed_pg, old, False)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker) is False
    assert decision(managed_pg) == 'disabled'


@pytest.mark.parametrize('legacy', [True, False])
def test_custom_deny_and_exact_owner_enable_order(managed_pg, legacy):
    other = policy(legacy=legacy, custom='fixture-custom-choice')
    custom(managed_pg, other)
    owner_choice(managed_pg, other, False)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker) is False
    assert decision(managed_pg) == 'disabled'
    owner_choice(managed_pg, policy(), True)
    assert decision(managed_pg) == ('enabled' if legacy else 'disabled')
    owner_choice(managed_pg, other, False)
    assert decision(managed_pg) == 'disabled'
    with connection(managed_pg) as admin:
        assert admin.execute('select lifecycle_status from semantic_risk_policies where policy_id=%s', (other.policy_id,)).fetchone()['lifecycle_status'] == 'shadow'


def test_owner_governance_audit_failure_rolls_back_real_admission_and_trigger(managed_pg):
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker)
    class AuditFailure(Exception):
        pass
    def broken(cur, *args):
        assert cur.execute('select enabled from semantic_policy_admission where policy_id=%s', (policy().policy_id,)).fetchone()['enabled'] is False
        raise AuditFailure
    with connection(managed_pg) as admin:
        before = admin.execute('select count(*) as n from semantic_control_audit').fetchone()['n']
    with pytest.raises(AuditFailure):
        owner_choice(managed_pg, policy(), False, audit=broken)
    assert decision(managed_pg) == 'enabled'
    with connection(managed_pg) as admin:
        assert admin.execute('select count(*) as n from semantic_control_audit').fetchone()['n'] == before


@pytest.mark.parametrize('damage', ['missing', 'hash', 'link', 'actor_prefix'])
def test_incomplete_or_forged_system_provenance_unconfirmed(managed_pg, damage):
    import psycopg
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker)
    with connection(managed_pg) as admin:
        statements = {
            'missing': "delete from semantic_control_audit where action='password_policy_managed'",
            'hash': "update semantic_control_audit set details=jsonb_set(details,'{definition_sha256}',to_jsonb(repeat('0',64))) where action='password_policy_managed'",
            'link': "update semantic_control_audit set details=jsonb_set(details,'{admission_audit_id}','0') where action='password_policy_managed'",
            'actor_prefix': "update semantic_control_audit set actor='system:defaults' where action='policy_admission'; delete from semantic_control_audit where action='password_policy_managed'",
        }
        admin.execute(statements[damage])
    assert decision(managed_pg) == 'unknown'
    with connection(managed_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match='password_policy_unconfirmed'):
            ensure(worker)


def test_unicode_custom_document_uses_utf8_policy_hash_not_ascii_scope_codec(managed_pg):
    old = policy(legacy=True, custom='fixture-unicode')
    document = deepcopy(dict(old.definition))
    document['title'] = 'Синтетический выбор'
    old = RiskPolicyDefinition(policy_id=old.policy_id, policy_version=1, source_kind=old.source_kind, definition=document)
    custom(managed_pg, old)
    owner_choice(managed_pg, old, False)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker) is False
    assert decision(managed_pg) == 'disabled'


def test_family_sentinel_is_unavailable_without_partial_seed(managed_pg):
    import psycopg
    item = policy(legacy=True, custom='fixture-overflow')
    with connection(managed_pg) as admin:
        admin.execute("insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256) select 'fixture-overflow-'||g,1,'qw_signal','draft',%s::jsonb,%s from generate_series(1,257)g",
                      (item.definition_json, item.definition_sha256))
    assert decision(managed_pg) == 'unknown'
    with connection(managed_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match='password_policy_unconfirmed'):
            ensure(worker)
    with connection(managed_pg) as admin:
        assert _count(admin) == 257


def test_no_new_runtime_private_authority_or_policy_writes(managed_pg):
    import psycopg
    for mode in ('worker', 'web'):
        with connection(managed_pg, **{mode: True}) as login:
            for statement in ('select password_policy_ensure_v275(%s,1,%s)',
                              'select password_policy_provenance_v275(%s,1,%s)'):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    login.execute(statement, (policy().policy_id, policy().definition_json))
    with connection(managed_pg) as admin:
        assert not admin.execute("select exists(select 1 from pg_proc p cross join lateral aclexplode(p.proacl) a where p.oid='ensure_default_qw_policy(text,integer,text)'::regprocedure and a.grantee=0) as v").fetchone()['v']
        assert admin.execute("select has_function_privilege('adlog_semantic_worker','ensure_default_qw_policy(text,integer,text)','EXECUTE') as v").fetchone()['v']


@pytest.mark.parametrize('first', ['owner', 'rollover'])
def test_owner_deny_and_rollover_serialize_both_orders(managed_pg, first):
    old = policy(legacy=True)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker, old)
    entered = Event()
    release = Event()
    started = Event()
    def run_first():
        with connection(managed_pg, **({'web': True} if first == 'owner' else {'worker': True})) as conn, conn.transaction():
            if first == 'owner':
                set_policy_admission(conn.cursor(), old.policy_id, 1, False, actor='session:42', reason='Synthetic choice', audit=lambda *a: None)
            else:
                assert ensure(conn)
            entered.set()
            assert release.wait(10)
    def run_second():
        assert entered.wait(10)
        with connection(managed_pg, **({'worker': True} if first == 'owner' else {'web': True})) as conn, conn.transaction():
            started.set()
            if first == 'owner':
                return ensure(conn)
            set_policy_admission(conn.cursor(), old.policy_id, 1, False, actor='session:42', reason='Synthetic choice', audit=lambda *a: None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first_result = pool.submit(run_first)
        second_result = pool.submit(run_second)
        try:
            assert started.wait(10)
            deadline = monotonic() + 5
            blocked = False
            while monotonic() < deadline:
                with connection(managed_pg) as admin:
                    blocked = admin.execute("select exists(select 1 from pg_stat_activity where usename in(%s,%s) and wait_event_type='Lock' and wait_event='advisory') as v", (managed_pg[1], managed_pg[2])).fetchone()['v']
                if blocked:
                    break
                sleep(.02)
            assert blocked, 'second real transaction did not wait for managed policy locks'
        finally:
            release.set()
        first_result.result(10)
        result = second_result.result(10)
        if first == 'owner':
            assert result is False
    assert decision(managed_pg) == 'disabled'


@pytest.mark.parametrize('first', ['registration', 'rollover'])
def test_custom_registration_and_rollover_family_absence_race(managed_pg, first):
    other = policy(legacy=True, custom='fixture-new-custom')
    entered, release, started = Event(), Event(), Event()
    def register(conn):
        register_risk_policy(conn.cursor(), policy=other)
        for status in ('validated', 'test', 'shadow', 'disabled'):
            transition_risk_policy(conn.cursor(), policy_id=other.policy_id, policy_version=1, target_status=status)
    def run_first():
        with connection(managed_pg, **({'writer': True} if first == 'registration' else {'worker': True})) as conn, conn.transaction():
            register(conn) if first == 'registration' else ensure(conn)
            entered.set()
            assert release.wait(10)
    def run_second():
        assert entered.wait(10)
        with connection(managed_pg, **({'worker': True} if first == 'registration' else {'writer': True})) as conn, conn.transaction():
            started.set()
            return ensure(conn) if first == 'registration' else register(conn)
    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(run_first), pool.submit(run_second)
        try:
            assert started.wait(10)
            until = monotonic() + 5
            blocked = False
            while monotonic() < until:
                with connection(managed_pg) as admin:
                    blocked = admin.execute("select exists(select 1 from pg_stat_activity where usename in(%s,%s) and wait_event='advisory') as v", (managed_pg[1], managed_pg[3])).fetchone()['v']
                if blocked:
                    break
                sleep(.02)
            assert blocked
        finally:
            release.set()
        a.result(10)
        result = b.result(10)
        if first == 'registration':
            assert result is False
    assert decision(managed_pg) == 'disabled'
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker) is False


def test_manual_v1_false_preserved_before_any_retirement(managed_pg):
    old = policy(legacy=True)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker, old)
    owner_choice(managed_pg, old, False)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker) is False
    with connection(managed_pg) as admin:
        assert admin.execute('select lifecycle_status from semantic_risk_policies where policy_id=%s', (old.policy_id,)).fetchone()['lifecycle_status'] == 'shadow'
        assert admin.execute("select count(*) as n from semantic_control_audit where details->>'kind'='retirement'").fetchone()['n'] == 0
        seed = admin.execute("select details from semantic_control_audit where action='password_policy_managed' and target=%s", (policy().policy_id + ':1',)).fetchone()['details']
        assert seed['kind'] == 'preserved-owner-choice' and seed['enabled'] is False
    owner_choice(managed_pg, policy(), True)
    assert decision(managed_pg) == 'enabled'


def test_equal_timestamp_owner_events_use_audit_ids(managed_pg):
    old = policy(legacy=True, custom='fixture-tied-custom')
    custom(managed_pg, old)
    owner_choice(managed_pg, old, False)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker) is False
    owner_choice(managed_pg, policy(), True)
    with connection(managed_pg) as admin:
        admin.execute("update semantic_control_audit set occurred_at='2100-01-01 UTC' where action='policy_admission' and actor='session:42'")
    assert decision(managed_pg) == 'enabled'
    owner_choice(managed_pg, old, False)
    with connection(managed_pg) as admin:
        admin.execute("update semantic_control_audit set occurred_at='2100-01-01 UTC' where action='policy_admission' and actor='session:42'")
    assert decision(managed_pg) == 'disabled'


def test_changed_managed_v1_document_is_never_retired(managed_pg):
    old = policy(legacy=True)
    document = deepcopy(dict(old.definition))
    document['title'] = 'Custom owner wording'
    changed = RiskPolicyDefinition(policy_id=old.policy_id, policy_version=1, source_kind=old.source_kind, definition=document)
    custom(managed_pg, changed)
    owner_choice(managed_pg, changed, True)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker)
    with connection(managed_pg) as admin:
        row = admin.execute('select lifecycle_status,definition_json,definition_sha256 from semantic_risk_policies where policy_id=%s', (old.policy_id,)).fetchone()
        assert row['lifecycle_status'] == 'shadow' and row['definition_json'] == document
        assert bytes(row['definition_sha256']) == changed.definition_sha256


@pytest.mark.parametrize('state', ['disabled', 'deprecated'])
def test_exact_v2_lifecycle_veto_under_any_id(managed_pg, state):
    other = policy(custom='fixture-exact-v2-status')
    custom(managed_pg, other, state=state)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker) is False
    assert decision(managed_pg) == 'disabled'


def test_retirement_failure_rolls_back_seed_subscription_admission_and_audit(managed_pg):
    import psycopg
    old = policy(legacy=True)
    with connection(managed_pg, worker=True) as worker:
        assert ensure(worker, old)
    with connection(managed_pg) as admin:
        before = admin.execute('select count(*) as n from semantic_control_audit').fetchone()['n']
        admin.execute("create function public.fixture_reject_retirement() returns trigger language plpgsql as $$ begin if new.lifecycle_status='deprecated' then raise exception 'fixture_retirement_failure'; end if; return new; end $$")
        admin.execute('create trigger fixture_reject_retirement before update on semantic_risk_policies for each row execute function fixture_reject_retirement()')
    with connection(managed_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.RaiseException, match='fixture_retirement_failure'):
            ensure(worker)
    with connection(managed_pg) as admin:
        assert _count(admin) == 1
        assert admin.execute('select count(*) as n from semantic_risk_policy_subscriptions where policy_id=%s', (policy().policy_id,)).fetchone()['n'] == 0
        assert admin.execute('select count(*) as n from semantic_policy_admission where policy_id=%s', (policy().policy_id,)).fetchone()['n'] == 0
        assert admin.execute('select count(*) as n from semantic_control_audit').fetchone()['n'] == before


def test_pre275_legacy_system_prefix_without_identity_is_unconfirmed(managed_base_pg):
    import psycopg
    old = policy(legacy=True)
    with connection(managed_base_pg, worker=True) as worker:
        assert ensure(worker, old)
    with connection(managed_base_pg) as admin:
        admin.execute(PATH.read_text('utf-8-sig'))
    with connection(managed_base_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match='password_policy_unconfirmed'):
            ensure(worker)
    assert decision(managed_base_pg) == 'unknown'
    with connection(managed_base_pg) as admin:
        assert _count(admin) == 1
        assert admin.execute('select lifecycle_status from semantic_risk_policies where policy_id=%s', (old.policy_id,)).fetchone()['lifecycle_status'] == 'shadow'


@pytest.mark.parametrize('failure', ['predecessor', 'future', 'mid_ddl'])
def test_migration_preflight_and_transactional_ddl_rollback(managed_base_pg, failure):
    import psycopg
    with connection(managed_base_pg) as admin:
        before = admin.execute("select pg_get_functiondef('ensure_default_qw_policy(text,integer,text)'::regprocedure) as body").fetchone()['body']
        if failure == 'predecessor':
            admin.execute("update schema_migrations set name='fixture_wrong_contract' where version=274")
        elif failure == 'future':
            admin.execute("insert into schema_migrations values(276,'fixture_future')")
        source = PATH.read_text('utf-8-sig')
        if failure == 'mid_ddl':
            source = source.replace('create or replace function public.ensure_default_qw_policy(', 'select 1/0;\ncreate or replace function public.ensure_default_qw_policy(')
        try:
            with pytest.raises(psycopg.errors.DivisionByZero if failure == 'mid_ddl' else psycopg.errors.ObjectNotInPrerequisiteState):
                admin.execute(source)
        finally:
            admin.execute('rollback')
        assert admin.execute("select pg_get_functiondef('ensure_default_qw_policy(text,integer,text)'::regprocedure) as body").fetchone()['body'] == before
        assert admin.execute("select to_regclass('idx_password_policy_family_v275') as v").fetchone()['v'] is None
        assert admin.execute("select to_regprocedure('password_policy_decision_v275(jsonb)') as v").fetchone()['v'] is None
        assert admin.execute('select count(*) as n from schema_migrations where version=275').fetchone()['n'] == 0


def test_definer_path_and_schema_shadowing_boundary(managed_pg):
    import psycopg
    for mode in ('worker', 'web'):
        with connection(managed_pg, **{mode: True}) as login:
            assert not login.execute("select has_schema_privilege(session_user,'public','CREATE') as v").fetchone()['v']
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                login.execute('create table public.fixture_shadow_attempt(id integer)')
            login.execute('create temp table semantic_risk_policies(policy_id text,policy_version integer,lifecycle_status text)')
            if mode == 'worker':
                assert ensure(login)
    with connection(managed_pg) as admin:
        row = admin.execute("select proconfig,pg_get_userbyid(proowner) as owner,prosecdef from pg_proc where oid='password_policy_ensure_v275(text,integer,text)'::regprocedure").fetchone()
        assert row['owner'] == 'adlog_storage_owner' and row['prosecdef']
        assert row['proconfig'] == ['search_path=pg_catalog, public, pg_temp']


def test_source_identity_is_rechecked_after_waiting_for_source_lock(managed_pg):
    import psycopg
    entered, release, started = Event(), Event(), Event()
    def change_source():
        with connection(managed_pg) as admin, admin.transaction():
            admin.execute("select pg_advisory_xact_lock(hashtextextended(encode(password_v2_scope_key(%s::jsonb),'hex'),0))", (json.dumps(asdict(SCOPE)),))
            admin.execute("update sli_agents set assigned_modules=jsonb_set(assigned_modules,'{0,enabled}','false') where id=%s", (AGENT,))
            entered.set()
            assert release.wait(10)
    def produce():
        assert entered.wait(10)
        with connection(managed_pg, worker=True) as worker:
            started.set()
            with pytest.raises(psycopg.errors.InsufficientPrivilege, match='password_policy_source_unavailable'):
                ensure(worker)
    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(change_source), pool.submit(produce)
        try:
            assert started.wait(10)
            until = monotonic() + 5
            blocked = False
            while monotonic() < until:
                with connection(managed_pg) as admin:
                    blocked = admin.execute("select exists(select 1 from pg_stat_activity where usename=%s and wait_event='advisory') as v", (managed_pg[1],)).fetchone()['v']
                if blocked:
                    break
                sleep(.02)
            assert blocked
        finally:
            release.set()
        a.result(10)
        b.result(10)
    with connection(managed_pg) as admin:
        assert _count(admin) == 0


@pytest.mark.parametrize('isolation', ['repeatable read', 'serializable'])
def test_snapshot_isolation_cannot_claim_fresh_post_lock_decision(managed_pg, isolation):
    import psycopg
    with connection(managed_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match='password_policy_unconfirmed'):
            with worker.transaction():
                worker.execute('set transaction isolation level ' + isolation)
                ensure(worker)
    with connection(managed_pg) as admin:
        assert _count(admin) == 0


def test_legacy_prefix_custom_document_never_receives_managed_seed_provenance(managed_pg):
    import psycopg
    old = policy(legacy=True)
    document = deepcopy(dict(old.definition))
    document['title'] = 'Custom legacy document'
    changed = RiskPolicyDefinition(policy_id=old.policy_id, policy_version=1, source_kind=old.source_kind, definition=document)
    with connection(managed_pg, worker=True) as worker:
        # Preserve262's existing v1 admission behavior, without upgrading its
        # prefix into the new canonical managed-system provenance authority.
        assert ensure(worker, changed)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match='password_policy_unconfirmed'):
            ensure(worker)
    assert decision(managed_pg) == 'unknown'
    with connection(managed_pg) as admin:
        assert admin.execute("select count(*) as n from semantic_control_audit where action='password_policy_managed'").fetchone()['n'] == 0
        assert _count(admin) == 1


@pytest.mark.parametrize('acl_marker', ['kind', 'resource'])
def test_legacy_password_interception_preserves_existing265_acl_denial(managed_pg, acl_marker):
    import psycopg
    old = policy(legacy=True)
    document = deepcopy(dict(old.definition))
    if acl_marker == 'kind':
        document['source_selector']['execution']['kind'] = 'acl'
    else:
        document['source_selector']['execution']['resource'] = {}
    bad = RiskPolicyDefinition(policy_id=old.policy_id, policy_version=1, source_kind=old.source_kind, definition=document)
    with connection(managed_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match='file_acl_medium_policy_required'):
            ensure(worker, bad)
    with connection(managed_pg) as admin:
        assert _count(admin) == 0


PRIVATE_HELPERS_V275 = (
    'password_policy_json_v275(jsonb,integer)',
    'password_policy_definition_v275(jsonb)',
    'password_policy_legacy_execution_v275(jsonb,text)',
    'password_policy_family_lock_v275(jsonb,text)',
    'password_policy_lifecycle_audit_v275()',
    'password_policy_provenance_v275(text,integer,text)',
    'password_policy_decision_v275(jsonb)',
    'password_policy_ensure_v275(text,integer,text)',
)


def _owner_function_defaults(conn):
    return conn.execute("""select coalesce(jsonb_agg(jsonb_build_object(
        'namespace',defaclnamespace,'acl',defaclacl::text) order by defaclnamespace),'[]') as v
        from pg_default_acl where defaclrole='adlog_storage_owner'::regrole and defaclobjtype='f'""").fetchone()['v']


@contextmanager
def _default_function_execute(conn, grantee):
    """Test-only schema default, restored even after an aborted migration."""
    from psycopg import sql
    before = _owner_function_defaults(conn)
    had_grant = conn.execute("""select exists(select 1 from pg_default_acl d
        cross join lateral aclexplode(d.defaclacl) a
        where d.defaclrole='adlog_storage_owner'::regrole and d.defaclnamespace='public'::regnamespace
          and d.defaclobjtype='f' and a.grantee=(select oid from pg_roles where rolname=%s)
          and a.privilege_type='EXECUTE') as v""", (grantee,)).fetchone()['v']
    if not had_grant:
        conn.execute(sql.SQL('alter default privileges for role adlog_storage_owner in schema public grant execute on functions to {}').format(sql.Identifier(grantee)))
    try:
        yield
    finally:
        if conn.info.transaction_status != 0:
            conn.execute('rollback')
        if not had_grant:
            conn.execute(sql.SQL('alter default privileges for role adlog_storage_owner in schema public revoke execute on functions from {}').format(sql.Identifier(grantee)))
        assert _owner_function_defaults(conn) == before


def _old_function_catalog(conn):
    return conn.execute("""select p.oid::regprocedure::text as signature,
        pg_get_functiondef(p.oid) as body,p.proowner,p.proacl::text as acl
        from pg_proc p where p.oid in (
          'ensure_default_qw_policy(text,integer,text)'::regprocedure,
          'password_v2_coverage_policy(jsonb)'::regprocedure,
          'semantic_control_audit_v160()'::regprocedure) order by signature""").fetchall()


def test_unexpected_default_private_execute_aborts_entire_migration(managed_base_pg):
    import psycopg
    from psycopg import sql
    outsider = 'sli_test_password_unexpected_' + uuid4().hex
    with connection(managed_base_pg) as admin:
        admin.execute(sql.SQL('create role {} login').format(sql.Identifier(outsider)))
        try:
            assert not admin.execute("select pg_has_role(%s,'adlog_storage_owner','MEMBER') as v", (outsider,)).fetchone()['v']
            before = _old_function_catalog(admin)
            ledger = admin.execute('select version,name from schema_migrations order by version').fetchall()
            with _default_function_execute(admin, outsider):
                try:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege, match='password_policy_private_acl_unexpected') as denied:
                        admin.execute(PATH.read_text('utf-8-sig'))
                    assert denied.value.sqlstate == '42501'
                finally:
                    if admin.info.transaction_status != 0:
                        admin.execute('rollback')
                assert _old_function_catalog(admin) == before
                assert admin.execute('select version,name from schema_migrations order by version').fetchall() == ledger
                assert all(admin.execute('select to_regprocedure(%s) as v', ('public.' + helper,)).fetchone()['v'] is None
                           for helper in PRIVATE_HELPERS_V275)
                assert admin.execute("select to_regclass('public.idx_password_policy_family_v275') as v").fetchone()['v'] is None
                assert admin.execute("select to_regclass('public.idx_password_policy_audit_v275') as v").fetchone()['v'] is None
                assert not admin.execute("select exists(select 1 from pg_trigger where tgname='password_policy_lifecycle_audit_v275' and not tgisinternal) as v").fetchone()['v']
        finally:
            if admin.info.transaction_status != 0:
                admin.execute('rollback')
            # RED may have installed the old candidate. Remove only this
            # newly-created disposable role's leaked grants before dropping it.
            for helper in PRIVATE_HELPERS_V275:
                if admin.execute('select to_regprocedure(%s) as v', ('public.' + helper,)).fetchone()['v'] is not None:
                    admin.execute(sql.SQL('revoke all on function {} from {}').format(
                        sql.SQL('public.' + helper), sql.Identifier(outsider)))
            admin.execute(sql.SQL('drop role {}').format(sql.Identifier(outsider)))


def test_known_app_default_execute_is_revoked_and_normal_install_succeeds(managed_base_pg):
    with connection(managed_base_pg) as admin:
        with _default_function_execute(admin, 'adlog_user'):
            admin.execute(PATH.read_text('utf-8-sig'))
            for helper in PRIVATE_HELPERS_V275:
                row = admin.execute("""select p.proowner='adlog_storage_owner'::regrole as correct_owner,
                    exists(select 1 from aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                        where a.grantee<>p.proowner) as nonowner_acl
                    from pg_proc p where p.oid=to_regprocedure(%s)""", ('public.' + helper,)).fetchone()
                assert row == dict(correct_owner=True, nonowner_acl=False)
                assert not admin.execute("select has_function_privilege('adlog_user',%s,'EXECUTE') as v",
                                         ('public.' + helper,)).fetchone()['v']
            assert admin.execute("select name from schema_migrations where version=275").fetchone()['name'] == 'password_policy_management'
            assert admin.execute("select has_function_privilege('adlog_semantic_worker','ensure_default_qw_policy(text,integer,text)','EXECUTE') as v").fetchone()['v']
    with connection(managed_base_pg, worker=True) as worker:
        assert ensure(worker) is True
    assert decision(managed_base_pg) == 'enabled'

"""Disposable reader candidate experiment; frozen baseline and product stay unchanged."""
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace
from uuid import UUID

import pytest

from server.sli.semantic.account_decoy_runtime import read_events
from tests.migrations import test_account_decoy_native_profile as base
from tests.migrations.test_account_decoy_native_profile import ad_pg as ad_pg

ROOT = Path(__file__).resolve().parents[2]
READER = base.FUNCTIONS[2]
RESOLVER = base.FUNCTIONS[1]
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def baseline_sql():
    return base.function(base.source('244_account_decoy.sql'),
                         'create function public.read_account_decoy_events').replace(
                             'create function', 'create or replace function', 1)


def candidate_sql():
    return (ROOT/'tests/fixtures/account_decoy_source_prefilter_candidate.sql').read_text('utf-8-sig')


def install(admin, definition):
    admin.execute('set role adlog_storage_owner')
    try:
        admin.execute(definition)
    finally:
        admin.execute('reset role')


def catalog(admin):
    functions = {}
    for signature in base.FUNCTIONS:
        row = admin.execute('''select oid,pg_get_userbyid(proowner),proacl::text,
          prosecdef,provolatile,proconfig,pronargdefaults,proisstrict,proleakproof,
          proparallel,prosrc from pg_proc where oid=%s::regprocedure''', (signature,)).fetchone()
        functions[signature] = dict(oid=row[0], owner=row[1], acl=row[2],
            security_definer=row[3], volatility=row[4], config=row[5], defaults=row[6],
            strict=row[7], leakproof=row[8], parallel=row[9],
            body_sha256=hashlib.sha256(row[10].encode()).hexdigest())
    return functions


def assert_authority(env, definition):
    current = catalog(env.admin)
    for signature, original in env.catalog.items():
        expected = dict(original)
        if signature == READER:
            expected['body_sha256'] = hashlib.sha256(definition.split('$$', 2)[1].encode()).hexdigest()
        assert current[signature] == expected
    return current


@contextmanager
def reader(env, variant):
    definition = baseline_sql() if variant == 'baseline' else candidate_sql()
    install(env.admin, definition)
    assert_authority(env, definition)
    try:
        yield
    finally:
        install(env.admin, baseline_sql())
        assert catalog(env.admin) == env.catalog


def boundary(worker):
    import psycopg
    for table in ('events_v2_core', 'raw_log_files', 'sli_agent_receipts',
                  'sli_agent_packet_inbox', 'finding_evidence_source_bindings'):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute('select * from '+table)


@pytest.fixture
def env(ad_pg, postgres_semantic_worker_dsn):
    import psycopg
    from psycopg.rows import dict_row
    assert hashlib.sha256((ROOT/'tests/migrations/test_account_decoy_native_profile.py').read_bytes().replace(b'\r\n', b'\n')).hexdigest() == 'fb7ae0c253e51a671a84ad8463b8f8a029b4263ae43e42d5095c581dad4bba19'
    assert hashlib.sha256((ROOT/'tests/migrations/test_acl_provenance_native_profile.py').read_bytes().replace(b'\r\n', b'\n')).hexdigest() == 'f972d11c73b695249207d0aa14e17edd02f38cdd0f68d1b79663dd69669ba8c0'
    with psycopg.connect(ad_pg, autocommit=True) as admin, psycopg.connect(
            postgres_semantic_worker_dsn, autocommit=True, row_factory=dict_row) as worker:
        worker.execute('set role adlog_semantic_worker')
        worker.execute("set statement_timeout='60s'")
        worker.execute("set lock_timeout='2s'")
        identity = worker.execute('''select session_user as physical_login,
          current_user='adlog_semantic_worker' as semantic,session_user<>current_user as physical,
          not rolsuper and not rolbypassrls and not rolinherit as bounded,
          not pg_has_role(session_user,'adlog_storage_owner','MEMBER') as nonowner
          from pg_roles where rolname=session_user''').fetchone()
        assert all(identity[key] for key in ('semantic', 'physical', 'bounded', 'nonowner'))
        admin.execute('''insert into finding_evidence_source_bindings
          select oid,rolname,%s,%s,%s,%s,'','core_event',7,null,%s
          from pg_roles where rolname=%s''',
          (base.INSTALLATION, base.PLUGIN, base.SOURCE, base.GENERATION, base.AGENT, worker.info.user))
        bindings = admin.execute('select * from finding_evidence_source_bindings').fetchall()
        original = base.catalog(admin)
        rule = SimpleNamespace(scope=SimpleNamespace(installation_id=base.INSTALLATION,
            plugin_id=base.PLUGIN, source_instance_id=base.SOURCE,
            source_generation=base.GENERATION), checkpoint_key=base.CHECKPOINT)
        value = SimpleNamespace(admin=admin, worker=worker, rule=rule,
                                catalog=catalog(admin), native_catalog=original, identity=identity)
        boundary(worker)
        try:
            yield value
        finally:
            install(admin, baseline_sql())
            assert base.catalog(admin) == original
            assert catalog(admin) == value.catalog
            assert admin.execute('select * from finding_evidence_source_bindings').fetchall() == bindings
            boundary(worker)


def stats(env):
    env.worker.execute('select pg_stat_force_next_flush()')
    env.admin.execute('select pg_stat_clear_snapshot()')
    return {signature: env.admin.execute('''select coalesce(s.calls,0),coalesce(s.total_time,0),
      coalesce(s.self_time,0) from pg_proc p left join pg_stat_user_functions s on s.funcid=p.oid
      where p.oid=%s::regprocedure''', (signature,)).fetchone() for signature in base.FUNCTIONS}


def read(env, normalized=None):
    before = stats(env)
    started = perf_counter()
    with env.worker.cursor() as cur:
        rows = read_events(cur, env.rule, normalized_event_id=str(normalized) if normalized else None)
    elapsed = (perf_counter()-started)*1000
    after = stats(env)
    functions = {key: dict(zip(('calls', 'total_ms', 'self_ms'),
        (end-start for start, end in zip(before[key], after[key], strict=True)), strict=True)) for key in before}
    assert functions[READER]['calls'] == 1
    record = dict(rows=len(rows), resolver_calls=functions[RESOLVER]['calls'], wall_ms=elapsed,
        output_sha256=hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest(),
        functions=functions)
    return rows, record


def paired(env, normalized=None):
    outputs, records = {}, {}
    for variant in ('baseline', 'candidate'):
        with reader(env, variant):
            outputs[variant], records[variant] = read(env, normalized)
    assert outputs['candidate'] == outputs['baseline']
    return outputs['baseline'], records


def checkpoint(env, ids):
    for normalized in ids:
        env.admin.execute('''insert into semantic_account_decoy_checks
          values(%s,%s,%s::jsonb,'no_match',now()) on conflict do nothing''',
          (base.CHECKPOINT, normalized, json.dumps(vars(env.rule.scope))))


def test_native_calls_are_source_prefiltered_before_full_proof(env):
    base.seed(env.admin, 1024)
    control, exact = paired(env, UUID(int=1))
    assert len(control) == 1
    assert all(record['resolver_calls'] == 1 for record in exact.values())
    rows, scan = paired(env)
    assert len(rows) == 128
    checkpoint(env, [UUID(int=n) for n in range(1, 129)])
    rows, empty = paired(env)
    assert rows == []
    print('PREFILTER_COUNTER_RESULT='+json.dumps(dict(scan=scan, empty=empty,
        exact_control=exact, authority=env.catalog, native_catalog=env.native_catalog, candidate_reader_body_sha256=hashlib.sha256(candidate_sql().split('$$', 2)[1].encode()).hexdigest(), physical_login=env.identity), sort_keys=True, default=str))
    assert scan['baseline']['resolver_calls'] == 1024
    assert empty['baseline']['resolver_calls'] == 896
    assert scan['candidate']['resolver_calls'] == 128
    assert empty['candidate']['resolver_calls'] == 0


def test_fresh_native_and_binding_denials_restore_exact_public_output(env):
    import psycopg
    base.seed(env.admin, 8)
    with reader(env, 'candidate'):
        boundary(env.worker)
    initial, _ = paired(env, UUID(int=1))
    assert len(initial) == 1
    records = {}
    changes = (
        ('receipt', "update sli_agent_receipts set envelope=envelope||'{\"synthetic_mismatch\":true}'::jsonb where packet_id=%s",
         'update sli_agent_receipts set envelope=(select envelope from sli_agent_packet_inbox where packet_id=%s) where packet_id=%s'),
        ('import', 'update sli_agent_packet_inbox set imported_at=null where packet_id=%s',
         'update sli_agent_packet_inbox set imported_at=now() where packet_id=%s'),
        ('native_hash', "update events_v2_core set normalized_hash=decode(repeat('b',64),'hex') where id=1",
         "update events_v2_core set normalized_hash=decode(repeat('a',64),'hex') where id=1"),
    )
    for name, mutation, restore in changes:
        env.admin.execute(mutation, (UUID(int=1),) if '%s' in mutation else None)
        try:
            denied, measured = paired(env, UUID(int=1))
            assert denied == []
            records[name] = measured
        finally:
            params = (UUID(int=1),)*(2 if name == 'receipt' else 1) if '%s' in restore else None
            env.admin.execute(restore, params)
        restored, _ = paired(env, UUID(int=1))
        assert restored == initial
    for key, wrong in (('source_instance_id', 'foreign-source'), ('generation', 'foreign-generation')):
        packet = UUID(int=1)
        original = env.admin.execute('select envelope from sli_agent_packet_inbox where packet_id=%s', (packet,)).fetchone()[0]
        mutated = json.dumps(original | {key: wrong})
        for table in ('sli_agent_packet_inbox', 'sli_agent_receipts'):
            env.admin.execute('update '+table+' set envelope=%s::jsonb where packet_id=%s', (mutated, packet))
        try:
            denied, records[key] = paired(env, packet)
            assert denied == []
        finally:
            for table in ('sli_agent_packet_inbox', 'sli_agent_receipts'):
                env.admin.execute('update '+table+' set envelope=%s::jsonb where packet_id=%s', (json.dumps(original), packet))
        restored, _ = paired(env, packet)
        assert restored == initial
    for column, value in (('principal_name', 'synthetic-missing-login'), ('principal_oid', 0)):
        original = env.admin.execute('select '+column+' from finding_evidence_source_bindings').fetchone()[0]
        env.admin.execute('update finding_evidence_source_bindings set '+column+'=%s', (value,))
        try:
            for variant in ('baseline', 'candidate'):
                with reader(env, variant), pytest.raises(psycopg.errors.InsufficientPrivilege):
                    read(env, UUID(int=1))
        finally:
            env.admin.execute('update finding_evidence_source_bindings set '+column+'=%s', (original,))
        restored, _ = paired(env, UUID(int=1))
        assert restored == initial
    for field in ('source_instance_id', 'source_generation'):
        foreign = SimpleNamespace(scope=SimpleNamespace(**(vars(env.rule.scope) | {field: 'unbound'})),
                                  checkpoint_key=base.CHECKPOINT)
        for variant in ('baseline', 'candidate'):
            with reader(env, variant), pytest.raises(psycopg.errors.InsufficientPrivilege), env.worker.cursor() as cur:
                read_events(cur, foreign)
    print('PREFILTER_NEGATIVE_RESULT='+json.dumps(dict(denials=records,
        restored_output_sha256=hashlib.sha256(json.dumps(initial, sort_keys=True, default=str).encode()).hexdigest(),
        principal_oid_name_denials=True, unbound_source_generation_denials=True), sort_keys=True, default=str))


def test_late_valid_latest_tie_order_checkpoint_and_exact_id_parity(env):
    base.seed(env.admin, 1024)
    env.admin.execute("update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{source_instance_id}',to_jsonb('foreign-source'::text))")
    env.admin.execute("update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{source_instance_id}',to_jsonb(%s::text)) where packet_id in (%s,%s)",
                      (base.SOURCE, UUID(int=1023), UUID(int=1024)))
    env.admin.execute('update sli_agent_receipts r set envelope=i.envelope from sli_agent_packet_inbox i where i.packet_id=r.packet_id')
    env.admin.execute("update normalized_events set normalized_at='2026-01-03' where source_event_id in (1023,1024)")
    env.admin.execute('''insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,
      normalizer_id,normalizer_version,processing_status,normalized_at,source_event_sha256,semantic_sha256,
      semantic_type,occurred_at_utc,source_ingested_at,roles_json)
      select %s,source_event_id,semantic_contract_version,normalizer_id,'2',processing_status,normalized_at,
      source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,source_ingested_at,roles_json
      from normalized_events where normalized_event_id=%s''', (UUID(int=2048), UUID(int=1024)))
    rows, scan = paired(env)
    assert [row['normalized_event_id'] for row in rows] == [UUID(int=1023), UUID(int=2048)]
    records = dict(scan=scan)
    checkpoint(env, [UUID(int=1024)])
    same, records['old_checkpoint'] = paired(env)
    assert same == rows
    checkpoint(env, [UUID(int=2048)])
    remaining, records['latest_checkpoint'] = paired(env)
    assert [row['normalized_event_id'] for row in remaining] == [UUID(int=1023)]
    for normalized in (UUID(int=1024), UUID(int=2048)):
        exact, records['exact_'+str(normalized)] = paired(env, normalized)
        assert len(exact) == 1
    checkpoint(env, [UUID(int=1023)])
    empty, records['empty'] = paired(env)
    assert empty == []
    print('PREFILTER_ORDER_RESULT='+json.dumps(records, sort_keys=True, default=str))

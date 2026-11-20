"""Actual270 upgrade/guards on the bounded AD fixture; unrelated269 ledger marker."""
import hashlib
import json
from pathlib import Path
from uuid import UUID

import pytest

from tests.migrations import test_account_decoy_native_profile as base
from tests.migrations import test_account_decoy_prefilter_candidate as experiment
from tests.migrations.test_account_decoy_native_profile import ad_pg as ad_pg
from tests.migrations.test_account_decoy_prefilter_candidate import env as env

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT/'config/postgres_migrations/270_account_decoy_source_prefilter.sql'
NAME = 'account_decoy_source_prefilter'
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


@pytest.fixture
def ready(env):
    # AD-only fragments do not build the unrelated ACL canonical function.
    # Exact269 ledger marker is explicit, not a full269/chain installation.
    env.admin.execute("insert into schema_migrations values(269,'file_audit_canonical_aggregation')")
    return env


def state(admin):
    return dict(function=admin.execute('''select to_jsonb(p) from pg_proc p
      where oid=%s::regprocedure''', (experiment.READER,)).fetchone()[0],
      resolver=admin.execute('select pg_get_functiondef(%s::regprocedure)',
                            (experiment.RESOLVER,)).fetchone()[0],
      ledger=admin.execute('select version,name from schema_migrations order by version').fetchall())


def test_whole270_replaces_only_reviewed_reader_and_preserves_native_proof(ready):
    env = ready
    base.seed(env.admin, 1024)
    original = state(env.admin)
    rows, before = experiment.read(env)
    exact, exact_before = experiment.read(env, UUID(int=1))
    experiment.checkpoint(env, [UUID(int=n) for n in range(1, 129)])
    empty, empty_before = experiment.read(env)
    assert len(rows) == 128 and len(exact) == 1 and empty == []
    assert before['resolver_calls'] == 1024 and empty_before['resolver_calls'] == 896
    assert env.admin.execute("select pg_has_role(session_user,'adlog_storage_owner','MEMBER')").fetchone()[0]
    env.admin.execute(MIGRATION.read_text('utf-8-sig'))
    upgraded = state(env.admin)
    assert upgraded['ledger'] == original['ledger']+[(270, NAME)]
    assert upgraded['resolver'] == original['resolver']
    assert {key:value for key,value in upgraded['function'].items() if key != 'prosrc'} == {
        key:value for key,value in original['function'].items() if key != 'prosrc'}
    assert upgraded['function']['prosrc'] == experiment.candidate_sql().split('$$', 2)[1]
    assert hashlib.sha256(upgraded['function']['prosrc'].encode()).hexdigest() == '00d0458c557bbc046492f4dfe745b673ce397c94529379ab7e01f08e6709fe94'
    experiment.assert_authority(env, experiment.candidate_sql())
    experiment.boundary(env.worker)
    env.admin.execute('delete from semantic_account_decoy_checks')
    candidate, after = experiment.read(env)
    candidate_exact, exact_after = experiment.read(env, UUID(int=1))
    assert candidate == rows and candidate_exact == exact
    assert after['resolver_calls'] == 128
    assert exact_before['resolver_calls'] == exact_after['resolver_calls'] == 1
    experiment.checkpoint(env, [UUID(int=n) for n in range(1, 129)])
    candidate_empty, empty_after = experiment.read(env)
    assert candidate_empty == empty and empty_after['resolver_calls'] == 0
    env.admin.execute("update sli_agent_receipts set envelope=envelope||'{\"synthetic_mismatch\":true}'::jsonb where packet_id=%s", (UUID(int=1),))
    denied, denial = experiment.read(env, UUID(int=1))
    assert denied == [] and denial['resolver_calls'] == 1
    env.admin.execute('update sli_agent_receipts set envelope=(select envelope from sli_agent_packet_inbox where packet_id=%s) where packet_id=%s', (UUID(int=1), UUID(int=1)))
    restored, _ = experiment.read(env, UUID(int=1))
    assert restored == exact
    print('MIGRATION270_APPLY_RESULT='+json.dumps(dict(scan_before=before, scan_after=after,
        exact_before=exact_before, exact_after=exact_after, empty_before=empty_before,
        empty_after=empty_after, fresh_receipt_denial=denial,
        oid_acl_owner_catalog_preserved=True, resolver_unchanged=True,
        reader_body_sha256=hashlib.sha256(upgraded['function']['prosrc'].encode()).hexdigest(),
        authority=experiment.catalog(env.admin)), sort_keys=True, default=str))


@pytest.mark.parametrize('drift', ['missing269', 'wrong269', 'duplicate270', 'higher271',
                                  'body', 'acl', 'owner', 'search_path', 'security', 'volatility'])
def test_whole270_rejects_precursor_or_reader_drift_atomically(ready, drift):
    import psycopg
    env = ready
    if drift == 'missing269':
        env.admin.execute('delete from schema_migrations where version=269')
    elif drift == 'wrong269':
        env.admin.execute("update schema_migrations set name='wrong' where version=269")
    elif drift in ('duplicate270', 'higher271'):
        env.admin.execute('insert into schema_migrations values(%s,%s)',
                          (270 if drift == 'duplicate270' else 271, 'synthetic-existing'))
    elif drift == 'body':
        experiment.install(env.admin, experiment.baseline_sql().replace('begin\n', 'begin\n    -- synthetic drift\n', 1))
    elif drift == 'acl':
        env.admin.execute('grant execute on function '+experiment.READER+' to adlog_user')
    elif drift == 'owner':
        env.admin.execute('alter function '+experiment.READER+' owner to adlog_user')
    elif drift == 'search_path':
        env.admin.execute('alter function '+experiment.READER+' set search_path=public')
    elif drift == 'security':
        env.admin.execute('alter function '+experiment.READER+' security invoker')
    elif drift == 'volatility':
        env.admin.execute('alter function '+experiment.READER+' volatile')
    before = state(env.admin)
    try:
        with pytest.raises(psycopg.errors.RaiseException, match='migration 270 prerequisites failed'):
            env.admin.execute(MIGRATION.read_text('utf-8-sig'))
        env.admin.execute('rollback')
        assert state(env.admin) == before
        print('MIGRATION270_REJECT_RESULT='+json.dumps(dict(case=drift,
            reader_resolver_ledger_unchanged=True), sort_keys=True))
    finally:
        env.admin.execute('rollback')
        if drift == 'owner':
            env.admin.execute('alter function '+experiment.READER+' owner to adlog_storage_owner')
        if drift == 'acl':
            env.admin.execute('revoke execute on function '+experiment.READER+' from adlog_user')
        experiment.install(env.admin, experiment.baseline_sql())


def test_whole270_rejects_semantic_worker_migrator(ready):
    import psycopg
    env = ready
    before = state(env.admin)
    with pytest.raises(psycopg.errors.RaiseException, match='migration 270 prerequisites failed'):
        env.worker.execute(MIGRATION.read_text('utf-8-sig'))
    env.worker.execute('rollback')
    assert state(env.admin) == before


def test_whole270_rolls_back_reader_and_ledger_after_postddl_fault(ready):
    import psycopg
    env = ready
    before = state(env.admin)
    resolver_before = env.admin.execute('''select to_jsonb(p) from pg_proc p
      where p.oid=%s::regprocedure''', (experiment.RESOLVER,)).fetchone()[0]
    migration = MIGRATION.read_text('utf-8-sig')
    anchor = '\ncommit;\n'
    assert migration.count(anchor) == 1 and migration.endswith(anchor)
    fault = '''
do $postddl_fault$ begin
    if not exists(select 1 from pg_catalog.pg_proc p
        where p.oid=to_regprocedure('public.read_account_decoy_events(uuid,text,text,text,text,uuid)')
          and encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=
            '00d0458c557bbc046492f4dfe745b673ce397c94529379ab7e01f08e6709fe94')
       or not exists(select 1 from public.schema_migrations
          where version=270 and name='account_decoy_source_prefilter') then
        raise exception 'migration270_postddl_state_missing';
    end if;
    raise exception 'migration270_postddl_rollback_probe';
end $postddl_fault$;
'''
    injected = migration.replace(anchor, fault+anchor, 1)
    with pytest.raises(psycopg.errors.RaiseException) as error:
        env.admin.execute(injected)
    assert error.value.diag.message_primary == 'migration270_postddl_rollback_probe'
    env.admin.execute('rollback')
    after = state(env.admin)
    assert after == before
    assert env.admin.execute('''select to_jsonb(p) from pg_proc p
      where p.oid=%s::regprocedure''', (experiment.RESOLVER,)).fetchone()[0] == resolver_before
    print('MIGRATION270_POSTDDL_ROLLBACK_RESULT='+json.dumps(dict(
        fault_after_candidate_body_and_ledger_verified=True,
        expected_error=error.value.diag.message_primary,
        full_reader_pg_proc_row_restored=True, full_resolver_pg_proc_row_unchanged=True,
        ledger_restored=True,
        reader_body_before=hashlib.sha256(before['function']['prosrc'].encode()).hexdigest(),
        reader_body_after=hashlib.sha256(after['function']['prosrc'].encode()).hexdigest()), sort_keys=True))

"""Three actual producer COMMITs: K601 -> new empty W1200 -> K1202.

The disclosed frozen historical baseline is owner-seeded ONLY before poll1.
No intermediate CP/State/W/ledger writes, fake clock/reader/native callback, or
manual prepare/track/reserve/completion replaces a public producer poll.
"""
from datetime import timedelta
import json
from time import monotonic, sleep

import pytest

from server.sli.semantic import password_attack_producer as producer
from server.sli.semantic import password_attack_runtime, qw_input
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from tests.migrations.test_password_attacks_v2_coordinator_migration import (
    RULE, _event, _frozen_history, _native,
    acl_pg as acl_pg, coordinator_pg as coordinator_pg, native_pg as native_pg,
    password_base_pg as password_base_pg, password_pg as password_pg,
    reservation_pg as reservation_pg,
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
OLD_COMMITTED = (
    'reserved_ref_occurrences', 'reserved_portions', 'reserved_xml_bytes',
    'first_ledger_revision', 'admitted_revision', 'last_sequence',
    'last_emission_id', 'last_admitted_endpoint', 'last_admitted_as_of',
)


def _snapshot(observer):
    cp, = observer.execute('select * from semantic_password_checkpoints').fetchall()
    return {
        'cp': cp,
        'ledgers': observer.execute('select * from semantic_password_episode_budgets order by first_ledger_revision').fetchall(),
        'jobs': observer.execute('select * from semantic_risk_evaluation_jobs order by job_id').fetchall(),
        'signals': observer.execute('select signal_id from semantic_qw_signals order by signal_id').fetchall(),
    }


def _identity(worker):
    return worker.execute('select current_user as role,session_user as principal,pg_backend_pid() as pid,'
        '(select oid from pg_roles where rolname=session_user) as principal_oid').fetchone()


def _clock(worker):
    return worker.execute('select clock_timestamp() as at').fetchone()['at']


def _wait_clock(worker, target):
    # Harness deadline only: DB time remains the sole event/finalization clock.
    deadline = monotonic() + 30
    while (at := _clock(worker)) < target:
        assert monotonic() < deadline, 'disposable DB clock did not reach chronology target'
        sleep(min(0.1, (target - at).total_seconds()))
    return at


def _committed(worker, outcome, identity, before, after):
    assert not outcome.failed and outcome.status == 'committed', outcome
    assert _identity(worker) == identity and worker.info.transaction_status == 0
    cp, old = after['cp'], before['cp']
    assert cp['state_revision'] == old['state_revision'] + 1 == outcome.revision
    assert cp['active_token'] == cp['last_observed_token'] > old['last_observed_token']
    assert cp['watermark'] > old['watermark']
    assert cp['last_successful_cutoff'] == cp['watermark']
    assert cp['last_completed_at'] is not None
    assert cp['coverage_epoch'] == old['coverage_epoch'] == 0
    assert after['ledgers'][0]['episode_key'] == before['ledgers'][0]['episode_key']
    assert {k: after['ledgers'][0][k] for k in OLD_COMMITTED} == {
        k: before['ledgers'][0][k] for k in OLD_COMMITTED}


def _provisional(snapshot, pending, barrier):
    episode, = snapshot['cp']['state_document']['episodes']
    assert episode['seed']['ref']['native_id'] == episode['last']['ref']['native_id'] == '1000'
    assert episode['seed']['at'] == episode['last']['at'] == pending.member.witness.at.isoformat()
    assert episode['sequence'] == 0 and episode['root_id'] is None and episode['last_emission'] is None
    assert not episode['frozen'] and episode['budget'] == dict(ref_occurrences=0, portions=0, xml_bytes=0)
    assert episode['prequalification'] == [episode['seed']]
    assert episode['key'] != barrier.key
    ledger, = snapshot['ledgers']
    assert ledger['frozen'] and ledger['barrier_unresolved']
    assert ledger['successor_episode_key'] is ledger['successor_seed'] is ledger['successor_epoch'] is None
    assert ledger['tracking_endpoint']['ref']['native_id'] == barrier.last.ref.native_id
    assert ledger['tracking_through'] == snapshot['cp']['watermark'] and ledger['tracking_epoch'] == 0
    return episode


def test_actual_producer_601_then_new_empty_then_only_1202_successor(coordinator_pg):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    with psycopg.connect(coordinator_pg[0], autocommit=True, row_factory=dict_row) as observer:
        # Explicit initial-fixture exception: consistent past lifetime/freeze and
        # coverage are NOT public historical admission/completion evidence.
        # Age chosen once before construction; twelve seconds first-read headroom.
        _, frozen = _frozen_history(observer, age=1308, covered=600)
        barrier, = frozen.episodes
        endpoint = barrier.last.at
        pending = _event(1000, endpoint + timedelta(seconds=601))
        _native(observer, (pending.member.witness,))
        initial = _snapshot(observer)
        assert initial['cp']['watermark'] == endpoint + timedelta(seconds=600)
        assert initial['ledgers'][0]['tracking_through'] == initial['cp']['watermark']
        assert initial['ledgers'][0]['reserved_portions'] == 256

        with psycopg.connect(make_conninfo(coordinator_pg[0], user=coordinator_pg[1]),
                             autocommit=True, row_factory=dict_row) as worker:
            worker.execute('set role adlog_semantic_worker')
            assert assert_semantic_worker_least_privilege(worker.cursor())['exclusive_worker_membership']
            identity = _identity(worker)
            assert identity['role'] == 'adlog_semantic_worker' and identity['principal'] == coordinator_pg[1]
            before = _clock(worker)
            assert endpoint + timedelta(seconds=721) <= before
            assert before < endpoint + timedelta(seconds=1319.7), 'initial fixture exhausted first-read timing headroom'

            # POLL1. Only public producer may save provisional K601/State/W.
            first = producer.run_password_producer(worker, rule=RULE)
            one = _snapshot(observer)
            _committed(worker, first, identity, initial, one)
            provisional = _provisional(one, pending, barrier)
            assert first.jobs == 0 and first.work['reservation_calls'] == 0
            assert one['cp']['watermark'] <= endpoint + timedelta(seconds=1200)
            assert one['jobs'] == initial['jobs'] and one['signals'] == initial['signals']
            member, = one['cp']['state_document']['window']
            assert member['witness']['ref']['native_id'] == '1000'

            # POLL2. Actual DB clock crosses W1200. Already-seen K601 may be
            # reread/verified; empty means no NEW finalizable input/emission.
            _wait_clock(worker, endpoint + timedelta(seconds=1320.1))
            empty = producer.run_password_producer(worker, rule=RULE)
            two = _snapshot(observer)
            _committed(worker, empty, identity, one, two)
            assert _provisional(two, pending, barrier) == provisional
            assert two['cp']['watermark'] >= endpoint + timedelta(seconds=1200)
            assert empty.jobs == 0 and empty.work['reservation_calls'] == 0
            assert two['jobs'] == initial['jobs'] and two['signals'] == initial['signals']
            new_finalizable = observer.execute('''select count(*) as n from events_v2_core
                where log_source_id=7 and event_id in (4625,4771,4776)
                  and time_created_utc between %s and %s and time_created_utc>%s''',
                (two['cp']['watermark'] - timedelta(seconds=600), two['cp']['watermark'],
                 one['cp']['watermark'])).fetchone()['n']
            assert new_finalizable == 0
            current_candidates = observer.execute('''select count(*) as n from events_v2_core
                where log_source_id=7 and event_id in (4625,4771,4776)
                  and time_created_utc between %s and %s''',
                (two['cp']['watermark'] - timedelta(seconds=600),
                 two['cp']['watermark'] + timedelta(seconds=120))).fetchone()['n']
            assert {m['witness']['ref']['native_id'] for m in two['cp']['state_document']['window']} <= {'1000'}

            # Native append only after empty COMMIT. No intermediate owner
            # checkpoint/State/W/ledger write or public tracking shortcut.
            actual = tuple(_event(1001 + n, endpoint + timedelta(seconds=1202, microseconds=n))
                           for n in range(10))
            _native(observer, tuple(event.member.witness for event in actual))
            _wait_clock(worker, actual[-1].at + timedelta(seconds=120.1))

            # POLL3. Public producer itself tracks/reserves/queues actual K1202.
            third = producer.run_password_producer(worker, rule=RULE)
            three = _snapshot(observer)
            _committed(worker, third, identity, two, three)
            assert third.jobs == third.work['reservation_calls'] == third.work['tracking_calls'] == 1
            old, new = three['ledgers']
            assert old['frozen'] and not old['barrier_unresolved']
            assert old['successor_episode_key'] == new['episode_key'] != provisional['key']
            assert new['predecessor_episode_key'] == old['episode_key'] == barrier.key
            assert old['successor_seed'] == new['seed']
            assert new['seed']['ref']['native_id'] == '1001' and old['successor_epoch'] == new['coverage_epoch'] == 0
            assert not new['frozen'] and new['last_sequence'] == 1
            assert new['first_ledger_revision'] == new['admitted_revision'] == third.revision
            assert new['reserved_ref_occurrences'] == 10 and new['reserved_portions'] == 1
            assert all(row['episode_key'] != provisional['key'] for row in three['ledgers'])
            assert [job for job in three['jobs'] if job['job_id'] in {j['job_id'] for j in initial['jobs']}] == initial['jobs']
            assert len(three['jobs']) == len(initial['jobs']) + 1
            new_ids = {r['signal_id'] for r in three['signals']} - {r['signal_id'] for r in initial['signals']}
            signal_id, = new_ids
            signal = qw_input.load_qw_signal(worker.cursor(), signal_id=signal_id)
            episode = password_attack_runtime.load_episode(worker.cursor(), signal)
            emission, = episode.emissions
            assert emission.seed == actual[0].member.witness and emission.sequence == 1
            assert emission.previous_id is None and emission.predecessor is None
            assert emission.episode_key == new['episode_key'] and signal.episode_key == new['episode_key']
            assert emission.occurrences == tuple(event.member.witness for event in actual)
            assert {ref.native_id for ref in signal.evidence_refs} == {str(n) for n in range(1001, 1011)}
            assert signal.password_context['occurrence_total'] == signal.evidence_total == 10
            assert _identity(worker) == identity and worker.info.transaction_status == 0
            print('SUCCESSOR_CHRONOLOGY_PROOF=' + json.dumps({
                'public_producer_polls': 3, 'same_physical_login_oid_pid_role': True,
                'initial_owner_historical_baseline_only': True, 'initial_age': 1308, 'initial_covered': 600,
                'revisions': [s['cp']['state_revision'] for s in (initial, one, two, three)],
                'tokens': [s['cp']['last_observed_token'] for s in (initial, one, two, three)],
                'watermarks_relative_seconds': [(s['cp']['watermark'] - endpoint).total_seconds()
                                                for s in (initial, one, two, three)],
                'empty_current_candidates': current_candidates, 'empty_new_finalizable': new_finalizable,
                'first_jobs': first.jobs, 'empty_jobs': empty.jobs, 'third_jobs': third.jobs,
                'new_successor_refs': len(signal.evidence_refs), 'k601_has_no_ledger': True,
                'old_admitted_totals_unchanged': True, 'reciprocal_k1202_links': True,
                'intermediate_owner_state_writes': False, 'default_switch': False,
            }, sort_keys=True))
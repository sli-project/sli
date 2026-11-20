"""Actual lost-horizon producer keeps the old positive-L frozen barrier.

Owner historical State/ledger/coverage setup is allowed ONLY before the public
poll. No private State/CP/W/ledger write, fake clock/reader, manual tracking or
reservation replaces the ordinary physical semantic producer transaction.
"""
from datetime import timedelta
import json

import pytest

from server.sli.semantic import password_attack_producer as producer
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from tests.migrations.test_password_attacks_v2_coordinator_migration import (
    RULE, _event, _frozen_history, _native,
    acl_pg as acl_pg, coordinator_pg as coordinator_pg, native_pg as native_pg,
    password_base_pg as password_base_pg, password_pg as password_pg,
    reservation_pg as reservation_pg,
)
from tests.migrations.test_password_producer_successor_chronology import OLD_COMMITTED, _identity, _snapshot

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def test_actual_cold_producer_rebases_tracking_but_never_authorizes_k601(coordinator_pg):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    with psycopg.connect(coordinator_pg[0], autocommit=True, row_factory=dict_row) as observer:
        # Explicit initial exception: this owner-seeded historical lifetime and
        # frozen barrier are NOT public historical admission/freeze evidence.
        _, frozen = _frozen_history(observer, age=1308, covered=300)
        barrier, = frozen.episodes
        endpoint = barrier.last.at
        pending = _event(1000, endpoint + timedelta(seconds=601))
        _native(observer, (pending.member.witness,))
        initial = _snapshot(observer)
        old, = initial['ledgers']
        old_state, = initial['cp']['state_document']['episodes']
        assert old_state['frozen'] and old_state['key'] == old['episode_key'] == barrier.key
        assert old_state['sequence'] == old['last_sequence'] == old['reserved_portions'] == 256
        assert initial['cp']['watermark'] == old['tracking_through'] == endpoint + timedelta(seconds=300)
        assert initial['cp']['coverage_epoch'] == old['coverage_epoch'] == old['tracking_epoch'] == 0

        # Same physical LOGIN and ordinary role; observer never executes producer.
        with psycopg.connect(make_conninfo(coordinator_pg[0], user=coordinator_pg[1]),
                             autocommit=True, row_factory=dict_row) as worker:
            worker.execute('set role adlog_semantic_worker')
            assert assert_semantic_worker_least_privilege(worker.cursor())['exclusive_worker_membership']
            identity = _identity(worker)
            assert identity['role'] == 'adlog_semantic_worker' and identity['principal'] == coordinator_pg[1]
            stamp = worker.execute('select clock_timestamp() as at').fetchone()['at']
            lower, final = stamp - timedelta(seconds=720), stamp - timedelta(seconds=120)
            assert initial['cp']['watermark'] < lower
            assert lower < pending.at - timedelta(seconds=0.3), 'initial fixture exhausted native K601 read headroom'
            assert final >= pending.at

            # The ONLY producer call owns actual native proof, epoch transition,
            # public finalizer tracking and COMMIT. No owner writes after it.
            outcome = producer.run_password_producer(worker, rule=RULE)
            after = _snapshot(observer)
            assert not outcome.failed and outcome.status == 'committed', outcome
            assert outcome.jobs == 0 and outcome.work['reservation_calls'] == 0
            assert _identity(worker) == identity and worker.info.transaction_status == 0
            cp = after['cp']
            assert cp['state_revision'] == initial['cp']['state_revision'] + 1 == outcome.revision
            assert cp['active_token'] == cp['last_observed_token'] > initial['cp']['last_observed_token']
            assert cp['watermark'] > initial['cp']['watermark']
            assert cp['last_successful_cutoff'] == cp['watermark'] and cp['last_completed_at'] is not None
            assert cp['coverage_epoch'] == cp['state_document']['epoch'] == 1
            assert cp['health_status'] == outcome.health['status'] == 'partial'
            assert outcome.health['loss']['coverage_gap']['count_lower_bound'] >= 1
            # The actual committed reader bounds put K601 inside the cold window.
            assert initial['cp']['watermark'] < cp['watermark'] - timedelta(seconds=600) <= pending.at
            assert cp['watermark'] >= pending.at

            # Pure clears epoch0 working episodes, but ordinary producer restores
            # the durable OLD key/root/positive sequence/budget, still frozen.
            episode, = cp['state_document']['episodes']
            for key in ('key', 'entity', 'seed', 'root_id', 'last_emission', 'sequence', 'budget', 'frozen'):
                assert episode[key] == old_state[key], key
            assert episode['frozen'] and episode['sequence'] == 256
            assert episode['last']['ref']['native_id'] == '1000'
            assert episode['last']['at'] == pending.at.isoformat()
            assert episode['prequalification'] == []
            member, = cp['state_document']['window']
            assert member['witness'] == episode['last']

            ledger, = after['ledgers']
            assert ledger['episode_key'] == barrier.key and ledger['frozen'] and ledger['barrier_unresolved']
            assert {k: ledger[k] for k in OLD_COMMITTED} == {k: old[k] for k in OLD_COMMITTED}
            assert ledger['coverage_epoch'] == 0 and ledger['tracking_epoch'] == 1
            assert ledger['tracking_endpoint'] == episode['last']
            assert ledger['tracking_through'] == cp['watermark']
            assert ledger['successor_episode_key'] is ledger['successor_seed'] is ledger['successor_epoch'] is None
            assert ledger['predecessor_episode_key'] is None
            assert after['jobs'] == initial['jobs'] and after['signals'] == initial['signals']
            assert all(row['seed']['ref']['native_id'] != '1000' for row in after['ledgers'])
            assert _identity(worker) == identity
            print('COLD_BARRIER_PROOF=' + json.dumps({
                'public_producer_polls': 1, 'same_physical_login_oid_pid_role': True,
                'initial_owner_historical_baseline_only': True, 'initial_age': 1308, 'initial_covered': 300,
                'revisions': [initial['cp']['state_revision'], cp['state_revision']],
                'tokens': [initial['cp']['last_observed_token'], cp['last_observed_token']],
                'watermarks_relative_seconds': [(initial['cp']['watermark'] - endpoint).total_seconds(),
                                                (cp['watermark'] - endpoint).total_seconds()],
                'reader_lower_relative_seconds': (cp['watermark'] - timedelta(seconds=600) - endpoint).total_seconds(),
                'coverage_epoch': [initial['cp']['coverage_epoch'], cp['coverage_epoch']],
                'ledger_coverage_epoch': ledger['coverage_epoch'], 'tracking_epoch': ledger['tracking_epoch'],
                'coverage_gap_count_lower_bound': outcome.health['loss']['coverage_gap']['count_lower_bound'],
                'old_positive_frozen_state_key_budget_preserved': True,
                'k601_as_tracking_not_successor': True, 'old_barrier_unresolved': True,
                'successor_fields_null': True, 'k601_has_no_ledger': True,
                'old_admitted_totals_jobs_qw_unchanged': True, 'jobs': outcome.jobs,
                'intermediate_owner_state_writes': False, 'default_switch': False,
            }, sort_keys=True))
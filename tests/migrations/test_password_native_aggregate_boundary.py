"""Actual shared incoming+unaffected retained32MiB edge; disposable PG only."""
from contextlib import contextmanager
from datetime import timedelta

import pytest

from server.sli.semantic import password_attack_producer as producer
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from tests.migrations.test_password_attack_producer_pipeline import (
    RULE, _connection, _seed, _xml, _replace_xml,
    _wait_until_early_events_leave_actual_window,
    acl_pg as acl_pg, coordinator_pg as coordinator_pg, native_pg as native_pg,
    password_base_pg as password_base_pg, password_pg as password_pg,
    reservation_pg as reservation_pg,
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
CAP = 33_554_432
RETAINED = 6_000_000


@contextmanager
def _physical_worker(source):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    with psycopg.connect(make_conninfo(source[0], user=source[1]),
                         autocommit=True, row_factory=dict_row) as worker:
        worker.execute("set role adlog_semantic_worker")
        assert assert_semantic_worker_least_privilege(worker.cursor())["exclusive_worker_membership"]
        assert worker.execute("select session_user as u").fetchone()["u"] == source[1]
        yield worker


def _snapshot(admin):
    return (admin.execute("select * from semantic_password_checkpoints").fetchone(),
            admin.execute("select * from semantic_password_episode_budgets").fetchone(),
            admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"],
            admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"])


@pytest.mark.parametrize("excess", [0, 1], ids=["exact32MiB", "overByOne"])
def test_actual_incoming_and_unaffected_retained_share_exact_budget(coordinator_pg, excess):
    # A is committed by the actual producer, not an owner CP/State/ledger seed.
    # Only its seed and last witnesses are large; no lifetime cap is approached.
    with _connection(coordinator_pg) as admin:
        early = admin.execute("select clock_timestamp()-interval '710 seconds' as t").fetchone()["t"]
        _seed(admin, 10, at=early)
        for native_id in (1, 10):
            _replace_xml(admin, native_id, _xml(early, native_id, size=3_000_000))
    with _physical_worker(coordinator_pg) as worker:
        first = producer.run_password_producer(worker, rule=RULE)
        assert not first.failed and first.jobs == 1 and first.revision == 1
        assert first.work["native_items"] == first.work["reservation_occurrences"] == 10
        assert worker.info.transaction_status == 0
    with _connection(coordinator_pg) as admin:
        before, ledger, signals, jobs = _snapshot(admin)
        assert signals == jobs == ledger["last_sequence"] == 1
        assert RETAINED < ledger["reserved_xml_bytes"] < CAP
        a = before["state_document"]["episodes"][0]
        assert a["seed"]["xml_bytes"] + a["last"]["xml_bytes"] == RETAINED
        assert not ledger["frozen"]

    _wait_until_early_events_leave_actual_window(coordinator_pg, early)
    with _connection(coordinator_pg) as admin:
        # Seven finalized independent B failures cannot qualify brute10 or
        # continue A. They all fall after the real first committed watermark.
        at = before["watermark"] + timedelta(microseconds=1)
        _seed(admin, 7, at=at, start=11)
        total = CAP - RETAINED + excess
        unit, remainder = divmod(total, 7)
        for offset, native_id in enumerate(range(11, 18)):
            size = unit + (remainder if offset == 6 else 0)
            xml = _xml(at, native_id, size=size).replace("fixture-account", "fixture-otherxx")
            assert len(xml.encode("utf-8")) == size <= 4_194_304
            _replace_xml(admin, native_id, xml)
        # Actual persisted XML byte lengths, not a fabricated cost callback.
        counts = admin.execute("""select count(*) as n,
            sum(octet_length(convert_to(event_rows->0->>'xml','UTF8'))) as bytes
            from sli_agent_packet_inbox where packet_id in
            (select md5('password-v2-fixture-'||g::text)::uuid from generate_series(11,17) g)""").fetchone()
        assert counts["n"] == 7 and counts["bytes"] == total < CAP

    with _physical_worker(coordinator_pg) as worker:
        outcome = producer.run_password_producer(worker, rule=RULE)
        assert worker.info.transaction_status == 0
        assert outcome.jobs == 0
        if not excess:
            assert not outcome.failed and outcome.status == "committed" and outcome.revision == 2
            assert outcome.health["status"] == "healthy"
            assert outcome.work["native_items"] == 9
            assert outcome.work["xml_bytes"] == CAP
            assert outcome.work["retained_queries"] == outcome.work["completion_calls"] == 1
            assert outcome.work["reservation_calls"] == outcome.work["reservation_occurrences"] == 0
        else:
            # No fresh qualified A endpoint exists: aggregate failure rolls
            # TxB back, then the same issued token is observed by normal TxC.
            assert outcome.failed and outcome.failure_observed and outcome.revision is None

    with _connection(coordinator_pg) as admin:
        after, after_ledger, after_signals, after_jobs = _snapshot(admin)
        assert after_ledger == ledger and after_signals == signals and after_jobs == jobs
        assert after["active_token"] == after["last_observed_token"] > before["active_token"]
        if not excess:
            assert after["state_revision"] == before["state_revision"] + 1
            assert after["watermark"] > before["watermark"]
            assert after["last_successful_cutoff"] == after["watermark"]
            state = after["state_document"]
            assert len(state["episodes"]) == 2
            assert next(e for e in state["episodes"] if e["key"] == a["key"]) == a
            b, = [e for e in state["episodes"] if e["key"] != a["key"]]
            assert b["sequence"] == 0 and b["root_id"] is None and not b["frozen"]
            assert b["budget"] == {"ref_occurrences": 0, "portions": 0, "xml_bytes": 0}
            assert len(b["prequalification"]) == 7
            assert len(state["window"]) == 7
            assert {m["target_key"] for m in state["window"]}.isdisjoint(
                {m["target_key"] for m in before["state_document"]["window"]})
        else:
            for key in ("state_revision", "watermark", "last_successful_cutoff", "state_document"):
                assert after[key] == before[key]
            assert after["health_status"] == "error"

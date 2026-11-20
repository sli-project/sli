from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.semantic.semantic_correlation_repository import (
    CorrelationRuleDefinition,
    register_correlation_rule,
    transition_correlation_rule,
)
from server.sli.semantic.semantic_dispatch import (
    compile_correlation_rule,
    match_compiled_rule,
)
from server.sli.semantic.semantic_dispatch_repository import (
    claim_dispatch_jobs,
    complete_dispatch_job,
    enqueue_dispatch_jobs,
    expire_correlation_candidates,
    load_dispatch_work_item,
    persist_dispatched_relation,
    replace_rule_subscriptions,
)
from server.sli.semantic.semantic_processing import StoredEvent, normalize_windows_event
from server.sli.semantic.semantic_processing_repository import persist_normalized_event
from tests.postgres_integration_guard import assert_disposable_database


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_dispatch_late_evidence_reopens_once_in_disposable_postgres() -> None:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL tests")

    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    rule_id = "dispatch-session-special-privileges"
    source_ids = (920001, 920002)
    with connect() as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        cur.execute(
            "select 1 from schema_migrations "
            "where version=27 and name='semantic_dispatch_foundation'"
        )
        assert cur.fetchone() is not None
        cur.execute(
            "update semantic_correlation_rules set lifecycle_status='draft' "
            "where rule_id=%s",
            (rule_id,),
        )
        cur.execute(
            "delete from semantic_correlation_dispatch_jobs where rule_id=%s", (rule_id,)
        )
        cur.execute(
            "delete from semantic_correlation_candidate_evidence where candidate_id in "
            "(select candidate_id from semantic_correlation_candidates where rule_id=%s)",
            (rule_id,),
        )
        cur.execute("delete from semantic_correlation_candidates where rule_id=%s", (rule_id,))
        cur.execute("delete from semantic_correlation_replays where rule_id=%s", (rule_id,))
        cur.execute("delete from semantic_correlation_subscriptions where rule_id=%s", (rule_id,))
        cur.execute("delete from semantic_correlation_rules where rule_id=%s", (rule_id,))
        cur.execute("delete from normalized_events where source_event_id=any(%s)", (list(source_ids),))
        cur.execute("delete from semantic_processing_outbox where source_event_id=any(%s)", (list(source_ids),))
        cur.execute("delete from events_v2_core where id=any(%s)", (list(source_ids),))

    occurred = datetime(2026, 7, 19, 3, tzinfo=timezone.utc)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "insert into storage_v2_provider(value) values ('Microsoft-Windows-Security-Auditing') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        provider_id = cur.fetchone()["id"]
        cur.execute(
            "insert into storage_v2_channel(value) values ('Security') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        channel_id = cur.fetchone()["id"]
        cur.execute(
            "insert into storage_v2_computer(value) values ('dispatch-dc') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        computer_id = cur.fetchone()["id"]
        for index, (source_id, event_id) in enumerate(zip(source_ids, (4624, 4672))):
            event_time = occurred + timedelta(seconds=index)
            ingested = event_time + (timedelta(minutes=10) if index else timedelta(seconds=5))
            cur.execute(
                """
                insert into events_v2_core(
                    id,server_id,domain_id,log_source_id,event_record_id,event_id,
                    provider_id,channel_id,computer_id,time_created_utc,
                    normalized_at,normalized_hash,source_core_sha256,migrated_at
                ) values (%s,1,1,1,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    source_id,
                    source_id,
                    event_id,
                    provider_id,
                    channel_id,
                    computer_id,
                    event_time,
                    event_time,
                    bytes([event_id % 251]) * 32,
                    bytes([(event_id + 1) % 251]) * 32,
                    ingested,
                ),
            )
        normalized = (
            normalize_windows_event(
                StoredEvent(
                    920001,
                    4624,
                    "Security",
                    "DC1",
                    occurred,
                    {"TargetUserSid": "S-1-5-21-200", "TargetLogonId": "0xdef"},
                    provider="Microsoft-Windows-Security-Auditing",
                    source_host_id=1,
                )
            ),
            normalize_windows_event(
                StoredEvent(
                    920002,
                    4672,
                    "Security",
                    "DC1",
                    occurred + timedelta(seconds=1),
                    {"SubjectUserSid": "S-1-5-21-200", "SubjectLogonId": "0xdef"},
                    provider="Microsoft-Windows-Security-Auditing",
                    source_host_id=1,
                )
            ),
        )
        normalized_ids = [persist_normalized_event(cur, event=item) for item in normalized]
        definition = CorrelationRuleDefinition(
            rule_id=rule_id,
            rule_version=1,
            rule_kind="all_of",
            definition={
                "type": "all_of",
                "inputs": [
                    "authentication.session.created",
                    "authentication.privileged_session.created",
                ],
                "join_roles": ["source_host", "session_principal"],
                "window_seconds": 900,
                "output_relation_kind": "authentication.session.has_special_privileges",
                "confidence": "high",
                "explanation": "same source host and session principal",
            },
        )
        register_correlation_rule(cur, rule=definition)
        compiled = compile_correlation_rule(definition)
        replace_rule_subscriptions(cur, rule=compiled)
        replace_rule_subscriptions(cur, rule=compiled)
        transition_correlation_rule(
            cur, rule_id=rule_id, rule_version=1, target_status="validated"
        )
        transition_correlation_rule(
            cur, rule_id=rule_id, rule_version=1, target_status="test"
        )
        jobs = tuple(
            job_id
            for normalized_id in normalized_ids
            for job_id in enqueue_dispatch_jobs(cur, normalized_event_id=normalized_id)
        )
        assert len(jobs) == 2

    with connect() as conn, conn.cursor() as cur:
        claimed = claim_dispatch_jobs(cur, limit=2)
        assert len(claimed) == 2
        work = [
            load_dispatch_work_item(
                cur, job_id=str(row["job_id"]), lease_token=str(row["lease_token"])
            )
            for row in claimed
        ]
        non_late = next(item for item in work if not item.is_late)
        late = next(item for item in work if item.is_late)
        first_relation = match_compiled_rule(non_late.rule, non_late.events)[0]
        assert first_relation.source_event_ids == source_ids
        initial = persist_dispatched_relation(
            cur, rule=non_late.rule, relation=first_relation
        )
        assert initial.candidate_status == "matched"
        assert initial.reopen_count == 0
        assert expire_correlation_candidates(
            cur, before_utc=occurred + timedelta(hours=1)
        ) == (initial.candidate_id,)
        late_relation = match_compiled_rule(late.rule, late.events)[0]
        reopened = persist_dispatched_relation(
            cur,
            rule=late.rule,
            relation=late_relation,
            late_source_event_ids=(late.trigger_source_event_id,),
        )
        assert reopened.candidate_id == initial.candidate_id
        assert reopened.candidate_status == "matched"
        assert reopened.reopen_count == 1
        assert reopened.late_evidence_count == 1
        replayed = persist_dispatched_relation(
            cur,
            rule=late.rule,
            relation=late_relation,
            late_source_event_ids=(late.trigger_source_event_id,),
        )
        assert replayed.reopen_count == 1
        assert replayed.late_evidence_count == 1
        for item in work:
            complete_dispatch_job(
                cur, job_id=item.job_id, lease_token=item.lease_token
            )

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "select candidate_status,reopen_count,late_evidence_count,"
            "last_evidence_occurred_at is not null as has_last "
            "from semantic_correlation_candidates where rule_id=%s",
            (rule_id,),
        )
        assert cur.fetchone() == {
            "candidate_status": "matched",
            "reopen_count": 1,
            "late_evidence_count": 1,
            "has_last": True,
        }
        cur.execute(
            "select count(*) filter(where is_late) as late_count "
            "from semantic_correlation_candidate_evidence"
        )
        assert cur.fetchone()["late_count"] == 1
        cur.execute(
            "select count(*) filter(where dispatch_status='completed') as completed "
            "from semantic_correlation_dispatch_jobs where rule_id=%s",
            (rule_id,),
        )
        assert cur.fetchone()["completed"] == 2

    with pytest.raises(psycopg.Error, match="immutable outside draft"), connect() as conn, conn.cursor() as cur:
        cur.execute(
            "update semantic_correlation_subscriptions set semantic_type='type.changed' "
            "where rule_id=%s and subscription_order=0",
            (rule_id,),
        )

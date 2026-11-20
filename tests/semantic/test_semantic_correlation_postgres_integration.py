from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.semantic.semantic_correlation import (
    correlate_session_privilege_observation,
)
from server.sli.semantic.semantic_correlation_repository import (
    CorrelationRuleDefinition,
    claim_correlation_replays,
    complete_correlation_replay,
    persist_correlation_candidate,
    register_correlation_rule,
    schedule_correlation_replay,
    transition_correlation_rule,
)
from server.sli.semantic.semantic_processing import StoredEvent, normalize_windows_event
from server.sli.semantic.semantic_processing_repository import persist_normalized_event
from tests.postgres_integration_guard import assert_disposable_database


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_rule_candidate_and_bounded_replay_are_durable_and_idempotent() -> None:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")

    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    with connect() as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        cur.execute(
            "select 1 from schema_migrations "
            "where version=26 and name='semantic_correlation_foundation'"
        )
        assert cur.fetchone() is not None
        cur.execute("delete from semantic_correlation_candidate_evidence")
        cur.execute("delete from semantic_correlation_candidates")
        cur.execute("delete from semantic_correlation_replays")
        cur.execute("delete from semantic_correlation_rules")
        cur.execute("delete from normalized_events where source_event_id in (910001,910002)")
        cur.execute("delete from semantic_processing_outbox where source_event_id in (910001,910002)")
        cur.execute("delete from events_v2_core where id in (910001,910002)")

    occurred = datetime(2026, 7, 19, 2, tzinfo=timezone.utc)
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
            "insert into storage_v2_computer(value) values ('correlation-dc') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        computer_id = cur.fetchone()["id"]
        for source_id, event_id in ((910001, 4624), (910002, 4672)):
            cur.execute(
                """
                insert into events_v2_core(
                    id,server_id,domain_id,log_source_id,event_record_id,event_id,
                    provider_id,channel_id,computer_id,time_created_utc,
                    normalized_at,normalized_hash,source_core_sha256
                ) values (%s,1,1,1,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    source_id,
                    source_id,
                    event_id,
                    provider_id,
                    channel_id,
                    computer_id,
                    occurred + timedelta(seconds=source_id - 910001),
                    occurred,
                    bytes([event_id % 251]) * 32,
                    bytes([(event_id + 1) % 251]) * 32,
                ),
            )
        normalized = (
            normalize_windows_event(
                StoredEvent(
                    910001,
                    4624,
                    "Security",
                    "DC1",
                    occurred,
                    {"TargetUserSid": "S-1-5-21-100", "TargetLogonId": "0xabc"},
                    provider="Microsoft-Windows-Security-Auditing",
                    source_host_id=1,
                )
            ),
            normalize_windows_event(
                StoredEvent(
                    910002,
                    4672,
                    "Security",
                    "DC1",
                    occurred + timedelta(seconds=1),
                    {"SubjectUserSid": "S-1-5-21-100", "SubjectLogonId": "0xabc"},
                    provider="Microsoft-Windows-Security-Auditing",
                    source_host_id=1,
                )
            ),
        )
        for event in normalized:
            persist_normalized_event(cur, event=event)

        rule = CorrelationRuleDefinition(
            rule_id="session-special-privileges",
            rule_version=1,
            rule_kind="all_of",
            definition={
                "type": "all_of",
                "inputs": [
                    "authentication.session.created",
                    "authentication.privileged_session.created",
                ],
                "window_seconds": 900,
            },
        )
        register_correlation_rule(cur, rule=rule)
        register_correlation_rule(cur, rule=rule)
        assert transition_correlation_rule(
            cur, rule_id=rule.rule_id, rule_version=1, target_status="validated"
        ) == "validated"
        assert transition_correlation_rule(
            cur, rule_id=rule.rule_id, rule_version=1, target_status="test"
        ) == "test"
        relation = correlate_session_privilege_observation(normalized)[0]
        first_candidate = persist_correlation_candidate(
            cur, rule_id=rule.rule_id, rule_version=1, relation=relation
        )
        assert persist_correlation_candidate(
            cur, rule_id=rule.rule_id, rule_version=1, relation=relation
        ) == first_candidate
        replay_id = schedule_correlation_replay(
            cur,
            rule_id=rule.rule_id,
            rule_version=1,
            range_start_utc=occurred - timedelta(minutes=1),
            range_end_utc=occurred + timedelta(minutes=1),
        )
        assert schedule_correlation_replay(
            cur,
            rule_id=rule.rule_id,
            rule_version=1,
            range_start_utc=occurred - timedelta(minutes=1),
            range_end_utc=occurred + timedelta(minutes=1),
        ) == replay_id

    with connect() as conn, conn.cursor() as cur:
        replay = claim_correlation_replays(cur, limit=1)[0]
        complete_correlation_replay(
            cur,
            replay_id=str(replay["replay_id"]),
            lease_token=str(replay["lease_token"]),
            checkpoint_utc=occurred + timedelta(seconds=1),
            processed_events=2,
            matched_candidates=1,
        )

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "select evidence_count,candidate_status from semantic_correlation_candidates"
        )
        candidate = cur.fetchone()
        assert candidate == {"evidence_count": 2, "candidate_status": "matched"}
        cur.execute("select count(*) as value from semantic_correlation_candidate_evidence")
        assert cur.fetchone()["value"] == 2
        cur.execute(
            "select replay_status,processed_events,matched_candidates "
            "from semantic_correlation_replays"
        )
        assert cur.fetchone() == {
            "replay_status": "completed",
            "processed_events": 2,
            "matched_candidates": 1,
        }

    with pytest.raises(psycopg.Error, match="immutable"), connect() as conn, conn.cursor() as cur:
        cur.execute(
            "update semantic_correlation_rules "
            "set definition_json='{\"type\":\"count\"}'::jsonb "
            "where rule_id='session-special-privileges' and rule_version=1"
        )

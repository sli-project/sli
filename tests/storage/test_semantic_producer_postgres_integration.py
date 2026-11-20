from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from server.sli.semantic.semantic_producer import (
    publish_investigation_candidates,
    publish_semantic_candidates,
)
from server.sli.storage.storage_v2_models import EventCoreV2
from server.sli.storage.storage_v2_repository import (
    PostgresStorageV2Repository,
    core_chunk_digest,
)
from tests.postgres_integration_guard import assert_disposable_database

SIGNAL_EVENT_ID = 8_100_001
DIRECT_EVENT_ID = 8_100_002
DIRECT_RESET_EVENT_ID = 8_100_003
DIRECT_OUT_OF_SCOPE_EVENT_ID = 8_100_004
DIRECT_CONTEXT_EVENT_ID = 8_100_005
DIRECT_EVENTLOG_EVENT_ID = 8_100_006


def _create_contract(conn) -> tuple[int, int, int]:
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            """
            create table storage_v2_channel(
                id integer generated always as identity primary key,
                value text not null unique
            );
            create table storage_v2_provider(
                id integer generated always as identity primary key,
                value text not null unique
            );
            create table storage_v2_computer(
                id integer generated always as identity primary key,
                value text not null unique
            );
            create table storage_v2_keywords(
                id integer generated always as identity primary key,
                value text not null unique
            );
            create table events_v2_core(
                id integer primary key,
                raw_log_file_id integer,
                server_id integer not null,
                domain_id integer not null,
                site_id integer,
                log_source_id integer not null,
                event_record_id bigint,
                event_id integer not null,
                version integer,
                level integer,
                task integer,
                opcode integer,
                keywords_id integer references storage_v2_keywords(id),
                channel_id integer not null references storage_v2_channel(id),
                provider_id integer references storage_v2_provider(id),
                computer_id integer,
                time_created_utc timestamptz not null,
                subject_user_sid text,
                subject_user_name text,
                subject_domain_id integer,
                target_user_sid text,
                target_user_name text,
                target_domain_id integer,
                ip_address text,
                workstation_name text,
                logon_id text,
                correlation_id text,
                normalized_at timestamptz,
                normalized_hash bytea not null,
                noise_class text,
                noise_catalog_version integer,
                source_core_sha256 bytea,
                migrated_at timestamptz not null default now()
            );
            create table event_entity_link_blocks_v2(
                entity_id integer not null,
                block_no integer not null,
                first_event_id integer not null,
                last_event_id integer not null,
                event_ids integer[] not null,
                role_ids integer[] not null,
                identity_sha256 bytea not null,
                primary key(entity_id,block_no)
            );
            create table semantic_processing_outbox(
                job_id uuid primary key,
                source_event_id integer not null references events_v2_core(id),
                job_kind text not null check (job_kind in (
                    'normalize_event','assemble_action','semantic_replay',
                    'investigation_context'
                )),
                semantic_contract_version integer not null,
                processor_id text not null,
                processor_version text not null,
                idempotency_key bytea not null unique,
                status text not null default 'queued',
                attempt_count integer not null default 0,
                max_attempts integer not null default 5,
                available_at timestamptz not null default now(),
                lease_token uuid,
                lease_until timestamptz,
                heartbeat_at timestamptz,
                payload_json jsonb not null default '{}'::jsonb,
                source_identity_json jsonb not null default '{}'::jsonb,
                last_error_code text,
                last_error_detail text,
                created_at timestamptz not null default now(),
                updated_at timestamptz not null default now(),
                completed_at timestamptz,
                source_id bigint,
                domain_id bigint,
                partition_key text,
                occurred_at_utc timestamptz,
                emitted_at timestamptz not null default now(),
                unique(
                    source_event_id,job_kind,semantic_contract_version,
                    processor_id,processor_version
                )
            )
            """
        )
        cur.execute(
            "insert into storage_v2_channel(value) values ('Security') returning id"
        )
        channel_id = int(cur.fetchone()["id"])
        cur.execute(
            "insert into storage_v2_provider(value) "
            "values ('Microsoft-Windows-Security-Auditing') returning id"
        )
        provider_id = int(cur.fetchone()["id"])
        cur.execute(
            "insert into storage_v2_provider(value) "
            "values ('Microsoft-Windows-Eventlog') returning id"
        )
        eventlog_provider_id = int(cur.fetchone()["id"])
    return channel_id, provider_id, eventlog_provider_id


def _direct_signal_event(*, channel_id: int, provider_id: int) -> EventCoreV2:
    source_hash = b"d" * 32
    return EventCoreV2(
        values={
            "id": DIRECT_EVENT_ID,
            "raw_log_file_id": 11,
            "server_id": 1,
            "domain_id": 1,
            "site_id": None,
            "log_source_id": 1,
            "event_record_id": 81_000_002,
            "event_id": 4625,
            "version": 0,
            "level": 0,
            "task": 12544,
            "opcode": 0,
            "keywords_id": None,
            "provider_id": provider_id,
            "channel_id": channel_id,
            "computer_id": None,
            "time_created_utc": datetime(2026, 7, 29, 10, 5, tzinfo=timezone.utc),
            "subject_user_sid": "S-1-5-18",
            "subject_user_name": "SYSTEM",
            "subject_domain_id": 1,
            "target_user_sid": "S-1-5-21-8100002",
            "target_user_name": "direct-user",
            "target_domain_id": 1,
            "ip_address": "192.0.2.10",
            "workstation_name": "WS-DIRECT",
            "logon_id": "0x8100002",
            "correlation_id": None,
            "normalized_at": datetime(2026, 7, 29, 10, 6, tzinfo=timezone.utc),
            "normalized_hash": b"n" * 32,
            "noise_class": "signal",
            "noise_catalog_version": 1,
        },
        source_core_sha256=source_hash,
    )


def _direct_out_of_scope_signal_event(
    *,
    channel_id: int,
    provider_id: int,
) -> EventCoreV2:
    direct = _direct_signal_event(channel_id=channel_id, provider_id=provider_id)
    return EventCoreV2(
        values={
            **direct.values,
            "id": DIRECT_OUT_OF_SCOPE_EVENT_ID,
            "event_record_id": 81_000_004,
            "event_id": 5504,
        },
        source_core_sha256=b"o" * 32,
    )


def _direct_report_event(
    *,
    source_event_id: int,
    windows_event_id: int,
    channel_id: int,
    provider_id: int,
) -> EventCoreV2:
    direct = _direct_signal_event(channel_id=channel_id, provider_id=provider_id)
    return EventCoreV2(
        values={
            **direct.values,
            "id": source_event_id,
            "event_record_id": source_event_id,
            "event_id": windows_event_id,
            "provider_id": provider_id,
        },
        source_core_sha256=bytes([source_event_id % 251]) * 32,
    )


def _write_direct_signal(
    conn,
    *,
    repository: PostgresStorageV2Repository,
    event: EventCoreV2,
) -> None:
    source_sha256 = core_chunk_digest([event], [], [], [])
    with conn.cursor() as cur:
        repository.write_verified_rows(
            cur=cur,
            events=[event],
            facts=[],
            entities=[],
            links=[],
            verified_archive_links=[],
            source_sha256=source_sha256,
        )


def _insert_signal_and_publish(
    conn,
    *,
    channel_id: int,
    provider_id: int,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into events_v2_core(
                id,server_id,domain_id,log_source_id,event_id,
                channel_id,provider_id,time_created_utc,normalized_hash
            ) values (%s,1,1,1,4719,%s,%s,
                      timestamptz '2026-07-29 10:00:00+00',%s)
            """,
            (
                SIGNAL_EVENT_ID,
                channel_id,
                provider_id,
                b"x" * 32,
            ),
        )
        result = publish_semantic_candidates(cur, [SIGNAL_EVENT_ID])
        assert result["queued"] == 1


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_signal_event_and_semantic_outbox_share_real_postgres_commit() -> None:
    dsn = str(os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip(
            "ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL "
            "integration tests"
        )

    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    with connect() as setup:
        assert_disposable_database(setup)
        channel_id, provider_id, eventlog_provider_id = _create_contract(setup)

    interrupted = connect()
    backend_pid = interrupted.info.backend_pid
    _insert_signal_and_publish(
        interrupted,
        channel_id=channel_id,
        provider_id=provider_id,
    )
    with connect() as controller:
        assert_disposable_database(controller)
        with controller.cursor() as cur:
            cur.execute("select pg_terminate_backend(%s) as terminated", (backend_pid,))
            assert cur.fetchone()["terminated"] is True
    interrupted.close()

    with connect() as verify, verify.cursor() as cur:
        cur.execute(
            "select "
            "(select count(1) from events_v2_core) as event_rows,"
            "(select count(1) from semantic_processing_outbox) as outbox_rows"
        )
        rolled_back = dict(cur.fetchone())
        assert rolled_back == {"event_rows": 0, "outbox_rows": 0}

    with connect() as committed:
        _insert_signal_and_publish(
            committed,
            channel_id=channel_id,
            provider_id=provider_id,
        )

    with connect() as verify, verify.cursor() as cur:
        cur.execute(
            """
                select source_event_id,source_id,domain_id,partition_key,
                       payload_json,
                       (select count(1) from events_v2_core) as event_rows,
                       (select count(1) from semantic_processing_outbox) as outbox_rows
                from semantic_processing_outbox
                """
        )
        committed = dict(cur.fetchone())
        assert committed == {
            "source_event_id": SIGNAL_EVENT_ID,
            "source_id": 1,
            "domain_id": 1,
            "partition_key": "1:1",
            "payload_json": {"selection_reason": "signal"},
            "event_rows": 1,
            "outbox_rows": 1,
        }

    repository = PostgresStorageV2Repository(
        connect,
        semantic_publisher=publish_investigation_candidates,
    )
    direct_event = _direct_signal_event(
        channel_id=channel_id,
        provider_id=provider_id,
    )

    interrupted = connect()
    backend_pid = interrupted.info.backend_pid
    _write_direct_signal(
        interrupted,
        repository=repository,
        event=direct_event,
    )
    with connect() as controller:
        assert_disposable_database(controller)
        with controller.cursor() as cur:
            cur.execute("select pg_terminate_backend(%s) as terminated", (backend_pid,))
            assert cur.fetchone()["terminated"] is True
    interrupted.close()

    with connect() as verify, verify.cursor() as cur:
        cur.execute(
            "select "
            "(select count(1) from events_v2_core where id=%s) as event_rows,"
            "(select count(1) from semantic_processing_outbox "
            " where source_event_id=%s) as outbox_rows",
            (DIRECT_EVENT_ID, DIRECT_EVENT_ID),
        )
        assert dict(cur.fetchone()) == {"event_rows": 0, "outbox_rows": 0}

    for _attempt in range(2):
        with connect() as committed_direct:
            _write_direct_signal(
                committed_direct,
                repository=repository,
                event=direct_event,
            )

    with connect() as verify, verify.cursor() as cur:
        cur.execute(
            "select "
            "(select count(1) from events_v2_core where id=%s) as event_rows,"
            "(select count(1) from semantic_processing_outbox "
            " where source_event_id=%s) as outbox_rows",
            (DIRECT_EVENT_ID, DIRECT_EVENT_ID),
        )
        assert dict(cur.fetchone()) == {"event_rows": 1, "outbox_rows": 1}

    out_of_scope_event = _direct_out_of_scope_signal_event(
        channel_id=channel_id,
        provider_id=provider_id,
    )
    with connect() as committed_out_of_scope:
        _write_direct_signal(
            committed_out_of_scope,
            repository=repository,
            event=out_of_scope_event,
        )
    with connect() as verify, verify.cursor() as cur:
        cur.execute(
            "select "
            "(select count(1) from events_v2_core where id=%s) as event_rows,"
            "(select count(1) from semantic_processing_outbox "
            " where source_event_id=%s) as outbox_rows",
            (DIRECT_OUT_OF_SCOPE_EVENT_ID, DIRECT_OUT_OF_SCOPE_EVENT_ID),
        )
        assert dict(cur.fetchone()) == {"event_rows": 1, "outbox_rows": 0}

    for report_event in (
        _direct_report_event(
            source_event_id=DIRECT_CONTEXT_EVENT_ID,
            windows_event_id=4776,
            channel_id=channel_id,
            provider_id=provider_id,
        ),
        _direct_report_event(
            source_event_id=DIRECT_EVENTLOG_EVENT_ID,
            windows_event_id=1102,
            channel_id=channel_id,
            provider_id=eventlog_provider_id,
        ),
    ):
        with connect() as committed_report_event:
            _write_direct_signal(
                committed_report_event,
                repository=repository,
                event=report_event,
            )
    with connect() as verify, verify.cursor() as cur:
        cur.execute(
            """
                select source_event_id,payload_json
                from semantic_processing_outbox
                where source_event_id=any(%s)
                order by source_event_id
                """,
            ([DIRECT_CONTEXT_EVENT_ID, DIRECT_EVENTLOG_EVENT_ID],),
        )
        assert [dict(row) for row in cur.fetchall()] == [
            {
                "source_event_id": DIRECT_CONTEXT_EVENT_ID,
                "payload_json": {"selection_reason": "signal"},
            },
            {
                "source_event_id": DIRECT_EVENTLOG_EVENT_ID,
                "payload_json": {"selection_reason": "signal"},
            },
        ]

    with connect() as prepare_reset, prepare_reset.cursor() as cur:
        cur.execute(
            "insert into storage_v2_keywords(value) values (%s) returning id",
            ("0x8020000000000000",),
        )
        keywords_id = int(cur.fetchone()["id"])
    reset_event = EventCoreV2(
        values={
            **direct_event.values,
            "id": DIRECT_RESET_EVENT_ID,
            "event_record_id": 81_000_003,
            "event_id": 4724,
            "keywords_id": keywords_id,
            "time_created_utc": datetime(
                2026, 7, 29, 11, 0, tzinfo=timezone.utc,
            ),
            "normalized_at": datetime(
                2026, 7, 29, 11, 1, tzinfo=timezone.utc,
            ),
        },
        source_core_sha256=b"r" * 32,
    )
    with connect() as committed_reset:
        _write_direct_signal(
            committed_reset,
            repository=repository,
            event=reset_event,
        )
    with connect() as verify, verify.cursor() as cur:
        cur.execute(
            "select job_kind from semantic_processing_outbox "
            "where source_event_id=%s order by job_kind",
            (DIRECT_RESET_EVENT_ID,),
        )
        assert [row["job_kind"] for row in cur.fetchall()] == [
            "investigation_context",
            "normalize_event",
        ]

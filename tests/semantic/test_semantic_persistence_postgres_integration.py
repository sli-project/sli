from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

import pytest

from server.sli.semantic.semantic_processing import (
    CanonicalAction,
    NormalizedEvent,
    StoredEvent,
    assemble_canonical_actions,
    normalize_windows_event,
)
from server.sli.semantic import semantic_processing_repository
from server.sli.semantic.semantic_processing_repository import (
    claim_semantic_jobs,
    complete_semantic_job,
    enqueue_semantic_job,
    load_semantic_source_event,
    persist_canonical_actions,
    persist_normalized_event,
)
from server.sli.storage.storage_v2_archive import ArchivePublisher, ArchiveReader
from server.sli.storage.storage_v2_models import parse_utc_timestamp
from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore
from tests.postgres_integration_guard import assert_disposable_database


def _isolated_postgres_dsn() -> str:
    """Return only a DSN whose explicit database name is in the test namespace."""
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")
    parsed = urlsplit(dsn)
    database = unquote(parsed.path).lstrip("/") if parsed.scheme else ""
    if not database:
        match = re.search(r"(?:^|\s)dbname=(?:'([^']+)'|\"([^\"]+)\"|(\S+))", dsn)
        database = next((value for value in (match.groups() if match else ()) if value), "")
    if not database.startswith("sli_test_"):
        pytest.skip("ADLOG_TEST_PG_DSN must explicitly target a sli_test_* database")
    return dsn


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_v2_archive_to_normalized_action_is_durable_and_idempotent(tmp_path) -> None:
    dsn = _isolated_postgres_dsn()

    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    with connect() as guard_conn, guard_conn.cursor() as cur:
        assert_disposable_database(guard_conn)
        cur.execute(
            "select 1 from schema_migrations where version=25 and name='semantic_persistence_contract'"
        )
        assert cur.fetchone() is not None
        cur.execute("delete from canonical_action_evidence")
        cur.execute("delete from canonical_actions")
        cur.execute("delete from normalized_events")
        cur.execute("delete from semantic_processing_outbox")
        cur.execute(
            "delete from storage_v2_archive_blocks "
            "where archive_kind='event' and first_event_id >= 900001 and last_event_id <= 900002"
        )
        cur.execute(
            "delete from storage_v2_archive_sets archive_set "
            "where source_min_event_id >= 900001 and source_max_event_id <= 900002 "
            "and not exists (select 1 from storage_v2_archive_blocks block "
            "where block.archive_set_id=archive_set.archive_set_id)"
        )
        cur.execute("delete from events_v2_core where id in (900001,900002)")

    occurred = datetime(2026, 7, 19, 1, tzinfo=timezone.utc)
    rows = [
        {
            "id": 900001,
            "server_id": 1,
            "domain_id": 1,
            "log_source_id": 1,
            "event_record_id": 900001,
            "event_id": 4697,
            "time_created_utc": occurred,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "computer": "DC1",
            "event_data_json": {
                "ServiceName": "semantic-test-service",
                "ServiceFileName": "C:/semantic-test.exe",
            },
            "correlation_id": "semantic-test-service-install",
        },
        {
            "id": 900002,
            "server_id": 1,
            "domain_id": 1,
            "log_source_id": 1,
            "event_record_id": 900002,
            "event_id": 7045,
            "time_created_utc": occurred,
            "provider_name": "Service Control Manager",
            "channel": "System",
            "computer": "DC1",
            "event_data_json": {
                "ServiceName": "semantic-test-service",
                "ImagePath": "C:/semantic-test.exe",
            },
            "correlation_id": "semantic-test-service-install",
        },
    ]

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "insert into storage_v2_provider(value) values ('semantic-provider') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        provider_id = cur.fetchone()["id"]
        cur.execute(
            "insert into storage_v2_channel(value) values ('semantic-channel') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        channel_id = cur.fetchone()["id"]
        cur.execute(
            "insert into storage_v2_computer(value) values ('semantic-dc') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        computer_id = cur.fetchone()["id"]
        for row in rows:
            cur.execute(
                """
                insert into events_v2_core(
                    id,server_id,domain_id,log_source_id,event_record_id,event_id,
                    provider_id,channel_id,computer_id,time_created_utc,
                    correlation_id,normalized_at,normalized_hash,source_core_sha256
                ) values (%s,1,1,1,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    row["id"],
                    row["event_record_id"],
                    row["event_id"],
                    provider_id,
                    channel_id,
                    computer_id,
                    occurred,
                    row["correlation_id"],
                    occurred,
                    bytes([row["event_id"] % 251]) * 32,
                    bytes([(row["event_id"] + 1) % 251]) * 32,
                ),
            )

    manifest = PostgresArchiveManifestStore(connect)
    archive_root = tmp_path.resolve() / "semantic-archive"
    ArchivePublisher(archive_root, manifest).publish_rows(
        archive_set_id=str(uuid.uuid4()),
        archive_kind="event",
        block_index=0,
        rows=rows,
    )
    archive = ArchiveReader(manifest, archive_root=archive_root)

    with connect() as conn, conn.cursor() as cur:
        cur.execute("set local role adlog_storage_worker")
        for row in rows:
            enqueue_semantic_job(cur, source_event_id=row["id"])

    with connect() as conn:
        for _ in rows:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute("set local role adlog_storage_worker")
                job = claim_semantic_jobs(cur, limit=1)[0]
                source = load_semantic_source_event(
                    cur,
                    source_event_id=int(job["source_event_id"]),
                    archive=archive,
                )
                event = StoredEvent(
                    event_id=int(source["id"]),
                    windows_event_id=int(source["event_id"]),
                    channel=str(source["channel"]),
                    server=str(source["computer"]),
                    occurred_at_utc=parse_utc_timestamp(source["time_created_utc"]),
                    event_data=source["event_data_json"],
                    provider=source["provider_name"],
                    correlation_id=source["correlation_id"],
                    source_host_id=source["source_host_id"],
                )
                normalized = normalize_windows_event(event)
                persist_normalized_event(cur, event=normalized)
                actions = assemble_canonical_actions((normalized,))
                persist_canonical_actions(
                    cur,
                    actions=actions,
                )
                # At-least-once processing may repeat a transaction. Durable
                # identities must turn the exact replay into a no-op.
                persist_normalized_event(cur, event=normalized)
                persist_canonical_actions(cur, actions=actions)
                complete_semantic_job(
                    cur,
                    job_id=str(job["job_id"]),
                    lease_token=str(job["lease_token"]),
                )

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "select semantic_type,roles_json from normalized_events order by source_event_id"
        )
        normalized_rows = cur.fetchall()
        assert [row["semantic_type"] for row in normalized_rows] == [
            "service.installed.fragment",
            "service.installed.fragment",
        ]
        assert all(row["roles_json"]["source_host"] == "1" for row in normalized_rows)
        cur.execute("select count(*) as value,min(action_status) as status from canonical_actions")
        action_summary = cur.fetchone()
        assert action_summary["value"] == 2
        assert action_summary["status"] == "observed"
        cur.execute("select count(*) as value from canonical_action_evidence")
        assert cur.fetchone()["value"] == 2
        cur.execute(
            "select count(*) as value from semantic_processing_outbox "
            "where status='completed' and partition_key is not null and occurred_at_utc is not null"
        )
        assert cur.fetchone()["value"] == 2


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_canonical_action_replay_across_assembler_versions_reinterprets_evidence(
    monkeypatch,
) -> None:
    """A stable action ID must survive 1.0 -> 1.1 without losing provenance."""
    dsn = _isolated_postgres_dsn()
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    source_event_id = 900010
    contribution_key = "5a" * 32
    action_id = str(uuid.uuid5(
        uuid.NAMESPACE_URL, f"adlog:canonical:{contribution_key}"
    ))
    occurred = datetime(2026, 7, 20, 1, tzinfo=timezone.utc)

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    with connect() as guard_conn, guard_conn.cursor() as cur:
        assert_disposable_database(guard_conn)
        cur.execute("delete from canonical_action_evidence where canonical_action_id=%s", (action_id,))
        cur.execute("delete from canonical_actions where canonical_action_id=%s", (action_id,))
        cur.execute("delete from normalized_events where source_event_id=%s", (source_event_id,))
        cur.execute("delete from events_v2_core where id=%s", (source_event_id,))

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "insert into storage_v2_provider(value) values ('semantic-version-provider') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        provider_id = cur.fetchone()["id"]
        cur.execute(
            "insert into storage_v2_channel(value) values ('semantic-version-channel') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        channel_id = cur.fetchone()["id"]
        cur.execute(
            "insert into storage_v2_computer(value) values ('semantic-version-dc') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        computer_id = cur.fetchone()["id"]
        cur.execute(
            """
            insert into events_v2_core(
                id,server_id,domain_id,log_source_id,event_record_id,event_id,
                provider_id,channel_id,computer_id,time_created_utc,
                correlation_id,normalized_at,normalized_hash,source_core_sha256
            ) values (%s,1,1,1,%s,4624,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                source_event_id, source_event_id, provider_id, channel_id, computer_id,
                occurred, "semantic-version-replay", occurred, bytes([0x5A]) * 32,
                bytes([0x5B]) * 32,
            ),
        )

    old_normalized = NormalizedEvent(
        source_event_id=source_event_id,
        semantic_type="authentication.succeeded",
        occurred_at_utc=occurred,
        roles={"source_host": "DC1"},
        facts={"logon_type": "network"},
        quality={"interpretation": "old"},
        semantic_sha256="11" * 32,
    )
    new_normalized = NormalizedEvent(
        source_event_id=source_event_id,
        semantic_type="authentication.succeeded",
        occurred_at_utc=occurred,
        roles={"source_host": "DC1"},
        facts={"logon_type": "network", "authentication_package": "Kerberos"},
        quality={"interpretation": "new"},
        semantic_sha256="22" * 32,
    )
    old_action = CanonicalAction(
        action_kind="authentication.succeeded",
        status="observed",
        occurred_at_utc=occurred,
        contribution_key=contribution_key,
        source_event_ids=(source_event_id,),
        attributes={
            "material_identity": {"source_host": "DC1", "source_event_id": source_event_id},
            "source_evidence": [{"source_event_id": source_event_id, "semantic_sha256": "11" * 32}],
            "observed_facts": [{"logon_type": "network"}],
            "observed_roles": [{"source_host": "DC1"}],
        },
    )
    new_action = CanonicalAction(
        action_kind=old_action.action_kind,
        status=old_action.status,
        occurred_at_utc=occurred,
        contribution_key=contribution_key,
        source_event_ids=(source_event_id,),
        attributes={
            "material_identity": {"source_host": "DC1", "source_event_id": source_event_id},
            "source_evidence": [{"source_event_id": source_event_id, "semantic_sha256": "22" * 32}],
            "observed_facts": [{"logon_type": "network", "authentication_package": "Kerberos"}],
            "observed_roles": [{"source_host": "DC1"}],
        },
    )

    with connect() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_storage_worker")
        old_normalized_id = persist_normalized_event(cur, event=old_normalized, normalizer_version="1.0")
        monkeypatch.setattr(semantic_processing_repository, "ASSEMBLER_VERSION", "1.0")
        assert persist_canonical_actions(cur, actions=(old_action,), normalizer_version="1.0") == (action_id,)
        cur.execute(
            "select encode(action_sha256, 'hex') as action_sha256 "
            "from canonical_actions where canonical_action_id=%s",
            (action_id,),
        )
        old_action_sha256 = cur.fetchone()["action_sha256"]

    with connect() as conn, conn.transaction(), conn.cursor() as cur:
        cur.execute("set local role adlog_storage_worker")
        new_normalized_id = persist_normalized_event(cur, event=new_normalized, normalizer_version="1.1")
        monkeypatch.setattr(semantic_processing_repository, "ASSEMBLER_VERSION", "1.1")
        assert persist_canonical_actions(cur, actions=(new_action,), normalizer_version="1.1") == (action_id,)
        with pytest.raises(RuntimeError, match="canonical action identity replay conflict"):
            persist_canonical_actions(
                cur,
                actions=(CanonicalAction(
                    action_kind="authentication.failed",
                    status="observed",
                    occurred_at_utc=occurred,
                    contribution_key=contribution_key,
                    source_event_ids=(source_event_id,),
                    attributes=new_action.attributes,
                ),),
                normalizer_version="1.1",
            )

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "select assembler_version,attributes_json from canonical_actions where canonical_action_id=%s",
            (action_id,),
        )
        action = cur.fetchone()
        assert action["assembler_version"] == "1.1"
        assert action["attributes_json"]["source_evidence"] == [
            {"source_event_id": source_event_id, "semantic_sha256": "22" * 32}
        ]
        assert action["attributes_json"]["prior_interpretations"] == [{
            "assembler_id": "semantic-action-assembler",
            "assembler_version": "1.0",
            "action_sha256": old_action_sha256,
            "evidence": [{
                "source_event_id": source_event_id,
                "normalized_event_id": old_normalized_id,
                "evidence_role": "primary",
                "entity_role": None,
                "evidence_order": 0,
                "relation_confidence": "1.000",
            }],
            "attributes": {
                "material_identity": {"source_host": "DC1", "source_event_id": source_event_id},
                "source_evidence": [{"source_event_id": source_event_id, "semantic_sha256": "11" * 32}],
                "observed_facts": [{"logon_type": "network"}],
                "observed_roles": [{"source_host": "DC1"}],
            },
        }]
        cur.execute(
            """
            select normalized_event_id from canonical_action_evidence
            where canonical_action_id=%s order by evidence_order
            """,
            (action_id,),
        )
        assert [str(row["normalized_event_id"]) for row in cur.fetchall()] == [new_normalized_id]

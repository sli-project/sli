"""Exercise the retained-packet SQL reader against disposable PostgreSQL JSONB."""
from __future__ import annotations

import os
from types import SimpleNamespace
from uuid import uuid4

import pytest

from server.sli.storage.event_source_identity import legacy_event_hash
from server.sli.storage.storage_v2_archive import (
    ArchiveIntegrityError,
    ArchiveReader,
    InMemoryArchiveManifestStore,
)
from server.sli.storage.storage_v2_runtime import (
    PostgresStorageV2ReadStore,
    StorageV2RuntimeReader,
)
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_agent_event_payload import attested_packet, packet, source

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


@pytest.fixture
def retained_packet_store():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL required")

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    with connect() as conn:
        assert_disposable_database(conn)
        conn.execute("""create table raw_log_files(
            id bigint primary key, server_id int, log_source_id int,
            file_path text, sha256 text);
            create table sli_agent_packet_inbox(
            packet_id uuid primary key, event_rows jsonb, imported_at timestamptz,
            packet jsonb, envelope jsonb);
            create table sli_agent_receipts(
            packet_id uuid primary key, envelope jsonb, envelope_sha256 text);""")
    return PostgresStorageV2ReadStore(connect), connect


def retain(connect, summary, retained):
    from psycopg.types.json import Jsonb

    packet_id = uuid4()
    attested = attested_packet(retained["event_rows"][0], packet_id=str(packet_id))
    with connect() as conn:
        # The SQL reader now verifies the durable receipt and its original packet.
        conn.execute("""insert into sli_agent_receipts(packet_id,envelope,envelope_sha256)
                     values(%s,%s,%s)""",
                     (packet_id, Jsonb(attested["attested_envelope"]), attested["envelope_sha256"]))
        conn.execute("""insert into sli_agent_packet_inbox(packet_id,event_rows,imported_at,packet,envelope)
                     values(%s,%s,now(),%s,%s)""",
                     (packet_id, Jsonb(retained["event_rows"]), Jsonb(attested["attested_packet"]),
                      Jsonb(attested["attested_envelope"])))
        # The importer hashes rows after reading them from the JSONB inbox.
        rows = conn.execute("select event_rows from sli_agent_packet_inbox where packet_id=%s",
                            (packet_id,)).fetchone()["event_rows"]
        conn.execute("insert into raw_log_files values(%s,%s,%s,%s,%s)",
                     (summary["raw_log_file_id"], summary["server_id"], summary["log_source_id"],
                      "agent-packet:" + str(packet_id), packet(rows)["raw_sha256"]))


@pytest.mark.parametrize("event_id,field,value", [
    (4728, "MemberSid", "S-1-5-21-100-200-300-1001"),
    (4719, "SubcategoryGuid", "{00000000-0000-4000-8000-000000000001}"),
])
@pytest.mark.parametrize("identity_version", [1, 2])
def test_sql_reader_hydrates_exact_jsonb_source(retained_packet_store, event_id, field, value, identity_version):
    import json

    store, connect = retained_packet_store
    summary, retained = source(event_id)
    if identity_version == 1:
        summary["normalized_hash"] = bytes.fromhex(legacy_event_hash(retained["event_rows"][0]))
    retain(connect, summary, retained)

    reader = StorageV2RuntimeReader(
        SimpleNamespace(get_event_summary=lambda _id: summary,
                        get_agent_event_payload=store.get_agent_event_payload),
        ArchiveReader(InMemoryArchiveManifestStore()),
    )
    payload = reader.event_details(summary["id"])

    assert payload["id"] == summary["id"] and "source_payload_state" not in payload
    assert payload["normalized_hash"] == summary["normalized_hash"].hex()
    assert json.loads(payload["event_data_json"])[field] == value


@pytest.mark.parametrize("change", ["raw_file", "server", "log_source", "path", "pending", "receipt", "envelope"])
def test_sql_reader_rejects_unrelated_or_unimported_packet(retained_packet_store, change):
    store, connect = retained_packet_store
    summary, retained = source()
    retain(connect, summary, retained)
    if change in ("raw_file", "server", "log_source"):
        summary[{"raw_file": "raw_log_file_id", "server": "server_id",
                 "log_source": "log_source_id"}[change]] += 1
    else:
        with connect() as conn:
            if change == "path":
                conn.execute("update raw_log_files set file_path=%s", ("agent-packet:" + str(uuid4()),))
            elif change == "pending":
                conn.execute("update sli_agent_packet_inbox set imported_at=null")
            elif change == "receipt":
                conn.execute("delete from sli_agent_receipts")
            else:
                conn.execute("update sli_agent_packet_inbox set envelope='{}'::jsonb")

    assert store.get_agent_event_payload(summary) is None


def test_sql_reader_rejects_tampered_jsonb_source(retained_packet_store):
    from psycopg.types.json import Jsonb

    store, connect = retained_packet_store
    summary, retained = source()
    retain(connect, summary, retained)
    retained["event_rows"][0]["xml"] = "<Event/>"
    with connect() as conn:
        conn.execute("update sli_agent_packet_inbox set event_rows=%s", (Jsonb(retained["event_rows"]),))

    with pytest.raises(ArchiveIntegrityError, match="receipt mismatch"):
        store.get_agent_event_payload(summary)

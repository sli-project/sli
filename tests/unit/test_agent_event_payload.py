"""Retained agent sources are exact, checksummed and read with fakes only."""
import hashlib
import importlib
import json
from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace

import pytest

from server.sli.storage.agent_event_payload import verified_agent_event_payload
from server.sli.storage.event_source_identity import legacy_event_hash
from server.sli.storage.storage_v2_archive import (
    ArchiveBlockUnavailableError,
    ArchiveIntegrityError,
)
from server.sli.storage.storage_v2_runtime import (
    PostgresStorageV2ReadStore,
    StorageV2RuntimeReader,
)
from sli_agent.envelope import digest as envelope_digest
from sli_collect.eventlog import event_packet

importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")


def source(event_id=4728):
    data = '<Data Name="MemberSid">S-1-5-21-100-200-300-1001</Data>'
    if event_id == 4719:
        data = '<Data Name="SubcategoryGuid">{00000000-0000-4000-8000-000000000001}</Data>'
    row = {
        "event_id": event_id, "record_id": 11, "channel": "Security", "computer_name": "fixture-dc",
        "time_created": "2026-10-12T08:04:47Z", "provider_name": "fixture-provider",
        "xml": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData>{data}</EventData></Event>',
    }
    summary = {
        "id": 7, "raw_log_file_id": 9, "server_id": 3, "domain_id": 2, "site_id": None,
        "log_source_id": 1, "event_id": event_id, "time_created_utc": row["time_created"],
        "normalized_hash": bytes.fromhex(importer.event_normalized_hash(row)),
    }
    return summary, packet([row])


def packet(rows):
    raw = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows).encode("utf-8")
    return {"event_rows": rows, "raw_sha256": hashlib.sha256(raw).hexdigest()}


def attested_packet(row, *, packet_id="00000000-0000-4000-8000-000000000063"):
    native = event_packet(row, generation=None, after_record_id=None)
    envelope = {"packet_id": packet_id, "payload_sha256": envelope_digest(native)}
    return {**packet([row]), "attested_packet": native, "attested_envelope": envelope,
            "envelope_sha256": envelope_digest(envelope), "packet_id": packet_id}


@pytest.mark.parametrize("identity_version", [1, 2])
def test_attested_payload_accepts_jsonb_key_reordering_for_both_hash_versions(identity_version):
    summary, retained = source()
    row = retained["event_rows"][0]
    if identity_version == 1:
        summary["normalized_hash"] = bytes.fromhex(legacy_event_hash(row))
    retained = attested_packet(row)
    # JSONB changes object key order; the durable receipt binds the full body.
    retained["event_rows"] = [dict(sorted(row.items()))]
    assert packet(retained["event_rows"])["raw_sha256"] != retained["raw_sha256"]

    payload = verified_agent_event_payload(summary, retained)

    assert payload["normalized_hash"] == summary["normalized_hash"].hex()
    assert json.loads(payload["event_data_json"])["MemberSid"] == "S-1-5-21-100-200-300-1001"


@pytest.mark.parametrize("change", ["event_rows", "packet", "envelope", "envelope_sha256", "packet_id"])
def test_attested_payload_rejects_tampering_even_when_v2_identity_is_unchanged(change):
    summary, retained = source()
    row = retained["event_rows"][0]
    retained = attested_packet(row)
    if change == "event_rows":
        retained["event_rows"][0]["xml"] = "<Event/>"
        assert bytes.fromhex(importer.event_normalized_hash(row)) == summary["normalized_hash"]
    elif change == "packet":
        retained["attested_packet"]["records"][0]["payload"]["xml"] = "<Event/>"
    elif change == "envelope":
        retained["attested_envelope"]["payload_sha256"] = "0" * 64
    elif change == "envelope_sha256":
        retained["envelope_sha256"] = "0" * 64
    else:
        retained["packet_id"] = "00000000-0000-4000-8000-000000000064"
    with pytest.raises(ArchiveIntegrityError, match="receipt mismatch"):
        verified_agent_event_payload(summary, retained)


@pytest.mark.parametrize("event_id,field", [(4728, "MemberSid"), (4719, "SubcategoryGuid")])
def test_missing_archive_uses_exact_imported_packet(event_id, field):
    summary, retained = source(event_id)

    def missing(**_kwargs):
        raise ArchiveBlockUnavailableError("fixture absent block")

    store = SimpleNamespace(get_event_summary=lambda _id: summary,
                            get_agent_event_payload=lambda core: verified_agent_event_payload(core, retained))
    result = StorageV2RuntimeReader(store, SimpleNamespace(read_event=missing)).event_details(7)

    assert result["id"] == 7 and "source_payload_state" not in result
    assert result["computer"] == "fixture-dc" and result["provider_name"] == "fixture-provider"
    assert json.loads(result["event_data_json"])[field]
    assert result["normalized_hash"] == summary["normalized_hash"].hex()


@pytest.mark.parametrize("change", ["checksum", "identity", "duplicate", "empty", "oversize", "malformed"])
def test_corrupted_or_ambiguous_packet_fails_closed(change):
    summary, retained = source()
    if change == "checksum":
        retained["event_rows"][0]["xml"] = "<Event/>"
    elif change == "identity":
        altered = deepcopy(retained["event_rows"][0])
        altered["record_id"] += 1
        retained = packet([altered])
    elif change == "duplicate":
        retained = packet(retained["event_rows"] * 2)
    elif change == "empty":
        retained = packet([])
    elif change == "oversize":
        retained = packet(retained["event_rows"] * 5001)
    else:
        retained = packet([None])
    with pytest.raises(ArchiveIntegrityError):
        verified_agent_event_payload(summary, retained)


def test_archive_integrity_failure_never_opens_inbox():
    summary, _retained = source()

    def corrupt(**_kwargs):
        raise ArchiveIntegrityError("fixture altered archive")

    store = SimpleNamespace(get_event_summary=lambda _id: summary,
                            get_agent_event_payload=lambda _core: pytest.fail("inbox fallback forbidden"))
    with pytest.raises(ArchiveIntegrityError):
        StorageV2RuntimeReader(store, SimpleNamespace(read_event=corrupt)).event_details(7)


def test_packet_payload_must_match_verified_core_timestamp():
    summary, retained = source()
    summary["time_created_utc"] = "2026-10-12T08:04:48Z"

    def missing(**_kwargs):
        raise ArchiveBlockUnavailableError("fixture absent block")

    store = SimpleNamespace(get_event_summary=lambda _id: summary,
                            get_agent_event_payload=lambda core: verified_agent_event_payload(core, retained))
    with pytest.raises(ArchiveIntegrityError, match="timestamp mismatch"):
        StorageV2RuntimeReader(store, SimpleNamespace(read_event=missing)).event_details(7)


def test_missing_core_never_opens_inbox_or_archive():
    store = SimpleNamespace(get_event_summary=lambda _id: None,
                            get_agent_event_payload=lambda _core: pytest.fail("unverified core"))
    archive = SimpleNamespace(read_event=lambda **_kwargs: pytest.fail("unverified core"))
    with pytest.raises(KeyError, match="core not found"):
        StorageV2RuntimeReader(store, archive).event_details(7)


def test_event_detail_endpoint_preserves_member_sid(monkeypatch):
    from server.sli.events import event_details

    summary, retained = source()

    def missing(**_kwargs):
        raise ArchiveBlockUnavailableError("fixture absent block")

    store = SimpleNamespace(get_event_summary=lambda _id: summary,
                            get_agent_event_payload=lambda core: verified_agent_event_payload(core, retained))
    monkeypatch.setattr(event_details, "_v2_detail_route_selected", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(event_details, "primary_read_enabled", lambda: False)
    monkeypatch.setattr(event_details, "PostgresStorageV2ReadStore", lambda _connect: store)
    monkeypatch.setattr(event_details, "PostgresArchiveManifestStore", lambda _connect: None)
    monkeypatch.setattr(event_details, "ArchiveReader", lambda _manifest: SimpleNamespace(read_event=missing))
    monkeypatch.setattr(event_details, "query_rows", lambda *_args: [{"server": "fixture-dc"}])
    row = event_details._get_v2_event_detail_by_id({"event_db_id": 7})
    result = event_details._normalize_event_detail_row(row)
    assert result["event_data"]["MemberSid"] == "S-1-5-21-100-200-300-1001"
    assert "source_payload_state" not in result


def test_absent_packet_preserves_archive_unavailable():
    summary, _retained = source()

    def missing(**_kwargs):
        raise ArchiveBlockUnavailableError("fixture absent block")

    store = SimpleNamespace(get_event_summary=lambda _id: summary, get_agent_event_payload=lambda _core: None)
    with pytest.raises(ArchiveBlockUnavailableError):
        StorageV2RuntimeReader(store, SimpleNamespace(read_event=missing)).event_details(7)


@pytest.mark.parametrize("found", [True, False])
def test_postgres_read_addresses_only_imported_raw_file(found):
    summary, retained = source()
    retained = attested_packet(retained["event_rows"][0])
    queries = []

    class Cursor:
        def execute(self, sql, params):
            queries.append((sql, params))

        def fetchone(self):
            return retained if found else None

    conn = SimpleNamespace(cursor=lambda: nullcontext(Cursor()))
    store = PostgresStorageV2ReadStore(lambda: nullcontext(conn))
    result = store.get_agent_event_payload(summary)
    assert (result is not None) == found
    sql, params = queries[0]
    assert params == (9, 3, 1)
    assert "i.imported_at is not null" in sql and "limit 1" in sql
    assert "i.packet_id::text" in sql and "r.file_path='agent-packet:'" in sql
    assert "join sli_agent_receipts receipt on receipt.packet_id=i.packet_id and receipt.envelope=i.envelope" in sql
    assert "i.packet as attested_packet" in sql and "receipt.envelope_sha256" in sql

"""Synthetic native identities, legacy bindings and monotonic representations."""
import json
from contextlib import contextmanager
from copy import deepcopy

import pytest

from server.sli.storage import event_source_representation as representations
from server.sli.storage.event_source_identity import (
    RepresentationConflict,
    event_identity_hash,
    legacy_event_hash,
    preferred_representation,
)
from server.sli.storage.storage_v2_repository import (
    PostgresStorageV2Repository,
    SourceEventIdentityConflict,
)
from sli_collect.eventlog import parse_event_xml


def source(count=8, *, changed=False):
    data = "".join(f'<Data Name="Field{i}">{"changed" if changed and i == 2 else str(i)}</Data>' for i in range(count))
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="fixture-provider"/><EventID>4624</EventID><EventRecordID>364663</EventRecordID>'
           '<Channel>Security</Channel><Computer>fixture-dc.example.test</Computer>'
           '<TimeCreated SystemTime="2026-10-11T00:31:00Z"/></System><EventData>' + data + '</EventData></Event>')
    return parse_event_xml(xml, source_name="fixture-dc", connect_address="localhost", channel="Security")


def reservation(row):
    return {"server_id": 1, "channel_id": 1, "event_record_id": row["record_id"],
            "time_created_utc": row["time_created"], "normalized_hash": event_identity_hash(row), "source_row": row}


class Database:
    def __init__(self):
        self.allocations, self.representations, self.core, self.sql = {}, {}, {}, []

    @contextmanager
    def connect(self):
        saved = deepcopy((self.allocations, self.representations))
        try:
            yield self
        except Exception:
            self.allocations, self.representations = saved
            raise

    @contextmanager
    def cursor(self):
        yield Cursor(self)


class Cursor:
    def __init__(self, db):
        self.db, self.rows = db, []

    def execute(self, sql, params=()):
        db = self.db
        db.sql.append(sql)
        if "insert into storage_v2_event_identity_allocations" in sql:
            for i in range(0, len(params), 5):
                key, fingerprint = tuple(params[i:i+4]), params[i+4]
                if key not in db.core:
                    db.allocations.setdefault(key, {"id": len(db.allocations) + 1, "normalized_hash": fingerprint})
        elif "with wanted(ordinal" in sql:
            self.rows = []
            for i in range(0, len(params), 6):
                ordinal, *values = params[i:i+6]
                key = tuple(values[:4])
                allocation, core = db.allocations.get(key), db.core.get(key)
                entry = core or allocation
                self.rows.append({"ordinal": ordinal, "id": entry["id"] if entry else None,
                    "normalized_hash": entry["normalized_hash"] if entry else None,
                    "allocated_hash": allocation["normalized_hash"] if allocation else None,
                    "published": bool(core), "core_hash": core["normalized_hash"] if core else None})
        elif sql.startswith("select * from event_source_representations_v2"):
            row = db.representations.get(params[0])
            self.rows = [deepcopy(row)] if row else []
        elif sql.startswith("insert into event_source_representations_v2"):
            event_id, normalized_hash, version, canonical, body, body_hash = params
            db.representations.setdefault(event_id, {"event_id": event_id, "normalized_hash": normalized_hash,
                "identity_version": version, "canonical_hash": canonical,
                "representation": json.loads(body), "representation_sha256": body_hash})
        elif sql.startswith("update event_source_representations_v2"):
            db.representations[params[2]].update(representation=json.loads(params[0]), representation_sha256=params[1])
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


def test_transport_is_excluded_but_intrinsic_data_is_versioned():
    row = source()
    other = {**row, "connect_address": "fixture-dc.example.test", "collector_host": "other-host"}
    assert event_identity_hash(row) == event_identity_hash(other)
    assert legacy_event_hash(row) != legacy_event_hash(other)
    assert event_identity_hash(row) != legacy_event_hash(row)
    assert event_identity_hash(row) != event_identity_hash({**row, "custom_event_data": "changed"})


def test_named_subset_properties_and_xml_upgrade_without_downgrade():
    short, full = source(8), source(27)
    assert event_identity_hash(short) == event_identity_hash(full)
    assert preferred_representation(short, full) == full
    assert preferred_representation(full, short) == full
    # Named subsets do not need the same positional offsets.
    subset = deepcopy(full)
    subset["xml"] = subset["xml"].replace('<Data Name="Field0">0</Data>', '')
    subset["properties"] = subset["properties"][1:]
    assert preferred_representation(full, subset) == full


@pytest.mark.parametrize("change,reason", [
    (lambda row: source(changed=True), "event_xml_differs"),
    (lambda row: {**row, "properties": ["changed"] + row["properties"][1:]}, "event_properties_differs"),
    (lambda row: {**row, "event_id": 4625}, "event_identity_differs"),
    (lambda row: {**row, "xml": "<!DOCTYPE x><Event/>"}, "event_representation_invalid"),
])
def test_real_event_changes_fail_closed(change, reason):
    with pytest.raises(RepresentationConflict) as error:
        preferred_representation(source(), change(source()))
    assert error.value.reason == reason


def test_same_xml_longer_properties_wins_and_complementary_xml_is_retained():
    full = source(27)
    partial = {**full, "properties": full["properties"][:8]}
    assert preferred_representation(partial, full) == full
    a, b = source(), source()
    a["xml"] = a["xml"].replace('<Data Name="Field0">0</Data>', '')
    b["xml"] = b["xml"].replace('<Data Name="Field1">1</Data>', '')
    a["properties"] = b["properties"] = []
    with pytest.raises(RepresentationConflict, match="event_representation_incomparable"):
        preferred_representation(a, b)


def test_repository_replays_transport_upgrades_payload_and_rolls_back_real_conflicts():
    db = Database()
    repo = PostgresStorageV2Repository(db.connect)
    short, full = source(), source(27)
    reserved = repo.reserve_event_identities([reservation(short)])[0]
    original_hash = db.allocations[next(iter(db.allocations))]["normalized_hash"]
    replay = repo.reserve_event_identities([reservation({**full, "connect_address": "fixture-dc.example.test"})])[0]
    assert replay["id"] == reserved["id"] and len(replay["source_row"]["properties"]) == 27
    replay = repo.reserve_event_identities([reservation(short)])[0]
    assert len(replay["source_row"]["properties"]) == 27
    before = deepcopy(db.representations)
    with pytest.raises(SourceEventIdentityConflict) as error:
        repo.reserve_event_identities([reservation(source(changed=True))])
    assert error.value.detail == "event_xml_differs"
    assert db.representations == before
    assert db.allocations[next(iter(db.allocations))]["normalized_hash"] == original_hash


def test_masked_file_context_accepts_subset_but_rejects_changed_shared_sid():
    from sli_agent.file_audit_events import masked_event

    native = source()["xml"]
    start, end = native.index("<EventData>"), native.index("</EventData>")
    native = (native[:start] + '<EventData><Data Name="TargetUserName">fixture-user</Data>'
              '<Data Name="LogonType">3</Data>'
              '<Data Name="TargetUserSid">S-1-5-21-100-200-300-1001</Data>' + native[end:])

    def row(xml, address):
        return parse_event_xml(xml, source_name="fixture-dc", connect_address=address, channel="Security")

    full = row(native, "fixture-endpoint")
    masked = row(masked_event(native), "localhost")
    conflicting = row(masked_event(native.replace("300-1001", "300-1002")), "localhost")
    assert "fixture-user" not in masked["xml"]
    assert event_identity_hash(full) == event_identity_hash(masked) == event_identity_hash(conflicting)

    db = Database()
    repo = PostgresStorageV2Repository(db.connect)
    reserved = repo.reserve_event_identities([reservation(full)])[0]
    db.core.update(deepcopy(db.allocations))
    before = deepcopy((db.allocations, db.representations, db.core))
    replay = repo.reserve_event_identities([reservation(masked)])[0]
    assert replay["published"] and replay["id"] == reserved["id"]
    assert replay["source_row"] == full
    with pytest.raises(SourceEventIdentityConflict, match="source event allocation hash mismatch") as error:
        repo.reserve_event_identities([reservation(conflicting)])
    assert error.value.detail == "event_xml_differs"
    assert (db.allocations, db.representations, db.core) == before


def test_published_legacy_hash_is_preserved_and_full_source_is_used(monkeypatch):
    from server.sli.storage.storage_v2_models import parse_utc_timestamp

    db = Database()
    old, incoming = source(27), source()
    key = (1, 1, old["record_id"], parse_utc_timestamp(old["time_created"]))
    legacy_hash = bytes.fromhex(legacy_event_hash(old))
    db.allocations[key] = db.core[key] = {"id": 9, "normalized_hash": legacy_hash}
    monkeypatch.setattr(representations, "_retained_source", lambda *args: old)
    row = PostgresStorageV2Repository(db.connect).reserve_event_identities([reservation(incoming)])[0]
    assert row["published"] and row["source_row"] == old
    assert db.representations[9]["normalized_hash"] == legacy_hash
    assert db.core[key]["normalized_hash"] == db.allocations[key]["normalized_hash"] == legacy_hash


def test_readonly_comparison_does_not_allocate_update_or_advance_sequence():
    db = Database()
    repo = PostgresStorageV2Repository(db.connect)
    row = repo.reserve_event_identities([reservation(source())], read_only=True)[0]
    assert row["id"] is None and row["source_row"] == source()
    assert not db.allocations and not db.representations
    assert all("insert " not in sql and "update " not in sql for sql in db.sql)


def test_legacy_packet_hydration_still_verifies_v1_digest():
    import hashlib

    from server.sli.storage.event_source_representation import packet_source_row
    from server.sli.storage.storage_v2_archive import ArchiveIntegrityError

    old = source()
    summary = {"normalized_hash": bytes.fromhex(legacy_event_hash(old))}

    def packet(row):
        raw = (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
        return {"event_rows": [row], "raw_sha256": hashlib.sha256(raw).hexdigest()}

    assert packet_source_row(summary, packet(old)) == old
    with pytest.raises(ArchiveIntegrityError, match="exact identity mismatch"):
        packet_source_row(summary, packet(source(changed=True)))


def test_jsonb_key_reordering_uses_retained_receipt_and_rejects_changed_body():
    import hashlib
    from uuid import uuid4

    from server.sli.storage.event_source_representation import packet_source_row
    from server.sli.storage.storage_v2_archive import ArchiveIntegrityError
    from sli_collect.eventlog import event_packet

    def checksum(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()

    row = source()
    native_packet = event_packet(row, generation=None, after_record_id=None)
    envelope = {"packet_id": str(uuid4()), "payload_sha256": checksum(native_packet)}
    retained = {"event_rows": [dict(sorted(row.items()))], "raw_sha256": "old-order-not-reconstructible",
        "attested_packet": native_packet, "attested_envelope": envelope,
        "envelope_sha256": checksum(envelope), "packet_id": envelope["packet_id"]}
    summary = {"normalized_hash": bytes.fromhex(legacy_event_hash(row))}
    assert packet_source_row(summary, retained) == row
    retained["event_rows"][0]["xml"] = source(changed=True)["xml"]
    with pytest.raises(ArchiveIntegrityError, match="receipt mismatch"):
        packet_source_row(summary, retained)


def test_readonly_packet_detects_two_changed_bodies_for_same_new_key():
    db = Database()
    with pytest.raises(SourceEventIdentityConflict) as error:
        PostgresStorageV2Repository(db.connect).reserve_event_identities(
            [reservation(source()), reservation(source(changed=True))], read_only=True)
    assert error.value.detail == "event_xml_differs"
    assert not db.allocations and not db.representations


def test_archive_integrity_failure_does_not_open_preferred_source():
    from types import SimpleNamespace

    from server.sli.storage.storage_v2_archive import ArchiveIntegrityError
    from server.sli.storage.storage_v2_runtime import StorageV2RuntimeReader

    def corrupt(**kwargs):
        raise ArchiveIntegrityError("fixture-corrupt-archive")

    store = SimpleNamespace(get_event_summary=lambda event_id: {"id": event_id},
        get_preferred_event_payload=lambda summary: pytest.fail("archive integrity must fail closed"))
    with pytest.raises(ArchiveIntegrityError, match="fixture-corrupt-archive"):
        StorageV2RuntimeReader(store, SimpleNamespace(read_event=corrupt)).event_details(1)

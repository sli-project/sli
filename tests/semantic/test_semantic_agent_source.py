import json
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest

from server.sli.semantic.semantic_context import hydrate_dispatch_context
from server.sli.semantic.semantic_processing import normalize_semantic_source_payload
from server.sli.semantic.semantic_processing_repository import (
    load_semantic_source_event,
)
from server.sli.storage.storage_v2_archive import (
    ArchiveIntegrityError,
    ArchiveReader,
    InMemoryArchiveManifestStore,
)

NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)
XML = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
       '<EventData><Data Name="TargetUserName">fixture-account</Data>'
       '<Data Name="Status">0xc000006a</Data><Data Name="LogonType">3</Data>'
       '</EventData></Event>')


def evidence(event_id=4625):
    row = {"event_id": event_id, "record_id": 42, "time_created": NOW.isoformat(),
           "computer_name": "fixture-dc", "channel": "Security", "xml": XML}
    digest = sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()).digest()
    core = {"id": 7, "server_id": 1, "domain_id": 2, "log_source_id": 3,
            "event_id": event_id, "event_record_id": 42, "time_created_utc": NOW,
            "normalized_hash": digest, "migrated_at": NOW, "channel": "Security",
            "computer": "fixture-dc", "provider_name": "Microsoft-Windows-Security-Auditing"}
    return core, row


class Cursor:
    def __init__(self, value):
        self.value = value

    def execute(self, sql, params=()):
        assert "read_agent_semantic_source_v190" in sql
        assert params == (7,)

    def fetchone(self):
        return self.value


class MissingArchive:
    def read_event(self, *, archive_kind, event_id):
        raise KeyError(f"published archive block not found for event {event_id}")


def test_agent_event_without_archive_normalizes_named_evidence():
    core, row = evidence()
    source = load_semantic_source_event(
        Cursor({"source": {"core": core, "event_row": row}}), source_event_id=7,
        archive=MissingArchive(), source_identity=core,
    )
    normalized = normalize_semantic_source_payload(source)
    assert normalized.semantic_type == "authentication.session.failed"
    assert source["event_data_json"]["LogonType"] == "3"
    assert normalized.facts["failure_status"] == "0xc000006a"
    assert source["source_event_sha256"] == core["normalized_hash"]


@pytest.mark.parametrize("difference_us", [-1, 1])
def test_agent_timestamp_precision_preserves_exact_evidence(difference_us):
    core, row = evidence()
    core["time_created_utc"] = NOW + timedelta(microseconds=difference_us)
    source = load_semantic_source_event(
        Cursor({"source": {"core": core, "event_row": row}}), source_event_id=7,
        archive=MissingArchive(), source_identity=core,
    )
    assert source["time_created_utc"] == core["time_created_utc"]
    assert source["source_event_sha256"] == core["normalized_hash"]
    assert normalize_semantic_source_payload(source).semantic_type == "authentication.session.failed"


def test_windows_100ns_timestamp_rounding_reads_immutable_row():
    core, row = evidence()
    row["time_created"] = "2026-10-09T00:00:00.502957500Z"
    core["time_created_utc"] = NOW.replace(microsecond=502958)
    core["normalized_hash"] = sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()).digest()
    source = load_semantic_source_event(
        Cursor({"source": {"core": core, "event_row": row}}), source_event_id=7,
        archive=MissingArchive(), source_identity=core,
    )
    assert source["source_event_sha256"] == core["normalized_hash"]


@pytest.mark.parametrize("difference_us", [-2, 2])
def test_agent_timestamp_beyond_precision_bound_fails_closed(difference_us):
    core, row = evidence()
    core["time_created_utc"] = NOW + timedelta(microseconds=difference_us)
    with pytest.raises(ArchiveIntegrityError, match="identity mismatch"):
        load_semantic_source_event(
            Cursor({"source": {"core": core, "event_row": row}}), source_event_id=7,
            archive=MissingArchive(), source_identity=core,
        )


def test_timestamp_precision_never_admits_changed_payload():
    core, row = evidence()
    core["time_created_utc"] = NOW + timedelta(microseconds=1)
    row["xml"] = row["xml"].replace("fixture-account", "other-account")
    with pytest.raises(ArchiveIntegrityError, match="hash mismatch"):
        load_semantic_source_event(
            Cursor({"source": {"core": core, "event_row": row}}), source_event_id=7,
            archive=MissingArchive(), source_identity=core,
        )


@pytest.mark.parametrize("mutation", ["hash", "record", "time", "job", "core_hash"])
def test_agent_evidence_mismatch_fails_closed(mutation):
    core, row = evidence()
    identity = dict(core)
    if mutation == "hash":
        row["xml"] = row["xml"].replace("fixture-account", "other-account")
    elif mutation == "record":
        core["event_record_id"] = 43
    elif mutation == "time":
        core["time_created_utc"] = NOW.replace(hour=1)
    elif mutation == "job":
        identity["normalized_hash"] = b"x" * 32
    else:
        core["normalized_hash"] = b"x" * 32
    with pytest.raises(ArchiveIntegrityError):
        load_semantic_source_event(
            Cursor({"source": {"core": core, "event_row": row}}), source_event_id=7,
            archive=MissingArchive(), source_identity=identity,
        )


def test_missing_agent_evidence_preserves_archive_failure():
    core, _ = evidence()
    with pytest.raises(KeyError, match="published archive block not found"):
        load_semantic_source_event(Cursor({"source": None}), source_event_id=7,
                                   archive=MissingArchive(), source_identity=core)


def test_archive_integrity_error_does_not_fall_back_to_inbox():
    core, _ = evidence()

    class BrokenArchive:
        def read_event(self, **kwargs):
            raise ArchiveIntegrityError("archive digest mismatch")

    with pytest.raises(ArchiveIntegrityError, match="archive digest mismatch"):
        load_semantic_source_event(Cursor(None), source_event_id=7,
                                   archive=BrokenArchive(), source_identity=core)


def test_agent_context_without_archive_is_hydrated_for_correlation(monkeypatch):
    core, row = evidence(4624)

    class ContextCursor(Cursor):
        def execute(self, sql, params=()):
            if "read_agent_semantic_source_v190" in sql:
                super().execute(sql, params)

        def fetchall(self):
            return [core]

    events = []
    monkeypatch.setattr("server.sli.semantic.semantic_context.persist_normalized_event",
                        lambda cur, *, event, source_identity: events.append(event))
    count = hydrate_dispatch_context(
        ContextCursor({"source": {"core": core, "event_row": row}}),
        archive=ArchiveReader(InMemoryArchiveManifestStore()),
        semantic_types=("authentication.session.created",), join_roles=("source_host",),
        trigger_roles={"source_host": "1"}, partition_key="1", start_utc=NOW, end_utc=NOW,
    )
    assert count == 1
    assert events[0].semantic_type == "authentication.session.created"
    assert events[0].facts["logon_type"] == "3"


def test_context_missing_row_in_published_block_does_not_use_inbox():
    core, _ = evidence(4624)

    class ContextCursor:
        def execute(self, sql, params=()):
            assert "read_agent_semantic_source_v190" not in sql

        def fetchall(self):
            return [core]

    class BrokenArchive:
        manifest = type("Manifest", (), {"find_published": lambda *args: object()})()

        def read_events_many(self, *args, **kwargs):
            raise KeyError("event archive is missing requested identities: [7]")

    with pytest.raises(KeyError, match="missing requested identities"):
        hydrate_dispatch_context(
            ContextCursor(), archive=BrokenArchive(),
            semantic_types=("authentication.session.created",), join_roles=("source_host",),
            trigger_roles={"source_host": "1"}, partition_key="1", start_utc=NOW, end_utc=NOW,
        )

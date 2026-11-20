"""Immutable conflicts are isolated; transient projection failures still retry."""
from contextlib import nullcontext

import pytest

from server.sli.agents import consumer
from server.sli.ops import logging_config
from server.sli.storage.storage_v2_repository import PostgresStorageV2Repository, SourceEventIdentityConflict
from tests.unit.test_agent_dispatch import Database, NOW, runner, stage


@pytest.mark.parametrize("published", [False, True])
def test_conflict_rolls_back_projection_quarantines_evidence_and_does_not_starve_next_packet(monkeypatch, published):
    db = Database()
    bad = stage(db)
    good = stage(db, received=NOW.replace(second=1))
    real = consumer.dispatch_packet
    logs = []

    def dispatch(conn, rows, **kwargs):
        real(conn, rows, **kwargs)
        if kwargs["envelope"]["packet_id"] == bad:
            raise SourceEventIdentityConflict(0, published=published)

    monkeypatch.setattr(consumer, "dispatch_packet", dispatch)
    monkeypatch.setattr(logging_config, "log_event", lambda *args, **kw: logs.append((args[1], kw)))
    result = runner(monkeypatch, db).run_once()
    reason = "published_source_event_hash_mismatch" if published else "source_event_allocation_hash_mismatch"
    assert result["imported"] == 1 and result["quarantined"] == 1
    assert result["pending_reasons"] == {} and result["quarantine_reasons"] == {reason: 1}
    assert db.quarantine == {bad: {"reason_code": reason, "event_ordinal": 0}}
    assert not db.inbox[0].get("imported") and db.inbox[1]["packet_id"] == good and db.inbox[1]["imported"]
    assert len(db.observations) == 1
    assert logs[0][0] == "agent_packets_quarantined"
    assert logs[0][1]["quarantined_packets"][0]["reason"] == reason
    assert "source_xml" not in repr(logs) and "fixture-bookmark" not in repr(logs)
    assert runner(monkeypatch, db).run_once()["scanned"] == 0


def test_unknown_exception_even_with_conflict_message_stays_retryable_and_has_safe_packet_diagnostics(monkeypatch):
    db = Database()
    packet_id = stage(db)
    logs = []

    def fail(*args, **kwargs):
        raise RuntimeError("allocation hash mismatch fixture-private-diagnostic")

    monkeypatch.setattr(consumer, "dispatch_packet", fail)
    monkeypatch.setattr(logging_config, "log_event", lambda *args, **kw: logs.append(kw))
    result = runner(monkeypatch, db).run_once()
    assert result["pending_reasons"] == {"agent_projection_failed": 1}
    assert result["quarantined"] == 0 and not db.quarantine and not db.inbox[0].get("imported")
    diagnostic = logs[0]["pending_packets"][0]
    assert diagnostic["packet_id"] == packet_id and diagnostic["module_id"] == "sli.workstations"
    assert diagnostic["agent_id"] == db.agent["id"] and diagnostic["error_type"] == "RuntimeError"
    assert "fixture-private-diagnostic" not in repr(logs)


@pytest.mark.parametrize("mismatch", ["allocation", "core", "retained_allocation"])
def test_repository_preserves_hash_guards_and_raises_typed_conflict_with_fake_readback(mismatch):
    wanted = b"a" * 32
    row = {"ordinal": 0, "id": 7, "normalized_hash": wanted, "allocated_hash": wanted,
           "published": True, "core_hash": wanted}
    if mismatch == "allocation":
        row["normalized_hash"] = b"b" * 32
    elif mismatch == "core":
        row["core_hash"] = b"b" * 32
    else:
        row["allocated_hash"] = b"b" * 32
    statements = []

    class Cursor:
        def execute(self, sql, params):
            statements.append(sql)

        def fetchall(self):
            return [row]

    class Connection:
        def cursor(self):
            return nullcontext(Cursor())

    repo = PostgresStorageV2Repository(lambda: nullcontext(Connection()))
    with pytest.raises(SourceEventIdentityConflict) as error:
        repo.reserve_event_identities([{"server_id": 1, "channel_id": 1, "event_record_id": 1,
            "time_created_utc": "2026-10-11T00:00:00Z", "normalized_hash": wanted}])
    assert error.value.ordinal == 0
    assert error.value.reason == ("published_source_event_hash_mismatch" if mismatch == "core"
                                  else "source_event_allocation_hash_mismatch")
    assert len(statements) == 2 and "on conflict" in statements[0]
    assert not any("update " in sql.lower() or "delete " in sql.lower() for sql in statements)

"""Durable quota admission with fake cursors, never a real database."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import json
from threading import Barrier, Lock
from uuid import uuid4

import pytest

from server.sli.agent_ingest import PostgresLedger
from server.sli.agents import inbox_quota
from server.sli.agents.inbox_quota import InboxLimits, quota_error


@pytest.fixture(autouse=True)
def audit_events(monkeypatch):
    events = []
    monkeypatch.setattr(inbox_quota, "log_audit_action", lambda action, status, **fields:
                        events.append((action, status, fields)))
    return events


def packet():
    return {"envelope": {"agent_id": str(uuid4()), "module_id": "sli.windows-eventlog"},
            "payload": {"records": [{"xml": "synthetic evidence"}]}}, {"status": "committed"}, []


class Cursor:
    def __init__(self, *, usage=None, storage_bytes=0):
        self.usage = dict.fromkeys((key for key in asdict(InboxLimits()) if key != "storage_bytes"), 0)
        self.usage.update(usage or {})
        self.storage_bytes = storage_bytes
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if sql.startswith("with stored"):
            self.result = dict(self.usage)
        elif sql.startswith("select coalesce"):
            # PostgreSQL's JSONB text has spaces, UTF-8 and unescaped non-ASCII.
            self.result = {"bytes": sum(len(json.dumps(json.loads(raw), ensure_ascii=False).encode("utf-8"))
                                        for raw in params[0]), "storage_bytes": self.storage_bytes}
        elif "pg_advisory_xact_lock" not in sql:
            pytest.fail("unexpected quota query")

    def fetchone(self):
        return self.result


def cost(value, receipt, rows):
    documents = [value["envelope"], receipt]
    overhead = 1024
    if rows is not None:
        overhead += 1024
        documents += [value["envelope"], value["payload"], rows]
    return overhead + sum(len(json.dumps(item, ensure_ascii=False).encode("utf-8")) for item in documents)


@pytest.mark.parametrize("field", asdict(InboxLimits()))
def test_each_budget_accepts_exact_boundary_and_rejects_one_byte_or_packet_over(field, audit_events):
    value, receipt, rows = packet()
    amount = cost(value, receipt, rows)
    boundary = 2 * amount + 65536 if field == "storage_bytes" else amount if field.endswith("bytes") else 1
    limits = replace(InboxLimits(), **{field: boundary})
    assert quota_error(Cursor(), value, receipt, rows, limits=limits) is None
    usage = {} if field == "storage_bytes" else {field: 1}
    cur = Cursor(usage=usage, storage_bytes=int(field == "storage_bytes"))
    assert quota_error(cur, value, receipt, rows, limits=limits) == "agent_inbox_" + field + "_limit"
    assert not any("insert into sli_agent_receipts" in sql or "insert into sli_agent_packet_inbox" in sql
                   for sql, _ in cur.calls)
    action, status, metrics = audit_events[0]
    assert action == "agent_packet_admission" and status == "retry_later"
    assert metrics["event"] == "packet_quota_rejected"
    assert metrics["agent_id"] == value["envelope"]["agent_id"]
    assert metrics["usage"][field] == 1
    assert metrics["packet_bytes"] == amount
    assert "synthetic evidence" not in json.dumps(metrics)


def test_pending_bytes_charge_both_envelopes_packet_and_expanded_rows():
    value, receipt, _ = packet()
    rows = [{"xml": "synthetic expanded evidence" * 100}]
    cur = Cursor()
    assert PostgresLedger(cur).quota_error(value, receipt, rows) is None
    assert cur.calls[0][0] == "select pg_advisory_xact_lock(157, 1)"
    sql, params = cur.calls[1]
    assert "where i.imported_at is null" in sql
    assert "join sli_agent_receipts" in sql
    assert "coalesce(i.quota_payload_bytes," in sql
    assert "octet_length(i.packet::text)" in sql  # Exact fallback for legacy NULLs.
    assert params == (value["envelope"]["agent_id"],) * 2 + (value["envelope"]["module_id"],) * 2
    documents = [json.loads(raw) for raw in cur.calls[2][1][0]]
    assert documents == [value["envelope"], receipt, value["envelope"], value["payload"], rows]
    limit = len(json.dumps(value).encode())
    assert quota_error(Cursor(), value, receipt, rows,
                       limits=replace(InboxLimits(), agent_bytes=limit)) == "agent_inbox_agent_bytes_limit"


def test_receipt_only_heartbeat_is_bounded_by_storage_high_water():
    value, receipt, _ = packet()
    value["envelope"]["module_id"] = "sli.heartbeat"
    cur = Cursor(storage_bytes=InboxLimits().storage_bytes)
    assert quota_error(cur, value, receipt, None) == "agent_inbox_storage_bytes_limit"
    assert len(cur.calls[2][1][0]) == 2


def test_restart_rebuilds_usage_and_consumer_progress_releases_pending_budget():
    value, receipt, rows = packet()
    limits = replace(InboxLimits(), agent_count=1)
    durable_usage = {"agent_count": 1, "module_count": 1, "global_count": 1}
    # Each fresh cursor represents a restarted process; no in-memory quota resets.
    for _ in range(2):
        assert quota_error(Cursor(usage=durable_usage), value, receipt, rows, limits=limits)
    assert quota_error(Cursor(storage_bytes=100_000), value, receipt, rows, limits=limits) is None


def test_an_exhausted_agent_budget_does_not_block_another_agent():
    value, receipt, rows = packet()
    limits = replace(InboxLimits(), agent_count=1)
    assert quota_error(Cursor(usage={"agent_count": 1, "global_count": 1}),
                       value, receipt, rows, limits=limits) == "agent_inbox_agent_count_limit"
    value["envelope"]["agent_id"] = str(uuid4())
    assert quota_error(Cursor(usage={"global_count": 1}), value, receipt, rows, limits=limits) is None


def test_global_reservation_serializes_competing_agents_until_commit():
    shared = Cursor()
    mutex, barrier = Lock(), Barrier(2)
    limits = replace(InboxLimits(), global_count=1)

    def admit():
        value, receipt, rows = packet()
        class TransactionCursor(Cursor):
            def execute(self, sql, params=()):
                if "pg_advisory_xact_lock" in sql:
                    mutex.acquire()
                    self.usage = dict(shared.usage)
                super().execute(sql, params)
        cur = TransactionCursor()
        barrier.wait(timeout=5)
        try:
            result = quota_error(cur, value, receipt, rows, limits=limits)
            if result is None:
                # Simulate the receipt/inbox INSERT and COMMIT under the lock.
                shared.usage["global_count"] += 1
            return result
        finally:
            mutex.release()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: admit(), range(2)))
    assert results.count(None) == 1
    assert results.count("agent_inbox_global_count_limit") == 1
    assert shared.usage["global_count"] == 1


@pytest.mark.parametrize("value", ["0", "-1", "invalid"])
def test_invalid_server_limit_fails_closed(monkeypatch, value):
    monkeypatch.setenv("SLI_AGENT_INBOX_AGENT_COUNT", value)
    with pytest.raises(ValueError):
        quota_error(Cursor(), *packet())


def test_server_limits_come_from_environment_not_signed_payload(monkeypatch):
    monkeypatch.setenv("SLI_AGENT_INBOX_AGENT_COUNT", "1")
    value, receipt, rows = packet()
    value["payload"]["agent_count"] = 1_000_000
    assert quota_error(Cursor(usage={"agent_count": 1}), value, receipt, rows) == "agent_inbox_agent_count_limit"


def test_audit_write_failure_preserves_retryable_backpressure(monkeypatch):
    def fail(*a, **kw):
        raise OSError("synthetic-private-error")
    events = []
    monkeypatch.setattr(inbox_quota, "log_audit_action", fail)
    monkeypatch.setattr(inbox_quota, "log_event", lambda *a, **kw: events.append((a, kw)))
    assert quota_error(Cursor(storage_bytes=InboxLimits().storage_bytes), *packet()) == "agent_inbox_storage_bytes_limit"
    assert len(events) == 1
    assert "synthetic-private-error" not in str(events)

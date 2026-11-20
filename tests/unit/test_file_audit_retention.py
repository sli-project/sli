"""Seven-day XML and yearly ACL retention with no database or history service."""
from datetime import timedelta

import pytest

from server.sli.plugins.file_audit import retention
from tests.unit.test_file_audit_collection import NOW


class Cursor:
    def __init__(self, *, held=False, unresolved=False, snapshot_hold=False, fault=None):
        self.held, self.unresolved, self.snapshot_hold = held, unresolved, snapshot_hold
        self.calls = []
        self.rowcount = 1
        self.fault = fault

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, sql, args=()):
        self.calls.append((sql, args))

    def fetchall(self):
        sql = self.calls[-1][0]
        if "file_retention_packets" in sql:
            return [{"packet_id": "synthetic", "record_count": 1,
                     "events": [] if self.unresolved else [{"id": 41, "normalized_hash": "61" * 32}],
                     "held": self.held}]
        if "file_retention_snapshots" in sql:
            return [] if self.snapshot_hold else [{"snapshot_id": "synthetic-snapshot"}]
        if "file_retention_readback" in sql:
            return [{"packet_id": "synthetic"}] if self.fault == "readback" else []
        if "file_retention_event_locks" in sql:
            return [{"id": 41, "normalized_hash": b"b" * 32 if self.fault == "source" else b"a" * 32}]
        if "file_retention_semantic_locks" in sql:
            return [{"source_event_id": 41, "status": "pending" if self.fault == "semantic" else "completed"}]
        if "file_retention_event_holds" in sql:
            return [{"id": 41}] if self.fault == "hold" else []
        return []


class Connection:
    def __init__(self, **kwargs):
        self.cur = Cursor(**kwargs)
        self.commits, self.rollbacks = 0, 0

    def __enter__(self):
        return self

    def __exit__(self, kind, *_):
        if kind:
            self.rollback()

    def cursor(self):
        return self.cur

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def test_payload_is_deleted_only_after_exact_history_verification_and_facts_remain():
    conn = Connection()
    def verify(rows):
        assert rows == [{"id": 41, "normalized_hash": b"a" * 32}]
        assert not any("delete from" in sql for sql, _ in conn.cur.calls)
    result = retention.retain_batch(conn, now=NOW, preservation_check=verify)
    assert result["packets_deleted"] == 1 and result["snapshots_deleted"] == 1
    packet_args = next(args for sql, args in conn.cur.calls if "file_retention_packets" in sql)
    snapshot_args = next(args for sql, args in conn.cur.calls if "file_retention_snapshots" in sql)
    assert packet_args[0] == NOW - timedelta(days=7)
    assert snapshot_args[0] == NOW - timedelta(days=365)
    for sql, _ in conn.cur.calls:
        assert "delete from sli_plugin_file_audit.actions" not in sql
        assert "delete from sli_plugin_file_audit.observations" not in sql
        assert "delete from sli_agent_receipts" not in sql


def test_unavailable_history_prevents_both_payload_and_acl_cleanup():
    conn = Connection()
    def unavailable(_):
        raise RuntimeError("synthetic_history_unavailable")
    with pytest.raises(RuntimeError, match="history_unavailable"):
        retention.retain_batch(conn, now=NOW, preservation_check=unavailable)
    assert not any("delete from" in sql for sql, _ in conn.cur.calls)
    result = retention.retain_batch(Connection(), now=NOW, preservation_check=None)
    assert result["status"] == "blocked"


def test_workstation_packet_evidence_is_not_admitted_to_server_event_cleanup():
    conn = Connection()
    retention.retain_batch(conn, now=NOW, preservation_check=lambda _: None)
    sql = next(sql for sql, _ in conn.cur.calls if "file_retention_packets" in sql)
    # WS observations resolve to attested packet evidence, not server core events.
    assert "o.core_evidence_ref like 'agent-workstation-event:%'" in sql
    assert "and not exists(select 1 from sli_plugin_file_audit.observations o" in sql


@pytest.mark.parametrize("kwargs", [{"held": True}, {"unresolved": True}])
def test_hold_or_unresolved_identity_blocks_packet_cleanup(kwargs):
    conn = Connection(**kwargs)
    result = retention.retain_batch(conn, now=NOW,
        preservation_check=lambda _: pytest.fail("held evidence admitted"))
    assert result["packets_deleted"] == 0 and result["held_count"] == 1
    assert not any("delete from public.sli_agent_packet_inbox" in sql for sql, _ in conn.cur.calls)


def test_snapshot_holds_and_finding_references_are_fenced_and_retained():
    conn = Connection(snapshot_hold=True)
    result = retention.retain_batch(conn, now=NOW, preservation_check=lambda _: None)
    assert result["snapshots_deleted"] == 0
    sql = next(sql for sql, _ in conn.cur.calls if "file_retention_snapshots" in sql)
    assert "rule_snapshots" in sql and "retention_holds" in sql
    assert any("lock table sli_plugin_file_audit.retention_holds" in sql for sql, _ in conn.cur.calls)


@pytest.mark.parametrize("fault", ["semantic", "hold"])
def test_locked_processing_or_evidence_hold_prevents_cleanup(fault):
    conn = Connection(fault=fault)
    result = retention.retain_batch(conn, now=NOW,
        preservation_check=lambda _: pytest.fail("held core event admitted"))
    assert result["status"] == "blocked" and result["held_count"] == 1
    assert not any("delete from" in sql for sql, _ in conn.cur.calls)


@pytest.mark.parametrize("fault", ["source", "readback"])
def test_changed_source_or_failed_delete_readback_requires_rollback(fault):
    with pytest.raises(RuntimeError, match="file_audit_retention_"):
        retention.retain_batch(Connection(fault=fault), now=NOW, preservation_check=lambda _: None)


def test_retention_remains_opt_in_and_invalid_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("SLI_FILE_AUDIT_RETENTION_ENABLED", raising=False)
    assert retention.cleanup_enabled() is False
    monkeypatch.setenv("SLI_FILE_AUDIT_RETENTION_ENABLED", "1")
    assert retention.cleanup_enabled() is True
    monkeypatch.setenv("SLI_FILE_AUDIT_RETENTION_ENABLED", "yes")
    with pytest.raises(ValueError):
        retention.cleanup_enabled()


def test_core_runner_records_exact_tables_and_commits_only_verified_deletion(tmp_path, monkeypatch):
    from server.sli.storage import permanent_fact_history as history, purge_audit
    conn = Connection()
    monkeypatch.setattr(purge_audit, "AUDIT_DIR", tmp_path)
    monkeypatch.setattr("server.sli.storage.tier_retention_delete_executor_runtime._connect_write", lambda: conn)
    probes = []
    monkeypatch.setattr(history, "_rows", lambda *args: probes.append(args) or [])
    monkeypatch.setattr(history, "verify_preserved_candidates", lambda *args: None)
    result = retention.run_batch(port=1234, now=NOW)
    assert result["status"] == "complete" and conn.commits == 1
    assert probes and "published_batches" in probes[0][1]
    receipt = purge_audit.last_purge_runs()["runs"][0]
    assert receipt["lane"] == "file_audit" and receipt["transaction"] == "committed"
    assert receipt["tables"]["sli_agent_packet_inbox"]["deleted_count"] == 1
    assert receipt["tables"]["sli_plugin_file_audit.access_snapshots"]["deleted_count"] == 1

"""Signed capture -> receipt -> core dispatch -> projection, with transactional fakes."""
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import consumer
from server.sli.agent_ingest import receive_packet
from server.sli.plugins.workstations import importer
from sli_agent.envelope import digest, make_packet
from sli_agent.workstations import WorkstationsModule

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)
HOST = str(uuid4())
AGENT = str(uuid4())
XML = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
       '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>'
       '<EventRecordID>7</EventRecordID><Channel>Security</Channel>'
       '<TimeCreated SystemTime="2026-10-06T00:00:00Z"/></System>'
       '<EventData><Data Name="LogonType">10</Data></EventData></Event>')


class Database:
    def __init__(self):
        self.agent = {"id": AGENT, "host_id": HOST, "status": "active", "assigned_modules": [
            {"module_id": "sli.workstations", "enabled": True, "config": {}}]}
        self.plugin = {"installed": True, "enabled": True}
        self.inbox, self.receipts, self.observations = [], {}, {}
        self.quarantine = {}
        self.commits = 0
        self.sql = []

    def cursor(self):
        return nullcontext(Cursor(self))

    @contextmanager
    def transaction(self):
        saved = deepcopy((self.inbox, self.observations, self.quarantine))
        try:
            yield
        except Exception:
            self.inbox, self.observations, self.quarantine = saved
            raise

    def commit(self):
        self.commits += 1


class Cursor:
    def __init__(self, db):
        self.db, self.rows = db, []

    def execute(self, sql, params=()):
        db = self.db
        db.sql.append((sql, params))
        self.rows = []
        if "from sli_agent_packet_inbox" in sql:
            pending = [r for r in db.inbox if not r.get("imported") and r["packet_id"] not in db.quarantine]
            if len(params) == 3:
                pending = [r for r in pending if (r["received_at"], r["packet_id"]) > params[:2]]
            self.rows = sorted(pending, key=lambda r: (r["received_at"], r["packet_id"]))[:params[-1]]
        elif sql.startswith("update sli_agent_packet_inbox"):
            next(r for r in db.inbox if r["packet_id"] == params[0])["imported"] = True
        elif "insert into sli_agent_packet_quarantine" in sql:
            db.quarantine.setdefault(params[0], {"reason_code": params[1], "event_ordinal": params[2]})
        elif "from sli_agents" in sql:
            self.rows = [db.agent] if params[0] == AGENT else []
        elif "from sli_agent_receipts" in sql:
            self.rows = [db.receipts[params[0]]] if params[0] in db.receipts else []
        elif "from read_plugin_states_v1" in sql:
            self.rows = [db.plugin] if db.plugin else []
        elif "from sli_agent_snapshot_cycles" in sql:
            self.rows = []
        elif "resolve_agent_workstation_v160" in sql:
            self.rows = [{"entity_id": 17, "ad_computer_id": None}]
        elif "insert into sli_plugin_workstations.observations" in sql:
            observation_id = params[0]
            if observation_id not in db.observations:
                db.observations[observation_id] = {"observation": json.loads(params[7]),
                    "observation_sha256": params[8], "source_xml": params[9]}
                self.rows = [{"id": observation_id}]
        elif "select observation_sha256,observation" in sql:
            self.rows = [db.observations[params[0]]]
        elif "pg_advisory_xact_lock" not in sql:
            raise AssertionError(sql)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


def stage(db, *, module="sli.workstations", received=NOW):
    key = ec.generate_private_key(ec.SECP256R1())
    sample = WorkstationsModule(HOST, reader=lambda *a: [(XML, "fixture-bookmark")]).collect(now=NOW)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    if module == "sli.workstations":
        class Ledger:
            def get(self, *a): return None
            def packet_exists(self, *a): return False
            def latest(self, *a): return None
            def quota_error(self, *a): return None
            def commit(self, value, receipt, envelope_hash, rows):
                self.rows = rows
        ledger = Ledger()
        receipt = receive_packet(ledger, identity=db.agent, public_key=key.public_key(), value=value, now=NOW)
        assert receipt["status"] == "committed"
        rows = ledger.rows
    else:
        rows = []
        value["envelope"]["module_id"] = module
    envelope = value["envelope"]
    packet_id = envelope["packet_id"]
    db.receipts[packet_id] = {"envelope": deepcopy(envelope), "envelope_sha256": digest(envelope)}
    db.inbox.append({"packet_id": packet_id, "envelope": envelope, "packet": value["payload"],
                     "event_rows": rows, "received_at": received})
    return packet_id


def runner(monkeypatch, db):
    monkeypatch.setattr(consumer, "connect", lambda: nullcontext(db))
    return consumer.AgentPacketConsumer()


def test_signed_workstation_packet_reaches_projection_and_restart_is_idempotent(monkeypatch):
    db = Database()
    stage(db)
    result = runner(monkeypatch, db).run_once()
    assert result == {"imported": 1, "scanned": 1, "pending_reasons": {},
                      "snapshots": {"completed": 0, "scanned": 0, "pending_reasons": {}},
                      "quarantined": 0, "quarantine_reasons": {}}
    assert db.inbox[0]["imported"] and db.commits == 2
    observation = next(iter(db.observations.values()))
    assert observation["source_xml"] == XML
    assert observation["observation"]["agent_key"] == AGENT
    assert observation["observation"]["entity_id"] == 17
    db.inbox[0]["imported"] = False  # replay publication with preserved evidence
    assert runner(monkeypatch, db).run_once()["imported"] == 1
    assert len(db.observations) == 1


@pytest.mark.parametrize("state", [None, {"installed": False, "enabled": True}, {"installed": True, "enabled": False}])
def test_uninstalled_or_disabled_plugin_preserves_evidence(monkeypatch, state):
    db = Database()
    stage(db)
    db.plugin = state
    result = runner(monkeypatch, db).run_once()
    assert result["pending_reasons"] == {"agent_plugin_disabled": 1}
    assert not db.inbox[0].get("imported") and not db.observations


@pytest.mark.parametrize("module,reason", [("fixture.unknown", "agent_module_unknown"),
                                           ("sli.windows-eventlog", "dc_importer_unavailable")])
def test_unavailable_module_keeps_pending_with_safe_reason(monkeypatch, module, reason):
    db = Database()
    stage(db, module=module)
    assert runner(monkeypatch, db).run_once()["pending_reasons"] == {reason: 1}
    assert not db.observations and not db.inbox[0].get("imported")


def test_scanner_walks_past_deferred_packets_and_wraps(monkeypatch):
    db = Database()
    stage(db, module="fixture.unknown")
    stage(db, received=NOW.replace(second=1))
    worker = runner(monkeypatch, db)
    assert worker.run_once(limit=1)["imported"] == 0
    assert worker.run_once(limit=1)["imported"] == 1
    assert worker.run_once(limit=1)["scanned"] == 0
    assert worker.run_once(limit=1)["pending_reasons"] == {"agent_module_unknown": 1}


def test_busy_inbox_throttles_snapshot_retries_without_losing_snapshot_position(monkeypatch):
    from server.sli.agents import snapshot_consumer

    db = Database()
    clock = [100.0]
    scans = []

    def snapshots(conn, *, after, on_scan, **kwargs):
        scans.append(after)
        on_scan("fixture-cycle")
        return {"completed": 0, "scanned": 1, "pending_reasons": {"agent_ad_publication_failed": 1}}

    monkeypatch.setattr(consumer, "monotonic", lambda: clock[0])
    monkeypatch.setattr(snapshot_consumer, "consume_snapshot_cycles", snapshots)
    worker = runner(monkeypatch, db)
    stage(db)
    assert worker.run_once(limit=1)["imported"] == 1
    for second in (101, 110, 129):
        clock[0] = second
        stage(db, received=NOW.replace(second=second - 100))
        result = worker.run_once(limit=1)
        assert result["imported"] == 1
        assert result["snapshots"]["scanned"] == 0
        assert worker.snapshot_after == "fixture-cycle"
    assert scans == [None]
    clock[0] = 130
    worker.run_once(limit=1)
    assert scans == [None, "fixture-cycle"]


def test_snapshot_scan_failure_is_retried_on_the_next_poll(monkeypatch):
    from server.sli.agents import snapshot_consumer

    worker = runner(monkeypatch, Database())
    monkeypatch.setattr(consumer, "monotonic", lambda: 100.0)

    def fail(*args, **kwargs):
        raise RuntimeError("fixture-failure")

    monkeypatch.setattr(snapshot_consumer, "consume_snapshot_cycles", fail)
    with pytest.raises(RuntimeError, match="fixture-failure"):
        worker.run_once()
    assert worker.snapshot_poll_at == 0
    assert worker.snapshot_after is None


def test_successful_full_snapshot_batches_continue_without_retry_delay(monkeypatch):
    from server.sli.agents import snapshot_consumer

    scans = []

    def snapshots(conn, *, after, on_scan, **kwargs):
        scans.append(after)
        on_scan(f"fixture-cycle-{len(scans)}")
        return {"completed": 4, "scanned": 4, "pending_reasons": {}}

    monkeypatch.setattr(consumer, "monotonic", lambda: 100.0)
    monkeypatch.setattr(snapshot_consumer, "consume_snapshot_cycles", snapshots)
    worker = runner(monkeypatch, Database())
    worker.run_once()
    worker.run_once()
    assert scans == [None, "fixture-cycle-1"]


def test_failed_poll_commit_keeps_snapshot_position_and_retry_due(monkeypatch):
    from server.sli.agents import snapshot_consumer

    db = Database()
    scans = []

    def snapshots(conn, *, after, on_scan, **kwargs):
        scans.append(after)
        on_scan("fixture-cycle")
        return {"completed": 0, "scanned": 1, "pending_reasons": {}}

    monkeypatch.setattr(consumer, "monotonic", lambda: 100.0)
    monkeypatch.setattr(snapshot_consumer, "consume_snapshot_cycles", snapshots)
    commit = db.commit
    monkeypatch.setattr(db, "commit", lambda: (_ for _ in ()).throw(RuntimeError("fixture-commit")))
    worker = runner(monkeypatch, db)
    with pytest.raises(RuntimeError, match="fixture-commit"):
        worker.run_once()
    assert worker.snapshot_after is None and worker.snapshot_poll_at == 0
    monkeypatch.setattr(db, "commit", commit)
    worker.run_once()
    assert scans == [None, None]


def test_each_packet_is_committed_before_importing_the_next(monkeypatch):
    db = Database()
    first = stage(db)
    second = stage(db, received=NOW.replace(second=1))
    real = importer.project_packet
    seen = []

    def project(*args, **kwargs):
        if seen:
            assert db.commits == 1
            assert next(row for row in db.inbox if row["packet_id"] == first)["imported"]
        seen.append(True)
        return real(*args, **kwargs)

    monkeypatch.setattr(importer, "project_packet", project)
    result = runner(monkeypatch, db).run_once(limit=2)
    assert result["imported"] == 2 and result["pending_reasons"] == {}
    assert len(seen) == 2 and db.commits == 3
    assert next(row for row in db.inbox if row["packet_id"] == second)["imported"]


def test_disable_between_packet_commits_prevents_later_publication(monkeypatch):
    db = Database()
    first = stage(db)
    second = stage(db, received=NOW.replace(second=1))
    commit = db.commit

    def disable_after_commit():
        commit()
        db.agent["status"] = "disabled"

    monkeypatch.setattr(db, "commit", disable_after_commit)
    result = runner(monkeypatch, db).run_once(limit=2)
    assert result["imported"] == 1
    assert result["scanned"] == 2
    assert result["pending_reasons"] == {"agent_disabled": 1}
    assert next(row for row in db.inbox if row["packet_id"] == first)["imported"]
    assert not next(row for row in db.inbox if row["packet_id"] == second).get("imported")
    assert len(db.observations) == 1


def test_update_sigterm_commits_current_packet_and_preserves_remaining_inbox(monkeypatch):
    import signal
    from server.sli.ops import shutdown

    db = Database()
    first = stage(db)
    second = stage(db, received=NOW.replace(second=1))
    commit = db.commit

    def stop_after_commit():
        commit()
        signal.raise_signal(signal.SIGTERM)

    worker = runner(monkeypatch, db)
    with shutdown.graceful_shutdown():
        monkeypatch.setattr(db, "commit", stop_after_commit)
        result = worker.run_once(limit=16)
        assert result["imported"] == result["scanned"] == 1
    assert next(row for row in db.inbox if row["packet_id"] == first)["imported"]
    assert not next(row for row in db.inbox if row["packet_id"] == second).get("imported")
    monkeypatch.setattr(db, "commit", commit)
    # A fresh worker starts from durable state and imports the retained packet.
    assert runner(monkeypatch, db).run_once(limit=16)["imported"] == 1


def test_packet_commits_keep_deferred_scan_position_within_batch(monkeypatch):
    db = Database()
    stage(db, module="fixture.unknown")
    stage(db, received=NOW.replace(second=1))
    worker = runner(monkeypatch, db)
    result = worker.run_once(limit=2)
    assert result["imported"] == 1 and result["scanned"] == 2
    assert result["pending_reasons"] == {"agent_module_unknown": 1}
    assert worker.run_once(limit=2)["scanned"] == 0
    assert worker.run_once(limit=2)["pending_reasons"] == {"agent_module_unknown": 1}


@pytest.mark.parametrize("limit", [True, 0, 129, "16"])
def test_invalid_packet_limit_does_not_open_connection(monkeypatch, limit):
    monkeypatch.setattr(consumer, "connect", lambda: pytest.fail("invalid poll reached database"))
    with pytest.raises(ValueError, match="agent_import_limit_invalid"):
        consumer.AgentPacketConsumer().run_once(limit=limit)


@pytest.mark.parametrize("mutation,reason", [("disabled", "agent_disabled"),
    ("unassigned", "agent_module_not_assigned"), ("module_disabled", "agent_module_not_assigned"),
    ("receipt", "agent_packet_attestation_invalid"),
    ("payload", "agent_packet_attestation_invalid")])
def test_rechecks_attestation_without_deriving_identity_from_payload(monkeypatch, mutation, reason):
    db = Database()
    packet_id = stage(db)
    if mutation == "disabled": db.agent["status"] = "disabled"
    elif mutation == "unassigned": db.agent["assigned_modules"] = []
    elif mutation == "module_disabled": db.agent["assigned_modules"][0]["enabled"] = False
    elif mutation == "receipt": db.receipts[packet_id]["envelope_sha256"] = "0" * 64
    else: db.inbox[0]["packet"]["header"]["source"] = str(uuid4())
    assert runner(monkeypatch, db).run_once()["pending_reasons"] == {reason: 1}
    assert not db.observations and not db.inbox[0].get("imported")


def test_pending_reason_is_recorded_with_packet_without_source_data(monkeypatch):
    from server.sli.ops import logging_config

    db = Database()
    packet_id = stage(db)
    db.agent["status"] = "disabled"
    logs = []
    monkeypatch.setattr(logging_config, "log_event", lambda *_args, **kw: logs.append(kw))
    assert runner(monkeypatch, db).run_once()["imported"] == 0
    assert logs == [{"pending_reasons": {"agent_disabled": 1},
                    "pending_packets": [{"packet_id": packet_id, "reason": "agent_disabled"}]}]
    assert not db.inbox[0].get("imported")


def test_partial_projection_failure_rolls_back_evidence_and_can_retry(monkeypatch):
    db = Database()
    stage(db)
    real = importer.project_packet

    def fail(*args, **kwargs):
        real(*args, **kwargs)
        raise RuntimeError("fixture-private-diagnostic")

    monkeypatch.setattr(importer, "project_packet", fail)
    result = runner(monkeypatch, db).run_once()
    assert result["pending_reasons"] == {"agent_projection_failed": 1}
    assert "fixture-private-diagnostic" not in repr(result)
    assert not db.observations and not db.inbox[0].get("imported")
    monkeypatch.setattr(importer, "project_packet", real)
    assert runner(monkeypatch, db).run_once()["imported"] == 1


@pytest.mark.parametrize("agent_state", ["imported", "empty", "disabled", "unavailable", "projection_failed", "quarantined"])
@pytest.mark.parametrize("legacy_failure", [False, True])
@pytest.mark.parametrize("full_batch", [False, True])
def test_existing_worker_polls_agent_inbox_and_reports_safe_failures(monkeypatch, capsys, agent_state, legacy_failure, full_batch):
    from scripts.runtime import post_collection_worker as worker

    events = []
    heartbeats = []
    monkeypatch.setattr(worker, "resolve_storage_route", lambda **kw: None)
    monkeypatch.setattr(worker, "_worker_id", lambda: "fixture-worker")
    monkeypatch.setattr(worker, "log_event", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **kw: heartbeats.append(kw))
    agent_failed = agent_state in {"unavailable", "projection_failed"}
    reasons = {
        "disabled": {"agent_plugin_disabled": 1},
        "unavailable": {"agent_consumer_unavailable": 1},
        "projection_failed": {"agent_projection_failed": 1},
    }.get(agent_state, {})
    agent_result = {"imported": int(agent_state == "imported"),
                    "scanned": (16 if full_batch else 1) if agent_state != "empty" else 0, "pending_reasons": reasons,
                    "quarantined": int(agent_state == "quarantined")}

    class Poller:
        def run_once(self, *, limit):
            assert limit == worker.AGENT_PACKET_BATCH_LIMIT
            events.append("agents")
            if agent_state == "unavailable":
                raise RuntimeError("fixture-private-diagnostic")
            return agent_result

    monkeypatch.setattr(worker, "AgentPacketConsumer", Poller)
    monkeypatch.setattr(worker, "run_persisted_post_collection_worker_once",
                        lambda **kw: events.append("legacy") or {"failed": int(legacy_failure)})
    assert worker._run_locked(once=True, poll_seconds=30, limit=1) == int(legacy_failure)
    assert events == ["agents", "legacy"]
    assert heartbeats[-1]["status"] == ("failed" if agent_failed or legacy_failure else
                                       "warning" if agent_state == "quarantined" else "idle")
    assert heartbeats[-1]["details"]["agent_packets"]["pending_reasons"] == reasons
    output = capsys.readouterr().out
    assert "fixture-private-diagnostic" not in output
    assert '"agent_packets"' in output


@pytest.mark.parametrize("deferred", [False, True])
@pytest.mark.parametrize("scans", [(16, 16, 0), (16, 3)])
def test_worker_drains_full_agent_batches_then_sleeps_before_cursor_wrap(monkeypatch, deferred, scans):
    from scripts.runtime import post_collection_worker as worker

    events = []
    batches = iter(scans)
    monkeypatch.setattr(worker, "resolve_storage_route", lambda **kw: None)
    monkeypatch.setattr(worker, "_worker_id", lambda: "fixture-worker")
    monkeypatch.setattr(worker, "log_event", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **kw: None)

    class Poller:
        def run_once(self, *, limit):
            assert limit == worker.AGENT_PACKET_BATCH_LIMIT
            scanned = next(batches)
            events.append(("agents", scanned))
            return {"scanned": scanned, "imported": 0 if deferred else scanned,
                    "pending_reasons": {"agent_plugin_disabled": scanned} if deferred and scanned else {}}

    monkeypatch.setattr(worker, "AgentPacketConsumer", Poller)
    monkeypatch.setattr(worker, "run_persisted_post_collection_worker_once",
                        lambda **kw: events.append(("legacy", 1)) or {"failed": 0})
    monkeypatch.setattr(worker, "plugin_hook", lambda *a: None)
    from server.sli.sources import ad_dc_agent_import
    monkeypatch.setattr(ad_dc_agent_import, "run_agent_import_once", lambda **kw: 0)

    class StopPolling(Exception):
        pass

    def sleep(seconds):
        events.append(("sleep", seconds))
        raise StopPolling()

    monkeypatch.setattr(worker.time, "sleep", sleep)
    with pytest.raises(StopPolling):
        worker._run_locked(once=False, poll_seconds=30, limit=1)
    assert events == [event for scanned in scans for event in (("agents", scanned), ("legacy", 1))] + [("sleep", 30)]

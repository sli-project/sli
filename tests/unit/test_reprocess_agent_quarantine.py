"""Bounded quarantine command uses readonly preflight and per-packet commits."""
from contextlib import contextmanager
from copy import deepcopy
from uuid import uuid4

import pytest

from scripts.maintenance import reprocess_agent_quarantine as command
from server.sli.storage.storage_v2_repository import SourceEventIdentityConflict
from sli_collect.eventlog import event_packet
from tests.unit.test_event_source_identity import source


class Database:
    def __init__(self):
        self.agent = str(uuid4())
        self.rows, self.quarantine, self.sql, self.dispatched = {}, {}, [], []
        for index in range(2):
            event = source(changed=bool(index))
            packet_id = str(uuid4())
            packet = event_packet(event, generation=None, after_record_id=None)
            self.rows[packet_id] = {"packet_id": packet_id, "packet": packet, "event_rows": [event],
                "envelope": {"agent_id": self.agent, "module_id": command.MODULE, "packet_id": packet_id}, "imported": False}
            self.quarantine[packet_id] = None

    @contextmanager
    def connect(self):
        conn = Connection(self)
        with conn.transaction():
            yield conn


class Connection:
    def __init__(self, db):
        self.db, self.readonly = db, False

    def execute(self, sql):
        assert sql == "set transaction read only"
        self.readonly = True

    @contextmanager
    def transaction(self):
        saved = deepcopy((self.db.rows, self.db.quarantine, self.db.dispatched))
        try:
            yield
        except Exception:
            self.db.rows, self.db.quarantine, self.db.dispatched = saved
            raise

    @contextmanager
    def cursor(self):
        yield Cursor(self)


class Cursor:
    def __init__(self, conn):
        self.conn, self.rows = conn, []

    def execute(self, sql, params=()):
        db = self.conn.db
        db.sql.append((sql, params))
        if sql.startswith("select i.packet_id from sli_agent_packet_quarantine"):
            assert params[:3] == (db.agent, command.MODULE, "Security")
            self.rows = [{"packet_id": value} for value in db.quarantine][:params[-1]]
        elif sql.startswith("select i.packet_id,i.envelope"):
            self.rows = [deepcopy(db.rows[params[0]])] if params[0] in db.quarantine else []
        elif sql.startswith("select s.id as server_id"):
            self.rows = [{"server_id": 1, "source_name": "fixture-dc", "channel_id": 1}]
        elif sql.startswith("update sli_agent_packet_inbox"):
            assert not self.conn.readonly
            db.rows[params[0]]["imported"] = True
        elif sql.startswith("select public.recheck_agent_quarantine_v284"):
            assert not self.conn.readonly
            if len(params) == 1:
                assert db.rows[params[0]]["imported"]
                del db.quarantine[params[0]]
                self.rows = [{"resolved": True}]
            else:
                db.quarantine[params[0]] = params[1]
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


@pytest.fixture
def database(monkeypatch):
    db = Database()

    class Repository:
        def __init__(self, connect):
            pass

        def reserve_event_identities(self, events, *, read_only):
            assert read_only
            if events and events[0]["source_row"]["properties"][2] == "changed":
                raise SourceEventIdentityConflict(0, detail="event_xml_differs")

    def dispatch(conn, rows, *, packet, envelope):
        assert not conn.readonly
        db.dispatched.append(envelope["packet_id"])

    monkeypatch.setattr(command, "PostgresStorageV2Repository", Repository)
    monkeypatch.setattr(command, "dispatch_packet", dispatch)
    return db


def run(db, **kwargs):
    return command.reprocess(connect=db.connect, storage_connect=db.connect, agent_id=db.agent, **kwargs)


def test_default_dry_run_reports_each_packet_without_writes(database):
    db = database
    before = deepcopy((db.rows, db.quarantine))
    report = run(db)
    assert report["dry_run"] and report["compatible"] == report["incompatible"] == 1
    assert report["summary_ru"] == "1 совместимо / 1 нет"
    assert report["imported"] == 0 and not db.dispatched
    assert (db.rows, db.quarantine) == before
    reason = report["packets"][1]
    assert reason["reason_code"] == "event_xml_differs" and reason["reason_ru"] and reason["reason_en"]
    assert "fixture-provider" not in str(report) and "<Event" not in str(report)


def test_apply_only_imports_compatible_packet_and_retains_conflict_reason(database):
    db = database
    report = run(db, apply=True)
    assert report["imported"] == 1 and report["incompatible"] == 1
    assert len(db.dispatched) == 1 and len(db.quarantine) == 1
    assert next(iter(db.quarantine.values())) == "event_xml_differs"
    assert sum(row["imported"] for row in db.rows.values()) == 1


def test_failed_import_rolls_back_inbox_and_preserves_quarantine_without_secret_output(database, monkeypatch):
    db = database

    def fail(conn, rows, **kwargs):
        packet_id = kwargs["envelope"]["packet_id"]
        db.rows[packet_id]["imported"] = True
        raise RuntimeError("fixture-private-source-and-password")

    monkeypatch.setattr(command, "dispatch_packet", fail)
    report = run(db, apply=True)
    assert report["failed"] == 1 and report["imported"] == 0
    assert len(db.quarantine) == 2 and not any(row["imported"] for row in db.rows.values())
    assert "fixture-private-source-and-password" not in str(report)


def test_snapshot_is_bounded_and_filters_are_bound(database):
    db = database
    report = run(db, limit=1, packet_ids=[next(iter(db.rows))], received_from="2026-10-11T00:00:00Z")
    assert report["has_more"] and len(report["packets"]) == 1
    sql, params = db.sql[0]
    assert "i.packet_id=any(%s::uuid[])" in sql and "i.received_at>=%s::timestamptz" in sql
    assert params[-1] == 2

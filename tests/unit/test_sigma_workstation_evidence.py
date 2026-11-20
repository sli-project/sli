from __future__ import annotations

import copy
import hashlib
from contextlib import nullcontext
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.plugins.workstations.importer import digest
from server.sli.sigma.workstation_evidence import (
    SigmaEvidenceError,
    WorkstationEvidenceRef,
    read_workstation_evidence,
)
from server.sli.storage import workstation_history
from tests.unit.test_sigma_process_mapping import process_xml
from tests.unit.test_sigma_windows_mapping import SCOPE

AGENT = "fixture-agent"
STAMP = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc)
START, END = STAMP - timedelta(days=1), STAMP + timedelta(days=1)


@pytest.fixture
def row():
    xml = process_xml(CommandLine="fixture " + "x" * 6000)
    body = dict(agent_key=AGENT, entity_id=17, ad_computer_id=None, family="processes", event_id=4688,
                generation=SCOPE.source_generation, channel="Security", record_id=7,
                provider_name="Microsoft-Windows-Security-Auditing", observed_at=STAMP.isoformat(),
                source_sha256=hashlib.sha256(xml.encode()).hexdigest(),
                facts={"process_command_line": "bounded-fixture"}, quality={"coverage": "not_proven"})
    return dict(id=digest([AGENT, "Security", SCOPE.source_generation, 7]), agent_key=AGENT,
                entity_id=17, ad_computer_id=None, family="processes", event_id=4688,
                observed_at=STAMP, observation=body, observation_sha256=digest(body), source_xml=xml)


def reference(row):
    return WorkstationEvidenceRef(row["id"], row["observation_sha256"], row["observation"]["source_sha256"])


class PG:
    def __init__(self, rows=()):
        self.rows = copy.deepcopy(rows)
        self.calls = []

    def cursor(self):
        return nullcontext(self)

    def execute(self, sql, params):
        self.calls.append((sql, params))
        assert "from sli_plugin_workstations.observations" in sql
        assert "agent_key=%s and id=%s and family='processes'" in sql
        assert "observed_at>=%s and observed_at<%s" in sql
        assert "limit 2" in sql
        assert params[0] == AGENT
        assert isinstance(params[1], str)

    def fetchall(self):
        return self.rows


class History:
    def __init__(self, rows):
        self.rows = copy.deepcopy(rows)
        self.calls = []

    def read(self, **kwargs):
        self.calls.append(kwargs)
        return self.rows


def read(pg, ref, **kwargs):
    return read_workstation_evidence(pg, ref=ref, scope=kwargs.pop("scope", SCOPE), agent_key=AGENT,
                                     start=START, end=END, **kwargs)


def test_hot_xml_is_complete_and_id_is_not_coerced_or_replaced(row):
    pg = PG([row])
    cold = History([])
    evidence = read(pg, reference(row), history=cold)
    assert evidence.ref.observation_id == row["id"]
    assert isinstance(evidence.ref.observation_id, str)
    assert evidence.storage_kind == "workstation_observation"
    assert evidence.event.fields["CommandLine"] == "fixture " + "x" * 6000
    assert "bounded-fixture" not in evidence.event.fields.values()
    assert evidence.event.identity.scope == SCOPE
    assert pg.calls[0][1] == (AGENT, row["id"], START, END)
    assert not cold.calls
    assert not hasattr(evidence, "core_event_id")
    with pytest.raises(FrozenInstanceError):
        evidence.ref.observation_id = "1" * 64
    assert AGENT not in repr(evidence)
    assert row["id"] not in repr(evidence.ref)


def test_cold_history_adapter_reads_full_immutable_payload_without_database(row, monkeypatch):
    cold = workstation_history.ClickHouseHistoryAdapter(8123)
    calls = []

    def records(sql, params):
        calls.append((sql, params))
        return [workstation_history._record({**row, "observed_at": STAMP.isoformat()})]

    monkeypatch.setattr(cold, "_rows", records)
    evidence = read(PG(), reference(row), history=cold)
    assert evidence.ref == reference(row)
    assert evidence.event.fields["CommandLine"] == "fixture " + "x" * 6000
    assert evidence.event.identity.key == read(PG([row]), reference(row)).event.identity.key
    assert len(calls) == 1
    assert "AND id={id:String}" in calls[0][0]
    assert calls[0][1]["id"] == row["id"]
    assert calls[0][1]["family"] == "processes"
    assert calls[0][1]["limit"] == "2"


def test_cold_request_is_exact_and_scoped(row):
    history = History([workstation_history.report_row(row, evidence=True)])
    assert read(PG(), reference(row), history=history).ref == reference(row)
    assert history.calls == [dict(keys=(AGENT,), family="processes", start=START, end=END,
                                  cursor="", limit=2, observation_id=row["id"])]


@pytest.mark.parametrize("cold", [False, True])
@pytest.mark.parametrize(("field", "value"), [
    ("id", "0" * 64), ("agent_key", "fixture-other"), ("event_id", 4697),
    ("observation_sha256", "0" * 64), ("source_xml", "<Event/>"),
    ("observed_at", STAMP + timedelta(days=4)),
])
def test_hot_and_cold_evidence_are_independently_checked(row, cold, field, value):
    ref = reference(row)
    if cold:
        bad = {**workstation_history.report_row(row, evidence=True), field: value}
        pg, history = PG(), History([bad])
    else:
        pg, history = PG([{**row, field: value}]), History([])
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_evidence_mismatch$"):
        read(pg, ref, history=history)
    if not cold:
        assert not history.calls  # Integrity failure never substitutes a cold copy.


@pytest.mark.parametrize("field", ["source_instance_id", "source_generation", "installation_id"])
def test_scope_is_trusted_and_generation_must_match_immutable_ws_id(row, field):
    other = replace(SCOPE, **{field: "fixture-other"})
    cold = History([workstation_history.report_row(row, evidence=True)])
    if field == "source_generation":
        for pg, history in ((PG([row]), None), (PG(), cold)):
            with pytest.raises(SigmaEvidenceError, match="^sigma_ws_evidence_mismatch$"):
                read(pg, reference(row), scope=other, history=history)
    else:
        original = read(PG([row]), reference(row))
        scoped = read(PG([row]), reference(row), scope=other)
        assert scoped.event.identity.key != original.event.identity.key
        assert scoped.ref == original.ref


@pytest.mark.parametrize("key", ["record_id", "channel", "provider_name", "generation", "agent_key", "entity_id",
                                 "ad_computer_id", "family", "event_id", "observed_at"])
def test_mutated_observation_cannot_hide_behind_recomputed_hash(row, key):
    row["observation"][key] = "fixture-mutated"
    row["observation_sha256"] = digest(row["observation"])
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_evidence_mismatch$"):
        read(PG([row]), reference(row))


def test_observation_hash_is_verified_before_using_projection(row):
    ref = reference(row)
    row["observation"]["facts"]["process_command_line"] = "fixture-mutated"
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_evidence_mismatch$"):
        read(PG([row]), ref)


def test_cold_adapter_rejects_corrupt_full_payload(row, monkeypatch):
    cold = workstation_history.ClickHouseHistoryAdapter(8123)
    record = workstation_history._record({**row, "observed_at": STAMP.isoformat()})
    record["payload_json"] = record["payload_json"].replace("bounded-fixture", "changed-fixture")
    monkeypatch.setattr(cold, "_rows", lambda *_: [record])
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_evidence_mismatch$"):
        read(PG(), reference(row), history=cold)


def test_missing_xml_never_uses_bounded_facts(row):
    del row["source_xml"]
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_evidence_mismatch$"):
        read(PG([row]), reference(row))


@pytest.mark.parametrize("name", ["observation_id", "observation_sha256", "source_xml_sha256"])
@pytest.mark.parametrize("value", [1, "1", "", "f" * 63, "F" * 64])
def test_reference_requires_original_string_hashes(row, name, value):
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_reference_invalid$"):
        replace(reference(row), **{name: value})


def test_numeric_looking_ws_id_is_preserved_as_string(row):
    # A string of 64 digits is a legal opaque WS ID, never an integer core ID.
    ref = replace(reference(row), observation_id="1" * 64)
    assert ref.observation_id == "1" * 64
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_evidence_mismatch$"):
        read(PG([{**row, "id": ref.observation_id}]), ref)


@pytest.mark.parametrize(("rows", "code"), [([], "sigma_ws_evidence_not_found"),
                                             ([{}, {}], "sigma_ws_evidence_mismatch")])
def test_missing_or_duplicate_cold_evidence_is_not_a_nonmatch(row, rows, code):
    with pytest.raises(SigmaEvidenceError, match=f"^{code}$"):
        read(PG(), reference(row), history=History(rows))


def test_hot_duplicates_and_unavailable_stores_fail_closed(row):
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_evidence_mismatch$"):
        read(PG([row, row]), reference(row))
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_history_unavailable$"):
        read(PG(), reference(row))

    class Broken:
        def read(self, **_):
            raise RuntimeError("fixture-private-marker")

        def cursor(self):
            raise RuntimeError("fixture-private-marker")

    for pg, history, code in ((Broken(), None, "store"), (PG(), Broken(), "history")):
        with pytest.raises(SigmaEvidenceError, match=f"^sigma_ws_{code}_unavailable$") as error:
            read(pg, reference(row), history=history)
        assert "fixture-private-marker" not in str(error.value)
        assert error.value.__suppress_context__


@pytest.mark.parametrize(("start", "end"), [(END, START), (START, START),
    (START.replace(tzinfo=None), END), (START, END + timedelta(days=3651))])
def test_invalid_windows_do_not_query_stores(row, start, end):
    pg = PG([row])
    with pytest.raises(SigmaEvidenceError, match="^sigma_ws_window_invalid$"):
        read_workstation_evidence(pg, ref=reference(row), scope=SCOPE, agent_key=AGENT, start=start, end=end)
    assert not pg.calls

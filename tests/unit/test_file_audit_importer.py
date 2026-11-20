"""Core evidence publication and plugin actions share a fake inbox transaction."""
import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from server.sli.plugins.file_audit import importer
from sli_agent.envelope import make_packet
from tests.unit.test_file_audit_agent_ingest import packet
from tests.unit.test_file_audit_collection import NOW, collector, xml
from tests.unit.test_file_audit_contracts import AGENT


class Cursor:
    def __init__(self):
        self.context = {"complete": True, "observations": []}
        self.projections = []
        self.calls = []
        self.rule_snapshots = []
        self.rules = []
        self.ad_context_bound = False
        self.replay_counts = None
        self.context_keys = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, sql, args):
        self.calls.append(sql)
        if "collection_context_for_packet" in sql:
            self.context_keys = json.loads(args[-1])
        if "store_collection" in sql:
            self.projections.append(json.loads(args[-1]))
        if "publish_rules" in sql:
            self.rules.extend(json.loads(args[-1]))

    def fetchall(self):
        return [{"server_id": 1, "domain_id": 1, "site_id": None}]

    def fetchone(self):
        if "collection_replay" in self.calls[-1]:
            return {"publication": self.replay_counts}
        if "ad_context_bound" in self.calls[-1]:
            return {"ad_context_bound": self.ad_context_bound}
        if "rule_context" in self.calls[-1]:
            return {"context": {"complete": self.context["complete"], "snapshots": self.rule_snapshots,
                    "actions": self.projections[-1]["actions"]}}
        if "platform_settings" in self.calls[-1]:
            return None
        return {"context": deepcopy(self.context)}


def dependencies(monkeypatch, identity):
    cur, published = Cursor(), []
    monkeypatch.setattr(importer, "authorize_packet", lambda *_a, **_k: identity)
    monkeypatch.setattr(importer, "authorize_plugin", lambda *_: None)
    def load_runtime(*_args, **kwargs):
        assert kwargs["publish_archive"] is False
        return object()
    native = SimpleNamespace(load_authorized_direct_runtime=load_runtime)
    real_import = importer.importlib.import_module
    monkeypatch.setattr(importer.importlib, "import_module", lambda name: native if name ==
                        "scripts.import.import_event_jsonl_to_postgres" else real_import(name))
    monkeypatch.setattr("server.sli.plugins.ad.event_import.import_event_rows",
                        lambda _cur, rows, **kwargs: published.append({"rows": rows, **kwargs}))
    return SimpleNamespace(cursor=lambda: cur), cur, published


@pytest.mark.parametrize("bound", [True, False])
def test_ad_bound_context_stays_in_file_projection_without_republishing_core(monkeypatch, bound):
    key, _, identity, _ = packet()
    sample = collector(reader=lambda *_: [(xml(1, 4624, LogonType="3"), "b1"), (xml(2), "b2")],
                       path_check=lambda *_: "file").collect(now=NOW)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    conn, cur, published = dependencies(monkeypatch, identity)
    cur.ad_context_bound = bound
    result = importer.import_packet(conn, [row["payload"] for row in sample.payload["records"]],
                                   packet=sample.payload, envelope=value["envelope"])
    assert result == {"observed": 2, "actions": 1}
    assert [row["record_id"] for row in published[0]["publication_rows"]] == ([2] if bound else [1, 2])
    assert [row["record_id"] for row in published[0]["rows"]] == [1, 2]
    assert [row["event_id"] for row in cur.projections[0]["observations"]] == [4624, 4663]


@pytest.mark.parametrize("complete,expected", [(True, "rename"), (False, "write")])
def test_rename_reaches_publication_only_with_complete_native_context(monkeypatch, complete, expected):
    key, _, identity, _ = packet()
    sample = collector(reader=lambda *_: [
        (xml(1, 4656, mask="0x10000"), "b1"),
        (xml(2, mask="0x10000"), "b2"),
        (xml(3, path=r"C:\synthetic\renamed"), "b3"),
    ], path_check=lambda *_: "file").collect(now=NOW)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    conn, cur, _ = dependencies(monkeypatch, identity)
    cur.context["complete"] = complete
    importer.import_packet(conn, [r["payload"] for r in sample.payload["records"]],
                           packet=sample.payload, envelope=value["envelope"])
    last = cur.projections[-1]["actions"][-1]
    assert last["operation"] == expected
    assert len(last["evidence"]) == (3 if complete else 1)
    assert last["path"] == r"C:\synthetic\renamed"


def test_ad_bound_context_only_packet_needs_no_core_runtime(monkeypatch):
    key, _, identity, _ = packet()
    sample = collector(reader=lambda *_: [(xml(1, 4624, LogonType="3"), "b1")]).collect(now=NOW)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    conn, cur, published = dependencies(monkeypatch, identity)
    cur.ad_context_bound = True
    result = importer.import_packet(conn, [row["payload"] for row in sample.payload["records"]],
                                   packet=sample.payload, envelope=value["envelope"])
    assert result == {"observed": 1, "actions": 0}
    assert not published


def test_import_publishes_core_without_archive_and_confirms_delete_across_packets(monkeypatch):
    key, value, identity, _ = packet()
    conn, cur, published = dependencies(monkeypatch, identity)
    first = importer.import_packet(conn, [r["payload"] for r in value["payload"]["records"]],
                                   packet=value["payload"], envelope=value["envelope"])
    assert first == {"observed": 1, "actions": 1} and len(published) == 1
    assert cur.projections[0]["actions"][0]["operation"] == "write"
    cur.context["observations"] = cur.projections[0]["observations"]
    sample = collector(reader=lambda *_: [(xml(2, 4660, path=""), "b2")]).collect(value["envelope"], now=NOW)
    second = make_packet(key, agent_id=AGENT, sequence=2, sample=sample, now=NOW)
    importer.import_packet(conn, [r["payload"] for r in second["payload"]["records"]],
                           packet=second["payload"], envelope=second["envelope"])
    action = cur.projections[-1]["actions"][0]
    assert action["operation"] == "delete" and len(action["evidence"]) == 2
    assert cur.context_keys == [{"policy_revision": cur.projections[-1]["observations"][0]["policy_revision"],
                                 "facts": cur.projections[-1]["observations"][0]["facts"]}]
    assert all("commit" not in call.lower() for call in cur.calls)


def test_context_overflow_never_confirms_deletion(monkeypatch):
    key, value, identity, _ = packet()
    conn, cur, _ = dependencies(monkeypatch, identity)
    cur.context["complete"] = False
    sample = collector(reader=lambda *_: [(xml(1, 4660, path=""), "b1")]).collect(now=NOW)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    importer.import_packet(conn, [r["payload"] for r in value["payload"]["records"]],
                           packet=value["payload"], envelope=value["envelope"])
    assert cur.projections[-1]["actions"] == []
    assert cur.projections[-1]["observations"][0]["correlation_state"] == "partial"


@pytest.mark.parametrize("with_file_event", [False, True])
def test_masked_shared_context_is_correlated_but_never_claims_native_ad_identity(monkeypatch, with_file_event):
    key, _, identity, _ = packet()
    context_xml = xml(1, 4624, LogonType="3", TargetUserName="synthetic-account")
    captured = [(context_xml, "b1")]
    if with_file_event:
        captured.append((xml(2), "b2"))
    sample = collector(reader=lambda *_: captured, path_check=lambda *_: "file").collect(now=NOW)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    rows = [record["payload"] for record in sample.payload["records"]]
    assert "synthetic-account" not in rows[0]["xml"]
    conn, cur, published = dependencies(monkeypatch, identity)
    cur.ad_context_bound = True
    result = importer.import_packet(conn, rows, packet=sample.payload, envelope=value["envelope"])
    assert result["observed"] == len(captured)
    assert cur.projections[0]["observations"][0]["event_id"] == 4624
    assert len(published) == int(with_file_event)
    if with_file_event:
        assert [row["event_id"] for row in published[0]["publication_rows"]] == [4663]
        assert published[0]["rows"] == rows
        assert cur.projections[0]["actions"][0]["operation"] == "write"


def test_unattested_rows_never_reach_storage_or_projection(monkeypatch):
    _, value, identity, _ = packet()
    conn, cur, published = dependencies(monkeypatch, identity)
    with pytest.raises(ValueError, match="attestation_invalid"):
        importer.import_packet(conn, [], packet=value["payload"], envelope=value["envelope"])
    assert not published and not cur.projections


def test_workstation_import_uses_attested_agent_without_server_hostname_lookup(monkeypatch):
    from tests.unit.test_workstation_file_audit import workstation_policy
    _, value, identity, assignment = packet()
    config = workstation_policy()
    assignment["config"] = config
    identity["assigned_modules"].append({"module_id": "sli.workstations", "enabled": True, "config": {}})
    sample = collector(config, reader=lambda *_: [(xml(1, SubjectUserSid="S-1-5-21-1-2-3-1004"), "b1")],
                       path_check=lambda *_: "file", account_check=lambda _: True).collect(now=NOW)
    value["payload"], value["envelope"]["cursor_after"] = sample.payload, sample.cursor_after
    conn, cur, published = dependencies(monkeypatch, identity)
    result = importer.import_packet(conn, [r["payload"] for r in sample.payload["records"]],
                                   packet=sample.payload, envelope=value["envelope"])
    assert result == {"observed": 1, "actions": 1}
    assert not any("from servers" in sql for sql in cur.calls)
    assert not published
    assert cur.projections[0]["observations"][0]["core_evidence_ref"] == f"agent-workstation-event:{AGENT}:{AGENT}:1"
    first = deepcopy(cur.projections[0])
    value["envelope"]["packet_id"] = "00000000-0000-4000-8000-000000000009"
    importer.import_packet(conn, [r["payload"] for r in sample.payload["records"]],
                           packet=sample.payload, envelope=value["envelope"])
    assert cur.projections[-1] == first


def test_source_kind_cannot_change_under_acknowledged_packet(monkeypatch):
    _, value, identity, assignment = packet()
    old = deepcopy(assignment)
    assignment["config"].update(policy_revision="3", source_kind="workstation")
    conn, cur, published = dependencies(monkeypatch, identity)
    original = cur.fetchone
    cur.fetchone = lambda: {"assignment": old} if "select assignment" in cur.calls[-1] else original()
    with pytest.raises(importer.PacketPending, match="source_binding_changed"):
        importer.import_packet(conn, [r["payload"] for r in value["payload"]["records"]],
                               packet=value["payload"], envelope=value["envelope"])
    assert not published and not cur.projections


def test_import_retains_module_revision_across_unrelated_control_revisions(monkeypatch):
    _, value, identity, assignment = packet()
    old = deepcopy(assignment)
    identity["assigned_modules"][0]["config"]["policy_revision"] = "3"
    conn, cur, published = dependencies(monkeypatch, identity)
    original = cur.fetchone
    cur.fetchone = lambda: {"assignment": old} if "select assignment" in cur.calls[-1] else original()
    result = importer.import_packet(conn, [r["payload"] for r in value["payload"]["records"]],
                                   packet=value["payload"], envelope=value["envelope"])
    assert result["observed"] == 1 and len(published) == 1
    assert any("coalesce(assignment->'config'->>'policy_revision','1')=%s" in sql for sql in cur.calls)


def test_admitted_packet_produces_mass_rule_with_inventory_and_native_evidence(monkeypatch):
    from tests.unit.test_file_audit_rules import snapshot
    _, value, identity, assignment = packet()
    assignment["config"]["mass_operation_files"] = 1
    conn, cur, _ = dependencies(monkeypatch, identity)
    inventory = snapshot(observed_at_utc="2025-12-31T23:00:00Z")
    inventory["objects"][0]["path"] = r"C:\synthetic\item"
    cur.rule_snapshots = [inventory]
    importer.import_packet(conn, [row["payload"] for row in value["payload"]["records"]],
                           packet=value["payload"], envelope=value["envelope"])
    assert len(cur.rules) == 1 and cur.rules[0]["rule_code"] == "file-audit.mass-write"
    assert cur.rules[0]["action_ids"] == [cur.projections[0]["actions"][0]["action_id"]]
    assert cur.rules[0]["snapshot_ids"] == [inventory["snapshot_id"]]


def test_published_packet_replay_keeps_original_correlation_without_core_republication(monkeypatch):
    _, value, identity, _ = packet()
    conn, cur, published = dependencies(monkeypatch, identity)
    cur.replay_counts = {"observed": 1, "actions": 1}
    cur.context = {"complete": False, "observations": []}
    result = importer.import_packet(conn, [r["payload"] for r in value["payload"]["records"]],
                                    packet=value["payload"], envelope=value["envelope"])
    assert result == {"observed": 1, "actions": 1}
    assert not published and not cur.projections and not cur.rules


def test_published_replay_still_rejects_changed_attested_rows(monkeypatch):
    _, value, identity, _ = packet()
    conn, cur, published = dependencies(monkeypatch, identity)
    cur.replay_counts = {"observed": 1, "actions": 1}
    rows = deepcopy([r["payload"] for r in value["payload"]["records"]])
    rows[0]["record_id"] += 1
    with pytest.raises(importer.PacketPending, match="agent_packet_attestation_invalid"):
        importer.import_packet(conn, rows, packet=value["payload"], envelope=value["envelope"])
    assert not published and not cur.projections


def test_published_replay_still_requires_an_active_configured_source(monkeypatch):
    _, value, identity, _ = packet()
    conn, cur, published = dependencies(monkeypatch, identity)
    cur.replay_counts = {"observed": 1, "actions": 1}
    cur.fetchall = lambda: []
    with pytest.raises(importer.PacketPending, match="file_audit_source_not_configured"):
        importer.import_packet(conn, [r["payload"] for r in value["payload"]["records"]],
                               packet=value["payload"], envelope=value["envelope"])
    assert not published and not cur.projections


def test_published_replay_rejects_incomplete_retained_observations(monkeypatch):
    _, value, identity, _ = packet()
    conn, cur, published = dependencies(monkeypatch, identity)
    cur.replay_counts = {"observed": 0, "actions": 1}
    with pytest.raises(importer.PacketPending, match="file_audit_replay_conflict"):
        importer.import_packet(conn, [r["payload"] for r in value["payload"]["records"]],
                               packet=value["payload"], envelope=value["envelope"])
    assert not published and not cur.projections

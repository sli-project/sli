"""Rule execution joins the admitted inbox/inventory transaction with cursor fakes."""
from copy import deepcopy
from datetime import timedelta
import json

import pytest

from server.sli.plugins.file_audit import rule_runtime
from sli_agent.envelope import timestamp
from tests.unit.test_file_audit_rules import AGENT, action, config, snapshot


class Cursor:
    def __init__(self, context=None):
        self.calls = []
        self.context = context or {"complete": True, "actions": [], "snapshots": []}

    def execute(self, sql, args):
        self.calls.append((sql, args))

    def fetchone(self):
        if "rule_context" in self.calls[-1][0]:
            return {"context": deepcopy(self.context)}
        return None


class WindowCursor(Cursor):
    """Model the inclusive SQL context bounds and immutable result publication."""

    def __init__(self, *, complete=True, snapshots=()):
        super().__init__()
        self.admitted = {}
        self.published = {}
        self.complete = complete
        self.snapshots = snapshots

    def execute(self, sql, args):
        super().execute(sql, args)
        if "publish_rules" in sql:
            for row in json.loads(args[-1]):
                previous = self.published.setdefault(row["result_id"], row)
                assert previous == row

    def fetchone(self):
        if "rule_context" in self.calls[-1][0]:
            agent, _, start, end = self.calls[-1][1]
            return {"context": {"complete": self.complete, "snapshots": deepcopy(self.snapshots), "actions": [
                deepcopy(row) for row in self.admitted.values()
                if row["agent_id"] == agent and row["source_instance_id"] == AGENT
                and start <= timestamp(row["observed_at"]) <= end]}}
        return None


def mass_packets(cfg, *, separation=300):
    early_at = timestamp(action()["observed_at"])
    late_at = early_at + timedelta(seconds=separation)
    # Each packet is below the unchanged threshold, even with native witnesses
    # that refer to the same file. Together they exceed it by one file.
    split = cfg["mass_operation_files"] // 2
    early = [action(i, observed_at=early_at.isoformat()) for i in range(1, split + 1)]
    late = [action(i, observed_at=late_at.isoformat())
            for i in range(split + 1, cfg["mass_operation_files"] + 2)]
    for index, rows in enumerate((early, late), cfg["mass_operation_files"] + 2):
        rows.append(action(index, observed_at=rows[0]["observed_at"], path=rows[0]["path"].upper()))
    return early, late


def deliver(cur, rows, cfg, packet):
    cur.admitted.update((row["action_id"], deepcopy(row)) for row in rows)
    return rule_runtime.evaluate_packet(cur, envelope={"agent_id": AGENT, "source_instance_id": AGENT,
        "packet_id": f"00000000-0000-4000-8000-{packet:012d}"}, actions=rows, config=cfg)


@pytest.mark.parametrize("threshold", [20, 100])
def test_reverse_arrival_preserves_mass_window_native_witnesses_and_replay(threshold):
    cfg = config()
    # Cover the documented configured threshold and the unchanged policy default.
    cfg["mass_operation_files"] = threshold
    assert cfg["mass_operation_seconds"] == 300
    early, late = mass_packets(cfg)
    expected = rule_runtime.activity_findings(early + late, config=cfg,
        agent_id=AGENT, source_instance_id=AGENT)
    assert len(expected) == 1
    assert expected[0]["details"]["distinct_files"] == threshold + 1
    assert expected[0]["action_ids"] == sorted(row["action_id"] for row in early + late)
    publications = []
    for packets in ((early, late), (late, early)):
        cur = WindowCursor()
        assert deliver(cur, packets[0], cfg, 4) == 0
        assert deliver(cur, packets[1], cfg, 5) == 1
        assert list(cur.published.values()) == expected
        for packet, rows in enumerate(packets, 4):
            deliver(cur, rows, cfg, packet)
        assert list(cur.published.values()) == expected
        assert all("commit" not in sql.lower() for sql, _ in cur.calls)
        for sql, args in cur.calls:
            if "rule_context" in sql:
                assert args[3] - args[2] == timedelta(seconds=600)
        publications.append(cur.published)
    assert publications[0] == publications[1]


@pytest.mark.parametrize("separation, count", [(300, 1), (300.000001, 0)])
@pytest.mark.parametrize("reverse", [False, True])
def test_packet_window_boundary_does_not_widen_mass_rule(separation, count, reverse):
    cfg = config()
    early, late = mass_packets(cfg, separation=separation)
    cur = WindowCursor()
    packets = (late, early) if reverse else (early, late)
    assert deliver(cur, packets[0], cfg, 4) == 0
    assert deliver(cur, packets[1], cfg, 5) == count
    assert len(cur.published) == count


@pytest.mark.parametrize("reason", ["truncated_actions", "truncated_snapshots", "continuity_gap", "pending_predecessor"])
@pytest.mark.parametrize("partial_native", [False, True])
def test_incomplete_reverse_context_does_not_complete_a_mass_window(reason, partial_native):
    cfg = config()
    early, late = mass_packets(cfg)
    # The SQL contract reports all these conditions as complete=False.
    inventory = snapshot(objects=[{"path": row["path"], "object_type": "file"} for row in early + late])
    cur = WindowCursor(complete=False, snapshots=[inventory])
    if partial_native:
        for row in early + late:
            row["correlation_state"] = "partial"
            row["object_type"] = "unknown"
    assert deliver(cur, late, cfg, 4) == 0
    assert deliver(cur, early, cfg, 5) == 0
    assert not cur.published, reason


@pytest.mark.parametrize("changes", [
    {"operation": "delete", "correlation_state": "ambiguous"},
    {"object_type": "unknown"}, {"collection_scope_id": "scope:other"},
    {"source_instance_id": "synthetic-other"}, {"agent_id": "00000000-0000-4000-8000-000000000002"},
    {"subject_sid": "S-1-5-21-1-2-3-1002"}, {"operation": "write"},
])
def test_reverse_context_does_not_combine_ineligible_or_unrelated_actions(changes):
    cfg = config()
    cfg["roots"].append({**cfg["roots"][0], "collection_scope_id": "scope:other", "path": r"C:\synthetic-other"})
    early, late = mass_packets(cfg)
    if changes.get("operation") == "delete":
        for row in early:
            row["operation"] = "delete"
    for row in late:
        row.update(changes)
        if changes.get("collection_scope_id") == "scope:other":
            row["path"] = row["path"].lower().replace(r"c:\synthetic", r"C:\synthetic-other", 1)
    cur = WindowCursor()
    assert deliver(cur, late, cfg, 4) == 0
    assert deliver(cur, early, cfg, 5) == 0
    assert not cur.published


def test_reverse_context_preserves_service_account_exclusion():
    cfg = config()
    early, late = mass_packets(cfg)
    cfg["service_account_exclusions"] = [early[0]["subject_sid"]]
    cur = WindowCursor()
    assert deliver(cur, late, cfg, 4) == 0
    assert deliver(cur, early, cfg, 5) == 0
    assert not cur.published


def test_forward_context_cannot_publish_unrelated_neighbor_result():
    cfg = config()
    early, late = mass_packets(cfg)
    cur = WindowCursor()
    cur.admitted.update((row["action_id"], row) for row in early + late)
    current = [action(1000, subject_sid="S-1-5-21-1-2-3-1002")]
    assert deliver(cur, current, cfg, 4) == 0
    assert not cur.published


def test_extended_context_preserves_two_day_query_limit():
    cfg = config()
    rows = [action(), action(2, observed_at="2026-01-07T05:00:00Z")]
    cur = WindowCursor()
    assert deliver(cur, rows, cfg, 4) == 0
    assert not cur.calls


def test_cross_packet_window_publishes_once_and_never_commits(monkeypatch):
    cfg = config()
    cfg["mass_operation_files"] = 2
    rows = [action(), action(2)]
    cur = Cursor({"complete": True, "actions": rows, "snapshots": []})
    monkeypatch.setattr(rule_runtime, "plugin_hook", lambda *_: None)
    count = rule_runtime.evaluate_packet(cur, envelope={"agent_id": AGENT, "source_instance_id": AGENT,
        "packet_id": "00000000-0000-4000-8000-000000000004"}, actions=[rows[-1]], config=cfg)
    assert count == 1
    payload = json.loads(cur.calls[-1][1][-1])
    assert payload[0]["action_ids"] == [row["action_id"] for row in rows]
    assert all("commit" not in sql for sql, _ in cur.calls)


def test_context_overflow_never_publishes_truncated_mass_or_guessed_calendar(monkeypatch):
    cfg = config()
    cfg["mass_operation_files"] = 2
    cur = Cursor({"complete": False, "actions": [action(), action(2)], "snapshots": []})
    monkeypatch.setattr(rule_runtime, "plugin_hook", lambda *_: None)
    assert rule_runtime.evaluate_packet(cur, envelope={"agent_id": AGENT, "source_instance_id": AGENT,
        "packet_id": "00000000-0000-4000-8000-000000000004"}, actions=[action(2)], config=cfg) == 0
    assert not any("publish_rules" in sql for sql, _ in cur.calls)


def test_inventory_uses_optional_ad_contract_and_preserves_agent_binding(monkeypatch):
    cur = Cursor()
    snap = snapshot()
    snap["objects"][0]["dacl"] = "D:(A;;FW;;;WD)"
    snap["share"]["dacl"] = "D:(A;;FR;;;WD)"
    monkeypatch.setattr(rule_runtime, "plugin_hook", lambda *_: None)
    count = rule_runtime.evaluate_snapshots(cur, agent_id=AGENT, source_instance_id=AGENT,
        command_id="synthetic-check", config=config(), snapshots=[snap], domain_id=1)
    assert count == 1
    row = json.loads(cur.calls[-1][1][-1])[0]
    assert row["agent_id"] == AGENT and row["source_instance_id"] == AGENT
    assert row["snapshot_ids"] == [snap["snapshot_id"]]

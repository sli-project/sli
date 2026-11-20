"""The managed Sigma caller matches native XML and persists exact inputs."""
from dataclasses import asdict

import pytest

from server.sli.semantic.qw_input import _digest
from server.sli.sigma import live_runtime as live
from server.sli.sigma.compiler import IRValue
from tests.unit.test_finding_evidence_refs import reference
from tests.unit.test_sigma_matcher import compare, plan
from tests.unit.test_sigma_windows_mapping import event_xml


class Cursor:
    def __init__(self, pin, *, enabled=True):
        self.pin, self.enabled = pin, enabled
        self.after = 0
        self.rows = []
        self.calls = []
    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "read_admitted_sigma_revision" in sql:
            revision = {"execution": self.pin, "raw_yaml": "fixture", "source_uri": "", "upstream_commit": "b" * 40,
                        "license": "DRL-1.1"}
            self.rows = [{"revision": revision if self.enabled else None}]
        elif "select last_event_id" in sql:
            self.rows = [{"last_event_id": self.after}]
        elif "read_admitted_sigma_events" in sql:
            self.rows = [{"source_event_id": 42, "sha256": "b" * 64,
                          "source_xml": event_xml()}] if self.after < 42 else []
        elif "update semantic_sigma_live_cursors" in sql:
            self.after = params[0]
    def fetchone(self):
        return self.rows[0]
    def fetchall(self):
        return self.rows


def setup(monkeypatch, *, event_id=4624, **overrides):
    rule = plan(compare(IRValue("number", event_id), "EventID"))
    pin = {"version": "sli.sigma.execution.v1", "rule_id": rule.rule_id, "rule_sha256": rule.source_sha256,
           "manifest_sha256": "2" * 64, "compiler_version": rule.compiler_version,
           "mapping_version": rule.mapping_version, "overlay_sha256": _digest({}),
           "scope": asdict(reference().scope)} | overrides
    monkeypatch.setattr(live, "compile_rule", lambda *a, **kw: rule)
    return Cursor(pin), rule


def test_match_calls_durable_adapter_once_and_advances_replay_cursor(monkeypatch):
    cur, rule = setup(monkeypatch)
    matches = []
    monkeypatch.setattr(live, "enqueue_detection_match_risk_jobs", lambda cur, *, match: matches.append(match) or ("job",))
    assert live.evaluate_revision(cur, policy_id="fixture", version=1) == 1
    assert live.evaluate_revision(cur, policy_id="fixture", version=1) == 0
    item, = matches
    assert item.rule_id == rule.rule_id and item.evidence == reference()
    assert item.execution == cur.pin and cur.after == 42


def test_disabled_or_nonmatching_rule_creates_no_match(monkeypatch):
    cur, _ = setup(monkeypatch, event_id=4625)
    monkeypatch.setattr(live, "enqueue_detection_match_risk_jobs", lambda *a, **kw: pytest.fail("unexpected match"))
    assert live.evaluate_revision(cur, policy_id="fixture", version=1) == 0
    assert cur.after == 42
    cur.enabled = False
    cur.calls.clear()
    assert live.evaluate_revision(cur, policy_id="fixture", version=1) == 0
    assert len(cur.calls) == 1


@pytest.mark.parametrize("field,value", [("rule_sha256", "f" * 64), ("overlay_sha256", "f" * 64),
                                         ("compiler_version", "unknown")])
def test_changed_pin_never_advances_or_falls_back_to_unmodified_rule(monkeypatch, field, value):
    cur, _ = setup(monkeypatch, **{field: value})
    with pytest.raises(RuntimeError):
        live.evaluate_revision(cur, policy_id="fixture", version=1)
    assert cur.after == 0

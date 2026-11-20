"""N08 source-time windows, durable replay and QW publication, all simulated."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json

import pytest

from server.sli.semantic import nps_threshold as nps, nps_threshold_runtime as worker, qw_input as qw
from server.sli.semantic.semantic_risk_policy import compile_risk_policy
from tests.unit.test_qw_publication import Cursor as PublicationCursor, evaluate as publish
from tests.unit.test_finding_evidence_refs import reference
from tests.unit.test_detection_match_risk import NOW


def rule(**changes):
    return nps.ThresholdRule(scope=replace(reference().scope, plugin_id="sli.vpn-nps"), **changes)


def events(count, *, previous=0, selected=None, group="synthetic-entity", **changes):
    selected = selected or rule()
    ref = replace(reference(), scope=selected.scope)
    return [nps.Denial(NOW - timedelta(seconds=10 + i), replace(ref, native_id=str(i + 1)), group)
            for i in range(count)] + [
        nps.Denial(NOW - timedelta(seconds=310 + i), replace(ref, native_id=str(1000 + i)), group)
        for i in range(previous)]


def evaluate(items, *, selected=None, **changes):
    return nps.evaluate(selected or rule(), items, end=NOW, now=NOW,
                        current_quality=changes.pop("current_quality", "good"),
                        previous_quality=changes.pop("previous_quality", "good"), **changes)


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    from server.sli.core import database, postgres_runtime_pipeline
    from server.sli.semantic import semantic_risk_runtime_repository as runtime
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected database connection")
    monkeypatch.setattr(database, "query_rows", forbidden)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", forbidden)
    monkeypatch.setattr(runtime, "record_scenario_identity_supersessions", lambda *a, **kw: None)
    monkeypatch.setattr(runtime, "record_finding_identity_supersessions", lambda *a, **kw: None)


@pytest.mark.parametrize("count,previous,severity,comparison", [
    (19, 0, None, None), (20, 0, "medium", "new_activity"),
    (20, 7, "medium", "threshold"), (20, 6, "high", "surge"),
    (60, 20, "high", "surge"), (59, 20, "medium", "threshold"),
])
def test_boundary_surge_and_zero_previous(count, previous, severity, comparison):
    state, signals = evaluate(events(count, previous=previous))
    assert state["rows"][0]["severity"] == severity
    assert state["rows"][0]["comparison"] == comparison
    assert len(signals) == int(count >= 20)
    if signals:
        assert signals[0].effective_severity == severity
        assert signals[0].threshold_context["count"] == count
        assert signals[0].threshold_context["previous_count"] == previous


@pytest.mark.parametrize("quality", ["partial", "stale", "not_collected", "truncated"])
@pytest.mark.parametrize("which", ["current_quality", "previous_quality"])
def test_incomplete_comparison_never_promotes_to_high(quality, which):
    state, (signal,) = evaluate(events(20, previous=1), **{which: quality})
    assert signal.effective_severity == "medium" and signal.quality == "degraded"
    assert state["rows"][0][which] == quality


def test_no_collection_is_not_proven_and_no_negative_conclusion():
    state, signals = evaluate([], current_quality="not_collected")
    assert state["state"] == "not_proven" and not signals
    state, signals = evaluate(events(19), current_quality="partial")
    assert state["rows"][0]["state"] == "not_proven" and not signals


def test_source_time_half_open_boundaries_duplicates_and_late_overlap():
    data = events(19)
    ref = data[0].evidence
    boundary = nps.Denial(NOW - timedelta(seconds=300), replace(ref, native_id="20"), data[0].group_value)
    future = nps.Denial(NOW, replace(ref, native_id="21"), data[0].group_value)
    older = nps.Denial(NOW - timedelta(seconds=601), replace(ref, native_id="22"), data[0].group_value)
    _, signals = evaluate(data + data + [future, older])
    assert not signals
    state, (signal,) = evaluate(data + [boundary, future, older])
    assert len(signal.evidence_refs) == state["rows"][0]["count"] == 20
    replay, signals = evaluate(list(reversed(data + [boundary])) * 2, checkpoint=json.loads(json.dumps(state)))
    assert not signals and replay["episodes"] == state["episodes"]
    with pytest.raises(ValueError, match="event_conflict"):
        evaluate(data + [replace(data[0], occurred_at_utc=NOW)])


def test_unknown_identity_is_separate_and_nas_is_never_client_ip():
    state, signals = evaluate(events(20, group=None) + [replace(e, evidence=replace(e.evidence,
        native_id=str(int(e.evidence.native_id) + 100))) for e in events(19)])
    assert len(signals) == 1 and signals[0].threshold_context["identity_state"] == "unknown"
    assert len(state["rows"]) == 2
    selected = rule(dimension="client_ip")
    state, signals = evaluate(events(20, selected=selected, group=None), selected=selected)
    assert not signals and not state["rows"]


def test_source_generation_policy_and_dimension_isolation():
    selected = rule()
    data = events(20, selected=selected)
    state, (signal,) = evaluate(data, selected=selected)
    for changed in (replace(selected, policy_revision=2), replace(selected, dimension="nas_identifier"),
                    replace(selected, scope=replace(selected.scope, source_instance_id="synthetic-other")),
                    replace(selected, scope=replace(selected.scope, source_generation="generation-2"))):
        changed_data = [replace(e, evidence=replace(e.evidence, scope=changed.scope)) for e in data]
        _, (other,) = evaluate(changed_data, selected=changed)
        assert changed.checkpoint_key != selected.checkpoint_key
        assert other.episode_key != signal.episode_key
    with pytest.raises(ValueError, match="scope_mismatch"):
        evaluate(data, selected=replace(selected, scope=replace(selected.scope, source_instance_id="synthetic-other")))
    assert "synthetic-entity" not in json.dumps(state)


def test_episode_persists_through_gaps_and_new_episode_requires_full_quiet_window():
    state, (first,) = evaluate(events(20))
    gap, signals = nps.evaluate(rule(), [], end=NOW + timedelta(minutes=8), now=NOW + timedelta(minutes=8),
        checkpoint=state, current_quality="partial", previous_quality="partial")
    assert gap["episodes"] and not signals
    quiet, _ = nps.evaluate(rule(), [], end=NOW + timedelta(minutes=9), now=NOW + timedelta(minutes=9),
        checkpoint=gap, current_quality="good", previous_quality="partial")
    assert not quiet["episodes"]
    later = [replace(e, occurred_at_utc=e.occurred_at_utc + timedelta(minutes=10),
                     evidence=replace(e.evidence, native_id=str(200 + int(e.evidence.native_id)))) for e in events(20)]
    _, (second,) = nps.evaluate(rule(), later, end=NOW + timedelta(minutes=10), now=NOW + timedelta(minutes=10),
        checkpoint=quiet, current_quality="good", previous_quality="good")
    assert first.episode_key != second.episode_key


def test_257_members_use_bounded_portions_and_one_episode():
    _, signals = evaluate(events(257))
    assert [len(item.evidence_refs) for item in signals] == [256, 1]
    assert {item.evidence_total for item in signals} == {257}
    assert len({item.episode_key for item in signals}) == 1


def test_stale_end_and_watermark_regression():
    state, signals = nps.evaluate(rule(), events(20, previous=1), end=NOW, now=NOW + timedelta(minutes=10),
        current_quality="good", previous_quality="good")
    assert signals[0].quality == "degraded" and signals[0].effective_severity == "medium"
    with pytest.raises(ValueError, match="watermark_regression"):
        nps.evaluate(rule(), [], end=NOW - timedelta(seconds=1), now=NOW, checkpoint=state)


class Cursor(PublicationCursor):
    def __init__(self, item, selected):
        super().__init__(item)
        self.policies = [(nps.risk_policy(selected, policy_id="fixture-qw"), selected.evaluation_mode)]
        self.checkpoint = {}

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if "insert into semantic_nps_threshold_state" in normalized:
            self.calls.append((normalized, params))
        elif "select checkpoint_json" in normalized:
            self.rows = [{"checkpoint_json": deepcopy(self.checkpoint)}]
        elif "update semantic_nps_threshold_state" in normalized:
            self.checkpoint = json.loads(params[0])
        elif "update semantic_security_scenarios set explanation=" in normalized:
            self.scenarios[params[1]]["explanation"] = params[0]
        else:
            super().execute(sql, params)


@pytest.mark.parametrize("previous,quality,severity", [(0, "good", "medium"), (1, "good", "high"), (1, "partial", "medium")])
def test_nps_signal_uses_admitted_risk_policy_and_existing_queue_bridge(previous, quality, severity):
    selected = rule(evaluation_mode="enabled")
    state, (item,) = evaluate(events(20, previous=previous, selected=selected), selected=selected, previous_quality=quality)
    cur = Cursor(item, selected)
    result = publish(cur, item)
    assert result.finding_created and result.risk_class.value == severity
    inserted = next(params for sql, params in cur.calls if "insert into findings(" in sql)
    assert inserted[3] == severity and len(cur.outbox) == 1
    proposal = qw.qw_signal_proposal(cur, policy=compile_risk_policy(cur.policies[0][0]), source_id=item.signal_id)
    assert "20 unique denials" in proposal.explanation and "policy revision 1" in proposal.explanation
    assert quality in proposal.explanation and "synthetic-entity" not in proposal.explanation
    assert not publish(cur, item).finding_created


def test_worker_restart_replay_and_missing_policy_do_not_consume_threshold(monkeypatch):
    selected = rule(evaluation_mode="enabled")
    data = events(20, selected=selected)
    _, (item,) = evaluate(data, selected=selected)
    cur = Cursor(item, selected)
    cur.allowed.update(e.evidence.params for e in data)
    reader = lambda *a, **kw: (data + data, "partial", "partial")
    assert worker.run_once(cur, rule=selected, now=NOW, reader=reader)["jobs"] == 1
    previous_state = deepcopy(cur.checkpoint)
    assert worker.run_once(cur, rule=selected, now=NOW + timedelta(seconds=1), reader=reader)["jobs"] == 0
    assert len(cur.signals) == len(cur.jobs) == 1
    cur.checkpoint, cur.policies = {}, []
    with pytest.raises(RuntimeError, match="policy_unavailable"):
        worker.run_once(cur, rule=selected, now=NOW, reader=reader)
    assert not cur.checkpoint
    assert previous_state["watermark"] == NOW.isoformat()


def test_first_nps_source_watermark_replaces_absent_source_diagnostic_clock():
    selected = rule(evaluation_mode="enabled")
    data = events(20, selected=selected)
    _, (item,) = evaluate(data, selected=selected)
    cur = Cursor(item, selected)
    cur.allowed.update(e.evidence.params for e in data)
    worker.run_once(cur, rule=selected, now=NOW,
        reader=lambda *a, **kw: ([], "not_collected", "not_collected", NOW))
    assert cur.checkpoint["state"] == "not_proven"
    assert worker.run_once(cur, rule=selected, now=NOW,
        reader=lambda *a, **kw: (data, "partial", "partial", NOW - timedelta(seconds=1)))["jobs"] == 1


@pytest.mark.parametrize("change", [
    {"current_quality": "partial"}, {"previous_count": 0}, {"count": 19},
    {"dimension": "nas_ip"}, {"surge_factor": 0}, {"count": True}, {"private": "synthetic-private"},
])
def test_invalid_or_private_context_is_rejected(change):
    _, (item,) = evaluate(events(20, previous=1))
    with pytest.raises(ValueError):
        replace(item, threshold_context=item.threshold_context | change)


def test_legacy_context_free_qw_ids_and_nps_core_type():
    from tests.unit.test_qw_semantic_input import signal
    assert "threshold_context" not in signal().document
    assert replace(reference(), scope=rule().scope).storage_kind == "core_event"


def test_empty_reader_quality_and_no_raw_values_in_diagnostics():
    class ReaderCursor:
        def execute(self, sql, params=()):
            self.observed = "source_observed" in sql
        def fetchall(self):
            return []
        def fetchone(self):
            return {"quality": "not_collected"}
    assert worker.read_denials(ReaderCursor(), rule(), end=NOW) == ([], "not_collected", "not_collected", NOW)


@pytest.mark.parametrize("observed,expected", [("192.0.2.7", "192.0.2.7"), ("2001:db8::7", "2001:db8::7"),
                                                ("00-11-22-33-44-55", None), (None, None)])
def test_reader_client_ip_uses_only_observed_calling_station_ip(observed, expected):
    selected = rule(dimension="client_ip")
    class ReaderCursor:
        def execute(self, sql, params=()):
            pass
        def fetchall(self):
            return [{"source_event_id": 1, "sha256": "b" * 64, "occurred_at_utc": NOW,
                     "facts_json": {"nas_identifier": "synthetic-gateway", "ClientIPAddress": "192.0.2.99"},
                     "roles_json": {"source_ip": observed}, "quality_json": {}}]
        def fetchone(self):
            return {"quality": "partial"}
    items, current, previous, watermark = worker.read_denials(ReaderCursor(), selected, end=NOW)
    assert items[0].group_value == expected and current == previous == "partial"


def test_worker_cli_redacts_rule_and_connection_errors(monkeypatch, capsys, tmp_path):
    from scripts.runtime import nps_threshold_worker as cli

    path = tmp_path / "synthetic-rule.json"
    path.write_text('{"private":"synthetic-private"}', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["nps_threshold_worker", "--rule-file", str(path)])
    assert cli.main() == 1
    assert capsys.readouterr().out == '{"state": "failed", "code": "nps_threshold_unavailable"}\n'

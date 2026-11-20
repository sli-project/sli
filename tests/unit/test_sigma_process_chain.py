"""Stage 16: exact Sigma/native process chain using only cursors and archives."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from server.sli.sigma.detection_input import DetectionMatch
from server.sli.sigma.process_chain import (
    MAX_CONTEXT, MAX_MATCHES, ProcessChainRule, evaluate_process_chain,
)
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceRefError, EvidenceScope

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)
SCOPE = EvidenceScope("00000000-0000-0000-0000-000000000001",
                      "sli.windows.ad-dc", "fixture-source", "fixture-generation")


def source(source_id, event_id, seconds, *, pid=64, host=11, domain=7, record=None):
    data = {}
    if event_id in (4688, 4689):
        data = {
            "NewProcessId" if event_id == 4688 else "ProcessId": hex(pid),
            "NewProcessName" if event_id == 4688 else "ProcessName": "C:\\fixture.exe",
            "SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectLogonId": "0x123",
        }
    return {
        "id": source_id, "event_id": event_id, "server_id": host, "domain_id": domain,
        "log_source_id": 1, "time_created_utc": (NOW + timedelta(seconds=seconds)).isoformat(),
        "migrated_at": NOW.isoformat(), "normalized_hash": f"{source_id:064x}",
        "event_record_id": source_id if record is None else record,
        "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
        "computer": "fixture-host", "event_data_json": data,
    }


def reference(row, *, scope=SCOPE):
    return EvidenceRef("core_event", str(row["id"]), row["normalized_hash"], scope)


def detection(row, *, mode="test", **changes):
    return replace(DetectionMatch(
        rule_id="00000000-0000-0000-0000-000000000016",
        rule_sha256="1" * 64, manifest_sha256="2" * 64,
        compiler_version="fixture-v1", mapping_version="fixture-v1", overlay_sha256="3" * 64,
        evidence=reference(row), entity_key="4" * 64,
        occurred_at_utc=datetime.fromisoformat(row["time_created_utc"]), evaluation_mode=mode,
    ), **changes)


class Cursor:
    def __init__(self, rows, matches):
        self.sources = {row["id"]: row for row in rows}
        self.matches = {item.match_id: item for item in matches}
        self.allowed = {reference(row).params for row in rows}
        self.calls = []
        self.rows = []
        self.plugin_states = {
            plugin_id: {"plugin_id": plugin_id, "package_version": "1.0.0", "installed": True,
                        "configured": True, "enabled": True, "component_runtime": "running"}
            for plugin_id in ("sli.ad", "sli.sigma")
        }

    def execute(self, sql, params=()):
        sql = " ".join(sql.lower().split())
        self.calls.append((sql, params))
        assert sql.startswith("select "), "chain must not write findings, risk or native evidence"
        if "public.read_sigma_chain_plugin_states_v1()" in sql:
            self.rows = list(self.plugin_states.values())
        elif "public.resolve_finding_evidence_ref(" in sql:
            self.rows = [{"verified": params in self.allowed}]
        elif "from semantic_detection_matches where match_id=" in sql:
            item = self.matches.get(params[0])
            self.rows = [] if item is None else [{
                "rule_id": item.rule_id, "evaluation_mode": item.evaluation_mode,
                "occurred_at_utc": item.occurred_at_utc, "evidence_key": item.evidence_key,
                "document_json": deepcopy(item.document),
            }]
        elif "from events_v2_core core" in sql:
            self.rows = [self.sources[params[0]]] if params[0] in self.sources else []
        else:
            raise AssertionError("unexpected query")

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class Archive:
    def __init__(self, rows):
        self.rows = {row["id"]: deepcopy(row) for row in rows}
        self.calls = []

    def read_event(self, *, archive_kind, event_id):
        assert archive_kind == "event"
        self.calls.append(event_id)
        return deepcopy(self.rows[event_id])


def fixture(*, mode="test"):
    rows = (source(1, 4608, 0), source(2, 4688, 10), source(3, 4689, 20))
    return rows, detection(rows[1], mode=mode)


def evaluate(rows, matches, *, rule=None, refs=None, watermark=NOW, cursor=None, archive=None):
    return evaluate_process_chain(
        cursor or Cursor(rows, matches),
        rule=rule or ProcessChainRule(execution_sha256=matches[0].execution_sha256,
                                      scope=SCOPE, evaluation_mode=matches[0].evaluation_mode),
        match_ids=tuple(item.match_id for item in matches),
        source_refs=refs if refs is not None else tuple(reference(row) for row in rows),
        archive=archive or Archive(rows), watermark=watermark,
    )


@pytest.mark.parametrize("mode", ["test", "shadow", "enabled"])
def test_reversed_delivery_and_replay_preserve_exact_native_evidence_without_writes(mode):
    rows, item = fixture(mode=mode)
    cur = Cursor(rows, (item,))
    first = evaluate(rows, (item,), cursor=cur)
    replay = evaluate(tuple(reversed(rows)), (item, item), cursor=cur)
    assert first == replay
    assert first.unmatched_match_ids == first.late_match_ids == ()
    result, = first.results
    assert result.match_ids == (item.match_id,)
    assert result.evaluation_mode == mode and json.loads(result.execution_json) == item.execution
    assert result.source_host_id == "11" and result.domain_id == "7" and result.process_id == 64
    assert result.boot_event_id == 1
    assert result.evidence_refs == tuple(reference(row) for row in rows)
    assert result.evidence_count == 3  # Boot, start, end; Sigma adds no new source event.
    assert result.started_at_utc == NOW + timedelta(seconds=10)
    assert result.ended_at_utc == NOW + timedelta(seconds=20)
    assert len(result.result_id) == 64
    assert all(sql.startswith("select ") for sql, _ in cur.calls)


def test_missing_terminal_stays_unmatched_and_late_terminal_completes_same_episode():
    rows, item = fixture()
    incomplete = evaluate(rows[:2], (item,))
    assert incomplete.results == () and incomplete.unmatched_match_ids == (item.match_id,)
    on_time = evaluate(rows, (item,))
    late = evaluate(rows, (item,), watermark=NOW + timedelta(minutes=30))
    assert late == on_time


def test_event_time_lateness_boundary_is_inclusive_and_excess_is_explicit():
    rows, item = fixture()
    boundary = NOW + timedelta(seconds=3620)
    assert len(evaluate(rows, (item,), watermark=boundary).results) == 1
    expired = evaluate(rows, (item,), watermark=boundary + timedelta(microseconds=1))
    assert expired.results == expired.unmatched_match_ids == ()
    assert expired.late_match_ids == (item.match_id,)


@pytest.mark.parametrize("changed", ["host", "domain", "pid", "boot", "reused_pid", "duplicate_record", "second_end"])
def test_key_collisions_and_ambiguous_terminal_cannot_complete_old_anchor(changed):
    rows, item = fixture()
    boot, start, end = rows
    if changed in ("host", "domain", "pid"):
        end = source(3, 4689, 20, **{changed: 99})
        rows = (boot, start, end)
    elif changed == "boot":
        rows = (boot, start, source(3, 4608, 15), source(4, 4689, 20))
    elif changed == "reused_pid":
        rows = (boot, start, source(3, 4688, 15), source(4, 4689, 20))
    elif changed == "duplicate_record":
        rows = (boot, start, end, source(4, 4688, 10, record=2))
    else:
        rows = (*rows, source(4, 4689, 21))
    result = evaluate(rows, (item,))
    assert result.results == () and result.unmatched_match_ids == (item.match_id,)


@pytest.mark.parametrize("seconds", [9, 3611])
def test_reversed_or_out_of_window_native_end_does_not_complete(seconds):
    rows, item = fixture()
    rows = (*rows[:2], source(3, 4689, seconds))
    assert evaluate(rows, (item,)).results == ()


def test_exact_window_boundary_completes():
    rows, item = fixture()
    rows = (*rows[:2], source(3, 4689, 3610))
    assert len(evaluate(rows, (item,)).results) == 1


def test_bounded_fanout_links_each_match_only_to_its_exact_process():
    rows = [source(1, 4608, 0)]
    matches = []
    for index in range(40):
        start_id = 2 + index * 2
        start = source(start_id, 4688, 10, pid=100 + index)
        rows.extend((start, source(start_id + 1, 4689, 20, pid=100 + index)))
        matches.append(detection(start))
    result = evaluate(tuple(reversed(rows)), tuple(reversed(matches)))
    assert len(result.results) == 40
    assert result.unmatched_match_ids == ()
    assert len({row.result_id for row in result.results}) == 40
    assert sum(row.evidence_count for row in result.results) == 120
    for row in result.results:
        anchor = next(item for item in matches if item.match_id == row.match_ids[0])
        assert row.evidence_refs[1] == anchor.evidence
        assert int(row.evidence_refs[2].native_id) == int(anchor.evidence.native_id) + 1


@pytest.mark.parametrize("overflow", ["context", "matches"])
def test_fanout_overflow_rejects_entire_slice_before_io(overflow):
    rows, item = fixture()
    cur, archive = Cursor(rows, (item,)), Archive(rows)
    rule = ProcessChainRule(execution_sha256=item.execution_sha256, scope=SCOPE, evaluation_mode="test")
    with pytest.raises(ValueError, match="sigma_process_chain_request_invalid"):
        evaluate_process_chain(cur, rule=rule,
                               match_ids=(item.match_id,) * (MAX_MATCHES + 1 if overflow == "matches" else 1),
                               source_refs=(reference(rows[0]),) * (MAX_CONTEXT + 1 if overflow == "context" else 1),
                               archive=archive, watermark=NOW)
    assert cur.calls == archive.calls == []


@pytest.mark.parametrize("change", ["execution", "mode", "source", "generation", "installation"])
def test_foreign_execution_or_scope_cannot_join(change):
    rows, item = fixture()
    rule = ProcessChainRule(execution_sha256=item.execution_sha256, scope=SCOPE, evaluation_mode="test")
    if change == "execution":
        item = replace(item, mapping_version="fixture-v2")
    elif change == "mode":
        item = replace(item, evaluation_mode="shadow")
    else:
        field, value = {"source": ("source_instance_id", "other-source"),
                        "generation": ("source_generation", "other-generation"),
                        "installation": ("installation_id", "00000000-0000-0000-0000-000000000002")}[change]
        item = replace(item, evidence=replace(item.evidence, scope=replace(SCOPE, **{field: value})))
    with pytest.raises(RuntimeError, match="sigma_process_chain_execution_mismatch"):
        evaluate(rows, (item,), rule=rule)


def test_foreign_context_rejected_before_read():
    rows, item = fixture()
    refs = tuple(reference(row) for row in rows)
    refs = (*refs[:2], replace(refs[2], scope=replace(SCOPE, source_generation="other-generation")))
    with pytest.raises(ValueError, match="sigma_process_chain_request_invalid"):
        evaluate(rows, (item,), refs=refs)


@pytest.mark.parametrize("change", ["denied", "hash", "archive", "expired", "anchor_time", "anchor_type"])
def test_unavailable_or_conflicting_evidence_fails_closed(change):
    rows, item = fixture()
    cur, archive = Cursor(rows, (item,)), Archive(rows)
    if change == "denied":
        cur.allowed.clear()
    elif change == "hash":
        cur.sources[3] = {**rows[2], "normalized_hash": "f" * 64}
    elif change == "archive":
        archive.rows[3]["server_id"] = 99
    elif change == "expired":
        archive.rows.pop(3)
    elif change == "anchor_time":
        item = replace(item, occurred_at_utc=NOW)
        cur.matches = {item.match_id: item}
    else:
        item = detection(rows[2])
        cur.matches = {item.match_id: item}
    with pytest.raises((RuntimeError, EvidenceRefError), match=(
        "evidence_unavailable_or_denied|sigma_process_chain_source_unavailable|sigma_process_chain_anchor_mismatch"
    )):
        evaluate(rows, (item,), cursor=cur, archive=archive)


def test_two_entity_claims_for_same_source_fail_closed_instead_of_duplicate_output():
    rows, item = fixture()
    other = replace(item, entity_key="5" * 64)
    with pytest.raises(RuntimeError, match="sigma_process_chain_identity_conflict"):
        evaluate(rows, (item, other))


def test_definition_pins_time_budget_native_versions_and_mode():
    _, item = fixture()
    rule = ProcessChainRule(execution_sha256=item.execution_sha256, scope=SCOPE, evaluation_mode="test")
    assert rule.definition_sha256 != replace(rule, window_seconds=60).definition_sha256
    assert rule.definition_sha256 != replace(rule, evaluation_mode="shadow").definition_sha256
    assert rule.definition_sha256 != replace(rule, allowed_lateness_seconds=0).definition_sha256


@pytest.mark.parametrize("changes", [
    {"window_seconds": 0}, {"window_seconds": 86401}, {"window_seconds": True},
    {"allowed_lateness_seconds": -1}, {"allowed_lateness_seconds": 86401},
    {"execution_sha256": ""}, {"evaluation_mode": "draft"},
])
def test_invalid_rule_is_rejected(changes):
    with pytest.raises(ValueError, match="sigma_process_chain_rule_invalid"):
        ProcessChainRule(**({"execution_sha256": "a" * 64, "scope": SCOPE, "evaluation_mode": "test"} | changes))

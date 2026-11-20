from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import MappingProxyType

import pytest

from server.sli.sigma import history_job as job
from server.sli.sigma.compiler import CompiledRule, IRExpression, IRValue, PatternPart
from server.sli.sigma.windows_mapping import (
    AUDIT_PROVIDER,
    MAPPING_VERSION,
    EventIdentity,
    EventScope,
    MappedWindowsEvent,
)

START = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCOPE = EventScope("fixture-installation", "fixture-source", "fixture-generation")


def rule(number=1, *, logsource="security", field="EventID", value=9):
    predicate = IRValue("number", value) if isinstance(value, int) else IRValue(
        "pattern", parts=(PatternPart("literal", value),))
    return CompiledRule(f"00000000-0000-0000-0000-{number:012d}", "a" * 64, logsource,
                        IRExpression("compare", field=field, value=predicate), (field,),
                        "Fixture Team", "DRL-1.1", "", "b" * 40)


def request(*, watermark=3, rules=None, partitions=None):
    part = job.HistoryPartition(SCOPE, "core_event", START, START + timedelta(days=1), "fixture-snapshot", watermark)
    return job.HistoryRequest("fixture-job", rules or (rule(),), partitions or (part,), "c" * 64)


def record(position, *, value=9, missing=False, quality=(), ref=None, scope=SCOPE, stamp=None):
    stamp = stamp or START + timedelta(seconds=position)
    identity = EventIdentity(scope, "Security", AUDIT_PROVIDER, None, value, 0,
                             position, "fixture.example.invalid", stamp.isoformat(), "d" * 64)
    event = MappedWindowsEvent(MAPPING_VERSION, identity,
                               MappingProxyType({"EventID": value}), MappingProxyType({}))
    return job.HistoryRecord(position, ref or job.HistoryEvidenceRef("core_event", str(position), "d" * 64),
                             scope, stamp, None if missing else event, quality)


class Reader:
    """Only a bounded read port; intentionally no database/write interface."""

    def __init__(self, records=(), *, fail_after=None, error=None):
        self.records = records
        self.calls = []
        self.fail_after = fail_after
        self.error = error or RuntimeError("synthetic-private-diagnostic")

    def read_one(self, partition, *, after, max_bytes, timeout_seconds):
        self.calls.append((partition, after, max_bytes, timeout_seconds))
        if self.fail_after is not None and after >= self.fail_after:
            raise self.error
        return next((row for row in self.records if after < row.position <= partition.high_watermark), None)


def run(req=None, reader=None, **kwargs):
    return job.run_history_job(req or request(), reader or Reader(), authorized=lambda part: True, **kwargs)


def test_completed_manifest_counts_quality_and_separate_export(tmp_path):
    req = request(watermark=5)
    reader = Reader([record(1), record(2, value=8), record(3, missing=True),
                     record(4, quality=("audit_disabled",)), record(5, quality=("payload_expired",))])
    checkpoints = []
    result = run(req, reader, save_checkpoint=checkpoints.append)
    assert (result.status, result.reason, result.mode) == ("completed", "snapshot_exhausted", "test")
    assert result.checkpoint.partition_index == 1
    assert result.checkpoint.rows_read == 5
    row, = result.checkpoint.counts
    assert (row.scanned, row.evaluable, row.matched, row.unknown, row.suppressed, row.skipped) == (5, 2, 1, 3, 0, 0)
    assert dict(row.reasons) == {"audit_disabled": 1, "payload_expired": 1, "payload_unavailable": 1}
    assert len(result.checkpoint.samples) == 1
    assert result.checkpoint.samples[0].ref == reader.records[0].ref
    manifest = result.manifest()
    assert manifest["checkpoint"]["counts"][0]["matches_per_1000_evaluable"] == 500
    assert manifest["checkpoint"]["counts"][0]["evaluable_percent"] == 40
    assert manifest["rules"][0]["plan_sha256"] == req.rules[0].plan_sha256
    assert manifest["partitions"][0]["start"] == START.isoformat()
    path = job.write_history_result(result, tmp_path / "evaluation")
    assert json.loads(path.read_text()) == json.loads(json.dumps(manifest))
    assert not path.with_name("result.pending").exists()
    with pytest.raises(FileExistsError):
        job.write_history_result(result, path.parent)
    text = path.read_text()
    assert "fixture.example.invalid" not in text
    assert "fixture-source" not in text
    assert "fixture-snapshot" not in text
    assert '"fields"' not in text
    assert checkpoints[-1] == result.checkpoint


def test_partial_resumes_without_double_counting_and_matches_single_run():
    req = request()
    reader = Reader([record(1), record(2), record(3)])
    partial = run(req, reader, budget=job.HistoryBudget(max_rows=1))
    assert (partial.status, partial.reason, partial.checkpoint.after) == ("partial", "row_budget", 1)
    result = run(req, reader, checkpoint=partial.checkpoint)
    expected = run(req, Reader(reader.records))
    assert result == expected
    assert [call[1] for call in reader.calls] == [0, 1, 2]
    assert result.checkpoint.counts[0].scanned == 3
    # A completed checkpoint is a no-op, even if source data later changes.
    untouched = Reader(error=AssertionError("must not read"), fail_after=0)
    assert run(req, untouched, checkpoint=result.checkpoint) == result
    assert not untouched.calls


def test_exported_checkpoint_round_trip_and_corruption_rejected(tmp_path):
    req = request()
    rows = [record(1), record(2), record(3)]
    partial = run(req, Reader(rows), budget=job.HistoryBudget(max_rows=1))
    path = job.write_history_result(partial, tmp_path / "partial")
    checkpoint = job.read_history_checkpoint(path)
    assert checkpoint == partial.checkpoint
    assert run(req, Reader(rows), checkpoint=checkpoint) == run(req, Reader(rows))
    manifest = json.loads(path.read_text())
    manifest["checkpoint"]["after"] = 3
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="sigma_history_checkpoint_invalid"):
        job.read_history_checkpoint(path)


def test_reader_failure_keeps_last_acknowledged_checkpoint_for_retry():
    req = request()
    rows = [record(1), record(2), record(3)]
    checkpoints = []
    failed = run(req, Reader(rows, fail_after=1), save_checkpoint=checkpoints.append)
    assert (failed.status, failed.reason) == ("failed", "history_job_failed")
    assert failed.checkpoint.after == 1
    assert failed.checkpoint == checkpoints[-1]
    assert "synthetic-private-diagnostic" not in json.dumps(failed.manifest())
    retried = run(req, Reader(rows), checkpoint=failed.checkpoint)
    assert retried == run(req, Reader(rows))


def test_checkpoint_write_failure_does_not_acknowledge_unpersisted_row():
    writes = []

    def save(state):
        if state.after == 2:
            raise OSError("synthetic-private-diagnostic")
        writes.append(state)

    req = request(watermark=2)
    rows = [record(1), record(2)]
    failed = run(req, Reader(rows), save_checkpoint=save)
    assert failed.status == "failed"
    assert failed.checkpoint.after == 1
    assert failed.checkpoint == writes[-1]
    assert run(req, Reader(rows), checkpoint=failed.checkpoint) == run(req, Reader(rows))


def test_cancel_before_read_and_resume():
    req = request(watermark=1)
    reader = Reader([record(1)])
    cancelled = run(req, reader, cancelled=lambda: True)
    assert (cancelled.status, cancelled.reason) == ("cancelled", "cancel_requested")
    assert not reader.calls
    resumed = run(req, reader, checkpoint=cancelled.checkpoint)
    assert resumed.status == "completed"


def test_cancel_after_one_row_preserves_checkpoint_and_no_extra_read():
    saved = []
    reader = Reader([record(1), record(2), record(3)])
    cancelled = run(reader=reader, save_checkpoint=saved.append, cancelled=lambda: bool(saved))
    assert cancelled.status == "cancelled"
    assert cancelled.checkpoint.after == 1
    assert len(reader.calls) == 1
    assert run(reader=reader, checkpoint=cancelled.checkpoint).checkpoint.counts[0].scanned == 3


def test_cancel_during_rule_batch_never_commits_half_a_row(monkeypatch):
    req = request(watermark=1, rules=(rule(), rule(2)))
    real_match = job.match_rule
    matched = []

    def match(*args, **kwargs):
        matched.append(1)
        return real_match(*args, **kwargs)

    monkeypatch.setattr(job, "match_rule", match)
    result = run(req, Reader([record(1)]), cancelled=lambda: bool(matched))
    assert result.status == "cancelled"
    assert result.checkpoint.rows_read == 0
    assert result.checkpoint.counts == ()
    assert result.checkpoint.samples == ()
    resumed = run(req, Reader([record(1)]), checkpoint=result.checkpoint)
    assert resumed.status == "completed"
    assert [row.scanned for row in resumed.checkpoint.counts] == [1, 1]


@pytest.mark.parametrize("error", [False, RuntimeError("private-access-error")])
def test_permission_denied_before_any_read_or_checkpoint_access(error):
    req = request()
    reader = Reader([record(1)])
    saved = []

    def authorized(part):
        if error:
            raise error
        return False

    result = job.run_history_job(req, reader, authorized=authorized, save_checkpoint=saved.append)
    assert (result.status, result.reason) == ("failed", "permission_denied")
    assert not reader.calls and not saved
    assert result.checkpoint.samples == ()
    assert result.checkpoint.counts == ()


def test_permission_revoked_on_resume_hides_previous_refs():
    req = request()
    partial = run(req, Reader([record(1), record(2)]), budget=job.HistoryBudget(max_rows=1))
    assert partial.checkpoint.samples
    reader = Reader([record(2)])
    result = job.run_history_job(req, reader, authorized=lambda part: False, checkpoint=partial.checkpoint)
    assert result.status == "failed" and result.reason == "permission_denied"
    assert not reader.calls
    assert not result.checkpoint.samples and not result.checkpoint.counts


def test_store_permission_denial_and_mid_run_revocation():
    reader = Reader([record(1)], fail_after=0, error=PermissionError("private-store-error"))
    result = run(reader=reader)
    assert result.reason == "permission_denied" and not result.checkpoint.samples
    saved = []
    result = job.run_history_job(request(), Reader([record(1), record(2)]),
                                 authorized=lambda part: not saved, save_checkpoint=saved.append)
    assert result.reason == "permission_denied"
    assert not result.checkpoint.samples and not result.checkpoint.counts
    assert len(saved) == 1


def test_all_sources_authorized_before_reading_first_partition():
    req = request()
    other = replace(req.partitions[0], scope=EventScope("fixture-installation", "other-source", "generation"))
    req = replace(req, partitions=(*req.partitions, other))
    reader = Reader([record(1)])
    result = job.run_history_job(req, reader, authorized=lambda part: part.scope == SCOPE)
    assert result.reason == "permission_denied"
    assert not reader.calls


def test_timeout_is_partial_and_passes_read_bounds():
    reader = Reader(fail_after=0, error=TimeoutError())
    result = run(reader=reader, budget=job.HistoryBudget(max_bytes=1234, read_timeout_seconds=0.25))
    assert result.status == "partial" and result.reason == "read_timeout"
    _, after, max_bytes, timeout = reader.calls[0]
    assert after == 0 and max_bytes == 1234 and timeout == 0.25
    assert result.checkpoint.rows_read == 0


@pytest.mark.parametrize("clock,reason", [("monotonic", "time_budget"), ("process_time", "cpu_budget")])
def test_time_and_cpu_budgets_with_fake_clocks(monkeypatch, clock, reason):
    ticks = iter([0.0, 100.0])
    monkeypatch.setattr(job.time, clock, lambda: next(ticks, 100.0))
    reader = Reader([record(1)])
    result = run(reader=reader)
    assert (result.status, result.reason) == ("partial", reason)
    assert not reader.calls


def test_evaluation_budget_does_not_start_a_partial_rule_batch():
    req = request(rules=(rule(), rule(2)))
    reader = Reader([record(1)])
    result = run(req, reader, budget=job.HistoryBudget(max_evaluations=1))
    assert result.reason == "evaluation_budget" and result.status == "partial"
    assert not reader.calls


def test_event_bytes_and_total_byte_budgets_leave_cursor_unchanged():
    reader = Reader([record(1)])
    failed = run(reader=reader, budget=job.HistoryBudget(max_event_bytes=1))
    assert (failed.status, failed.reason, failed.checkpoint.after) == ("failed", "event_byte_budget", 0)
    partial = run(reader=reader, budget=job.HistoryBudget(max_bytes=1))
    assert (partial.status, partial.reason, partial.checkpoint.after) == ("partial", "byte_budget", 0)


def test_job_lifetime_and_samples_are_bounded_across_slices():
    req = request()
    reader = Reader([record(1), record(2), record(3)])
    first = run(req, reader, budget=job.HistoryBudget(max_rows=1, max_job_rows=2, max_samples=1))
    result = run(req, reader, checkpoint=first.checkpoint,
                 budget=job.HistoryBudget(max_job_rows=2, max_samples=1))
    assert result.status == "partial" and result.reason == "job_row_budget"
    assert result.checkpoint.rows_read == 2
    assert len(result.checkpoint.samples) == 1


def test_duplicate_delivery_is_counted_separately_and_not_evaluated_twice():
    first = record(1)
    result = run(reader=Reader([first, record(2, ref=first.ref), record(3)]))
    assert result.status == "completed"
    assert result.checkpoint.rows_read == 3
    assert result.checkpoint.deduplicated == 1
    assert result.checkpoint.counts[0].scanned == 2
    assert len(result.checkpoint.samples) == 2


def test_snapshot_exhaustion_not_live_tail_and_empty_snapshot():
    reader = Reader([record(1), record(2), record(3)])
    result = run(request(watermark=1), reader)
    assert result.status == "completed" and result.checkpoint.rows_read == 1
    assert len(reader.calls) == 1
    reader = Reader([record(1)])
    result = run(request(watermark=0), reader)
    assert result.status == "completed" and result.checkpoint.rows_read == 0
    assert not reader.calls
    assert result.checkpoint.counts[0].scanned == 0
    assert result.manifest()["checkpoint"]["counts"][0]["evaluable_percent"] is None
    result = run(request(watermark=5), Reader([record(1)]))
    assert result.status == "completed" and result.checkpoint.rows_read == 1


@pytest.mark.parametrize("change", [
    {"position": 0}, {"position": 4},
    {"scope": EventScope("fixture-installation", "wrong-source", "generation")},
    {"occurred_at": START - timedelta(seconds=1)},
    {"occurred_at": START.replace(tzinfo=None)},
    {"quality_reasons": ("private text must not become a reason",)},
    {"ref": job.HistoryEvidenceRef("workstation_history", "e" * 64, "d" * 64)},
])
def test_reader_scope_cursor_and_quality_contract_fail_closed(change):
    bad = replace(record(1), **change)

    class BadReader:
        def read_one(self, *args, **kwargs):
            return bad

    result = run(reader=BadReader())
    assert result.status == "failed" and result.reason == "reader_contract_invalid"
    assert result.checkpoint.after == 0
    assert not result.checkpoint.counts


def test_mapping_mismatch_unknown_and_logsource_mismatch_skipped():
    row = record(1)
    row = replace(row, event=replace(row.event, mapping_version="unsupported-version"))
    result = run(request(watermark=1), Reader([row]))
    assert result.checkpoint.counts[0].unknown == 1
    assert dict(result.checkpoint.counts[0].reasons) == {"mapping_version_mismatch": 1}
    result = run(request(watermark=1, rules=(rule(logsource="system"),)), Reader([record(1)]))
    counts, = result.checkpoint.counts
    assert counts.skipped == 1 and counts.evaluable == 0 and counts.unknown == 0
    assert result.manifest()["checkpoint"]["counts"][0]["matches_per_1000_evaluable"] is None


def test_unavailable_negated_field_does_not_become_clean():
    plan = rule(field="CommandLine", value="fixture")
    plan = replace(plan, expression=IRExpression("not", (plan.expression,)))
    row = record(1)
    event = replace(row.event, fields={"CommandLine": "private-fixture-command"},
                     unavailable={"CommandLine": "masked"})
    result = run(request(watermark=1, rules=(plan,)), Reader([replace(row, event=event)]))
    counts, = result.checkpoint.counts
    assert counts.unknown == 1 and counts.matched == 0 and counts.evaluable == 0
    assert counts.unknown_fields == (("CommandLine", "field_unavailable", 1),)
    assert "private-fixture-command" not in json.dumps(result.manifest())


@pytest.mark.parametrize("change", [
    {"manifest_sha256": "e" * 64}, {"rules": (rule(2),)}, {"job_id": "other-job"},
    {"match_limits": job.MatchLimits(max_steps=100)},
])
def test_retry_rejects_changed_execution_identity(change):
    req = request()
    state = run(req, Reader([record(1), record(2)]), budget=job.HistoryBudget(max_rows=1)).checkpoint
    with pytest.raises(ValueError, match="sigma_history_checkpoint_mismatch"):
        run(replace(req, **change), checkpoint=state)
    other = replace(req.partitions[0], snapshot="another-snapshot")
    with pytest.raises(ValueError, match="sigma_history_checkpoint_mismatch"):
        run(replace(req, partitions=(other,)), checkpoint=state)


def test_ws_string_ids_and_source_day_buckets_stay_separate():
    part = replace(request().partitions[0], storage_kind="workstation_observation", high_watermark=1)
    tomorrow = replace(part, start=START + timedelta(days=1), end=START + timedelta(days=2))
    req = request(partitions=(part, tomorrow))
    native_id = "e" * 64

    class DayReader:
        def read_one(self, partition, **kwargs):
            row = record(1, stamp=partition.start + timedelta(seconds=1),
                          ref=job.HistoryEvidenceRef("workstation_observation", native_id,
                                                     "d" * 64 if partition == part else "f" * 64))
            return row

    result = run(req, DayReader())
    assert result.status == "completed"
    assert len(result.checkpoint.counts) == 2
    assert {sample.ref.native_id for sample in result.checkpoint.samples} == {native_id}
    assert {row.partition_key for row in result.checkpoint.counts} == {part.key, tomorrow.key}


@pytest.mark.parametrize("kwargs", [
    {"max_rows": 0}, {"max_rows": True}, {"max_rows": 10_001},
    {"max_seconds": float("nan")}, {"max_seconds": float("inf")}, {"max_job_rows": 100_001},
    {"max_samples": 1001}, {"read_timeout_seconds": 11},
])
def test_invalid_budgets_rejected(kwargs):
    with pytest.raises(ValueError, match="sigma_history_budget_invalid"):
        job.HistoryBudget(**kwargs)


def test_seven_day_window_daily_blocks_and_overlap_required():
    part = request().partitions[0]
    with pytest.raises(ValueError, match="sigma_history_partition_invalid"):
        replace(part, end=START + timedelta(days=2))
    with pytest.raises(ValueError, match="sigma_history_request_invalid"):
        request(partitions=(part, replace(part, start=START + timedelta(days=7), end=START + timedelta(days=8))))
    with pytest.raises(ValueError, match="sigma_history_partition_overlap"):
        request(partitions=(part, replace(part, storage_kind="core_history")))


def test_history_has_no_production_writes(monkeypatch):
    import psycopg

    from server.sli.core import database, postgres_runtime_pipeline
    from server.sli.semantic import semantic_findings

    def forbidden(*args, **kwargs):
        pytest.fail("History job attempted runtime database IO")

    monkeypatch.setattr(database, "query_rows", forbidden)
    monkeypatch.setattr(database, "query_rows_bounded", forbidden)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", forbidden)
    monkeypatch.setattr(psycopg, "connect", forbidden)
    monkeypatch.setattr(semantic_findings, "publish_enabled_scenario_finding", forbidden)
    saved = []
    result = run(reader=Reader([record(1), record(2), record(3)]), save_checkpoint=saved.append)
    assert result.status == "completed"
    assert saved[-1] == result.checkpoint
    assert result.mode == "test" and all(row.suppressed == 0 for row in result.checkpoint.counts)

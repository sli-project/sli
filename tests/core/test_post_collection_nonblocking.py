import threading
import subprocess

import pytest

from server.jobs import collector


def _job(job_id=1):
    now = collector.utc_now()
    return collector.Job(id=job_id, kind="collect_all_dc_logs:scheduled", status="completed", servers=["DC1"], hours=1, max_events_per_channel=1000, created_at=now, updated_at=now)


def test_post_collection_failure_does_not_change_collection_status(monkeypatch):
    job = _job(901)
    with collector._lock:
        collector._jobs[job.id] = job
    monkeypatch.setattr(collector, "update_post_collection_job", lambda *a, **k: None)
    monkeypatch.setattr(collector, "update_post_collection_findings", lambda *a, **k: None)
    monkeypatch.setattr(collector, "refresh_findings_from_events", lambda: {"status": "ok"})
    monkeypatch.setattr(collector, "generate_recommendation_report", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(collector, "log_internal_error", lambda *a, **k: "ERR-901")
    collector._run_post_collection_job(job.id, job.servers, "trace")
    result = collector.get_job(job.id)
    assert result["status"] == "completed"
    assert result["collection_status"] in (None, "completed")
    assert result["analysis_status"] == "failed"
    assert result["analysis_error_id"] == "ERR-901"


def test_enqueue_is_deduplicated(monkeypatch):
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "0")
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "1")
    calls=[]
    class Immediate:
        def submit(self, fn, *args): calls.append(args)
    monkeypatch.setattr(collector, "_post_collection_executor", Immediate())
    monkeypatch.setattr(collector, "queue_post_collection_job", lambda **k: {})
    monkeypatch.setattr(collector, "claim_post_collection_job", lambda durable_job_id, **k: {"durable_job_id": durable_job_id, "attempt_count": 1})
    with collector._post_collection_guard:
        collector._post_collection_active.discard("runtime-902")
    collector._enqueue_post_collection(902, ["DC1"], "t")
    collector._enqueue_post_collection(902, ["DC1"], "t")
    assert len(calls) == 1
    with collector._post_collection_guard:
        collector._post_collection_active.discard("runtime-902")


def test_enqueue_stands_down_when_row_claimed_elsewhere(monkeypatch):
    """The in-process executor must not run a job another owner already claimed."""
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "0")
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "1")
    calls = []
    class Immediate:
        def submit(self, fn, *args): calls.append(args)
    monkeypatch.setattr(collector, "_post_collection_executor", Immediate())
    monkeypatch.setattr(collector, "queue_post_collection_job", lambda **k: {})
    monkeypatch.setattr(collector, "claim_post_collection_job", lambda durable_job_id, **k: None)
    monkeypatch.setattr(collector, "log_event", lambda *a, **k: None)
    with collector._post_collection_guard:
        collector._post_collection_active.discard("runtime-903")
    collector._enqueue_post_collection(903, ["DC1"], "t")
    assert calls == []
    with collector._post_collection_guard:
        assert "runtime-903" not in collector._post_collection_active


def test_collection_source_has_no_inline_report_call():
    import inspect
    source = inspect.getsource(collector._run_collect_job_body)
    assert "generate_recommendation_report" not in source
    assert "_enqueue_post_collection" in source


@pytest.mark.parametrize(
    ("job_id", "return_code", "expected_status", "post_collection_expected", "partial_marker"),
    (
        (920, 0, "completed", True, False),
        (921, 0, "partial", True, True),
        (924, 4, "partial", True, False),
        (925, 1, "failed", False, False),
    ),
)
def test_collection_cycle_distinguishes_success_partial_and_failure(
    monkeypatch, job_id, return_code, expected_status, post_collection_expected, partial_marker
):
    job = _job(job_id)
    job.status = "queued"
    with collector._lock:
        collector._jobs[job.id] = job
    completed = subprocess.CompletedProcess(
        ["pilot"],
        return_code,
        stdout=(
            '{"events_collected": 10}\n'
            + ('collection_result={"status":"partial"}\n' if partial_marker else "")
        ),
        stderr=(
            "Collection process returned a non-zero code after importing successful channels."
            if return_code == 4
            else "collector failed"
            if return_code
            else ""
        ),
    )
    queued = []
    monkeypatch.setattr(collector, "can_start_collection", lambda: {"collection_allowed": True})
    monkeypatch.setattr(collector, "CONTINUOUS_RECOVERY_ENABLED", False)
    monkeypatch.setattr(
        collector,
        "_collect_servers_parallel",
        lambda *args, **kwargs: [("DC1", completed, 50, completed.stdout, completed.stderr)],
    )
    monkeypatch.setattr(collector, "_enqueue_post_collection", lambda *args: queued.append(args))
    monkeypatch.setattr(collector, "_scheduler_skip_report_enabled", lambda: False)
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_performance_stage", lambda *args, **kwargs: None)

    try:
        # This test is about the job-body state machine (success/partial/
        # failure), not the reason-based advisory-lock wrapper -- call the
        # body directly, matching how the scheduler/worker reasons already
        # skip that wrapper too.
        collector._run_collect_job_body(job.id)
        result = collector.get_job(job.id)
    finally:
        with collector._lock:
            collector._jobs.pop(job.id, None)

    assert result["status"] == expected_status
    assert bool(queued) is post_collection_expected
    if expected_status == "partial":
        assert result["warnings"]
        assert result["errors"] == []
        assert result["analysis_status"] == "queued"
    elif expected_status == "failed":
        assert result["errors"]
        assert result["analysis_status"] == "not_queued"
    else:
        assert result["warnings"] == []
        assert result["errors"] == []


def test_continuous_recovery_cycle_budget_is_partial_not_complete(monkeypatch):
    job = _job(930)
    job.status = "queued"
    with collector._lock:
        collector._jobs[job.id] = job
    completed = subprocess.CompletedProcess(
        ["pilot"], 0, stdout='{"events_collected": 50000}\n', stderr=""
    )
    queued = []
    monkeypatch.setattr(collector, "can_start_collection", lambda: {"collection_allowed": True})
    monkeypatch.setattr(collector, "CONTINUOUS_RECOVERY_ENABLED", True)
    monkeypatch.setattr(collector, "CONTINUOUS_RECOVERY_MAX_CYCLES", 1)
    monkeypatch.setattr(collector, "CONTINUOUS_RECOVERY_MAX_JOB_SECONDS", 3600)
    monkeypatch.setattr(collector, "_servers_in_recovery", lambda _servers: ["DC1"])
    monkeypatch.setattr(
        collector,
        "_collect_servers_parallel",
        lambda *args, **kwargs: [("DC1", completed, 50, completed.stdout, "")],
    )
    monkeypatch.setattr(collector, "_enqueue_post_collection", lambda *args: queued.append(args))
    monkeypatch.setattr(collector, "_scheduler_skip_report_enabled", lambda: False)
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "log_performance_stage", lambda *args, **kwargs: None)

    try:
        collector._run_collect_job_body(job.id)
        result = collector.get_job(job.id)
    finally:
        with collector._lock:
            collector._jobs.pop(job.id, None)

    assert result["status"] == "partial"
    assert any("budget" in warning.lower() for warning in result["warnings"])
    assert result["errors"] == []
    assert queued


def test_post_collection_analysis_sql_avoids_postgres_having_aliases():
    from pathlib import Path

    source = Path("server/sli/reports/analysis.py").read_text(encoding="utf-8")
    assert "having failure_count" not in source
    assert "order by failure_count" not in source
    assert "having privilege_count" not in source
    assert "order by privilege_count" not in source


def test_postgres_query_translation_supports_analysis_json_helpers():
    from server.sli.core.database import _pg_sql

    sql = """
    select
      coalesce(json_extract(e.event_data_json, '$.ProcessName'), json_extract(e.event_data_json, '$.ProcessId'), '<нет процесса>'),
      min(coalesce(json_extract(e.event_data_json, '$.TaskName'), '<нет имени задачи>')),
      group_concat(distinct e.event_id)
    from events e
    where e.id = ?
    """

    converted = _pg_sql(sql)

    assert "(e.event_data_json::jsonb ->> 'ProcessName')" in converted
    assert "(e.event_data_json::jsonb ->> 'ProcessId')" in converted
    assert "(e.event_data_json::jsonb ->> 'TaskName')" in converted
    assert "string_agg(distinct (e.event_id)::text, ',')" in converted
    assert "json_extract" not in converted
    assert "group_concat" not in converted
    assert "%s" in converted


def test_postgres_query_translation_escapes_literal_like_percent():
    from server.sli.core.database import _pg_sql

    converted = _pg_sql("select * from events where provider_name like '%Group Policy%' and id = ?")

    assert "like '%%Group Policy%%'" in converted
    assert "id = %s" in converted

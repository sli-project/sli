import pytest

from server.sli.ops import runtime_workers


class QueryCanceled(RuntimeError):
    pass


class Cursor:
    def __init__(self, rows=(), *, fail=False):
        self.rows = rows
        self.fail = fail
        self.executed = []

    def execute(self, sql, params=()):
        query = " ".join(sql.casefold().split())
        self.executed.append(query)
        if query.startswith("select"):
            assert self.executed[:3] == [
                "set transaction read only",
                "set local statement_timeout = '3000ms'",
                "set local lock_timeout = '1000ms'",
            ]
            if self.fail:
                raise QueryCanceled("private error detail")

    def fetchall(self):
        return self.rows

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class Connection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def read_metrics(cursor):
    return runtime_workers.get_semantic_queue_overview(
        connection_factory=lambda: Connection(cursor),
    )


def row(stage, status, depth, *, age=0, completed=0):
    return {
        "queue_name": stage, "queue_status": status, "depth": depth,
        "oldest_pending_age_seconds": age, "completed_last_hour": completed,
        "payload_json": {"private": "must not escape"},
    }


def test_stage_metrics_include_retries_and_leases_but_exclude_terminal_jobs():
    cursor = Cursor([
        row("processing", "queued", 4, age=60),
        row("processing", "failed", 2, age=120),
        row("processing", "leased", 1, age=900),
        row("processing", "completed", 8000, completed=42),
        row("dispatch", "failed", 3, age=70),
        row("dispatch", "quarantined", 5000, age=9000),
        row("dispatch", "completed", 6000, completed=23),
        row("risk", "leased", 2, age=10),
        row("risk", "completed", 7000, completed=11),
    ])
    result = read_metrics(cursor)

    assert result["status"] == "ok"
    assert result["contains_event_payload"] is False
    assert result["window_seconds"] == 3600
    assert result["warning_thresholds"] == {
        "depth": 1000, "oldest_pending_age_seconds": 900,
    }
    assert result["stages"] == [
        {"queue_name": "processing", "depth": 7,
         "oldest_pending_age_seconds": 900, "completed_last_hour": 42},
        {"queue_name": "dispatch", "depth": 3,
         "oldest_pending_age_seconds": 70, "completed_last_hour": 23},
        {"queue_name": "risk", "depth": 2,
         "oldest_pending_age_seconds": 10, "completed_last_hour": 11},
    ]
    assert "payload_json" not in str(result)
    assert "private" not in str(result)

    sql = cursor.executed[3]
    for table, status in (
        ("semantic_processing_outbox", "status"),
        ("semantic_correlation_dispatch_jobs", "dispatch_status"),
        ("semantic_risk_evaluation_jobs", "evaluation_status"),
    ):
        assert f"from {table}" in sql
        assert f"{status} in ('queued','failed','leased')" in sql
        assert f"where {status}='completed' and completed_at>=now()-interval '1 hour' and completed_at<=now()" in sql
    assert "now()-created_at" in sql
    assert not any(token in sql.split() for token in ("update", "insert", "delete"))
    assert "payload_json" not in sql


@pytest.mark.parametrize("rows", [[], [row("processing", "completed", 9000, completed=8)]])
def test_empty_stages_are_zero_without_losing_recent_throughput(rows):
    result = read_metrics(Cursor(rows))
    assert result["status"] == "ok"
    assert [stage["queue_name"] for stage in result["stages"]] == ["processing", "dispatch", "risk"]
    assert all(stage["depth"] == stage["oldest_pending_age_seconds"] == 0 for stage in result["stages"])
    assert [stage["completed_last_hour"] for stage in result["stages"]] == [8 if rows else 0, 0, 0]


def test_query_timeout_does_not_publish_zero_or_private_error_details():
    result = read_metrics(Cursor(fail=True))
    assert result == {
        "status": "unavailable", "contains_event_payload": False,
        "error_type": "QueryCanceled", "items": [],
    }


def test_operations_overview_forwards_stage_metrics_through_worker_state(monkeypatch):
    from server.sli.reporting import ui_operations

    snapshot = read_metrics(Cursor([row("risk", "queued", 9, age=90)]))
    monkeypatch.setattr(runtime_workers, "connect", lambda: Connection(Cursor()))
    monkeypatch.setattr(runtime_workers, "get_semantic_queue_overview", lambda: snapshot)
    monkeypatch.setattr(runtime_workers, "WORKER_SPECS", (("semantic", "Semantic"),))
    monkeypatch.setattr(ui_operations, "get_runtime_workers_overview", runtime_workers.get_runtime_workers_overview)
    monkeypatch.setattr(ui_operations, "get_collector_health", lambda: {"items": []})
    monkeypatch.setattr(ui_operations, "get_postgres_operations_status", lambda **_kwargs: {})
    monkeypatch.setattr(ui_operations, "get_collection_runtime_status", lambda: {"collection_enabled": False})
    monkeypatch.setattr(ui_operations, "get_operations_storage_summary", lambda _postgres: {})
    monkeypatch.setattr(ui_operations, "_event_catalog_completeness_view", dict)
    monkeypatch.setattr(ui_operations, "_radius_vpn_operations_view", dict)

    result = ui_operations.get_operations_overview()
    assert result["read_only"] is True
    assert result["workers"]["semantic_queues"] is snapshot
    assert result["workers"]["semantic_queues"]["stages"][2]["depth"] == 9

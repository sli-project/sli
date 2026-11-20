from __future__ import annotations



class _Cursor:
    def __init__(self, statements: list[tuple[str, tuple]], rows: list[dict]) -> None:
        self.statements = statements
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, sql, params=()):
        self.statements.append((str(sql), tuple(params)))

    def fetchall(self):
        return self.rows


class _Connection:
    def __init__(self, statements: list[tuple[str, tuple]], rows: list[dict]) -> None:
        self.statements = statements
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def cursor(self):
        return _Cursor(self.statements, self.rows)


def _run(monkeypatch, *, v2: bool, rows: list[dict]) -> tuple[dict, str, tuple]:
    from server.sli.reporting import dashboard_fast
    from server.sli.core import postgres_runtime_pipeline

    statements: list[tuple[str, tuple]] = []
    monkeypatch.setattr(dashboard_fast, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        dashboard_fast,
        "resolve_storage_route",
        lambda **_kwargs: {"route": "v2" if v2 else "v1"},
    )
    monkeypatch.setattr(
        postgres_runtime_pipeline,
        "connect",
        lambda: _Connection(statements, rows),
    )
    result = dashboard_fast.get_overview_activity(
        time_from="2026-07-17T00:00:00Z",
        time_to="2026-07-17T01:00:00Z",
        bucket_count=2,
        authorization=object(),
    )
    query, params = statements[-1]
    return result, query.lower(), params


def test_overview_aggregates_canonical_contextual_severity_in_postgres(monkeypatch) -> None:
    result, query, params = _run(
        monkeypatch,
        v2=False,
        rows=[
            {"bucket": 0, "final_security_severity": "high", "count": 2},
            {"bucket": 0, "final_security_severity": "unknown", "count": 1},
        ],
    )

    assert "event_data_json" in query
    assert "powershell" not in query
    assert any("powershell" in str(value).lower() for value in params)
    assert "final_security_severity" in query
    assert result["items"][0]["critical"] == 2
    assert result["items"][0]["informational"] == 1
    assert result["exact"] is True


def test_overview_v2_projects_bounded_facts_into_contextual_event_data(monkeypatch) -> None:
    _result, query, _params = _run(monkeypatch, v2=True, rows=[])

    assert "left join event_facts_v2 facts" in query
    assert "jsonb_build_object" in query
    assert "facts.task_action" in query
# Private compilation-cache behavior is intentionally outside this public query contract.

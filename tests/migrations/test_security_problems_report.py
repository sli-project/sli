from pathlib import Path
from datetime import datetime, timedelta, timezone

from server.sli.semantic import findings as module
from server.api.routes import findings as route
from scripts.maintenance import security_problems_report_control as control
from scripts.maintenance.repository_relevance_audit import COMPONENTS


ROOT = Path(__file__).resolve().parents[2]


def test_migration_79_exposes_only_publication_membership_to_web_role() -> None:
    forward = (
        ROOT
        / "config/postgres_migrations/079_semantic_finding_report_reader.sql"
    ).read_text(encoding="utf-8").casefold()
    rollback = (
        ROOT
        / "config/postgres_migrations/079_semantic_finding_report_reader.rollback.sql"
    ).read_text(encoding="utf-8").casefold()

    assert "is_semantic_finding_published_v1(bigint)" in forward
    assert "security definer" in forward
    assert "set search_path = pg_catalog, public" in forward
    assert "grant execute on function is_semantic_finding_published_v1(bigint)" in forward
    assert "grant select on" not in forward
    assert "semantic_finding_publications" in forward
    assert "revoke all on function is_semantic_finding_published_v1(bigint)" in rollback
    assert "drop function if exists is_semantic_finding_published_v1(bigint)" in rollback


def test_migration_79_controller_requires_exact_confirmation(monkeypatch) -> None:
    monkeypatch.setattr(
        control,
        "plan",
        lambda: {
            "status": "ready",
            "migration": {"state": "ready"},
            "snapshot": {},
        },
    )

    try:
        control.apply(confirmation="wrong")
    except PermissionError as exc:
        assert "exact migration confirmation" in str(exc)
    else:
        raise AssertionError("apply accepted a non-exact confirmation")


def test_security_problems_report_controller_is_classified_as_migration() -> None:
    assert (
        "scripts/maintenance/security_problems_report_control.py"
        in COMPONENTS["перенос_и_миграции"]
    )


def test_security_problems_read_model_contains_only_published_semantic_findings(monkeypatch) -> None:
    calls: list[str] = []

    monkeypatch.setattr(module, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        module,
        "resolve_storage_route",
        lambda **_kwargs: {"route": "v2"},
    )
    monkeypatch.setattr(module, "_attach_postgres_finding_details", lambda rows, **_kwargs: None)
    monkeypatch.setattr(module, "get_findings_refresh_status", lambda **_kwargs: {"limitations": []})

    def fake_query(sql: str, params=(), **_kwargs):
        calls.append(sql)
        if "runtime_worker_heartbeats" in sql:
            return [{
                "status": "idle",
                "phase": "production_sleep",
                "heartbeat_at": datetime.now(timezone.utc).isoformat(),
                "expected_interval_seconds": 30,
                "details_json": {
                    "manual_runtime": False,
                    "enabled_policy": "l1-audit-policy-changed:2",
                    "runtime_mode": "findings-v1",
                },
            }]
        if "group by findings.severity" in sql:
            return [{"severity": "high", "status": "new", "count": 7}]
        if "from findings_active" in sql:
            return [{
                "id": 558,
                "title": "Audit policy was changed",
                "severity": "high",
                "status": "new",
                "summary": "Exact named EventData from Event 4719 was observed",
                "why_it_matters": "Exact named EventData from Event 4719 was observed",
                "recommended_action": "Review the linked evidence and validate the security impact.",
                "evidence_count": 70,
                "assigned_to": None,
            }]
        raise AssertionError(sql)

    monkeypatch.setattr(module, "query_rows", fake_query)

    result = module.get_security_problems_data(limit=50)

    assert result["status"] == "ok"
    assert result["source"] == "semantic_production_findings"
    assert [item["id"] for item in result["items"]] == [558]
    assert result["summary"] == [{"severity": "high", "status": "new", "count": 7}]
    assert result["semantic_runtime"]["state"] == "active"
    assert result["semantic_runtime"]["enabled_policy"] == "l1-audit-policy-changed:2"
    list_sql = next(sql for sql in calls if "from findings_active" in sql and "group by" not in sql)
    assert "is_semantic_finding_published_v1(findings.id)" in list_sql
    assert "join semantic_finding_publications" not in list_sql


def test_security_problems_read_model_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(module, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(module, "resolve_storage_route", lambda **_kwargs: {"route": "v2"})
    monkeypatch.setattr(module, "_attach_postgres_finding_details", lambda rows, **_kwargs: None)
    monkeypatch.setattr(module, "get_findings_refresh_status", lambda **_kwargs: {"limitations": []})
    seen: list[tuple[str, tuple]] = []

    def fake_query(sql: str, params=(), **_kwargs):
        seen.append((sql, tuple(params)))
        if "runtime_worker_heartbeats" in sql:
            return []
        return []

    monkeypatch.setattr(module, "query_rows", fake_query)

    result = module.get_security_problems_data(limit=5000)

    assert result["limits"]["limit"] == 200
    assert result["has_more"] is False
    list_params = next(params for sql, params in seen if "from findings_active" in sql and "group by" not in sql)
    assert list_params[-1] == 201


def test_security_problems_read_model_applies_half_open_observation_period(monkeypatch) -> None:
    monkeypatch.setattr(module, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(module, "resolve_storage_route", lambda **_kwargs: {"route": "v2"})
    monkeypatch.setattr(module, "_attach_postgres_finding_details", lambda rows, **_kwargs: None)
    monkeypatch.setattr(module, "get_findings_refresh_status", lambda **_kwargs: {"limitations": []})
    seen: list[tuple[str, tuple]] = []

    def fake_query(sql: str, params=(), **_kwargs):
        seen.append((sql, tuple(params)))
        return []

    monkeypatch.setattr(module, "query_rows", fake_query)

    module.get_security_problems_data(
        time_from="2026-08-20T00:00:00Z",
        time_to="2026-08-28T00:00:00Z",
    )

    list_sql, list_params = next(
        (sql, params)
        for sql, params in seen
        if "from findings_active" in sql and "group by" not in sql
    )
    assert "findings.last_seen_utc::timestamptz >= ?::timestamptz" in list_sql
    assert "findings.last_seen_utc::timestamptz < ?::timestamptz" in list_sql
    assert list_params[:2] == (
        "2026-08-20T00:00:00Z",
        "2026-08-28T00:00:00Z",
    )


def test_semantic_runtime_projection_marks_old_heartbeat_stale() -> None:
    now = datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc)
    projection = module._semantic_runtime_projection(
        {
            "status": "idle",
            "phase": "production_sleep",
            "heartbeat_at": now - timedelta(minutes=5),
            "expected_interval_seconds": 30,
            "details_json": {"manual_runtime": False, "runtime_mode": "findings-v1"},
        },
        generated=now,
    )

    assert projection["state"] == "stale"
    assert projection["fresh"] is False
    assert projection["age_seconds"] == 300


def test_investigation_worker_reports_live_facts_and_relations_without_finding_publication() -> None:
    now = datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc)

    projection = module._semantic_runtime_projection({
        "status": "idle", "heartbeat_at": now, "expected_interval_seconds": 30,
        "details_json": {"manual_runtime": False, "runtime_mode": "investigation-v1"},
    }, generated=now)

    assert projection["state"] == "inactive"
    assert projection["runtime_mode"] == "investigation-v1"
    assert projection["facts_state"] == "active"
    assert projection["relations_state"] == "active"
    assert projection["findings_state"] == "inactive"


def test_stale_or_unknown_worker_does_not_claim_unavailable_capabilities_are_active() -> None:
    now = datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc)
    stale_facts = module._semantic_runtime_projection({
        "status": "idle", "heartbeat_at": now - timedelta(minutes=5),
        "expected_interval_seconds": 30,
        "details_json": {"manual_runtime": False, "runtime_mode": "facts-v1"},
    }, generated=now)
    unknown_mode = module._semantic_runtime_projection({
        "status": "idle", "heartbeat_at": now, "expected_interval_seconds": 30,
        "details_json": {"manual_runtime": False, "runtime_mode": "future-v1"},
    }, generated=now)

    assert stale_facts["state"] == "inactive"
    assert stale_facts["facts_state"] == "stale"
    assert stale_facts["relations_state"] == "inactive"
    assert stale_facts["findings_state"] == "inactive"
    assert unknown_mode["state"] == "unknown"
    assert unknown_mode["facts_state"] == "unknown"
    assert unknown_mode["relations_state"] == "unknown"
    assert unknown_mode["findings_state"] == "unknown"


def test_investigation_only_runtime_keeps_an_empty_findings_report_partial(monkeypatch) -> None:
    monkeypatch.setattr(module, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(module, "resolve_storage_route", lambda **_kwargs: {"route": "v2"})
    monkeypatch.setattr(module, "_attach_postgres_finding_details", lambda rows, **_kwargs: None)
    monkeypatch.setattr(module, "get_findings_refresh_status", lambda **_kwargs: {"limitations": []})

    def fake_query(sql: str, params=(), **_kwargs):
        if "runtime_worker_heartbeats" in sql:
            return [{
                "status": "idle", "phase": "production_sleep",
                "heartbeat_at": datetime.now(timezone.utc).isoformat(),
                "expected_interval_seconds": 30,
                "details_json": {"manual_runtime": False, "runtime_mode": "investigation-v1"},
            }]
        return []

    monkeypatch.setattr(module, "query_rows", fake_query)

    result = module.get_security_problems_data()

    assert result["state"] == "partial"
    assert result["semantic_runtime"]["facts_state"] == "active"
    assert result["semantic_runtime"]["relations_state"] == "active"
    assert result["semantic_runtime"]["findings_state"] == "inactive"


def test_facts_only_worker_is_not_a_live_problem_publisher() -> None:
    now = datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc)
    projection = module._semantic_runtime_projection({
        "status": "idle", "heartbeat_at": now, "expected_interval_seconds": 30,
        "details_json": {"manual_runtime": False, "runtime_mode": "facts-v1"},
    }, generated=now)
    assert projection["fresh"] is True
    assert projection["state"] == "inactive"


def test_findings_route_selects_semantic_production_report(monkeypatch) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        route,
        "get_security_problems_data",
        lambda **kwargs: calls.append(kwargs) or {"source": "semantic_production_findings"},
        raising=False,
    )

    class Handler:
        storage_route_authorization = None

        def _access_decision(self):
            return {"reports": [{"report_key": "security.queue", "allowed": True, "allowed_actions": ["view"],
                                 "grants": [{"scope": {"kind": "all"}, "allowed_actions": ["view"], "field_categories": ["security"]}]}]}

        def _send_json(self, payload):
            self.payload = payload

    handler = Handler()
    route._handle_findings_api(
        handler,
        {
            "source": ["semantic-production"],
            "status": ["new"],
            "limit": ["50"],
        },
    )

    assert handler.payload["source"] == "semantic_production_findings"
    assert calls == [{
        "status": "new",
        "severity": None,
        "q": None,
        "time_from": None,
        "time_to": None,
        "limit": 50,
        "risk": None,
        "domain_ids": None,
        "authorization": None,
    }]

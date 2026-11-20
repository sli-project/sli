from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

import pytest

from server.api.routes import reports as routes_reports
from server.sli.access.access_control_v4 import report_access_trace
from server.sli.reporting.ui_api_models import V4ReportAccessTraceResponse


def _access(*, allowed: bool = True) -> dict[str, object]:
    return {
        "evaluated_at_utc": "2026-07-23T00:00:00Z",
        "platform_owner": False,
        "subject": {"id": 77, "username": "real-user", "coarse_role": "operator"},
        "groups": [{"id": 9, "key": "security-reviewers", "name": "Security reviewers"}],
        "explicit_denies": {"reports": []},
        "ignored_denies": {"reports": []},
        "reports": [{
            "report_key": "ad.state", "name": "AD", "version": 3,
            "allowed": allowed, "explanation": "server decision",
            "missing_capabilities": [], "assignment_version_state": "compatible",
            "grants": [{
                "source_type": "direct", "source": "user:77", "scope": {"kind": "server", "ids": [1]},
                "field_categories": ["security"], "allowed_actions": ["view"],
                "validated_report_version": 3, "validated_dataset_version": 2,
            }, {
                "source_type": "temporary", "source": "group:9", "scope": {"kind": "domain", "ids": [4]},
                "field_categories": ["identity_basic"], "allowed_actions": ["view", "export"],
            }],
        }],
    }


def test_report_access_trace_is_bounded_and_preserves_atomic_grants() -> None:
    trace = report_access_trace(_access(), "ad.state")
    assert trace["decision"] == "allowed"
    assert trace["subject"] == {"username": "real-user", "coarse_role": "operator"}
    assert [item["scope"]["kind"] for item in trace["grants"]] == ["server", "domain"]
    assert [item["source"] for item in trace["grants"]] == ["current_subject", "group:security-reviewers"]
    assert "id" not in trace["subject"]
    V4ReportAccessTraceResponse(**trace)


def test_report_access_trace_denied_never_discloses_grants() -> None:
    access = _access(allowed=False)
    access["explicit_denies"] = {"reports": ["ad.state"]}
    trace = report_access_trace(access, "ad.state")
    assert trace["decision"] == "denied"
    assert trace["exact_deny"] is True
    assert trace["grants"] == []


def test_report_access_trace_fails_closed_when_allowed_report_has_no_atomic_grant() -> None:
    access = _access()
    access["reports"][0]["grants"] = []
    trace = report_access_trace(access, "ad.state")
    assert trace["decision"] == "denied"
    assert trace["grants"] == []
    assert "не вернул атомарную" in trace["explanation"]


def test_report_access_trace_rejects_invalid_and_unknown_keys() -> None:
    with pytest.raises(ValueError, match="invalid_report_key"):
        report_access_trace(_access(), "../ad.state")
    with pytest.raises(LookupError, match="report_not_found"):
        report_access_trace(_access(), "missing.report")


def test_report_access_trace_handler_uses_request_scoped_snapshot() -> None:
    from types import SimpleNamespace
    handler = SimpleNamespace()
    calls: list[str] = []
    sent: list[tuple[dict[str, object], HTTPStatus]] = []
    handler._access_decision = lambda: calls.append("access") or _access()
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    routes_reports._handle_v4_report_access_trace_api(handler, "/api/v1/reports/ad.state/access-trace")
    assert calls == ["access"]
    assert sent[0][1] == HTTPStatus.OK
    assert sent[0][0]["report"]["report_key"] == "ad.state"


def test_privileged_security_migration_does_not_rewrite_atomic_grants() -> None:
    migration = (
        Path(__file__).resolve().parents[2]
        / "config/postgres_migrations/057_privileged_security_category.sql"
    ).read_text(encoding="utf-8")
    lowered = migration.lower()
    assert "access_package_reports" not in lowered
    assert "access_report_assignments" not in lowered
    assert "{field_categories}" in migration
    assert "{field_categories}" in migration[
        migration.index("request_profile_json") :
    ]

    access = _access()
    access["reports"][0].update({
        "report_key": "ad.privileged",
        "name": "Privileged",
        "grants": [{
            "source_type": "direct",
            "source": "user:77",
            "scope": {"kind": "all"},
            "field_categories": ["identity_basic", "privilege", "technical"],
            "allowed_actions": ["view"],
        }],
    })
    trace = report_access_trace(access, "ad.privileged")
    assert trace["grants"][0]["field_categories"] == [
        "identity_basic", "privilege", "technical",
    ]

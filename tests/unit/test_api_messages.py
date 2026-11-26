from __future__ import annotations

import ast
import io
import json
import re
import threading
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.api.http_server import ProtectedHTTPServer, RequestHandler
from server.api.routes import auth
from server.sli.core.messages import (
    AUTH_ERRORS,
    LOGIN_INPUT_ERRORS,
    LOGIN_SERVICE_ERRORS,
    PLUGIN_SETTINGS_MESSAGE_CODES,
    REPORT_STATES,
    WORKSTATION_ERRORS,
    catalog,
    message,
    response_messages,
    select_locale,
)
from server.sli.reporting.v2.definition import ResultState, result

ROOT = Path(__file__).resolve().parents[2]


AD_REPORT_PREFIXES = ("reports.v2.ad.users.v2.", "reports.v2.ad.computers.v6.", "reports.v2.ad.infrastructure.", "reports.values.", "reports.boolean.")


def frontend_catalog(locale):
    source = (ROOT / f"frontend/src/i18n/{locale}.ts").read_text(encoding="utf-8")
    return {json.loads(key): json.loads(value) for key, value in re.findall(r'^\s*("(?:\\.|[^"\\])*"): ("(?:\\.|[^"\\])*")', source, re.MULTILINE)}


@pytest.mark.parametrize("locale", ["ru", "en"])
@pytest.mark.parametrize("params", ['{"status":"new"}', '{"population":"attention"}', '{"status":"active"}', '{"severity":"high"}', '{"risk":"accepted"}'])
def test_frontend_catalog_preserves_escaped_message_codes(locale, params):
    code = f"reports.v2.security.problems.presets.{params}"
    assert frontend_catalog(locale)[code] == catalog(locale)[code]


def test_catalog_completeness_and_frontend_wording():
    expected = set(AUTH_ERRORS.values()) | {"login.error.generic", "login.error.locked", "login.error.unavailable", "reports.renderer.error_gpo_snapshot"}
    expected |= set(WORKSTATION_ERRORS.values())
    expected |= PLUGIN_SETTINGS_MESSAGE_CODES
    expected |= {"events.unknown_type", "events.semantic.System:Service Control Manager:7036.title",
                 "events.semantic.Security:Microsoft-Windows-Eventlog:1104.title",
                 "events.semantic.Security:Microsoft-Windows-Eventlog:1104.summary",
                 "events.catalog_title", "events.participant_unknown"}
    expected |= {"domain_archive_must_be_boolean", "domain_archive_update_fields_invalid"}
    expected |= {"invalid_agent_registration_name", "agent_registration_name_mismatch"}
    expected |= {"backup.insufficient_backup_disk_space", "backup.insufficient_data_disk_space",
                 "backup.restore_volume_mismatch"}
    # Setup shares only these operational summaries, not all frontend labels.
    expected |= {f"setup.agentCollection.{state}" for state in (
        "current", "error", "partial", "unknown", "unavailable",
    )}
    expected |= {f"notifications.smtp.setup.{code}" for code in ("invalid", "unavailable", "conflict", "needs_save")}
    expected |= {f"reports.state.{state}" for state in REPORT_STATES}
    # Event search validation errors, snapshot/storage/history failures and legacy notices are shared API messages.
    expected |= {f"evsearch.{code}" for code in (
        "invalid_request", "unsupported_version", "invalid_period", "invalid_condition",
        "period_too_wide", "period_outside_scope",
        "unsupported_field", "unsupported_operator", "event_context_required", "unsupported_action",
        "policy_denied", "unsupported_question", "legacy_unsupported_filter", "legacy_ambiguous_filter",
        "legacy_identity_unresolved", "legacy_paging_reset",
        "invalid_cursor",
        "snapshot_expired", "snapshot_invalidated", "snapshot_limit_exceeded", "snapshot_timeout",
        "storage_integrity_error", "storage_limit_exceeded", "storage_timeout",
        "history_unavailable", "history_predicate_unavailable", "history_timeout",
        "history_integrity_error", "history_limit_exceeded",
    )}
    # T002 exposes these explicit, allowlisted reasons in both API locales.
    expected |= {f"reports.v2.ad.new-logon-pairs.limitations.{reason}" for reason in (
        "report_domain_not_configured", "domain_context_unavailable", "domain_controllers_missing",
        "users_context_missing", "computers_context_missing", "context_verification_failed",
        "context_read_failed", "history_not_enabled", "history_not_configured",
        "history_verification_failed", "history_read_failed", "read_cancelled", "read_timeout",
        "comparison_failed", "history_empty", "context_read_timeout", "context_read_cancelled",
        "computer_inventory_unavailable",
    )}
    # Shared API messages for the AD account registry; the other adAccounts
    # labels are frontend-only and must not expand the server catalog.
    expected |= {"adAccounts.denied", "adAccounts.operationsUnavailable", "adAccounts.permission",
        "adAccounts.keyUnavailable", "adAccounts.checkUnavailable", "adAccounts.error"}
    expected |= {f"reports.workstations.{reason}" for reason in (
        "source_timeout", "source_not_initialized", "source_access_denied", "source_unavailable",
    )}
    expected |= {f"reports.v2.workstations.{family}.{field}"
                 for family in ("logons", "processes", "usb", "protection")
                 for field in ("columns.host_name.label", "columns.agent_key.label", "detail.columns.agent_key.label")}
    # The workstation overview shares C01-C10 presentation and reason messages.
    expected |= {"workstations.overview." + field for field in (
        "title", "stations", "observed", "station", "os", "ou", "search", "checks", "unknown", "unnamed",
        "backToStation", "evidence", "sourceHash", "noSource", "noFindings", "details", "domain", "check",
    )}
    expected |= {"reports.v2.workstations.overview." + field for field in (
        "title", "columns.station_id.label", "detail.title", "metrics.stations.label", "metrics.observed.label",
        "intent.question", "intent.denominator", "intent.freshness_expectation",
        "params.period.label", "params.domain.label", "params.domain_id.label", "params.search.label",
        "params.ou.label", "params.check_id.label", "params.finding_id.label", "params.evidence_index.label",
    )}
    expected |= {f"reports.v2.workstations.overview.params.check_id.options.C{number:02}" for number in range(1, 11)}
    expected |= {f"workstations.checks.C{number:02}.{field}"
                 for number in range(1, 11) for field in ("title", "why", "action", "remediation")}
    expected |= {f"workstations.reasons.{reason}" for reason in (
        "protection_disabled", "protection_enabled", "local_admin_added", "password_failures", "suspicious_process_path",
        "service_or_task_changed", "removable_media_first_seen", "logon_outside_policy",
        "server_silent", "protection_stale", "workstation_silent", "source_missing",
        "coverage_incomplete", "baseline_unknown", "scope_denied", "data_stale", "not_collected",
        "local_admin_baseline_unknown", "local_admin_removed", "device_history_incomplete",
        "logon_policy_not_configured", "logon_type_unknown",
        # C05 native changes and the unknown service/task inventory baseline.
        "service_installed", "task_created", "task_deleted", "task_enabled", "task_disabled", "task_updated",
        "service_task_baseline_unknown",
    )}
    expected |= {f"workstations.logon_policy.{field}" for field in ("title", "description", "validation")}
    expected |= {f"workstations.directions.{direction}" for direction in ("on_station", "from_station")}
    expected.add("reports.file-audit.source_timeout")
    expected.add("workstations.process.signature_not_received")
    expected |= {"reports.v2.ad.users.v2." + suffix for suffix in (
        "views.all.title", "views.changes.columns.observed_at_utc.label", "views.changes.columns.actor.label",
        "params.as_of.label", "params.check.label", "params.account_state.label",
        "params.account_state.options.enabled", "params.account_state.options.disabled", "params.account_state.options.unknown",
    )}
    expected |= {"decoys.denied", "decoys.conflict", "decoys.failed"}
    expected |= {"watch.denied", "watch.conflict", "watch.failed"}
    expected |= {"decoys.id", "decoys.event_version", "decoys.version_missing", "notifications.delivery.delayed"}
    expected |= {
        "notifications.telegram.unavailable", "notifications.telegram.timeout", "notifications.telegram.invalid_proxy",
    }
    expected |= {f"notifications.problem{category}.{field}"
                 for category in ("", ".remote_access", ".account_decoy", ".file_decoy", ".account_watch")
                 for field in ("what", "action")}
    expected |= {f"reports.v2.notifications.deliveries.columns.{suffix}" for suffix in (
        "delivery_reason.label", "delay_minutes.label", "delivery_reason.labels.live",
        "delivery_reason.labels.pipeline_delay", "delivery_reason.labels.historical_replay",
        "delivery_reason.labels.history_import", "result_code.labels.historical_replay", "result_code.labels.history_import",
    )}
    # T011 shares only the new rule names and inline-detail labels, not all legacy metadata.
    expected |= {f"reports.v2.security.rule-quality.names.{name}" for name in (
        "password_spray", "password_brute", "disabled_logon", "account_decoy", "account_watch",
        "file_decoy", "file_ransom", "file_acl", "nps_denials", "unknown",
        "audit_controls_changed", "privileged_group_member_added", "scheduled_task_created",
        "metadata.security_incident", "metadata.security_exposure", "metadata.control_gap",
    )}
    expected |= {f"reports.v2.security.rule-quality.{field}" for field in (
        "columns.rule_name.label", "detail.title", "detail.columns.rule_code.label",
        "detail.columns.policies.label", "detail.columns.admitted_policies.label", "detail.columns.managed_policies.label",
    )}
    # RANSOM details extend the shared catalog with an explicit set of messages.
    expected |= {f"file-audit.ransom.{field}" for field in (
        "title", "explanation", "threshold", "window", "files", "episode",
        "start", "end", "generation", "reason", "approved_by", "active_from",
        "active_to", "incomplete",
    )}
    expected |= {f"file-audit.ransom.state.{state}" for state in (
        "not_evaluated", "details_unavailable", "denied", "not_applicable",
        "admitted", "diagnostic", "excluded",
    )}
    # Problem identity and occurrence messages are shared with the frontend.
    expected |= {
        "security.problems.identity.name", "security.problems.identity.sources",
        "security.problems.identity.sources_partial", "security.problems.identity.unavailable",
        "security.problems.assignee.unassigned",
        "home.queue.occurrences.one", "home.queue.occurrences.few",
        "home.queue.occurrences.many", "home.queue.occurrences.other",
    }
    frontend_only_user_labels = tuple(f"reports.ad.users.{section}." for section in (
        "deviation", "list", "card", "event",
    ))
    expected |= {key for key in frontend_catalog("ru") if key.startswith((
        "reports.v2.security.problems.", "security.problems.status.", "security.problems.entity.",
        "security.problems.actor.", "security.problems.presentation.", "security.problems.ad_hardening.", "investigations.caseStatus.", "reports.ad.checks.",
        "reports.ad.users.", "events.semantic.", "reports.v2.file-audit.overview.limitations.",
    )) and not key.startswith(frontend_only_user_labels)}
    # AD report metadata codes mirror the frontend keys; test_report_metadata_codes.py proves they are complete.
    expected |= {code for code in catalog("ru") if code.startswith(AD_REPORT_PREFIXES)}
    expected |= {f"access.builtin.package.{key}.{field}"
                 for key in ("security_operator", "security_analyst", "ad_auditor", "project_operations", "access_admin")
                 for field in ("name", "description")}
    expected |= {f"access.builtin.report.{key}.purpose" for key in (
        "security.queue", "events.explorer", "investigations.workspace", "ad.state", "ad.privileged", "ad.gpo.review",
        "operations.readiness", "access.center", "vpn.audit", "ad.users", "ad.computers", "ad.computers.v2",
        "ad.computers.v4", "ad.computers.v5", "ad.computers.v6", "ad.users.v2", "ad.gpo.v2", "security.events.chains",
        "notifications.channels", "notifications.deliveries", "decoys.registry", "watch.registry", "workstations.overview",
    )}
    builtin_name_keys = (
        "security.queue", "events.explorer", "investigations.workspace", "ad.state", "ad.privileged", "ad.gpo.review",
        "operations.readiness", "access.center", "vpn.audit", "ad.users", "ad.computers", "ad.computers.v2",
        "ad.computers.v4", "ad.computers.v5", "ad.computers.v6", "ad.users.v2", "ad.gpo.v2", "ad.computer-logons",
        "security.events.chains", "notifications.channels", "notifications.deliveries", "decoys.registry", "watch.registry", "workstations.overview",
    )
    file_audit_keys = tuple("file-audit." + key for key in (
        "overview", "actions", "mass-operations", "permission-changes", "access-denials", "out-of-hours", "permissions", "audit-state"))
    expected |= {f"access.builtin.report.{key}.name" for key in (*builtin_name_keys, *file_audit_keys)}
    expected |= {f"access.builtin.report.{key}.purpose" for key in ("ad.computer-logons", *file_audit_keys)}
    expected |= {"access.builtin.report." + key for key in (
        "ad.state.name.alias.seed035", "ad.state.purpose.alias.seed035", "ad.gpo.review.name.alias.seed035",
        "ad.gpo.review.purpose.alias.seed035", "ad.users.v2.name.alias.seed110", "ad.users.v2.purpose.alias.seed110",
        "ad.computers.v6.name.alias.seed113", "notifications.deliveries.purpose.alias.seed225",
        "ad.computer-logons.name.alias.seed126", "ad.computer-logons.purpose.alias.seed126",
        "notifications.deliveries.purpose.alias.smtp226", "notifications.deliveries.purpose.alias.telegram227",
    )}
    # The legacy API still supplies this wording to clients that use the old problem presentation.
    legacy_problem_codes = {f"security.problems.presentation.{field}" for field in (
        "watch_limitation", "decoy_limitation", "default_next", "audit_limitations", "wording_limitation",
    )}
    # Home period facts are formatted on the server, like notification text.
    def is_server_rendered_message(code):
        return code.startswith(("notifications.message.", "notifications.bot.", "home.period.problem."))

    def is_domain_change_action(code):
        return code.startswith("reports.v2.security.events.chains.actions.")

    assert set(catalog("ru")) == set(catalog("en"))
    assert {
        code for code in catalog("ru") if not is_server_rendered_message(code) and not is_domain_change_action(code)
    } == expected | legacy_problem_codes
    attribute_change = "reports.v2.security.events.chains.actions.5136"
    for locale in ("ru", "en"):
        frontend = frontend_catalog(locale)
        assert attribute_change in catalog(locale)
        assert message(attribute_change, locale=locale)["text"] == frontend[attribute_change]
        for code, text in catalog(locale).items():
            assert text
            if code in legacy_problem_codes or is_server_rendered_message(code):
                assert code not in frontend
                assert message(code, locale=locale)["text"] == text
            else:
                assert frontend[code] == text
            assert sorted(re.findall(r"\{\w+\}", text)) == sorted(re.findall(r"\{\w+\}", catalog("ru")[code]))


@pytest.mark.parametrize("locale", ["ru", "en"])
@pytest.mark.parametrize("error,code", WORKSTATION_ERRORS.items())
def test_workstation_errors_are_localized_without_disclosing_data(locale, error, code):
    payload = response_messages({"error": error}, locale)
    assert payload == {"error": error, "message": message(code, locale=locale)}


@pytest.mark.parametrize(("header", "expected"), [
    (None, "ru"), ("", "ru"), ("fr", "ru"), ("en-US", "en"),
    ("ru;q=0.3,en-GB;q=0.9", "en"), ("en;q=0,ru;q=0.5", "ru"),
    ("en;q=bad,ru", "ru"), ("en;q=2,ru", "ru"), ("ru,en", "ru"),
    ("en;q=nan,ru", "ru"),
])
def test_locale_negotiation(header, expected):
    assert select_locale(header) == expected


def test_explicit_locale_and_default():
    assert select_locale("en", user_locale="ru") == "ru"
    assert select_locale("ru", user_locale="en") == "en"
    assert select_locale("en", user_locale="unsupported") == "en"
    assert message("reports.state.empty", locale="unsupported")["text"] == catalog("ru")["reports.state.empty"]


def test_message_interpolates_only_parameters_and_rejects_unknown_code():
    assert message("login.error.retryAfter", {"seconds": 3}, locale="en") == {
        "code": "login.error.retryAfter", "params": {"seconds": 3},
        "text": catalog("en")["login.error.retryAfter"].replace("{seconds}", "3"),
    }
    assert "{seconds}" in message("login.error.retryAfter")["text"]
    with pytest.raises(KeyError):
        message("unknown.code")


def test_response_preserves_legacy_contract_and_does_not_mutate_input():
    payload = {"error": "login_temporarily_locked", "retry_after_seconds": 2.1}
    translated = response_messages(payload, "en")
    assert translated["message"] == message("login.error.retryAfter", {"seconds": 3}, locale="en")
    assert translated["retry_after_seconds"] == 2.1
    assert "message" not in payload
    assert response_messages({"error": "login_temporarily_locked"})["message"]["code"] == "login.error.locked"
    assert response_messages({"error": "unknown"}) == {"error": "unknown"}
    assert response_messages({"error": {}, "state": []}, login=True, report=True) == {"error": {}, "state": []}


@pytest.mark.parametrize("error", sorted(LOGIN_INPUT_ERRORS))
def test_body_errors_are_migrated_only_on_login(error):
    assert response_messages({"error": error}, "en", login=True)["message"] == message("login.error.generic", locale="en")
    assert response_messages({"error": error}, "en") == {"error": error}


@pytest.mark.parametrize("error", sorted(LOGIN_SERVICE_ERRORS))
def test_service_errors_are_migrated_only_on_login(error):
    assert response_messages({"error": error}, "en", login=True)["message"] == message("login.error.unavailable", locale="en")
    assert response_messages({"error": error}, "en") == {"error": error}


def handler(path, locale="en"):
    fake = RequestHandler.__new__(RequestHandler)
    fake.path = path
    fake.headers = Message()
    fake.headers["Accept-Language"] = locale
    fake.wfile = io.BytesIO()
    fake.sent_headers = {}
    fake.send_response = lambda status: setattr(fake, "sent_status", status)
    fake.send_header = lambda name, value: fake.sent_headers.update({name: value})
    fake.end_headers = lambda: None
    return fake


@pytest.mark.parametrize("path", ["/api/v1/access/grant-options", "/api/v1/reports/catalog"])
def test_http_localizes_builtin_purpose_without_rewriting_custom_metadata(path):
    purpose = "Что произошло, влияние, гипотеза и безопасный следующий шаг"
    payload = {"items": [{"report_key": "security.queue", "version": 1, "name": "Название владельца", "purpose": purpose},
                         {"report_key": "custom", "version": 1, "name": "Название владельца", "purpose": purpose}]}
    fake = handler(path)
    fake._send_json(payload)
    actual = json.loads(fake.wfile.getvalue())
    assert actual["items"][0]["purpose"] == "What happened, its impact, the hypothesis and a safe next step"
    assert actual["items"][0]["name"] == "Название владельца"
    assert actual["items"][1] == payload["items"][1]


def test_http_localizes_package_choices_and_history_but_keeps_user_text():
    payload = {"packages": [{"package_key": "security_operator", "name": "ИБ · операторы",
                             "description": "Очередь проблем, влияние, гипотезы и безопасные действия"}],
               "package_assignments": [{"package_key": "security_operator", "package_name": "ИБ · операторы",
                                        "business_reason": "ИБ · операторы", "effect": "deny"}]}
    fake = handler("/api/v1/access/subjects?account_type=people")
    fake._send_json(payload)
    actual = json.loads(fake.wfile.getvalue())
    assert actual["packages"][0]["name"] == "InfoSec operators"
    assert actual["package_assignments"][0]["package_name"] == "InfoSec operators"
    assert actual["package_assignments"][0]["business_reason"] == "ИБ · операторы"
    assert actual["package_assignments"][0]["effect"] == "deny"


@pytest.mark.parametrize("state", sorted(state.value for state in ResultState))
@pytest.mark.parametrize("locale", ["ru", "en"])
def test_report_state_builder_and_http_serialization(state, locale):
    payload = result(SimpleNamespace(key="synthetic.report"), state=state)
    assert payload["state_message"]["code"] == f"reports.state.{state}"
    fake = handler("/api/v2/reports/synthetic.report/data", locale)
    fake._send_json(payload)
    actual = json.loads(fake.wfile.getvalue())
    assert actual["state"] == state
    assert actual["state_message"] == message(f"reports.state.{state}", locale=locale)
    assert actual["state_details"] == payload["state_details"]
    assert int(fake.sent_headers["Content-Length"]) == len(fake.wfile.getvalue())


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_legacy_unavailable_state_still_gets_a_localized_message(locale):
    payload = response_messages({"state": "unavailable"}, locale, report=True)
    assert payload["state_message"] == message("reports.state.unavailable", locale=locale)


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_state_message_follows_coverage_promotion_and_retains_details(locale):
    payload = result(SimpleNamespace(key="synthetic.report"), state="empty", coverage={
        "state": "processing", "missing_sources": ["fixture-source"], "missing_domains": [7],
    })
    actual = response_messages(payload, locale, report=True)
    assert actual["state"] == "processing"
    assert actual["state_message"] == message("reports.state.processing", locale=locale)
    assert actual["state_details"]["missing_sources"] == ["fixture-source"]
    assert actual["state_details"]["missing_domains"] == [7]


def test_http_refreshes_state_message_after_projection_and_localizes_gpo_failure():
    fake = handler("/api/v2/reports/synthetic.report/data")
    payload = result(SimpleNamespace(key="synthetic.report"), state="ok")
    payload["state"] = "denied"
    fake._send_json(payload, HTTPStatus.FORBIDDEN)
    assert json.loads(fake.wfile.getvalue())["state_message"] == message("reports.state.denied", locale="en")
    fake = handler("/api/v2/reports/synthetic.report/data")
    fake._send_json({"error": "gpo_snapshot_unavailable", "state": "unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
    assert json.loads(fake.wfile.getvalue())["message"] == message("reports.renderer.error_gpo_snapshot", locale="en")


@pytest.mark.parametrize(("failure", "error", "status"), [
    ("disabled", "authentication_not_enabled", 409),
    ("transport", "secure_transport_required", 403),
    ("locked", "login_temporarily_locked", 429),
    ("account_locked", "login_temporarily_locked", 429),
    ("credentials", "invalid_credentials", 401),
    ("origin", "cross_origin_request_rejected", 403),
])
@pytest.mark.parametrize("locale", ["ru", "en"])
def test_login_failures_through_actual_http_serializer(monkeypatch, failure, error, status, locale):
    fake = handler("/api/auth/login", locale)
    fake.client_address = ("192.0.2.1", 12345)
    calls = []
    audits = []
    fake.server = SimpleNamespace(
        login_allowed=lambda address: (failure != "locked", 7),
    )
    fake._secure_transport = lambda: failure != "transport"
    fake._read_json_body = lambda: {"username": "synthetic-user", "password": "fixture-placeholder"}

    def origin_check():
        if failure == "origin":
            fake._send_json({"error": "cross_origin_request_rejected"}, HTTPStatus.FORBIDDEN)
            return False
        return True

    fake._check_request_origin = origin_check
    monkeypatch.setenv("ADLOG_AUTH_ALLOW_INSECURE_HTTP", "0")
    monkeypatch.setattr(auth, "auth_required", lambda: failure != "disabled")

    def audit(**kwargs):
        audits.append(kwargs)
        if kwargs.get("outcome") == "failed":
            calls.append("failure")

    monkeypatch.setattr(auth, "record_auth_audit", audit)
    def authenticate(*args):
        calls.append("authenticate")
        if failure == "account_locked":
            raise auth.LoginThrottled(7)

    monkeypatch.setattr(auth, "authenticate_password", authenticate)
    auth._handle_login(fake)
    payload = json.loads(fake.wfile.getvalue())
    assert fake.sent_status == status
    assert payload["error"] == error
    params = {"seconds": 7} if failure in {"locked", "account_locked"} else {}
    assert payload["message"] == message(AUTH_ERRORS[error], params, locale=locale)
    if failure in {"locked", "account_locked"}:
        assert fake.sent_headers["Retry-After"] == "7"
        assert payload["retry_after_seconds"] == 7
    expected_calls = ["authenticate", "failure"] if failure == "credentials" else ["authenticate"] if failure == "account_locked" else []
    assert calls == expected_calls
    if failure in {"credentials", "locked", "account_locked"}:
        assert audits == [{"actor_type": "anonymous", "actor_id": None, "action": "login",
                           "outcome": "failed" if failure == "credentials" else "throttled",
                           "remote_address": "192.0.2.1"}]
    else:
        assert audits == []


def test_successful_login_keeps_session_and_remember_contract(monkeypatch):
    fake = handler("/api/auth/login")
    fake.client_address = ("192.0.2.1", 12345)
    fake.server = ProtectedHTTPServer.__new__(ProtectedHTTPServer)
    fake.server.login_lock = threading.Lock()
    fake.server.login_failure_window_seconds = 900
    fake.server.max_login_failures = 3
    fake.server.login_attempts = {}
    assert fake.server.login_allowed("192.0.2.1") == (True, 0)
    fake._secure_transport = lambda: True
    fake._check_request_origin = lambda: True
    fake._read_json_body = lambda: {"username": "synthetic-user", "password": "fixture-placeholder", "remember": True}
    fake._public_principal = lambda principal: {"id": principal["id"], "role": principal["role"]}
    principal = {"id": 1, "role": "viewer"}
    monkeypatch.setattr(auth, "auth_required", lambda: True)
    monkeypatch.setattr(auth, "authenticate_password", lambda *args: principal)
    audits = []
    monkeypatch.setattr(auth, "record_auth_audit", lambda **kwargs: audits.append(kwargs))

    def issue_session(value, *, remember):
        assert value == principal and remember is True
        return "synthetic-session-placeholder"

    monkeypatch.setattr(auth, "issue_session", issue_session)
    auth._handle_login(fake)
    assert fake.sent_status == HTTPStatus.OK
    assert json.loads(fake.wfile.getvalue()) == {"authenticated": True, "principal": principal}
    # Successful logins consume the reserved budget without resetting earlier attempts.
    assert len(fake.server.login_attempts["192.0.2.1"]) == 2
    assert audits == [{"actor_type": "session", "actor_id": 1, "action": "login",
                       "remote_address": "192.0.2.1"}]
    assert "Max-Age=1209600; HttpOnly; SameSite=Strict; Secure" in fake.sent_headers["Set-Cookie"]


def test_no_hardcoded_russian_in_migrated_scopes():
    scopes = {
        "server/sli/core/messages.py": None,
        "server/api/routes/reports_v2.py": None,
        "server/api/routes/auth.py": "_handle_login",
        "server/api/http_server.py": "_send_json",
        "server/sli/reporting/v2/definition.py": "result",
        "frontend/src/i18n/messages.ts": None,
        "frontend/src/design-system/StateView.tsx": None,
        "frontend/src/design-system/ReportLayout.tsx": None,
        "frontend/src/app/report-v2/ReportRenderer.tsx": None,
        "server/sli/reporting/v2/reports/security_problems.py": None,
        "frontend/src/app/security-problems-report.ts": None,
        "frontend/src/app/case-status.ts": None,
        "frontend/src/app/case-page.tsx": None,
        "frontend/src/app/cases.tsx": None,
        "frontend/src/app/investigation-workspace.tsx": None,
    }
    for filename, function in scopes.items():
        source = (ROOT / filename).read_text(encoding="utf-8")
        if function:
            node = next(node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef) and node.name == function)
            source = ast.get_source_segment(source, node)
        literals = re.finditer(r'''(["'`])(?:\\.|(?!\1)[^\\])*?\1''', source)
        assert not any(re.search(r"[\u0400-\u04ff]", match[0]) for match in literals), filename
    login_source = (ROOT / "web/app/sli-login.js").read_text(encoding="utf-8").split("  const errorMessage =", 1)[1]
    assert not re.search(r"[\u0400-\u04ff]", login_source)
    error_source = (ROOT / "frontend/src/api/client.ts").read_text(encoding="utf-8").split("async function apiResponseError", 1)[1].split("async function requestMutation", 1)[0]
    assert not re.search(r"[\u0400-\u04ff]", error_source)


@pytest.mark.parametrize("locale", ["ru", "en"])
@pytest.mark.parametrize("status", [code.removeprefix("investigations.caseStatus.") for code in catalog("ru") if code.startswith("investigations.caseStatus.")])
@pytest.mark.parametrize("path", ["/api/v1/investigation-cases", "/api/v1/investigations", "/api/v1/investigations/7", "/api/v1/investigations/7/status"])
def test_case_status_envelopes_through_http_preserve_case_and_evidence(status, locale, path):
    item = {"id": 7, "status": status, "title": "Synthetic case", "notes": [{"id": 8, "status": "new", "body": "source observation"}]}
    for payload in (item, {"items": [item]}, {"item": item}):
        fake = handler(path, locale)
        fake._send_json(payload)
        actual = json.loads(fake.wfile.getvalue())
        case = actual["items"][0] if "items" in actual else actual.get("item", actual)
        assert case["status_message"] == message(f"investigations.caseStatus.{status}", locale=locale)
        assert {key: value for key, value in case.items() if key != "status_message"} == item
        assert "status_message" not in item
    assert response_messages(item, locale) == item
    assert response_messages({"id": 7, "status": "future"}, locale, investigation=True) == {"id": 7, "status": "future"}

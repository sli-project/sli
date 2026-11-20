import json
from datetime import datetime, timedelta, timezone
from email.message import Message
from http.client import BadStatusLine
from io import BytesIO
from urllib.error import HTTPError
from urllib.request import HTTPSHandler
from urllib.response import addinfourl
from uuid import UUID

import pytest

from scripts.maintenance import beta_acceptance as acceptance


ORIGIN = "https://sli.example.test"
AGENT = UUID(int=1)
NOW = datetime(2026, 11, 18, 12, tzinfo=timezone.utc)
COMMIT = "b" * 40
REPORTS = ("ad.infrastructure", "ad.users.v2", "ad.computers.v6", "ad.gpo.v2")


def stamp(moment):
    return moment.isoformat()


@pytest.fixture
def run(monkeypatch):
    started = NOW - timedelta(days=9)
    exercise = NOW - timedelta(days=1)
    observations = {
        "origin": ORIGIN,
        "domain_id": 1,
        "install": {
            "clean_debian_13": True, "public_readme_only": True, "commands": 3, "file_edits": 0,
            "started_at": stamp(started), "ready_at": stamp(started + timedelta(minutes=30)),
        },
        "first_login": {"one_time_code_used": True, "dotnet_screen_opened": True},
        "agent": {
            "id": str(AGENT), "msi_count": 1, "commands": 1, "started_at": stamp(started),
            "collecting_at": stamp(started + timedelta(minutes=10)),
        },
        "ad": {
            "observed_at": stamp(started + timedelta(minutes=15)),
            "rows": dict.fromkeys(REPORTS, 1),
        },
        "exercises": [
            {"scenario": i, "finding_id": i, "started_at": stamp(exercise + timedelta(minutes=i * 6)),
             "on_home_at": stamp(exercise + timedelta(minutes=i * 6 + 5)), "groups": 1,
             "title": "Проблема в LAB", "what": "Событие получено", "action": "Проверьте журнал"}
            for i in range(1, 11)
        ],
        "quiet": {
            "clean_install_without_attacks": True, "observed_at": stamp(exercise),
            "hygiene": 10, "other": 0,
        },
        "storage": {
            "retention_elapsed_at": stamp(NOW - timedelta(days=7)),
            "samples": [
                {"at": stamp(NOW - timedelta(days=day)), "bytes": 1000 + day}
                for day in range(7, 0, -1)
            ],
        },
        "upgrade": {
            "command": "apt upgrade", "exit_code": 0, "manual_steps": 0,
            "before_commit": "a" * 40, "after_commit": COMMIT,
            "records": 2, "before_sha256": "1" * 64, "after_sha256": "1" * 64,
        },
        "menu": {
            "commit": COMMIT,
            "pages": {
                key: {"data": True, "action_phrases": 0, "load_errors": 0, "completeness_labels": 0}
                for key in acceptance.menu_entries()
            },
        },
    }
    responses = {
        "/api/v1/domains": {"items": [{"id": 1}]},
        "/api/health": {"status": "ok", "runtime_identity": {"git_commit": COMMIT}},
        "/api/health/ready": {"ready": True},
        "/api/v1/overview": {"agent_collection": {"checked_at_utc": stamp(NOW), "items": [
            {"id": str(AGENT), "state": "current", "connection": "online", "modules": [
                {"module_id": "sli.windows.ad-dc", "channels": [
                    {"channel": "Security", "state": "current", "last_import_at": stamp(NOW)}
                ]}
            ]},
        ]}},
        "/api/storage/lifecycle": {"backend": "postgres",
                                   "latest_snapshot": {"captured_at": stamp(NOW), "database_bytes": 1000}},
        **{f"/api/v2/reports/{key}/data": {"report_key": key, "state": "ok", "items": [{"row_id": "one"}]}
           for key in REPORTS},
    }

    def get(path, params=None):
        if path == "/api/v1/notification-channels/workspace":
            return {"items": [{"finding_id": params["finding_id"], "state": "accepted",
                               "channel": "telegram", "object_kind": "semantic_finding",
                               "created_at": stamp(NOW - timedelta(hours=8))}], "has_more": False}
        return responses[path]

    monkeypatch.setattr(acceptance, "utc_now", lambda: NOW)
    return observations, responses, get


def test_cli_prints_nine_green_rows_for_complete_observations(run, tmp_path, monkeypatch, capsys):
    observations, _, get = run
    source = tmp_path / "observations.json"
    source.write_text(json.dumps(observations), encoding="utf-8")
    monkeypatch.setenv("SLI_OPERATOR_TOKEN", "fixture-token")
    monkeypatch.setattr(acceptance.Api, "get", lambda self, *args: get(*args))

    assert acceptance.main([
        "--api-url", ORIGIN, "--domain-id", "1", "--agent-id", str(AGENT), "--observations", str(source),
    ]) == 0
    output = capsys.readouterr().out
    assert output.count("| Зелёная |") == 9
    assert "9 из 9" in output
    assert "fixture-token" not in output


def test_incomplete_evidence_and_live_error_stay_red_without_hiding_other_rows(run):
    observations, responses, get = run
    observations.pop("first_login")
    observations["exercises"][0]["groups"] = 2
    observations["exercises"][1]["on_home_at"] = stamp(NOW)
    observations["quiet"]["observed_at"] = stamp(NOW)
    observations["storage"]["samples"].pop(1)
    observations["upgrade"]["after_sha256"] = "2" * 64
    observations["menu"]["pages"].pop("workspace")
    responses["/api/v2/reports/ad.users.v2/data"] = {"state": "error", "reason": "fixture-sensitive"}
    rows = acceptance.run_checks(get, observations, 1, AGENT)

    assert [passed for passed, _ in rows] == [True, False, True, False, False, False, False, False, False]
    assert "/api/auth/bootstrap" in rows[1][1]
    assert "ad.users.v2" in rows[3][1]
    assert "workspace" in rows[8][1]
    assert "fixture-sensitive" not in acceptance.table(rows)


def test_receipt_for_different_finding_and_old_storage_sample_are_insufficient(run):
    observations, responses, get = run
    responses["/api/storage/lifecycle"]["latest_snapshot"]["captured_at"] = stamp(NOW - timedelta(days=3))

    def wrong_finding(path, params=None):
        payload = get(path, params)
        if path.endswith("/workspace"):
            payload["items"][0]["finding_id"] += 100
        return payload

    rows = acceptance.run_checks(wrong_finding, observations, 1, AGENT)
    assert not rows[4][0]
    assert not rows[6][0]


def test_one_telegram_receipt_cannot_pass_two_attempts_for_same_finding(run):
    observations, _, get = run
    observations["exercises"][0]["finding_id"] = observations["exercises"][1]["finding_id"]
    rows = acceptance.run_checks(get, observations, 1, AGENT)
    assert rows[4] == (False, "Главная, группировка, тексты, время или Telegram не подтверждены для сценариев 1.")


def test_storage_checks_subsequent_growth_even_when_final_size_is_lower(run):
    observations, responses, get = run
    for sample, size in zip(observations["storage"]["samples"], [1020, 200, 300, 400, 600, 800, 900]):
        sample["bytes"] = size
    rows = acceptance.run_checks(get, observations, 1, AGENT)
    assert not rows[6][0]
    assert "Объём PostgreSQL растёт" in rows[6][1]


def test_bad_observations_still_print_all_rows(monkeypatch, tmp_path, capsys):
    observations = tmp_path / "observations.json"
    observations.write_text("{broken", encoding="utf-8")
    monkeypatch.delenv("SLI_OPERATOR_TOKEN", raising=False)
    assert acceptance.main(["--api-url", ORIGIN, "--domain-id", "1", "--observations", str(observations)]) == 1
    result = capsys.readouterr()
    assert result.out.count("| Красная |") == 9
    assert "0 из 9" in result.out
    assert "{broken" not in result.out + result.err


def test_https_only_and_redirect_refuses_to_forward_token(monkeypatch):
    with pytest.raises(acceptance.CheckFailed):
        acceptance.Api("http://sli.example.test", "fixture-token")
    api = acceptance.Api(ORIGIN, "fixture-token")
    assert any(isinstance(handler, acceptance.NoRedirect) for handler in api.opener.handlers)

    def redirect(request):
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") == "Bearer fixture-token"
        raise HTTPError(request.full_url, 302, "fixture-sensitive", {}, None)

    monkeypatch.setattr(api.opener, "open", redirect)
    with pytest.raises(acceptance.CheckFailed, match="HTTP 302"):
        api.get("/api/health")


class FixtureHttps(HTTPSHandler):
    handler_order = 400

    def __init__(self, handle):
        super().__init__()
        self.handle = handle

    def https_open(self, request):
        status, payload, headers = self.handle(request)
        message = Message()
        for name, value in headers.items():
            message[name] = value
        response = addinfourl(BytesIO(json.dumps(payload).encode()), message, request.full_url, status)
        response.msg = "fixture"
        return response


def test_owner_uses_normal_login_cookie_and_logs_out_its_session_only():
    api = acceptance.Api(ORIGIN, "adl_fixture")
    visited = []

    def handle(request):
        visited.append(request.full_url)
        assert request.get_header("Authorization") is None
        if request.full_url.endswith("/login"):
            assert request.get_method() == "POST"
            assert request.get_header("Origin") == ORIGIN
            assert json.loads(request.data) == {"username": "platform-owner", "password": "fixture-password"}
            return 200, {"authenticated": True, "principal": {
                "username": "platform-owner", "type": "session", "role": "admin",
            }}, {"Set-Cookie": "adlog_session=fixture-cookie; Path=/; Secure; HttpOnly; SameSite=Strict"}
        assert request.get_header("Cookie") == "adlog_session=fixture-cookie"
        if request.full_url.endswith("/logout"):
            assert request.get_method() == "POST"
            assert request.get_header("Origin") == ORIGIN
            return 200, {"status": "ok"}, {}
        return 302, {"fixture-cookie": "fixture-password"}, {"Location": "https://other.example.test/"}

    api.opener.add_handler(FixtureHttps(handle))
    api.logout_owner()
    assert visited == []
    api.login_owner("fixture-password")
    with pytest.raises(acceptance.CheckFailed, match=r"^HTTP 302$"):
        api.get("/api/health")
    api.logout_owner()
    api.logout_owner()
    assert visited == [ORIGIN + path for path in ("/api/auth/login", "/api/health", "/api/auth/logout")]


@pytest.mark.parametrize("status", [401, 403])
def test_reports_owner_login_http_error_without_credentials_or_session(monkeypatch, capsys, status):
    requests = []

    def handle(request):
        requests.append(request.full_url)
        return status, {"error": "fixture-password fixture-cookie"}, {
            "Set-Cookie": "adlog_session=fixture-cookie; Path=/; Secure",
        }

    api = acceptance.Api(ORIGIN, "")
    api.opener.add_handler(FixtureHttps(handle))
    monkeypatch.setattr(acceptance, "Api", lambda *_: api)
    monkeypatch.setenv("SLI_ACCEPTANCE_OWNER_PASSWORD", "fixture-password")
    monkeypatch.delenv("SLI_OPERATOR_TOKEN", raising=False)
    assert acceptance.main(["--api-url", ORIGIN, "--domain-id", "1"]) == 1
    captured = capsys.readouterr()
    assert captured.out.count("| Красная |") == 9
    assert f"HTTP {status}" in captured.err
    assert "fixture-password" not in captured.out + captured.err
    assert "fixture-cookie" not in captured.out + captured.err
    assert requests == [ORIGIN + "/api/auth/login"]


def test_ad_and_notifications_keep_authorization_errors_in_the_table(run):
    observations, _, get = run

    def restricted_get(path, params=None):
        if path.startswith("/api/v2/reports/"):
            raise acceptance.AuthorizationFailed("HTTP 401. SLI требует аутентификацию.")
        if path == "/api/v1/notification-channels/workspace":
            raise acceptance.AuthorizationFailed("HTTP 403. SLI отказал в доступе.")
        return get(path, params)

    rows = acceptance.run_checks(restricted_get, observations, 1, AGENT)
    assert not rows[3][0] and "HTTP 401" in rows[3][1]
    assert not rows[4][0] and "HTTP 403" in rows[4][1]


@pytest.mark.parametrize(("snapshot_domain", "accessible_domains", "accepted"), [
    (2, [1], False),
    (1, [1, 2], True),
    (None, [1, 2], False),
    (None, [2], False),
    (None, [1], True),
])
def test_gpo_rows_only_count_for_the_lab_domain(run, snapshot_domain, accessible_domains, accepted):
    observations, responses, get = run
    responses["/api/v1/domains"] = {"items": [{"id": item} for item in accessible_domains]}
    if snapshot_domain is not None:
        responses["/api/v2/reports/ad.gpo.v2/data"]["coverage"] = {"domain_id": snapshot_domain}
    passed, evidence = acceptance.run_checks(get, observations, 1, AGENT)[3]
    assert passed is accepted
    if not accepted:
        assert "GPO" in evidence and "LAB" in evidence


@pytest.mark.parametrize("malformed_http", [False, True])
def test_logout_rejects_invalid_confirmation_without_showing_the_response(malformed_http):
    api = acceptance.Api(ORIGIN, "")

    def handle(request):
        if request.full_url.endswith("/login"):
            return 200, {"authenticated": True, "principal": {
                "username": "platform-owner", "type": "session", "role": "admin",
            }}, {"Set-Cookie": "adlog_session=fixture-cookie; Path=/; Secure"}
        if malformed_http:
            raise BadStatusLine("fixture-sensitive")
        return 200, {"status": "fixture-sensitive"}, {}

    api.opener.add_handler(FixtureHttps(handle))
    api.login_owner("fixture-password")
    with pytest.raises(acceptance.CheckFailed) as error:
        api.logout_owner()
    assert "fixture-sensitive" not in str(error.value)
    assert not list(api.cookies)

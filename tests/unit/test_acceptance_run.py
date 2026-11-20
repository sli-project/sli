from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.maintenance import acceptance_run as acceptance

NOW = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)
STAMP = "20261007T110000.000000Z"


class FakeProbes:
    def __init__(self, settings):
        self.settings = settings
        self.calls = []
        self.rows = [{"ID": f"{index + 1:064x}", "Service": service,
                      "State": "exited" if service == "migrate" else "running",
                      "Health": "" if service == "migrate" else "healthy", "ExitCode": 0}
                     for index, service in enumerate(settings.services)]
        self.responses = {
            "/api/health": (200, {"status": "ok"}),
            "/api/health/live": (200, {"status": "ok"}),
            "/api/health/ready": (200, {"ready": True}),
            "/api/auth/login": (401, {"error": "invalid_credentials"}),
            **{f"/api/v2/reports/{key}/data?limit=1": (200, {"state": "empty"}) for key in settings.reports},
        }
        self.logs = "worker completed\n"
        self.project_label = settings.project
        self.command_error = None

    def compose(self, arguments):
        self.calls.append(arguments)
        return json.dumps(self.rows)

    def command(self, arguments):
        self.calls.append(arguments)
        if self.command_error:
            raise self.command_error
        if arguments[1] == "inspect":
            return json.dumps({"com.docker.compose.project": self.project_label})
        assert arguments[1] == "logs"
        return self.logs

    def http(self, path, **kwargs):
        self.calls.append((path, kwargs))
        return self.responses[path]


@pytest.fixture
def setup(tmp_path):
    backup_root = tmp_path / "backups"
    folder = backup_root / STAMP
    (folder / "postgres").mkdir(parents=True)
    (folder / "postgres/toc.dat").write_bytes(b"fake-toc")
    for name in ("history", "warm"):
        (folder / f"{name}.zip").write_bytes(b"fake-archive")
    manifest = {
        "format_version": 1, "status": "success", "backup_id": STAMP,
        "completed_at_utc": "2026-10-07T11:30:00+00:00",
        "components": {"postgres": {"size_bytes": 8}, **{
            name: {"size_bytes": 12, "archive": f"{name}.zip"} for name in ("history", "warm")}},
    }
    manifest_path = folder / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    receipt = {
        "format_version": 1, "status": "passed", "source_project": "sli-c01-test",
        "target_project": "sli-c01-restore", "backup_id": STAMP,
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "completed_at_utc": "2026-10-07T11:50:00+00:00", "cleanup_passed": True,
        "fresh_password_login_verified": True,
        "components": {name: {"status": "passed", "counts_match": True, "ledger_match": True}
                       for name in ("postgres", "history", "warm")},
    }
    receipt_path = tmp_path / "restore-result.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    token = tmp_path / "token"
    token.write_text("synthetic-test-credential", encoding="utf-8")
    settings = acceptance.Settings("sli-c01-test", "https://localhost:19443", ("compose.yml",),
                                   backup_root, receipt_path, token_file=token)
    return settings, FakeProbes(settings)


def results(settings, probes):
    return acceptance.run_checks(settings, probes, now=NOW)


def check_status(result, name):
    return next(check["status"] for check in result["checks"] if check["check"] == name)


def test_all_checks_pass_without_mutating_commands(setup):
    settings, probes = setup
    result = results(settings, probes)
    assert result["status"] == "passed"
    assert all(check["status"] == "passed" for check in result["checks"])
    docker_calls = [call for call in probes.calls if isinstance(call, list)]
    assert docker_calls[0] == ["ps", "--all", "--format", "json"]
    assert all(call[1] in {"inspect", "logs"} for call in docker_calls[1:])
    login = next(call for call in probes.calls if isinstance(call, tuple) and call[0] == "/api/auth/login")
    assert login[1]["payload"]["username"] == "acceptance-probe"
    assert "synthetic-test-credential" not in json.dumps(result)


@pytest.mark.parametrize("project", ["sli", "SLI"])
def test_production_refused_before_any_io(setup, project):
    settings, probes = setup
    with pytest.raises(ValueError, match="production_project_refused"):
        results(replace(settings, project=project), probes)
    assert probes.calls == []


def test_production_override_allows_only_probes(setup):
    settings, probes = setup
    settings = replace(settings, project="sli", allow_production_readonly=True)
    probes.project_label = "sli"
    # Restore receipt belongs to the test project; it must fail after the guard allows probes.
    result = results(settings, probes)
    assert probes.calls
    assert check_status(result, "restore:receipt") == "failed"


@pytest.mark.parametrize("path,response", [
    ("/api/health", (503, {"status": "ok"})),
    ("/api/health/live", (200, {"status": "failed"})),
    ("/api/health/ready", (200, {"ready": False})),
    ("/api/health/ready", (200, {"ready": "true"})),
    ("/api/auth/login", (200, {"status": "ok"})),
    ("/api/auth/login", (403, {"error": "secure_transport_required"})),
    ("/api/auth/login", (429, {"error": "login_temporarily_locked"})),
    ("/api/auth/login", (401, {"error": "other"})),
])
def test_http_failures_map_to_failed(setup, path, response):
    settings, probes = setup
    probes.responses[path] = response
    result = results(settings, probes)
    assert result["status"] == "failed"
    assert check_status(result, "login:bad_password" if path.endswith("login") else "health:" + path) == "failed"


@pytest.mark.parametrize("state,status,expected", [
    *( (state, 200, "passed") for state in sorted(acceptance.REPORT_STATES) ),
    ("denied", 403, "passed"), ("unavailable", 503, "passed"),
    ("ok", 503, "failed"), ("ok", 401, "failed"), ("denied", 401, "failed"),
    ("invented", 200, "failed"), (None, 200, "failed"), ({"token": "synthetic"}, 200, "failed"),
])
def test_report_state_mapping(setup, state, status, expected):
    settings, probes = setup
    probes.responses["/api/v2/reports/ad.users.v2/data?limit=1"] = (status, {"state": state})
    assert check_status(results(settings, probes), "report:ad.users.v2") == expected


@pytest.mark.parametrize("change", ["missing", "unhealthy", "stopped", "migration_failure", "wrong_project", "empty", "timeout"])
def test_service_and_inventory_failures(setup, change):
    settings, probes = setup
    if change == "missing":
        probes.rows = [row for row in probes.rows if row["Service"] != "api"]
    elif change in {"unhealthy", "stopped"}:
        row = next(row for row in probes.rows if row["Service"] == "api")
        row["Health" if change == "unhealthy" else "State"] = "unhealthy" if change == "unhealthy" else "exited"
    elif change == "migration_failure":
        next(row for row in probes.rows if row["Service"] == "migrate")["ExitCode"] = 1
    elif change == "wrong_project":
        probes.project_label = "sli"
    elif change == "empty":
        probes.rows = []
    else:
        probes.command_error = subprocess.TimeoutExpired("synthetic", 15)
    result = results(settings, probes)
    assert result["status"] == "failed"
    if change in {"wrong_project", "empty", "timeout"}:
        assert check_status(result, "services:inventory") == "failed"
        assert check_status(result, "logs:inventory") == "failed"
        assert not any(isinstance(call, list) and call[1:2] == ["logs"] for call in probes.calls)
    else:
        assert check_status(result, "service:migrate" if change == "migration_failure" else "service:api") == "failed"


@pytest.mark.parametrize("change", ["missing", "stale", "future", "partial", "empty_archive", "wrong_size", "invalid_json"])
def test_backup_failures(setup, change):
    settings, probes = setup
    folder = settings.backup_dir / STAMP
    path = folder / "manifest.json"
    manifest = json.loads(path.read_text())
    if change == "missing":
        path.unlink()
    elif change == "empty_archive":
        (folder / "warm.zip").write_bytes(b"")
    elif change == "invalid_json":
        path.write_text("not-json")
    else:
        if change in {"stale", "future"}:
            manifest["completed_at_utc"] = "2026-10-01T00:00:00+00:00" if change == "stale" else "2026-10-08T00:00:00+00:00"
        elif change == "partial":
            manifest["status"] = "failed"
        else:
            manifest["components"]["history"]["size_bytes"] = 999
        path.write_text(json.dumps(manifest))
    result = results(settings, probes)
    assert check_status(result, "backup:recent_complete") == "failed"
    assert check_status(result, "restore:receipt") == "failed"


@pytest.mark.parametrize("field,value", [
    ("status", "failed"), ("source_project", "other-test"), ("target_project", "sli"),
    ("target_project", "sli-c01-test"), ("backup_id", "other"), ("manifest_sha256", "wrong"),
    ("completed_at_utc", "2026-10-07T11:00:00+00:00"), ("cleanup_passed", False),
])
def test_restore_receipt_binding(setup, field, value):
    settings, probes = setup
    receipt = json.loads(settings.restore_result.read_text())
    receipt[field] = value
    settings.restore_result.write_text(json.dumps(receipt))
    result = results(settings, probes)
    assert check_status(result, "backup:recent_complete") == "passed"
    assert check_status(result, "restore:receipt") == "failed"


@pytest.mark.parametrize("component", ["postgres", "history", "warm"])
def test_restore_requires_each_component_counts(setup, component):
    settings, probes = setup
    receipt = json.loads(settings.restore_result.read_text())
    receipt["components"][component]["counts_match"] = False
    settings.restore_result.write_text(json.dumps(receipt))
    assert check_status(results(settings, probes), "restore:receipt") == "failed"


@pytest.mark.parametrize("verified", [None, False, "true"])
def test_restore_receipt_requires_verified_fresh_password_login(setup, verified):
    settings, probes = setup
    receipt = json.loads(settings.restore_result.read_text())
    if verified is None:
        del receipt["fresh_password_login_verified"]
    else:
        receipt["fresh_password_login_verified"] = verified
    settings.restore_result.write_text(json.dumps(receipt))
    assert check_status(results(settings, probes), "restore:receipt") == "failed"


def test_secret_scan_test_source_passes_sanitary_check(tmp_path):
    from scripts.maintenance.github_sanitary_check import scan

    source = Path(__file__)
    (tmp_path / source.name).write_bytes(source.read_bytes())

    assert scan(tmp_path)["status"] == "ok"


@pytest.mark.parametrize("logs,pattern", [
    ('password=synthetic-value', "credential_assignment"),
    ('ADLOG_PG_PASSWORD=synthetic-value', "credential_assignment"),
    ('{"access_token": "synthetic-value"}', "credential_assignment"),
    ('Authorization: Bearer synthetic-value', "authorization"),
    ('Authorization: Basic c3ludGhldGlj', "authorization"),
    # Assemble synthetic secret signatures at runtime to keep source SAN-clean.
    ('://'.join(('postgresql', 'demo:synthetic-value@localhost/test')), "url_credentials"),
    ('-----' + 'BEGIN PRIVATE KEY' + '-----', "private_key"),
    ('eyJzeW50aGV0aWM.e30.c3ludGhldGlj', "jwt"),
])
def test_secret_scan_fails_without_disclosing_matches(setup, logs, pattern):
    settings, probes = setup
    probes.logs = logs
    result = results(settings, probes)
    assert check_status(result, "logs:1") == "failed"
    assert acceptance.scan_secrets(logs)[pattern] == 1
    assert logs not in json.dumps(result)
    assert "synthetic-value" not in json.dumps(result)


@pytest.mark.parametrize("logs", ["password_file=/run/secrets/runtime_password", "password=***",
                                       '"token": "[redacted]"', "password=<redacted>", "token=null"])
def test_redacted_values_and_file_settings_are_not_secret_findings(logs):
    assert acceptance.scan_secrets(logs) == {}


def test_missing_token_and_log_exception_fail_closed(setup):
    settings, probes = setup
    settings.token_file.unlink()
    original = probes.command

    def command(arguments):
        if arguments[1] == "logs":
            raise RuntimeError("password=synthetic-private-value")
        return original(arguments)

    probes.command = command
    result = results(settings, probes)
    assert check_status(result, "report:ad.users.v2") == "failed"
    assert check_status(result, "logs:1") == "failed"
    assert "synthetic-private-value" not in json.dumps(result)


def test_login_account_file_is_not_disclosed(setup, tmp_path):
    settings, probes = setup
    account = tmp_path / "login-account"
    account.write_text("synthetic-probe-account", encoding="utf-8")
    result = results(replace(settings, login_user_file=account), probes)
    login = next(call for call in probes.calls if isinstance(call, tuple) and call[0] == "/api/auth/login")
    assert login[1]["payload"]["username"] == "synthetic-probe-account"
    assert "synthetic-probe-account" not in json.dumps(result)
    account.write_text("invalid\naccount", encoding="utf-8")
    assert check_status(results(replace(settings, login_user_file=account), probes), "login:bad_password") == "failed"


def test_compose_command_uses_explicit_project_files_and_environment(setup, monkeypatch):
    settings, _ = setup
    settings = replace(settings, compose_files=("base.yml", "overlay.yml"), env_file="stand.env")
    commands = []

    def run(command, **kwargs):
        commands.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "[]", "")

    monkeypatch.setattr(acceptance.subprocess, "run", run)
    assert acceptance.Probes(settings).compose(["ps", "--all", "--format", "json"]) == "[]"
    assert commands[0][0] == ["docker", "compose", "-p", settings.project, "-f", "base.yml",
                               "-f", "overlay.yml", "--env-file", "stand.env", "ps", "--all", "--format", "json"]
    assert commands[0][1]["timeout"] == settings.timeout
    assert commands[0][1]["capture_output"] is True


def test_http_uses_no_redirect_and_does_not_send_token_on_login(setup, monkeypatch):
    settings, _ = setup
    requests = []

    class Response:
        code = 401

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            assert limit == 1024 * 1024 + 1
            return b'{"error": "invalid_credentials"}'

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            return Response()

    def build(*handlers):
        assert any(isinstance(handler, acceptance.NoRedirect) for handler in handlers)
        return Opener()

    monkeypatch.setattr(acceptance, "build_opener", build)
    probe = acceptance.Probes(settings)
    assert probe.http("/api/auth/login", payload={"username": "acceptance-probe", "password": "synthetic"})[0] == 401
    assert requests[0].headers["Origin"] == settings.base_url
    assert "Authorization" not in requests[0].headers
    assert acceptance.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid") is None


@pytest.mark.parametrize("change", ["missing", "stale", "future", "invalid_json", "ledger"])
def test_restore_receipt_missing_or_invalid(setup, change):
    settings, probes = setup
    receipt = json.loads(settings.restore_result.read_text())
    if change == "missing":
        settings.restore_result.unlink()
    elif change == "invalid_json":
        settings.restore_result.write_text("not-json")
    else:
        if change in {"stale", "future"}:
            receipt["completed_at_utc"] = "2026-10-01T00:00:00+00:00" if change == "stale" else "2026-10-08T00:00:00+00:00"
        else:
            receipt["components"]["postgres"]["ledger_match"] = False
        settings.restore_result.write_text(json.dumps(receipt))
    assert check_status(results(settings, probes), "restore:receipt") == "failed"


def test_no_completed_backups_is_not_passed(setup):
    settings, probes = setup
    folder = settings.backup_dir / STAMP
    folder.rename(settings.backup_dir / ("." + STAMP + ".partial"))
    assert check_status(results(settings, probes), "backup:recent_complete") == "failed"


def test_cli_refusal_outputs_json_and_human_summary(setup, monkeypatch, capsys):
    settings, _ = setup
    monkeypatch.setattr(acceptance, "Probes", lambda _: pytest.fail("must refuse before creating probes"))
    assert acceptance.main(["--project", "sli", "--base-url", settings.base_url,
                            "--compose-file", "compose.yml", "--backup-dir", str(settings.backup_dir),
                            "--restore-result", str(settings.restore_result)]) == 1
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "failed"
    assert json.loads(output.out)["checks"][0]["evidence"]["code"] == "production_project_refused"
    assert "FAILED configuration" in output.err

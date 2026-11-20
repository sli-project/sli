"""Hermetic contracts for the read-only report smoke command."""
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from tools.e2e import report_check as check

NOW = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)
TOKEN = "adl_" + "x" * 43


@pytest.mark.parametrize("report", check.REPORTS)
def test_parse_primary_rows_without_double_counting_collections(report):
    field = ("activity_at" if report == "ad.users.v2" else "last_seen_utc"
             if report == "security.problems" else "time_created_utc"
             if report in {"events.journal", "security.events.chains"} else "observed_at")
    summary = check.parse_response({
        "state": "partial", "items": [
            {field: "2026-10-11T14:00:00+07:00"}, {field: "2026-10-11T08:00:00Z"},
            {field: "invalid private diagnostic"},
        ], "has_more": True, "filtered_count": 900,
        "collections": {"timeline": [{"observed_at": "2099-01-01T00:00:00Z"}]},
    })
    assert summary == {"rows": 3, "latest": "2026-10-11T08:00:00+00:00",
                       "state": "partial", "has_more": True}


def test_empty_and_missing_dates_are_not_replaced_with_coverage_timestamps():
    for rows in ([], [{"observed_at": None}, {"observed_at": "2026-10-11T12:00:00"}]):
        summary = check.parse_response({"state": "empty", "items": rows,
                                        "coverage": {"observed_at_utc": NOW.isoformat()}})
        assert summary["rows"] == len(rows)
        assert summary["latest"] is None


def test_mass_operation_uses_observation_window_end():
    assert check.parse_response({"state": "ok", "items": [
        {"details": {"window_end": NOW.isoformat()}}, {"details": None},
    ]})["latest"] == NOW.isoformat()


def test_users_query_matches_current_report_declaration():
    from server.sli.plugins.ad.reports.definitions.users import REPORT
    from server.sli.reporting.v2.definition import parse_params

    query = check.report_query("ad.users.v2", 7, NOW)
    params, paging = parse_params(REPORT, {key: [str(value)] for key, value in query.items()}, now=NOW)
    assert paging["tab"] == "all"
    assert params["account_state"] == "enabled"


@pytest.mark.parametrize("payload", [None, [], {}, {"state": "ok"},
    {"state": "ok", "items": {}}, {"state": "ok", "items": [None]},
    {"state": [], "items": []},
    {"state": "private message", "items": []}, {"state": "ok", "items": [], "has_more": "false"}])
def test_invalid_response_is_not_reported_as_zero_rows(payload):
    with pytest.raises(ValueError, match="invalid_response"):
        check.parse_response(payload)


def test_all_reports_and_domains_use_correct_scope_and_fixed_window(monkeypatch):
    requests = []

    def fetch(base_url, report, query, token, **kwargs):
        requests.append((report, query, token, kwargs["deadline"]))
        return {"http": 200, "state": "empty", "rows": 0, "latest": None}

    monkeypatch.setattr(check, "fetch_report", fetch)
    results, _ = check.check_reports("https://example.invalid", [(7, TOKEN), (8, TOKEN + "y")])
    per_domain = len(check.REPORTS) + len(check.VPN_CONNECTION_TABS) - 1
    assert len(results) == len(requests) == per_domain * 2
    assert {row["report"] for row in results} == set(check.REPORTS)
    assert [row["domain"] for row in results] == [1] * per_domain + [2] * per_domain
    assert len({deadline for _, _, _, deadline in requests}) == 1
    windows = set()
    for report, query, token, _ in requests:
        domain = 7 if token == TOKEN else 8
        assert query["limit"] == 50 and query["tz"] == "UTC"
        if report == "ad.users.v2":
            assert query == {"limit": 50, "tz": "UTC", "tab": "all", "account_state": "enabled"}
        elif report == "vpn.accounts":
            assert query == {"limit": 50, "tz": "UTC"}
        elif report == "security.problems":
            assert query["domain"] == domain and "period" not in query
            windows.add((query["time_from"], query["time_to"]))
        else:
            assert query["period"] == "custom"
            assert (query.get("domain") == domain) == (report in {"security.events.chains", "vpn.connections"})
            windows.add((query["from"], query["to"]))
    assert len(windows) == 1
    start, end = next(iter(windows))
    assert (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() == 86400


def test_network_is_get_only_timeout_wrapped_and_key_is_stdin_only(monkeypatch):
    def run(args, **kwargs):
        assert args[:3] == ["timeout", "-k", "0.2s"]
        assert args[4:6] == ["curl", "--disable"]
        assert args[args.index("--request") + 1] == "GET"
        assert "--location" not in args
        assert TOKEN not in " ".join(args)
        assert kwargs["input"] == f'header = "Authorization: Bearer {TOKEN}"\n'
        assert kwargs["timeout"] <= 8.5
        assert args[-2:] == ["--cacert", "/protected/ca.pem"]
        url = args[args.index("--url") + 1]
        assert urlsplit(url).path == "/api/v2/reports/security.events.chains/data"
        assert parse_qs(urlsplit(url).query)["domain"] == ["7"]
        return SimpleNamespace(returncode=0, stdout=json.dumps({"state": "ok", "items": []}) + "\n200")

    monkeypatch.setattr(check.subprocess, "run", run)
    summary = check.fetch_report("https://example.invalid", "security.events.chains",
                                  check.report_query("security.events.chains", 7, NOW), TOKEN,
                                  deadline=check.time.monotonic() + 20, ca_file=Path("/protected/ca.pem"))
    assert summary["http"] == 200 and summary["rows"] == 0


@pytest.mark.parametrize("code,stdout,http,state", [
    (0, TOKEN + "\n401", 401, "authentication_failed"),
    (0, TOKEN + "\n403", 403, "http_error"),
    (0, TOKEN + "\n302", 302, "http_error"),
    (0, TOKEN + "\n200", 200, "invalid_response"),
    (0, '{"state":"error","items":[]}\n200', 200, "error"),
    (28, TOKEN, "TIMEOUT", "request_failed"),
    (124, TOKEN, "TIMEOUT", "request_failed"),
    (7, TOKEN, "ERROR", "request_failed"),
])
def test_network_failures_never_expose_private_response(monkeypatch, code, stdout, http, state):
    monkeypatch.setattr(check.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=code, stdout=stdout, stderr=TOKEN))
    summary = check.fetch_report("https://example.invalid", "events.journal", {}, TOKEN,
                                  deadline=check.time.monotonic() + 10)
    assert summary["http"] == http and summary["state"] == state
    markdown, failed = check.render_results([{"domain": 1, "report": "events.journal", **summary}], NOW)
    assert failed and TOKEN not in markdown


def test_unauthenticated_results_explain_protected_key_reissuance():
    results = [{"domain": 1, "report": report, "http": 401, "state": "authentication_failed",
                "rows": None, "latest": None} for report in check.REPORTS]
    markdown, failed = check.render_results(results, NOW)
    assert failed and "#515" in markdown and "Authorization: Bearer" in markdown
    assert "истёк" in markdown and "защищённый файл" in markdown
    assert markdown.count("| 401 |") == len(check.REPORTS)
    assert TOKEN not in markdown


def test_scope_denial_does_not_request_key_reissuance():
    markdown, failed = check.render_results([
        {"domain": 1, "report": "events.journal", "http": 403, "state": "http_error",
         "rows": None, "latest": None}], NOW)
    assert failed and "#515" not in markdown


def test_deadline_and_subprocess_timeout_are_bounded(monkeypatch):
    def run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("private diagnostic", 1, output=TOKEN)

    monkeypatch.setattr(check.subprocess, "run", run)
    assert check.fetch_report("https://example.invalid", "events.journal", {}, TOKEN,
                              deadline=check.time.monotonic() + 1)["http"] == "TIMEOUT"
    monkeypatch.setattr(check.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("expired call"))
    assert check.fetch_report("https://example.invalid", "events.journal", {}, TOKEN,
                              deadline=0)["http"] == "TIMEOUT"


def test_key_file_is_private_and_rejects_header_injection(tmp_path):
    path = tmp_path / "key"
    path.write_text(TOKEN, encoding="utf-8")
    path.chmod(0o600)
    assert check.read_key(path) == TOKEN
    path.write_text(TOKEN + '\nheader="extra"', encoding="utf-8")
    with pytest.raises(ValueError, match="key_file_invalid"):
        check.read_key(path)
    path.write_text(TOKEN, encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(ValueError, match="key_file_not_protected"):
        check.read_key(path)


def test_cli_prints_and_writes_identical_safe_results(monkeypatch, tmp_path, capsys):
    key = tmp_path / "key"
    key.write_text(TOKEN, encoding="utf-8")
    key.chmod(0o600)
    output = tmp_path / "REPORTS_NOW.md"
    monkeypatch.setattr(check.shutil, "which", lambda name: name)

    def reports(_url, keys, **_kwargs):
        assert keys == [(7, TOKEN)]
        assert "in_progress" in output.read_text(encoding="utf-8")
        return [{"domain": 1, "report": "events.journal", "http": 200, "rows": 50,
                 "latest": NOW.isoformat(), "state": "partial", "has_more": True}], NOW

    monkeypatch.setattr(check, "check_reports", reports)
    assert check.main(["--domain-key", f"7={key}", "--output", str(output)]) == 0
    text = capsys.readouterr().out
    assert text == output.read_text(encoding="utf-8")
    assert TOKEN not in text and "50+" in text
    assert "verified" in text


def test_missing_key_writes_failed_status_without_network(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(check, "check_reports", lambda *_a, **_k: pytest.fail("must not call API"))
    output = tmp_path / "REPORTS_NOW.md"
    assert check.main(["--domain-key", f"7={tmp_path / 'missing'}", "--output", str(output)]) == 1
    assert "failed" in output.read_text(encoding="utf-8")
    assert str(tmp_path) not in capsys.readouterr().out


def test_output_cannot_overwrite_key_file(tmp_path, capsys):
    key = tmp_path / "key"
    key.write_text(TOKEN, encoding="utf-8")
    with pytest.raises(SystemExit):
        check.main(["--domain-key", f"7={key}", "--output", str(key)])
    assert key.read_text(encoding="utf-8") == TOKEN
    assert TOKEN not in capsys.readouterr().err


@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59"])
def test_out_of_range_utc_dates_are_ignored(stamp):
    assert check.utc_stamp(stamp) is None


@pytest.mark.parametrize("url", ["http://example.invalid", "https://user:password@example.invalid",
                                 "https://example.invalid/path", "https://example.invalid?key=value"])
def test_api_origin_refuses_credential_leaks(url):
    with pytest.raises(check.argparse.ArgumentTypeError):
        check.api_url(url)


def test_vpn_queries_cover_every_declared_tab_and_accounts_contract():
    from server.sli.plugins.remote_access.reports.vpn_audit import REPORT as accounts
    from server.sli.plugins.remote_access.reports.vpn_connections import REPORT as connections
    from server.sli.reporting.v2.definition import parse_params

    assert {"vpn.accounts", "vpn.connections"} <= set(check.REPORTS)
    assert set(check.VPN_CONNECTION_TABS) == {view.key for view in connections.views}
    for tab in check.VPN_CONNECTION_TABS:
        query = check.report_query("vpn.connections", 7, NOW, tab=tab)
        params, paging = parse_params(connections, {k: [str(v)] for k, v in query.items()}, now=NOW)
        assert params["domain"] == 7 and params["overlap_complete"] == "false"
        assert paging["tab"] == tab
    query = check.report_query("vpn.accounts", 7, NOW)
    parse_params(accounts, {k: [str(v)] for k, v in query.items()}, now=NOW)
    assert "domain" not in query and "period" not in query


def test_ad_and_gpo_queries_match_report_declarations():
    from server.sli.reporting.v2.reports.ad_state import REPORT as infrastructure
    from server.sli.reporting.v2.reports.gpo import REPORT as gpo
    from server.sli.reporting.v2.definition import parse_params

    for definition in (infrastructure, gpo):
        assert definition.key in check.REPORTS
        query = check.report_query(definition.key, 7, NOW)
        params, _ = parse_params(definition, {k: [str(v)] for k, v in query.items()}, now=NOW)
        assert params["period"]["from_utc"] == "2026-10-10T12:00:00Z"


def test_vpn_collection_rows_are_counted_instead_of_employee_rows(monkeypatch):
    payload = {"state": "partial", "items": [{"entity_id": 11}], "has_more": True,
               "collections": {"authorizations": [
                   {"time_created_utc": NOW.isoformat()}, {"time_created_utc": None}],
                   "daily": [{"date": "2099-01-01"}]}}
    monkeypatch.setattr(check.subprocess, "run", lambda *_a, **_k:
                        SimpleNamespace(returncode=0, stdout=json.dumps(payload) + "\n200"))
    summary = check.fetch_report("https://example.invalid", "vpn.connections",
                                check.report_query("vpn.connections", 7, NOW, tab="authorizations"),
                                TOKEN, deadline=check.time.monotonic() + 10)
    assert summary["rows"] == 2 and summary["latest"] == NOW.isoformat()
    assert summary["has_more"] is False  # Employee pagination does not page NPS facts.
    missing = check.fetch_report("https://example.invalid", "vpn.connections",
                                check.report_query("vpn.connections", 7, NOW, tab="windows"),
                                TOKEN, deadline=check.time.monotonic() + 10)
    assert missing["state"] == "invalid_response" and missing["rows"] is None


@pytest.mark.parametrize("tab", ["session_overlap", "daily", "authorizations"])
def test_denied_vpn_response_without_collections_preserves_api_state(monkeypatch, tab):
    # The access boundary clears collections on a canonical denied response.
    payload = {"state": "denied", "items": [], "collections": {}, "has_more": False}
    monkeypatch.setattr(check.subprocess, "run", lambda *_a, **_k:
                        SimpleNamespace(returncode=0, stdout=json.dumps(payload) + "\n200"))
    summary = check.fetch_report("https://example.invalid", "vpn.connections",
                                check.report_query("vpn.connections", 7, NOW, tab=tab),
                                TOKEN, deadline=check.time.monotonic() + 10)
    assert summary == {"http": 200, "state": "denied", "rows": None,
                       "latest": None, "has_more": False}
    markdown, failed = check.render_results([
        {"domain": 1, "report": "vpn.connections", "tab": tab, **summary}], NOW)
    assert failed and "| 200 | — | — | denied |" in markdown
    assert "invalid_response" not in markdown


@pytest.mark.parametrize("override", [
    {"collections": []}, {"items": [{}]}, {"has_more": "false"}, {"has_more": True},
])
def test_malformed_denied_collection_response_is_still_rejected(override):
    payload = {"state": "denied", "items": [], "collections": {}, "has_more": False,
               **override}
    with pytest.raises(ValueError, match="invalid_response"):
        check.parse_response(payload, source="daily")

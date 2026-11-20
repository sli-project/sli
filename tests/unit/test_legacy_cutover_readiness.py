"""Read-only cutover checks use fake connections and report responses."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import Message
import json

import pytest

from scripts.maintenance import legacy_cutover_readiness as readiness

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)
HOST = "00000000-0000-4000-8000-000000000001"


class FakeConnection:
    def __init__(self):
        self.queries = []
        self.bindings = [{"agent_id": HOST, "host_id": HOST, "source_name": "synthetic",
                          "policy_revision": "1", "assigned_modules": [
                              {"module_id": "sli.workstations", "enabled": True, "config": {}}]}]
        self.channels = list(readiness.MODULE_CHANNELS["sli.workstations"])

    @contextmanager
    def cursor(self):
        yield self

    def execute(self, sql, params=None):
        normalized = " ".join(sql.lower().split())
        assert normalized.startswith("select ")
        assert "for update" not in normalized
        self.queries.append((normalized, params))
        if "from sli_agent_module_bindings" in normalized or "from sli_agents a" in normalized:
            self.rows = self.bindings
        elif "from sli_agent_packet_inbox" in normalized:
            self.rows = [{"channel": channel} for channel in self.channels]
        elif "from servers" in normalized:
            self.rows = [{"present": True}]
        elif "from ad_snapshot_manifests" in normalized:
            self.rows = [{"manifest_id": "00000000-0000-4000-8000-000000000002"}]
        else:
            raise AssertionError(normalized)

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


@pytest.fixture
def source():
    return {"module_id": "sli.workstations", "source_instance_id": HOST,
            "history_probes": [{"path": "/api/reports/history?before=2026-10-01",
                                "rows_key": "items"}]}


def check(conn, source, **kwargs):
    return readiness.check_source(conn, source, now=NOW, max_age_seconds=86400,
                                  history_reader=lambda probe: True, **kwargs)


def test_workstation_go_is_read_only_and_has_no_ad_parity_claim(source):
    conn = FakeConnection()
    conn.bindings[0].pop("source_name")
    conn.bindings[0].pop("policy_revision")
    result = check(conn, source)
    assert result["verdict"] == "GO"
    assert result["checks"]["ad_jobs_parity"] == "not_applicable"
    assert conn.queries
    assert HOST not in json.dumps(result)
    assert "synthetic" not in json.dumps(result)
    assert "sli_agent_module_bindings" not in conn.queries[0][0]


@pytest.mark.parametrize("change,reason", [
    ("unenrolled", "agent_module_not_enrolled"),
    ("disabled_assignment", "agent_module_not_enrolled"),
    ("ambiguous", "agent_module_not_enrolled"),
    ("missing_channel", "recent_import_missing"),
])
def test_missing_or_ambiguous_evidence_is_no_go(source, change, reason):
    conn = FakeConnection()
    if change == "unenrolled":
        conn.bindings = []
    elif change == "disabled_assignment":
        conn.bindings[0]["assigned_modules"][0]["enabled"] = False
    elif change == "ambiguous":
        conn.bindings *= 2
    else:
        conn.channels.pop()
    result = check(conn, source)
    assert result["verdict"] == "NO-GO"
    assert reason in result["reasons"]


def test_import_query_requires_fresh_receipt_and_import_and_matching_owner(source):
    conn = FakeConnection()
    check(conn, source)
    sql, params = conn.queries[-1]
    assert "i.imported_at between %s and %s" in sql
    assert "r.received_at between %s and %s" in sql
    assert "r.agent_id=%s" in sql and "r.module_id=%s" in sql
    assert "source_instance_id" in sql and "policy_revision" in sql
    assert NOW - timedelta(days=1) in params and NOW in params


def test_history_failure_does_not_get_a_green_verdict(source):
    result = readiness.check_source(FakeConnection(), source, now=NOW, max_age_seconds=86400,
                                    history_reader=lambda probe: False)
    assert result["verdict"] == "NO-GO"
    assert "history_unreadable" in result["reasons"]


def test_missing_history_probes_fail_closed(source):
    source["history_probes"] = []
    assert "history_unreadable" in check(FakeConnection(), source)["reasons"]


def test_unshipped_module_cannot_be_ready(source):
    source["module_id"] = "sli.remote-access"
    assert check(FakeConnection(), source)["reasons"] == ["replacement_module_unavailable"]


@pytest.mark.parametrize("status,coverage,expected", [
    ("match", "complete", "GO"), ("mismatch", "complete", "NO-GO"),
    ("error", "complete", "NO-GO"), ("match", "partial", "NO-GO"),
])
def test_ad_parity_uses_exact_live_manifest(source, monkeypatch, status, coverage, expected):
    conn = FakeConnection()
    source.update(module_id="sli.windows.ad-dc", domain_id=1, legacy_server_id=1)
    conn.bindings[0]["assigned_modules"] = [
        {"module_id": source["module_id"], "enabled": True, "config": {"source_name": "synthetic"}}]
    conn.channels = list(readiness.MODULE_CHANNELS[source["module_id"]])
    seen = []

    def snapshot(connection, source, **kwargs):
        assert connection is conn
        seen.append(source["domain_id"])
        return {"manifest": {"domain_id": 1}}

    monkeypatch.setattr(readiness, "read_snapshot", snapshot)
    result = check(conn, source, parity_compare=lambda snapshot: {"status": status, "coverage_state": coverage})
    assert seen == [1]
    assert result["verdict"] == expected


def test_db_failure_is_redacted_per_source(source):
    class Broken(FakeConnection):
        def execute(self, *_args):
            raise RuntimeError("synthetic-private-diagnostic")

    result = check(Broken(), source)
    assert result["verdict"] == "NO-GO"
    assert result["reasons"] == ["source_read_failed"]
    assert "synthetic-private-diagnostic" not in json.dumps(result)


@pytest.mark.parametrize("sources", [[], [{}], [{"module_id": "sli.workstations", "source_instance_id": HOST}] * 2])
def test_inventory_cannot_be_empty_incomplete_or_duplicate(tmp_path, sources):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"sources": sources}), encoding="utf-8")
    with pytest.raises(ValueError, match="inventory_invalid"):
        readiness.load_inventory(path)


def test_history_requires_json_rows_not_a_login_page_or_empty_report():
    assert readiness.history_payload_readable({"items": [{}]}, {"rows_key": "items"})
    assert not readiness.history_payload_readable({"items": []}, {"rows_key": "items"})
    assert not readiness.history_payload_readable({"error": "synthetic", "items": [{}]}, {"rows_key": "items"})
    assert not readiness.history_payload_readable("<html>login</html>", {"rows_key": "items"})


def test_cli_reports_missing_dsn_without_exposing_values(tmp_path, source, monkeypatch, capsys):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"sources": [source]}), encoding="utf-8")
    monkeypatch.delenv("SLI_CUTOVER_PG_DSN", raising=False)
    assert readiness.main(["--inventory", str(path), "--api-base", "https://example.invalid"]) == 2
    output = capsys.readouterr().out
    assert "readiness_unavailable" in output
    assert HOST not in output


@pytest.mark.parametrize("include_unavailable,exit_code", [(False, 0), (True, 1)])
def test_cli_checks_sources_in_read_only_transactions(tmp_path, source, monkeypatch, capsys,
                                                     include_unavailable, exit_code):
    import psycopg

    class Connection(FakeConnection):
        read_only = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @contextmanager
        def transaction(self):
            assert self.read_only
            yield self

    conn = Connection()

    def connect(dsn, **kwargs):
        assert dsn == "synthetic-dsn"
        assert kwargs["autocommit"] is True
        assert "default_transaction_read_only=on" in kwargs["options"]
        assert "statement_timeout=5000" in kwargs["options"]
        return conn

    sources = [source]
    if include_unavailable:
        sources.append({**source, "module_id": "sli.remote-access"})
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({"sources": sources}), encoding="utf-8")
    monkeypatch.setenv("SLI_CUTOVER_PG_DSN", "synthetic-dsn")
    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setattr(readiness, "read_history", lambda probe, **kwargs: True)
    assert readiness.main(["--inventory", str(path), "--api-base", "https://example.invalid"]) == exit_code
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["verdict"] == ("NO-GO" if include_unavailable else "GO")
    assert result["sources"][0]["source"] == "source-001"
    assert len(result["sources"]) == len(sources)
    assert HOST not in output and "synthetic-dsn" not in output


def test_snapshot_is_loaded_from_live_manifest_members(source, monkeypatch):
    from server.ad_context import repository

    conn = FakeConnection()
    source["domain_id"] = 1
    members = [{"family": "users_v2", "source_id": "1", "payload_sha256": "a" * 64},
               {"family": "ad_vpn_membership", "source_id": "2", "payload_sha256": "b" * 64}]
    loaded = []
    monkeypatch.setattr(repository, "load_projection_manifest", lambda connection, manifest_id: {
        "manifest_id": manifest_id, "domain_id": 1, "members": members})

    def exact(connection, **member):
        assert connection is conn
        loaded.append(member)
        return {"items": []}

    monkeypatch.setattr(repository, "load_exact_projection_source", exact)
    snapshot = readiness.read_snapshot(conn, source, now=NOW, cutoff=NOW - timedelta(days=1))
    assert loaded == members[:1]
    assert snapshot["manifest"]["members"] == members
    assert snapshot["sources"] == [{**members[0], "payload_json": {"items": []}}]
    assert conn.queries[0][1] == (1, NOW - timedelta(days=1), NOW)


@pytest.mark.parametrize("content_type,payload,expected", [
    ("application/json", {"data": {"items": [{}]}}, True),
    ("application/json", {"data": {"items": []}}, False),
    ("text/html", "<html>login</html>", False),
])
def test_history_get_checks_response_without_printing_data(monkeypatch, capsys, content_type, payload, expected):
    observed = []

    class Response:
        status = 200
        headers = Message()
        headers["Content-Type"] = content_type

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, limit):
            assert limit == readiness.MAX_RESPONSE_BYTES + 1
            return json.dumps(payload).encode()

    class Opener:
        def open(self, request, timeout):
            assert request.get_method() == "GET"
            assert timeout == 10
            assert request.get_header("Authorization") == "Bearer synthetic-token"
            observed.append(request.full_url)
            return Response()

    def opener(handler):
        assert handler.redirect_request(None, None, None, None, None, None) is None
        return Opener()

    monkeypatch.setattr(readiness, "build_opener", opener)
    monkeypatch.setenv("SLI_CUTOVER_API_TOKEN", "synthetic-token")
    result = readiness.read_history({"path": "/api/report?before=2026-10-01", "rows_key": "data.items"},
                                    api_base="https://example.invalid")
    assert result is expected
    assert len(observed) == 1
    assert capsys.readouterr().out == ""


def test_history_does_not_send_credentials_over_remote_http(monkeypatch):
    monkeypatch.setattr(readiness, "build_opener", lambda *_: pytest.fail("network contacted"))
    assert not readiness.read_history({"path": "/api/report", "rows_key": "items"},
                                      api_base="http://example.invalid")

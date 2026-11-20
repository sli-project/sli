"""Executable Python oracle for the legacy investigation GET contract.

Only the two data owners are replaced with fixture rows; query handling,
time validation and the complete workspace projection execute the reference.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

import pytest

from server.api.routes import investigations as routes
from server.sli.events.event_search_filters import normalize_search_filters
from server.sli.semantic import investigation


FIXTURE = Path(__file__).resolve().parents[2] / "server-dotnet/tests/Sli.Server.Tests/Investigations/Fixtures/workspace-source.json"


def reference_vectors():
    events = [
        {"id": 7, "event_id": 4728, "time_created_utc": "2026-11-06T10:00:00.1234567Z",
         "server": "dc & +.example.test", "channel": "Security", "target": "<fixture>&\"' +/~",
         "target_user_name": "", "subject": "initiator", "subject_user_name": "", "workstation_name": "",
         "ip_address": "192.0.2.17", "logon_id": "0x123", "label": "", "time_created_utc_display": ""},
        {"id": 0, "event_db_id": 8, "event_id": 4625, "time_created_utc": "invalid time", "label": "<label>", "server": "dc.example.test"},
        {"event_id": 999999, "time_created_utc": None},
        {"id": 10, "event_id": 4624, "time_created_utc": "2026-11-05T01:00:00+03:00", "time_created_utc_display": "stored display"},
    ]
    search = {"items": events, "total": 25, "returned_count": 6, "total_is_exact": True, "has_more": False}
    findings = {"items": [{"id": 3, "title": "<fixture>&\"'"}], "summary": [], "backend": "postgres"}
    cases = [
        ("empty", "", {}, {}),
        ("empty_unused_invalid_time", "q=%20&time_from=bad&timezone=bad", {}, {}),
        ("aliases", "q=&account=fixture&user=ignored&scope=&mode=ALL&limit=0", search, findings),
        ("full_projection", "q=fixture&time_from=2026-11-01&time_to=2026-11-07", search, findings),
        ("missing_optional_search_fields", "q=fixture&scope=all", {"items": []}, {}),
        ("no_results", "user=fixture&scope=unknown", {"items": [], "total": 0}, {}),
        ("findings_only", "q=fixture", {"items": [], "total": None}, findings),
        ("has_more", "q=fixture&mode=hide_noise&limit=2001", {**search, "has_more": True}, findings),
        ("backend", "q=fixture&time_from=%20", search, {**findings, "backend": "fixture-backend"}),
        ("unicode_space", "q=%1Cfixture%1F&scope=%1CHIDE_NOISE%1F", search, findings),
        ("large_limit", "q=fixture&limit=99999999999999999999999999999", search, findings),
        ("negative_limit", "q=fixture&limit=-12", search, findings),
        ("python_integer", "q=fixture&limit=%2B1_000", search, findings),
        ("unicode_integer", "q=fixture&limit=%D9%A1%D9%A2", search, findings),
        ("duplicate_query", "q=fixture&q=ignored&limit=12&limit=bad", search, findings),
        ("bad_limit", "q=fixture&limit=bad", {}, {}),
        ("bad_time", "q=fixture&time_from=bad", {}, {}),
        ("bad_zone", "q=fixture&timezone=Invalid/Fixture", {}, {}),
        ("reversed", "q=fixture&time_from=2026-11-07&time_to=2026-11-01", {}, {}),
        ("ambiguous", "q=fixture&timezone=America/New_York&time_from=2026-11-01T01:30:00", {}, {}),
        ("nonexistent", "q=fixture&timezone=America/New_York&time_from=2026-03-08T02:30:00", {}, {}),
    ]
    for name, ids in [("all_checks", [4625, 4624, 4724, 4740, 4728, 4672]), ("failed_threshold", [4625] * 5), ("normal", [4634]), ("no_event_id", [None]), ("string_event_id", ["4728"])]:
        cases.append((name, "q=fixture", {"items": [{"event_id": n, "target": "pivot"} for n in ids]}, findings if name == "all_checks" else {}))
    pivot_rows = [{"event_id": 4624, "target": f"user-{n}", "subject": f"actor-{n}", "ip_address": f"192.0.2.{n + 1}", "server": f"dc{n}.example.test", "logon_id": f"0x{n}"} for n in range(4)]
    cases.append(("pivot_boundary", "q=USER-0&scope=all", {"items": pivot_rows}, {}))
    output = []
    for name, query, stored_search, stored_findings in cases:
        calls = {}

        def search_owner(**kwargs):
            calls["search"] = kwargs
            calls["normalized"] = normalize_search_filters(**{k: v for k, v in kwargs.items() if k != "include_internal_evidence"})
            return copy.deepcopy(stored_search)

        def findings_owner(**kwargs):
            calls["findings"] = kwargs
            return copy.deepcopy(stored_findings)

        class Handler:
            def _send_json(self, body, status=200):
                self.body, self.status = body, int(status)

        handler = Handler()
        with patch.object(investigation, "get_event_search_data", search_owner), patch.object(investigation, "get_findings_data", findings_owner):
            try:
                routes._handle_investigation_api(handler, parse_qs(query))
            except ValueError:
                # HTTPServer.do_GET's public response; the generated ID is dynamic.
                handler.body, handler.status = {"error": "internal_server_error"}, 500
        output.append({"name": name, "query": query, "search": stored_search, "findings": stored_findings,
                       "status": handler.status, "body": handler.body, "calls": calls})
    return output


@pytest.mark.parametrize("vector", json.loads(FIXTURE.read_text(encoding="utf-8")), ids=lambda v: v["name"])
def test_workspace_fixture_matches_executed_reference(vector):
    actual = next(v for v in reference_vectors() if v["name"] == vector["name"])
    assert actual == vector

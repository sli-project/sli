"""Reader-to-report boundaries: SQL labels and bounded export completeness."""
import csv
import io
import re
from contextlib import nullcontext
from datetime import UTC, datetime

import pytest

from server.api.routes import reports_v2 as routes
from server.sli.access import domain_scope
from server.sli.plugins.ad.reports import computers_v6_reporting as inventory
from server.sli.plugins.ad.reports import dc_powershell_reporting as powershell
from server.sli.plugins.ad.reports.definitions import computers


@pytest.mark.parametrize("kind", ["rdp", "local", "powershell_remoting"])
@pytest.mark.parametrize("condition", ["complete", "cross_boot", "ambiguous", *[
    "missing:" + name + suffix
    for name in ("process_start", "process_stop", "session_start", "session_end")
    for suffix in ("_event_db_id", "_boot_event_db_id")
]])
def test_sql_origin_projection_reaches_composer(monkeypatch, kind, condition):
    # Model database column naming from the actual SELECT, not a pre-aliased DTO.
    origin = {
        "origin_kind": kind, "source_ip": "192.0.2.41", "workstation_name": "ADMIN-01",
        "process_start_event_db_id": 11, "process_stop_event_db_id": 12,
        "session_start_event_db_id": 13, "session_end_event_db_id": 14,
        **{name + "_boot_event_db_id": 15 for name in
           ("process_start", "process_stop", "session_start", "session_end")},
    }
    if condition.startswith("missing:"):
        origin[condition.split(":", 1)[1]] = None
    if condition == "cross_boot":
        origin["session_end_boot_event_db_id"] = 16

    class Cursor:
        def execute(self, sql, params=()):
            if "from bounded_powershell power" not in sql:
                return
            assert params[0] == params[6] == 7
            projection = sql.split("select power.event_db_id,", 1)[1].split("from bounded_powershell power", 1)[0]
            labels = re.findall(r"origin\.(\w+)(?:\s+as\s+(\w+))?", projection)
            row = {"event_db_id": 1, "event_id": 4104,
                   "time_created_utc": datetime(2026, 8, 21, 10, 1, tzinfo=UTC),
                   "domain_controller": "dc.example.test", "powershell_script_block_text": "private-script"}
            row.update({alias or name: origin[name] for name, alias in labels})
            self.rows = [row]
            if condition == "ambiguous":
                second = dict(row)
                key = next(alias or name for name, alias in labels if name == "process_start_event_db_id")
                second[key] = 99
                self.rows.append(second)

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return {"history_event_present": True}

    class Connection:
        def cursor(self):
            return nullcontext(Cursor())

    monkeypatch.setattr(powershell, "_connect", lambda: nullcontext(Connection()))
    result = powershell.get_dc_powershell_activity(
        {"capability_policies": [{"capability_key": "events.view", "effect": "allow",
          "valid": True, "scope": {"kind": "domain", "ids": [7]}}]}, source_domain_id=7,
        time_from="2026-08-21T10:00:00Z", time_to="2026-08-21T11:00:00Z",
    )
    assert "private-script" not in str(result)
    resolved = result["items"][0]["origin"]
    if condition == "complete":
        assert resolved["state"] == "observed"
        assert resolved["kind"] == kind
        assert resolved["evidence"] == {
            "process_start_event_db_id": 11, "process_stop_event_db_id": 12,
            "session_start_event_db_id": 13, "session_end_event_db_id": 14,
            "boot_start_event_db_id": 15,
        }
    else:
        assert resolved == {"state": "unknown", "reason": {
            "missing": "no_complete_native_origin_chain",
            "cross_boot": "origin_crosses_security_boot_boundary",
            "ambiguous": "ambiguous_complete_native_origin_chain",
        }["missing" if condition.startswith("missing:") else condition]}


@pytest.mark.parametrize("count,query,expected_rows,truncated", [
    (10_000, {}, 10_000, False),
    (10_001, {}, 10_000, True),
    (10_001, {"q": ["missing-match"]}, 0, True),
    (0, {}, 0, False),
])
def test_inventory_input_cap_reaches_csv_headers(monkeypatch, count, query, expected_rows, truncated):
    def read(sql, params=(), **kwargs):
        assert "computers_v6_accounts" in sql
        assert "entity.domain_id=any(?)" in sql
        assert params == ([7], 10_001)
        return [{"entity_id": i, "domain_id": 7, "display_name": f"WS-{i}",
                 "attributes": {"enabled": True, "operating_system": "Windows 11"}}
                for i in range(1, count + 1)]

    monkeypatch.setattr(inventory, "query_rows_bounded", read)
    monkeypatch.setattr(inventory, "_coverage", lambda ids: {"state": "available", "domains": []})
    monkeypatch.setattr(inventory, "_load_computers_v6_source_overlay", lambda ids: {})
    monkeypatch.setattr(inventory, "_semantic_rows", lambda items: [])
    monkeypatch.setattr(inventory, "_load_snapshot_comparison", lambda ids: {})
    monkeypatch.setattr(routes, "get_report", lambda key: computers.REPORT)
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [
        {"id": 7, "display_name": "example.test"}])

    class Handler:
        def __init__(self):
            self.wfile = io.BytesIO()
            self.headers = {}

        def _access_decision(self):
            return {"reports": [{"report_key": computers.REPORT.access.report_key,
                "allowed": True, "allowed_actions": ["export"], "grants": [{
                    "allowed_actions": ["export"],
                    "field_categories": list(computers.REPORT.access.required_fields),
                    "scope": {"kind": "domain", "ids": [7]}}]}]}

        def send_response(self, status):
            assert status == 200

        def send_header(self, key, value):
            self.headers[key] = value

        def end_headers(self):
            pass

        def _send_json(self, payload, status=200):
            pytest.fail(f"Unexpected JSON response: {status} {payload}")

    handler = Handler()
    assert routes.try_handle_get(handler, "/api/v2/reports/ad.computers.v6/export.csv",
                                 {"tab": ["computers"], "view": ["all"], **query})
    assert handler.headers["X-Sli-Export-Truncated"] == str(truncated).lower()
    assert handler.headers["X-Sli-Export-Rows"] == str(expected_rows)
    suffix = "INCOMPLETE-first" if truncated else "complete"
    assert f"{suffix}-{expected_rows}-rows.csv" in handler.headers["Content-Disposition"]
    rows = list(csv.reader(io.StringIO(handler.wfile.getvalue().decode("utf-8-sig")), delimiter=";"))
    assert len(rows) == expected_rows + 1

from __future__ import annotations

from datetime import datetime, timezone
import json

from scripts.runtime.computers_report_v6_snapshot_worker import (
    persist_computers_v6_snapshot,
)


class Cursor:
    def __init__(self) -> None:
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.phase = ""
        self.rowcount = 0

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        self.statements.append((sql, params))
        if "insert into computers_report_v6_snapshots" in sql:
            self.phase = "insert"
        elif "select object_count,payload_sha256" in sql:
            self.phase = "readback"
        elif "delete from computers_report_v6_snapshots" in sql:
            self.phase = "delete"

    def fetchone(self):
        if self.phase == "insert":
            return {"snapshot_id": 6}
        if self.phase == "readback":
            params = self.statements[0][1]
            return {"object_count": params[8], "payload_sha256": params[10]}
        return None


class Connection:
    def __init__(self, cursor: Cursor) -> None:
        self.cursor_value = cursor

    def cursor(self):
        cursor = self.cursor_value

        class Context:
            def __enter__(self):
                return cursor

            def __exit__(self, *_args):
                return False

        return Context()


def test_v6_snapshot_identity_includes_activity_threshold() -> None:
    cursor = Cursor()
    report = {
        "contract_id": "sli.computers-report.v6",
        "report_key": "ad.computers.v6",
        "state": "available",
        "threshold": {"selected_days": 90, "allowed_days": [30, 60, 90, 180]},
        "coverage": {"domains": [], "latest_observed_at_utc": None},
        "summary": {"total_computers": 1},
        "semantic": {},
        "items": [{"entity_id": 1, "display_name": "WS-01"}],
    }

    result = persist_computers_v6_snapshot(
        Connection(cursor),
        report=report,
        domain_id=1,
        captured_at=datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc),
    )

    assert result["status"] == "captured"
    insert_params = cursor.statements[0][1]
    scope = json.loads(str(insert_params[3]))
    payload = json.loads(str(insert_params[9]))
    assert scope == {
        "domain_ids": [1],
        "report_key": "ad.computers.v6",
        "threshold_days": 90,
    }
    assert payload["threshold"] == {
        "allowed_days": [30, 60, 90, 180],
        "selected_days": 90,
    }


def test_computers_v6_exact_projector_hash_matches_active_output_fixture() -> None:
    from server.sli.sources.ad_snapshot_projection import canonical_output_sha256
    from server.sli.reports.computers_v6_reporting import project_computers_v6_exact

    active_output = {
        "contract_id": "sli.computers-report.v6",
        "report_key": "ad.computers.v6",
        "items": [{"entity_id": 1, "display_name": "WS-01"}],
        "threshold": {"selected_days": 60},
    }
    shadow = project_computers_v6_exact(active_output)
    assert shadow is not active_output
    assert canonical_output_sha256(shadow) == canonical_output_sha256(active_output)

"""Dashboard HTTP contract from the frozen Python implementation; synthetic inputs only."""
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import sys
from unittest.mock import patch
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from server.api.routes import workspace
from server.sli.reporting import dashboard_fast, dashboard_snapshot as snapshot


class Cursor:
    """Rows at the PostgreSQL boundary, consumed by the real summary functions."""
    def __init__(self, populated):
        self.populated = populated
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self

    def execute(self, sql, parameters=()):
        self.rows = []
        if "pc.relname = %s" in sql:
            self.rows = [{"estimated_rows": {"events_v2_core": 9, "entities_v2": 5,
                          "entity_identity_merges_v2": 2}[parameters[0]] if self.populated else 0}]
        elif "tablesample system (1)" in sql:
            self.rows = [{"estimated_rows": 6 if self.populated else 0}]
        elif "from log_sources ls" in sql and self.populated:
            self.rows = [{"channel": "Security", "count": 12}]

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


def normalize(value):
    if isinstance(value, dict):
        return {
            key: ("<generated>" if key == "generated_at_utc" else
                  0 if key.endswith("_ms") and not isinstance(item, dict) else
                  {name: 0 for name in item} if key == "components_ms" else normalize(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def components(populated):
    with patch("server.sli.core.postgres_runtime_pipeline.connect", return_value=Cursor(populated)), \
            patch.object(dashboard_fast, "_v2_read_selected", return_value=True), \
            patch.object(dashboard_fast, "_recent_event_sample", return_value=50000), \
            patch.object(dashboard_fast, "_recent_entity_sample", return_value=20000):
        events = dashboard_fast.get_dashboard_event_summary()
        entities = dashboard_fast.get_dashboard_entity_summary()
    return {
        "events_summary": events,
        "entity_summary": entities,
        "collector_health": {"summary": {"security_high": 0, "security_warn": 1 if populated else 0},
            "items": [{"channel": "Security", "lag_minutes": "invalid"},
                      {"channel": "Security", "lag_minutes": -3}] if populated else []},
        "sources": [{"hostname": "dc.example.test", "label": "<script>&\"fixture"}] if populated else [],
        "findings": {"items": [{"status": "open"}, {"status": "closed"}, {"status": "false_positive"}] if populated else []},
        "ai_runs": {"items": [{"id": "fixture"}] if populated else []},
        "jobs": [], "reports": [],
        "archive_status": {"archive_start_utc": None, "channel_states": [], "backend": "postgres"},
    }


def build_case(name, populated, failure=None):
    values = components(populated)
    runtime = {"status": "ok", "active_backend": "postgres", "scheduler": {}, "collection": {}}
    functions = {"events_summary": "get_dashboard_event_summary", "entity_summary": "get_dashboard_entity_summary",
        "collector_health": "get_collector_health", "sources": "get_sources", "findings": "get_findings_dashboard_data",
        "ai_runs": "list_ai_runs", "jobs": "list_jobs", "reports": "list_reports", "archive_status": "_archive_status_payload"}
    with ExitStack() as stack:
        stack.enter_context(patch.object(snapshot, "_runtime_payload", return_value=runtime))
        stack.enter_context(patch.object(snapshot, "resolve_storage_route"))
        stack.enter_context(patch.object(snapshot, "_cache_ttl_seconds", return_value=17.0))
        for key, function in functions.items():
            kwargs = {"side_effect": RuntimeError("dashboard_component_unavailable")} if failure == key else {"return_value": deepcopy(values[key])}
            stack.enter_context(patch.object(snapshot, function, **kwargs))
        snapshot.clear_dashboard_snapshot_cache()
        payload = snapshot.build_dashboard_snapshot(force=True)
        warming = snapshot._warming_response()
        fresh = snapshot._cached_response(payload, age=0, stale=False, refreshing=False)
        stale = snapshot._cached_response(payload, age=20, stale=True, refreshing=True)
    return {"name": name, "components": values, "runtime": runtime, "failure": failure,
            "payload": normalize(payload), "warming": normalize(warming),
            "fresh": normalize(fresh), "stale": normalize(stale)}


class Handler:
    def _send_json(self, value):
        self.value = value


forces = []
for query in ("", "force=1", "force=TRUE", "force=Yes", "force=0", "force=false", "force=on",
              "force=%20true%20", "force=", "force=&force=yes", "force=no&force=yes", "force=yes&force=no"):
    handler = Handler()
    with patch.object(workspace, "build_dashboard_snapshot", side_effect=lambda **kwargs: kwargs):
        workspace.try_handle_get(handler, "/api/dashboard/snapshot", parse_qs(query))
    forces.append({"query": query, "force": handler.value["force"]})

Path(__file__).with_name("dashboard-reference.json").write_text(json.dumps({
    "cases": [build_case("populated", True), build_case("empty", False),
              build_case("partial", True, "entity_summary")], "forces": forces,
}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

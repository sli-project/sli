"""Offline workspace vectors evaluated by the frozen Python route and composer."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server.api.routes import workspace as route
from server.sli.access.access_composition import capability_decision, compose_access_facts
from server.sli.core.database import QueryTimeoutError
from server.sli.reporting import reporting_v4 as reporting


TARGET = (Path(__file__).resolve().parents[2] / "server-dotnet/tests/Sli.Server.Tests/"
          "Workspace/workspace-source.json")
SUBJECT = {"type": "session", "id": 7, "role": "viewer", "username": "fixture"}
NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)


def policy(key, kind="all", ids=None, effect="allow"):
    return {"capability_key": key, "effect": effect, "source_type": "direct",
            "subject_type": "user", "subject_id": 7,
            "scope_json": {"kind": kind, **({"ids": ids} if ids is not None else {})}}


def metric(key, **changes):
    return {"key": key, "label": key, "kind": "required", "value_path": "items.count",
            "target_path": "/reports/fixture", **changes}


def vectors():
    base = {key: [] for key in ("groups", "role_packages", "subject_packages", "owner_packages",
                               "package_capabilities", "direct_capabilities", "all_capabilities",
                               "package_reports", "report_assignments", "definitions", "requests", "preferences")}
    base["is_owner"] = [{"is_owner": False}]
    base["direct_capabilities"] = [policy("workspace.view")]
    row = {"id": 7, "object_type": "account", "display_name": "<script>fixture</script> & \"text\"",
           "natural_key": "TECHNICAL_SENTINEL", "domain_id": 11, "server_id": 22,
           "last_seen_utc": "2026-01-02T00:00:00Z"}
    cases = []

    def add(name, caps=(), rows=None, policies=(), owner=False, error=None, facts=None, report_error=False):
        data = deepcopy(facts or base)
        data["direct_capabilities"] += [policy(key) for key in caps] + list(policies)
        data["is_owner"] = [{"is_owner": owner}]
        data["all_capabilities"] = [{"capability_key": key} for key in ("workspace.view", "objects.view", "field.technical")]
        cases.append({"name": name, "facts": data, "rows": rows if rows is not None else [row],
                      "read_error": error, "report_error": report_error})

    add("no_object_permission")
    add("empty", caps=["objects.view"], rows=[])
    add("redacted", caps=["objects.view"])
    add("technical", caps=["objects.view", "field.technical"])
    add("owner", owner=True)
    for natural in (None, "", "fixture-key"):
        add(f"fallback_{natural}", caps=["objects.view", "field.technical"],
            rows=[{**row, "display_name": "", "natural_key": natural}])
    for key in ("domain_id", "server_id"):
        for value in (None, 0, -1, True, "22", 1.5):
            add(f"context_{key}_{value}", caps=["objects.view"], rows=[{**row, key: value}])
        missing = {k: v for k, v in row.items() if k != key}
        add(f"missing_{key}", owner=True, rows=[missing])
    add("unknown_context", owner=True, rows=[{**row, "domain_id": None, "server_id": None}])
    for kind, id_ in (("domain", 11), ("server", 22)):
        add(f"object_deny_{kind}", caps=["objects.view"], policies=[policy("objects.view", kind, [id_], "deny")])
        add(f"technical_deny_{kind}", caps=["objects.view", "field.technical"],
            policies=[policy("field.technical", kind, [id_], "deny")], rows=[{**row, "display_name": ""}])
    add("scoped", policies=[policy("objects.view", "domain", [11]), policy("field.technical", "server", [22])],
        rows=[row, {**row, "id": 8, "domain_id": 12}])
    add("cross_dimension_deny", policies=[policy("objects.view", "domain", [11]), policy("objects.view", "server", [22], "deny")])
    add("invalid_deny", caps=["objects.view"], policies=[policy("objects.view", "invalid", effect="deny")])
    add("first_eight_denied", caps=["objects.view"], policies=[policy("objects.view", "domain", [11], "deny")],
        rows=[{**row, "id": i} for i in range(1, 9)])
    add("cancelled_read", caps=["objects.view"], error="57014")
    add("unexpected_read_failure", caps=["objects.view"], error="XX000")
    add("workspace_denied", policies=[policy("workspace.view", effect="deny")])
    add("workspace_scoped", policies=[policy("workspace.view", "domain", [11], "deny")])
    local = deepcopy(base)
    local["direct_capabilities"] = []
    local["role_packages"] = [{"id": 1, "package_key": "fixture", "name": "Fixture package",
                               "effect": "allow", "source_kind": "role", "source_key": "operator"}]
    local["package_capabilities"] = [{"package_key": "fixture", "capability_key": "workspace.view"}]
    add("local_operator", facts=local)
    cases[-1]["local"] = True

    reports = deepcopy(base)
    reports["direct_capabilities"] += [policy("field.identity_basic")]
    reports["subject_packages"] = [{"id": 1, "package_key": "fixture", "name": "Fixture package",
                                    "effect": "allow", "source_kind": "direct", "source_key": "user:7"}]
    reports["groups"] = [{"id": 3, "group_key": "fixture", "name": "Fixture group", "source": "manual"}]
    for i, name in enumerate(("Zulu", "Alpha", "Denied")):
        key = f"fixture.{i}"
        reports["definitions"].append({"report_key": key, "version": 1, "dataset_version": 1,
            "name": name, "dataset_key": "entities.v2", "discoverable": True,
            "fields_json": [{"key": "id", "category": "identity_basic"}], "actions_json": ["view"],
            "definition_json": {"columns": ["id"], "field_categories": ["identity_basic"], "actions": ["view"],
                "dashboard_metrics": [metric(f"count.{i}"), metric(f"optional.{i}", kind="optional", default_selected=True),
                                      metric(f"selected.{i}", kind="optional", value_path="summary.missing")]}})
        reports["report_assignments"].append({"id": i + 1, "subject_type": "user", "subject_id": 7,
            "source_type": "temporary" if i == 1 else "direct", "report_key": key, "effect": "allow",
            "scope_json": {"kind": "all"}, "field_categories": ["identity_basic"], "allowed_actions": ["view"]})
    reports["report_assignments"].append({"report_key": "fixture.2", "effect": "deny"})
    reports["preferences"] = [{"report_key": "fixture.0", "pinned": True, "view_json": {"focus_metric_keys": ["selected.0"]}}]
    add("reports_and_preferences", facts=reports)
    add("unavailable_report", facts=reports, report_error=True)
    add("empty_report", facts=reports, rows=[])
    invalid = deepcopy(reports)
    invalid["definitions"][0]["definition_json"]["dashboard_metrics"] = [metric("bad", value_path="sql.count(*)")]
    add("invalid_metrics", facts=invalid)
    tied = deepcopy(reports)
    tied["preferences"] = [{"report_key": "fixture.1", "pinned": True}]
    for definition in tied["definitions"]:
        definition["definition_json"]["dashboard_metrics"] = [metric("same.metric")]
    add("stable_metric_order", facts=tied)
    many = deepcopy(reports)
    many["definitions"] = []
    many["report_assignments"] = []
    for i in range(6):
        definition = deepcopy(reports["definitions"][0])
        assignment = deepcopy(reports["report_assignments"][0])
        definition["report_key"] = assignment["report_key"] = f"many.{i}"
        definition["definition_json"]["dashboard_metrics"] = [metric(f"metric.{i}", label=("ß", "SS", "Σ", "ς", "Zulu", "Alpha")[i])]
        many["definitions"].append(definition)
        many["report_assignments"].append(assignment)
    add("six_required_metrics", facts=many)

    for case in cases:
        subject = {"type": "local", "id": None, "role": "operator"} if case.get("local") else SUBJECT
        access = compose_access_facts(subject, case["facts"], now=NOW)
        decision = capability_decision(access, "workspace.view")
        case["expected_reads"] = 0
        case["expected_reports"] = []
        if not decision["allowed"]:
            case.update(status=403, expected={"error": decision["reason"], "required_capability": "workspace.view"})
            continue

        def query(*args, **kwargs):
            case["expected_reads"] += 1
            if case["read_error"] == "57014":
                raise QueryTimeoutError("synthetic cancellation", timeout_ms=3000)
            if case["read_error"]:
                raise RuntimeError("synthetic database failure")
            return deepcopy(case["rows"])

        def execute(key, principal, *, limit, access):
            assert limit == 1
            case["expected_reports"].append(key)
            if case["report_error"]:
                raise RuntimeError("synthetic report failure")
            items = [{"id": 7}] if case["name"] != "empty_report" else []
            return {"state": "available" if items else "empty", "items": items}

        def send(payload, status=200):
            case.update(status=int(status), expected=payload)

        handler = SimpleNamespace(_principal=None if case.get("local") else SUBJECT, _access_decision=lambda: access, _send_json=send)
        with patch.object(reporting, "query_rows_bounded", side_effect=query), patch.object(reporting, "execute_report", side_effect=execute):
            try:
                assert route.try_handle_get(handler, "/api/v1/workspace", {"limit": ["bad", "ignored"]})
            except RuntimeError:
                case.update(status=500, expected=None)
    return cases


def test_workspace_fixture_matches_frozen_route():
    assert json.loads(TARGET.read_text("utf-8")) == vectors()


if __name__ == "__main__":
    TARGET.write_text(json.dumps(vectors(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

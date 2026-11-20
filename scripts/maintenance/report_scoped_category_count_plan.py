#!/usr/bin/env python3
"""Measure category counts for the exact owner's assigned events report slice."""
from __future__ import annotations

import inspect
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.access.access_control_v4 import effective_access  # noqa: E402
from server.sli.events.event_catalog import all_event_catalog_entries  # noqa: E402
from server.sli.events.event_search import (  # noqa: E402
    ACCOUNT_MANAGEMENT_EVENT_IDS,
    AUTHENTICATION_EVENT_IDS,
    SERVICE_TASK_EVENT_IDS,
)
from server.sli.core.postgres_runtime_pipeline import connect  # noqa: E402
from server.sli.reporting.reporting_v4 import (  # noqa: E402
    REPORT_DATA_TIMEOUT_MS,
    _append_predicates,
    _compile_definition_query,
    _compile_interactive_event_query,
)

SAMPLES = 5
def _placeholders(values: Iterable[Any]) -> str:
    return ",".join("%s" for _ in values) or "null"

def _scope(scopes: list[dict[str, Any]]) -> tuple[list[str], list[Any], bool]:
    if any(str(item.get("kind") or "") == "all" for item in scopes):
        return [], [], True
    clauses: list[str] = []
    params: list[Any] = []
    for item in scopes:
        kind = str(item.get("kind") or "")
        if kind in {"server", "domain"}:
            ids = [int(value) for value in item.get("ids") or []][:100]
            if ids:
                clauses.append(f"event.{kind}_id=any(%s)")
                params.append(ids)
        elif kind == "channel":
            values = [str(value) for value in item.get("values") or []][:100]
            if values:
                clauses.append("channel.value=any(%s)")
                params.append(values)
    if not clauses:
        raise PermissionError("report_scope_not_executable")
    return ["(" + " or ".join(clauses) + ")"], params, False

def _count_sql(predicates: list[str]) -> tuple[str, list[Any]]:
    attention = sorted({
        int(item.get("event_id") or 0)
        for item in all_event_catalog_entries()
        if int(item.get("event_id") or 0) > 0
        and (
            str(item.get("purpose_tier") or "").lower() == "critical"
            or str(item.get("base_risk") or item.get("severity") or "").lower()
            in {"critical", "high"}
        )
    })
    authentication = sorted(AUTHENTICATION_EVENT_IDS)
    accounts = sorted(ACCOUNT_MANAGEMENT_EVENT_IDS)
    tasks = sorted(SERVICE_TASK_EVENT_IDS)
    where = " where " + " and ".join(f"({item})" for item in predicates) if predicates else ""
    sql = f"""
        select count(*) as all_count,
          count(*) filter (where event.event_id in ({_placeholders(attention)})) as attention_count,
          count(*) filter (where event.event_id in ({_placeholders(authentication)})) as authentication_count,
          count(*) filter (where event.event_id in ({_placeholders(accounts)})) as accounts_count,
          count(*) filter (
            where lower(coalesce(channel.value,'')) like %s
               or event.event_id in ({_placeholders(tasks)})
          ) as tasks_count
        from events_v2_core event
        join servers server on server.id=event.server_id
        join storage_v2_channel channel on channel.id=event.channel_id
        {where}
    """
    return sql, [*attention, *authentication, *accounts, "%taskscheduler%", *tasks]

def _percentile(samples: list[float], percentile: float) -> float:
    ordered = sorted(samples)
    rank = max(0, min(len(ordered) - 1, int((len(ordered) * percentile + 0.999999) - 1)))
    return round(ordered[rank], 3)

def _dominant_leaf(plan: dict[str, Any]) -> dict[str, Any]:
    leaves: list[dict[str, Any]] = []

    def visit(node: dict[str, Any]) -> None:
        children = [item for item in node.get("Plans") or [] if isinstance(item, dict)]
        if children:
            for child in children:
                visit(child)
        else:
            leaves.append(node)

    visit(plan)
    node = max(
        leaves or [plan],
        key=lambda item: float(item.get("Actual Total Time") or 0)
        * float(item.get("Actual Loops") or 1),
    )
    return {
        "node_type": node.get("Node Type"),
        "relation": node.get("Relation Name"),
        "index": node.get("Index Name"),
        "actual_total_ms": round(
            float(node.get("Actual Total Time") or 0)
            * float(node.get("Actual Loops") or 1),
            3,
        ),
    }

def _measure(cur: Any, sql: str, params: list[Any]) -> dict[str, Any]:
    samples: list[float] = []
    row: dict[str, Any] = {}
    for _ in range(SAMPLES):
        started = time.perf_counter()
        cur.execute(sql, params)
        row = dict(cur.fetchone() or {})
        samples.append((time.perf_counter() - started) * 1000)
    cur.execute("explain (analyze, buffers, format json) " + sql, params)
    explain = cur.fetchone()["QUERY PLAN"]
    plan = explain[0]["Plan"]
    return {
        "samples": SAMPLES,
        "p50_ms": round(statistics.median(samples), 3),
        "p95_ms": _percentile(samples, 0.95),
        "counts": {key.removesuffix("_count"): int(value or 0) for key, value in row.items()},
        "dominant_plan_node": _dominant_leaf(plan),
    }

def measure() -> dict[str, Any]:
    with connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("select set_config('statement_timeout', %s, true)", (str(REPORT_DATA_TIMEOUT_MS),))
        cur.execute(
            "select id from auth_users where lower(username)=%s and is_active=true",
            ("platform-owner",),
        )
        subject = cur.fetchone()
        if not subject:
            raise RuntimeError("active_owner_not_found")
        access = effective_access(None, preview_user_id=int(subject["id"]))
        report = next(
            item for item in access["reports"] if item["report_key"] == "events.explorer"
        )
        grants = [
            item for item in report.get("grants") or []
            if "view" in (item.get("allowed_actions") or [])
        ]
        scopes = [dict(item.get("scope") or {}) for item in grants]
        scope_clauses, scope_params, unrestricted = _scope(scopes)
        cur.execute(
            """select registry.definition_json
               from report_registry_v4 registry
               where registry.report_key=%s and registry.version=%s""",
            ("events.explorer", report["version"]),
        )
        definition = dict((cur.fetchone() or {}).get("definition_json") or {})
        definition_clauses, definition_params, _ = _compile_definition_query(
            "events.v2", definition
        )
        definition_clauses = [item.replace("?", "%s") for item in definition_clauses]
        scoped_sql, category_params = _count_sql(scope_clauses + definition_clauses)
        corpus_sql, corpus_category_params = _count_sql(definition_clauses)
        scoped = _measure(
            cur, scoped_sql, category_params + scope_params + definition_params
        )
        if scoped_sql == corpus_sql and scope_params == []:
            corpus = {**scoped, "shared_identical_query_samples": True}
        else:
            corpus = _measure(
                cur, corpus_sql, corpus_category_params + definition_params
            )
        conn.rollback()

    function_line = inspect.getsourcelines(_compile_interactive_event_query)[1]
    append_line = inspect.getsourcelines(_append_predicates)[1]
    difference = {
        key: corpus["counts"][key] - scoped["counts"][key]
        for key in scoped["counts"]
    }
    return {
        "status": "measured",
        "principal": "platform-owner",
        "report": "events.explorer",
        "scope": {
            "unrestricted": unrestricted,
            "grant_count": len(grants),
            "kinds": sorted({str(item.get("kind") or "") for item in scopes}),
        },
        "filter_placement": {
            "can_apply_after_access_scope": True,
            "compile_function": "_compile_interactive_event_query",
            "compile_line": function_line,
            "scope_composition_function": "_append_predicates",
            "scope_composition_line": append_line,
            "effective_where_line": inspect.getsourcelines(
                sys.modules["server.sli.reporting.reporting_v4"].execute_report
            )[1] + 274,
        },
        "assigned_slice": scoped,
        "whole_corpus": corpus,
        "legacy_endpoint_minus_report": difference,
        "timeout_budget_ms": REPORT_DATA_TIMEOUT_MS,
        "read_contract": "aggregate counts and EXPLAIN only; no event rows or payload",
    }

if __name__ == "__main__":
    print(json.dumps(measure(), ensure_ascii=False, indent=2))

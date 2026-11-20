#!/usr/bin/env python3
"""Measure bounded newest-4624 lookup cost without exposing account identities."""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from server.sli.core.postgres_runtime_pipeline import connect  # noqa: E402
TIMEOUT_MS = 50_000
SAMPLES = 7
LATEST_SQL = """
select requested.ordinality, latest.latest_utc
from unnest(%s::text[]) with ordinality requested(account_key, ordinality)
left join lateral (
    select event.time_created_utc as latest_utc
    from events_v2_core event
    where event.event_id=4624
      and lower(event.target_user_name)=requested.account_key
    order by event.time_created_utc desc,event.id desc
    limit 1
) latest on true
order by requested.ordinality
"""
PRIVILEGED_SQL = """
select distinct source_entity.id as entity_id,
       lower(account.attributes_json->'attributes'->>'sam_account_name') as account_key
from ad_context_relation_versions relation
join entities_v2 source_entity on source_entity.id=relation.source_entity_id
join lateral (
    select current.attributes_json
    from ad_context_entity_versions current
    where current.entity_id=source_entity.id
      and current.source_section='directory_accounts'
      and current.valid_to_utc is null
    order by current.last_observed_at_utc desc,current.id desc
    limit 1
) account on true
where relation.valid_to_utc is null
  and relation.relation_kind='member_of'
  and relation.source_section='privileged_membership'
  and coalesce(account.attributes_json->'attributes'->>'sam_account_name','')<>''
order by account_key,source_entity.id
"""
class StopMeasurement(RuntimeError):
    pass
def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return round(ordered[max(0, int(len(ordered) * .95 + .999999) - 1)], 3)
def _walk(plan: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = [plan]
    for child in plan.get("Plans") or []:
        if isinstance(child, dict):
            nodes.extend(_walk(child))
    return nodes
def _node_summary(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "node_type": node.get("Node Type"),
        "relation": node.get("Relation Name"),
        "index": node.get("Index Name"),
        "actual_total_ms_x_loops": round(
            float(node.get("Actual Total Time") or 0)
            * float(node.get("Actual Loops") or 1), 3
        ),
    }
def _measure(cur: Any, names: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    samples: list[float] = []
    rows: list[dict[str, Any]] = []
    for _ in range(SAMPLES):
        started = time.perf_counter()
        cur.execute(LATEST_SQL, (names,))
        rows = [dict(row) for row in cur.fetchall()]
        elapsed = (time.perf_counter() - started) * 1000
        if elapsed >= TIMEOUT_MS:
            raise StopMeasurement("newest_4624_aggregate_exceeded_50000_ms")
        samples.append(elapsed)
    cur.execute("explain (analyze, buffers, format json) " + LATEST_SQL, (names,))
    plan = cur.fetchone()["QUERY PLAN"][0]["Plan"]
    nodes = _walk(plan)
    leaves = [node for node in nodes if not node.get("Plans")] or nodes
    dominant = max(
        leaves,
        key=lambda node: float(node.get("Actual Total Time") or 0)
        * float(node.get("Actual Loops") or 1),
    )
    indexes = sorted({
        str(node["Index Name"]) for node in nodes if node.get("Index Name")
    })
    return {
        "names": len(names),
        "samples": SAMPLES,
        "p50_ms": round(statistics.median(samples), 3),
        "p95_ms": _p95(samples),
        "execution_plan_ms": round(float(plan.get("Actual Total Time") or 0), 3),
        "dominant_leaf": _node_summary(dominant),
        "indexes_used": indexes,
        "uses_index": bool(indexes),
    }, rows
def measure() -> dict[str, Any]:
    with connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("select set_config('statement_timeout',%s,true)", (str(TIMEOUT_MS),))
        cur.execute(PRIVILEGED_SQL)
        privileged = [dict(row) for row in cur.fetchall()]
        names22 = [str(row["account_key"]) for row in privileged]
        if len(names22) != 22 or len(set(names22)) != 22:
            raise StopMeasurement(f"expected_22_exact_privileged_names_got_{len(names22)}")
        cur.execute(
            """select lower(version.attributes_json->'attributes'->>'sam_account_name') account_key
               from ad_context_entity_versions version
               where version.valid_to_utc is null
                 and version.source_section='directory_accounts'
                 and lower(coalesce(version.attributes_json->'identity'->>'kind',''))='ad_user'
                 and coalesce(version.attributes_json->'attributes'->>'sam_account_name','')<>''
                 and not (lower(version.attributes_json->'attributes'->>'sam_account_name')=any(%s))
               order by account_key,version.entity_id limit 78""",
            (names22,),
        )
        names100 = names22 + [str(row["account_key"]) for row in cur.fetchall()]
        if len(names100) != 100 or len(set(names100)) != 100:
            raise StopMeasurement(f"expected_100_unique_directory_names_got_{len(set(names100))}")
        cost22, result22 = _measure(cur, names22)
        cost100, _ = _measure(cur, names100)
        cur.execute(
            """select count(*) total,
                      count(*) filter(where nullif(btrim(target_user_name),'') is not null) target_present,
                      count(*) filter(where nullif(btrim(subject_user_name),'') is not null) subject_present,
                      count(*) filter(where target_user_name<>btrim(target_user_name)) target_whitespace
               from events_v2_core where event_id=4624"""
        )
        quality = dict(cur.fetchone())
        cur.execute(
            """select count(distinct lower(target_user_name)) normalized_matches,
                      count(distinct lower(target_user_name))
                        filter(where target_user_name=any(%s)) exact_case_matches,
                      count(distinct target_user_name) raw_variants
               from events_v2_core
               where event_id=4624 and lower(target_user_name)=any(%s)""",
            (names22, names22),
        )
        matching = dict(cur.fetchone())
        ids = [int(row["entity_id"]) for row in privileged]
        cur.execute(
            """select count(*) filter(where has_links) linked_accounts,
                      count(*) filter(where has_4624) linked_to_4624_accounts
               from (
                 select requested.entity_id,
                   exists(select 1 from event_entity_link_blocks_v2 block
                          where block.entity_id=requested.entity_id) has_links,
                   exists(select 1 from event_entity_link_blocks_v2 block
                          cross join lateral unnest(block.event_ids) linked(event_id)
                          join events_v2_core event on event.id=linked.event_id
                          where block.entity_id=requested.entity_id and event.event_id=4624) has_4624
                 from unnest(%s::integer[]) requested(entity_id)
               ) coverage""",
            (ids,),
        )
        spine = dict(cur.fetchone())
        conn.rollback()
    total = int(quality["total"])
    matched = int(matching["normalized_matches"] or 0)
    missing = sum(1 for row in result22 if row.get("latest_utc") is None)
    if matched + missing != 22:
        raise StopMeasurement("casefold_key_does_not_partition_the_22_accounts_exactly")
    return {
        "status": "measured",
        "read_only": True,
        "timeout_budget_ms": TIMEOUT_MS,
        "cost": {"privileged_22": cost22, "directory_growth_100": cost100},
        "field_contract": {
            "event_id": 4624,
            "account_field": "events_v2_core.target_user_name",
            "target_present_rows": int(quality["target_present"] or 0),
            "target_present_percent": round(100 * int(quality["target_present"] or 0) / total, 4),
            "subject_present_rows": int(quality["subject_present"] or 0),
            "target_whitespace_rows": int(quality["target_whitespace"] or 0),
            "normalization": "lower(target_user_name) = lower(sam_account_name)",
            "normalization_is_exact_key": True,
            "normalized_privileged_matches": matched,
            "exact_case_privileged_matches": int(matching["exact_case_matches"] or 0),
            "raw_target_variants_for_privileged_names": int(matching["raw_variants"] or 0),
        },
        "identity_spine": {
            "accounts_with_any_event_links": int(spine["linked_accounts"] or 0),
            "accounts_with_linked_4624": int(spine["linked_to_4624_accounts"] or 0),
            "join_on_entity_id_ready_for_this_aggregate":
                int(spine["linked_to_4624_accounts"] or 0) == 22,
        },
        "absence": {
            "privileged_accounts_without_observed_4624": missing,
            "meaning": "No 4624 was observed for this account in the currently collected corpus.",
            "does_not_mean": "Never logged on.",
            "coverage_caveat": "SLI currently collects two domain controllers; a logon may occur on an uncollected host or outside corpus coverage.",
        },
        "query_contract": "One bounded lateral newest-row aggregate over an exact case-insensitive sAMAccountName key; no event payload returned.",
    }
if __name__ == "__main__":
    try:
        print(json.dumps(measure(), ensure_ascii=False, indent=2, default=str))
    except StopMeasurement as exc:
        print(json.dumps({"status": "stopped", "question": str(exc)}, ensure_ascii=False))
        raise SystemExit(2)
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": f"{type(exc).__name__}:{exc}"}, ensure_ascii=False))
        raise SystemExit(1)

"""Bounded, evidence-backed relations for one exact event."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from server.sli.core.database import is_postgres_runtime_db, query_rows_bounded
from server.sli.core.keyset_cursor import decode_cursor, encode_cursor
from server.sli.storage.runtime_storage import (
    StorageRouteConsumer,
    resolve_storage_route,
)
from server.sli.storage.storage_v2_transition_controller import CutoverAuthorization


def get_event_relations(
    event_db_id: int,
    *,
    limit: int = 100,
    cursor: str | None = None,
    authorization: CutoverAuthorization | None = None,
    consumer: str = StorageRouteConsumer.EVENT_RELATIONS,
) -> dict[str, Any]:
    """Return stored links or narrowly defined, rule-based correlations.

    A nearby timestamp is deliberately not a relation: it may be rendered by a
    caller as context, but never receives the same evidentiary status.
    """
    event_id = int(event_db_id)
    page_limit = max(1, min(int(limit), 200))
    _require_v2_relations_route(authorization, consumer)
    return _v2_relations_response(event_id, page_limit, cursor=cursor)


def _require_v2_relations_route(
    authorization: CutoverAuthorization | None,
    consumer: str = StorageRouteConsumer.EVENT_RELATIONS,
) -> None:
    """Storage V2 is the only route (plan 6.5); reject bad authority or non-PostgreSQL."""
    resolve_storage_route(authorization=authorization, consumer=consumer)
    if not is_postgres_runtime_db():
        raise ValueError("storage_v2_route_requires_postgres")


def _v2_relations_response(event_id: int, page_limit: int, *, cursor: str | None = None) -> dict[str, Any]:
    """Build the public correlation contract from V2 compact facts only."""
    after = None
    if cursor is not None:
        position = decode_cursor(cursor, ["event-relations", event_id])
        try:
            delta = Decimal(position["delta"])
            row_id = position["id"]
            if not delta.is_finite() or delta < 0 or type(row_id) is not int or not 0 < row_id < 2**63:
                raise ValueError("invalid_cursor")
            after = (str(delta), -row_id)
        except (KeyError, TypeError, ValueError, InvalidOperation) as exc:
            raise ValueError("invalid_cursor") from exc
    rows = (_query_v2_relation_rows(event_id, page_limit + 1, after=after)
            if after is not None else _query_v2_relation_rows(event_id, page_limit + 1))
    return _v2_relations_contract(event_id, rows, page_limit)


def _query_v2_relation_rows(event_id: int, page_limit: int, *, after: tuple[str, int] | None = None) -> list[dict[str, Any]]:
    """Read V2 relation candidates through one selective evidence key at a time."""
    base_rows = query_rows_bounded(
        """
        select
            base_event.server_id,
            base_event.time_created_utc,
            base_event.logon_id,
            base_fact.task_name
        from events_v2_core base_event
        left join event_facts_v2 base_fact on base_fact.event_id = base_event.id
        where base_event.id = ?
        limit 1
        """,
        (event_id,),
        statement_timeout_ms=3000,
    )
    if not base_rows:
        return []

    base = base_rows[0]
    server_id = int(base["server_id"])
    base_time = base.get("time_created_utc")
    logon_id = str(base.get("logon_id") or "").strip()
    task_name = str(base.get("task_name") or "").strip()
    rows: list[dict[str, Any]] = []
    cursor_sql = "" if after is None else """
      and (abs(extract(epoch from (other_event.time_created_utc - cast(? as timestamptz)))),
           -other_event.id) > (cast(? as numeric), ?)
    """
    cursor_params = () if after is None else (base_time, *after)

    # Keep independently indexed evidence keys in independent statements.  A
    # single OR between LogonId and TaskName makes PostgreSQL abandon both
    # selective paths and scan the full event corpus before applying LIMIT.
    if logon_id.lower() not in {"", "-", "0x0"}:
        rows.extend(query_rows_bounded(
            f"""
            select
                other_event.id as related_event_db_id,
                other_event.event_id as related_event_id,
                other_event.time_created_utc as related_time_utc,
                'auth_session' as entity_type,
                other_event.logon_id as entity,
                'context' as source_role,
                'context' as related_role,
                abs(extract(epoch from (
                    other_event.time_created_utc - cast(? as timestamptz)
                ))) as time_delta_seconds,
                'same_logon_id_same_server' as relation_rule
            from events_v2_core other_event
            where other_event.logon_id = ?
              and other_event.server_id = ?
              and other_event.id <> ?
              and other_event.time_created_utc between cast(? as timestamptz) - interval '4 hours'
                                                     and cast(? as timestamptz) + interval '4 hours'
            {cursor_sql}
            order by time_delta_seconds asc, other_event.id desc
            limit ?
            """,
            (base_time, logon_id, server_id, event_id, base_time, base_time, *cursor_params, page_limit),
            statement_timeout_ms=3000,
        ))
    if task_name:
        rows.extend(query_rows_bounded(
            f"""
            select
                other_event.id as related_event_db_id,
                other_event.event_id as related_event_id,
                other_event.time_created_utc as related_time_utc,
                'scheduled_task' as entity_type,
                other_fact.task_name as entity,
                'context' as source_role,
                'context' as related_role,
                abs(extract(epoch from (
                    other_event.time_created_utc - cast(? as timestamptz)
                ))) as time_delta_seconds,
                'same_task_same_server_time_window' as relation_rule
            from event_facts_v2 other_fact
            join events_v2_core other_event on other_event.id = other_fact.event_id
            where other_fact.task_name = ?
              and other_event.server_id = ?
              and other_event.id <> ?
              and other_event.time_created_utc between cast(? as timestamptz) - interval '1 hour'
                                                     and cast(? as timestamptz) + interval '1 hour'
            {cursor_sql}
            order by time_delta_seconds asc, other_event.id desc
            limit ?
            """,
            (base_time, task_name, server_id, event_id, base_time, base_time, *cursor_params, page_limit),
            statement_timeout_ms=3000,
        ))
    rows.sort(key=lambda row: (
        Decimal(str(row.get("time_delta_seconds") or 0)),
        -int(row.get("related_event_db_id") or 0),
    ))
    return rows


def _v2_relations_contract(
    event_id: int,
    rows: list[dict[str, Any]],
    page_limit: int,
) -> dict[str, Any]:
    """Project bounded V2 rows into the stable public relation contract."""
    items: list[dict[str, Any]] = []
    seen_related_events: set[int] = set()
    for row in rows:
        related = int(row["related_event_db_id"])
        if related <= 0 or related == event_id or related in seen_related_events:
            continue
        seen_related_events.add(related)
        relation_rule = str(row.get("relation_rule") or "same_task_same_server_time_window")
        is_logon = relation_rule == "same_logon_id_same_server"
        time_delta = int(float(row.get("time_delta_seconds") or 0))
        entity = str(row.get("entity") or "")
        items.append({
            "relation_type": "computed_correlation",
            "relation_origin": "computed",
            "confidence_kind": "rule_policy_score",
            "related_event_db_id": related,
            "source_event_db_id": event_id,
            "target_event_db_id": related,
            "rule_id": relation_rule,
            "confidence": 0.95 if is_logon else 0.80,
            "related_event_id": int(row.get("related_event_id") or 0),
            "related_time_utc": row.get("related_time_utc"),
            "relation_strength": "strong" if is_logon else "medium",
            "relation_rule": relation_rule,
            "time_delta_seconds": time_delta,
            "entity": entity,
            "entity_type": row.get("entity_type"),
            "source_role": row.get("source_role"),
            "related_role": row.get("related_role"),
            "reason_code": relation_rule,
            "reason_params": {"time_delta_seconds": time_delta},
            "reason": (
                f"Совпали LogonId и сервер; разница во времени {time_delta} с."
                if is_logon else f"Совпали имя задания и сервер; разница во времени {time_delta} с."
            ),
            "explanation": (
                f"Совпали LogonId и сервер: {entity or 'без значения'}."
                if is_logon else f"Совпали задание и сервер: {entity or 'без имени'}."
            ),
            "evidence_fields": (
                ["LogonId", "server_id", "time_created_utc"]
                if is_logon else ["TaskName", "server_id", "time_created_utc"]
            ),
        })
    next_cursor = None
    if len(items) > page_limit:
        last_id = items[page_limit - 1]["related_event_db_id"]
        last_row = next(row for row in rows if int(row["related_event_db_id"]) == last_id)
        next_cursor = encode_cursor(["event-relations", event_id], {
            "delta": str(last_row.get("time_delta_seconds") or 0), "id": last_id,
        })
    return {
        "next_cursor": next_cursor,
        "api_version": "v1",
        "event_db_id": event_id,
        "items": items[:page_limit],
        "truncated": len(items) > page_limit,
        "contract": "explicit_event_link_or_rule_based_correlation",
        "confidence_contract": {
            "stored_link_value": "Значение сохранённой явной связи.",
            "rule_policy_score": "Оценка силы правила корреляции; не вероятность и не доказательство причинности.",
        },
    }

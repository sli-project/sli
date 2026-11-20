"""Scoped identity dataset for plugin readers; directory enrichment is optional."""
from __future__ import annotations

from typing import Any

from server.sli.access.scope import AccessScope


def query_entities(cursor: Any, scope: AccessScope, *, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    """Filter provenance and entities before deduplication, count and paging.

    Associations are intentionally read separately with their own scope; a
    directory join must not introduce an entity outside the permitted scope.
    """
    if type(limit) is not int or not 1 <= limit <= 500 or type(offset) is not int or offset < 0:
        raise ValueError("invalid_identity_page")
    predicate, parameters = scope.sql_predicate({
        "plugin_ids": "r.plugin_id", "source_instance_ids": "r.source_instance_id",
        "entity_ids": "r.entity_id", "device_ids": "r.device_id", "collection_scope_ids": "r.collection_scope_id",
    })
    cursor.execute(
        f"""with permitted as (
            select r.* from core_entity_scope_resources r where {predicate}
        ), identities as (
            select distinct on (entity_id) entity_id,entity_type,display_name,natural_key,resolution,observed_at_utc
            from permitted order by entity_id,observed_at_utc desc
        )
        select *,count(*) over() as filtered_count from identities order by entity_id limit %s offset %s""",
        (*parameters, limit, offset),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    count = int(rows[0]["filtered_count"]) if rows else None
    for row in rows:
        row.pop("filtered_count", None)
    return {"items": rows, "filtered_count": count, "has_more": count is not None and offset + len(rows) < count}

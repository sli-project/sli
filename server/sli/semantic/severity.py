from __future__ import annotations

from typing import Any

from server.source_packs.registry import resolve_source_normalizer


def classify_contextual_event(row: dict[str, Any]) -> dict[str, Any]:
    normalizer = resolve_source_normalizer(
        row.get("channel"),
        row.get("provider_name"),
        str(row.get("event_id") or ""),
    )
    if normalizer:
        return normalizer.contextual_classification(row)
    try:
        event_id = int(row.get("event_id") or 0)
    except (TypeError, ValueError):
        event_id = 0
    return {
        "severity": "info",
        "title": f"Event ID {event_id}",
        "reason": "Нет контекстного правила; используется базовая классификация.",
    }


def severity_rank(value: str) -> int:
    return {"critical": 5, "high": 4, "important": 3, "medium": 3, "low": 2, "info": 1}.get(str(value).lower(), 1)

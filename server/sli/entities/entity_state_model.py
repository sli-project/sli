"""Evidence-first, deliberately narrow entity-state projection rules."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from server.sli.semantic.event_card_semantics import build_event_card
from server.source_packs.registry import resolve_source_normalizer

RULESET_VERSION = "entity-state-1.0"


def _utc_text(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def observation_order(observation: dict[str, Any]) -> tuple[datetime, int, str]:
    """Stable newest-wins key; invalid timestamps sort before valid evidence."""
    text = _utc_text(observation.get("observed_at_utc"))
    instant = datetime.min.replace(tzinfo=timezone.utc)
    if text:
        instant = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return instant, int(observation.get("source_event_db_id") or 0), str(observation.get("rule_version") or "")


def resolve_current(current: dict[str, Any] | None, candidate: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return ``insert``, ``replace``, ``same``, ``older`` or explicit ``conflict``."""
    if current is None:
        return "insert", candidate
    current_key = observation_order(current)
    candidate_key = observation_order(candidate)
    if candidate_key > current_key:
        return "replace", candidate
    if candidate_key < current_key:
        return "older", current
    if str(current.get("status")) == str(candidate.get("status")):
        return "same", current
    conflict = dict(candidate)
    conflict["status"] = "unknown"
    conflict["projection_status"] = "conflict"
    conflict["conflict_statuses"] = sorted({str(current.get("status")), str(candidate.get("status"))})
    return "conflict", conflict


def state_for_entity_link(event_row: dict[str, Any], event_data: dict[str, Any], link: dict[str, Any]) -> dict[str, Any] | None:
    """Project only target/affected entities from a known catalogue event."""
    role = str(link.get("link_role") or "")
    if role not in {"target", "affected"}:
        return None
    try:
        event_id = int(event_row.get("event_id") or 0)
    except (TypeError, ValueError):
        return None
    source_normalizer = resolve_source_normalizer(
        event_row.get("channel"),
        event_row.get("provider_name"),
        str(event_id),
    )
    rule = (
        source_normalizer.state_semantics(
            channel=event_row.get("channel"),
            event_id=event_id,
        )
        if source_normalizer
        else None
    )
    if rule is None:
        return None
    card = build_event_card({**event_row, "event_data": event_data})
    if not card.get("known") or not card.get("catalog_match"):
        return None
    observed_at = _utc_text(event_row.get("time_created_utc") or event_row.get("time_created"))
    if observed_at is None:
        return None
    return {
        "state_type": rule.state_type,
        "severity": str(card["severity"]),
        "status": rule.status,
        "observed_at_utc": observed_at,
        "summary": str(card["title"]),
        "rule_id": rule.rule_id,
        "rule_version": RULESET_VERSION,
        "projection_status": "normal",
        "details": {
            "catalog_key": {
                "provider": event_row.get("provider_name"),
                "channel": event_row.get("channel"),
                "event_id": event_id,
            },
            "entity_role": role,
            "catalog_match": card.get("catalog_match"),
        },
    }

from __future__ import annotations

from typing import Any


MEMBERSHIP_ADD_EVENTS = frozenset({4728, 4732, 4756})
MEMBERSHIP_REMOVE_EVENTS = frozenset({4729, 4733, 4757})


def explain_privileged_membership_event(
    event: dict[str, Any],
    *,
    relation: dict[str, Any] | None,
    historical_context_available: bool,
) -> dict[str, Any]:
    """Explain one exact membership event without inventing causality or risk."""
    try:
        event_id = int(event.get("event_id"))
    except (TypeError, ValueError):
        event_id = 0
    if event_id not in MEMBERSHIP_ADD_EVENTS | MEMBERSHIP_REMOVE_EVENTS:
        return {"matched": False, "reason": "event_not_supported"}
    data = event.get("event_data") if isinstance(event.get("event_data"), dict) else event
    member_sid = _clean(data.get("MemberSid"))
    group_sid = _clean(data.get("TargetSid") or data.get("TargetUserSid"))
    if not member_sid or not group_sid:
        return {
            "matched": False,
            "reason": "stable_sid_pivots_missing",
            "required_fields": ["MemberSid", "TargetSid"],
        }
    if relation is None:
        return {
            "matched": False,
            "reason": "context_relation_not_found",
            "identity_match": "exact_domain_qualified_sid",
            "member_sid": member_sid,
            "group_sid": group_sid,
        }
    if _clean(relation.get("member_sid")) != member_sid or _clean(relation.get("group_sid")) != group_sid:
        return {"matched": False, "reason": "context_relation_identity_mismatch"}
    added = event_id in MEMBERSHIP_ADD_EVENTS
    current_active = bool(relation.get("current_active"))
    if historical_context_available:
        context_label = "historical_context"
        limitation = None
    else:
        context_label = "current_context_only"
        limitation = "Текущий контекст не доказывает состояние на момент события."
    if added and current_active:
        explanation = "Добавление в привилегированную группу подтверждается структурированным AD Context."
    elif added:
        explanation = "Событие добавления найдено, но текущее членство не подтверждено; изменение могло быть временным."
    elif not current_active:
        explanation = "Удаление из привилегированной группы согласуется с текущим AD Context."
    else:
        explanation = "После события удаления членство снова присутствует; требуется проверить последующие изменения."
    return {
        "matched": True,
        "relation_type": "privileged_membership_context",
        "identity_match": "exact_domain_qualified_sid",
        "classification": "Baseline",
        "confidence_kind": "deterministic" if historical_context_available else "incomplete_context",
        "context_kind": context_label,
        "explanation": explanation,
        "limitation": limitation,
        "member_sid": member_sid,
        "group_sid": group_sid,
        "context_evidence_id": relation.get("evidence_id"),
    }


def _clean(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None

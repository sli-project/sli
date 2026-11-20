"""Typed, presentation-neutral semantics for one persisted event.

The event catalogue owns declared meaning.  This module is the only place
that normalizes catalogue values (including legacy aliases) into the public
machine contract.  Human labels remain a separate projection so callers do
not need to parse localized text to filter or compare events.
"""
from __future__ import annotations

from enum import Enum
from typing import Any


class MachineRisk(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class PurposeTier(str, Enum):
    CRITICAL = "critical"
    IMPORTANT = "important"
    TECHNICAL = "technical"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class NoiseClass(str, Enum):
    SIGNAL = "signal"
    CONTEXT = "context"
    NOISE = "noise"
    UNKNOWN = "unknown"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    ACCOUNT_MANAGEMENT = "account_management"
    PRIVILEGE_MANAGEMENT = "privilege_management"
    POLICY_CHANGE = "policy_change"
    SERVICE_TASK = "service_task"
    OPERATIONS = "operations"
    INFRASTRUCTURE = "infrastructure"
    OTHER = "other"
    UNKNOWN = "unknown"


_RISK_ALIASES = {
    "important": MachineRisk.MEDIUM.value,
    "warning": MachineRisk.MEDIUM.value,
    "warn": MachineRisk.MEDIUM.value,
}
_CONFIDENCE_ALIASES = {
    "высокая": Confidence.HIGH.value,
    "средняя": Confidence.MEDIUM.value,
    "низкая": Confidence.LOW.value,
}
_CATEGORY_ALIASES = {
    "auth": EventCategory.AUTHENTICATION.value,
    "logon": EventCategory.AUTHENTICATION.value,
    "account": EventCategory.ACCOUNT_MANAGEMENT.value,
    "accounts": EventCategory.ACCOUNT_MANAGEMENT.value,
    "privileges": EventCategory.PRIVILEGE_MANAGEMENT.value,
    "services_tasks": EventCategory.SERVICE_TASK.value,
    "service": EventCategory.SERVICE_TASK.value,
    "event": EventCategory.OTHER.value,
    "infra": EventCategory.INFRASTRUCTURE.value,
}


def normalize_risk(value: Any, *, unknown: str = MachineRisk.UNKNOWN.value) -> str:
    key = str(value or "").strip().lower()
    key = _RISK_ALIASES.get(key, key)
    return key if key in {item.value for item in MachineRisk} else unknown


def normalize_confidence(value: Any, *, unknown: str = Confidence.UNKNOWN.value) -> str:
    key = str(value or "").strip().lower()
    key = _CONFIDENCE_ALIASES.get(key, key)
    return key if key in {item.value for item in Confidence} else unknown


def normalize_category(value: Any, *, known: bool = True) -> str:
    key = str(value or "").strip().lower()
    key = _CATEGORY_ALIASES.get(key, key)
    if key in {item.value for item in EventCategory}:
        return key
    return EventCategory.OTHER.value if known else EventCategory.UNKNOWN.value


def normalize_purpose_tier(value: Any, *, final_risk: str, known: bool) -> str:
    key = str(value or "").strip().lower()
    if key in {item.value for item in PurposeTier}:
        return key
    if not known:
        return PurposeTier.TECHNICAL.value
    if final_risk in {MachineRisk.CRITICAL.value, MachineRisk.HIGH.value}:
        return PurposeTier.CRITICAL.value
    if final_risk == MachineRisk.MEDIUM.value:
        return PurposeTier.IMPORTANT.value
    return PurposeTier.TECHNICAL.value


def normalize_noise_class(value: Any, *, final_risk: str, known: bool) -> str:
    key = str(value or "").strip().lower()
    if key in {item.value for item in NoiseClass}:
        return key
    if not known:
        return NoiseClass.UNKNOWN.value
    if final_risk in {MachineRisk.CRITICAL.value, MachineRisk.HIGH.value, MachineRisk.MEDIUM.value}:
        return NoiseClass.SIGNAL.value
    return NoiseClass.CONTEXT.value


def build_machine_semantics(
    *, entry: dict[str, Any] | None, final_risk: Any, confidence: Any,
    purpose_tier: Any = None, category: Any = None, noise_class: Any = None,
    reasons: list[str] | tuple[str, ...] | None = None,
    evidence_fields: list[str] | tuple[str, ...] | None = None,
    classification_origin: str = "unavailable",
    card_completeness: str = "not_applicable",
) -> dict[str, Any]:
    """Build the canonical semantic contract from one catalogue result.

    The long canonical names are authoritative.  ``final_risk`` and
    ``confidence`` remain additive compatibility aliases for existing backend
    consumers; both aliases are derived here and can therefore never disagree
    with their canonical counterpart.  ``classification_origin`` says whether
    the value is a catalog base class or a matched contextual rule; it never
    turns an event card into a finding or scenario assessment.
    """
    known = entry is not None
    base_risk = normalize_risk((entry or {}).get("base_risk") or (entry or {}).get("severity"))
    normalized_final = normalize_risk(final_risk, unknown=base_risk)
    if not known:
        base_risk = MachineRisk.UNKNOWN.value
        normalized_final = MachineRisk.UNKNOWN.value
    assessment_confidence = normalize_confidence(confidence)
    canonical_reasons = list(dict.fromkeys(str(value) for value in (reasons or []) if str(value).strip()))
    canonical_fields = list(dict.fromkeys(str(value) for value in (evidence_fields or []) if str(value).strip()))
    return {
        "category": normalize_category(category or (entry or {}).get("category"), known=known),
        "purpose_tier": normalize_purpose_tier(
            purpose_tier or (entry or {}).get("purpose_tier"), final_risk=normalized_final, known=known
        ),
        "base_risk": base_risk,
        "final_security_severity": normalized_final,
        "assessment_confidence": assessment_confidence,
        "classification_origin": (
            classification_origin
            if classification_origin in {"catalog_base", "contextual_rule", "unavailable"}
            else "unavailable"
        ),
        "card_completeness": (
            card_completeness
            if card_completeness in {"complete", "partial", "not_applicable"}
            else "not_applicable"
        ),
        "catalog_match": known,
        "reasons": canonical_reasons,
        "evidence_fields": canonical_fields,
        # Transitional aliases.  Do not calculate these in individual callers.
        "final_risk": normalized_final,
        "confidence": assessment_confidence,
        "noise_class": normalize_noise_class(
            noise_class or (entry or {}).get("noise_class"), final_risk=normalized_final, known=known
        ),
    }

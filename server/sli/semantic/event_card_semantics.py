"""Catalog-driven semantics for the human event card.

This is deliberately a small contract: a source pack can supply a catalog
entry without putting product-specific Event IDs into the report renderer.
The renderer owns presentation; the catalog owns meaning and field mappings.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from server.sli.events.event_catalog import event_catalog_entries, lookup_event_catalog
from server.sli.semantic.event_semantic_contract import (
    build_machine_semantics,
    normalize_risk,
)
from server.source_packs.registry import resolve_source_pack

_RISK = {
    "critical": ("Высокий риск", "risk-high"),
    "high": ("Высокий риск", "risk-high"),
    "important": ("Требует проверки", "risk-medium"),
    "medium": ("Требует проверки", "risk-medium"),
    "low": ("Низкий риск", "risk-low"),
    "info": ("Информация", "risk-info"),
}


@dataclass(frozen=True, kw_only=True)
class CompiledRiskSql:
    """SQL projection of the catalogue's final-risk contract.

    ``case_sql`` returns a machine risk for a catalogue-matched row and
    ``matched_sql`` identifies rows owned by one of those declarations.  A
    caller may therefore keep an explicit legacy fallback for unknown rows
    without overriding catalogue-owned meaning.
    """

    case_sql: str
    matched_sql: str
    case_params: tuple[Any, ...]
    matched_params: tuple[Any, ...]
    exact: bool
    limitations: tuple[str, ...]


def build_event_card(item: dict[str, Any]) -> dict[str, Any]:
    card = _build_catalog_event_card(item)
    priority = item.get("watch_priority")
    if isinstance(priority, dict) and priority.get("reason") == "watch":
        from server.sli.semantic.account_watch import effective_severity, SEVERITIES

        base, final = priority.get("base_severity"), priority.get("effective_severity")
        if base in SEVERITIES and final == effective_severity(base):
            risk, risk_class = _RISK[final]
            card = {**card, "base_risk": base, "severity": final, "final_risk": final,
                    "final_security_severity": final, "risk": risk, "risk_class": risk_class,
                    "classification_origin": "contextual_rule",
                    "reasons": list(dict.fromkeys([*card["reasons"], "watch"])),
                    "watch_priority": priority,
                    "display_labels": {**card["display_labels"], "risk": risk}}
    return card


def _build_catalog_event_card(item: dict[str, Any]) -> dict[str, Any]:
    """Return a safe analyst card from a catalog entry and a normalized event.

    Unknown events intentionally receive no invented action, result or advice.
    Their raw fields remain available in the technical section of the report.
    """
    event_id = int(item.get("event_id") or 0)
    entry = lookup_event_catalog(event_id, item.get("channel"), item.get("provider_name"))
    pack = resolve_source_pack(
        item.get("channel"),
        item.get("provider_name"),
        str(event_id),
    )
    if not entry:
        machine = build_machine_semantics(
            entry=None,
            final_risk=None,
            confidence="low",
            reasons=["catalog_rule_missing"],
            evidence_fields=[],
            classification_origin="unavailable",
            card_completeness="not_applicable",
        )
        return {
            "known": False,
            "has_card": False,
            "title": "Событие пока не расшифровано каталогом",
            "title_code": "uncatalogued.title",
            "summary_code": "uncatalogued.summary",
            "severity": machine["final_security_severity"],
            "tier": "technical",
            "risk": "Оценка ИБ не определена",
            "assessment_confidence_label": "низкая",
            "risk_class": "risk-info",
            "facts": _present_facts([("Сервер", item.get("server")), ("Журнал", item.get("channel"))]),
            "summary": "Каталог не содержит правила для этого Provider, Channel и Event ID. Ни действие, ни результат не интерпретируются автоматически.",
            "checks": ["Открыть технические данные и сообщение Windows.", "Добавить проверенное правило в каталог события, если оно повторяется."],
            "related_event_ids": [],
            "technical_reason": "Не найдено правило по ключу Provider + Channel + Event ID.",
            "source_pack": pack.public_dict() if pack else None,
            **machine,
            "display_labels": {"risk": "Оценка ИБ не определена", "confidence": "низкая"},
        }

    card = dict(entry.get("card") or {})
    values = catalog_role_values(item, entry=entry)
    risk_key, tier, assessment, confidence_override, matched_rule_index, matched_rule = _contextual_risk(
        card, item, values, entry.get("severity", "info")
    )
    technical_reason = _missing_reason(card, values)
    has_card = bool(card)
    # A catalog descriptor without a card declares a source classification,
    # not an assessed set of required roles.  Zero configured roles must not
    # appear as a high-confidence assessment.
    confidence = "unknown" if not has_card else ("высокая" if not technical_reason else "средняя")
    if confidence_override:
        confidence = {"low": "низкая", "medium": "средняя", "high": "высокая"}.get(confidence_override, confidence_override)
    risk_key = normalize_risk(risk_key, unknown="info")
    risk, risk_class = _RISK.get(risk_key, _RISK["info"])
    machine = build_machine_semantics(
        entry=entry,
        final_risk=risk_key,
        confidence=confidence,
        purpose_tier=tier,
        category=card.get("category"),
        noise_class=card.get("noise_class"),
        reasons=_semantic_reasons(card, values, matched_rule_index),
        evidence_fields=_semantic_evidence_fields(card, values, matched_rule),
        classification_origin="contextual_rule" if matched_rule_index is not None else "catalog_base",
        card_completeness=("not_applicable" if not has_card else ("partial" if technical_reason else "complete")),
    )

    fact_label_codes = ["facts.event"]
    facts: list[tuple[str, str]] = [("Событие", str(card.get("action") or entry.get("title") or f"Event ID {event_id}"))]
    labels = {
        "object": str(card.get("object_label") or "Объект изменения"),
        "initiator": "Кто выполнил изменение",
        "account": "Учётная запись",
        "result": "Результат",
    }
    for role in card.get("fact_order") or ("object", "initiator", "account"):
        value = values.get(str(role))
        if value:
            facts.append((labels.get(str(role), str(role)), value))
            fact_label_codes.append(_card_text_code(entry, "object_label") if str(role) == "object" else f"facts.{role}")
        elif str(role) in set(card.get("expected_roles") or []):
            facts.append((labels.get(str(role), str(role)), "Не удалось определить"))
            fact_label_codes.append(_card_text_code(entry, "object_label") if str(role) == "object" else f"facts.{role}")
    fact_label_codes.append("facts.server")
    facts.append(("Сервер", str(item.get("server") or item.get("computer") or "Не удалось определить")))
    result = str(card.get("result") or "").strip()
    if values.get("result"):
        result = values["result"]
    if result:
        facts.append(("Результат", result))
        fact_label_codes.append("facts.result")

    checks = [str(value) for value in card.get("checks") or [] if str(value).strip()]
    if not checks:
        checks = [str(entry.get("fix") or "Открыть технические данные и сообщение Windows.")]
    return {
        "known": True,
        "has_card": has_card,
        "severity": risk_key,
        "tier": tier,
        "title": str(card.get("action") or entry.get("title") or f"Event ID {event_id}"),
        "title_code": _card_text_code(entry, "title"),
        "summary_code": _card_text_code(
            entry, f"summary.rule.{matched_rule_index}" if matched_rule_index is not None and assessment else "summary"
        ),
        "risk": risk,
        "assessment_confidence_label": confidence,
        "risk_class": risk_class,
        "facts": facts,
        "fact_label_codes": fact_label_codes,
        "summary": assessment or str(card.get("purpose") or entry.get("why") or "Событие расшифровано локальным каталогом."),
        "checks": checks,
        "check_codes": [_card_text_code(entry, f"checks.{index}") for index in range(len(checks))],
        "related_event_ids": [int(value) for value in card.get("related_event_ids") or []],
        "technical_reason": technical_reason,
        "source_pack": pack.public_dict() if pack else None,
        **machine,
        "display_labels": {"risk": risk, "confidence": confidence},
    }


def _card_text_code(entry: dict[str, Any], field: str) -> str:
    """Include provider/channel identity: numeric Event IDs alone are ambiguous."""
    return f"{entry.get('channel') or ''}:{entry.get('provider_name') or ''}:{entry['event_id']}.{field}"


def compile_catalog_risk_sql(
    event_ids: list[int] | tuple[int, ...], *, event_alias: str = "e", server_alias: str = "s",
    placeholder: str = "?",
) -> CompiledRiskSql:
    """Compile catalogue base/contextual risk for a bounded Event ID set.

    The supported rule operators are deliberately the operators interpreted by
    :func:`_matches_rule`.  Unsupported risk-changing rules are reported via
    ``exact=False`` instead of being silently approximated.
    """
    cases: list[str] = []
    matches: list[str] = []
    limitations: list[str] = []
    case_params: list[Any] = []
    matched_params: list[Any] = []
    entries = event_catalog_entries(event_ids)
    entries.sort(
        key=lambda entry: (
            bool(str(entry.get("channel") or "").strip())
            + bool(str(entry.get("provider_name") or "").strip()),
            int(entry.get("event_id") or 0),
        ),
        reverse=True,
    )
    for entry in entries:
        entry_match, entry_params = _catalog_entry_match_sql(entry, event_alias=event_alias, placeholder=placeholder)
        matches.append(entry_match)
        matched_params.extend(entry_params)
        base = normalize_risk(entry.get("base_risk") or entry.get("severity"), unknown="info")
        risk_case = placeholder
        risk_params: list[Any] = [base]
        card = dict(entry.get("card") or {})
        for index, rule_value in reversed(list(enumerate(card.get("risk_rules") or []))):
            rule = dict(rule_value)
            severity = normalize_risk(rule.get("severity") or base, unknown=base)
            if severity == base:
                continue
            condition_result = _catalog_rule_sql(
                rule,
                event_alias=event_alias,
                server_alias=server_alias,
                placeholder=placeholder,
            )
            if condition_result is None:
                limitations.append(f"event_id={int(entry.get('event_id') or 0)}:risk_rule={index}")
                continue
            condition_sql, condition_params = condition_result
            risk_case = f"case when {condition_sql} then {placeholder} else {risk_case} end"
            risk_params = [*condition_params, severity, *risk_params]
        cases.append(f"when {entry_match} then {risk_case}")
        case_params.extend([*entry_params, *risk_params])
    matched_sql = "(" + " or ".join(matches) + ")" if matches else "(1 = 0)"
    case_sql = "case " + " ".join(cases) + f" else {placeholder} end" if cases else placeholder
    case_params.append("unknown")
    return CompiledRiskSql(
        case_sql=case_sql,
        matched_sql=matched_sql,
        case_params=tuple(case_params),
        matched_params=tuple(matched_params),
        exact=not limitations,
        limitations=tuple(limitations),
    )
def catalog_role_values(item: dict[str, Any], *, entry: dict[str, Any] | None = None) -> dict[str, str]:
    """Return semantic field values declared by the matching source catalog.

    Entity extraction and indexed event columns use this same small helper as
    the analyst card. A source pack therefore declares field meaning once,
    instead of every consumer guessing product-specific parameter names.
    """
    if entry is None:
        entry = lookup_event_catalog(
            int(item.get("event_id") or 0), item.get("channel"), item.get("provider_name")
        )
    if not entry:
        return {}
    roles = dict((entry.get("card") or {}).get("field_roles") or {})
    return {name: _first_value(item, names) for name, names in roles.items()}


def _first_value(item: dict[str, Any], names: Any) -> str:
    data = item.get("event_data") or {}
    for name in names or []:
        key = str(name)
        value = item.get(key) if key in item else data.get(key)
        text = str(value or "").strip()
        if text and text not in {"-", "—"}:
            return text
    return ""


def _present_facts(values: list[tuple[str, Any]]) -> list[tuple[str, str]]:
    return [(label, str(value).strip()) for label, value in values if str(value or "").strip()]


def _contextual_risk(
    card: dict[str, Any], item: dict[str, Any], values: dict[str, str], base: str
) -> tuple[str, str, str, str, int | None, dict[str, Any] | None]:
    for index, rule_value in enumerate(card.get("risk_rules") or []):
        rule = dict(rule_value)
        if _matches_rule(dict(rule), item, values):
            severity = str(rule.get("severity") or base)
            assessment = str(rule.get("assessment") or "")
            return (
                severity,
                str(rule.get("tier") or card.get("tier") or _tier_for_severity(severity)),
                assessment,
                str(rule.get("confidence") or ""),
                index,
                rule,
            )
    severity = str(base)
    return (
        severity,
        str(card.get("tier") or _tier_for_severity(severity)),
        str(card.get("assessment") or ""),
        str(card.get("confidence") or ""),
        None,
        None,
    )


def _semantic_reasons(
    card: dict[str, Any], values: dict[str, str], matched_rule_index: int | None
) -> list[str]:
    reasons = ["catalog_rule_matched"]
    if matched_rule_index is not None:
        reasons.append(f"contextual_rule_matched:{matched_rule_index}")
    missing = [str(role) for role in card.get("expected_roles") or [] if not values.get(str(role))]
    reasons.extend(f"expected_role_missing:{role}" for role in missing)
    return reasons


def _semantic_evidence_fields(
    card: dict[str, Any], values: dict[str, str], matched_rule: dict[str, Any] | None
) -> list[str]:
    """Return field names only; never leak EventData values into semantics."""
    roles = dict(card.get("field_roles") or {})
    fields: list[str] = []
    for role, configured_fields in roles.items():
        if values.get(str(role)):
            fields.extend(str(value) for value in configured_fields or [])
    for condition_value in (matched_rule or {}).get("all") or []:
        condition = dict(condition_value)
        fields.extend(str(value) for value in condition.get("fields") or [])
        role = str(condition.get("role") or "")
        if role:
            fields.extend(str(value) for value in roles.get(role) or [])
        if condition.get("dc"):
            fields.append("server")
        if condition.get("contains_any"):
            fields.append("event_data")
    return list(dict.fromkeys(value for value in fields if value))


def _tier_for_severity(severity: str) -> str:
    value = str(severity).lower()
    if value in {"critical", "high"}:
        return "critical"
    if value in {"important", "medium"}:
        return "important"
    return "technical"


def _matches_rule(rule: dict[str, Any], item: dict[str, Any], values: dict[str, str]) -> bool:
    for condition in rule.get("all") or []:
        condition = dict(condition)
        value = values.get(str(condition.get("role") or "")) or _first_value(item, condition.get("fields") or [])
        normalized = value.lower()
        if condition.get("microsoft_namespace") and not normalized.startswith("\\microsoft\\windows\\"):
            return False
        if condition.get("machine_or_system") and not (normalized.endswith("$") or normalized in {"system", "nt authority\\system"}):
            return False
        if condition.get("dc") and not str(item.get("server") or "").lower().startswith("dc"):
            return False
        contains = [str(v).lower() for v in condition.get("contains_any") or []]
        haystack = " ".join(str(v) for v in (item.get("event_data") or {}).values()).lower()
        if contains and not any(token in haystack for token in contains):
            return False
    return True


def _catalog_entry_match_sql(entry: dict[str, Any], *, event_alias: str, placeholder: str) -> tuple[str, list[Any]]:
    clauses = [f"{event_alias}.event_id = {placeholder}"]
    params: list[Any] = [int(entry.get("event_id") or 0)]
    channel = str(entry.get("channel") or "").strip().lower()
    provider = str(entry.get("provider_name") or "").strip().lower()
    if channel:
        clauses.append(f"lower(coalesce({event_alias}.channel, '')) = {placeholder}")
        params.append(channel)
    if provider:
        clauses.append(f"lower(coalesce({event_alias}.provider_name, '')) = {placeholder}")
        params.append(provider)
    return "(" + " and ".join(clauses) + ")", params


def _catalog_rule_sql(
    rule: dict[str, Any], *, event_alias: str, server_alias: str, placeholder: str
) -> tuple[str, list[Any]] | None:
    checks: list[str] = []
    params: list[Any] = []
    for condition_value in rule.get("all") or []:
        condition = dict(condition_value)
        condition_checks: list[str] = []
        if condition.get("dc"):
            condition_checks.append(f"lower(coalesce({server_alias}.hostname, '')) like {placeholder}")
            params.append("dc%")
        contains = [str(value).lower() for value in condition.get("contains_any") or []]
        if contains:
            haystack = f"lower(coalesce({event_alias}.event_data_json, ''))"
            # SQL sees the serialized JSON text while ``_matches_rule`` sees
            # decoded scalar values.  Encode backslashes exactly as JSON does
            # so a UNC indicator (``\\\\``) does not match every ordinary
            # Windows path containing one decoded backslash.
            encoded_tokens = [json.dumps(token, ensure_ascii=False)[1:-1] for token in contains]
            condition_checks.append(
                "(" + " or ".join(f"{haystack} like {placeholder}" for _ in encoded_tokens) + ")"
            )
            params.extend(f"%{token}%" for token in encoded_tokens)
        if condition.get("microsoft_namespace") or condition.get("machine_or_system"):
            # Role extraction can use several catalogue-declared JSON fields.
            # There is no backend-neutral exact JSON scalar expression in the
            # current SQLite/PostgreSQL compatibility contract.  Risk-changing
            # rules using it must not be represented as an exact SQL filter.
            return None
        known_keys = {"dc", "contains_any", "role", "fields", "microsoft_namespace", "machine_or_system"}
        if any(key not in known_keys for key in condition):
            return None
        checks.extend(condition_checks)
    return ("(" + " and ".join(checks) + ")" if checks else "(1 = 1)"), params


def _missing_reason(card: dict[str, Any], values: dict[str, str]) -> str:
    missing = [str(role) for role in card.get("expected_roles") or [] if not values.get(str(role))]
    if not missing:
        return ""
    return "Не извлечены обязательные роли карточки: " + ", ".join(missing) + "."

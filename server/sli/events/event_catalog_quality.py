"""Payload-free event-catalog validation, coverage and fixture promotion."""
from __future__ import annotations

import re
from typing import Any, Iterable

from server.sli.semantic.event_card_semantics import build_event_card
from server.sli.semantic.event_semantic_contract import EventCategory
from server.sli.storage.storage_v2_repository import (
    EVENT_FACTS_V2_WRITE_COLUMNS,
    EVENT_V2_WRITE_COLUMNS,
)

SEVERITIES = {"critical", "high", "medium", "low", "info"}
PURPOSE_TIERS = {"critical", "important", "technical"}
NOISE_CLASSES = {"signal", "context", "noise", "unknown"}
CONFIDENCE = {"low", "medium", "high"}
CATEGORIES = {item.value for item in EventCategory}
FIELD_ROLES = {"initiator", "object", "account", "result"}
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
LIFECYCLE_PERIOD_FIELDS = ("raw_payload_days", "record_days", "warm_record_days")
LIFECYCLE_ROLLUP_ROLES = {"open", "close", "boot_scope"}
PROMOTION_FIELDS = (
    "version", "archive_requirement", "post_promotion_disposition",
    "read_representation", "high_volume", "semantic_role", "hot_need",
    "warm_value", "executable_lifecycle", "budget",
)
PROMOTION_BUDGET_FIELDS = (
    "events_per_day_upper", "source_bytes_per_event_upper",
    "derived_bytes_per_object_upper", "calibration",
)
PREDICATE_OPERATORS = {"one_of", "prefix", "suffix", "contains", "regex", "equals"}
CORRELATION_ROLES = {"open", "close", "step", "standalone"}
CORRELATION_CARDINALITIES = {"pair", "chain", "fan_out"}
V2_IDENTITY_FIELDS = ("source", "stream", "event_key")
STORAGE_EVENT_FIELDS = EVENT_V2_WRITE_COLUMNS | EVENT_FACTS_V2_WRITE_COLUMNS


def _validate_lifecycle_period(value: Any) -> str | None:
    if isinstance(value, bool):
        return "period_must_be_positive_integer_or_predicate"
    if isinstance(value, int):
        return None if value > 0 else "period_must_be_positive_integer_or_predicate"
    if not isinstance(value, dict) or "default" not in value:
        return "period_must_be_positive_integer_or_predicate"
    default = value.get("default")
    if isinstance(default, bool) or not isinstance(default, int) or default <= 0:
        return "predicate_default_must_be_positive_integer"
    rules = value.get("rules")
    if not isinstance(rules, list):
        return "predicate_rules_must_be_array"
    for rule in rules:
        if not isinstance(rule, dict):
            return "predicate_rule_must_be_object"
        if not _FIELD_NAME.fullmatch(str(rule.get("field") or "")):
            return "predicate_field_invalid"
        operator = str(rule.get("op") or "")
        if operator not in PREDICATE_OPERATORS:
            return "predicate_operator_invalid"
        then = rule.get("then")
        if isinstance(then, bool) or not isinstance(then, int) or then <= 0:
            return "predicate_then_must_be_positive_integer"
        if operator == "regex":
            patterns = rule.get("value")
            patterns = patterns if isinstance(patterns, list) else [patterns]
            try:
                for pattern in patterns:
                    re.compile(str(pattern))
            except re.error:
                return "predicate_regex_invalid"
    return None


def _lifecycle_errors(entry: dict[str, Any], index: int) -> list[dict[str, Any]]:
    lifecycle = entry.get("lifecycle")
    if lifecycle is None:
        return []
    if not isinstance(lifecycle, dict):
        return [{"code": "lifecycle_must_be_object", "index": index}]
    errors: list[dict[str, Any]] = []
    for field in LIFECYCLE_PERIOD_FIELDS:
        if field not in lifecycle:
            errors.append({"code": "lifecycle_field_missing", "index": index, "field": field})
            continue
        code = _validate_lifecycle_period(lifecycle[field])
        if code:
            errors.append({"code": code, "index": index, "field": field})
    if "rollup" not in lifecycle:
        errors.append({"code": "lifecycle_field_missing", "index": index, "field": "rollup"})
    elif lifecycle["rollup"] is not None and not isinstance(lifecycle["rollup"], str):
        errors.append({"code": "lifecycle_rollup_invalid", "index": index})
    rollup_role = lifecycle.get("rollup_role")
    if rollup_role is not None and rollup_role not in LIFECYCLE_ROLLUP_ROLES:
        errors.append({"code": "lifecycle_rollup_role_invalid", "index": index})
    promotion = lifecycle.get("promotion")
    if promotion is None:
        return errors
    if not isinstance(promotion, dict):
        return [*errors, {"code": "lifecycle_promotion_must_be_object", "index": index}]
    missing = [field for field in PROMOTION_FIELDS if field not in promotion]
    errors.extend(
        {"code": "lifecycle_promotion_field_missing", "index": index, "field": field}
        for field in missing
    )
    if missing:
        return errors
    if promotion["version"] != "descriptor-lifecycle-v2":
        errors.append({"code": "lifecycle_promotion_version_invalid", "index": index})
    archive_requirement = promotion["archive_requirement"]
    if archive_requirement not in {"archive_required", "no_archive"}:
        errors.append({"code": "lifecycle_archive_requirement_invalid", "index": index})
    if promotion["post_promotion_disposition"] != "delete_source":
        errors.append({"code": "lifecycle_disposition_invalid", "index": index})
    read_representation = promotion["read_representation"]
    if read_representation not in {"archived_atomic", "derived_only"}:
        errors.append({"code": "lifecycle_read_representation_invalid", "index": index})
    if not isinstance(promotion["high_volume"], bool):
        errors.append({"code": "lifecycle_high_volume_invalid", "index": index})
    for field in ("semantic_role", "hot_need", "warm_value"):
        if not isinstance(promotion[field], str) or not promotion[field].strip():
            errors.append({"code": "lifecycle_promotion_term_invalid", "index": index, "field": field})
    if promotion["executable_lifecycle"] not in {
        "existing_warm_then_retention_executor",
        "semantic_then_direct_retention_executor",
    }:
        errors.append({"code": "lifecycle_executable_target_invalid", "index": index})
    if (
        promotion["executable_lifecycle"] == "semantic_then_direct_retention_executor"
        and promotion["archive_requirement"] != "no_archive"
    ):
        errors.append({
            "code": "lifecycle_direct_retention_requires_no_archive",
            "index": index,
        })
    budget = promotion["budget"]
    if not isinstance(budget, dict):
        return [*errors, {"code": "lifecycle_budget_must_be_object", "index": index}]
    missing_budget = [field for field in PROMOTION_BUDGET_FIELDS if field not in budget]
    errors.extend(
        {"code": "lifecycle_budget_field_missing", "index": index, "field": field}
        for field in missing_budget
    )
    for field in PROMOTION_BUDGET_FIELDS[:-1]:
        value = budget.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append({"code": "lifecycle_budget_value_invalid", "index": index, "field": field})
        elif promotion["high_volume"] and value == 0:
            errors.append({"code": "high_volume_budget_must_be_positive", "index": index, "field": field})
    if budget.get("calibration") not in {"representative", "production"}:
        errors.append({"code": "lifecycle_budget_calibration_invalid", "index": index})
    if promotion["high_volume"] and (lifecycle.get("rollup") is None or rollup_role is None):
        errors.append({"code": "high_volume_lifecycle_role_required", "index": index})
    if archive_requirement == "no_archive" and read_representation != "derived_only":
        errors.append({"code": "no_archive_requires_derived_only", "index": index})
    if archive_requirement == "archive_required" and read_representation != "archived_atomic":
        errors.append({"code": "archive_required_requires_archived_atomic", "index": index})
    return errors


def _predicate_errors(
    value: Any,
    *,
    allowed_results: set[str],
    index: int,
    field: str,
) -> list[dict[str, Any]]:
    if isinstance(value, str):
        return [] if value.lower() in allowed_results else [
            {"code": f"invalid_{field}", "index": index}
        ]
    if not isinstance(value, dict) or "default" not in value:
        return [{"code": f"invalid_{field}", "index": index}]
    errors: list[dict[str, Any]] = []
    if str(value.get("default") or "").lower() not in allowed_results:
        errors.append({"code": "predicate_default_invalid", "index": index, "field": field})
    rules = value.get("rules")
    if not isinstance(rules, list):
        return [*errors, {"code": "predicate_rules_must_be_array", "index": index, "field": field}]
    for rule_index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append({"code": "predicate_rule_must_be_object", "index": index, "field": field, "rule": rule_index})
            continue
        if not _FIELD_NAME.fullmatch(str(rule.get("field") or "")):
            errors.append({"code": "predicate_field_invalid", "index": index, "field": field, "rule": rule_index})
        operator = str(rule.get("op") or "")
        if operator not in PREDICATE_OPERATORS:
            errors.append({"code": "predicate_operator_invalid", "index": index, "field": field, "rule": rule_index})
        if str(rule.get("then") or "").lower() not in allowed_results:
            errors.append({"code": "predicate_then_invalid", "index": index, "field": field, "rule": rule_index})
        if operator == "regex":
            patterns = rule.get("value")
            patterns = patterns if isinstance(patterns, list) else [patterns]
            try:
                for pattern in patterns:
                    re.compile(str(pattern))
            except re.error:
                errors.append({"code": "predicate_regex_invalid", "index": index, "field": field, "rule": rule_index})
    return errors


def _correlation_errors(entry: dict[str, Any], index: int) -> list[dict[str, Any]]:
    if "correlation" not in entry:
        return []
    correlation = entry["correlation"]
    if correlation is None:
        if not str(entry.get("correlation_absent_reason") or "").strip():
            return [{"code": "correlation_absent_reason_required", "index": index}]
        return []
    if not isinstance(correlation, dict) or not correlation:
        return [{"code": "correlation_must_be_nonempty_object_or_null", "index": index}]
    errors: list[dict[str, Any]] = []
    role = str(correlation.get("role") or "")
    cardinality = str(correlation.get("cardinality") or "")
    if role not in CORRELATION_ROLES:
        errors.append({"code": "correlation_role_invalid", "index": index})
    if cardinality not in CORRELATION_CARDINALITIES:
        errors.append({"code": "correlation_cardinality_invalid", "index": index})
    keys = correlation.get("key")
    keys = keys if isinstance(keys, list) else [keys]
    if not keys or any(not _FIELD_NAME.fullmatch(str(value or "")) for value in keys):
        errors.append({"code": "correlation_key_invalid", "index": index})
    terminators = correlation.get("terminators")
    if not isinstance(terminators, list) or any(not str(value or "").strip() for value in terminators):
        errors.append({"code": "correlation_terminators_invalid", "index": index})
    else:
        if role == "open" and not terminators:
            errors.append({"code": "correlation_open_requires_terminator", "index": index})
        if cardinality == "pair" and len(terminators) > 1:
            errors.append({"code": "correlation_pair_has_multiple_terminators", "index": index})
    timeout = correlation.get("close_timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        errors.append({"code": "correlation_timeout_invalid", "index": index})
    return errors


def catalog_identity(entry: dict[str, Any]) -> tuple[str, str, str]:
    if any(field in entry for field in V2_IDENTITY_FIELDS):
        return (
            str(entry.get("source") or "").strip().casefold(),
            str(entry.get("stream") or "").strip().casefold(),
            str(entry.get("event_key") or "").strip().casefold(),
        )
    return (
        str(entry.get("channel") or "").strip().casefold(),
        str(entry.get("event_id") or "").strip().casefold(),
        str(entry.get("provider_name") or "").strip().casefold(),
    )


def _legacy_catalog_identity(entry: dict[str, Any]) -> tuple[str, str, str] | None:
    """Return the v1 Windows identity when compatibility fields are present."""
    identity = (
        str(entry.get("channel") or "").strip().casefold(),
        str(entry.get("event_id") or "").strip().casefold(),
        str(entry.get("provider_name") or "").strip().casefold(),
    )
    return identity if all(identity) else None


def validate_catalog_data(data: dict[str, Any]) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    entries = data.get("entries")
    if not isinstance(entries, list):
        return {"valid": False, "entry_count": 0, "errors": [{"code": "entries_must_be_array"}]}
    seen: dict[tuple[str, str, str], int] = {}
    for index, raw in enumerate(entries):
        if not isinstance(raw, dict):
            errors.append({"code": "entry_must_be_object", "index": index})
            continue
        entry = dict(raw)
        identity = catalog_identity(entry)
        if not all(identity):
            errors.append({"code": "invalid_identity", "index": index})
        if identity in seen:
            errors.append({"code": "duplicate_identity", "index": index, "first_index": seen[identity]})
        else:
            seen[identity] = index
        severity = str(entry.get("severity") or "").lower()
        if severity not in SEVERITIES:
            errors.append({"code": "invalid_severity", "index": index})
        for key, allowed in (("base_risk", SEVERITIES | {"important"}), ("purpose_tier", PURPOSE_TIERS)):
            value = entry.get(key)
            if value is not None and str(value).lower() not in allowed:
                errors.append({"code": f"invalid_{key}", "index": index})
        if entry.get("noise_class") is not None:
            errors.extend(_predicate_errors(
                entry["noise_class"],
                allowed_results=NOISE_CLASSES,
                index=index,
                field="noise_class",
            ))
        category = entry.get("category")
        if category is not None and str(category).lower() not in CATEGORIES:
            errors.append({"code": "invalid_category", "index": index})
        errors.extend(_lifecycle_errors(entry, index))
        errors.extend(_correlation_errors(entry, index))
        required_fields = entry.get("required_fields")
        if required_fields is not None and (
            not isinstance(required_fields, list)
            or not required_fields
            or any(str(value) not in STORAGE_EVENT_FIELDS for value in required_fields)
        ):
            errors.append({"code": "required_fields_invalid", "index": index})
        card = entry.get("card") or {}
        if not isinstance(card, dict):
            errors.append({"code": "card_must_be_object", "index": index})
            continue
        roles = card.get("field_roles") or {}
        if not isinstance(roles, dict):
            errors.append({"code": "field_roles_must_be_object", "index": index})
        else:
            for role, fields in roles.items():
                if role not in FIELD_ROLES:
                    errors.append({"code": "invalid_field_role", "index": index, "role": str(role)})
                if not isinstance(fields, list) or not fields or any(not _FIELD_NAME.fullmatch(str(field)) for field in fields):
                    errors.append({"code": "invalid_field_pivot", "index": index, "role": str(role)})
        related = card.get("related_event_ids") or []
        if not isinstance(related, list) or any(not isinstance(value, int) or value <= 0 for value in related):
            errors.append({"code": "invalid_related_event_ids", "index": index})
        for rule_index, raw_rule in enumerate(card.get("risk_rules") or []):
            if not isinstance(raw_rule, dict):
                errors.append({"code": "risk_rule_must_be_object", "index": index, "rule": rule_index})
                continue
            if str(raw_rule.get("severity") or severity).lower() not in SEVERITIES:
                errors.append({"code": "invalid_risk_rule_severity", "index": index, "rule": rule_index})
            if raw_rule.get("confidence") is not None and str(raw_rule["confidence"]).lower() not in CONFIDENCE:
                errors.append({"code": "invalid_risk_rule_confidence", "index": index, "rule": rule_index})
            conditions = raw_rule.get("all") or []
            if not isinstance(conditions, list) or any(not isinstance(condition, dict) for condition in conditions):
                errors.append({"code": "invalid_risk_rule_conditions", "index": index, "rule": rule_index})
    return {"valid": not errors, "entry_count": len(entries), "errors": errors}


SCHEMA_V2_FIELDS = ("lifecycle", "correlation", "required_fields")
CLASSIFICATION_FIELDS = ("base_risk", "purpose_tier", "noise_class", "category")


def entry_fingerprint(entry: dict[str, Any]) -> str:
    """Отпечаток содержания записи, не зависящий от порядка ключей."""
    import hashlib
    import json as _json

    payload = _json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _required_missing(entry: dict[str, Any]) -> list[str]:
    missing = [f for f in CLASSIFICATION_FIELDS if entry.get(f) in (None, "", [], {})]
    missing += [f for f in SCHEMA_V2_FIELDS if f not in entry]
    missing += [f for f in V2_IDENTITY_FIELDS if not str(entry.get(f) or "").strip()]
    lifecycle = entry.get("lifecycle")
    if isinstance(lifecycle, dict):
        missing += [
            f"lifecycle.{field}"
            for field in (*LIFECYCLE_PERIOD_FIELDS, "rollup")
            if field not in lifecycle
        ]
    return missing


def validate_catalog_changes(data: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Полнота обязательна для новых и изменённых записей, не для прежних.

    Решение владельца 28.07.2026. Требовать полноту от всех семидесяти шести
    записей значило бы остановить выпуск до ручного заполнения семидесяти
    одной; не требовать ни от кого значило бы повторить то, из-за чего каталог
    и стоит на 7% - ничто не заставляет его заполнять.

    Поэтому граница проводится по времени: то, что уже есть, живёт как есть;
    всё, что добавляется или правится сегодня, приходит в форме версии 2 и
    сразу заполненным. Каталог перестаёт ухудшаться, не останавливая работу.

    `baseline` - снимок отпечатков на момент введения правила. Без него
    «новая» и «прежняя» запись неразличимы, и правило вырождается в первый
    вариант либо во второй.
    """
    known: dict[str, str] = baseline.get("fingerprints") or {}
    violations: list[dict[str, Any]] = []
    новых = 0
    изменённых = 0

    for index, raw in enumerate(data.get("entries") or []):
        if not isinstance(raw, dict):
            continue
        identity_tuple = catalog_identity(raw)
        identity = "/".join(str(part) for part in identity_tuple)
        fingerprint = entry_fingerprint(raw)
        прежний = known.get(identity)
        if прежний is None:
            legacy_identity = _legacy_catalog_identity(raw)
            if legacy_identity is not None and legacy_identity != identity_tuple:
                прежний = known.get("/".join(legacy_identity))
        if прежний is None:
            вид = "новая"
            новых += 1
        elif прежний != fingerprint:
            вид = "изменённая"
            изменённых += 1
        else:
            continue  # прежняя и нетронутая - освобождена

        missing = _required_missing(raw)
        if missing:
            violations.append({
                "index": index, "identity": identity, "вид": вид,
                "не_заполнено": missing,
            })

    return {
        "valid": not violations,
        "новых": новых,
        "изменённых": изменённых,
        "освобождено_прежних": len(known) - изменённых,
        "нарушений": len(violations),
        "violations": violations,
        "правило": (
            "Обязательная полнота применяется к новым и изменённым записям. "
            "Прежние освобождены и заполняются по мере надобности."
        ),
    }


def build_catalog_baseline(data: dict[str, Any]) -> dict[str, Any]:
    """Снимок отпечатков: что считать «уже существовавшим»."""
    fingerprints = {
        "/".join(str(part) for part in catalog_identity(entry)): entry_fingerprint(entry)
        for entry in (data.get("entries") or []) if isinstance(entry, dict)
    }
    return {
        "schema_version": 2,
        "назначение": (
            "Граница между записями, освобождёнными от обязательной полноты, и "
            "теми, к которым она применяется. Снят в момент введения правила."
        ),
        "правило_обновления": (
            "Снимок не обновляется автоматически. Обновлять его вручную значит "
            "освобождать записи от проверки задним числом - именно то, ради "
            "чего он и заводился."
        ),
        "entry_count": len(fingerprints),
        "fingerprints": fingerprints,
    }


def catalog_completeness(data: dict[str, Any]) -> dict[str, Any]:
    """Считать, что каталог объявляет, не проваливая выпуск.

    :func:`validate_catalog_data` оставляет поля классификации необязательными
    ради чтения внешних/старых каталогов. Поэтому полнота считается отдельно
    и должна быть равна 100% для канонического каталога после B1.

    Замер помогает, только если он действительно снимается. Валидатор выше
    существует давно и не вызывается ниоткуда: ни проверкой выпуска, ни
    тестом, ни одним модулем. Объявленный и неподключённый механизм
    неотличим от отсутствующего - тот же изъян, что был у ворот
    производительности этапа 7.
    """
    entries = [entry for entry in (data.get("entries") or []) if isinstance(entry, dict)]
    total = len(entries)
    counts = {
        field: sum(1 for entry in entries if entry.get(field) not in (None, "", [], {}))
        for field in (*CLASSIFICATION_FIELDS, *SCHEMA_V2_FIELDS)
    }
    fully_classified = sum(
        1 for entry in entries
        if all(entry.get(field) not in (None, "", [], {}) for field in CLASSIFICATION_FIELDS)
    )
    schema_v2_ready = sum(1 for entry in entries if all(f in entry for f in SCHEMA_V2_FIELDS))
    return {
        "entry_count": total,
        "fully_classified": fully_classified,
        "classification_ratio": fully_classified / total if total else 1.0,
        "schema_v2_ready": schema_v2_ready,
        "declared_per_field": counts,
    }


def coverage_summary(groups: Iterable[dict[str, Any]], *, catalog_entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    identities: set[tuple[str, str, str]] = set()
    for raw_entry in catalog_entries:
        entry = dict(raw_entry)
        identities.add(catalog_identity(entry))
        legacy_identity = _legacy_catalog_identity(entry)
        if legacy_identity is not None:
            identities.add(legacy_identity)
    inspected = 0
    covered_groups = 0
    total_events = 0
    covered_events = 0
    gaps: list[dict[str, Any]] = []
    for raw in groups:
        row = dict(raw)
        inspected += 1
        count = max(0, int(row.get("count") or 0))
        total_events += count
        identity = catalog_identity(row)
        if identity in identities:
            covered_groups += 1
            covered_events += count
        else:
            gaps.append({
                "channel": row.get("channel"), "event_id": int(row.get("event_id") or 0),
                "provider_name": row.get("provider_name"), "count": count,
                "first_seen": row.get("first_seen"), "last_seen": row.get("last_seen"),
            })
    gaps.sort(key=lambda row: (-int(row["count"]), str(row["channel"]), int(row["event_id"]), str(row["provider_name"])))
    return {
        "contains_event_payload": False,
        "groups_inspected": inspected,
        "groups_covered": covered_groups,
        "group_coverage_ratio": covered_groups / inspected if inspected else 1.0,
        "events_in_groups": total_events,
        "events_covered": covered_events,
        "event_coverage_ratio": covered_events / total_events if total_events else 1.0,
        "gap_count": len(gaps),
        "gaps": gaps,
    }


def propose_catalog_promotion(data: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    """Build a reviewable entry; never edits the catalogue or promotes from payload alone."""
    identity_source = {
        "channel": fixture.get("channel"), "event_id": fixture.get("event_id"),
        "provider_name": fixture.get("provider_name"),
    }
    identity = catalog_identity(identity_source)
    if not all(identity):
        raise ValueError("fixture_identity_incomplete")
    if any(catalog_identity(dict(entry)) == identity for entry in data.get("entries") or []):
        raise ValueError("catalog_identity_already_exists")
    semantic = fixture.get("verified_semantics")
    if not isinstance(semantic, dict):
        raise ValueError("verified_semantics_required")
    evidence_fields = fixture.get("evidence_fields")
    if not isinstance(evidence_fields, list) or not evidence_fields or any(not _FIELD_NAME.fullmatch(str(value)) for value in evidence_fields):
        raise ValueError("field_level_evidence_required")
    entry = {
        **identity_source,
        "severity": str(semantic.get("severity") or "").lower(),
        "title": str(semantic.get("title") or "").strip(),
        "why": str(semantic.get("why") or "").strip(),
        "fix": str(semantic.get("fix") or "").strip(),
        "missing": str(semantic.get("missing") or "").strip(),
    }
    candidate = {**data, "entries": [*(data.get("entries") or []), entry]}
    validation = validate_catalog_data(candidate)
    if not all(entry[key] for key in ("title", "why", "fix")) or not validation["valid"]:
        raise ValueError("promotion_candidate_invalid")
    return {"status": "proposed", "writes_performed": False, "identity": identity_source, "entry": entry, "evidence_fields": list(evidence_fields)}


def build_report_event_dto(row: dict[str, Any]) -> dict[str, Any]:
    """Deterministic non-HTML DTO using the canonical event semantic result."""
    card = build_event_card(row)
    return {
        "event_db_id": int(row.get("event_db_id") or row.get("id") or 0),
        "event_id": int(row.get("event_id") or 0),
        "time_created_utc": row.get("time_created_utc"),
        "server": row.get("server"), "channel": row.get("channel"),
        "provider_name": row.get("provider_name"),
        "title": card["title"],
        "final_security_severity": card["final_security_severity"],
        "purpose_tier": card["purpose_tier"],
        "assessment_confidence": card["assessment_confidence"],
        "noise_class": card["noise_class"],
        "catalog_match": card["catalog_match"],
        "reasons": list(card["reasons"]),
        "evidence_fields": list(card["evidence_fields"]),
    }

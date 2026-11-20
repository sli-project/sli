from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

AI_PROMPT_VERSION = "sli-ai-security-analysis-v2"
DEFAULT_OPENAI_MODEL = "gpt-5.5"

AI_ANALYSIS_JSON_SCHEMA: dict[str, Any] = {
    "name": "security_log_intelligence_analysis",
    "strict": True,
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "summary",
            "overall_risk",
            "confidence",
            "facts",
            "hypotheses",
            "evidence",
            "recommended_actions",
            "alternative_explanations",
            "limitations",
            "manual_checks",
        ],
        "properties": {
            "summary": {"type": "string", "description": "Short Russian-language executive summary for an analyst."},
            "overall_risk": {"type": "string", "enum": ["critical", "high", "medium", "low", "info", "unknown"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "facts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["statement", "event_indexes"],
                    "properties": {
                        "statement": {"type": "string"},
                        "event_indexes": {"type": "array", "items": {"type": "integer"}},
                    },
                },
            },
            "hypotheses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["hypothesis", "why_it_matters", "confidence", "event_indexes"],
                    "properties": {
                        "hypothesis": {"type": "string"},
                        "why_it_matters": {"type": "string"},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "event_indexes": {"type": "array", "items": {"type": "integer"}},
                    },
                },
            },
            "evidence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["event_index", "event_id", "meaning", "reason"],
                    "properties": {
                        "event_index": {"type": "integer"},
                        "event_id": {"type": ["integer", "string"]},
                        "meaning": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                },
            },
            "recommended_actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["priority", "action", "owner", "reason"],
                    "properties": {
                        "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                        "action": {"type": "string"},
                        "owner": {"type": "string", "enum": ["ИБ", "ИТ", "совместно", "не определено"]},
                        "reason": {"type": "string"},
                    },
                },
            },
            "alternative_explanations": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Plausible benign or operational explanations that should be checked before escalation.",
            },
            "limitations": {"type": "array", "items": {"type": "string"}},
            "manual_checks": {"type": "array", "items": {"type": "string"}},
        },
    },
}


def schema_for_openai_response() -> dict[str, Any]:
    """Return the JSON schema block used by the OpenAI Responses API."""
    return json.loads(json.dumps(AI_ANALYSIS_JSON_SCHEMA, ensure_ascii=False))


def _matches_json_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def _validate_schema_node(value: Any, schema: Mapping[str, Any], path: str, errors: list[str]) -> None:
    expected = schema.get("type")
    expected_types = [expected] if isinstance(expected, str) else list(expected or [])
    if expected_types and not any(_matches_json_type(value, item) for item in expected_types):
        errors.append(f"invalid_type:{path or '$'}")
        return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"invalid:{path or '$'}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"invalid:{path or '$'}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"invalid:{path or '$'}")
    if isinstance(value, Mapping):
        properties = dict(schema.get("properties") or {})
        for name in schema.get("required") or []:
            if name not in value:
                errors.append(f"missing:{path + '.' if path else ''}{name}")
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    errors.append(f"unexpected:{path + '.' if path else ''}{name}")
        for name, child in properties.items():
            if name in value:
                _validate_schema_node(
                    value[name], child, f"{path}.{name}" if path else name, errors
                )
    elif isinstance(value, list) and isinstance(schema.get("items"), Mapping):
        for index, item in enumerate(value):
            _validate_schema_node(item, schema["items"], f"{path}[{index}]", errors)


def validate_ai_analysis_shape(
    payload: dict[str, Any],
    *,
    events: Sequence[Mapping[str, Any]] | None = None,
) -> list[str]:
    """Validate the complete response schema and evidence references locally."""
    errors: list[str] = []
    _validate_schema_node(payload, AI_ANALYSIS_JSON_SCHEMA["schema"], "", errors)
    event_count = len(events) if events is not None else None
    for collection_name in ("facts", "hypotheses"):
        for item_index, item in enumerate(payload.get(collection_name) or []):
            if not isinstance(item, Mapping):
                continue
            for reference_index, event_index in enumerate(item.get("event_indexes") or []):
                path = f"{collection_name}[{item_index}].event_indexes[{reference_index}]"
                if (
                    not isinstance(event_index, int)
                    or isinstance(event_index, bool)
                    or event_index < 0
                    or (event_count is not None and event_index >= event_count)
                ):
                    errors.append(f"invalid_reference:{path}")
    for item_index, item in enumerate(payload.get("evidence") or []):
        if not isinstance(item, Mapping):
            continue
        event_index = item.get("event_index")
        path = f"evidence[{item_index}].event_index"
        if (
            not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or event_index < 0
            or (event_count is not None and event_index >= event_count)
        ):
            errors.append(f"invalid_reference:{path}")
            continue
        if events is not None:
            source_event_id = events[event_index].get("event_id")
            if str(source_event_id) != str(item.get("event_id")):
                errors.append(f"evidence_mismatch:evidence[{item_index}].event_id")
    return list(dict.fromkeys(errors))

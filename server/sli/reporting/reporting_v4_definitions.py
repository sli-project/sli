"""Pure report-definition validation and metric helpers for reporting_v4."""
from __future__ import annotations

import json
import re
from typing import Any, Mapping

from server.sli.plugins.registry import require_plugin

from server.sli.reporting.reporting_v4_catalog import (
    FOCUS_METRIC_MAX,
    FOCUS_REQUIRED_METRIC_MAX,
    UNSAFE_DEFINITION_KEYS,
)


def _json_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if value in (None, ""):
        return {}
    parsed = json.loads(str(value))
    return dict(parsed) if isinstance(parsed, Mapping) else {}


def _vpn_connections_catalog_item(
    vpn_audit: Mapping[str, Any], *, capabilities: set[str],
) -> dict[str, Any]:
    """Compatibility entry point for plugin-owned catalogue metadata."""
    return require_plugin(
        "sli.remote-access", "connections_catalog", vpn_audit, capabilities=capabilities,
    )


def _definition_has_unsafe_text(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).strip().lower() in UNSAFE_DEFINITION_KEYS or _definition_has_unsafe_text(item) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_definition_has_unsafe_text(item) for item in value)
    return False


def _definition_columns(definition: Mapping[str, Any], field_defs: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Normalize known seed/builder column shapes without rewriting stored JSON."""
    raw_columns = definition.get("columns")
    if not isinstance(raw_columns, list):
        raise ValueError("invalid_report_definition_columns")
    columns: list[str] = []
    for item in raw_columns:
        key = str(item.get("key") or "") if isinstance(item, Mapping) else str(item or "")
        if not key or key not in field_defs or key in columns:
            raise ValueError("invalid_report_definition_columns")
        columns.append(key)
    if not columns:
        raise ValueError("invalid_report_definition_columns")
    return columns


def _dashboard_metric_definitions(value: Any) -> list[dict[str, Any]]:
    """Validate publisher-owned dashboard metrics without accepting expressions."""
    if value in (None, ""):
        return []
    if not isinstance(value, list) or len(value) > FOCUS_METRIC_MAX:
        raise ValueError("invalid_dashboard_metrics")
    result: list[dict[str, Any]] = []
    keys: set[str] = set()
    required_count = 0
    for raw in value:
        if not isinstance(raw, Mapping):
            raise ValueError("invalid_dashboard_metrics")
        key = str(raw.get("key") or "").strip()
        label = str(raw.get("label") or "").strip()
        caption = str(raw.get("caption") or "").strip()
        kind = str(raw.get("kind") or "").strip().lower()
        value_path = str(raw.get("value_path") or "").strip()
        freshness_path = str(raw.get("freshness_path") or "").strip()
        unit = str(raw.get("unit") or "").strip()
        icon = str(raw.get("icon") or "report").strip()
        tone = str(raw.get("tone") or "accent").strip()
        target_path = str(raw.get("target_path") or "").strip()
        priority = raw.get("priority", 100)
        filters = raw.get("filters") or {}
        default_selected = raw.get("default_selected", False)
        if (
            not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,79}", key)
            or key in keys
            or not label or len(label) > 120
            or len(caption) > 240
            or kind not in {"required", "optional"}
            or not re.fullmatch(r"(?:summary\.[a-z0-9_]{1,80}|items\.count)", value_path)
            or (freshness_path and not re.fullmatch(r"summary\.[a-z0-9_]{1,80}", freshness_path))
            or len(unit) > 32
            or not re.fullmatch(r"[a-z][a-z0-9_-]{1,39}", icon)
            or tone not in {"accent", "good", "warn", "bad", "neutral"}
            or not target_path.startswith("/") or target_path.startswith("//") or len(target_path) > 300
            or not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 999
            or not isinstance(default_selected, bool)
            or not isinstance(filters, Mapping) or len(filters) > 12
            or any(
                not re.fullmatch(r"[a-z0-9_]{1,80}", str(filter_key))
                or isinstance(filter_value, (Mapping, list, tuple))
                or len(str(filter_value)) > 256
                for filter_key, filter_value in filters.items()
            )
        ):
            raise ValueError("invalid_dashboard_metrics")
        keys.add(key)
        required_count += int(kind == "required")
        result.append({
            "key": key, "label": label, "caption": caption, "kind": kind,
            "value_path": value_path, "freshness_path": freshness_path or None,
            "unit": unit or None, "icon": icon, "tone": tone,
            "priority": priority, "target_path": target_path,
            "default_selected": default_selected,
            "filters": {str(filter_key): filter_value for filter_key, filter_value in filters.items()},
        })
    if required_count > FOCUS_REQUIRED_METRIC_MAX:
        raise ValueError("required_dashboard_metric_capacity_exceeded")
    return result


def _security_expands(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    """Detect either allowlist expansion or a changed security interpretation."""
    for key in ("columns", "field_categories", "actions", "required_capabilities"):
        before = {str(item.get("key") if isinstance(item, Mapping) else item) for item in (previous.get(key) or [])}
        after = {str(item.get("key") if isinstance(item, Mapping) else item) for item in (current.get(key) or [])}
        if not after <= before:
            return True
    # Existing keys are not enough for these structures: changing a metric's
    # value path/filter/target or a report predicate changes what an already
    # assigned report means. Require the same reapproval as an expansion.
    for key in ("filters", "sort", "target_path", "export_policy", "dashboard_metrics"):
        before = json.dumps(
            previous.get(key), ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), default=str,
        )
        after = json.dumps(
            current.get(key), ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), default=str,
        )
        if before != after:
            return True
    return False


def _metric_value(payload: Mapping[str, Any], path: str) -> Any:
    if path == "items.count":
        return len(payload.get("items") or [])
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _metric_state(payload: Mapping[str, Any]) -> str:
    summary = payload.get("summary")
    collection = summary.get("collection") if isinstance(summary, Mapping) else None
    states = {
        str(item.get("state") or "")
        for item in (collection.values() if isinstance(collection, Mapping) else [])
        if isinstance(item, Mapping)
    }
    if "failed" in states:
        return "failed"
    if states & {"partial", "skipped"}:
        return "partial"
    if states and states <= {"not_collected", "scope_not_applicable"}:
        return "not_collected"
    return str(payload.get("state") or "unknown")

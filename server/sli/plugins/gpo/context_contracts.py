"""GPO-specific validation within the existing context wire contract."""
from __future__ import annotations

import re
from typing import Any

from server.sli.sources.gpo_v2_source import (
    GpoV2SourceContractError, is_gpo_sensitive_field,
    validate_snapshot as validate_gpo_v2_snapshot,
)

GPO_SETTING_KEYS = frozenset({
    "scope", "kind", "path", "properties", "redacted_fields", "truncated_fields",
    "sensitive_value_present", "sha256",
})
GPO_SETTING_SCOPES = frozenset({"computer", "user"})

def _gpo_settings(value: Any) -> list[dict[str, Any]]:
    from server.sli.plugins.ad.context.contracts import (
        AdContextContractError, MAX_TEXT_LENGTH,
        _object, _reject_unknown, _enum, _required_text,
    )

    if not isinstance(value, list) or len(value) > 2048:
        raise AdContextContractError("entity.attributes.gpo_settings must be a bounded array")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        label = f"entity.attributes.gpo_settings[{index}]"
        item = _object(raw, label)
        _reject_unknown(item, GPO_SETTING_KEYS, label)
        scope = _enum(item.get("scope"), GPO_SETTING_SCOPES, f"{label}.scope")
        kind = _required_text(item.get("kind"), f"{label}.kind")
        path = _required_text(item.get("path"), f"{label}.path")
        if len(kind) > 128 or len(path) > 512:
            raise AdContextContractError(f"{label} identity is too long")
        properties = _object(item.get("properties"), f"{label}.properties")
        if len(properties) > 64:
            raise AdContextContractError(f"{label}.properties has too many values")
        normalized_properties: dict[str, str] = {}
        for raw_key, raw_value in properties.items():
            key = _required_text(raw_key, f"{label}.properties key").lower()
            if len(key) > 128:
                raise AdContextContractError(f"{label}.properties key is too long")
            if is_gpo_sensitive_field(key):
                raise AdContextContractError(f"{label}.properties contains a sensitive field")
            if not isinstance(raw_value, str) or len(raw_value) > MAX_TEXT_LENGTH:
                raise AdContextContractError(f"{label}.properties.{key} must be a bounded string")
            normalized_properties[key] = raw_value
        redacted = item.get("redacted_fields")
        if not isinstance(redacted, list) or len(redacted) > 64:
            raise AdContextContractError(f"{label}.redacted_fields must be a bounded array")
        normalized_redacted = sorted({
            _required_text(field, f"{label}.redacted_fields").lower()
            for field in redacted
        })
        if any(not is_gpo_sensitive_field(field) for field in normalized_redacted):
            raise AdContextContractError(f"{label}.redacted_fields contains a non-sensitive field")
        truncated = item.get("truncated_fields")
        if not isinstance(truncated, list) or len(truncated) > 64:
            raise AdContextContractError(f"{label}.truncated_fields must be a bounded array")
        normalized_truncated = sorted({
            _required_text(field, f"{label}.truncated_fields").lower()
            for field in truncated
        })
        if any(field not in normalized_properties for field in normalized_truncated):
            raise AdContextContractError(f"{label}.truncated_fields references a missing property")
        sensitive = item.get("sensitive_value_present")
        if not isinstance(sensitive, bool) or sensitive != bool(normalized_redacted):
            raise AdContextContractError(f"{label}.sensitive_value_present is inconsistent")
        sha256 = _required_text(item.get("sha256"), f"{label}.sha256").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise AdContextContractError(f"{label}.sha256 is invalid")
        normalized.append({
            "scope": scope, "kind": kind, "path": path,
            "properties": normalized_properties,
            "redacted_fields": normalized_redacted,
            "truncated_fields": normalized_truncated,
            "sensitive_value_present": sensitive, "sha256": sha256,
        })
    return normalized


def validate_context_snapshot(bundle, *, names, collection_profile):
    from server.sli.plugins.ad.context.contracts import AdContextContractError

    gpo_v2_snapshot = bundle.get("gpo_v2_snapshot")
    if gpo_v2_snapshot is not None:
        if names != ["gpo_governance"] or collection_profile not in {"gpo_governance_v3", "gpo_governance_v4"}:
            raise AdContextContractError("gpo_v2_snapshot requires gpo_governance_v3 or gpo_governance_v4")
        try:
            gpo_v2_snapshot = validate_gpo_v2_snapshot(gpo_v2_snapshot)
        except GpoV2SourceContractError as exc:
            raise AdContextContractError(f"invalid gpo_v2_snapshot: {exc}") from exc
    elif collection_profile in {"gpo_governance_v3", "gpo_governance_v4"}:
        raise AdContextContractError(f"{collection_profile} requires gpo_v2_snapshot")

    return gpo_v2_snapshot

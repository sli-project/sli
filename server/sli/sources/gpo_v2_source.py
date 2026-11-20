from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime
from typing import Any

SCHEMA_PREFIX = "sli.ad-gpo.snapshot/"
SCHEMA_VERSION = "sli.ad-gpo.snapshot/1.0"
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_GPOS = 10_000
REQUIRED_ARRAYS = (
    "gpos",
    "scopes",
    "links",
    "settings",
    "permissions",
    "wmi_filters",
    "unresolved_links",
    "collection_errors",
)
ROOT_REQUIRED = frozenset(
    {
        "schema_version",
        "collector_version",
        "demo",
        "started_at",
        "completed_at",
        "observed_at",
        "collection_status",
        "domain",
        "scope",
        "source_states",
        *REQUIRED_ARRAYS,
    }
)
SOURCE_STATUSES = frozenset(
    {
        "observed",
        "not_collected",
        "not_evaluated",
        "missing_in_source",
        "no_record",
        "partial",
        "failed",
        "access_denied",
        "parse_error",
        "not_applicable",
    }
)
COLLECTION_STATUSES = frozenset({"complete", "partial", "failed"})
ROOT_SOURCE_NAMES = frozenset(
    {
        "gpo_list",
        "gpo_reports",
        "gpc_directory",
        "sysvol_gpt",
        "links",
        "permissions",
        "wmi_filters",
    }
)

GPO_SENSITIVE_FIELD_PATTERN = re.compile(
    r"password|cpassword|passwd|pwd|secret|privatekey|token|credential|apikey|accesskey|"
    r"sharedkey|presharedkey|psk|encryptionkey|decryptionkey|symmetrickey|signingkey|"
    r"keymaterial|passphrase|connectionstring",
)
GPO_HIDDEN_VALUE = "значение скрыто"
_GPO_ASSIGNMENT_PATTERN = re.compile(
    r'''(?:^|[\s;,{<])["']?(?P<name>[\w.:-]+)["']?\s*(?:=|:)\s*["']?(?P<label>[\w.:-]+)?''',
)
_GPO_NAMED_FIELDS = frozenset({"name", "key", "valuename", "property"})
_GPO_VALUE_FIELDS = frozenset({
    "value", "values", "value_display", "data", "text", "valuedata", "defaultvalue", "properties",
})


def is_gpo_sensitive_field(name: str) -> bool:
    return bool(GPO_SENSITIVE_FIELD_PATTERN.search(re.sub(r"[^a-z0-9]", "", name.lower())))


def _is_gpo_sensitive_value(value: str) -> bool:
    for match in _GPO_ASSIGNMENT_PATTERN.finditer(value):
        if is_gpo_sensitive_field(match["name"]):
            return True
        if (
            match["name"].lower() in _GPO_NAMED_FIELDS
            and match["label"] and is_gpo_sensitive_field(match["label"])
        ):
            return True
    return bool(re.search(r"-----BEGIN .*PRIVATE KEY-----", value, re.IGNORECASE))


def redact_gpo_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return a sanitized copy for storage after the incoming digest is checked."""
    def redact(value: Any, *, sensitive: bool = False) -> Any:
        if isinstance(value, dict):
            named_sensitive = any(
                isinstance(label, str) and is_gpo_sensitive_field(label)
                for key, label in value.items()
                if key.lower() in _GPO_NAMED_FIELDS | {"setting_name", "path", "source_xml_path"}
            )
            result = {}
            for key, item in value.items():
                if named_sensitive and not sensitive and key.lower() == "source_state" and isinstance(item, dict):
                    result[key] = {
                        field: redact(data, sensitive=field.lower() in {"value", "detail", "error"})
                        for field, data in item.items()
                    }
                else:
                    result[key] = redact(
                        item,
                        sensitive=sensitive or is_gpo_sensitive_field(key) or (
                            named_sensitive and key.lower() in _GPO_VALUE_FIELDS
                        ),
                    )
            return result
        if isinstance(value, list):
            return [redact(item, sensitive=sensitive) for item in value]
        if sensitive:
            return GPO_HIDDEN_VALUE if value is not None else None
        if isinstance(value, str) and _is_gpo_sensitive_value(value):
            return GPO_HIDDEN_VALUE
        return value

    return redact(snapshot)


class GpoV2SourceContractError(ValueError):
    pass


def _parse_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, Mapping):
        return deepcopy(dict(payload))
    if isinstance(payload, (bytes, bytearray)):
        if len(payload) > MAX_SNAPSHOT_BYTES:
            raise GpoV2SourceContractError("snapshot_size_out_of_bounds")
        try:
            payload = bytes(payload).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise GpoV2SourceContractError("snapshot_utf8_invalid") from exc
    if isinstance(payload, str):
        if len(payload.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
            raise GpoV2SourceContractError("snapshot_size_out_of_bounds")
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise GpoV2SourceContractError("snapshot_json_invalid") from exc
        if not isinstance(parsed, dict):
            raise GpoV2SourceContractError("snapshot_root_invalid")
        return parsed
    raise GpoV2SourceContractError("snapshot_payload_type_invalid")


def _require_timestamp(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise GpoV2SourceContractError(f"timestamp_required:{path}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GpoV2SourceContractError(f"timestamp_invalid:{path}") from exc
    if parsed.tzinfo is None:
        raise GpoV2SourceContractError(f"timestamp_timezone_required:{path}")


def _validate_source_state(state: Any, path: str) -> None:
    if not isinstance(state, Mapping):
        raise GpoV2SourceContractError(f"source_state_invalid:{path}")
    status = state.get("status")
    if status not in SOURCE_STATUSES:
        raise GpoV2SourceContractError(f"source_state_status_invalid:{path}")
    coverage = state.get("coverage")
    if coverage is not None:
        if not isinstance(coverage, Mapping):
            raise GpoV2SourceContractError(f"source_coverage_invalid:{path}")
        for key in ("requested", "successful", "failed"):
            if key in coverage:
                value = coverage[key]
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise GpoV2SourceContractError(f"source_coverage_counts_invalid:{path}")
        if (
            {"requested", "successful", "failed"}.issubset(coverage)
            and coverage["successful"] + coverage["failed"] > coverage["requested"]
        ):
            raise GpoV2SourceContractError(f"source_coverage_total_invalid:{path}")


def _validate_unique_ids(items: list[Any], path: str) -> set[str]:
    identifiers: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise GpoV2SourceContractError(f"record_invalid:{path}[{index}]")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise GpoV2SourceContractError(f"record_id_required:{path}[{index}]")
        if identifier in identifiers:
            raise GpoV2SourceContractError(f"duplicate_record_id:{path}:{identifier}")
        identifiers.add(identifier)
    return identifiers


def validate_gpo_v2_snapshot(payload: Any, *, allow_demo: bool = False) -> dict[str, Any]:
    snapshot = _parse_payload(payload)
    missing_root_fields = sorted(ROOT_REQUIRED.difference(snapshot))
    if missing_root_fields:
        raise GpoV2SourceContractError(f"root_fields_missing:{','.join(missing_root_fields)}")
    schema_version = snapshot.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version.startswith(SCHEMA_PREFIX):
        raise GpoV2SourceContractError("unsupported_schema_version")
    if snapshot.get("collection_status") not in COLLECTION_STATUSES:
        raise GpoV2SourceContractError("collection_status_invalid")
    if not allow_demo and (snapshot.get("demo") is True or "демо" in str(snapshot.get("demo_notice", "")).lower()):
        raise GpoV2SourceContractError("demo_source_snapshot_forbidden")
    for field in ("started_at", "completed_at", "observed_at"):
        _require_timestamp(snapshot.get(field), field)
    for field in REQUIRED_ARRAYS:
        if not isinstance(snapshot.get(field), list):
            raise GpoV2SourceContractError(f"required_array_missing:{field}")
    if len(snapshot["gpos"]) > MAX_GPOS:
        raise GpoV2SourceContractError("gpo_count_out_of_bounds")
    root_states = snapshot.get("source_states")
    if not isinstance(root_states, Mapping):
        raise GpoV2SourceContractError("source_states_required")
    missing_sources = sorted(ROOT_SOURCE_NAMES.difference(root_states))
    if missing_sources:
        raise GpoV2SourceContractError(f"required_source_missing:{','.join(missing_sources)}")
    for name, state in root_states.items():
        _validate_source_state(state, f"source_states.{name}")

    ids = {field: _validate_unique_ids(snapshot[field], field) for field in REQUIRED_ARRAYS[:6]}
    for index, gpo in enumerate(snapshot["gpos"]):
        if not gpo.get("guid") or not gpo.get("display_name"):
            raise GpoV2SourceContractError(f"gpo_identity_required:gpos[{index}]")
        states = gpo.get("source_states")
        if not isinstance(states, Mapping):
            raise GpoV2SourceContractError(f"source_states_required:gpos[{index}]")
        for name, state in states.items():
            _validate_source_state(state, f"gpos[{index}].source_states.{name}")
        for ref_field, target in (
            ("link_ids", "links"),
            ("setting_ids", "settings"),
            ("permission_ids", "permissions"),
        ):
            refs = gpo.get(ref_field, [])
            if not isinstance(refs, list) or any(ref not in ids[target] for ref in refs):
                raise GpoV2SourceContractError(f"invalid_reference:{field}.{ref_field}")
    gpo_ids = ids["gpos"]
    scope_ids = ids["scopes"]
    for index, link in enumerate(snapshot["links"]):
        if link.get("gpo_id") not in gpo_ids or link.get("scope_id") not in scope_ids:
            raise GpoV2SourceContractError(f"invalid_link_reference:links[{index}]")
        if not isinstance(link.get("raw_options"), int):
            raise GpoV2SourceContractError(f"link_raw_options_required:links[{index}]")
        if bool(link.get("enabled")) != ((link["raw_options"] & 1) == 0):
            raise GpoV2SourceContractError(f"link_enabled_derivation_invalid:links[{index}]")
        if bool(link.get("enforced")) != ((link["raw_options"] & 2) == 2):
            raise GpoV2SourceContractError(f"link_enforced_derivation_invalid:links[{index}]")
    for family in ("settings", "permissions"):
        for index, item in enumerate(snapshot[family]):
            if item.get("gpo_id") not in gpo_ids:
                raise GpoV2SourceContractError(f"invalid_gpo_reference:{family}[{index}]")
    # Optional extension: old immutable payloads keep their original digest.
    if "acl" in snapshot:
        acl = snapshot["acl"]
        if not isinstance(acl, list) or len(acl) > 100_000:
            raise GpoV2SourceContractError("gpo_acl_out_of_bounds")
        _validate_unique_ids(acl, "acl")
        indices = set()
        for ace in acl:
            index = ace.get("ace_index")
            mask = ace.get("access_mask")
            flags = ace.get("propagation_flags")
            if (ace.get("gpo_id") not in gpo_ids or not isinstance(index, int)
                    or isinstance(index, bool) or index < 0
                    or (ace["gpo_id"], index) in indices
                    or not isinstance(mask, int) or isinstance(mask, bool) or not -(2**31) <= mask < 2**32
                    or not isinstance(flags, int) or isinstance(flags, bool) or not 0 <= flags <= 3
                    or ace.get("access_control_type") not in {"Allow", "Deny"}
                    or not isinstance(ace.get("inherited"), bool)
                    or not isinstance(ace.get("trustee_sid"), str)
                    or not re.fullmatch(r"S-\d+(?:-\d+)+", ace["trustee_sid"], re.IGNORECASE)
                    or not isinstance(ace.get("object_type"), str)
                    or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", ace["object_type"], re.IGNORECASE)):
                raise GpoV2SourceContractError("gpo_acl_ace_invalid")
            indices.add((ace["gpo_id"], index))
    elif any((gpo.get("source_states") or {}).get("acl", {}).get("status") == "observed" for gpo in snapshot["gpos"]):
        raise GpoV2SourceContractError("gpo_acl_array_required")
    return snapshot


def canonical_gpo_v2_snapshot(payload: Any, *, allow_demo: bool = False) -> tuple[dict[str, Any], bytes, str]:
    snapshot = validate_gpo_v2_snapshot(payload, allow_demo=allow_demo)
    encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return snapshot, encoded, hashlib.sha256(encoded).hexdigest()


def validate_snapshot(payload: Any, *, allow_demo: bool = False) -> dict[str, Any]:
    return validate_gpo_v2_snapshot(payload, allow_demo=allow_demo)


def canonical_snapshot(payload: Any, *, allow_demo: bool = False) -> tuple[str, str]:
    _snapshot, encoded, digest = canonical_gpo_v2_snapshot(payload, allow_demo=allow_demo)
    return encoded.decode("utf-8"), digest

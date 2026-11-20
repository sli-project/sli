"""Prepared-only writer contract for the unified administrative journal."""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "config" / "stage10_administrative_activity_v1.json"
ACTION_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,119}$")
TARGET_KIND_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
ACTOR_KINDS = frozenset(
    {"session", "api_key", "windows", "system", "local_operator", "plugin"}
)


class AdministrativeActivityError(ValueError):
    """Fail-closed validation error without sensitive values."""


@dataclass(frozen=True)
class AdministrativeActivity:
    event_uid: UUID
    occurred_at_utc: datetime
    actor_kind: str
    actor_key: str
    category: str
    action_key: str
    outcome: str
    target_kind: str | None = None
    target_key: str | None = None
    reason_code: str | None = None
    details: Mapping[str, str | int | float | bool | None] = field(
        default_factory=dict
    )
    remote_address: str | None = None
    correlation_id: UUID | None = None


def load_administrative_activity_contract() -> dict[str, Any]:
    try:
        value = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdministrativeActivityError("administrative_activity_contract_unreadable") from exc
    expected = {
        "schema_version": 1,
        "contract_id": "sli.administrative-activity.v1",
        "required_migration": 66,
        "runtime_write_enabled": False,
        "runtime_read_enabled": False,
        "source_contact_allowed": False,
        "maximum_detail_bytes": 8192,
        "details_shape": "flat_scalar_object_only",
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise AdministrativeActivityError(
                f"administrative_activity_contract_{key}_invalid"
            )
    if {"status", "production_migration_applied"} & set(value):
        raise AdministrativeActivityError(
            "administrative_activity_contract_production_claim_present"
        )
    if not value.get("categories") or not value.get("outcomes"):
        raise AdministrativeActivityError("administrative_activity_contract_values_missing")
    reader = value.get("prepared_reader")
    if not isinstance(reader, Mapping) or reader != {
        "required_migration": 72,
        "capability": "administrative.activity.view",
        "access_package": "access_admin",
        "endpoint": "/api/v1/operations/administrative-activity",
        "database_function": "read_administrative_activity_v1",
        "pagination": "reverse_activity_id_keyset",
        "default_limit": 50,
        "maximum_limit": 200,
        "direct_table_select": False,
    }:
        raise AdministrativeActivityError(
            "administrative_activity_contract_prepared_reader_invalid"
        )
    producer = value.get("prepared_producers")
    auth_producer = producer.get("auth_audit") if isinstance(producer, Mapping) else None
    if not isinstance(auth_producer, Mapping) or auth_producer != {
        "source_table": "auth_audit",
        "source_actions": [
            "login",
            "logout",
            "initial_owner_claimed",
            "user_created",
            "user_updated",
            "user_password_reset",
            "api_key_issued",
            "api_key_revoked",
        ],
        "atomic_cursor_bridge": True,
        "runtime_enabled": False,
        "raw_username_or_key_prefix_copied": False,
    }:
        raise AdministrativeActivityError(
            "administrative_activity_contract_auth_producer_invalid"
        )
    access_producer = producer.get("access_audit_v4")
    if not isinstance(access_producer, Mapping) or access_producer != {
        "source_table": "access_audit_v4",
        "source_actions": [
            "report_assignment_created",
            "package_assignment_created",
            "vpn_session_evidence_grant_created",
            "report_access_requested",
            "report_access_request_rejected",
            "report_access_request_approved",
            "report_published",
            "report_draft_created",
            "report_version_promoted",
            "report_retired",
            "report_visibility_changed",
        ],
        "excluded_actions": ["report_preference_updated"],
        "atomic_cursor_bridge": True,
        "runtime_enabled": False,
        "raw_reason_or_details_copied": False,
    }:
        raise AdministrativeActivityError(
            "administrative_activity_contract_access_producer_invalid"
        )
    return value


def validate_administrative_activity(
    activity: AdministrativeActivity,
    contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    value = dict(contract or load_administrative_activity_contract())
    if activity.occurred_at_utc.tzinfo is None:
        raise AdministrativeActivityError("administrative_activity_time_not_aware")
    occurred = activity.occurred_at_utc.astimezone(timezone.utc)
    if activity.actor_kind not in ACTOR_KINDS:
        raise AdministrativeActivityError("administrative_activity_actor_kind_invalid")
    actor_key = activity.actor_key.strip()
    if not actor_key or len(actor_key) > 200:
        raise AdministrativeActivityError("administrative_activity_actor_key_invalid")
    if activity.category not in set(value["categories"]):
        raise AdministrativeActivityError("administrative_activity_category_invalid")
    if not ACTION_RE.fullmatch(activity.action_key):
        raise AdministrativeActivityError("administrative_activity_action_key_invalid")
    if activity.outcome not in set(value["outcomes"]):
        raise AdministrativeActivityError("administrative_activity_outcome_invalid")
    if activity.target_kind is not None and not TARGET_KIND_RE.fullmatch(
        activity.target_kind
    ):
        raise AdministrativeActivityError("administrative_activity_target_kind_invalid")
    if activity.target_key is not None and len(activity.target_key) > 240:
        raise AdministrativeActivityError("administrative_activity_target_key_invalid")
    if activity.reason_code is not None and not ACTION_RE.fullmatch(
        activity.reason_code
    ):
        raise AdministrativeActivityError("administrative_activity_reason_code_invalid")
    details = dict(activity.details)
    prohibited = tuple(str(item).casefold() for item in value["prohibited_detail_key_fragments"])
    for key, detail_value in details.items():
        if not isinstance(key, str) or not key:
            raise AdministrativeActivityError("administrative_activity_detail_key_invalid")
        if any(fragment in key.casefold() for fragment in prohibited):
            raise AdministrativeActivityError("administrative_activity_detail_key_prohibited")
        if detail_value is not None and not isinstance(
            detail_value, (str, int, float, bool)
        ):
            raise AdministrativeActivityError("administrative_activity_detail_value_not_scalar")
    details_json = json.dumps(
        details, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    if len(details_json.encode("utf-8")) > int(value["maximum_detail_bytes"]):
        raise AdministrativeActivityError("administrative_activity_details_too_large")
    return {
        "event_uid": str(activity.event_uid),
        "occurred_at_utc": occurred,
        "actor_kind": activity.actor_kind,
        "actor_key": actor_key,
        "category": activity.category,
        "action_key": activity.action_key,
        "target_kind": activity.target_kind,
        "target_key": activity.target_key,
        "outcome": activity.outcome,
        "reason_code": activity.reason_code,
        "details_json": details_json,
        "remote_address": activity.remote_address,
        "correlation_id": (
            str(activity.correlation_id) if activity.correlation_id else None
        ),
    }


def append_administrative_activity(
    activity: AdministrativeActivity,
    *,
    connection_factory: Callable[[], Any],
) -> dict[str, Any]:
    validate_administrative_activity(activity)
    with connection_factory() as conn, conn.cursor() as cur:
        return append_administrative_activity_with_cursor(activity, cursor=cur)


def append_administrative_activity_with_cursor(
    activity: AdministrativeActivity,
    *,
    cursor: Any,
) -> dict[str, Any]:
    """Append through an existing transaction owned by the calling action."""
    validated = validate_administrative_activity(activity)
    cursor.execute(
        """
        select activity_id,encode(record_hash,'hex') as record_hash
        from append_administrative_activity_v1(
            %s::uuid,%s::timestamptz,%s,%s,%s,%s,%s,%s,%s,%s,
            %s::jsonb,%s::inet,%s::uuid
        )
        """,
        (
            validated["event_uid"],
            validated["occurred_at_utc"],
            validated["actor_kind"],
            validated["actor_key"],
            validated["category"],
            validated["action_key"],
            validated["target_kind"],
            validated["target_key"],
            validated["outcome"],
            validated["reason_code"],
            validated["details_json"],
            validated["remote_address"],
            validated["correlation_id"],
        ),
    )
    row = dict(cursor.fetchone() or {})
    record_hash = str(row.get("record_hash") or "")
    if int(row.get("activity_id") or 0) < 1 or not re.fullmatch(
        r"[0-9a-f]{64}", record_hash
    ):
        raise AdministrativeActivityError("administrative_activity_write_result_invalid")
    return {
        "activity_id": int(row["activity_id"]),
        "record_hash": record_hash,
        "event_uid": validated["event_uid"],
        "contains_sensitive_details": False,
    }

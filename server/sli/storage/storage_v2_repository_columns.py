"""Storage V2 repository write-column contracts and pure fact/replay helpers (never patched)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from server.sli.storage.storage_v2_models import PROCESS_ACTIVITY_FACT_COLUMNS

EVENT_V2_WRITE_COLUMNS = frozenset({
    "id", "raw_log_file_id", "server_id", "domain_id", "site_id", "log_source_id",
    "event_record_id", "event_id", "version", "level", "task", "opcode",
    "keywords_id", "provider_id", "channel_id", "computer_id", "time_created_utc",
    "subject_user_sid", "subject_user_name", "subject_domain_id", "target_user_sid",
    "target_user_name", "target_domain_id", "ip_address", "workstation_name",
    "logon_id", "correlation_id", "normalized_at", "normalized_hash",
    "noise_class", "noise_catalog_version", "source_core_sha256",
})
ENTITY_V2_WRITE_COLUMNS = frozenset({
    "id", "entity_type_id", "natural_key", "display_name", "domain_id", "server_id",
    "first_seen_utc", "last_seen_utc", "source_core_sha256",
})
EVENT_FACTS_V2_WRITE_COLUMNS = frozenset({
    "event_id", "process_name", "process_id", "target_server_name", "service_name",
    "task_name", "task_action", "task_author", "run_as", "logon_type", "result_code",
    "object_name", "share_name", "message_sample", "powershell_user_name",
    "powershell_command_name", "powershell_script_block_text", "powershell_process_id",
    "account_target_sid", "account_target_name", "account_name_before", "account_name_after",
    "membership_member_sid", "membership_member_name",
    "process_parent_id", "process_command_line", "process_user_sid",
    "process_user_name", "process_user_domain", "process_logon_id",
    "service_file", "service_account", "service_start_type", "task_content",
    "task_change", "native_process_id", "file_audit_facts_json", "source_facts_sha256",
})
ADDITIVE_EVENT_FACT_COLUMNS = frozenset({
    "powershell_user_name", "powershell_command_name", "powershell_script_block_text",
    "powershell_process_id", "account_target_sid", "account_target_name",
    "account_name_before", "account_name_after", "membership_member_sid",
    "membership_member_name", "file_audit_facts_json",
}) | PROCESS_ACTIVITY_FACT_COLUMNS


def _validated_write_columns(values: Mapping[str, Any], allowed: frozenset[str], kind: str) -> tuple[str, ...]:
    actual = frozenset(values)
    if actual != allowed:
        missing = sorted(allowed - actual)
        unexpected = sorted(actual - allowed)
        raise RuntimeError(f"{kind} write-column contract mismatch; missing={missing}; unexpected={unexpected}")
    return tuple(values)


def _normalized_historical_fact_values(values: Mapping[str, Any]) -> dict[str, Any]:
    """Default only fields added after the original archived fact contract."""
    actual = frozenset(values)
    missing_required = EVENT_FACTS_V2_WRITE_COLUMNS - actual - ADDITIVE_EVENT_FACT_COLUMNS
    unexpected = actual - EVENT_FACTS_V2_WRITE_COLUMNS
    if missing_required or unexpected:
        raise RuntimeError(
            "event facts write-column contract mismatch; "
            f"missing={sorted(missing_required)}; unexpected={sorted(unexpected)}"
        )
    normalized = dict(values)
    for column in sorted(ADDITIVE_EVENT_FACT_COLUMNS - actual):
        normalized[column] = None
    return normalized


def _schema_compatible_fact_columns(
    values: Mapping[str, Any], available: set[str]
) -> tuple[str, ...]:
    columns = _validated_write_columns(
        values, EVENT_FACTS_V2_WRITE_COLUMNS, "event facts"
    )
    missing = EVENT_FACTS_V2_WRITE_COLUMNS - frozenset(available)
    unsupported = missing - PROCESS_ACTIVITY_FACT_COLUMNS - {"file_audit_facts_json"}
    if unsupported:
        raise RuntimeError(
            f"event facts schema mismatch; missing={sorted(unsupported)}"
        )
    populated = sorted(
        column for column in missing if values.get(column) is not None
    )
    if populated:
        if "file_audit_facts_json" in populated:
            raise RuntimeError("event facts require schema migration 186 for file audit facts")
        raise RuntimeError(
            "event facts require schema migration 089 for populated process activity "
            f"columns: {populated}"
        )
    return tuple(column for column in columns if column in available)


def _matches_event_replay(existing: Mapping[str, Any], values: Mapping[str, Any]) -> bool:
    """Accept only an exact replay of a V2 event, never a conflicting source key."""
    return (
        int(existing["id"]) == int(values["id"])
        and bytes(existing["source_core_sha256"]) == bytes(values["source_core_sha256"])
    )


def _matches_raw_file_reservation(
    existing: Mapping[str, Any],
    *,
    server_id: int,
    log_source_id: int,
    sha256: str,
) -> bool:
    """Match the canonical raw-file identity; collection paths are transient."""
    return (
        int(existing["server_id"]) == int(server_id)
        and int(existing["log_source_id"]) == int(log_source_id)
        and str(existing["sha256"]).lower() == str(sha256).lower()
    )


def events_by_id(events: Sequence[Mapping[str, Any]]) -> dict[int, Mapping[str, Any]]:
    return {int(event["id"]): event for event in events}


def _postgres_jsonb(value: Mapping[str, Any]) -> Any:
    """Wrap JSON explicitly: psycopg deliberately does not adapt dict by default."""
    from psycopg.types.json import Jsonb
    return Jsonb(dict(value))

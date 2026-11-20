#!/usr/bin/env python3
"""Validate or run the one-shot bounded RADIUS correlation/time audit."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import fnmatch
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.ad_context_live_canary import (  # noqa: E402
    current_windows_account,
    terminate_process_tree,
)
from scripts.maintenance.stage9_radius_field_quality_audit import (  # noqa: E402
    _read_accounting_segments,
    select_bounded_lines,
)
from server.source_packs.radius.accounting import (  # noqa: E402
    DATABASE_COMPATIBLE_COLUMNS,
    is_database_compatible_row,
)

PLAN_PATH = (
    ROOT / "config" / "stage9_radius_correlation_time_preflight.json"
)
TARGETS_PATH = ROOT / "config" / "stage9_radius_targets.json"
PLAN_ID = "stage9-radius-correlation-time-preflight-v1"
CONFIRMATION = "START-STAGE9-RADIUS-CORRELATION-TIME-AUDIT"
DEFAULT_OUTPUT = (
    ROOT
    / "artifacts"
    / "stage9"
    / "evidence"
    / "radius-correlation-time-audit.json"
)
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
INTEGER = re.compile(r"^-?\d+$")
SID = re.compile(r"^S-\d(?:-\d+)+$", re.IGNORECASE)
IPV4 = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
)
ACCOUNTING_INDEX = {
    name: index for index, name in enumerate(DATABASE_COMPATIBLE_COLUMNS)
}


class RadiusCorrelationTimePlanError(RuntimeError):
    """Closed-code validation failure."""


def load_plan(path: Path = PLAN_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusCorrelationTimePlanError("plan_invalid") from exc
    if not isinstance(value, dict):
        raise RadiusCorrelationTimePlanError("plan_object_required")
    return value


def validate_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    if plan.get("schema_version") != 1:
        raise RadiusCorrelationTimePlanError("unsupported_plan_schema")
    if plan.get("plan_id") != PLAN_ID:
        raise RadiusCorrelationTimePlanError("unexpected_plan_id")
    if plan.get("status") != "owner_authorized":
        raise RadiusCorrelationTimePlanError(
            "owner_authorization_required"
        )

    expected_limits = {
        "target_count": 1,
        "window_hours": 24,
        "event_ids": [6272, 6273],
        "nps_events": 100,
        "accounting_files": 1,
        "accounting_candidates": 20,
        "accounting_records": 200,
        "accounting_bytes": 262_144,
        "source_timezone_queries": 1,
        "overall_timeout_seconds": 60,
    }
    limits = dict(plan.get("limits") or {})
    if limits != expected_limits:
        raise RadiusCorrelationTimePlanError("bounded_limits_changed")

    target_path = (ROOT / str(plan.get("targets_source") or "")).resolve()
    if target_path != TARGETS_PATH.resolve():
        raise RadiusCorrelationTimePlanError("unexpected_targets_source")
    try:
        inventory = json.loads(target_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusCorrelationTimePlanError(
            "target_inventory_invalid"
        ) from exc
    expected_targets = [
        {
            "source_name": "radius01.example.invalid",
            "connect_address": "radius01.example.invalid",
            "owner_confirmed_ip": "192.0.2.15",
        }
    ]
    if inventory.get("targets") != expected_targets:
        raise RadiusCorrelationTimePlanError("approved_target_changed")

    account = str(plan.get("expected_windows_account") or "").strip()
    if account.casefold() != r"EXAMPLE\operator".casefold():
        raise RadiusCorrelationTimePlanError(
            "unexpected_windows_account"
        )

    required_memory = {
        "nps_event_time_utc",
        "nps_account_session_identifier",
        "nps_nas_identity",
        "nps_subject_sid",
        "accounting_record_date",
        "accounting_record_time",
        "accounting_event_timestamp",
        "accounting_account_session_id",
        "accounting_nas_identity",
        "accounting_user_name",
    }
    if set(plan.get("allowed_in_memory_fields") or []) != required_memory:
        raise RadiusCorrelationTimePlanError(
            "in_memory_field_contract_changed"
        )

    required_persisted = {
        "nps_event_counts_by_id",
        "accounting_lifecycle_counts",
        "cap_and_truncation_flags",
        "session_and_nas_joint_presence_counts",
        "session_only_and_session_plus_nas_join_counts",
        "one_to_one_ambiguous_and_unmatched_counts",
        "exact_principal_bridge_counts",
        "accounting_event_timestamp_presence_and_parse_counts",
        "record_date_time_format_counts",
        "source_timezone_id_offset_and_dst_metadata",
        "joined_time_delta_bucket_counts",
    }
    if set(plan.get("allowed_persisted_observations") or []) != (
        required_persisted
    ):
        raise RadiusCorrelationTimePlanError(
            "persisted_aggregate_contract_changed"
        )

    required_prohibited_persistence = {
        "event_xml",
        "event_payload",
        "event_timestamp_value",
        "accounting_raw_line",
        "accounting_timestamp_value",
        "account_session_identifier",
        "nas_identity",
        "subject_sid",
        "user_name",
        "distinguished_name",
        "ip_address",
        "file_name",
        "file_path",
        "radius_client",
        "radius_secret",
    }
    if not required_prohibited_persistence.issubset(
        set(plan.get("prohibited_persistence") or [])
    ):
        raise RadiusCorrelationTimePlanError(
            "required_persistence_prohibition_missing"
        )

    required_prohibited_actions = {
        "audit_policy_change",
        "nps_configuration_change",
        "radius_accounting_enable",
        "service_change",
        "scheduled_task_change",
        "firewall_change",
        "postgresql_write",
        "clickhouse_write",
        "event_import",
        "cursor_update",
        "migration",
        "source_instance_creation",
        "descriptor_change",
        "normalizer_change",
        "worker_activation",
        "autostart",
    }
    if not required_prohibited_actions.issubset(
        set(plan.get("prohibited_actions") or [])
    ):
        raise RadiusCorrelationTimePlanError(
            "required_action_prohibition_missing"
        )

    evaluation = dict(plan.get("evaluation_contract") or {})
    expected_evaluation = {
        "correlation_candidate_key": (
            "account_session_id_plus_nas_identity"
        ),
        "principal_bridge": (
            "exact_subject_sid_only_from_one_to_one_matched_nps_event"
        ),
        "username_is_not_exact_identity": True,
        "preferred_time_basis": (
            "accounting_event_timestamp_if_integer_epoch_and_join_delta_"
            "are_proven"
        ),
        "fallback_time_basis": (
            "record_date_plus_record_time_plus_explicit_source_timezone"
        ),
        "no_match_result": "correlation_not_proven",
        "ambiguous_match_result": "correlation_not_proven",
        "missing_time_basis_result": "timestamp_not_proven",
        "success_result": "ready_for_owner_review_before_runtime_design",
    }
    if evaluation != expected_evaluation:
        raise RadiusCorrelationTimePlanError(
            "evaluation_contract_changed"
        )
    if plan.get("next_action") != (
        "one_bounded_read_only_source_contact_then_owner_review"
    ):
        raise RadiusCorrelationTimePlanError("unexpected_next_action")

    return {
        "plan_id": PLAN_ID,
        "status": plan["status"],
        "source_contact": False,
        "read_only": True,
        "target_count": len(expected_targets),
        "limits": limits,
        "correlation_candidate_key": evaluation[
            "correlation_candidate_key"
        ],
        "preferred_time_basis": evaluation["preferred_time_basis"],
        "fallback_time_basis": evaluation["fallback_time_basis"],
        "next_action": plan["next_action"],
        "target": dict(expected_targets[0]),
        "expected_account": account,
    }


def _parse_utc(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _parse_epoch(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not INTEGER.fullmatch(text):
        return None
    try:
        return datetime.fromtimestamp(int(text), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _event_records(xml_items: Iterable[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for xml_text in xml_items:
        root = ET.fromstring(xml_text)
        event_id = int(
            root.findtext(f".//{{{EVENT_NS}}}EventID") or "0"
        )
        time_node = root.find(f".//{{{EVENT_NS}}}TimeCreated")
        system_time = (
            str(time_node.attrib.get("SystemTime") or "")
            if time_node is not None
            else ""
        )
        values = {
            str(node.attrib.get("Name") or ""): str(node.text or "").strip()
            for node in root.findall(
                f".//{{{EVENT_NS}}}EventData/{{{EVENT_NS}}}Data"
            )
        }
        records.append(
            {
                "event_id": event_id,
                "event_time_utc": _parse_utc(system_time),
                "session_id": values.get("AccountSessionIdentifier", ""),
                "nas_identity": (
                    values.get("NASIdentifier")
                    or values.get("NASIPv4Address")
                    or ""
                ),
                "subject_sid": values.get("SubjectUserSid", ""),
            }
        )
    return records


def _record_time_shape(date_text: str, time_text: str) -> str:
    date_value = str(date_text or "").strip()
    time_value = str(time_text or "").strip()
    if re.fullmatch(r"\d{2}/\d{2}/\d{4}", date_value) and re.fullmatch(
        r"\d{2}:\d{2}:\d{2}", time_value
    ):
        return "slash_mdy_hms"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_value) and re.fullmatch(
        r"\d{2}:\d{2}:\d{2}", time_value
    ):
        return "iso_date_hms"
    if not date_value and not time_value:
        return "missing"
    return "other"


def _accounting_records(
    lines: Iterable[str],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    records: list[dict[str, Any]] = []
    shapes: dict[str, int] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = next(csv.reader([line], strict=True))
        except (csv.Error, StopIteration):
            continue
        if not is_database_compatible_row(row):
            continue
        date_text = row[ACCOUNTING_INDEX["Record-Date"]].strip()
        time_text = row[ACCOUNTING_INDEX["Record-Time"]].strip()
        shape = _record_time_shape(date_text, time_text)
        shapes[shape] = shapes.get(shape, 0) + 1
        if row[ACCOUNTING_INDEX["Packet-Type"]].strip() != "4":
            continue
        status = {
            "1": "start",
            "2": "stop",
            "3": "interim_update",
        }.get(row[ACCOUNTING_INDEX["Acct-Status-Type"]].strip(), "other")
        timestamp_raw = row[
            ACCOUNTING_INDEX["Event-Timestamp"]
        ].strip()
        records.append(
            {
                "lifecycle": status,
                "session_id": row[
                    ACCOUNTING_INDEX["Acct-Session-Id"]
                ].strip(),
                "nas_identity": (
                    row[ACCOUNTING_INDEX["NAS-Identifier"]].strip()
                    or row[ACCOUNTING_INDEX["NAS-IP-Address"]].strip()
                ),
                "event_timestamp_raw": timestamp_raw,
                "event_time_utc": _parse_epoch(timestamp_raw),
            }
        )
    return records, shapes


def _join_key(record: Mapping[str, Any]) -> tuple[str, str]:
    return (
        str(record.get("session_id") or ""),
        str(record.get("nas_identity") or "").casefold(),
    )


def _delta_bucket(delta_seconds: float) -> str:
    absolute = abs(delta_seconds)
    if absolute <= 60:
        return "absolute_le_60_seconds"
    if absolute <= 300:
        return "absolute_le_5_minutes"
    if absolute <= 3600:
        return "absolute_le_1_hour"
    return "absolute_gt_1_hour"


def aggregate_observations(
    events: Iterable[Mapping[str, Any]],
    accounting: Iterable[Mapping[str, Any]],
    *,
    record_time_shapes: Mapping[str, int],
    timezone_metadata: Mapping[str, Any],
    caps: Mapping[str, bool],
) -> dict[str, Any]:
    event_rows = list(events)
    accounting_rows = list(accounting)
    event_by_session: dict[str, list[Mapping[str, Any]]] = {}
    event_by_joint: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    event_counts: dict[str, int] = {}
    for event in event_rows:
        event_id = str(int(event.get("event_id") or 0))
        event_counts[event_id] = event_counts.get(event_id, 0) + 1
        session = str(event.get("session_id") or "")
        if session:
            event_by_session.setdefault(session, []).append(event)
            key = _join_key(event)
            if key[1]:
                event_by_joint.setdefault(key, []).append(event)

    lifecycle = {
        "start": 0,
        "interim_update": 0,
        "stop": 0,
        "other": 0,
    }
    session_only = joint = one_to_one = ambiguous = unmatched = 0
    exact_bridge = missing_sid = 0
    timestamp_present = timestamp_parsed = joined_start = 0
    delta_buckets: dict[str, int] = {}
    for record in accounting_rows:
        status = str(record.get("lifecycle") or "other")
        lifecycle[status if status in lifecycle else "other"] += 1
        session = str(record.get("session_id") or "")
        if event_by_session.get(session):
            session_only += 1
        matches = event_by_joint.get(_join_key(record), [])
        if matches:
            joint += 1
        if len(matches) == 1:
            one_to_one += 1
            if SID.fullmatch(str(matches[0].get("subject_sid") or "")):
                exact_bridge += 1
            else:
                missing_sid += 1
            raw_timestamp = str(record.get("event_timestamp_raw") or "")
            if raw_timestamp:
                timestamp_present += 1
            accounting_time = record.get("event_time_utc")
            if isinstance(accounting_time, datetime):
                timestamp_parsed += 1
            event_time = matches[0].get("event_time_utc")
            if (
                status == "start"
                and isinstance(accounting_time, datetime)
                and isinstance(event_time, datetime)
            ):
                joined_start += 1
                bucket = _delta_bucket(
                    (accounting_time - event_time).total_seconds()
                )
                delta_buckets[bucket] = delta_buckets.get(bucket, 0) + 1
        elif len(matches) > 1:
            ambiguous += 1
        else:
            unmatched += 1

    nps_joint_presence = sum(
        bool(str(row.get("session_id") or ""))
        and bool(str(row.get("nas_identity") or ""))
        for row in event_rows
    )
    accounting_joint_presence = sum(
        bool(str(row.get("session_id") or ""))
        and bool(str(row.get("nas_identity") or ""))
        for row in accounting_rows
    )
    correlation = (
        "proven_on_bounded_sample"
        if one_to_one > 0 and ambiguous == 0 and exact_bridge > 0
        else "correlation_not_proven"
    )
    near_delta = sum(
        count
        for name, count in delta_buckets.items()
        if name in {
            "absolute_le_60_seconds",
            "absolute_le_5_minutes",
        }
    )
    timestamp = (
        "event_timestamp_proven_on_joined_starts"
        if joined_start > 0 and near_delta == joined_start
        else "timestamp_not_proven"
    )
    return {
        "nps_event_counts_by_id": event_counts,
        "accounting_lifecycle_counts": lifecycle,
        "cap_and_truncation_flags": dict(caps),
        "session_and_nas_joint_presence_counts": {
            "nps_events": nps_joint_presence,
            "accounting_records": accounting_joint_presence,
        },
        "session_only_and_session_plus_nas_join_counts": {
            "session_only_records": session_only,
            "session_plus_nas_records": joint,
        },
        "one_to_one_ambiguous_and_unmatched_counts": {
            "one_to_one_records": one_to_one,
            "ambiguous_records": ambiguous,
            "unmatched_records": unmatched,
        },
        "exact_principal_bridge_counts": {
            "exact_subject_sid_records": exact_bridge,
            "missing_or_invalid_subject_sid_records": missing_sid,
        },
        "accounting_event_timestamp_presence_and_parse_counts": {
            "present_on_one_to_one_records": timestamp_present,
            "parsed_as_integer_epoch_on_one_to_one_records": (
                timestamp_parsed
            ),
            "joined_start_records": joined_start,
        },
        "record_date_time_format_counts": dict(record_time_shapes),
        "source_timezone_id_offset_and_dst_metadata": dict(
            timezone_metadata
        ),
        "joined_time_delta_bucket_counts": delta_buckets,
        "classification": {
            "correlation": correlation,
            "timestamp": timestamp,
        },
    }


def _read_timezone_metadata(target: str) -> dict[str, Any]:
    try:
        import winreg

        registry = winreg.ConnectRegistry(
            rf"\\{target}", winreg.HKEY_LOCAL_MACHINE
        )
        try:
            key = winreg.OpenKey(
                registry,
                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
            )
            try:
                timezone_id = str(
                    winreg.QueryValueEx(key, "TimeZoneKeyName")[0]
                )
                active_bias = _signed_dword(
                    int(winreg.QueryValueEx(key, "ActiveTimeBias")[0])
                )
                try:
                    daylight_disabled = bool(
                        winreg.QueryValueEx(
                            key, "DynamicDaylightTimeDisabled"
                        )[0]
                    )
                except FileNotFoundError:
                    daylight_disabled = None
            finally:
                winreg.CloseKey(key)
        finally:
            winreg.CloseKey(registry)
        return {
            "status": "observed",
            "timezone_id": timezone_id,
            "utc_offset_minutes": -active_bias,
            "dynamic_daylight_time_disabled": daylight_disabled,
        }
    except Exception as exc:
        return {
            "status": "inaccessible",
            "error_type": type(exc).__name__,
            "winerror": getattr(exc, "winerror", None),
        }


def _signed_dword(value: int) -> int:
    number = int(value)
    if not 0 <= number <= 0xFFFFFFFF:
        raise ValueError("dword_out_of_range")
    return number - 0x100000000 if number >= 0x80000000 else number


def _read_live_inputs(
    target: str, limits: Mapping[str, Any]
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, int],
    dict[str, Any],
    dict[str, bool],
]:
    from scripts.collect import collect_windows_events as collector

    session = query = None
    handles: list[Any] = []
    try:
        session = collector.open_remote_session(target)
        milliseconds = int(limits["window_hours"]) * 60 * 60 * 1000
        xpath = (
            "*[System[(EventID=6272 or EventID=6273) and "
            f"TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]"
        )
        flags = (
            collector.win32evtlog.EvtQueryChannelPath
            | collector.win32evtlog.EvtQueryReverseDirection
        )
        query = collector.win32evtlog.EvtQuery(
            "Security", flags, xpath, session
        )
        while len(handles) < int(limits["nps_events"]):
            batch = collector.next_event_batch(
                query,
                min(32, int(limits["nps_events"]) - len(handles)),
                10_000,
            )
            if not batch:
                break
            handles.extend(batch)
        events = _event_records(
            collector.render_event_xml(handle) for handle in handles
        )
    finally:
        for handle in handles:
            close = getattr(handle, "Close", None)
            if callable(close):
                close()
        for handle in (query, session):
            close = getattr(handle, "Close", None)
            if callable(close):
                close()

    directory = rf"\\{target}\c$\Windows\System32\LogFiles"
    candidates: list[tuple[float, int, str]] = []
    candidate_truncated = False
    with os.scandir(directory) as entries:
        for entry in entries:
            if not fnmatch.fnmatch(entry.name.casefold(), "in*.log"):
                continue
            if len(candidates) >= int(limits["accounting_candidates"]):
                candidate_truncated = True
                break
            stat = entry.stat(follow_symlinks=False)
            candidates.append(
                (float(stat.st_mtime), int(stat.st_size), entry.path)
            )
    lines: list[str] = []
    sampled_bytes = 0
    selected_file_truncated = False
    if candidates:
        _modified, size, selected_path = max(
            candidates, key=lambda item: item[0]
        )
        head, tail, same_segment = _read_accounting_segments(
            selected_path,
            file_size=size,
            max_bytes=int(limits["accounting_bytes"]),
        )
        sampled_bytes = len(head) + len(tail)
        selected_file_truncated = not same_segment
        lines = select_bounded_lines(
            head.decode("utf-8-sig", errors="replace"),
            tail.decode("utf-8-sig", errors="replace"),
            same_segment=same_segment,
            max_records=int(limits["accounting_records"]),
        )
    accounting, shapes = _accounting_records(lines)
    caps = {
        "nps_event_cap_reached": (
            len(events) == int(limits["nps_events"])
        ),
        "accounting_candidate_cap_reached": candidate_truncated,
        "accounting_record_cap_reached": (
            len(lines) == int(limits["accounting_records"])
        ),
        "accounting_byte_cap_reached": (
            sampled_bytes == int(limits["accounting_bytes"])
        ),
        "selected_file_was_sampled_not_fully_read": (
            selected_file_truncated
        ),
        "accounting_file_observed": bool(candidates),
    }
    return (
        events,
        accounting,
        shapes,
        _read_timezone_metadata(target),
        caps,
    )


def _reject_sensitive_evidence(value: Any) -> None:
    forbidden_keys = {
        "event_xml",
        "raw_line",
        "session_id",
        "account_session_identifier",
        "nas_identity",
        "subject_sid",
        "user_name",
        "distinguished_name",
        "ip_address",
        "file_name",
        "file_path",
    }
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).casefold() in forbidden_keys:
                raise RadiusCorrelationTimePlanError(
                    "sensitive_evidence_key_present"
                )
            _reject_sensitive_evidence(item)
    elif isinstance(value, list):
        for item in value:
            _reject_sensitive_evidence(item)
    elif isinstance(value, str):
        if SID.fullmatch(value) or IPV4.fullmatch(value):
            raise RadiusCorrelationTimePlanError(
                "sensitive_evidence_value_present"
            )


def run_internal() -> dict[str, Any]:
    validated = validate_plan(load_plan())
    account = current_windows_account()
    if account.casefold() != validated["expected_account"].casefold():
        raise PermissionError("current_windows_account_is_not_approved_owner")
    live = _read_live_inputs(
        str(validated["target"]["connect_address"]),
        validated["limits"],
    )
    observations = aggregate_observations(
        live[0],
        live[1],
        record_time_shapes=live[2],
        timezone_metadata=live[3],
        caps=live[4],
    )
    _reject_sensitive_evidence(observations)
    return {
        "schema_version": 1,
        "read_only": True,
        "contains_source_values": False,
        "observations": observations,
    }


def run_live(plan: Mapping[str, Any], confirmation: str) -> dict[str, Any]:
    validated = validate_plan(plan)
    if confirmation != CONFIRMATION:
        raise PermissionError(
            f"execute requires --confirmation {CONFIRMATION}"
        )
    if os.name != "nt":
        raise RadiusCorrelationTimePlanError(
            "live_audit_requires_windows_host"
        )
    account = current_windows_account()
    if account.casefold() != validated["expected_account"].casefold():
        raise PermissionError("current_windows_account_is_not_approved_owner")
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--internal"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        stdout, _stderr = process.communicate(
            timeout=int(validated["limits"]["overall_timeout_seconds"])
        )
    except subprocess.TimeoutExpired as exc:
        terminate_process_tree(process)
        raise TimeoutError(
            "radius correlation/time audit exceeded timeout"
        ) from exc
    if process.returncode != 0:
        raise RadiusCorrelationTimePlanError(
            f"internal_audit_failed:exit_code={process.returncode}"
        )
    try:
        internal = json.loads(stdout.lstrip("\ufeff").strip())
    except json.JSONDecodeError as exc:
        raise RadiusCorrelationTimePlanError(
            "internal_json_invalid"
        ) from exc
    _reject_sensitive_evidence(internal)
    return {
        "schema_version": 1,
        "evidence_id": "stage9-radius-correlation-time-audit",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "owner_authorized": True,
        "read_only": True,
        "source_contact": True,
        "windows_changed": False,
        "postgresql_mutated": False,
        "clickhouse_mutated": False,
        "event_imported": False,
        "cursor_updated": False,
        "source_instance_created": False,
        "descriptor_changed": False,
        "normalizer_changed": False,
        "worker_activated": False,
        "autostart_changed": False,
        "contains_source_values": False,
        "limits": dict(validated["limits"]),
        "live": internal,
        "next_gate": "owner_review_before_runtime_design",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate the local owner-authorized bounded plan",
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation", default="")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--internal", action="store_true", help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    if args.internal:
        try:
            result = run_internal()
            print(json.dumps(result, ensure_ascii=False))
            return 0
        except Exception as exc:
            print(json.dumps({"error_type": type(exc).__name__}))
            return 1
    if args.validate_only == args.execute:
        raise RadiusCorrelationTimePlanError(
            "choose_exactly_one_mode"
        )
    plan = load_plan()
    if args.validate_only:
        result = validate_plan(plan)
        result.pop("target", None)
        result.pop("expected_account", None)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    output = args.output.resolve()
    artifact_root = (ROOT / "artifacts").resolve()
    if artifact_root not in output.parents:
        raise ValueError("evidence output must stay under artifacts")
    if output.exists():
        raise FileExistsError("one_shot_evidence_already_exists")
    result = run_live(plan, args.confirmation)
    _reject_sensitive_evidence(result)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {"status": result["status"], "output": str(output)},
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

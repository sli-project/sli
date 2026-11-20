#!/usr/bin/env python3
"""Run one bounded time-aligned RADIUS Accounting/NPS read-only preflight."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
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
from scripts.maintenance.stage9_radius_correlation_time_preflight import (  # noqa: E402
    _read_timezone_metadata,
)
from server.source_packs.radius.accounting import (  # noqa: E402
    DATABASE_COMPATIBLE_COLUMNS,
    is_database_compatible_row,
)


PLAN_PATH = ROOT / "config" / "stage9_radius_time_aligned_preflight.json"
TARGETS_PATH = ROOT / "config" / "stage9_radius_targets.json"
PLAN_ID = "stage9-radius-time-aligned-preflight-v1"
CONFIRMATION = "START-STAGE9-RADIUS-TIME-ALIGNED-READONLY-PREFLIGHT"
DEFAULT_OUTPUT = (
    ROOT
    / "artifacts"
    / "stage9"
    / "evidence"
    / "radius-time-aligned-preflight.json"
)
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SID = re.compile(r"^S-\d(?:-\d+)+$", re.IGNORECASE)
IPV4 = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
)
ACCOUNTING_INDEX = {
    name: index for index, name in enumerate(DATABASE_COMPATIBLE_COLUMNS)
}


class RadiusTimeAlignedPlanError(RuntimeError):
    """Closed-code validation failure."""


def load_plan(path: Path = PLAN_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusTimeAlignedPlanError("plan_invalid") from exc
    if not isinstance(value, dict):
        raise RadiusTimeAlignedPlanError("plan_object_required")
    return value


def validate_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    if plan.get("schema_version") != 1:
        raise RadiusTimeAlignedPlanError("unsupported_plan_schema")
    if plan.get("plan_id") != PLAN_ID:
        raise RadiusTimeAlignedPlanError("unexpected_plan_id")
    if plan.get("status") != "owner_authorized":
        raise RadiusTimeAlignedPlanError("owner_authorization_required")
    expected_limits = {
        "target_count": 1,
        "event_ids": [6272, 6273],
        "nps_events": 500,
        "accounting_files": 1,
        "accounting_candidates": 20,
        "accounting_records": 400,
        "accounting_bytes": 262_144,
        "alignment_padding_seconds": 600,
        "maximum_alignment_span_seconds": 10_800,
        "source_timezone_queries": 1,
        "overall_timeout_seconds": 75,
    }
    limits = dict(plan.get("limits") or {})
    if limits != expected_limits:
        raise RadiusTimeAlignedPlanError("bounded_limits_changed")
    target_path = (ROOT / str(plan.get("targets_source") or "")).resolve()
    if target_path != TARGETS_PATH.resolve():
        raise RadiusTimeAlignedPlanError("unexpected_targets_source")
    try:
        inventory = json.loads(target_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusTimeAlignedPlanError("target_inventory_invalid") from exc
    expected_targets = [
        {
            "source_name": "radius01.example.invalid",
            "connect_address": "radius01.example.invalid",
            "owner_confirmed_ip": "192.0.2.15",
        }
    ]
    if inventory.get("targets") != expected_targets:
        raise RadiusTimeAlignedPlanError("approved_target_changed")
    account = str(plan.get("expected_windows_account") or "").strip()
    if account.casefold() != r"EXAMPLE\operator".casefold():
        raise RadiusTimeAlignedPlanError("unexpected_windows_account")
    required_actions = {
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
    if not required_actions.issubset(
        set(plan.get("prohibited_actions") or [])
    ):
        raise RadiusTimeAlignedPlanError(
            "required_action_prohibition_missing"
        )
    required_persistence = {
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
    if not required_persistence.issubset(
        set(plan.get("prohibited_persistence") or [])
    ):
        raise RadiusTimeAlignedPlanError(
            "required_persistence_prohibition_missing"
        )
    evaluation = dict(plan.get("evaluation_contract") or {})
    if evaluation != {
        "alignment_basis": (
            "accounting_record_date_time_plus_explicit_source_utc_offset"
        ),
        "correlation_candidate_key": (
            "account_session_id_plus_nas_identity"
        ),
        "principal_bridge": (
            "exact_subject_sid_only_from_one_to_one_matched_nps_event"
        ),
        "username_is_not_exact_identity": True,
        "event_timestamp_preferred": True,
        "fallback_timestamp_basis": (
            "record_date_plus_record_time_plus_explicit_source_timezone"
        ),
        "truncated_or_ambiguous_result": "correlation_not_proven",
        "success_result": "ready_for_runtime_adapter_design",
    }:
        raise RadiusTimeAlignedPlanError("evaluation_contract_changed")
    if plan.get("next_action") != (
        "one_bounded_read_only_time_aligned_source_contact_then_owner_review"
    ):
        raise RadiusTimeAlignedPlanError("unexpected_next_action")
    return {
        "plan_id": PLAN_ID,
        "status": "owner_authorized",
        "source_contact": False,
        "read_only": True,
        "target_count": 1,
        "limits": limits,
        "target": dict(expected_targets[0]),
        "expected_account": account,
    }


def _tail_lines(
    path: str,
    *,
    file_size: int,
    max_bytes: int,
    max_records: int,
) -> tuple[list[str], int, bool]:
    with open(path, "rb") as stream:
        truncated = file_size > max_bytes
        if truncated:
            stream.seek(file_size - max_bytes)
        data = stream.read(max_bytes)
    text = data.decode("utf-8-sig", errors="replace")
    lines = text.splitlines()
    if truncated and lines:
        lines = lines[1:]
    return lines[-max_records:], len(data), truncated


def _local_record_utc(
    date_text: str,
    time_text: str,
    offset_minutes: int,
) -> datetime | None:
    try:
        local = datetime.strptime(
            f"{str(date_text).strip()} {str(time_text).strip()}",
            "%m/%d/%Y %H:%M:%S",
        )
    except ValueError:
        return None
    return (local - timedelta(minutes=offset_minutes)).replace(
        tzinfo=timezone.utc
    )


def _parse_epoch(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not re.fullmatch(r"-?\d+", text):
        return None
    try:
        return datetime.fromtimestamp(int(text), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def parse_accounting_sample(
    lines: Iterable[str],
    *,
    utc_offset_minutes: int,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    records: list[dict[str, Any]] = []
    counts = {
        "sampled_rows": 0,
        "database_compatible_rows": 0,
        "lifecycle_rows": 0,
        "local_time_parsed_rows": 0,
        "event_timestamp_parsed_rows": 0,
    }
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        counts["sampled_rows"] += 1
        try:
            row = next(csv.reader([line], strict=True))
        except (csv.Error, StopIteration):
            continue
        if not is_database_compatible_row(row):
            continue
        counts["database_compatible_rows"] += 1
        if row[ACCOUNTING_INDEX["Packet-Type"]].strip() != "4":
            continue
        lifecycle = {
            "1": "start",
            "2": "stop",
            "3": "interim_update",
        }.get(
            row[ACCOUNTING_INDEX["Acct-Status-Type"]].strip(),
            "other",
        )
        if lifecycle == "other":
            continue
        counts["lifecycle_rows"] += 1
        local_time = _local_record_utc(
            row[ACCOUNTING_INDEX["Record-Date"]],
            row[ACCOUNTING_INDEX["Record-Time"]],
            utc_offset_minutes,
        )
        event_time = _parse_epoch(
            row[ACCOUNTING_INDEX["Event-Timestamp"]]
        )
        counts["local_time_parsed_rows"] += int(local_time is not None)
        counts["event_timestamp_parsed_rows"] += int(
            event_time is not None
        )
        records.append(
            {
                "lifecycle": lifecycle,
                "session_id": row[
                    ACCOUNTING_INDEX["Acct-Session-Id"]
                ].strip(),
                "nas_identity": (
                    row[ACCOUNTING_INDEX["NAS-Identifier"]].strip()
                    or row[ACCOUNTING_INDEX["NAS-IP-Address"]].strip()
                ),
                "record_time_utc": local_time,
                "event_time_utc": event_time,
            }
        )
    return records, counts


def _format_system_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def build_time_aligned_xpath(
    start_utc: datetime,
    end_utc: datetime,
) -> str:
    if (
        start_utc.tzinfo is None
        or end_utc.tzinfo is None
        or start_utc >= end_utc
    ):
        raise RadiusTimeAlignedPlanError("invalid_alignment_window")
    return (
        "*[System[(EventID=6272 or EventID=6273) and "
        "TimeCreated[@SystemTime >= "
        f"'{_format_system_time(start_utc)}' and @SystemTime <= "
        f"'{_format_system_time(end_utc)}']]]"
    )


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
        try:
            event_time = datetime.fromisoformat(
                system_time.replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except ValueError:
            event_time = None
        values = {
            str(node.attrib.get("Name") or ""): str(node.text or "").strip()
            for node in root.findall(
                f".//{{{EVENT_NS}}}EventData/{{{EVENT_NS}}}Data"
            )
        }
        records.append(
            {
                "event_id": event_id,
                "event_time_utc": event_time,
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


def _join_key(value: Mapping[str, Any]) -> tuple[str, str]:
    return (
        str(value.get("session_id") or ""),
        str(value.get("nas_identity") or "").casefold(),
    )


def _delta_bucket(seconds: float) -> str:
    absolute = abs(seconds)
    if absolute <= 60:
        return "absolute_le_60_seconds"
    if absolute <= 300:
        return "absolute_le_5_minutes"
    if absolute <= 900:
        return "absolute_le_15_minutes"
    return "absolute_gt_15_minutes"


def aggregate_observations(
    events: Iterable[Mapping[str, Any]],
    accounting: Iterable[Mapping[str, Any]],
    *,
    accounting_counts: Mapping[str, int],
    alignment_span_seconds: int,
    caps: Mapping[str, bool],
) -> dict[str, Any]:
    event_rows = list(events)
    accounting_rows = list(accounting)
    event_by_joint: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    event_counts: dict[str, int] = {}
    for event in event_rows:
        event_id = str(int(event.get("event_id") or 0))
        event_counts[event_id] = event_counts.get(event_id, 0) + 1
        key = _join_key(event)
        if all(key):
            event_by_joint.setdefault(key, []).append(event)
    one_to_one = ambiguous = unmatched = exact_sid = 0
    lifecycle = {"start": 0, "interim_update": 0, "stop": 0}
    deltas = {"event_timestamp": {}, "record_local_time": {}}
    for record in accounting_rows:
        state = str(record.get("lifecycle") or "")
        if state in lifecycle:
            lifecycle[state] += 1
        matches = event_by_joint.get(_join_key(record), [])
        if len(matches) == 1:
            one_to_one += 1
            match = matches[0]
            exact_sid += int(
                SID.fullmatch(str(match.get("subject_sid") or ""))
                is not None
            )
            event_time = match.get("event_time_utc")
            for basis, field in (
                ("event_timestamp", "event_time_utc"),
                ("record_local_time", "record_time_utc"),
            ):
                accounting_time = record.get(field)
                if isinstance(event_time, datetime) and isinstance(
                    accounting_time, datetime
                ):
                    bucket = _delta_bucket(
                        (accounting_time - event_time).total_seconds()
                    )
                    bucket_counts = deltas[basis]
                    bucket_counts[bucket] = (
                        bucket_counts.get(bucket, 0) + 1
                    )
        elif len(matches) > 1:
            ambiguous += 1
        else:
            unmatched += 1
    # Accounting limits define the bounded sample and do not invalidate a
    # conclusion about that sample.  Only an NPS cap can hide a matching event
    # inside the already selected UTC interval.
    capped = bool(caps.get("nps_event_cap_reached"))
    correlation = (
        "proven_on_time_aligned_bounded_sample"
        if accounting_rows
        and one_to_one == len(accounting_rows)
        and ambiguous == 0
        and unmatched == 0
        and not capped
        else "correlation_not_proven"
    )
    preferred_near = sum(
        count
        for name, count in deltas["event_timestamp"].items()
        if name != "absolute_gt_15_minutes"
    )
    fallback_near = sum(
        count
        for name, count in deltas["record_local_time"].items()
        if name != "absolute_gt_15_minutes"
    )
    timestamp = (
        "event_timestamp_proven"
        if one_to_one > 0 and preferred_near == one_to_one
        else (
            "record_local_time_plus_timezone_proven"
            if one_to_one > 0 and fallback_near == one_to_one
            else "timestamp_not_proven"
        )
    )
    return {
        "accounting_sample_counts": {
            **dict(accounting_counts),
            "lifecycle": lifecycle,
        },
        "alignment_window_quality": {
            "basis": (
                "accounting_record_date_time_plus_explicit_source_utc_offset"
            ),
            "span_seconds": int(alignment_span_seconds),
        },
        "nps_event_counts_by_id": event_counts,
        "cap_and_truncation_flags": dict(caps),
        "join_quality_counts": {
            "accounting_lifecycle_records": len(accounting_rows),
            "one_to_one_records": one_to_one,
            "ambiguous_records": ambiguous,
            "unmatched_records": unmatched,
        },
        "exact_principal_bridge_counts": {
            "exact_subject_sid_records": exact_sid,
            "missing_or_invalid_subject_sid_records": (
                one_to_one - exact_sid
            ),
        },
        "joined_time_delta_bucket_counts": deltas,
        "classification": {
            "correlation": correlation,
            "timestamp": timestamp,
        },
    }


def _read_accounting(
    target: str,
    limits: Mapping[str, Any],
    *,
    utc_offset_minutes: int,
) -> tuple[
    list[dict[str, Any]],
    dict[str, int],
    dict[str, bool],
]:
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
    if not candidates:
        raise RadiusTimeAlignedPlanError("accounting_file_not_observed")
    _modified, size, selected_path = max(
        candidates, key=lambda item: item[0]
    )
    lines, sampled_bytes, truncated = _tail_lines(
        selected_path,
        file_size=size,
        max_bytes=int(limits["accounting_bytes"]),
        max_records=int(limits["accounting_records"]),
    )
    records, counts = parse_accounting_sample(
        lines,
        utc_offset_minutes=utc_offset_minutes,
    )
    caps = {
        "accounting_candidate_cap_reached": candidate_truncated,
        "accounting_record_cap_reached": (
            len(lines) == int(limits["accounting_records"])
        ),
        "accounting_byte_cap_reached": (
            sampled_bytes == int(limits["accounting_bytes"])
        ),
        "selected_file_was_sampled_not_fully_read": truncated,
    }
    return records, counts, caps


def _query_events(
    target: str,
    *,
    start_utc: datetime,
    end_utc: datetime,
    max_events: int,
) -> tuple[list[dict[str, Any]], bool]:
    from scripts.collect import collect_windows_events as collector

    session = query = None
    handles: list[Any] = []
    try:
        session = collector.open_remote_session(target)
        flags = (
            collector.win32evtlog.EvtQueryChannelPath
            | collector.win32evtlog.EvtQueryReverseDirection
        )
        query = collector.win32evtlog.EvtQuery(
            "Security",
            flags,
            build_time_aligned_xpath(start_utc, end_utc),
            session,
        )
        while len(handles) < max_events:
            batch = collector.next_event_batch(
                query,
                min(32, max_events - len(handles)),
                10_000,
            )
            if not batch:
                break
            handles.extend(batch)
        records = _event_records(
            collector.render_event_xml(handle) for handle in handles
        )
        return records, len(handles) == max_events
    finally:
        for handle in handles:
            close = getattr(handle, "Close", None)
            if callable(close):
                close()
        for handle in (query, session):
            close = getattr(handle, "Close", None)
            if callable(close):
                close()


def _reject_sensitive_evidence(value: Any) -> None:
    forbidden_keys = {
        "event_xml",
        "event_payload",
        "raw_line",
        "event_timestamp_value",
        "accounting_timestamp_value",
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
                raise RadiusTimeAlignedPlanError(
                    "sensitive_evidence_key_present"
                )
            _reject_sensitive_evidence(item)
    elif isinstance(value, list):
        for item in value:
            _reject_sensitive_evidence(item)
    elif isinstance(value, str):
        if SID.fullmatch(value) or IPV4.fullmatch(value):
            raise RadiusTimeAlignedPlanError(
                "sensitive_evidence_value_present"
            )


def run_internal() -> dict[str, Any]:
    validated = validate_plan(load_plan())
    account = current_windows_account()
    if account.casefold() != validated["expected_account"].casefold():
        raise PermissionError("current_windows_account_is_not_approved_owner")
    target = str(validated["target"]["connect_address"])
    limits = validated["limits"]
    timezone_metadata = _read_timezone_metadata(target)
    if timezone_metadata.get("status") != "observed":
        raise RadiusTimeAlignedPlanError("source_timezone_not_observed")
    offset = int(timezone_metadata["utc_offset_minutes"])
    if not -840 <= offset <= 840:
        raise RadiusTimeAlignedPlanError("source_timezone_offset_invalid")
    accounting, counts, caps = _read_accounting(
        target,
        limits,
        utc_offset_minutes=offset,
    )
    aligned_times = [
        row["record_time_utc"]
        for row in accounting
        if isinstance(row.get("record_time_utc"), datetime)
    ]
    if not aligned_times or len(aligned_times) != len(accounting):
        raise RadiusTimeAlignedPlanError(
            "accounting_alignment_time_incomplete"
        )
    minimum = min(aligned_times)
    maximum = max(aligned_times)
    span_seconds = int((maximum - minimum).total_seconds())
    if span_seconds > int(limits["maximum_alignment_span_seconds"]):
        raise RadiusTimeAlignedPlanError(
            "accounting_alignment_span_too_wide"
        )
    padding = timedelta(seconds=int(limits["alignment_padding_seconds"]))
    events, event_capped = _query_events(
        target,
        start_utc=minimum - padding,
        end_utc=maximum + padding,
        max_events=int(limits["nps_events"]),
    )
    caps["nps_event_cap_reached"] = event_capped
    observations = aggregate_observations(
        events,
        accounting,
        accounting_counts=counts,
        alignment_span_seconds=span_seconds,
        caps=caps,
    )
    observations["alignment_window_quality"].update(
        {
            "timezone_status": "observed",
            "utc_offset_minutes": offset,
            "padding_seconds": int(
                limits["alignment_padding_seconds"]
            ),
        }
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
        raise RadiusTimeAlignedPlanError(
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
            "RADIUS time-aligned audit exceeded timeout"
        ) from exc
    if process.returncode != 0:
        error_type = "InternalAuditError"
        try:
            failure = json.loads(stdout.lstrip("\ufeff").strip())
            candidate = str(failure.get("error_type") or "")
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", candidate):
                error_type = candidate
        except (json.JSONDecodeError, AttributeError):
            pass
        raise RadiusTimeAlignedPlanError(
            f"internal_audit_failed:{error_type}"
        )
    try:
        internal = json.loads(stdout.lstrip("\ufeff").strip())
    except json.JSONDecodeError as exc:
        raise RadiusTimeAlignedPlanError(
            "internal_json_invalid"
        ) from exc
    _reject_sensitive_evidence(internal)
    return {
        "schema_version": 1,
        "evidence_id": "stage9-radius-time-aligned-preflight",
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
        "next_gate": "owner_review_before_runtime_adapter_design",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation", default="")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--internal", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.internal:
        try:
            print(json.dumps(run_internal(), ensure_ascii=False))
            return 0
        except Exception as exc:
            print(json.dumps({"error_type": type(exc).__name__}))
            return 1
    if args.validate_only == args.execute:
        raise RadiusTimeAlignedPlanError("choose_exactly_one_mode")
    plan = load_plan()
    if args.validate_only:
        result = validate_plan(plan)
        result.pop("target", None)
        result.pop("expected_account", None)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    output = args.output.resolve()
    if (ROOT / "artifacts").resolve() not in output.parents:
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

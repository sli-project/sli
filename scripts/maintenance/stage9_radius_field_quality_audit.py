#!/usr/bin/env python3
"""Run the owner-authorized payload-free RADIUS field-quality audit."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import fnmatch
import io
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
from server.source_packs.radius.accounting import (  # noqa: E402
    DATABASE_COMPATIBLE_COLUMNS,
    is_database_compatible_row,
)


PLAN_PATH = ROOT / "config" / "stage9_radius_field_quality_audit.json"
TARGETS_PATH = ROOT / "config" / "stage9_radius_targets.json"
DEFAULT_OUTPUT = (
    ROOT
    / "artifacts"
    / "stage9"
    / "evidence"
    / "radius-field-quality-audit.json"
)
CONFIRMATION = "START-STAGE9-RADIUS-FIELD-QUALITY-AUDIT"
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SAFE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
SID_SHAPE = re.compile(r"^S-\d(?:-\d+)+$", re.IGNORECASE)
UUID_SHAPE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
IPV4_SHAPE = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
)
INTEGER_SHAPE = re.compile(r"^-?\d+$")
HEX_SHAPE = re.compile(r"^(?:0x)?[0-9a-f]+$", re.IGNORECASE)
ACCOUNTING_HEAD_BYTES = 65_536
ACCOUNTING_HEAD_RECORDS = 50


class RadiusFieldQualityError(RuntimeError):
    pass


def safe_error_code(error: BaseException) -> str:
    candidate = str(error)
    if re.fullmatch(r"[A-Za-z0-9_:=.-]{1,200}", candidate):
        return candidate
    return type(error).__name__


def load_plan(path: Path = PLAN_PATH) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RadiusFieldQualityError("plan_object_required")
    return value


def validate_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    if plan.get("schema_version") != 1:
        raise RadiusFieldQualityError("unsupported_plan_schema")
    if plan.get("plan_id") != "stage9-radius-field-quality-audit-v1":
        raise RadiusFieldQualityError("unexpected_plan_id")
    if plan.get("status") != "owner_authorized":
        raise RadiusFieldQualityError("owner_authorization_required")
    limits = dict(plan.get("limits") or {})
    expected_limits = {
        "target_count": 1,
        "window_hours": 168,
        "event_ids": [6272, 6273],
        "events_total": 100,
        "accounting_files": 1,
        "accounting_candidates": 20,
        "accounting_records": 200,
        "accounting_bytes": 262_144,
        "overall_timeout_seconds": 60,
    }
    if limits != expected_limits:
        raise RadiusFieldQualityError("approved_limits_changed")
    required_prohibitions = {
        "event_value_persistence",
        "event_xml_persistence",
        "accounting_raw_line_persistence",
        "accounting_value_persistence",
        "accounting_file_name_or_path_persistence",
        "radius_client_or_secret_read",
        "nps_full_configuration_export",
        "nps_configuration_change",
        "radius_accounting_enable",
        "postgresql_write",
        "clickhouse_write",
        "event_import",
        "cursor_update",
        "descriptor_addition",
        "normalizer_addition",
        "migration",
        "worker_activation",
        "autostart",
    }
    if not required_prohibitions.issubset(
        set(plan.get("prohibited_actions") or [])
    ):
        raise RadiusFieldQualityError("required_prohibition_missing")
    target_path = (ROOT / str(plan.get("targets_source") or "")).resolve()
    if target_path != TARGETS_PATH.resolve():
        raise RadiusFieldQualityError("unexpected_targets_source")
    target_inventory = json.loads(target_path.read_text(encoding="utf-8"))
    expected_targets = [
        {
            "source_name": "radius01.example.invalid",
            "connect_address": "radius01.example.invalid",
            "owner_confirmed_ip": "192.0.2.15",
        }
    ]
    if target_inventory.get("targets") != expected_targets:
        raise RadiusFieldQualityError("approved_target_changed")
    expected_account = str(plan.get("expected_windows_account") or "").strip()
    if expected_account.casefold() != r"EXAMPLE\operator".casefold():
        raise RadiusFieldQualityError("unexpected_windows_account")
    return {
        "limits": limits,
        "target": dict(expected_targets[0]),
        "expected_account": expected_account,
    }


def value_shape(value: str) -> str:
    text = value.strip()
    if not text:
        return "empty"
    if SID_SHAPE.fullmatch(text):
        return "sid"
    if UUID_SHAPE.fullmatch(text):
        return "uuid"
    if IPV4_SHAPE.fullmatch(text):
        return "ipv4"
    if INTEGER_SHAPE.fullmatch(text):
        return "integer"
    if HEX_SHAPE.fullmatch(text) and any(character.isdigit() for character in text):
        return "hex"
    return "text"


def summarize_event_xml(
    xml_items: Iterable[str],
) -> dict[str, Any]:
    groups: dict[int, int] = {}
    fields: dict[str, dict[str, Any]] = {}
    parse_errors = 0
    selected_count = 0
    for xml_text in xml_items:
        selected_count += 1
        try:
            root = ET.fromstring(xml_text)
            event_id_text = root.findtext(f".//{{{EVENT_NS}}}EventID")
            event_id = int(event_id_text or 0)
            groups[event_id] = groups.get(event_id, 0) + 1
            event_values: dict[str, str] = {}
            for node in root.findall(f".//{{{EVENT_NS}}}EventData/{{{EVENT_NS}}}Data"):
                name = str(node.attrib.get("Name") or "")
                if SAFE_NAME.fullmatch(name):
                    event_values.setdefault(name, str(node.text or ""))
            for name, value in event_values.items():
                summary = fields.setdefault(
                    name,
                    {
                        "present_count": 0,
                        "non_empty_count": 0,
                        "shape_counts": {},
                    },
                )
                summary["present_count"] += 1
                if value.strip():
                    summary["non_empty_count"] += 1
                shape = value_shape(value)
                shape_counts = summary["shape_counts"]
                shape_counts[shape] = int(shape_counts.get(shape, 0)) + 1
        except (ET.ParseError, TypeError, ValueError):
            parse_errors += 1
    return {
        "selected_count": selected_count,
        "groups": [
            {"event_id": key, "count": groups[key]}
            for key in sorted(groups)
        ],
        "xml_parse_errors": parse_errors,
        "fields": [
            {"name": name, **fields[name]}
            for name in sorted(fields)
        ],
    }


def _local_xml_name(tag: str) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _normalized_accounting_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _status_bucket(value: str) -> str:
    normalized = _normalized_accounting_name(value)
    if normalized in {"1", "start"}:
        return "start"
    if normalized in {"2", "stop"}:
        return "stop"
    if normalized in {"3", "interim", "interimupdate", "alive"}:
        return "interim_update"
    if not normalized:
        return "missing"
    return "other"


def summarize_accounting_lines(lines: Iterable[str]) -> dict[str, Any]:
    format_counts = {
        "xml_records": 0,
        "csv_records": 0,
        "database_compatible_csv_records": 0,
        "ias_attribute_pair_csv_records": 0,
        "unrecognized_records": 0,
    }
    schema_names: set[str] = set()
    radius_attribute_ids: set[int] = set()
    status_counts = {
        "start": 0,
        "interim_update": 0,
        "stop": 0,
        "other": 0,
        "missing": 0,
    }
    packet_type_counts: dict[str, int] = {}
    accounting_request_quality = {
        "records": 0,
        "with_status": 0,
        "with_session_identifier": 0,
        "with_status_and_session_identifier": 0,
    }
    field_count_histogram: dict[str, int] = {}
    session_present = 0
    session_non_empty = 0
    considered = 0
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        considered += 1
        status_value: str | None = None
        session_value: str | None = None
        if line.startswith("<"):
            try:
                root = ET.fromstring(line)
                format_counts["xml_records"] += 1
                for node in root.iter():
                    name = _local_xml_name(node.tag)
                    if SAFE_NAME.fullmatch(name):
                        schema_names.add(name)
                    normalized = _normalized_accounting_name(name)
                    value = str(node.attrib.get("data") or node.text or "")
                    if normalized == "acctstatustype":
                        status_value = value
                    elif normalized in {
                        "acctsessionid",
                        "accountsessionidentifier",
                    }:
                        session_value = value
            except ET.ParseError:
                format_counts["unrecognized_records"] += 1
        else:
            try:
                row = next(csv.reader([line]))
            except (csv.Error, StopIteration):
                format_counts["unrecognized_records"] += 1
                row = []
            if row:
                format_counts["csv_records"] += 1
                field_count = len(row)
                field_count_key = str(field_count)
                field_count_histogram[field_count_key] = (
                    field_count_histogram.get(field_count_key, 0) + 1
                )
                packet_type = row[4].strip() if field_count > 4 else ""
                database_compatible = is_database_compatible_row(row)
                if database_compatible:
                    format_counts["database_compatible_csv_records"] += 1
                    schema_names.update(
                        DATABASE_COMPATIBLE_COLUMNS[
                            : min(field_count, len(DATABASE_COMPATIBLE_COLUMNS))
                        ]
                    )
                    packet_type_counts[packet_type] = (
                        packet_type_counts.get(packet_type, 0) + 1
                    )
                    status_value = row[31]
                    session_value = row[35]
                    if packet_type == "4":
                        has_status = bool(status_value.strip())
                        has_session = bool(session_value.strip())
                        accounting_request_quality["records"] += 1
                        if has_status:
                            accounting_request_quality["with_status"] += 1
                        if has_session:
                            accounting_request_quality[
                                "with_session_identifier"
                            ] += 1
                        if has_status and has_session:
                            accounting_request_quality[
                                "with_status_and_session_identifier"
                            ] += 1
                else:
                    format_counts["ias_attribute_pair_csv_records"] += 1
                    for index in range(6, len(row) - 1, 2):
                        key = row[index].strip()
                        value = row[index + 1]
                        if key.isdigit() and 0 <= int(key) <= 255:
                            attribute_id = int(key)
                            radius_attribute_ids.add(attribute_id)
                            if attribute_id == 40:
                                status_value = value
                            elif attribute_id == 44:
                                session_value = value
                        else:
                            normalized = _normalized_accounting_name(key)
                            if normalized == "acctstatustype":
                                schema_names.add("Acct-Status-Type")
                                status_value = value
                            elif normalized in {
                                "acctsessionid",
                                "accountsessionidentifier",
                            }:
                                schema_names.add("Acct-Session-Id")
                                session_value = value
        status_counts[_status_bucket(status_value or "")] += 1
        if session_value is not None:
            session_present += 1
            if session_value.strip():
                session_non_empty += 1
    return {
        "records_considered": considered,
        "format_counts": format_counts,
        "schema_names": sorted(schema_names),
        "radius_attribute_ids": sorted(radius_attribute_ids),
        "field_count_histogram": field_count_histogram,
        "packet_type_counts": packet_type_counts,
        "accounting_request_quality": accounting_request_quality,
        "acct_status_type_counts": status_counts,
        "session_identifier_quality": {
            "present_count": session_present,
            "non_empty_count": session_non_empty,
        },
    }


def select_bounded_lines(
    head_text: str,
    tail_text: str,
    *,
    same_segment: bool,
    max_records: int,
) -> list[str]:
    if same_segment:
        return head_text.splitlines()[:max_records]
    head_lines = head_text.splitlines()
    tail_lines = tail_text.splitlines()
    if head_text and not head_text.endswith(("\n", "\r")):
        head_lines = head_lines[:-1]
    if tail_lines:
        tail_lines = tail_lines[1:]
    head_selected = head_lines[: min(ACCOUNTING_HEAD_RECORDS, max_records)]
    remaining = max(0, max_records - len(head_selected))
    tail_selected = tail_lines[-remaining:] if remaining else []
    return head_selected + tail_selected


def audit_events(target: str, *, window_hours: int, max_events: int) -> dict[str, Any]:
    session = None
    query = None
    handles: list[Any] = []
    try:
        from scripts.collect import collect_windows_events as collector

        session = collector.open_remote_session(target)
        milliseconds = int(window_hours) * 60 * 60 * 1000
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
        while len(handles) < max_events:
            batch = collector.next_event_batch(
                query, min(32, max_events - len(handles)), 10_000
            )
            if batch is None or not batch:
                break
            handles.extend(batch)
        summary = summarize_event_xml(
            collector.render_event_xml(handle) for handle in handles
        )
        return {
            "status": "observed" if summary["selected_count"] else "not_observed",
            "cap_reached": summary["selected_count"] == max_events,
            **summary,
        }
    except Exception as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror is None and exc.args and isinstance(exc.args[0], int):
            winerror = int(exc.args[0])
        return {
            "status": "inaccessible",
            "error_type": type(exc).__name__,
            "winerror": winerror,
            "selected_count": 0,
            "cap_reached": False,
            "groups": [],
            "xml_parse_errors": 0,
            "fields": [],
        }
    finally:
        for handle in handles:
            close = getattr(handle, "Close", None)
            if callable(close):
                close()
        for handle in (query, session):
            close = getattr(handle, "Close", None)
            if callable(close):
                close()


def _read_accounting_segments(
    path: str, *, file_size: int, max_bytes: int
) -> tuple[bytes, bytes, bool]:
    with open(path, "rb") as stream:
        if file_size <= max_bytes:
            return stream.read(max_bytes), b"", True
        head_size = min(ACCOUNTING_HEAD_BYTES, max_bytes)
        tail_size = max_bytes - head_size
        head = stream.read(head_size)
        stream.seek(max(0, file_size - tail_size))
        tail = stream.read(tail_size)
        return head, tail, False


def audit_accounting(
    target: str,
    *,
    max_candidates: int,
    max_records: int,
    max_bytes: int,
) -> dict[str, Any]:
    directory = rf"\\{target}\c$\Windows\System32\LogFiles"
    candidates: list[tuple[float, int, str]] = []
    candidate_truncated = False
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if not fnmatch.fnmatch(entry.name.casefold(), "in*.log"):
                    continue
                if len(candidates) >= max_candidates:
                    candidate_truncated = True
                    break
                stat = entry.stat(follow_symlinks=False)
                candidates.append(
                    (float(stat.st_mtime), int(stat.st_size), entry.path)
                )
        if not candidates:
            return {
                "status": "not_observed",
                "selected_files": 0,
                "candidate_count_observed": 0,
                "candidate_truncated": candidate_truncated,
                "selected_file_size": None,
                "selected_file_write_utc": None,
                "sampled_bytes": 0,
                **summarize_accounting_lines([]),
            }
        modified, size, selected_path = max(candidates, key=lambda item: item[0])
        head, tail, same_segment = _read_accounting_segments(
            selected_path,
            file_size=size,
            max_bytes=max_bytes,
        )
        head_text = head.decode("utf-8-sig", errors="replace")
        tail_text = tail.decode("utf-8-sig", errors="replace")
        lines = select_bounded_lines(
            head_text,
            tail_text,
            same_segment=same_segment,
            max_records=max_records,
        )
        summary = summarize_accounting_lines(lines)
        return {
            "status": "observed",
            "selected_files": 1,
            "candidate_count_observed": len(candidates),
            "candidate_truncated": candidate_truncated,
            "selected_file_size": size,
            "selected_file_write_utc": datetime.fromtimestamp(
                modified, tz=timezone.utc
            ).isoformat(),
            "sampled_bytes": len(head) + len(tail),
            "decode_replacement_count": (
                head_text.count("\ufffd") + tail_text.count("\ufffd")
            ),
            **summary,
        }
    except Exception as exc:
        winerror = getattr(exc, "winerror", None)
        return {
            "status": "inaccessible",
            "selected_files": 0,
            "error_type": type(exc).__name__,
            "winerror": winerror,
            "candidate_count_observed": 0,
            "candidate_truncated": False,
            "selected_file_size": None,
            "selected_file_write_utc": None,
            "sampled_bytes": 0,
            **summarize_accounting_lines([]),
        }


def validate_internal_result(
    result: Mapping[str, Any], *, limits: Mapping[str, Any]
) -> dict[str, Any]:
    if result.get("schema_version") != 1 or result.get("read_only") is not True:
        raise RadiusFieldQualityError("internal_contract_invalid")
    if result.get("contains_event_values") is not False:
        raise RadiusFieldQualityError("event_values_must_not_persist")
    if result.get("contains_accounting_values") is not False:
        raise RadiusFieldQualityError("accounting_values_must_not_persist")
    events = dict(result.get("events") or {})
    accounting = dict(result.get("accounting") or {})
    if int(events.get("selected_count") or 0) > int(limits["events_total"]):
        raise RadiusFieldQualityError("event_limit_exceeded")
    if any(
        int(item.get("event_id") or 0) not in set(limits["event_ids"])
        for item in events.get("groups") or []
    ):
        raise RadiusFieldQualityError("unexpected_event_id")
    if int(accounting.get("selected_files") or 0) > int(
        limits["accounting_files"]
    ):
        raise RadiusFieldQualityError("accounting_file_limit_exceeded")
    if int(accounting.get("candidate_count_observed") or 0) > int(
        limits["accounting_candidates"]
    ):
        raise RadiusFieldQualityError("accounting_candidate_limit_exceeded")
    if int(accounting.get("records_considered") or 0) > int(
        limits["accounting_records"]
    ):
        raise RadiusFieldQualityError("accounting_record_limit_exceeded")
    if int(accounting.get("sampled_bytes") or 0) > int(
        limits["accounting_bytes"]
    ):
        raise RadiusFieldQualityError("accounting_byte_limit_exceeded")
    _reject_sensitive_keys(result)
    return {"events": events, "accounting": accounting}


def _reject_sensitive_keys(value: Any) -> None:
    forbidden = {
        "raw",
        "raw_line",
        "xml",
        "event_xml",
        "value",
        "values",
        "file_name",
        "file_path",
        "selected_path",
        "user_name",
        "client_ip_address",
        "calling_station_id",
        "session_id",
    }
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).casefold() in forbidden:
                raise RadiusFieldQualityError("sensitive_field_present")
            _reject_sensitive_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_sensitive_keys(item)


def run_internal() -> dict[str, Any]:
    validated = validate_plan(load_plan())
    account = current_windows_account()
    if account.casefold() != validated["expected_account"].casefold():
        raise PermissionError("current_windows_account_is_not_approved_owner")
    limits = validated["limits"]
    target = str(validated["target"]["connect_address"])
    result = {
        "schema_version": 1,
        "probe": "stage9-radius-field-quality-audit",
        "read_only": True,
        "contains_event_values": False,
        "contains_accounting_values": False,
        "target": str(validated["target"]["source_name"]),
        "events": audit_events(
            target,
            window_hours=int(limits["window_hours"]),
            max_events=int(limits["events_total"]),
        ),
        "accounting": audit_accounting(
            target,
            max_candidates=int(limits["accounting_candidates"]),
            max_records=int(limits["accounting_records"]),
            max_bytes=int(limits["accounting_bytes"]),
        ),
    }
    validate_internal_result(result, limits=limits)
    return result


def run_live(plan: Mapping[str, Any], confirmation: str) -> dict[str, Any]:
    validated = validate_plan(plan)
    if confirmation != CONFIRMATION:
        raise PermissionError(f"execute requires --confirmation {CONFIRMATION}")
    if os.name != "nt":
        raise RadiusFieldQualityError("live_audit_requires_windows_host")
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
        raise TimeoutError("radius field-quality audit exceeded timeout") from exc
    if process.returncode != 0:
        internal_error_type = "InternalAuditError"
        internal_error_code = internal_error_type
        try:
            failure = json.loads(stdout.lstrip("\ufeff").strip())
            candidate = str(failure.get("error_type") or "")
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", candidate):
                internal_error_type = candidate
            candidate_code = str(failure.get("error_code") or "")
            if re.fullmatch(r"[A-Za-z0-9_:=.-]{1,200}", candidate_code):
                internal_error_code = candidate_code
        except (json.JSONDecodeError, AttributeError):
            pass
        raise RadiusFieldQualityError(
            f"internal_audit_failed:{internal_error_type}:{internal_error_code}"
        )
    try:
        internal = json.loads(stdout.lstrip("\ufeff").strip())
    except json.JSONDecodeError as exc:
        raise RadiusFieldQualityError("internal_json_invalid") from exc
    validated_internal = validate_internal_result(
        internal, limits=validated["limits"]
    )
    completed = all(
        item.get("status") in {"observed", "not_observed"}
        for item in validated_internal.values()
    )
    return {
        "schema_version": 1,
        "evidence_id": "stage9-radius-field-quality-audit",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "completed" if completed else "partial",
        "owner_authorized": True,
        "read_only": True,
        "source_contact": True,
        "windows_changed": False,
        "postgresql_mutated": False,
        "clickhouse_mutated": False,
        "event_imported": False,
        "cursor_updated": False,
        "descriptor_added": False,
        "normalizer_added": False,
        "migration_applied": False,
        "worker_activated": False,
        "contains_event_values": False,
        "contains_accounting_values": False,
        "windows_account": account,
        "limits": dict(validated["limits"]),
        "live": internal,
        "next_gate": (
            "review_field_quality_before_descriptor_normalizer_or_"
            "accounting_adapter"
        ),
    }


def build_failure_evidence(
    *,
    plan: Mapping[str, Any],
    windows_account: str,
    error: BaseException,
) -> dict[str, Any]:
    validated = validate_plan(plan)
    code = safe_error_code(error)
    return {
        "schema_version": 1,
        "evidence_id": "stage9-radius-field-quality-audit",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "failed",
        "owner_authorized": True,
        "read_only": True,
        "source_contact": True,
        "windows_changed": False,
        "postgresql_mutated": False,
        "clickhouse_mutated": False,
        "event_imported": False,
        "cursor_updated": False,
        "descriptor_added": False,
        "normalizer_added": False,
        "migration_applied": False,
        "worker_activated": False,
        "contains_event_values": False,
        "contains_accounting_values": False,
        "windows_account": windows_account,
        "limits": dict(validated["limits"]),
        "failure": {
            "error_type": type(error).__name__,
            "error_code": code,
            "stderr_persisted": False,
        },
        "next_gate": "fix_or_classify_audit_failure_before_source_design",
    }


def write_evidence(output: Path, evidence: Mapping[str, Any]) -> None:
    resolved = output.resolve()
    if (ROOT / "artifacts").resolve() not in resolved.parents:
        raise ValueError("evidence output must stay under artifacts")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "status": "failed",
                        "error_type": type(exc).__name__,
                        "error_code": safe_error_code(exc),
                    },
                    ensure_ascii=False,
                )
            )
            return 2
    plan = load_plan()
    validated = validate_plan(plan)
    if not args.execute:
        print(
            json.dumps(
                {
                    "status": "validated_only",
                    "source_contact": False,
                    "plan_id": plan["plan_id"],
                    "limits": validated["limits"],
                    "confirmation_required": CONFIRMATION,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    try:
        evidence = run_live(plan, args.confirmation)
    except (RadiusFieldQualityError, TimeoutError) as exc:
        evidence = build_failure_evidence(
            plan=plan,
            windows_account=current_windows_account(),
            error=exc,
        )
        write_evidence(args.output, evidence)
        print(
            json.dumps(
                {"status": "failed", "output": str(args.output.resolve())},
                ensure_ascii=False,
            )
        )
        return 2
    write_evidence(args.output, evidence)
    print(
        json.dumps(
            {"status": evidence["status"], "output": str(args.output.resolve())},
            ensure_ascii=False,
        )
    )
    return 0 if evidence["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())

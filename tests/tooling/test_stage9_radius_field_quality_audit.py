from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from scripts.maintenance.stage9_radius_field_quality_audit import (
    PLAN_PATH,
    RadiusFieldQualityError,
    build_failure_evidence,
    load_plan,
    select_bounded_lines,
    summarize_accounting_lines,
    summarize_event_xml,
    safe_error_code,
    validate_internal_result,
    validate_plan,
)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT / "scripts" / "maintenance" / "stage9_radius_field_quality_audit.py"
)
RUNNER = (
    ROOT
    / "archive"
    / "runner_one_shot_20260730"
    / "34-radius-field-quality-audit.cmd"
)


def _event_xml(event_id: int, fields: dict[str, str]) -> str:
    data = "".join(
        f'<Data Name="{name}">{value}</Data>' for name, value in fields.items()
    )
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f"<System><EventID>{event_id}</EventID></System>"
        f"<EventData>{data}</EventData></Event>"
    )


def _internal_result() -> dict:
    return {
        "schema_version": 1,
        "probe": "stage9-radius-field-quality-audit",
        "read_only": True,
        "contains_event_values": False,
        "contains_accounting_values": False,
        "target": "radius01.example.invalid",
        "events": {
            "status": "observed",
            "selected_count": 2,
            "cap_reached": False,
            "groups": [{"event_id": 6272, "count": 2}],
            "xml_parse_errors": 0,
            "fields": [],
        },
        "accounting": {
            "status": "observed",
            "selected_files": 1,
            "candidate_count_observed": 2,
            "sampled_bytes": 100,
            "records_considered": 2,
        },
    }


def test_owner_authorized_plan_is_exact_and_bounded(legacy_radius_target_inventory):
    plan = load_plan(PLAN_PATH)
    validated = validate_plan(plan)
    assert validated["limits"] == {
        "target_count": 1,
        "window_hours": 168,
        "event_ids": [6272, 6273],
        "events_total": 100,
        "accounting_files": 1,
        "accounting_candidates": 20,
        "accounting_records": 200,
        "accounting_bytes": 262144,
        "overall_timeout_seconds": 60,
    }
    assert validated["target"]["connect_address"] == "radius01.example.invalid"
    assert "accounting_value_persistence" in plan["prohibited_actions"]
    assert "nps_full_configuration_export" in plan["prohibited_actions"]


def test_changed_limit_fails_closed():
    plan = load_plan()
    broken = deepcopy(plan)
    broken["limits"]["accounting_bytes"] += 1
    with pytest.raises(RadiusFieldQualityError, match="approved_limits_changed"):
        validate_plan(broken)


def test_event_summary_persists_only_counts_and_shapes():
    result = summarize_event_xml(
        [
            _event_xml(
                6272,
                {
                    "AccountSessionIdentifier": "secret-session-value",
                    "SubjectUserSid": "S-1-5-21-123",
                    "ClientIPAddress": "192.0.2.1",
                },
            ),
            _event_xml(
                6273,
                {
                    "AccountSessionIdentifier": "",
                    "SubjectUserSid": "S-1-5-21-456",
                },
            ),
        ]
    )
    encoded = json.dumps(result)
    assert "secret-session-value" not in encoded
    assert "192.0.2.1" not in encoded
    assert "S-1-5-21-123" not in encoded
    assert result["selected_count"] == 2
    fields = {item["name"]: item for item in result["fields"]}
    session = fields["AccountSessionIdentifier"]
    assert session["present_count"] == 2
    assert session["non_empty_count"] == 1
    assert session["shape_counts"] == {"text": 1, "empty": 1}
    assert fields["SubjectUserSid"]["shape_counts"] == {"sid": 2}
    assert fields["ClientIPAddress"]["shape_counts"] == {"ipv4": 1}


def test_accounting_xml_summary_drops_values():
    lines = [
        (
            "<Event><Acct-Status-Type data=\"Start\"/>"
            "<Acct-Session-Id data=\"session-secret\"/>"
            "<User-Name data=\"alice\"/></Event>"
        ),
        (
            "<Event><Acct-Status-Type data=\"Interim-Update\"/>"
            "<Acct-Session-Id data=\"session-secret-2\"/></Event>"
        ),
    ]
    result = summarize_accounting_lines(lines)
    encoded = json.dumps(result)
    assert "session-secret" not in encoded
    assert "alice" not in encoded
    assert result["format_counts"]["xml_records"] == 2
    assert result["acct_status_type_counts"]["start"] == 1
    assert result["acct_status_type_counts"]["interim_update"] == 1
    assert result["session_identifier_quality"] == {
        "present_count": 2,
        "non_empty_count": 2,
    }
    assert "Acct-Status-Type" in result["schema_names"]


def test_accounting_ias_csv_uses_only_attribute_ids_and_aggregates():
    lines = [
        'nas,user,date,time,IAS,server,40,1,44,"session-one",1,"alice"',
        'nas,user,date,time,IAS,server,40,2,44,"session-two",1,"alice"',
    ]
    result = summarize_accounting_lines(lines)
    encoded = json.dumps(result)
    assert "session-one" not in encoded
    assert "alice" not in encoded
    assert result["radius_attribute_ids"] == [1, 40, 44]
    assert result["acct_status_type_counts"]["start"] == 1
    assert result["acct_status_type_counts"]["stop"] == 1
    assert result["session_identifier_quality"]["non_empty_count"] == 2


def test_database_compatible_csv_uses_fixed_microsoft_columns():
    row = [""] * 66
    row[0] = "secret-host"
    row[1] = "IAS"
    row[4] = "4"
    row[5] = "secret-user"
    row[31] = "1"
    row[35] = "secret-session"
    second = list(row)
    second[31] = "2"
    result = summarize_accounting_lines(
        [",".join(row), ",".join(second)]
    )
    encoded = json.dumps(result)
    assert "secret-host" not in encoded
    assert "secret-user" not in encoded
    assert "secret-session" not in encoded
    assert result["format_counts"]["database_compatible_csv_records"] == 2
    assert result["field_count_histogram"] == {"66": 2}
    assert result["packet_type_counts"] == {"4": 2}
    assert result["accounting_request_quality"] == {
        "records": 2,
        "with_status": 2,
        "with_session_identifier": 2,
        "with_status_and_session_identifier": 2,
    }
    assert result["acct_status_type_counts"]["start"] == 1
    assert result["acct_status_type_counts"]["stop"] == 1
    assert result["session_identifier_quality"]["non_empty_count"] == 2
    assert "Acct-Status-Type" in result["schema_names"]
    assert "Acct-Session-Id" in result["schema_names"]


def test_long_ias_attribute_pair_csv_is_not_misclassified_as_database_compatible():
    row = [
        "secret-nas",
        "secret-user",
        "07/30/2026",
        "08:00:00",
        "IAS",
        "secret-host",
    ]
    for attribute_id in range(1, 21):
        row.extend([str(attribute_id), f"secret-value-{attribute_id}"])
    result = summarize_accounting_lines([",".join(row)])
    encoded = json.dumps(result)
    assert "secret-" not in encoded
    assert result["format_counts"]["database_compatible_csv_records"] == 0
    assert result["format_counts"]["ias_attribute_pair_csv_records"] == 1
    assert result["accounting_request_quality"]["records"] == 0


def test_safe_format_aggregate_does_not_collide_with_raw_xml_guard(
    legacy_radius_target_inventory,
):
    result = _internal_result()
    result["accounting"]["format_counts"] = {
        "xml_records": 2,
        "csv_records": 0,
        "database_compatible_csv_records": 0,
        "ias_attribute_pair_csv_records": 0,
        "unrecognized_records": 0,
    }
    limits = validate_plan(load_plan())["limits"]
    validate_internal_result(result, limits=limits)


def test_head_tail_selection_is_record_bounded():
    head = "\n".join(f"head-{index}" for index in range(80)) + "partial"
    tail = "partial\n" + "\n".join(f"tail-{index}" for index in range(300))
    result = select_bounded_lines(
        head, tail, same_segment=False, max_records=200
    )
    assert len(result) == 200
    assert result[0] == "head-0"
    assert result[-1] == "tail-299"
    assert "partial" not in result


def test_internal_contract_enforces_caps_and_sensitive_keys(
    legacy_radius_target_inventory,
):
    limits = validate_plan(load_plan())["limits"]
    result = _internal_result()
    validate_internal_result(result, limits=limits)
    broken = deepcopy(result)
    broken["accounting"]["sampled_bytes"] = 262145
    with pytest.raises(RadiusFieldQualityError, match="byte_limit_exceeded"):
        validate_internal_result(broken, limits=limits)
    broken = deepcopy(result)
    broken["events"]["groups"] = [{"event_id": 4624, "count": 1}]
    with pytest.raises(RadiusFieldQualityError, match="unexpected_event_id"):
        validate_internal_result(broken, limits=limits)
    broken = deepcopy(result)
    broken["events"]["values"] = ["secret"]
    with pytest.raises(RadiusFieldQualityError, match="sensitive_field"):
        validate_internal_result(broken, limits=limits)


def test_failure_evidence_is_sanitized_and_preserves_safety_flags(
    legacy_radius_target_inventory,
):
    evidence = build_failure_evidence(
        plan=load_plan(),
        windows_account="EXAMPLE\\operator",
        error=RadiusFieldQualityError(
            "internal_audit_failed:PermissionError"
        ),
    )
    assert evidence["status"] == "failed"
    assert evidence["source_contact"] is True
    assert evidence["windows_changed"] is False
    assert evidence["contains_event_values"] is False
    assert evidence["failure"] == {
        "error_type": "RadiusFieldQualityError",
        "error_code": "internal_audit_failed:PermissionError",
        "stderr_persisted": False,
    }


def test_safe_error_code_keeps_only_fixed_machine_codes():
    assert (
        safe_error_code(RadiusFieldQualityError("unexpected_event_id"))
        == "unexpected_event_id"
    )
    assert (
        safe_error_code(ValueError(r"secret path C:\sensitive data"))
        == "ValueError"
    )


@pytest.mark.skipif(
    not RUNNER.is_file(),
    reason="ignored archive launcher 34-radius-field-quality-audit.cmd is absent",
)
def test_archived_runner_is_ascii_only_fail_closed_and_keeps_contract():
    source = RUNNER.read_bytes()
    assert all(value < 128 for value in source)
    text = source.decode("ascii").casefold().replace("\r\n", "\n")
    assert text.startswith(
        "@echo off\necho archived completed one-shot launcher. do not run."
    )
    assert text.index("exit /b 1") < text.index(
        "stage9_radius_field_quality_audit.py"
    )
    assert "stage9_radius_field_quality_audit.py" in text
    assert "start-stage9-radius-field-quality-audit" in text


def test_script_does_not_use_nps_export_or_remote_write_commands():
    text = SCRIPT.read_text(encoding="utf-8").casefold()
    for forbidden in (
        "netsh nps export",
        "import-npsconfiguration",
        "set-itemproperty",
        "new-itemproperty",
        "set-service",
        "start-service",
        "stop-service",
        "invoke-command",
    ):
        assert forbidden not in text

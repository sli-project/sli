from __future__ import annotations

import importlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.source_packs.windows_ad_dc import (
    TASK_SCHEDULER_CHANNEL,
    correlation_id_for_event,
    entity_semantics_for_event,
    retain_message_sample_for_event,
    state_semantics_for_event,
)
from scripts.maintenance.windows_task_correlation_audit import evaluate_task_correlation
from server.sli.storage.storage_v2_models import event_facts_from_v1
from server.sli.storage.storage_v2_repository import EVENT_FACTS_V2_WRITE_COLUMNS
from server.sli.semantic.semantic_processing import (
    ASSEMBLER_VERSION,
    NORMALIZER_BASE_VERSION,
    StoredEvent,
    normalize_windows_event,
)
from server.sli.semantic.severity import classify_contextual_event
from server.source_packs.registry import resolve_source_normalizer
from server.source_packs.windows_ad_dc import semantic_projection_for_event
from server.source_packs.windows_ad_dc import event_facts_for_event
from server.sli.semantic.semantic_investigation_backfill import SECURITY_HISTORY_EVENT_IDS


importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")

INSTANCE_ID = "{12345678-90AB-CDEF-1234-567890ABCDEF}"
CANONICAL_INSTANCE_ID = "12345678-90ab-cdef-1234-567890abcdef"


@pytest.mark.parametrize("event_id", SECURITY_HISTORY_EVENT_IDS)
def test_security_history_vocabulary_has_exact_provider_named_normalizer_mapping(
    event_id: int,
) -> None:
    """Every frozen retained ID resolves through its exact Windows provider, never unknown."""
    provider = (
        "Microsoft-Windows-Eventlog"
        if event_id == 1102
        else "Microsoft-Windows-Security-Auditing"
    )

    projection = semantic_projection_for_event(
        event_id=event_id,
        channel="Security",
        provider=provider,
        event_data={},
        correlation_id=None,
        source_host="dc-fixture",
    )

    assert projection["semantic_type"] != "event.unknown"


def test_service_install_7045_requires_exact_system_scm_provider() -> None:
    exact = semantic_projection_for_event(
        event_id=7045,
        channel="System",
        provider="Service Control Manager",
        event_data={"ServiceName": "fixture-service"},
        correlation_id=None,
        source_host="dc-fixture",
    )
    wrong_provider = semantic_projection_for_event(
        event_id=7045,
        channel="System",
        provider="Unrelated-Provider",
        event_data={"ServiceName": "fixture-service"},
        correlation_id=None,
        source_host="dc-fixture",
    )

    assert exact["semantic_type"] == "service.installed.fragment"
    assert wrong_provider["semantic_type"] == "event.unknown"


def test_service_install_7045_does_not_emit_process_attribution() -> None:
    projection = semantic_projection_for_event(
        event_id=7045,
        channel="System",
        provider="Service Control Manager",
        event_data={
            "ServiceName": "fixture-service",
            "ServiceFileName": "C:/fixture.exe",
            "ServiceAccount": "LocalSystem",
            "ServiceStartType": "2",
            "ClientProcessId": "0x44",
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "SubjectLogonId": "0x3e7",
        },
        correlation_id=None,
        source_host="dc-fixture",
    )

    assert projection["semantic_type"] == "service.installed.fragment"
    assert projection["facts"]["service_file"] == "C:/fixture.exe"
    assert projection["facts"]["service_account"] == "LocalSystem"
    assert projection["facts"]["service_start_type"] == "2"
    assert not {
        "native_process_id", "process_user_sid", "process_user_name",
        "process_user_domain", "process_logon_id",
    } & projection["facts"].keys()


def test_service_install_7045_warm_facts_preserve_catalog_fields() -> None:
    result = event_facts_for_event(
        row={
            "channel": "System",
            "event_id": 7045,
            "provider_name": "Service Control Manager",
        },
        event_data={
            "ServiceName": "fixture-service",
            "ServiceFileName": "C:/fixture.exe",
            "ServiceAccount": "LocalSystem",
            "ServiceStartType": "2",
            "ClientProcessId": "0x44",
            "SubjectUserSid": "S-1-5-18",
        },
    )

    assert result["service_name"] == "fixture-service"
    assert result["service_file"] == "C:/fixture.exe"
    assert result["service_account"] == "LocalSystem"
    assert result["service_start_type"] == "2"
    assert result["native_process_id"] is None
    assert result["process_user_sid"] is None


@pytest.mark.parametrize(
    ("event_id", "field"),
    ((100, "InstanceId"), (102, "InstanceId"), (200, "TaskInstanceId"), (201, "TaskInstanceId")),
)
def test_task_scheduler_correlation_id_uses_proven_provider_field(event_id: int, field: str) -> None:
    assert correlation_id_for_event(
        channel=TASK_SCHEDULER_CHANNEL,
        event_id=event_id,
        event_data={field: INSTANCE_ID},
    ) == CANONICAL_INSTANCE_ID


def test_task_scheduler_correlation_id_fails_closed_for_unowned_shapes() -> None:
    assert correlation_id_for_event(
        channel="Security",
        event_id=100,
        event_data={"InstanceId": INSTANCE_ID},
    ) is None
    assert correlation_id_for_event(
        channel=TASK_SCHEDULER_CHANNEL,
        event_id=106,
        event_data={"InstanceId": INSTANCE_ID},
    ) is None
    assert correlation_id_for_event(
        channel=TASK_SCHEDULER_CHANNEL,
        event_id=100,
        event_data={"InstanceId": "not-a-uuid"},
    ) is None
    assert correlation_id_for_event(
        channel=TASK_SCHEDULER_CHANNEL,
        event_id=200,
        event_data={"InstanceId": INSTANCE_ID},
    ) is None


def test_importer_persists_task_scheduler_correlation_id() -> None:
    xml = f"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <EventData>
        <Data Name="TaskName">\\SLI\\Example</Data>
        <Data Name="InstanceId">{INSTANCE_ID}</Data>
      </EventData>
    </Event>
    """
    event_data = importer.parse_event_data(xml)
    row = {
        "event_id": 100,
        "channel": TASK_SCHEDULER_CHANNEL,
        "record_id": 7,
        "time_created": "2026-07-28T00:00:00Z",
    }

    params = importer._event_params(
        raw_log_file_id=1,
        server_id=2,
        domain_id=3,
        site_id=4,
        log_source_id=5,
        row=row,
        event_data=event_data,
    )

    persisted = dict(zip(importer.EVENT_COLUMNS, params, strict=True))
    assert persisted["event_data_json"]
    assert persisted["correlation_id"] == CANONICAL_INSTANCE_ID


def test_importer_preserves_system_execution_process_id_for_powershell_bridge() -> None:
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Execution ProcessID="4096" /></System>
      <EventData><Data Name="CommandName">Get-ADUser</Data></EventData>
    </Event>
    """

    assert importer.parse_event_data(xml)["SystemExecutionProcessId"] == "4096"


def test_real_corpus_metrics_require_one_to_one_pair_cardinality() -> None:
    result = evaluate_task_correlation(
        [
            {"event_id": 100, "total": 293, "nonempty": 293, "distinct_ids": 293, "uuid_shaped": 293},
            {"event_id": 102, "total": 284, "nonempty": 284, "distinct_ids": 284, "uuid_shaped": 284},
            {"event_id": 200, "total": 297, "nonempty": 297, "distinct_ids": 293, "uuid_shaped": 297},
            {"event_id": 201, "total": 288, "nonempty": 288, "distinct_ids": 284, "uuid_shaped": 288},
        ],
        [
            {"opener": 100, "closer": 102, "shared_ids": 284},
            {"opener": 200, "closer": 201, "shared_ids": 284},
        ],
    )

    assert result["status"] == "ok"
    assert result["safe_pair_candidates"] == {
        "100_to_102_by_correlation_id": True,
        "200_to_201_by_correlation_id": False,
    }
    assert result["raw_identifiers_in_report"] is False


@pytest.mark.parametrize(
    ("channel", "event_id", "provider"),
    (
        ("DNS Server", 5504, "Microsoft-Windows-DNS-Server-Service"),
        ("System", 101, "Application Management Group Policy"),
        ("System", 999, "Microsoft-Windows-GroupPolicy"),
        (TASK_SCHEDULER_CHANNEL, 101, "Microsoft-Windows-TaskScheduler"),
    ),
)
def test_message_sample_policy_is_owned_by_windows_pack(
    channel: str,
    event_id: int,
    provider: str,
) -> None:
    assert retain_message_sample_for_event(
        channel=channel,
        event_id=event_id,
        provider_name=provider,
    )


def test_message_sample_policy_does_not_leak_windows_ids_to_other_streams() -> None:
    assert not retain_message_sample_for_event(
        channel="Security",
        event_id=101,
        provider_name="Unrelated",
    )
    facts = event_facts_from_v1(
        {
            "id": 1,
            "channel": "Security",
            "event_id": 101,
            "provider_name": "Unrelated",
            "message_text": "must stay only in canonical archive",
            "event_data_json": "{}",
        }
    )
    assert facts is None


def test_storage_v2_uses_pack_message_sample_policy() -> None:
    facts = event_facts_from_v1(
        {
            "id": 1,
            "channel": "System",
            "event_id": 101,
            "provider_name": "Application Management Group Policy",
            "message_text": "bounded diagnostic context",
            "event_data_json": "{}",
        }
    )
    assert facts is not None
    assert facts.values["message_sample"] == "bounded diagnostic context"


def test_powershell_activity_facts_are_stream_and_event_scoped() -> None:
    command = event_facts_from_v1(
        {
            "id": 1,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "event_id": 4103,
            "provider_name": "Microsoft-Windows-PowerShell",
            "event_data_json": '{"User":"CORP\\\\operator","CommandName":"Get-ADUser","SystemExecutionProcessId":"4096","ScriptBlockText":"must not leak"}',
        }
    )
    script_block = event_facts_from_v1(
        {
            "id": 2,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "event_id": 4104,
            "provider_name": "Microsoft-Windows-PowerShell",
            "event_data_json": '{"User":"CORP\\\\operator","CommandName":"must not leak","ScriptBlockText":"Get-ADUser -Identity alice"}',
        }
    )
    unrelated = event_facts_from_v1(
        {
            "id": 3,
            "channel": "Security",
            "event_id": 4104,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data_json": '{"CommandName":"must not leak","ScriptBlockText":"must not leak"}',
        }
    )

    assert command is not None
    assert command.values["powershell_user_name"] == "CORP\\operator"
    assert command.values["powershell_command_name"] == "Get-ADUser"
    assert command.values["powershell_process_id"] == "4096"
    assert command.values["powershell_script_block_text"] is None
    assert script_block is not None
    assert script_block.values["powershell_user_name"] == "CORP\\operator"
    assert script_block.values["powershell_command_name"] is None
    assert script_block.values["powershell_script_block_text"] == "Get-ADUser -Identity alice"
    assert unrelated is None
    assert {"powershell_command_name", "powershell_script_block_text", "powershell_process_id"} <= EVENT_FACTS_V2_WRITE_COLUMNS


def test_security_process_facts_use_created_process_identity() -> None:
    process_start = event_facts_from_v1(
        {
            "id": 4,
            "channel": "Security",
            "event_id": 4688,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data_json": '{"ProcessId":"0x11","NewProcessId":"0x1000","NewProcessName":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"}',
        }
    )
    process_stop = event_facts_from_v1(
        {
            "id": 5,
            "channel": "Security",
            "event_id": 4689,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data_json": '{"ProcessId":"0x1000","ProcessName":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"}',
        }
    )

    assert process_start is not None
    assert process_start.values["process_id"] == "4096"
    assert process_start.values["process_name"].endswith("powershell.exe")
    assert process_stop is not None
    assert process_stop.values["process_id"] == "4096"


def test_generic_storage_mapper_delegates_windows_message_policy() -> None:
    source = Path("server/sli/storage/storage_v2_models.py").read_text(encoding="utf-8")
    assert "resolve_source_normalizer(" in source
    assert "event_type in {101, 103, 108, 1112, 5504}" not in source
    assert '"ProcessName"' not in source


def test_windows_entity_semantics_are_stream_scoped() -> None:
    group = entity_semantics_for_event(channel="Security", event_id=4728)
    service = entity_semantics_for_event(channel="System", event_id=7045)
    target_server = entity_semantics_for_event(channel="Security", event_id=4769)

    assert group.target_is_group
    assert service.service_name_is_entity
    assert target_server.target_server_is_entity
    assert not entity_semantics_for_event(
        channel="Unrelated/Channel",
        event_id=4728,
    ).target_is_group


def test_generic_entity_linker_has_no_windows_event_id_sets() -> None:
    source = Path("server/sli/entities/entity_model.py").read_text(encoding="utf-8")
    assert "resolve_source_normalizer(" in source
    assert "GROUP_EVENT_IDS" not in source
    assert "{7035, 7036, 7040, 7045}" not in source
    assert "{4648, 4769}" not in source


def test_windows_state_projection_rules_are_owned_by_source_pack() -> None:
    account = state_semantics_for_event(channel="Security", event_id=4740)
    task = state_semantics_for_event(
        channel=TASK_SCHEDULER_CHANNEL,
        event_id=140,
    )

    assert account is not None and account.status == "locked"
    assert task is not None and task.state_type == "scheduled_task.configuration"
    assert state_semantics_for_event(channel="Unrelated", event_id=4740) is None


def test_generic_state_projector_has_no_windows_rule_table() -> None:
    source = Path("server/sli/entities/entity_state_model.py").read_text(encoding="utf-8")
    assert "resolve_source_normalizer(" in source
    assert "_RULES" not in source
    assert "account-created-4720" not in source


def test_contextual_severity_is_dispatched_to_windows_normalizer() -> None:
    result = classify_contextual_event(
        {
            "channel": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_id": 4624,
            "server": "DC1",
            "target_user_name": "svc-backup",
            "event_data_json": '{"LogonType":"10"}',
        }
    )
    assert result["severity"] == "critical"
    assert result["title"] == "Интерактивный вход сервисной учеткой на DC"

    foreign = classify_contextual_event(
        {
            "channel": "Unrelated/Channel",
            "event_id": 4624,
            "server": "DC1",
            "target_user_name": "svc-backup",
            "event_data_json": '{"LogonType":"10"}',
        }
    )
    assert foreign["severity"] == "info"


def test_generic_severity_module_contains_no_windows_event_rules() -> None:
    source = Path("server/sli/semantic/severity.py").read_text(encoding="utf-8")
    assert "resolve_source_normalizer(" in source
    assert "4624" not in source
    assert "4728" not in source


def test_account_timeline_semantics_and_search_families_are_pack_owned() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None

    lockout = normalizer.account_event(4740)
    assert lockout is not None
    assert lockout.timeline_category == "lockout"
    assert lockout.severity == "high"
    assert 4624 in normalizer.event_ids_for_search_family("authentication")
    assert 4728 in normalizer.event_ids_for_search_family("account_management")
    assert normalizer.account_event(999999) is None


def test_event_search_contains_no_windows_event_id_tables() -> None:
    source = "".join(
        path.read_text(encoding="utf-8") for path in sorted(Path("server/sli/events").glob("event_search*.py"))
    )
    assert "resolve_source_normalizer(" in source
    for event_id in (
        "1102",
        "4624",
        "4625",
        "4672",
        "4720",
        "4728",
        "4740",
        "4769",
        "4771",
        "7036",
        "7045",
    ):
        assert event_id not in source


def test_analysis_event_families_are_pack_owned_and_ordered() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None
    assert normalizer.event_ids_for_analysis_family("successful_logon") == (4624,)
    assert normalizer.event_ids_for_analysis_family("kerberos") == (
        4768,
        4769,
        4771,
    )
    assert normalizer.event_ids_for_analysis_family("audit_controls")[-1] == 1102
    assert normalizer.event_ids_for_analysis_family("unknown") == ()


def test_generic_analysis_contains_no_windows_event_id_literals() -> None:
    source = Path("server/sli/reports/analysis.py").read_text(encoding="utf-8")
    assert "event_ids_for_analysis_family(" in source
    for event_id in (
        "1102",
        "4624",
        "4625",
        "4648",
        "4672",
        "4720",
        "4728",
        "4740",
        "4769",
        "4771",
        "5504",
    ):
        assert event_id not in source


def test_windows_event_labels_are_pack_owned_and_localized() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None
    assert normalizer.event_label(4740, "ru") == "Учетная запись заблокирована"
    assert normalizer.event_label(4740, "en") == "Account locked out"
    assert normalizer.event_label(999999, "ru") is None


def test_generic_ui_labels_contains_no_windows_event_id_table() -> None:
    source = Path("server/sli/reporting/ui_labels.py").read_text(encoding="utf-8")
    assert "resolve_source_normalizer(" in source
    assert "EVENT_ID_LABELS" not in source
    for event_id in ("4624", "4625", "4720", "4740", "4769", "5504", "7045"):
        assert event_id not in source


def test_windows_finding_rules_are_pack_owned() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None
    rules = normalizer.finding_rules()
    assert rules[4740].rule_code == "account_lockout"
    assert rules[4724].severity == "high"
    assert rules[7045].title == "Установлена служба"
    assert "источник ошибок входа" in rules[4740].recommendation


def test_event_details_and_findings_contain_no_windows_rule_tables() -> None:
    event_details_source = Path("server/sli/events/event_details.py").read_text(encoding="utf-8")
    findings_source = Path("server/sli/semantic/findings.py").read_text(encoding="utf-8")
    assert "_event_risk" not in event_details_source
    assert "finding_rules()" in findings_source
    for event_id in ("4624", "4625", "4720", "4724", "4728", "4740", "4756", "7045"):
        assert event_id not in event_details_source
        assert event_id not in findings_source


def test_investigation_and_security_monitor_contracts_are_pack_owned() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None
    assert normalizer.investigation_category(4625) == "failed_logons"
    assert normalizer.investigation_category(7045) == "system"
    assert 4768 in normalizer.investigation_event_ids("important")
    assert 4768 not in normalizer.investigation_event_ids("hide_noise")
    groups = {group.key: group for group in normalizer.security_monitor_groups()}
    assert groups["passwords"].event_ids == (4723, 4724)
    assert groups["all_logons"].event_ids == (4624, 4634)
    assert normalizer.monitor_privileged_event_ids() == (4672, 4728, 4732, 4756)


def test_investigation_and_monitor_contain_no_windows_event_id_tables() -> None:
    investigation_source = Path("server/sli/semantic/investigation.py").read_text(encoding="utf-8")
    monitor_source = Path("server/sli/events/security_events_monitor.py").read_text(encoding="utf-8")
    assert "investigation_event_ids(" in investigation_source
    assert "security_monitor_groups()" in monitor_source
    for event_id in (
        "4624",
        "4625",
        "4648",
        "4672",
        "4723",
        "4724",
        "4728",
        "4740",
        "4768",
        "4771",
        "7045",
    ):
        assert event_id not in investigation_source
        assert event_id not in monitor_source


def test_semantic_projection_is_dispatched_to_windows_pack() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None
    projection = normalizer.semantic_projection(
        event_id=4624,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserSid": "S-1-5-21-1",
            "TargetLogonId": "0x123",
            "LogonType": "3",
        },
        correlation_id=None,
        source_host="dc1",
    )
    assert projection["semantic_type"] == "authentication.session.created"
    assert projection["roles"]["session_principal"] == "dc1:0x123"
    assert projection["facts"]["logon_type"] == "3"


@pytest.mark.parametrize(
    ("event_id", "semantic_type"),
    (
        (4720, "directory.account.created"),
        (4724, "account.password.reset.attempted"),
        (4740, "authentication.account.locked"),
        (4767, "authentication.account.unlocked"),
    ),
)
def test_account_management_relations_use_source_native_target_sid(
    event_id: int,
    semantic_type: str,
) -> None:
    event = StoredEvent(
        event_id=event_id,
        windows_event_id=event_id,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        server="dc-a.example.invalid",
        source_host_id=17,
        domain_id=8,
        occurred_at_utc=datetime(2026, 9, 11, tzinfo=timezone.utc),
        # 4720/4724/4740/4767 archive rows identify the affected account here.
        event_data={"TargetSid": "S-1-5-21-42-43-44-1001"},
    )

    normalized = normalize_windows_event(event)

    assert normalized.semantic_type == semantic_type
    assert normalized.facts["domain_id"] == 8
    assert normalized.facts["relation_account_sid"] == "S-1-5-21-42-43-44-1001"
    assert normalized.quality["relation_account_identity"] == {
        "state": "exact",
        "sid_field": "TargetSid",
    }


def test_group_relation_requires_exact_member_and_group_sids() -> None:
    event = StoredEvent(
        event_id=4728,
        windows_event_id=4728,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        server="dc-a.example.invalid",
        source_host_id=17,
        domain_id=8,
        occurred_at_utc=datetime(2026, 9, 11, tzinfo=timezone.utc),
        event_data={
            "MemberSid": "S-1-5-21-42-43-44-1001",
            "TargetSid": "S-1-5-21-42-43-44-512",
        },
    )

    normalized = normalize_windows_event(event)

    assert normalized.semantic_type == "group.member.added"
    assert normalized.facts["domain_id"] == 8
    assert normalized.facts["relation_member_sid"] == "S-1-5-21-42-43-44-1001"
    assert normalized.facts["relation_group_sid"] == "S-1-5-21-42-43-44-512"
    assert normalized.quality["relation_membership_identity"] == {
        "state": "exact",
        "member_sid_field": "MemberSid",
        "group_sid_field": "TargetSid",
    }


def test_group_relation_does_not_promote_member_or_group_names_to_exact_identity() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None

    projection = normalizer.semantic_projection(
        event_id=4733,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data={"MemberName": "alice", "TargetUserName": "Administrators"},
        correlation_id=None,
        source_host="17",
    )

    assert projection["semantic_type"] == "group.member.removed"
    assert "relation_member_sid" not in projection["facts"]
    assert "relation_group_sid" not in projection["facts"]
    assert projection["quality"]["relation_membership_identity"]["state"] == "not_exact"


def test_password_reset_remains_an_attempt_without_source_native_success() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None

    projection = normalizer.semantic_projection(
        event_id=4724,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data={"TargetUserSid": "S-1-5-21-42-43-44-1001"},
        correlation_id=None,
        source_host="17",
    )

    assert projection["semantic_type"] == "account.password.reset.attempted"
    assert projection["facts"].get("result") != "success"


def test_password_reset_uses_only_source_native_audit_keyword_to_mark_success() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None

    successful = normalizer.semantic_projection(
        event_id=4724,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserSid": "S-1-5-21-42-43-44-1001",
            "Status": "0x0",
        },
        keywords="0x8020000000000000",
        correlation_id=None,
        source_host="17",
    )
    failed = normalizer.semantic_projection(
        event_id=4724,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserSid": "S-1-5-21-42-43-44-1001",
            "Status": "0x0",
        },
        keywords="0x8010000000000000",
        correlation_id=None,
        source_host="17",
    )

    assert successful["semantic_type"] == "account.password.reset.succeeded"
    assert successful["facts"]["result"] == "success"
    assert failed["semantic_type"] == "account.password.reset.attempted"
    assert failed["facts"]["result"] == "failure"

    unproven = normalizer.semantic_projection(
        event_id=4724,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserSid": "S-1-5-21-42-43-44-1001",
            "Status": "0x0",
        },
        correlation_id=None,
        source_host="17",
    )
    assert unproven["semantic_type"] == "account.password.reset.attempted"
    assert unproven["facts"]["result"] == "unknown"


def test_successful_logon_uses_target_user_sid_not_unrelated_target_sid() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None

    projection = normalizer.semantic_projection(
        event_id=4624,
        channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserSid": "S-1-5-21-42-43-44-1001",
            "TargetSid": "S-1-5-21-42-43-44-512",
        },
        correlation_id=None,
        source_host="17",
    )

    assert projection["semantic_type"] == "authentication.session.created"
    assert projection["facts"]["relation_account_sid"] == "S-1-5-21-42-43-44-1001"
    assert projection["quality"]["relation_account_identity"] == {
        "state": "exact",
        "sid_field": "TargetUserSid",
    }


def test_account_relation_interpretation_bumps_normalizer_base_version() -> None:
    assert NORMALIZER_BASE_VERSION == "1.4"
    assert ASSEMBLER_VERSION == "1.1"


def test_semantic_context_prefilter_translates_canonical_identity_key() -> None:
    normalizer = resolve_source_normalizer("Security")
    assert normalizer is not None

    sid_filters = normalizer.semantic_core_role_filters(
        "authentication.session.created",
        ("source_host", "affected_entity"),
        {
            "source_host": "1",
            "affected_entity": "sid:S-1-5-21-1",
        },
    )
    sam_filters = normalizer.semantic_core_role_filters(
        "authentication.session.created",
        ("source_host", "affected_entity"),
        {
            "source_host": "1",
            "affected_entity": "sam:example:alice",
        },
    )

    assert sid_filters is not None and sid_filters[0].value == "S-1-5-21-1"
    assert sam_filters is not None and sam_filters[0].value == "alice"


def test_generic_semantic_modules_contain_no_windows_event_id_rules() -> None:
    processing_source = Path("server/sli/semantic/semantic_processing.py").read_text(
        encoding="utf-8"
    )
    correlation_source = Path("server/sli/semantic/semantic_correlation.py").read_text(
        encoding="utf-8"
    )
    assert "semantic_projection(" in processing_source
    for event_id in (
        "1102",
        "4624",
        "4625",
        "4648",
        "4672",
        "4728",
        "5136",
        "7045",
    ):
        assert event_id not in processing_source
        assert event_id not in correlation_source


def test_operational_core_has_no_known_windows_event_id_literals() -> None:
    # Operational infrastructure, not source-pack/report/detection vocabulary owners.
    root = Path(__file__).resolve().parents[2] / "server" / "sli"
    paths: list[Path] = []
    for package, sentinel in (
        ("core", "database.py"), ("ops", "logging_config.py"),
        ("storage", "storage_lifecycle_io.py"),
    ):
        package_root = root / package
        package_paths = sorted(package_root.rglob("*.py"))
        assert package_root / sentinel in package_paths, package
        assert any(path.name != "__init__.py" for path in package_paths), package
        paths.extend(package_paths)
    event_ids = (
        "1102",
        "4624",
        "4625",
        "4634",
        "4648",
        "4672",
        "4719",
        "4720",
        "4724",
        "4728",
        "4732",
        "4740",
        "4768",
        "4769",
        "4771",
        "4776",
        "5136",
        "5504",
        "7045",
    )
    violations: list[str] = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        for event_id in event_ids:
            if event_id in source:
                violations.append(f"{path}:{event_id}")
    assert violations == []

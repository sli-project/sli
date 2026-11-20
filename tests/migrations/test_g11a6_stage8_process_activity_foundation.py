from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from server.sli.semantic.semantic_processing import (
    NormalizedEvent,
    StoredEvent,
    assemble_process_episodes,
    normalize_windows_event,
)
from server.sli.storage.storage_v2_models import event_facts_from_v1
from server.sli.semantic.semantic_processing_repository import persist_process_episode_revision


UTC = timezone.utc
BASE = datetime(2026, 8, 25, 1, tzinfo=UTC)
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"


def stored(event_id: int, windows_event_id: int, data: dict[str, str], *, second: int = 0) -> StoredEvent:
    return StoredEvent(
        event_id=event_id,
        windows_event_id=windows_event_id,
        channel="Security",
        server="DC1.example.test",
        occurred_at_utc=BASE + timedelta(seconds=second),
        event_data=data,
        provider=SECURITY_PROVIDER,
        source_host_id=11,
        domain_id=7,
        event_record_id=1000 + event_id,
        source_event_sha256=f"{event_id:064x}",
        source_facts_sha256=f"{event_id + 1:064x}",
    )


def test_stage8_catalog_contains_exact_process_service_and_task_contracts() -> None:
    catalog = json.loads(Path("config/event_catalog.json").read_text(encoding="utf-8"))
    entries = {
        (item["channel"], item["event_id"]): item for item in catalog["entries"]
    }
    for event_id in (4697, 4698, 4699, 4700, 4701, 4702):
        item = entries[("Security", event_id)]
        assert item["provider_name"] == SECURITY_PROVIDER
        assert item["lifecycle"] == {
            "raw_payload_days": 2,
            "record_days": 7,
            "warm_record_days": 365,
            "rollup": "process_activity",
        }
        assert {
            "event_id", "time_created_utc", "server_id", "event_record_id",
            "source_core_sha256", "source_facts_sha256",
        } <= set(item["required_fields"])
    for event_id in (4688, 4689):
        required = set(entries[("Security", event_id)]["required_fields"])
        assert {"process_user_sid", "process_user_name", "process_user_domain", "process_logon_id"} <= required
    assert {"process_parent_id", "process_command_line"} <= set(
        entries[("Security", 4688)]["required_fields"]
    )


@pytest.mark.parametrize(
    ("event_id", "expected_type", "extra", "expected"),
    (
        (4697, "service.installed.fragment", {"ServiceName": "svc", "ServiceFileName": "C:\\svc.exe", "ServiceAccount": "LocalSystem", "ServiceStartType": "2", "ClientProcessId": "0x44"}, {"service_name": "svc", "service_file": "C:\\svc.exe", "service_account": "LocalSystem", "service_start_type": "2", "native_process_id": "68"}),
        (4698, "scheduled_task.created.fragment", {"TaskName": "\\Ops\\A", "TaskContent": "<Task/>", "ClientProcessId": "0x45"}, {"task_name": "\\Ops\\A", "task_content": "<Task/>", "task_change": "created", "native_process_id": "69"}),
        (4699, "scheduled_task.deleted.fragment", {"TaskName": "\\Ops\\A"}, {"task_name": "\\Ops\\A", "task_change": "deleted"}),
        (4700, "scheduled_task.enabled.fragment", {"TaskName": "\\Ops\\A"}, {"task_name": "\\Ops\\A", "task_change": "enabled"}),
        (4701, "scheduled_task.disabled.fragment", {"TaskName": "\\Ops\\A"}, {"task_name": "\\Ops\\A", "task_change": "disabled"}),
        (4702, "scheduled_task.updated.fragment", {"TaskName": "\\Ops\\A", "TaskContentNew": "<Task v='2'/>", "ClientProcessId": "70"}, {"task_name": "\\Ops\\A", "task_content": "<Task v='2'/>", "task_change": "updated", "native_process_id": "70"}),
    ),
)
def test_security_service_and_each_task_event_normalize_exactly(
    event_id: int,
    expected_type: str,
    extra: dict[str, str],
    expected: dict[str, str],
) -> None:
    normalized = normalize_windows_event(stored(
        event_id,
        event_id,
        {
            "SubjectUserSid": "S-1-5-21-7-1001",
            "SubjectUserName": "operator",
            "SubjectDomainName": "EXAMPLE",
            "SubjectLogonId": "0xabc",
            **extra,
        },
    ))
    assert normalized.semantic_type == expected_type
    assert expected.items() <= normalized.facts.items()
    assert normalized.facts["process_user_sid"] == "S-1-5-21-7-1001"
    assert normalized.facts["process_logon_id"] == "0xabc"
    assert normalized.facts["event_record_id"] == 1000 + event_id
    assert normalized.facts["source_event_sha256"] == f"{event_id:064x}"
    assert normalized.facts["source_facts_sha256"] == f"{event_id + 1:064x}"


def test_4688_and_4689_retain_exact_process_identity_and_bounded_unknowns() -> None:
    start = event_facts_from_v1({
        "id": 1,
        "channel": "Security",
        "event_id": 4688,
        "provider_name": SECURITY_PROVIDER,
        "event_data_json": json.dumps({
            "NewProcessId": "0x1000",
            "NewProcessName": "C:\\Windows\\process.exe",
            "CreatorProcessId": "0x40",
            "CommandLine": "process.exe --exact value",
            "SubjectUserSid": "S-1-5-21-7-1001",
            "SubjectUserName": "operator",
            "SubjectDomainName": "EXAMPLE",
            "SubjectLogonId": "0xabc",
        }),
    })
    stop = event_facts_from_v1({
        "id": 2,
        "channel": "Security",
        "event_id": 4689,
        "provider_name": SECURITY_PROVIDER,
        "event_data_json": json.dumps({
            "ProcessId": "0x1000",
            "ProcessName": "C:\\Windows\\process.exe",
            "SubjectUserSid": "S-1-5-21-7-1001",
            "SubjectUserName": "operator",
            "SubjectDomainName": "EXAMPLE",
            "SubjectLogonId": "0xabc",
        }),
    })
    assert start is not None and stop is not None
    assert start.values["process_parent_id"] == "64"
    assert start.values["process_command_line"] == "process.exe --exact value"
    for facts in (start, stop):
        assert facts.values["process_user_sid"] == "S-1-5-21-7-1001"
        assert facts.values["process_user_name"] == "operator"
        assert facts.values["process_user_domain"] == "EXAMPLE"
        assert facts.values["process_logon_id"] == "0xabc"
    oversized = event_facts_from_v1({
        "id": 3,
        "channel": "Security",
        "event_id": 4688,
        "provider_name": SECURITY_PROVIDER,
        "event_data_json": json.dumps({"NewProcessId": "-", "CommandLine": "x" * 5000}),
    })
    assert oversized is None


def test_process_normalization_marks_invalid_pid_and_over_limit_command_unknown() -> None:
    normalized = normalize_windows_event(stored(
        9,
        4688,
        {"NewProcessId": "not-a-pid", "CommandLine": "x" * 4097},
    ))
    assert "process_id" not in normalized.facts
    assert "process_command_line" not in normalized.facts
    assert normalized.quality["process_id_state"] == "unknown_invalid"
    assert normalized.quality["process_command_line_state"] == "unknown_over_limit"


def test_process_bounded_contract_is_utf8_byte_based_and_shared_by_episode_path() -> None:
    normalized = normalize_windows_event(stored(
        109,
        4688,
        {
            "NewProcessId": "0x100000000",
            "CreatorProcessId": "4294967296",
            "NewProcessName": "Ж" * 257,
            "CommandLine": "Ж" * 2049,
            "SubjectUserSid": "Ж" * 257,
            "SubjectUserName": "Ж" * 257,
            "SubjectDomainName": "Ж" * 257,
            "SubjectLogonId": "Ж" * 65,
        },
    ))
    for field in (
        "process_id", "process_parent_id", "process_name", "process_command_line",
        "process_user_sid", "process_user_name", "process_user_domain",
        "process_logon_id",
    ):
        assert field not in normalized.facts
    assert normalized.quality["process_command_line_state"] == "unknown_over_limit"
    assert normalized.quality["process_parent_id_state"] == "unknown_invalid"

    bypass = process_event(110, 4688, 75, 1)
    bypass = NormalizedEvent(**{
        **bypass.__dict__,
        "facts": {**bypass.facts, "process_command_line": "Ж" * 2049},
    })
    result = assemble_process_episodes([boot(108, 0), bypass])
    assert result.episodes == ()
    assert result.standalone_evidence_ids == (110,)


def process_event(
    source_id: int,
    windows_id: int,
    pid: int,
    second: int,
    *,
    parent_pid: int | None = None,
    logon_id: str = "0xabc",
    host_id: int = 11,
    domain_id: int = 7,
) -> object:
    data = {
        "SubjectUserSid": "S-1-5-21-7-1001",
        "SubjectUserName": "operator",
        "SubjectDomainName": "EXAMPLE",
        "SubjectLogonId": logon_id,
        ("NewProcessId" if windows_id == 4688 else "ProcessId"): hex(pid),
        ("NewProcessName" if windows_id == 4688 else "ProcessName"): f"C:\\p{pid}.exe",
    }
    if parent_pid is not None:
        data["CreatorProcessId"] = hex(parent_pid)
    if windows_id == 4688:
        data["CommandLine"] = f"p{pid}.exe --exact"
    event = stored(source_id, windows_id, data, second=second)
    event = StoredEvent(
        **{**event.__dict__, "source_host_id": host_id, "domain_id": domain_id}
    )
    return normalize_windows_event(event)


def boot(source_id: int, second: int, *, host_id: int = 11, domain_id: int = 7) -> object:
    event = stored(source_id, 4608, {}, second=second)
    event = StoredEvent(
        **{
            **event.__dict__,
            "source_host_id": host_id,
            "domain_id": domain_id,
            "event_record_id": source_id,
        }
    )
    return normalize_windows_event(event)


def test_process_assembler_keeps_parallel_open_and_closed_episodes_with_exact_parent() -> None:
    events = [
        boot(1, 0),
        process_event(2, 4688, 10, 1),
        process_event(3, 4688, 20, 2, parent_pid=10),
        process_event(4, 4688, 30, 3),
        process_event(5, 4689, 20, 4),
        process_event(6, 4689, 10, 5),
    ]
    result = assemble_process_episodes(tuple(reversed(events)))
    by_pid = {episode.process_id: episode for episode in result.episodes}
    assert by_pid[20].confirmation_state == "confirmed_end"
    assert by_pid[20].end_event_id == 5
    assert by_pid[20].parent_episode_id == by_pid[10].episode_id
    assert by_pid[30].confirmation_state == "open_incomplete"
    assert by_pid[30].confirmed_end_at_utc is None
    assert result.standalone_evidence_ids == ()


def test_process_assembler_isolates_pid_reuse_boot_and_logon_identity() -> None:
    events = [
        boot(10, 0),
        process_event(11, 4688, 50, 1, logon_id="0x1"),
        process_event(12, 4689, 50, 2, logon_id="0x1"),
        process_event(13, 4688, 50, 3, logon_id="0x1"),
        boot(14, 4),
        process_event(15, 4688, 50, 5, logon_id="0x1"),
        process_event(16, 4688, 51, 6, logon_id="0x1"),
    ]
    result = assemble_process_episodes(events)
    assert [(item.start_event_id, item.end_event_id) for item in result.episodes] == [
        (11, 12), (13, None), (15, None), (16, None)
    ]
    assert len({item.episode_id for item in result.episodes}) == 4


def test_process_identity_uses_immutable_domain_and_source_host_not_display_host() -> None:
    first = process_event(17, 4688, 52, 1, host_id=11, domain_id=7)
    renamed_same_identity = NormalizedEvent(**{
        **first.__dict__,
        "facts": {**first.facts, "host": "RENAMED.example.test"},
    })
    original_episode = assemble_process_episodes([boot(15, 0), first]).episodes[0]
    renamed_episode = assemble_process_episodes([
        boot(15, 0), renamed_same_identity
    ]).episodes[0]
    assert original_episode.episode_id == renamed_episode.episode_id
    assert original_episode.display_host != renamed_episode.display_host

    renamed = NormalizedEvent(
        **{
            **first.__dict__,
            "source_event_id": 18,
            "facts": {
                **first.facts,
                "host": "RENAMED.example.test",
                "event_record_id": 1018,
            },
            "semantic_sha256": "18" * 32,
        }
    )
    other_source = NormalizedEvent(
        **{
            **first.__dict__,
            "source_event_id": 19,
            "facts": {**first.facts, "source_host_id": 12},
            "semantic_sha256": "19" * 32,
        }
    )
    result = assemble_process_episodes([
        boot(15, 0, host_id=11, domain_id=7),
        boot(16, 0, host_id=12, domain_id=7),
        first,
        renamed,
        other_source,
    ])
    assert len(result.episodes) == 3
    assert {item.source_host_id for item in result.episodes} == {"11", "12"}
    same_source = [item for item in result.episodes if item.source_host_id == "11"]
    assert len({item.episode_id for item in same_source}) == 2
    assert {item.display_host for item in same_source} == {
        "DC1.example.test", "RENAMED.example.test"
    }


def test_process_assembler_deduplicates_exact_replay_and_fails_closed_on_bad_closes() -> None:
    start = process_event(21, 4688, 60, 2)
    early_close = process_event(22, 4689, 60, 1)
    close_a = process_event(23, 4689, 60, 3)
    close_b = process_event(24, 4689, 60, 3)
    result = assemble_process_episodes([
        close_b, start, boot(20, 0), close_a, start, early_close,
    ])
    assert len(result.episodes) == 1
    assert result.episodes[0].confirmation_state == "ambiguous_conflict"
    assert result.episodes[0].end_event_id is None
    assert result.episodes[0].evidence_event_ids == (21, 22, 23, 24)
    assert result.standalone_evidence_ids == ()


def test_source_event_semantic_conflict_is_permanently_quarantined_for_all_permutations() -> None:
    valid = process_event(27, 4688, 61, 1)
    conflict = NormalizedEvent(
        **{
            **valid.__dict__,
            "facts": {**valid.facts, "process_id": "62"},
            "semantic_sha256": "ff" * 32,
        }
    )
    for values in (
        [valid, conflict, valid],
        [conflict, valid, valid],
        [valid, valid, conflict],
    ):
        result = assemble_process_episodes([boot(26, 0), *values])
        assert result.episodes == ()
        assert result.standalone_evidence_ids == (27,)


def test_parent_pid_reuse_is_resolved_only_when_exact_parent_is_active() -> None:
    result = assemble_process_episodes([
        boot(30, 0),
        process_event(31, 4688, 70, 1),
        process_event(32, 4689, 70, 2),
        process_event(33, 4688, 70, 3),
        process_event(34, 4688, 71, 4, parent_pid=70),
        process_event(35, 4689, 70, 5),
        process_event(36, 4688, 72, 6, parent_pid=70),
    ])
    by_start = {item.start_event_id: item for item in result.episodes}
    assert by_start[34].parent_episode_id == by_start[33].episode_id
    assert by_start[36].parent_episode_id is None
    assert by_start[36].completeness_state == "incomplete_parent_unproven"


def test_event_record_id_orders_same_channel_and_cross_channel_order_is_explicitly_uncertain() -> None:
    start = process_event(100, 4688, 73, 1)
    close = process_event(99, 4689, 73, 1)
    start = NormalizedEvent(**{
        **start.__dict__, "facts": {**start.facts, "event_record_id": 200}
    })
    close = NormalizedEvent(**{
        **close.__dict__, "facts": {**close.facts, "event_record_id": 201}
    })
    same_channel = assemble_process_episodes([boot(98, 0), close, start])
    assert same_channel.episodes[0].end_event_id == 99
    assert same_channel.episodes[0].ordering_state == "source_native"

    cross_channel = assemble_process_episodes([
        boot(101, 0),
        process_event(102, 4688, 74, 1),
        attached_event(103, 4104, 2, pid=74),
    ])
    assert cross_channel.episodes[0].ordering_state == "cross_channel_uncertain"


def test_process_assembler_quarantines_missing_native_event_record_id() -> None:
    start = process_event(138, 4688, 138, 1)
    start = NormalizedEvent(**{
        **start.__dict__,
        "facts": {key: value for key, value in start.facts.items() if key != "event_record_id"},
    })

    result = assemble_process_episodes([boot(137, 0), start])

    assert result.episodes == ()
    assert result.standalone_evidence_ids == (138,)


def test_process_assembler_quarantines_zero_boot_event_record_id() -> None:
    boot_event = boot(155, 0)
    boot_event = NormalizedEvent(**{
        **boot_event.__dict__,
        "facts": {**boot_event.facts, "event_record_id": 0},
    })

    result = assemble_process_episodes([
        boot_event,
        process_event(156, 4688, 156, 1),
    ])

    assert result.episodes == ()
    assert result.standalone_evidence_ids == (155, 156)


def test_process_assembler_quarantines_zero_start_event_record_id() -> None:
    start = process_event(158, 4688, 158, 1)
    start = NormalizedEvent(**{
        **start.__dict__,
        "facts": {**start.facts, "event_record_id": 0},
    })

    result = assemble_process_episodes([boot(157, 0), start])

    assert result.episodes == ()
    assert result.standalone_evidence_ids == (158,)


def test_process_assembler_quarantines_zero_end_event_record_id() -> None:
    end = process_event(161, 4689, 160, 2)
    end = NormalizedEvent(**{
        **end.__dict__,
        "facts": {**end.facts, "event_record_id": 0},
    })

    result = assemble_process_episodes([
        boot(159, 0),
        process_event(160, 4688, 160, 1),
        end,
    ])

    assert len(result.episodes) == 1
    assert result.episodes[0].end_event_id is None
    assert result.standalone_evidence_ids == (161,)


def test_process_assembler_quarantines_zero_attached_event_record_id() -> None:
    attached = attached_event(164, 4104, 2, pid=163)
    attached = NormalizedEvent(**{
        **attached.__dict__,
        "facts": {**attached.facts, "event_record_id": 0},
    })

    result = assemble_process_episodes([
        boot(162, 0),
        process_event(163, 4688, 163, 1),
        attached,
    ])

    assert result.episodes[0].evidence_event_ids == (163,)
    assert result.standalone_evidence_ids == (164,)


def test_process_assembler_quarantines_duplicate_same_scope_event_record_id() -> None:
    start = process_event(143, 4688, 143, 1)
    close = process_event(144, 4689, 143, 2)
    start = NormalizedEvent(**{
        **start.__dict__, "facts": {**start.facts, "event_record_id": 300},
    })
    close = NormalizedEvent(**{
        **close.__dict__, "facts": {**close.facts, "event_record_id": 300},
    })

    result = assemble_process_episodes([boot(142, 0), start, close])

    assert result.episodes == ()
    assert result.standalone_evidence_ids == (143, 144)


def test_same_channel_record_id_301_closes_300_despite_reversed_timestamp() -> None:
    start = process_event(140, 4688, 140, 2)
    close = process_event(141, 4689, 140, 1)
    start = NormalizedEvent(**{
        **start.__dict__, "facts": {**start.facts, "event_record_id": 300}
    })
    close = NormalizedEvent(**{
        **close.__dict__, "facts": {**close.facts, "event_record_id": 301}
    })

    boot_event = boot(139, 0)
    boot_event = NormalizedEvent(**{
        **boot_event.__dict__,
        "facts": {**boot_event.facts, "event_record_id": 299},
    })
    result = assemble_process_episodes([close, boot_event, start])

    assert len(result.episodes) == 1
    assert result.episodes[0].end_event_id == 141
    assert result.episodes[0].evidence_event_ids == (140, 141)
    assert result.episodes[0].ordering_state == "source_native"
    assert result.standalone_evidence_ids == ()


def test_event_record_id_disambiguates_equal_time_generations_close_and_parent() -> None:
    def with_record(event: NormalizedEvent, value: int) -> NormalizedEvent:
        return NormalizedEvent(**{
            **event.__dict__, "facts": {**event.facts, "event_record_id": value}
        })

    first = with_record(process_event(130, 4688, 130, 1), 200)
    first_close = with_record(process_event(131, 4689, 130, 1), 201)
    second = with_record(process_event(132, 4688, 130, 1), 202)
    child = with_record(process_event(133, 4688, 131, 1, parent_pid=130), 203)
    second_close = with_record(process_event(134, 4689, 130, 1), 204)
    result = assemble_process_episodes([
        boot(129, 0), second_close, child, second, first_close, first,
    ])
    by_start = {item.start_event_id: item for item in result.episodes}
    assert by_start[130].end_event_id == 131
    assert by_start[132].end_event_id == 134
    assert by_start[133].parent_episode_id == by_start[132].episode_id
    assert all(item.confirmation_state != "ambiguous_conflict" for item in result.episodes)


def test_event_record_id_controls_reversed_time_generations_and_parent_selection() -> None:
    def with_record(event: NormalizedEvent, value: int) -> NormalizedEvent:
        return NormalizedEvent(**{
            **event.__dict__, "facts": {**event.facts, "event_record_id": value}
        })

    boot_event = with_record(boot(149, 0), 299)
    first = with_record(process_event(150, 4688, 150, 5), 300)
    first_close = with_record(process_event(151, 4689, 150, 4), 301)
    second = with_record(process_event(152, 4688, 150, 3), 302)
    child = with_record(
        process_event(153, 4688, 151, 2, parent_pid=150), 303
    )
    second_close = with_record(process_event(154, 4689, 150, 1), 304)

    result = assemble_process_episodes([
        second_close, child, first_close, second, boot_event, first,
    ])

    by_start = {item.start_event_id: item for item in result.episodes}
    assert by_start[150].end_event_id == 151
    assert by_start[152].end_event_id == 154
    assert by_start[153].parent_episode_id == by_start[152].episode_id
    assert result.standalone_evidence_ids == ()


def attached_event(
    source_id: int,
    windows_id: int,
    second: int,
    *,
    pid: int | None,
) -> object:
    if windows_id in {4103, 4104}:
        event = StoredEvent(
            event_id=source_id,
            windows_event_id=windows_id,
            channel="Microsoft-Windows-PowerShell/Operational",
            server="DC1.example.test",
            occurred_at_utc=BASE + timedelta(seconds=second),
            event_data={
                "SystemExecutionProcessId": str(pid) if pid is not None else "",
                "CommandName": "Get-Process",
                "ScriptBlockText": "Get-Process -Id 1",
                "User": "EXAMPLE\\operator",
            },
            provider="Microsoft-Windows-PowerShell",
            source_host_id=11,
            domain_id=7,
            event_record_id=1000 + source_id,
            source_event_sha256=f"{source_id:064x}",
            source_facts_sha256=f"{source_id + 1:064x}",
        )
    else:
        data = {
            "SubjectUserSid": "S-1-5-21-7-1001",
            "SubjectUserName": "operator",
            "SubjectDomainName": "EXAMPLE",
            "SubjectLogonId": "0xabc",
            "TaskName": "\\Ops\\A",
            "ServiceName": "svc",
            "ServiceFileName": "C:\\svc.exe",
        }
        if pid is not None:
            data["ClientProcessId"] = str(pid)
        event = stored(source_id, windows_id, data, second=second)
    return normalize_windows_event(event)


def test_native_bridge_attaches_powershell_service_and_task_in_evidence_order() -> None:
    result = assemble_process_episodes([
        boot(40, 0),
        process_event(41, 4688, 80, 1),
        attached_event(42, 4103, 2, pid=80),
        attached_event(43, 4104, 3, pid=80),
        attached_event(44, 4697, 4, pid=80),
        attached_event(45, 4698, 5, pid=80),
        process_event(46, 4689, 80, 6),
    ])
    assert result.episodes[0].evidence_event_ids == (41, 42, 43, 44, 45, 46)
    assert result.standalone_evidence_ids == ()


def test_missing_or_ambiguous_native_bridge_retains_standalone_evidence() -> None:
    first = process_event(51, 4688, 90, 1)
    second = process_event(52, 4688, 90, 1)
    result = assemble_process_episodes([
        boot(50, 0), first, second,
        attached_event(53, 4104, 2, pid=90),
        attached_event(54, 4697, 2, pid=None),
        attached_event(55, 4702, 2, pid=None),
    ])
    assert result.standalone_evidence_ids == (53, 54, 55)
    assert all(item.evidence_event_ids == (item.start_event_id,) for item in result.episodes)
    assert all(item.confirmation_state == "open_incomplete" for item in result.episodes)


class EpisodeCursor:
    def __init__(self) -> None:
        self.history: list[tuple[str, tuple[object, ...]]] = []
        self.sql = ""

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        self.sql = " ".join(sql.split()).lower()
        self.history.append((self.sql, params))

    def fetchone(self) -> dict[str, object] | None:
        if "select revision_id" in self.sql:
            return None
        if "max(revision_no)" in self.sql:
            return {"next_revision": 1}
        return None


def test_process_episode_repository_persists_exact_revision_and_provenance_idempotently() -> None:
    normalized = [
        boot(60, 0),
        process_event(61, 4688, 100, 1, parent_pid=4),
        attached_event(62, 4104, 2, pid=100),
        process_event(63, 4689, 100, 3),
    ]
    episode = assemble_process_episodes(normalized).episodes[0]
    by_id = {item.source_event_id: item for item in normalized}
    first = EpisodeCursor()
    second = EpisodeCursor()
    revision_id = persist_process_episode_revision(first, episode=episode, evidence_by_id=by_id)
    assert persist_process_episode_revision(second, episode=episode, evidence_by_id=by_id) == revision_id
    combined = "\n".join(sql for sql, _ in first.history)
    assert "write_process_episode_revision_v89" in combined
    assert "insert into process_episode_revisions" not in combined
    assert "insert into process_episode_evidence" not in combined
    assert "events_v2_core" not in combined and "raw_xml" not in combined
    payload = json.loads(str(first.history[0][1][0]))
    assert payload["command_line"] == episode.command_line
    assert payload["source_host_id"] == 11
    assert payload["display_host"] == "DC1.example.test"
    assert [item["source_event_id"] for item in payload["evidence_manifest"]] == [60, 61, 62, 63]
    assert payload["evidence_manifest"][1]["source_event_sha256"] == by_id[61].facts["source_event_sha256"]


def test_process_episode_repository_binds_boot_atom_as_durable_evidence() -> None:
    normalized = [
        boot(64, 0),
        process_event(65, 4688, 101, 1),
    ]
    episode = assemble_process_episodes(normalized).episodes[0]
    cursor = EpisodeCursor()

    persist_process_episode_revision(
        cursor,
        episode=episode,
        evidence_by_id={item.source_event_id: item for item in normalized},
    )

    payload = json.loads(str(cursor.history[0][1][0]))
    boot_atoms = [
        item for item in payload["evidence_manifest"]
        if item["evidence_role"] == "boot_scope"
    ]
    assert [item["source_event_id"] for item in boot_atoms] == [64]
    assert payload["boot_event_id"] == 64
    assert payload["evidence_count"] == 2


def test_process_episode_repository_rejects_zero_event_record_id() -> None:
    normalized = [boot(165, 0), process_event(166, 4688, 166, 1)]
    episode = assemble_process_episodes(normalized).episodes[0]
    invalid_start = NormalizedEvent(**{
        **normalized[1].__dict__,
        "facts": {**normalized[1].facts, "event_record_id": 0},
    })
    cursor = EpisodeCursor()

    with pytest.raises(ValueError, match="EventRecordID"):
        persist_process_episode_revision(
            cursor,
            episode=episode,
            evidence_by_id={165: normalized[0], 166: invalid_start},
        )

    assert cursor.history == []


def test_process_episode_manifest_pins_exact_normalized_semantic_provenance() -> None:
    normalized = [boot(66, 0), process_event(67, 4688, 102, 1)]
    episode = assemble_process_episodes(normalized).episodes[0]
    cursor = EpisodeCursor()

    persist_process_episode_revision(
        cursor,
        episode=episode,
        evidence_by_id={item.source_event_id: item for item in normalized},
    )

    payload = json.loads(str(cursor.history[0][1][0]))
    for source, atom in zip(normalized, payload["evidence_manifest"], strict=True):
        assert atom["semantic_contract_version"] == 1
        assert atom["normalizer_id"] == "windows.named-eventdata"
        assert atom["normalizer_version"]
        assert atom["semantic_sha256"] == source.semantic_sha256


def test_revision_identity_binds_full_ordered_evidence_manifest() -> None:
    normalized = [
        boot(120, 0),
        process_event(121, 4688, 120, 1),
        process_event(122, 4689, 120, 2),
    ]
    episode = assemble_process_episodes(normalized).episodes[0]
    original = {item.source_event_id: item for item in normalized}
    changed = dict(original)
    evidence = changed[122]
    changed[122] = NormalizedEvent(**{
        **evidence.__dict__,
        "facts": {**evidence.facts, "source_facts_sha256": "ab" * 32},
    })
    assert persist_process_episode_revision(
        EpisodeCursor(), episode=episode, evidence_by_id=original
    ) != persist_process_episode_revision(
        EpisodeCursor(), episode=episode, evidence_by_id=changed
    )


def test_migration89_is_additive_bounded_retention_independent_and_rollback_safe() -> None:
    forward = Path("config/postgres_migrations/089_process_activity_foundation.sql").read_text(encoding="utf-8").lower()
    rollback = Path("config/postgres_migrations/089_process_activity_foundation.rollback.sql").read_text(encoding="utf-8").lower()
    assert "values (89,'process_activity_foundation')" in forward
    assert "migration 089 requires migration 088" in forward
    assert "create table public.process_episode_revisions" in forward
    assert "create table public.process_episode_evidence" in forward
    assert "references events_v2_core" not in forward
    assert "event_record_id bigint not null" in forward
    assert "source_event_sha256 bytea not null" in forward
    assert "source_facts_sha256 bytea not null" in forward
    assert "octet_length(command_line) <= 4096" in forward
    assert "parent_process_id between 1 and 4294967295" in forward
    assert "event_facts_v2_process_id_windows" in forward
    assert "event_facts_v2_powershell_process_id_windows" in forward
    assert "process_id::numeric between 1 and 4294967295" in forward
    for field, limit in (
        ("process_name", 512), ("user_sid", 512), ("user_name", 512),
        ("user_domain", 512), ("logon_id", 128),
    ):
        assert f"octet_length({field}) <= {limit}" in forward
    assert "security definer" in forward
    assert "write_process_episode_revision_v89" in forward
    assert "grant execute on function public.write_process_episode_revision_v89" in forward
    assert "grant select,insert on table process_episode_revisions" not in forward
    assert "process episode evidence count mismatch" in forward
    assert "process episode start evidence mismatch" in forward
    assert "process episode end evidence mismatch" in forward
    assert "process episode evidence replay conflict" in forward
    assert "set local lock_timeout='5s'" in forward
    assert "set local statement_timeout='30s'" in forward
    assert "v_marker_count <> 1" in forward
    assert "where version>88" in forward
    assert "refuses conflicting process episode objects" in forward
    assert "lacks public schema create" in forward
    assert "evidence_order between 0 and 255" in forward
    assert "before update or delete" in forward
    assert "rollback would discard process episode evidence" in rollback
    assert "where version>89" in rollback
    assert "rollback refuses later migrations" in rollback
    assert "drop table public.process_episode_evidence" in rollback
    assert "drop table public.process_episode_revisions" in rollback


def test_migration89_pins_trusted_namespace_and_qualifies_security_boundary() -> None:
    forward = Path("config/postgres_migrations/089_process_activity_foundation.sql").read_text(encoding="utf-8").lower()
    rollback = Path("config/postgres_migrations/089_process_activity_foundation.rollback.sql").read_text(encoding="utf-8").lower()
    assert "set local search_path=pg_catalog,public" in forward
    assert "a.grantee=0 and a.privilege_type='create'" in forward
    assert "not pg_has_role(r.oid,'adlog_storage_owner','member')" in forward
    assert "set search_path=pg_catalog" in forward
    for fragment in (
        "public.schema_migrations", "public.event_facts_v2",
        "public.process_episode_revisions", "public.process_episode_evidence",
        "public.write_process_episode_revision_v89",
        "public.process_episode_evidence_reject_mutation",
        "grant execute on function public.write_process_episode_revision_v89(pg_catalog.jsonb)",
    ):
        assert fragment in forward
    assert "set local search_path=pg_catalog,public" in rollback
    for fragment in (
        "public.schema_migrations", "public.event_facts_v2",
        "public.process_episode_revisions", "public.process_episode_evidence",
        "public.write_process_episode_revision_v89",
        "public.process_episode_evidence_reject_mutation",
    ):
        assert fragment in rollback


def test_database_writer_derives_non_fabricable_identity_ordering_and_manifest_shape() -> None:
    forward = Path("config/postgres_migrations/089_process_activity_foundation.sql").read_text(encoding="utf-8").lower()
    assert "v_expected_episode_id" in forward
    assert "v_expected_revision_id" in forward
    assert "v_derived_ordering_state" in forward
    assert "process episode derived identity mismatch" in forward
    assert "process episode derived ordering mismatch" in forward
    assert "jsonb_object_keys(value))<>15" in forward
    assert "process episode evidence object shape mismatch" in forward
    assert forward.index("process episode evidence object shape mismatch") < forward.index(
        "where idempotency_key=v_idempotency"
    )


def test_database_writer_rejects_extra_and_oversized_top_level_payloads() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    assert "process episode writer payload shape mismatch" in forward
    shape = forward[:forward.index("process episode writer payload shape mismatch")]
    assert "jsonb_object_keys(p)" in shape
    assert "p ?& array[" in shape
    assert "process episode writer payload exceeds" in forward
    assert "octet_length(p::text)" in forward
    assert forward.index("process episode writer payload exceeds") < forward.index(
        "v_revision_id :="
    )


def test_database_writer_rejects_alternate_ignored_top_level_state() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    assert "process episode writer top-level state mismatch" in forward
    assert "p - array[" in forward
    assert "] <> v_state" in forward


def test_database_writer_validates_every_evidence_atom_against_hot_authorities_before_insert() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    for authority in (
        "public.events_v2_core",
        "public.event_facts_v2",
        "public.storage_v2_channel",
        "public.normalized_events",
    ):
        assert authority in forward
    for exact_match in (
        "source.id=(item.value->>'source_event_id')::integer",
        "source.domain_id<>(item.value->>'domain_id')::bigint",
        "source.server_id<>(item.value->>'source_host_id')::bigint",
        "source.time_created_utc<>(item.value->>'observed_at_utc')::timestamptz",
        "channel.value<>(item.value->>'source_channel')",
        "source.event_record_id<>(item.value->>'event_record_id')::bigint",
        "source.normalized_hash<>decode(item.value->>'source_event_sha256','hex')",
        "facts.source_facts_sha256<>decode(item.value->>'source_facts_sha256','hex')",
        "normalized.semantic_type=item.value->>'semantic_type'",
    ):
        assert exact_match in forward
    assert "process episode evidence does not match authoritative hot source" in forward
    assert forward.index(
        "process episode evidence does not match authoritative hot source"
    ) < forward.index("insert into public.process_episode_revisions(")
    assert "confirmed_end_at_utc >= started_at_utc" not in forward


def test_database_writer_pins_one_authoritative_normalized_row_and_digest() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    assert "semantic_contract_version integer not null" in forward
    assert "normalizer_id text not null" in forward
    assert "normalizer_version text not null" in forward
    assert "semantic_sha256 bytea not null" in forward
    assert "jsonb_object_keys(value))<>15" in forward
    for exact_match in (
        "normalized.semantic_contract_version=(item.value->>'semantic_contract_version')::integer",
        "normalized.normalizer_id=item.value->>'normalizer_id'",
        "normalized.normalizer_version=item.value->>'normalizer_version'",
        "normalized.semantic_sha256=decode(item.value->>'semantic_sha256','hex')",
        "facts.source_facts_sha256<>decode(item.value->>'source_facts_sha256','hex')",
    ):
        assert exact_match in forward
    assert "select count(*) from public.normalized_events normalized" in forward
    assert ")<>1" in forward


def test_database_writer_rejects_fabricated_boot_event_identity() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    assert "process episode boot evidence mismatch" in forward
    validation = forward[:forward.index("process episode boot evidence mismatch")]
    assert "value->>'evidence_role'='boot_scope'" in validation
    assert "value->>'semantic_type'='system.boot.boundary'" in validation
    assert "(value->>'source_event_id')::bigint=(v_state->>'boot_event_id')::bigint" in validation
    assert forward.index("process episode boot evidence mismatch") < forward.index(
        "select * into v_existing from public.process_episode_revisions"
    )


def test_database_writer_qualifies_json_manifest_value_against_channel_value() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    validation = forward[
        forward.index("-- validate caller-supplied identity/provenance only"):
        forward.index("process episode evidence does not match authoritative hot source")
    ]
    assert "from jsonb_array_elements(v_manifest) item(value)" in validation
    assert "where item.value->>'source_event_id' is null" in validation
    assert "channel.value<>(item.value->>'source_channel')" in validation
    assert "normalized.semantic_type=item.value->>'semantic_type'" in validation


def test_exact_replay_is_verified_from_durable_evidence_after_hot_source_expiry() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    replay_lookup = forward.index(
        "select * into v_existing from public.process_episode_revisions"
    )
    hot_validation = forward.index(
        "process episode evidence does not match authoritative hot source"
    )
    assert replay_lookup < hot_validation

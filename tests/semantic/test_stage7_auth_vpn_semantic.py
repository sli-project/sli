from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.sli.semantic.semantic_processing import (
    StoredEvent,
    assemble_canonical_actions,
    normalize_windows_event,
)
from server.sli.storage.warm_session_lifecycle import (
    ContinuityDeclaration,
    assemble_authentication_sessions,
    authentication_evidence_from_normalized,
)
from server.source_packs.radius.accounting import (
    DATABASE_COMPATIBLE_COLUMNS,
    build_session_observation,
    parse_database_compatible_record,
)
from server.source_packs.radius.session_read_model import (
    RadiusLifecycleInput,
    fold_radius_sessions,
)


PROVIDER = "Microsoft-Windows-Security-Auditing"


def _windows_event(
    source_event_id: int,
    windows_event_id: int,
    data: dict[str, str] | None = None,
    *,
    minute: int = 0,
    provider: str = PROVIDER,
) -> StoredEvent:
    return StoredEvent(
        event_id=source_event_id,
        windows_event_id=windows_event_id,
        channel="Security",
        server="DC1",
        occurred_at_utc=datetime(2026, 8, 25, 1, minute, tzinfo=timezone.utc),
        event_data=data or {},
        provider=provider,
        source_host_id=17,
    )


@pytest.mark.parametrize(
    ("event_id", "semantic_type", "result_code", "result"),
    [
        (4634, "authentication.session.ended", None, None),
        (4647, "authentication.logout.requested", None, None),
        (4768, "authentication.kerberos.tgt.requested", "0x0", "success"),
        (4769, "authentication.kerberos.service_ticket.requested", "0x0", "success"),
        (4770, "authentication.kerberos.service_ticket.renewed", "0x0", "success"),
        (4771, "authentication.kerberos.preauthentication.failed", "0x18", "failure"),
        (4773, "authentication.kerberos.service_ticket.failed", "0x18", "failure"),
        (4776, "authentication.credentials.validated", "0x0", "success"),
    ],
)
def test_authentication_source_events_normalize_only_for_exact_descriptor(
    event_id: int,
    semantic_type: str,
    result_code: str | None,
    result: str | None,
) -> None:
    data = {
        "TargetUserName": "alice",
        "TargetDomainName": "EXAMPLE",
        "TargetLogonId": "0xabc",
        "Status": result_code or "0x0",
    }
    normalized = normalize_windows_event(_windows_event(event_id, event_id, data))
    wrong_provider = normalize_windows_event(
        _windows_event(event_id + 100_000, event_id, data, provider="Wrong-Provider")
    )

    assert normalized.semantic_type == semantic_type
    if result_code is not None:
        assert normalized.facts["result_code"] == result_code
        assert normalized.facts["result_code_state"] == "observed"
        assert normalized.facts["result"] == result
    assert wrong_provider.semantic_type == "event.unknown"


def test_4772_remains_defined_but_not_emitted_and_missing_codes_stay_unknown() -> None:
    reserved = normalize_windows_event(_windows_event(4772, 4772))
    failed = normalize_windows_event(_windows_event(4625, 4625))
    kerberos = normalize_windows_event(_windows_event(4771, 4771))
    validation = normalize_windows_event(_windows_event(4776, 4776))

    assert reserved.semantic_type == "event.unknown"
    assert reserved.quality["semantic_mapping_status"] == "defined_but_not_emitted"
    assert reserved.quality["defined_but_not_emitted"] is True
    for normalized in (failed, kerberos, validation):
        assert normalized.facts["result_code_state"] == "unknown"
        assert normalized.facts["result"] == "unknown"
        assert "result_code" not in normalized.facts


def test_4624_emits_one_independent_evidence_bearing_action() -> None:
    normalized = normalize_windows_event(_windows_event(
        1001,
        4624,
        {"TargetUserName": "alice", "TargetLogonId": "0xabc"},
    ))

    actions = assemble_canonical_actions([normalized])

    assert len(actions) == 1
    action = actions[0]
    assert action.action_kind == "authentication.session.created"
    assert action.source_event_ids == (1001,)
    assert action.attributes["source_evidence"] == [
        {"source_event_id": 1001, "semantic_sha256": normalized.semantic_sha256}
    ]


def test_authentication_and_nps_events_remain_independent_actions() -> None:
    windows_ids = [4634, 4647, 4625, 4648, 4672, 4768, 4769, 4770, 4771, 4773, 4776]
    windows = [
        normalize_windows_event(_windows_event(
            2000 + event_id,
            event_id,
            {
                "TargetUserName": "alice",
                "TargetLogonId": "0xabc",
                "SubjectLogonId": "0xabc",
            },
            minute=1,
        ))
        for event_id in windows_ids
    ]
    nps = [
        normalize_windows_event(StoredEvent(
            event_id=9000 + event_id,
            windows_event_id=event_id,
            channel="Security",
            server="NPS01",
            occurred_at_utc=datetime(2026, 8, 25, 1, 1, tzinfo=timezone.utc),
            event_data={"AccountSessionIdentifier": "same-native-value"},
            provider=PROVIDER,
            source_host_id=32,
        ))
        for event_id in (6272, 6273)
    ]

    actions = assemble_canonical_actions(windows + nps)

    assert len(actions) == len(windows) + len(nps)
    assert all(len(action.source_event_ids) == 1 for action in actions)
    assert all(len(action.attributes["source_evidence"]) == 1 for action in actions)
    privileged = next(
        action for action in actions
        if action.action_kind == "authentication.privileged_session.created"
    )
    assert privileged.action_kind != "privilege.escalation"
    assert privileged.attributes["observed_facts"][0]["security_assertion"] == (
        "privileged_session_observed_not_privilege_escalation"
    )
    nps_actions = [action for action in actions if action.action_kind.startswith("remote_access.")]
    assert len(nps_actions) == 2
    assert all(action.attributes["session_independent"] is True for action in nps_actions)


def test_full_windows_boot_scoped_path_produces_complete_exact_session() -> None:
    source = [
        _windows_event(10, 4608, {}, minute=0),
        _windows_event(11, 4624, {
            "TargetUserName": "alice", "TargetLogonId": "0xabc", "LogonType": "3",
        }, minute=1),
        _windows_event(12, 4672, {
            "SubjectUserName": "alice", "SubjectLogonId": "0xabc", "PrivilegeList": "SeBackupPrivilege",
        }, minute=2),
        _windows_event(13, 4634, {"TargetLogonId": "0xabc"}, minute=6),
    ]
    normalized = [normalize_windows_event(item) for item in source]
    actions = assemble_canonical_actions(normalized)
    evidence = [
        authentication_evidence_from_normalized(item, source_record_id=100 + index)
        for index, item in enumerate(normalized)
    ]
    proof = ContinuityDeclaration(
        scope_identity="stage7-fixture",
        descriptor_source="sli.windows.ad-dc",
        descriptor_stream="Security",
        server_id=17,
        channel_id=1,
        provider_name=PROVIDER,
        channel_generation_identity="boot-generation-1",
        source_event_ids=tuple(item.source_event_id for item in evidence),
        source_hashes=tuple(item.normalized_hash for item in evidence),
        first_event_record_id=100,
        last_event_record_id=103,
        completeness="complete",
    )

    sessions = assemble_authentication_sessions(evidence, [proof])

    assert {action.action_kind for action in actions} == {
        "authentication.session.created",
        "authentication.privileged_session.created",
        "authentication.session.ended",
    }
    assert len(sessions) == 1
    session = sessions[0]
    assert session.completeness == "complete"
    assert session.duration_seconds == 300
    assert session.source_event_ids == (10, 11, 13)
    assert session.source_hashes == tuple(
        item.semantic_sha256 for item in (normalized[0], normalized[1], normalized[3])
    )
    assert session.privilege_source_event_id == 12
    assert session.privilege_normalized_hash == normalized[2].semantic_sha256


def test_incomplete_windows_path_preserves_missing_stop_without_duration() -> None:
    normalized = [
        normalize_windows_event(_windows_event(20, 4608, {}, minute=0)),
        normalize_windows_event(_windows_event(
            21, 4624, {"TargetLogonId": "0xdef"}, minute=1,
        )),
    ]
    evidence = [
        authentication_evidence_from_normalized(item, source_record_id=200 + index)
        for index, item in enumerate(normalized)
    ]
    proof = ContinuityDeclaration(
        scope_identity="stage7-incomplete-fixture",
        descriptor_source="sli.windows.ad-dc",
        descriptor_stream="Security",
        server_id=17,
        channel_id=1,
        provider_name=PROVIDER,
        channel_generation_identity="boot-generation-2",
        source_event_ids=(20, 21),
        source_hashes=tuple(item.semantic_sha256 for item in normalized),
        first_event_record_id=200,
        last_event_record_id=201,
        completeness="complete",
    )

    session = assemble_authentication_sessions(evidence, [proof])[0]

    assert session.completeness == "missing_stop"
    assert session.duration_seconds is None
    assert session.source_event_ids == (20, 21)


def test_4647_is_supplemental_and_4648_attaches_only_to_exact_native_key() -> None:
    source = [
        _windows_event(30, 4608, {}, minute=0),
        _windows_event(31, 4624, {"TargetLogonId": "0xaaa"}, minute=1),
        _windows_event(32, 4648, {"SubjectLogonId": "0xaaa"}, minute=2),
        _windows_event(33, 4647, {"TargetLogonId": "0xaaa"}, minute=3),
        _windows_event(34, 4648, {"SubjectLogonId": "0xbbb"}, minute=4),
    ]
    normalized = [normalize_windows_event(item) for item in source]
    evidence = [
        authentication_evidence_from_normalized(item, source_record_id=300 + index)
        for index, item in enumerate(normalized)
    ]
    proof = ContinuityDeclaration(
        scope_identity="stage7-supplemental-fixture",
        descriptor_source="sli.windows.ad-dc",
        descriptor_stream="Security",
        server_id=17,
        channel_id=1,
        provider_name=PROVIDER,
        channel_generation_identity="boot-generation-3",
        source_event_ids=tuple(item.source_event_id for item in evidence),
        source_hashes=tuple(item.normalized_hash for item in evidence),
        first_event_record_id=300,
        last_event_record_id=304,
        completeness="complete",
    )

    sessions = assemble_authentication_sessions(evidence, [proof])

    session = next(item for item in sessions if item.logon_source_event_id == 31)
    assert session.completeness == "missing_stop"
    assert session.duration_seconds is None
    assert session.supplemental_logout_source_event_ids == (33,)
    assert session.explicit_credentials_source_event_ids == (32,)
    assert session.explicit_credentials_normalized_hashes == (normalized[2].semantic_sha256,)
    assert 34 not in session.explicit_credentials_source_event_ids


def test_supplemental_fact_after_reboot_never_attaches_to_prior_logon_id() -> None:
    source = [
        _windows_event(40, 4608, {}, minute=0),
        _windows_event(41, 4624, {"TargetLogonId": "0xaaa"}, minute=1),
        _windows_event(42, 4608, {}, minute=2),
        _windows_event(43, 4648, {"SubjectLogonId": "0xaaa"}, minute=3),
    ]
    normalized = [normalize_windows_event(item) for item in source]
    evidence = [
        authentication_evidence_from_normalized(item, source_record_id=400 + index)
        for index, item in enumerate(normalized)
    ]
    proof = ContinuityDeclaration(
        scope_identity="stage7-reboot-fixture",
        descriptor_source="sli.windows.ad-dc",
        descriptor_stream="Security",
        server_id=17,
        channel_id=1,
        provider_name=PROVIDER,
        channel_generation_identity="boot-generation-4",
        source_event_ids=tuple(item.source_event_id for item in evidence),
        source_hashes=tuple(item.normalized_hash for item in evidence),
        first_event_record_id=400,
        last_event_record_id=403,
        completeness="complete",
    )

    session = assemble_authentication_sessions(evidence, [proof])[0]

    assert session.logon_source_event_id == 41
    assert session.explicit_credentials_source_event_ids == ()


def _radius_line(status: str, clock: str) -> str:
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    positions = {name: index for index, name in enumerate(DATABASE_COMPATIBLE_COLUMNS)}
    for name, value in {
        "ComputerName": "NPS01",
        "ServiceName": "IAS",
        "Record-Date": "08/25/2026",
        "Record-Time": clock,
        "Packet-Type": "4",
        "User-Name": "EXAMPLE\\alice",
        "NAS-Identifier": "VPN-GW-01",
        "Acct-Status-Type": status,
        "Acct-Session-Id": "opaque-session-7",
    }.items():
        row[positions[name]] = value
    return ",".join(row)


def test_radius_pipeline_folds_exact_evidence_and_preserves_honest_variants() -> None:
    principal = "sid:S-1-5-21-100000003-200000003-300000003-1101"
    observations = [
        build_session_observation(
            parse_database_compatible_record(_radius_line(status, clock)),
            source_instance_id="radius-stage7-fixture",
            exact_principal_key=principal,
            source_timezone_id="N. Central Asia Standard Time",
            source_utc_offset_minutes=420,
        )
        for status, clock in (("1", "09:00:00"), ("3", "09:05:00"), ("2", "09:10:00"))
    ]
    assert all(item is not None for item in observations)
    exact_inputs = [
        RadiusLifecycleInput(
            observation_id=item.canonical_record_sha256,
            lifecycle_event=item.lifecycle_event,
            identity_state="exact",
            timestamp_state="ready",
            session_identity_key=item.session_identity_key,
            exact_principal_key=item.exact_principal_key,
            observed_at_utc=item.observed_at_utc,
            evidence_sha256=item.canonical_record_sha256,
        )
        for item in observations if item is not None
    ]

    complete = fold_radius_sessions(exact_inputs).sessions[0]
    missing_stop = fold_radius_sessions(exact_inputs[:2]).sessions[0]
    unresolved = fold_radius_sessions([
        RadiusLifecycleInput(
            observation_id="unresolved",
            lifecycle_event="start",
            identity_state="unresolved",
            timestamp_state="ready",
            session_identity_key=None,
            exact_principal_key=None,
            observed_at_utc=exact_inputs[0].observed_at_utc,
            evidence_sha256=exact_inputs[0].evidence_sha256,
        )
    ])

    assert complete.completeness == "complete"
    assert complete.duration_seconds == 600
    assert complete.observation_ids == tuple(item.observation_id for item in exact_inputs)
    assert complete.evidence_sha256s == tuple(item.evidence_sha256 for item in exact_inputs)
    assert missing_stop.completeness == "missing_stop"
    assert missing_stop.duration_seconds is None
    assert unresolved.sessions == ()
    assert unresolved.unresolved_identity_observations == 1

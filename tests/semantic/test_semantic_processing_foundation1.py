from datetime import datetime, timezone

from server.sli.entities.identity_resolution import IDENTITY_RESOLUTION_VERSION
from server.sli.semantic import semantic_processing
from server.sli.semantic.semantic_processing import (
    NORMALIZER_VERSION,
    NormalizedEvent,
    SemanticFeatureSettings,
    StoredEvent,
    apply_identity_role_overrides,
    assemble_canonical_actions,
    normalize_windows_event,
    process_shadow_event,
)


def _event(
    event_id: int,
    windows_id: int,
    data: dict[str, str],
    *,
    minute: int = 0,
    correlation_id: str | None = None,
    channel: str = "Security",
    provider: str | None = "Microsoft-Windows-Security-Auditing",
) -> StoredEvent:
    return StoredEvent(
        event_id,
        windows_id,
        channel,
        "DC1",
        datetime(2026, 7, 18, 3, minute, tzinfo=timezone.utc),
        data,
        provider=provider,
        correlation_id=correlation_id,
        source_host_id=1,
    )


def _fragment(
    event_id: int,
    semantic_type: str,
    *,
    minute: int = 0,
    roles: dict[str, str] | None = None,
    facts: dict[str, object] | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        source_event_id=event_id,
        semantic_type=semantic_type,
        occurred_at_utc=datetime(2026, 7, 18, 3, minute, tzinfo=timezone.utc),
        roles=roles or {"source_host": "1"},
        facts=facts or {},
        quality={"event_data_encoding": "named"},
        semantic_sha256=f"{event_id:064x}",
    )


def test_semantic_features_fail_closed_and_preserve_dependency_order() -> None:
    assert SemanticFeatureSettings.from_env({}) == SemanticFeatureSettings()
    assert not SemanticFeatureSettings.from_env({"ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "true"}).assembly_enabled
    enabled = SemanticFeatureSettings.from_env({
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "true",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "true",
        "ADLOG_SEMANTIC_CORRELATION_ENABLED": "true",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "true",
        "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "true",
    })
    assert enabled.finding_creation_enabled and enabled.risk_engine_enabled


def test_identity_rule_version_changes_normalized_identity(monkeypatch) -> None:
    event = _event(
        900,
        4624,
        {
            "TargetUserName": "user",
            "TargetDomainName": "DOMAIN",
            "TargetLogonId": "0x900",
        },
    )
    first = normalize_windows_event(event)
    assert first.quality["identity_resolution_version"] == (
        IDENTITY_RESOLUTION_VERSION
    )
    assert NORMALIZER_VERSION.endswith(
        f"identity-{IDENTITY_RESOLUTION_VERSION}"
    )
    monkeypatch.setattr(
        semantic_processing,
        "IDENTITY_RESOLUTION_VERSION",
        "test-next-version",
    )
    second = normalize_windows_event(event)
    assert second.roles == first.roles
    assert second.facts == first.facts
    assert second.semantic_sha256 != first.semantic_sha256


def test_4672_and_4648_are_not_promoted_to_escalation_or_high_risk() -> None:
    privileged = normalize_windows_event(_event(1, 4672, {"SubjectUserSid": "S-1-5-21-1", "SubjectLogonId": "0x123"}))
    credentials = normalize_windows_event(_event(2, 4648, {"SubjectUserName": "user"}))
    assert privileged.semantic_type == "authentication.privileged_session.created"
    assert privileged.facts["security_assertion"] == "privileged_session_observed_not_privilege_escalation"
    assert credentials.semantic_type == "authentication.explicit_credentials.used"
    assert credentials.facts["security_assertion"] == "explicit_credentials_observed_no_high_risk_by_default"


def test_group_change_exposes_explicit_roles_and_unknown_event_is_not_finding() -> None:
    group = normalize_windows_event(_event(3, 4728, {"SubjectUserName": "admin", "TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-21-2"}))
    unknown = normalize_windows_event(_event(4, 203, {"NotAName": "positional values are rejected"}))
    assert group.semantic_type == "group.member.added" and group.facts["change"] == "added"
    assert group.roles["container_entity"] == "S-1-5-32-544"
    assert group.roles["target_entity"] == "S-1-5-21-2"
    assert unknown.semantic_type == "event.unknown"
    assert unknown.quality["event_data_encoding"] == "named"


def test_group_add_and_task_registration_assemble_as_independent_actions() -> None:
    group = normalize_windows_event(
        _event(
            50,
            4728,
            {
                "SubjectUserName": "admin",
                "TargetSid": "S-1-5-32-544",
                "MemberSid": "S-1-5-21-2",
            },
        )
    )
    task = normalize_windows_event(
        _event(
            51,
            106,
            {
                "TaskName": "\\SLI\\Example",
                "UserContext": "SYSTEM",
            },
            channel="Microsoft-Windows-TaskScheduler/Operational",
            provider="Microsoft-Windows-TaskScheduler",
        )
    )
    assert task.semantic_type == "scheduled_task.created.fragment"
    assert task.facts["task_name"] == "\\SLI\\Example"
    actions = assemble_canonical_actions((group, task))
    assert {(item.action_kind, item.source_event_ids) for item in actions} == {
        ("group.member.added", (50,)),
        ("scheduled_task.created", (51,)),
    }


def test_4719_normalizes_exact_audit_policy_fields_and_never_coalesces() -> None:
    data = {
        "SubjectUserSid": "S-1-5-18",
        "SubjectLogonId": "0x3e7",
        "CategoryId": "%%8274",
        "SubcategoryId": "%%12807",
        "SubcategoryGuid": "{00000000-0000-4000-8000-000000000012}",
        "AuditPolicyChanges": "%%8448, %%8450",
    }
    first = normalize_windows_event(_event(60, 4719, data, minute=1))
    second = normalize_windows_event(_event(61, 4719, data, minute=1))

    assert first.semantic_type == "audit.policy.changed"
    assert first.roles["actor"] == "sid:dc1:S-1-5-18"
    assert first.quality["identity_roles"]["actor"]["state"] == "resolved"
    assert first.facts["audit_subcategory_guid"] == data["SubcategoryGuid"]
    assert first.facts["audit_policy_changes"] == data["AuditPolicyChanges"]

    actions = assemble_canonical_actions((first, second))
    assert [item.source_event_ids for item in actions] == [(60,), (61,)]
    assert {item.action_kind for item in actions} == {"audit.policy.changed"}


def test_undocumented_semantic_donor_mappings_fail_closed() -> None:
    for event_id, channel, provider in (
        (999999, "Security", "Microsoft-Windows-Security-Auditing"),
        (4624, "Security", "Unregistered-Provider"),
    ):
        normalized = normalize_windows_event(
            _event(
                event_id,
                event_id,
                {},
                channel=channel,
                provider=provider,
            )
        )
        assert normalized.semantic_type == "event.unknown"
        assert normalized.quality["semantic_mapping_status"] in {
            "descriptor_identity_missing_or_mismatched",
            "source_pack_or_provider_unresolved",
        }


def test_assembler_only_uses_declared_material_identities() -> None:
    first = _fragment(
        5,
        "service.installed.fragment",
        facts={"service_name": "svc", "service_file": "C:/svc.exe"},
    )
    second = _fragment(
        6,
        "service.installed.fragment",
        facts={"service_name": "svc", "service_file": "C:/svc.exe"},
    )
    different = _fragment(
        7,
        "service.installed.fragment",
        facts={"service_name": "other", "service_file": "C:/svc.exe"},
    )
    actions = assemble_canonical_actions([different, second, first])
    assert {(action.action_kind, action.source_event_ids) for action in actions} == {
        ("service.installed", (5,)),
        ("service.installed", (6,)),
        ("service.installed", (7,)),
    }
    assert {action.status for action in actions} == {"observed"}


def test_declared_coalescing_window_groups_only_matching_fragments() -> None:
    directory_a = _fragment(
        9,
        "directory.attribute.changed.fragment",
        minute=1,
        roles={"source_host": "1", "actor": "admin"},
        facts={"object": "CN=A", "attribute": "member", "operation_correlation_id": "operation-1"},
    )
    directory_b = _fragment(
        10,
        "directory.attribute.changed.fragment",
        minute=4,
        roles={"source_host": "1", "actor": "admin"},
        facts={"object": "CN=A", "attribute": "member", "operation_correlation_id": "operation-1"},
    )
    later = _fragment(
        11,
        "directory.attribute.changed.fragment",
        minute=6,
        roles={"source_host": "1", "actor": "admin"},
        facts={"object": "CN=A", "attribute": "member", "operation_correlation_id": "operation-2"},
    )
    clear_security = normalize_windows_event(
        _event(
            12,
            1102,
            {},
            minute=2,
            provider="Microsoft-Windows-Eventlog",
        )
    )
    clear_system = _fragment(
        13,
        "eventlog.cleared.fragment",
        minute=3,
        facts={"cleared_log": "Security"},
    )
    actions = assemble_canonical_actions([directory_a, directory_b, later, clear_security, clear_system])
    assert {(item.action_kind, item.source_event_ids) for item in actions} == {
        ("directory.attribute.changed", (9, 10)),
        ("directory.attribute.changed", (11,)),
        ("eventlog.cleared", (12,)),
        ("eventlog.cleared", (13,)),
    }


def test_5136_assembly_retains_before_after_values_and_quality() -> None:
    common = {
        "object": "g",
        "attribute": "member",
        "operation_correlation_id": "operation-3",
    }
    added = _fragment(
        30,
        "directory.attribute.changed.fragment",
        minute=1,
        roles={"source_host": "1", "actor": "S-1"},
        facts={**common, "added_values": ["new"]},
    )
    removed = _fragment(
        31,
        "directory.attribute.changed.fragment",
        minute=2,
        roles={"source_host": "1", "actor": "S-1"},
        facts={**common, "removed_values": ["old"]},
    )
    action = assemble_canonical_actions([added, removed])[0]
    assert action.attributes["added_values"] == ["new"]
    assert action.attributes["removed_values"] == ["old"]
    assert action.attributes["quality"] == "complete"


def test_5136_different_correlation_ids_never_coalesce() -> None:
    common = {
        "ObjectGUID": "g",
        "AttributeLDAPDisplayName": "member",
        "SubjectUserSid": "S-1",
    }
    first = _fragment(
        40,
        "directory.attribute.changed.fragment",
        minute=1,
        roles={"source_host": "1", "actor": "S-1"},
        facts={"object": "g", "attribute": "member", "operation_correlation_id": "a"},
    )
    second = _fragment(
        41,
        "directory.attribute.changed.fragment",
        minute=2,
        roles={"source_host": "1", "actor": "S-1"},
        facts={"object": "g", "attribute": "member", "operation_correlation_id": "b"},
    )
    assert [item.source_event_ids for item in assemble_canonical_actions([first, second])] == [
        (40,),
        (41,),
    ]


def test_eventlog_clear_requires_exact_provider_and_source_channel() -> None:
    unrelated = normalize_windows_event(
        _event(
            42,
            1102,
            {},
            channel="Security",
            provider="Unrelated-Provider",
        )
    )
    legitimate = normalize_windows_event(
        _event(
            43,
            1102,
            {},
            channel="Security",
            provider="Microsoft-Windows-Eventlog",
        )
    )
    assert unrelated.semantic_type == "event.unknown"
    assert legitimate.semantic_type == "eventlog.cleared.fragment"


def test_account_roles_use_identity_ladder_and_mark_provisional_keys() -> None:
    provisional = normalize_windows_event(
        _event(
            48,
            4625,
            {
                "TargetUserName": "Alice",
                "TargetDomainName": "EXAMPLE",
                "IpAddress": "192.0.2.10",
            },
        )
    )
    unresolved = normalize_windows_event(
        _event(49, 4648, {"SubjectUserName": "Operator"})
    )

    assert provisional.roles["affected_entity"] == "sam:example:alice"
    assert provisional.quality["identity_roles"]["affected_entity"] == {
        "key": "sam:example:alice",
        "state": "provisional",
        "step": 4,
        "provisional": True,
        "confidence": 0.6,
        "reason": None,
        "aliases": ["sam:example:alice"],
        "rule": "identity-ladder/v1",
    }
    assert provisional.quality["provisional_identity_roles"] == [
        "affected_entity"
    ]
    assert unresolved.roles["actor"] == "name:operator"
    assert unresolved.quality["unresolved_identity_roles"] == ["actor"]


def test_directory_action_exact_correlation_crosses_bucket_without_false_fallback_merge() -> None:
    common = {
        "ObjectGUID": "g",
        "AttributeLDAPDisplayName": "member",
        "SubjectUserSid": "S-1",
    }
    correlated_a = _fragment(
        44,
        "directory.attribute.changed.fragment",
        minute=4,
        roles={"source_host": "1", "actor": "S-1"},
        facts={"object": "g", "attribute": "member", "operation_correlation_id": "exact-operation"},
    )
    correlated_b = _fragment(
        45,
        "directory.attribute.changed.fragment",
        minute=6,
        roles={"source_host": "1", "actor": "S-1"},
        facts={"object": "g", "attribute": "member", "operation_correlation_id": "exact-operation"},
    )
    uncorrelated_a = _fragment(
        46,
        "directory.attribute.changed.fragment",
        minute=7,
        roles={"source_host": "1", "actor": "S-1"},
        facts={"object": "g", "attribute": "member"},
    )
    uncorrelated_b = _fragment(
        47,
        "directory.attribute.changed.fragment",
        minute=8,
        roles={"source_host": "1", "actor": "S-1"},
        facts={"object": "g", "attribute": "member"},
    )

    actions = assemble_canonical_actions(
        [correlated_a, correlated_b, uncorrelated_a, uncorrelated_b]
    )

    assert sorted(item.source_event_ids for item in actions) == [
        (44, 45),
        (46,),
        (47,),
    ]


def test_service_install_without_a_native_key_keeps_each_source_event_separate() -> None:
    first = _fragment(
        50,
        "service.installed.fragment",
        facts={"service_name": "svc", "service_file": "C:/svc.exe"},
    )
    second = _fragment(
        51,
        "service.installed.fragment",
        facts={"service_name": "svc", "service_file": "C:/svc.exe"},
    )
    one = assemble_canonical_actions([first])[0]
    both = assemble_canonical_actions([first, second])
    assert one.source_event_ids == (50,)
    assert [action.source_event_ids for action in both] == [(50,), (51,)]
    assert {action.canonical_deduplication_key for action in both} == {
        one.canonical_deduplication_key,
        assemble_canonical_actions([second])[0].canonical_deduplication_key,
    }


def test_shadow_processing_is_no_write_and_disabled_by_default() -> None:
    event = _event(8, 1102, {}, provider="Microsoft-Windows-Eventlog")
    disabled = process_shadow_event(event, settings=SemanticFeatureSettings())
    enabled = process_shadow_event(event, settings=SemanticFeatureSettings(normalization_enabled=True, assembly_enabled=True))
    assert disabled.normalized is None and disabled.skipped_reason == "semantic_normalization_disabled"
    assert enabled.normalized is not None
    assert enabled.actions[0].action_kind == "eventlog.cleared"


def test_r7_identity_override_recomputes_provisional_semantic_identity() -> None:
    source = _event(
        61,
        4728,
        {
            "SubjectUserSid": "S-1-5-21-100000001-200000001-300000001-1001",
            "SubjectUserName": "admin",
            "SubjectDomainName": "EXAMPLE",
            "MemberName": "CN=User,DC=example,DC=test",
            "MemberSid": "S-1-0-0",
            "TargetUserName": "Domain Admins",
            "TargetDomainName": "EXAMPLE",
        },
    )
    provisional = normalize_windows_event(source)
    source_key = provisional.roles["affected_entity"]
    assert source_key.startswith("sam:")
    merged = apply_identity_role_overrides(
        provisional,
        {
            source_key: {
                "target_key": "sid:S-1-5-21-100000001-200000001-300000001-2002",
                "merge_id": "00000000-0000-4000-8000-000000000037",
            }
        },
    )
    assert merged.roles["affected_entity"] == "sid:S-1-5-21-100000001-200000001-300000001-2002"
    quality = merged.quality["identity_roles"]["affected_entity"]
    assert quality["state"] == "resolved"
    assert quality["provisional"] is False
    assert source_key in quality["aliases"]
    assert merged.quality["provisional_identity_roles"] == []
    assert merged.semantic_sha256 != provisional.semantic_sha256


def test_r7_identity_override_rejects_unproved_exact_role_rewrite() -> None:
    exact = normalize_windows_event(_event(
        62,
        1102,
        {"SubjectUserSid": "S-1-5-21-100000001-200000001-300000001-1001"},
        provider="Microsoft-Windows-Eventlog",
    ))
    source_key = exact.roles.get("actor")
    if source_key is None:
        source_key = exact.roles["source_host"]
    try:
        apply_identity_role_overrides(
            exact,
            {source_key: {"target_key": "sid:S-1-5-21-100000001-200000001-300000001-2002", "merge_id": "m"}},
        )
    except ValueError as exc:
        assert "identity" in str(exc)
    else:
        raise AssertionError("non-provisional role rewrite must fail closed")

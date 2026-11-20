from datetime import datetime, timedelta, timezone

import pytest

from server.sli.storage.warm_session_lifecycle import (
    AuthenticationEvidence,
    ContinuityDeclaration,
    SessionBoundary,
    WarmSessionLifecycleError,
    assemble_authentication_sessions,
    legacy_base_revision,
    load_contract,
    plan_revision,
)


NOW = datetime(2026, 8, 2, 1, 0, tzinfo=timezone.utc)


def boundary(event_id: int, role: str, when: datetime = NOW) -> SessionBoundary:
    return SessionBoundary(event_id, role, 1, 2, "0xabc", when, "a" * 64)


def test_contract_is_source_only_and_keeps_core_compatibility_owner() -> None:
    value = load_contract()
    assert value["component_owner"] == "core_hosted_compatibility"
    assert value["production_clickhouse_schema_applied"] is False
    assert value["runtime_enabled"] is False


def test_late_close_appends_hash_chained_revision_with_stable_identity() -> None:
    opened = plan_revision(None, boundary(101, "open"))
    closed = plan_revision(opened, boundary(102, "close", NOW + timedelta(minutes=5)))
    assert opened.state == "open" and closed.state == "closed"
    assert opened.session_uid == closed.session_uid
    assert closed.revision == 2
    assert closed.previous_revision_sha256 == opened.revision_sha256
    assert closed.logon_source_event_id == 101
    assert closed.logoff_source_event_id == 102


def test_out_of_order_open_closes_existing_orphan_without_identity_change() -> None:
    orphan = plan_revision(None, boundary(202, "close", NOW + timedelta(minutes=5)))
    closed = plan_revision(orphan, boundary(201, "open", NOW))
    assert orphan.state == "orphan_logoff"
    assert closed.state == "closed"
    assert closed.session_uid == orphan.session_uid
    assert closed.logon_source_event_id == 201
    assert closed.logoff_source_event_id == 202


def test_late_close_can_extend_immutable_legacy_revision_zero() -> None:
    legacy = legacy_base_revision(
        session_uid="11" * 16,
        state="open",
        server_id=1,
        domain_id=7,
        channel_id=2,
        logon_id="0xabc",
        logon_source_event_id=100,
        logoff_source_event_id=None,
        logon_time_utc=NOW,
        logoff_time_utc=None,
    )

    closed = plan_revision(
        legacy,
        boundary(101, "close", NOW + timedelta(minutes=5)),
    )

    assert closed.revision == 1
    assert closed.session_uid == legacy.session_uid
    assert closed.domain_id == 7
    assert closed.previous_revision_sha256 is None


def test_mismatch_duplicate_and_out_of_window_fail_closed() -> None:
    opened = plan_revision(None, boundary(301, "open"))
    with pytest.raises(WarmSessionLifecycleError, match="duplicate_open"):
        plan_revision(opened, boundary(302, "open"))
    with pytest.raises(WarmSessionLifecycleError, match="close_window_invalid"):
        plan_revision(opened, boundary(303, "close", NOW + timedelta(days=2)))
    mismatch = boundary(304, "close", NOW + timedelta(minutes=1))
    mismatch = SessionBoundary(
        mismatch.source_event_id, mismatch.role, 99, mismatch.channel_id,
        mismatch.logon_id, mismatch.observed_at_utc, mismatch.normalized_hash,
    )
    with pytest.raises(WarmSessionLifecycleError, match="pair_mismatch"):
        plan_revision(opened, mismatch)


def test_boot_scoped_assembly_closes_only_with_exact_immutable_proof() -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(
        11, 101, 4624, NOW + timedelta(minutes=1), principal="EXAMPLE\\alice",
        host="WS01", logon_type="10",
    )
    closed = authentication_evidence(12, 103, 4634, NOW + timedelta(minutes=6))
    privilege = authentication_evidence(
        13, 102, 4672, NOW + timedelta(minutes=2), privilege_marker="admin",
    )
    proof = ContinuityDeclaration(
        scope_identity="collection:42:file:7",
        descriptor_source="sli.windows.ad-dc",
        descriptor_stream="Security",
        server_id=1,
        channel_id=2,
        provider_name="Microsoft-Windows-Security-Auditing",
        channel_generation_identity="generation-stable",
        source_event_ids=(10, 11, 12, 13),
        source_hashes=("a" * 64, "b" * 64, "c" * 64, "d" * 64),
        first_event_record_id=100,
        last_event_record_id=103,
        completeness="complete",
    )

    result = assemble_authentication_sessions(
        [closed, privilege, boot, opened], [proof],
    )

    assert len(result) == 1
    session = result[0]
    assert session.state == "closed"
    assert session.quality_reason == "complete"
    assert session.boot_source_event_id == 10
    assert session.logon_source_event_id == 11
    assert session.logoff_source_event_id == 12
    assert session.source_event_ids == (10, 11, 12)
    assert session.source_hashes == ("a" * 64, "b" * 64, "c" * 64)
    assert session.principal == "EXAMPLE\\alice"
    assert session.host == "WS01"
    assert session.logon_type == "10"
    assert session.privilege_marker == "admin"
    assert session.duration_seconds == 300


def test_three_complete_capture_segments_close_one_boot_scoped_session() -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1))
    privilege = authentication_evidence(
        13, 102, 4672, NOW + timedelta(minutes=2), privilege_marker="admin",
    )
    closed = authentication_evidence(12, 103, 4634, NOW + timedelta(minutes=6))
    proofs = [
        continuity_proof([boot, opened], scope_identity="capture-a"),
        continuity_proof([privilege], scope_identity="capture-b"),
        continuity_proof([closed], scope_identity="capture-c"),
    ]

    result = assemble_authentication_sessions(
        [closed, privilege, opened, boot], proofs,
    )

    assert len(result) == 1
    assert result[0].state == "closed"
    assert result[0].quality_reason == "complete"
    assert result[0].duration_seconds == 300
    assert result[0].privilege_source_event_id == 13

    recreated = [
        proofs[0],
        continuity_proof(
            [privilege], scope_identity="capture-b-recreated",
            channel_generation_identity="generation-recreated",
        ),
        proofs[2],
    ]
    failed_closed = assemble_authentication_sessions(
        [closed, privilege, opened, boot], recreated,
    )
    assert len(failed_closed) == 1
    assert failed_closed[0].state == "incomplete"
    assert failed_closed[0].quality_reason == "incomplete_coverage_gap"


def test_sparse_adjacent_chain_with_empty_middle_closes_boot_scoped_session() -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(11, 105, 4624, NOW + timedelta(minutes=1))
    closed = authentication_evidence(12, 125, 4634, NOW + timedelta(minutes=6))
    first = continuity_proof([boot, opened], scope_identity="capture-a")
    first = ContinuityDeclaration(
        **{**first.__dict__, "first_event_record_id": 100, "last_event_record_id": 110}
    )
    empty = ContinuityDeclaration(
        scope_identity="capture-empty",
        descriptor_source="sli.windows.ad-dc",
        descriptor_stream="Security",
        server_id=1,
        channel_id=2,
        provider_name="Microsoft-Windows-Security-Auditing",
        channel_generation_identity="generation-stable",
        source_event_ids=(),
        source_hashes=(),
        first_event_record_id=111,
        last_event_record_id=120,
        completeness="complete",
    )
    third = continuity_proof([closed], scope_identity="capture-c")
    third = ContinuityDeclaration(
        **{**third.__dict__, "first_event_record_id": 121, "last_event_record_id": 130}
    )

    result = assemble_authentication_sessions(
        [closed, opened, boot], [first, empty, third],
    )

    assert len(result) == 1
    assert result[0].state == "closed"
    assert result[0].quality_reason == "complete"


def test_missing_intermediate_capture_segment_keeps_cross_capture_session_incomplete() -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1))
    closed = authentication_evidence(12, 103, 4634, NOW + timedelta(minutes=6))
    proofs = [
        continuity_proof([boot, opened], scope_identity="capture-a"),
        continuity_proof([closed], scope_identity="capture-c"),
    ]

    result = assemble_authentication_sessions([boot, opened, closed], proofs)

    assert result[0].state == "incomplete"
    assert result[0].quality_reason == "incomplete_coverage_gap"
    assert result[0].duration_seconds is None


def test_privilege_marker_requires_an_exact_fact_inside_the_closed_session() -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1))
    closed = authentication_evidence(12, 102, 4634, NOW + timedelta(minutes=6))
    late_privilege = authentication_evidence(
        13, 103, 4672, NOW + timedelta(minutes=7), privilege_marker="admin",
    )

    result = assemble_authentication_sessions(
        [boot, opened, closed, late_privilege],
        [continuity_proof([boot, opened, closed])],
    )

    assert result[0].state == "closed"
    assert result[0].privilege_marker is None
    assert result[0].privilege_source_event_id is None


def test_incomplete_boundary_requires_accepted_continuity_before_promotion() -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1))

    unavailable = assemble_authentication_sessions([boot, opened], [])[0]
    accepted = assemble_authentication_sessions(
        [boot, opened], [continuity_proof([boot, opened])],
    )[0]

    assert unavailable.quality_reason == "incomplete_missing_close"
    assert unavailable.coverage_state == "unavailable"
    assert unavailable.promotion_eligible is False
    assert accepted.quality_reason == "incomplete_missing_close"
    assert accepted.coverage_state == "accepted"
    assert accepted.promotion_eligible is True

    duplicate = authentication_evidence(12, 102, 4624, NOW + timedelta(minutes=2))
    duplicate_unavailable = assemble_authentication_sessions(
        [boot, opened, duplicate], [],
    )[0]
    duplicate_accepted = assemble_authentication_sessions(
        [boot, opened, duplicate],
        [continuity_proof([boot, opened, duplicate])],
    )[0]
    assert duplicate_unavailable.quality_reason == "incomplete_duplicate_boundary"
    assert duplicate_unavailable.coverage_state == "unavailable"
    assert duplicate_unavailable.promotion_eligible is False
    assert duplicate_accepted.coverage_state == "accepted"
    assert duplicate_accepted.promotion_eligible is True


def test_4672_attachment_states_retain_relevant_evidence_on_incomplete_sessions() -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1))
    first = authentication_evidence(
        13, 102, 4672, NOW + timedelta(minutes=2), privilege_marker="admin",
    )
    second = authentication_evidence(
        14, 103, 4672, NOW + timedelta(minutes=3), privilege_marker="admin-2",
    )

    missing = assemble_authentication_sessions(
        [boot, opened], [continuity_proof([boot, opened])],
    )[0]
    unverified = assemble_authentication_sessions(
        [boot, opened, first], [continuity_proof([boot, opened])],
    )[0]
    ambiguous = assemble_authentication_sessions(
        [boot, opened, first, second],
        [continuity_proof([boot, opened, first, second])],
    )[0]
    exact = assemble_authentication_sessions(
        [boot, opened, first], [continuity_proof([boot, opened, first])],
    )[0]

    assert missing.privilege_attachment_state == "missing"
    assert unverified.privilege_attachment_state == "provenance_unverified"
    assert unverified.privilege_evidence_source_event_ids == (13,)
    assert unverified.privilege_evidence_normalized_hashes == ("d" * 64,)
    assert ambiguous.privilege_attachment_state == "ambiguous"
    assert ambiguous.privilege_evidence_source_event_ids == (13, 14)
    assert exact.privilege_attachment_state == "exact"
    assert exact.privilege_source_event_id == 13

    close_only = authentication_evidence(12, 104, 4634, NOW + timedelta(minutes=4))
    missing_open = assemble_authentication_sessions(
        [boot, first, close_only],
        [continuity_proof([boot, first, close_only])],
    )[0]
    assert missing_open.completeness == "missing_start"
    assert missing_open.privilege_attachment_state == "exact"
    assert missing_open.privilege_evidence_source_event_ids == (13,)


def test_supplements_do_not_attach_from_disconnected_complete_declaration() -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1))
    supplement = authentication_evidence(13, 102, 4648, NOW + timedelta(minutes=2))
    closed = authentication_evidence(12, 103, 4634, NOW + timedelta(minutes=3))
    accepted_boundaries = continuity_proof([boot, opened, closed])
    disconnected_supplement = continuity_proof(
        [supplement], scope_identity="disconnected-supplement",
    )

    session = assemble_authentication_sessions(
        [boot, opened, supplement, closed],
        [accepted_boundaries, disconnected_supplement],
    )[0]

    assert session.state == "closed"
    assert session.explicit_credentials_source_event_ids == ()


@pytest.mark.parametrize(
    ("descriptor_stream", "provider_name"),
    [
        ("System", "Microsoft-Windows-Security-Auditing"),
        ("Security", "Untrusted-Provider"),
    ],
)
def test_assembly_rejects_non_security_or_non_native_provider_scope(
    descriptor_stream: str, provider_name: str,
) -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1))
    closed = authentication_evidence(12, 102, 4634, NOW + timedelta(minutes=6))
    unsafe = [
        AuthenticationEvidence(
            **{**item.__dict__, "descriptor_stream": descriptor_stream,
               "provider_name": provider_name}
        )
        for item in (boot, opened, closed)
    ]

    with pytest.raises(WarmSessionLifecycleError, match="source_scope_invalid"):
        assemble_authentication_sessions(unsafe, [])


@pytest.mark.parametrize("proof_source", ["missing", "hash_mismatch"])
def test_privilege_marker_requires_its_own_covered_source_identity(
    proof_source: str,
) -> None:
    boot = authentication_evidence(10, 100, 4608, NOW)
    opened = authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1))
    privilege = authentication_evidence(
        13, 102, 4672, NOW + timedelta(minutes=2), privilege_marker="admin",
    )
    closed = authentication_evidence(12, 103, 4634, NOW + timedelta(minutes=6))
    proof_facts = [boot, opened, closed]
    if proof_source == "hash_mismatch":
        proof_facts.append(AuthenticationEvidence(
            **{**privilege.__dict__, "normalized_hash": "f" * 64}
        ))

    result = assemble_authentication_sessions(
        [boot, opened, privilege, closed], [continuity_proof(proof_facts)],
    )

    assert result[0].state == "closed"
    assert result[0].privilege_marker is None
    assert result[0].privilege_source_event_id is None


def test_same_logon_id_in_two_boot_scopes_never_cross_pairs() -> None:
    first = [
        authentication_evidence(10, 100, 4608, NOW),
        authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1)),
        authentication_evidence(12, 102, 4634, NOW + timedelta(minutes=2)),
    ]
    second = [
        authentication_evidence(20, 200, 4608, NOW + timedelta(hours=1)),
        authentication_evidence(21, 201, 4624, NOW + timedelta(hours=1, minutes=1)),
        authentication_evidence(22, 202, 4634, NOW + timedelta(hours=1, minutes=2)),
    ]

    result = assemble_authentication_sessions(
        list(reversed(first + second)),
        [continuity_proof(first), continuity_proof(second)],
    )

    assert [(item.state, item.source_event_ids) for item in result] == [
        ("closed", (10, 11, 12)), ("closed", (20, 21, 22)),
    ]


def test_reordered_reboot_evidence_has_one_deterministic_incomplete_identity() -> None:
    facts = [
        authentication_evidence(10, 100, 4608, NOW),
        authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1)),
        authentication_evidence(12, 110, 4608, NOW + timedelta(minutes=2)),
        authentication_evidence(13, 111, 4634, NOW + timedelta(minutes=3)),
    ]

    first = assemble_authentication_sessions(facts, [])
    second = assemble_authentication_sessions(list(reversed(facts)), [])

    assert first == second
    assert first[0].source_event_ids == (10, 11, 12, 13)


@pytest.mark.parametrize(
    ("events", "proofs", "expected_reason", "expected_count"),
    [
        (
            lambda: [
                authentication_evidence(10, 100, 4608, NOW),
                authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1)),
                authentication_evidence(12, 110, 4608, NOW + timedelta(minutes=2)),
                authentication_evidence(13, 111, 4634, NOW + timedelta(minutes=3)),
            ],
            (),
            "incomplete_reboot_boundary",
            1,
        ),
        (
            lambda: [
                authentication_evidence(10, 100, 4608, NOW),
                authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1)),
                authentication_evidence(12, 102, 4624, NOW + timedelta(minutes=2)),
                authentication_evidence(13, 103, 4634, NOW + timedelta(minutes=3)),
            ],
            (),
            "incomplete_duplicate_boundary",
            1,
        ),
        (
            lambda: [
                authentication_evidence(10, 100, 4608, NOW),
                authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1)),
            ],
            (),
            "incomplete_missing_close",
            1,
        ),
        (
            lambda: [
                authentication_evidence(10, 100, 4608, NOW),
                authentication_evidence(11, 102, 4624, NOW + timedelta(minutes=3)),
                authentication_evidence(12, 101, 4634, NOW + timedelta(minutes=4)),
            ],
            (),
            "incomplete_out_of_order",
            1,
        ),
        (
            lambda: [
                authentication_evidence(10, 100, 4608, NOW),
                authentication_evidence(11, 101, 4624, NOW + timedelta(minutes=1)),
                authentication_evidence(12, 102, 4634, NOW + timedelta(minutes=2)),
            ],
            ("gap",),
            "incomplete_coverage_gap",
            1,
        ),
    ],
)
def test_unsafe_boundaries_are_incomplete_without_invented_end_or_duration(
    events: object,
    proofs: tuple[str, ...],
    expected_reason: str,
    expected_count: int,
) -> None:
    facts = events()
    declarations = [continuity_proof(facts, completeness=value) for value in proofs]

    result = assemble_authentication_sessions(facts, declarations)

    assert len(result) == expected_count
    assert {item.state for item in result} == {"incomplete"}
    assert {item.quality_reason for item in result} == {expected_reason}
    assert all(item.logoff_time_utc is None for item in result)
    assert all(item.duration_seconds is None for item in result)


def authentication_evidence(
    source_event_id: int,
    source_record_id: int,
    event_key: int,
    when: datetime,
    *,
    principal: str | None = None,
    host: str | None = None,
    logon_type: str | None = None,
    privilege_marker: str | None = None,
) -> AuthenticationEvidence:
    return AuthenticationEvidence(
        source_event_id=source_event_id,
        source_record_id=source_record_id,
        event_key=event_key,
        descriptor_source="sli.windows.ad-dc",
        descriptor_stream="Security",
        server_id=1,
        channel_id=2,
        provider_name="Microsoft-Windows-Security-Auditing",
        logon_id="0xabc" if event_key != 4608 else None,
        observed_at_utc=when,
        normalized_hash={
            10: "a" * 64, 11: "b" * 64, 12: "c" * 64, 13: "d" * 64,
        }.get(source_event_id, f"{source_event_id:064x}"),
        principal=principal,
        host=host,
        logon_type=logon_type,
        privilege_marker=privilege_marker,
    )


def continuity_proof(
    facts: list[AuthenticationEvidence], *, completeness: str = "complete",
    scope_identity: str = "collection:42:file:7",
    channel_generation_identity: str = "generation-stable",
) -> ContinuityDeclaration:
    return ContinuityDeclaration(
        scope_identity=scope_identity,
        descriptor_source="sli.windows.ad-dc",
        descriptor_stream="Security",
        server_id=1,
        channel_id=2,
        provider_name="Microsoft-Windows-Security-Auditing",
        channel_generation_identity=channel_generation_identity,
        source_event_ids=tuple(item.source_event_id for item in facts),
        source_hashes=tuple(item.normalized_hash for item in facts),
        first_event_record_id=min(item.source_record_id for item in facts),
        last_event_record_id=max(item.source_record_id for item in facts),
        completeness=completeness,
    )

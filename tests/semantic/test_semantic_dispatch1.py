from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from server.sli.semantic.semantic_correlation_repository import CorrelationRuleDefinition
from server.sli.semantic.semantic_dispatch import (
    MAX_MATCH_EVENTS,
    compile_correlation_rule,
    match_compiled_rule,
    relation_partition_key,
)
from server.sli.semantic.semantic_processing import NormalizedEvent


def _event(
    source_id: int,
    semantic_type: str,
    occurred: datetime,
    *,
    host: str = "dc-1",
    session: str = "session-1",
) -> NormalizedEvent:
    return NormalizedEvent(
        source_event_id=source_id,
        semantic_type=semantic_type,
        occurred_at_utc=occurred,
        roles={"source_host": host, "session_principal": session},
        facts={},
        quality={},
        semantic_sha256=f"{source_id:064x}",
    )


def _identity_event(
    source_id: int,
    semantic_type: str,
    occurred: datetime,
    *,
    domain_id: int = 7,
    account_sid: str = "S-1-5-21-100-200-300-400",
    member_sid: str | None = None,
    group_sid: str | None = None,
) -> NormalizedEvent:
    facts = {"domain_id": domain_id}
    quality: dict[str, object] = {}
    roles = {"source_host": f"dc-{source_id}"}
    if account_sid:
        facts["relation_account_sid"] = account_sid
        quality["relation_account_identity"] = {"state": "exact"}
        roles["affected_entity"] = f"sid:{account_sid}"
    if member_sid and group_sid:
        facts["relation_member_sid"] = member_sid
        facts["relation_group_sid"] = group_sid
        quality["relation_membership_identity"] = {"state": "exact"}
    return NormalizedEvent(
        source_event_id=source_id,
        semantic_type=semantic_type,
        occurred_at_utc=occurred,
        roles=roles,
        facts=facts,
        quality=quality,
        semantic_sha256=f"{source_id:064x}",
    )


def _compile(kind: str, **overrides):
    definition = {
        "type": kind,
        "inputs": [
            "authentication.session.created",
            "authentication.privileged_session.created",
        ],
        "join_roles": ["source_host", "session_principal"],
        "window_seconds": 900,
        "output_relation_kind": "authentication.session.has_special_privileges",
        "confidence": "high",
        "explanation": "same source host and session principal",
    }
    definition.update(overrides)
    return compile_correlation_rule(
        CorrelationRuleDefinition(
            rule_id=f"dispatch-{kind}",
            rule_version=1,
            rule_kind=kind,
            definition=definition,
        )
    )


def _cross_dc_rule(kind: str, **overrides):
    definition = {
        "type": kind,
        "inputs": [
            "authentication.session.failed",
            "authentication.account.locked",
        ],
        "partition_kind": "domain_account_sid",
        "window_seconds": 900,
        "minimum_count": 2,
        "strict_time_order": True,
        "output_relation_kind": "authentication.account.lockout_preceded_by_failures_observed",
        "confidence": "medium",
        "explanation": "Observed exact domain and SID sequence; this makes no causal claim.",
    }
    definition.update(overrides)
    return compile_correlation_rule(
        CorrelationRuleDefinition(
            rule_id=f"cross-dc-{kind}",
            rule_version=1,
            rule_kind=kind,
            definition=definition,
        )
    )


def test_cross_dc_count_then_uses_domain_and_exact_sid_with_strict_time() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _cross_dc_rule("count_then")
    relations = match_compiled_rule(
        rule,
        [
            _identity_event(1, "authentication.session.failed", occurred),
            _identity_event(
                2,
                "authentication.session.failed",
                occurred + timedelta(minutes=2),
            ),
            _identity_event(
                3,
                "authentication.account.locked",
                occurred + timedelta(minutes=3),
            ),
            _identity_event(
                4,
                "authentication.account.locked",
                occurred + timedelta(minutes=4),
                account_sid="S-1-5-21-100-200-300-401",
            ),
            _identity_event(
                5,
                "authentication.account.locked",
                occurred + timedelta(minutes=5),
                domain_id=8,
            ),
        ],
    )
    assert [item.source_event_ids for item in relations] == [(1, 2, 3)]
    assert relations[0].partition_key == "domain:7|account_sid:S-1-5-21-100-200-300-400"
    assert "causal" in relations[0].explanation.lower()

    assert match_compiled_rule(
        rule,
        [
            _identity_event(1, "authentication.session.failed", occurred),
            _identity_event(2, "authentication.session.failed", occurred),
            _identity_event(3, "authentication.account.locked", occurred),
        ],
    ) == []


def test_cross_dc_partition_rejects_non_numeric_domain_sid() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    event = _identity_event(
        1,
        "authentication.session.failed",
        occurred,
        account_sid="S-1-5-21-not-numeric",
    )

    assert relation_partition_key(_cross_dc_rule("count_then"), event) is None


def test_cross_dc_membership_rule_requires_exact_member_and_group_sids() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _cross_dc_rule(
        "sequence",
        inputs=["group.member.added", "group.member.removed"],
        partition_kind="domain_member_group_sid",
        window_seconds=86400,
        output_relation_kind="directory.group.membership_reverted_observed",
    )
    relations = match_compiled_rule(
        rule,
        [
            _identity_event(
                1,
                "group.member.added",
                occurred,
                account_sid="",
                member_sid="S-1-5-21-100-200-300-400",
                group_sid="S-1-5-21-100-200-300-512",
            ),
            _identity_event(
                2,
                "group.member.removed",
                occurred + timedelta(seconds=1),
                account_sid="",
                member_sid="S-1-5-21-100-200-300-400",
                group_sid="S-1-5-21-100-200-300-512",
            ),
            _identity_event(
                3,
                "group.member.removed",
                occurred + timedelta(seconds=2),
                account_sid="",
                member_sid="S-1-5-21-100-200-300-401",
                group_sid="S-1-5-21-100-200-300-512",
            ),
        ],
    )
    assert [item.source_event_ids for item in relations] == [(1, 2)]
    assert relations[0].partition_key.endswith(
        "member_sid:S-1-5-21-100-200-300-400|group_sid:S-1-5-21-100-200-300-512"
    )


def test_cross_dc_sequence_rejects_equal_timestamps() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _cross_dc_rule(
        "sequence",
        inputs=["authentication.account.locked", "authentication.account.unlocked"],
        window_seconds=86400,
        output_relation_kind="authentication.account.unlock_after_lock_observed",
    )
    assert match_compiled_rule(
        rule,
        [
            _identity_event(1, "authentication.account.locked", occurred),
            _identity_event(2, "authentication.account.unlocked", occurred),
        ],
    ) == []


def test_successful_password_reset_then_logon_requires_exact_identity_and_time() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _cross_dc_rule(
        "sequence",
        inputs=["account.password.reset.succeeded", "authentication.session.created"],
        window_seconds=3600,
        output_relation_kind="authentication.password_reset_followed_by_logon_observed",
    )
    reset = _identity_event(1, "account.password.reset.succeeded", occurred)
    matching_logon = _identity_event(
        2,
        "authentication.session.created",
        occurred + timedelta(minutes=30),
    )

    relations = match_compiled_rule(rule, [reset, matching_logon])

    assert [item.source_event_ids for item in relations] == [(1, 2)]
    assert relations[0].partition_key == "domain:7|account_sid:S-1-5-21-100-200-300-400"
    assert "causal" in relations[0].explanation.lower()
    assert match_compiled_rule(
        rule,
        [
            _identity_event(3, "account.password.reset.attempted", occurred),
            matching_logon,
        ],
    ) == []
    assert match_compiled_rule(
        rule,
        [
            reset,
            _identity_event(
                4,
                "authentication.session.created",
                occurred + timedelta(minutes=30),
                account_sid="S-1-5-21-100-200-300-401",
            ),
        ],
    ) == []
    assert match_compiled_rule(
        rule,
        [
            reset,
            _identity_event(5, "authentication.session.created", occurred),
        ],
    ) == []
    assert match_compiled_rule(
        rule,
        [
            reset,
            _identity_event(
                6,
                "authentication.session.created",
                occurred + timedelta(hours=1, seconds=1),
            ),
        ],
    ) == []


def test_anchor_scoped_sequence_preserves_every_later_exact_continuation() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _cross_dc_rule(
        "sequence",
        inputs=["account.password.reset.succeeded", "authentication.session.created"],
        window_seconds=3600,
        output_relation_kind="authentication.password_reset_followed_by_logon_observed",
        continuation_policy="anchor_all_admissible",
    )

    relations = match_compiled_rule(
        rule,
        [
            _identity_event(1, "account.password.reset.succeeded", occurred),
            _identity_event(3, "authentication.session.created", occurred + timedelta(minutes=30)),
            _identity_event(2, "authentication.session.created", occurred + timedelta(minutes=10)),
        ],
    )

    assert [item.source_event_ids for item in relations] == [(1, 2, 3)]
    assert relations[0].contribution_key.startswith("dispatch:")


def test_anchor_scoped_sequence_is_stable_for_replay_late_evidence_and_independent_anchors() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _cross_dc_rule(
        "sequence",
        inputs=["account.password.reset.succeeded", "authentication.session.created"],
        window_seconds=3600,
        output_relation_kind="authentication.password_reset_followed_by_logon_observed",
        continuation_policy="anchor_all_admissible",
    )
    initial = [
        _identity_event(1, "account.password.reset.succeeded", occurred),
        _identity_event(2, "authentication.session.created", occurred + timedelta(minutes=10)),
        _identity_event(10, "account.password.reset.succeeded", occurred + timedelta(hours=2)),
        _identity_event(11, "authentication.session.created", occurred + timedelta(hours=2, minutes=10)),
    ]
    initial_relations = match_compiled_rule(rule, initial)
    replay_relations = match_compiled_rule(
        rule,
        [*initial, _identity_event(3, "authentication.session.created", occurred + timedelta(minutes=20))],
    )

    assert [item.source_event_ids for item in initial_relations] == [(1, 2), (10, 11)]
    assert [item.source_event_ids for item in replay_relations] == [(1, 2, 3), (10, 11)]
    assert replay_relations[0].contribution_key == initial_relations[0].contribution_key
    assert replay_relations[1].contribution_key == initial_relations[1].contribution_key


def test_anchor_scoped_sequence_rejects_equal_timestamp_continuations() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _cross_dc_rule(
        "sequence",
        inputs=["account.password.reset.succeeded", "authentication.session.created"],
        window_seconds=3600,
        output_relation_kind="authentication.password_reset_followed_by_logon_observed",
        continuation_policy="anchor_all_admissible",
    )

    assert match_compiled_rule(
        rule,
        [
            _identity_event(1, "account.password.reset.succeeded", occurred),
            _identity_event(2, "authentication.session.created", occurred),
        ],
    ) == []


def test_cross_dc_count_then_keeps_lockout_anchor_stable_for_late_evidence() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _cross_dc_rule("count_then")
    initial = [
        _identity_event(2, "authentication.session.failed", occurred + timedelta(minutes=1)),
        _identity_event(3, "authentication.session.failed", occurred + timedelta(minutes=2)),
        _identity_event(4, "authentication.account.locked", occurred + timedelta(minutes=3)),
    ]
    initial_relation = match_compiled_rule(rule, initial)[0]
    replay_relation = match_compiled_rule(
        rule,
        [_identity_event(1, "authentication.session.failed", occurred), *initial],
    )[0]
    assert replay_relation.contribution_key == initial_relation.contribution_key
    assert replay_relation.source_event_ids == (1, 2, 3, 4)


def test_cross_dc_account_member_partition_rejects_member_sid_without_exact_quality() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _cross_dc_rule(
        "sequence",
        inputs=["directory.account.created", "group.member.added"],
        partition_kind="domain_account_member_sid",
        window_seconds=86400,
        output_relation_kind="directory.account.group_membership_added_observed",
    )
    unresolved_member = _identity_event(
        2,
        "group.member.added",
        occurred + timedelta(seconds=1),
        account_sid="",
        member_sid="S-1-5-21-100-200-300-400",
        group_sid="S-1-5-21-100-200-300-512",
    )
    unresolved_member = NormalizedEvent(
        source_event_id=unresolved_member.source_event_id,
        semantic_type=unresolved_member.semantic_type,
        occurred_at_utc=unresolved_member.occurred_at_utc,
        roles=unresolved_member.roles,
        facts=unresolved_member.facts,
        quality={},
        semantic_sha256=unresolved_member.semantic_sha256,
    )
    assert match_compiled_rule(
        rule,
        [
            _identity_event(1, "directory.account.created", occurred),
            unresolved_member,
        ],
    ) == []


def test_all_of_compiler_and_matcher_require_exact_partition_and_window() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _compile("all_of")
    relations = match_compiled_rule(
        rule,
        [
            _event(1, rule.input_types[0], occurred),
            _event(2, rule.input_types[1], occurred + timedelta(seconds=1)),
            _event(3, rule.input_types[1], occurred + timedelta(seconds=2), host="dc-2"),
        ],
    )
    assert len(relations) == 1
    assert relations[0].source_event_ids == (1, 2)
    assert relations[0].contribution_key.startswith("dispatch:")
    assert match_compiled_rule(
        rule,
        [
            _event(1, rule.input_types[0], occurred),
            _event(2, rule.input_types[1], occurred + timedelta(minutes=16)),
        ],
    ) == []


def test_count_matcher_is_bounded_and_uses_one_input_type() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _compile(
        "count",
        inputs=["authentication.session.failed"],
        minimum_count=3,
        output_relation_kind="authentication.session.failure_burst",
    )
    assert match_compiled_rule(
        rule,
        [_event(index, rule.input_types[0], occurred + timedelta(seconds=index)) for index in range(3)],
    )[0].source_event_ids == (0, 1, 2)
    with pytest.raises(ValueError, match="exceeds 5000"):
        match_compiled_rule(
            rule,
            [_event(index, rule.input_types[0], occurred) for index in range(MAX_MATCH_EVENTS + 1)],
        )


def test_matcher_returns_independent_relations_from_one_group() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _compile("all_of", window_seconds=30)
    relations = match_compiled_rule(
        rule,
        [
            _event(1, rule.input_types[0], occurred),
            _event(2, rule.input_types[1], occurred + timedelta(seconds=1)),
            _event(3, rule.input_types[0], occurred + timedelta(minutes=2)),
            _event(
                4,
                rule.input_types[1],
                occurred + timedelta(minutes=2, seconds=1),
            ),
        ],
    )
    assert [item.source_event_ids for item in relations] == [(1, 2), (3, 4)]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"join_roles": ["session_principal"]}, "include source_host"),
        ({"window_seconds": 86401}, "within 24 hours"),
        ({"minimum_count": 1}, "must equal"),
        ({"join_roles": ["source_host", "arbitrary"]}, "canonical"),
    ],
)
def test_compiler_rejects_unbounded_or_noncanonical_all_of(overrides, message) -> None:
    with pytest.raises(ValueError, match=message):
        _compile("all_of", **overrides)


def test_sequence_matcher_requires_declared_event_order() -> None:
    occurred = datetime(2026, 7, 19, tzinfo=timezone.utc)
    rule = _compile(
        "sequence",
        inputs=[
            "authentication.session.created",
            "authentication.privileged_session.created",
        ],
        window_seconds=900,
        output_relation_kind="authentication.session.privileged_context_observed",
    )

    assert match_compiled_rule(
        rule,
        [
            _event(1, rule.input_types[0], occurred),
            _event(2, rule.input_types[1], occurred + timedelta(seconds=1)),
        ],
    )[0].source_event_ids == (1, 2)
    assert match_compiled_rule(
        rule,
        [
            _event(1, rule.input_types[1], occurred),
            _event(2, rule.input_types[0], occurred + timedelta(seconds=1)),
        ],
    ) == []


def test_chain_training_pack_keeps_dispatch_rules_draft_and_compilable() -> None:
    root = Path(__file__).resolve().parents[2]
    pack = json.loads((root / "config" / "semantic_chain_pack_v1.json").read_text(encoding="utf-8"))
    assert pack["owner"] == "semantic_worker"
    assert pack["execution_policy"]["no_implicit_close"] is True
    dispatch_rules = [item for item in pack["rules"] if item["rule_kind"] != "worker_assembler"]
    assert dispatch_rules
    for item in dispatch_rules:
        assert item["lifecycle_status"] == "draft"
        compiled = compile_correlation_rule(
            CorrelationRuleDefinition(
                rule_id=item["rule_id"],
                rule_version=item["rule_version"],
                rule_kind=item["rule_kind"],
                definition=item["definition"],
            )
        )
        assert compiled.rule_kind in {"sequence", "count_then"}


def test_investigation_pack_declares_only_approved_sid_relation_rules() -> None:
    root = Path(__file__).resolve().parents[2]
    pack = json.loads((root / "config" / "semantic_chain_pack_v1.json").read_text(encoding="utf-8"))
    approved = {
        "investigation.account.lockout.preceded-by-failures": (
            "count_then",
            "domain_account_sid",
            ["authentication.session.failed", "authentication.account.locked"],
            900,
        ),
        "investigation.account.unlock.after-lock": (
            "sequence",
            "domain_account_sid",
            ["authentication.account.locked", "authentication.account.unlocked"],
            86400,
        ),
        "investigation.group.membership.removed-after-add": (
            "sequence",
            "domain_member_group_sid",
            ["group.member.added", "group.member.removed"],
            86400,
        ),
        "investigation.account.created-then-group-add": (
            "sequence",
            "domain_account_member_sid",
            ["directory.account.created", "group.member.added"],
            86400,
        ),
        "investigation.password.reset-then-logon": (
            "sequence",
            "domain_account_sid",
            ["account.password.reset.succeeded", "authentication.session.created"],
            3600,
        ),
    }
    rules = {item["rule_id"]: item for item in pack["rules"]}
    assert set(approved).issubset(rules)
    for rule_id, (kind, partition, inputs, seconds) in approved.items():
        item = rules[rule_id]
        assert item["rule_kind"] == kind
        assert item["lifecycle_status"] == "draft"
        assert item["definition"]["partition_kind"] == partition
        assert item["definition"]["inputs"] == inputs
        assert item["definition"]["window_seconds"] == seconds
        assert item["definition"]["strict_time_order"] is True
        assert "causal" in item["definition"]["explanation"].lower()
    assert all(
        "account.password.reset.attempted" not in item.get("definition", {}).get("inputs", [])
        for item in pack["rules"]
    )

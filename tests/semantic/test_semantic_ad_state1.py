from datetime import datetime, timezone

from server.sli.semantic.semantic_ad_state import (
    BASELINE_IMPORT,
    INCREMENTAL_SYNC,
    DirectoryStateSnapshot,
    MembershipEdge,
    assess_directory_action_state,
    derive_effective_privilege_paths,
)
from server.sli.semantic.semantic_processing import CanonicalAction


NOW = datetime(2026, 7, 18, 8, tzinfo=timezone.utc)


def _action(*, added: list[str] | None = None, removed: list[str] | None = None) -> CanonicalAction:
    return CanonicalAction(
        action_kind="directory.attribute.changed",
        status="observed",
        occurred_at_utc=NOW,
        contribution_key="key",
        source_event_ids=(1,),
        attributes={
            "object_identity": "guid:object-1",
            "attribute": "member",
            "added_values": added or [],
            "removed_values": removed or [],
        },
    )


def test_state_confirmation_requires_exact_object_attribute_and_nonbaseline_evidence() -> None:
    snapshot = DirectoryStateSnapshot("guid:object-1", "member", frozenset({"alice"}), NOW, INCREMENTAL_SYNC, "state-1")
    assert assess_directory_action_state(_action(added=["alice"]), snapshot).status == "state_confirmed"
    assert assess_directory_action_state(_action(removed=["alice"]), snapshot).status == "contradicted"
    baseline = DirectoryStateSnapshot("guid:object-1", "member", frozenset({"alice"}), NOW, BASELINE_IMPORT, "base-1")
    assert assess_directory_action_state(_action(added=["alice"]), baseline).reason == "baseline_import_does_not_confirm_new_change"


def test_effective_privilege_paths_are_deterministic_cycle_safe_and_baseline_safe() -> None:
    paths = derive_effective_privilege_paths(
        memberships=[
            MembershipEdge("alice", "group-a", "e1", NOW, BASELINE_IMPORT),
            MembershipEdge("group-a", "domain-admins", "e2", NOW, BASELINE_IMPORT),
            MembershipEdge("group-a", "alice", "cycle", NOW, INCREMENTAL_SYNC),
            MembershipEdge("bob", "domain-admins", "e3", NOW, INCREMENTAL_SYNC),
        ],
        privileged_group_identities=["domain-admins"],
    )
    assert [(item.principal_identity, item.chain, item.status) for item in paths] == [
        ("alice", ("alice", "group-a", "domain-admins"), "baseline_observed"),
        ("bob", ("bob", "domain-admins"), "state_confirmed"),
        ("group-a", ("group-a", "domain-admins"), "baseline_observed"),
    ]

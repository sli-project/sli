"""Deterministic AD-state confirmation and effective-privilege primitives.

This module is intentionally pure: it neither queries AD nor writes findings.
It gives a later, separately gated repository worker the only allowed ways to
raise the evidence status of a canonical action.  A baseline import describes
known state; it is never treated as a newly observed security change.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping

from server.sli.semantic.semantic_processing import CanonicalAction


BASELINE_IMPORT = "baseline_import"
INCREMENTAL_SYNC = "incremental_sync"
TARGETED_RECONCILE = "targeted_reconcile"
STATE_ORIGINS = frozenset({BASELINE_IMPORT, INCREMENTAL_SYNC, TARGETED_RECONCILE})


@dataclass(frozen=True)
class DirectoryStateSnapshot:
    object_identity: str
    attribute: str
    values: frozenset[str]
    observed_at_utc: datetime
    origin: str
    evidence_id: str

    def __post_init__(self) -> None:
        if self.origin not in STATE_ORIGINS:
            raise ValueError(f"unsupported state origin: {self.origin}")
        if self.observed_at_utc.tzinfo is None:
            raise ValueError("observed_at_utc must be timezone-aware")


@dataclass(frozen=True)
class ActionStateAssessment:
    status: str
    reason: str
    state_evidence_id: str | None = None


@dataclass(frozen=True)
class MembershipEdge:
    member_identity: str
    group_identity: str
    evidence_id: str
    observed_at_utc: datetime
    origin: str = INCREMENTAL_SYNC

    def __post_init__(self) -> None:
        if self.origin not in STATE_ORIGINS:
            raise ValueError(f"unsupported relationship origin: {self.origin}")
        if self.observed_at_utc.tzinfo is None:
            raise ValueError("observed_at_utc must be timezone-aware")


@dataclass(frozen=True)
class EffectivePrivilegePath:
    principal_identity: str
    privileged_group_identity: str
    chain: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    status: str


def assess_directory_action_state(
    action: CanonicalAction,
    snapshot: DirectoryStateSnapshot,
) -> ActionStateAssessment:
    """Assess one exact state observation against one directory action.

    The comparison requires the same object and LDAP attribute.  It never
    confirms an action merely because a snapshot is nearby in time.  A
    ``baseline_import`` remains non-actionable evidence by design.
    """
    if action.action_kind != "directory.attribute.changed":
        return ActionStateAssessment("observed", "action_kind_has_no_directory_state_contract")
    if snapshot.origin == BASELINE_IMPORT:
        return ActionStateAssessment("observed", "baseline_import_does_not_confirm_new_change", snapshot.evidence_id)

    attributes = action.attributes
    identity = str(attributes.get("object_identity") or attributes.get("object") or "")
    attribute = str(attributes.get("attribute") or "")
    if not identity or not attribute:
        return ActionStateAssessment("partially_confirmed", "action_missing_material_identity")
    if identity != snapshot.object_identity or attribute.casefold() != snapshot.attribute.casefold():
        return ActionStateAssessment("observed", "state_identity_mismatch")

    added = {str(value) for value in attributes.get("added_values") or []}
    removed = {str(value) for value in attributes.get("removed_values") or []}
    present_added = added.intersection(snapshot.values)
    still_present_removed = removed.intersection(snapshot.values)
    if still_present_removed:
        return ActionStateAssessment("contradicted", "removed_value_still_present_in_confirming_state", snapshot.evidence_id)
    if added and present_added == added and not removed:
        return ActionStateAssessment("state_confirmed", "all_added_values_present_in_state", snapshot.evidence_id)
    if removed and not still_present_removed and not added:
        return ActionStateAssessment("state_confirmed", "all_removed_values_absent_from_state", snapshot.evidence_id)
    if present_added or removed:
        return ActionStateAssessment("partially_confirmed", "state_matches_only_part_of_action", snapshot.evidence_id)
    return ActionStateAssessment("partially_confirmed", "state_has_no_observable_value_confirmation", snapshot.evidence_id)


def derive_effective_privilege_paths(
    *,
    memberships: Iterable[MembershipEdge],
    privileged_group_identities: Iterable[str],
) -> list[EffectivePrivilegePath]:
    """Return deterministic direct/transitive privilege paths, never risk.

    Only declared membership edges participate.  Cycles are bounded by the
    chain itself, and output is sorted to make replays stable.  Baseline paths
    are labelled as such so importing a first directory snapshot cannot create
    a security finding.
    """
    privileged = {str(value) for value in privileged_group_identities if str(value)}
    outgoing: dict[str, list[MembershipEdge]] = {}
    principals: set[str] = set()
    for edge in memberships:
        outgoing.setdefault(edge.member_identity, []).append(edge)
        principals.add(edge.member_identity)
    for edges in outgoing.values():
        edges.sort(key=lambda item: (item.group_identity, item.evidence_id))

    result: list[EffectivePrivilegePath] = []
    for principal in sorted(principals):
        queue: list[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = [
            (principal, (principal,), (), ())
        ]
        while queue:
            current, chain, evidence_ids, origins = queue.pop(0)
            for edge in outgoing.get(current, ()):
                if edge.group_identity in chain:
                    continue
                next_chain = (*chain, edge.group_identity)
                next_evidence = (*evidence_ids, edge.evidence_id)
                next_origins = (*origins, edge.origin)
                if edge.group_identity in privileged:
                    status = "baseline_observed" if next_origins and all(origin == BASELINE_IMPORT for origin in next_origins) else "state_confirmed"
                    result.append(EffectivePrivilegePath(
                        principal_identity=principal,
                        privileged_group_identity=edge.group_identity,
                        chain=next_chain,
                        evidence_ids=next_evidence,
                        status=status,
                    ))
                queue.append((edge.group_identity, next_chain, next_evidence, next_origins))
    return sorted(result, key=lambda item: (item.principal_identity, item.privileged_group_identity, item.chain, item.evidence_ids))

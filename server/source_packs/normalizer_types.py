from __future__ import annotations

"""Source normalizer contract: handler signatures and the ``SourceNormalizer`` bundle.

Kept apart from ``normalizers`` so a source pack can build its own
``SourceNormalizer`` without importing the registry that imports the pack.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from server.source_packs.contracts import (
    AccountEventSemantics,
    EventEntitySemantics,
    EventStateSemantics,
    FindingRule,
    SecurityMonitorGroup,
    SemanticCoreRoleFilter,
    SemanticEventIdentity,
)

CorrelationNormalizer = Callable[..., str | None]
EventFactsNormalizer = Callable[..., dict[str, Any]]
EntitySemanticsNormalizer = Callable[..., EventEntitySemantics]
StateSemanticsNormalizer = Callable[..., EventStateSemantics | None]
ContextualClassifier = Callable[[Mapping[str, Any]], dict[str, Any]]
AccountEventResolver = Callable[[Any], AccountEventSemantics | None]
EventIdFamilyResolver = Callable[[str], tuple[int, ...]]
ImportantEventIdsResolver = Callable[[], tuple[int, ...]]
EventLabelResolver = Callable[[Any, str], str | None]
FindingRulesResolver = Callable[[], Mapping[int, FindingRule]]
InvestigationEventIdsResolver = Callable[[str], tuple[int, ...]]
InvestigationCategoryResolver = Callable[[Any], str]
InvestigationCheckResolver = Callable[[str], str | None]
SecurityMonitorGroupsResolver = Callable[[], tuple[SecurityMonitorGroup, ...]]
SemanticProjectionNormalizer = Callable[..., dict[str, Any]]
SemanticEventIdentitiesResolver = Callable[
    [tuple[str, ...]], tuple[SemanticEventIdentity, ...]
]
SemanticCoreRoleFiltersResolver = Callable[
    [str, tuple[str, ...], Mapping[str, str]],
    tuple[SemanticCoreRoleFilter, ...] | None,
]


@dataclass(frozen=True)
class SourceNormalizer:
    normalizer_id: str
    correlation_id: CorrelationNormalizer
    event_facts: EventFactsNormalizer
    entity_semantics: EntitySemanticsNormalizer
    state_semantics: StateSemanticsNormalizer
    contextual_classification: ContextualClassifier
    account_event: AccountEventResolver
    event_ids_for_search_family: EventIdFamilyResolver
    event_ids_for_analysis_family: EventIdFamilyResolver
    important_account_event_ids: ImportantEventIdsResolver
    event_label: EventLabelResolver
    finding_rules: FindingRulesResolver
    investigation_event_ids: InvestigationEventIdsResolver
    investigation_category: InvestigationCategoryResolver
    investigation_check: InvestigationCheckResolver
    security_monitor_groups: SecurityMonitorGroupsResolver
    monitor_privileged_event_ids: ImportantEventIdsResolver
    semantic_projection: SemanticProjectionNormalizer
    semantic_event_identities: SemanticEventIdentitiesResolver
    semantic_core_role_filters: SemanticCoreRoleFiltersResolver

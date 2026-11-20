"""NPS normalization provider owned by the remote-access package."""
from functools import lru_cache
from server.source_packs.normalizer_types import SourceNormalizer
from server.source_packs.windows_nps_radius import (
    account_event_semantics as nps_account_event_semantics,
)
from server.source_packs.windows_nps_radius import (
    classify_contextual_event as classify_nps_contextual_event,
)
from server.source_packs.windows_nps_radius import (
    correlation_id_for_event as nps_correlation_id_for_event,
)
from server.source_packs.windows_nps_radius import (
    entity_semantics_for_event as nps_entity_semantics_for_event,
)
from server.source_packs.windows_nps_radius import (
    event_facts_for_event as nps_event_facts_for_event,
)
from server.source_packs.windows_nps_radius import (
    event_ids_for_analysis_family as nps_event_ids_for_analysis_family,
)
from server.source_packs.windows_nps_radius import (
    event_ids_for_search_family as nps_event_ids_for_search_family,
)
from server.source_packs.windows_nps_radius import (
    event_label as nps_event_label,
)
from server.source_packs.windows_nps_radius import (
    finding_rules as nps_finding_rules,
)
from server.source_packs.windows_nps_radius import (
    important_account_event_ids as nps_important_account_event_ids,
)
from server.source_packs.windows_nps_radius import (
    investigation_category as nps_investigation_category,
)
from server.source_packs.windows_nps_radius import (
    investigation_check as nps_investigation_check,
)
from server.source_packs.windows_nps_radius import (
    investigation_event_ids as nps_investigation_event_ids,
)
from server.source_packs.windows_nps_radius import (
    monitor_privileged_event_ids as nps_monitor_privileged_event_ids,
)
from server.source_packs.windows_nps_radius import (
    security_monitor_groups as nps_security_monitor_groups,
)
from server.source_packs.windows_nps_radius import (
    semantic_core_role_filters as nps_semantic_core_role_filters,
)
from server.source_packs.windows_nps_radius import (
    semantic_event_identities as nps_semantic_event_identities,
)
from server.source_packs.windows_nps_radius import (
    semantic_projection_for_event as nps_semantic_projection_for_event,
)
from server.source_packs.windows_nps_radius import (
    state_semantics_for_event as nps_state_semantics_for_event,
)


@lru_cache(maxsize=1)
def normalizer():
    return SourceNormalizer(
        normalizer_id="windows-nps-radius-v1",
        correlation_id=nps_correlation_id_for_event,
        event_facts=nps_event_facts_for_event,
        entity_semantics=nps_entity_semantics_for_event,
        state_semantics=nps_state_semantics_for_event,
        contextual_classification=classify_nps_contextual_event,
        account_event=nps_account_event_semantics,
        event_ids_for_search_family=nps_event_ids_for_search_family,
        event_ids_for_analysis_family=nps_event_ids_for_analysis_family,
        important_account_event_ids=nps_important_account_event_ids,
        event_label=nps_event_label,
        finding_rules=nps_finding_rules,
        investigation_event_ids=nps_investigation_event_ids,
        investigation_category=nps_investigation_category,
        investigation_check=nps_investigation_check,
        security_monitor_groups=nps_security_monitor_groups,
        monitor_privileged_event_ids=nps_monitor_privileged_event_ids,
        semantic_projection=nps_semantic_projection_for_event,
        semantic_event_identities=nps_semantic_event_identities,
        semantic_core_role_filters=nps_semantic_core_role_filters,
    )

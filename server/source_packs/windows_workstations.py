"""Entry point for identities not already owned by the shared Windows pack."""

from types import SimpleNamespace

from server.sli.plugins.workstations.normalizers import NEW_IDENTITIES, new_projection
from server.source_packs.contracts import EventEntitySemantics, SemanticEventIdentity


def event_facts(*, row, event_data):
    projection = new_projection(event_id=row.get("event_id"), channel=row.get("channel"),
                                provider=row.get("provider_name"), event_data=event_data)
    if not projection:
        return {}
    # Only columns in the existing bounded core facts contract are returned.
    facts = projection["facts"]
    return {"object_name": facts.get("device_id"),
            "result_code": facts.get("protection_component")}


def semantic_event_identities(types):
    return tuple(SemanticEventIdentity("sli.windows.workstations", channel, str(event_id),
                                      provider, semantic_type, "signal", "1.0.0")
                 for (channel, provider, event_id), (_, semantic_type) in NEW_IDENTITIES.items()
                 if semantic_type in types)


normalizer_namespace = SimpleNamespace(
    event_facts=event_facts,
    entity_semantics=lambda **_kwargs: EventEntitySemantics(),
    event_label=lambda event_id, lang: None,
    semantic_projection=new_projection,
    semantic_event_identities=semantic_event_identities,
)

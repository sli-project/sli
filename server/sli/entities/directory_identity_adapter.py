"""Attach directory SID/GUID to an existing shared entity without renumbering."""

import re
from uuid import UUID

from server.sli.entities.core_identity import EntityIdentifier, EntityObservation, IdentityResolution, IdentityRepository


def find_directory_entities(cursor, kind: str, identifier: EntityIdentifier) -> tuple[int, ...]:
    """Opt-in lookup adapter over the existing 034 directory aliases."""
    aliases = {"sli.ad.sid": "object_sid", "sli.ad.guid": "object_guid"}
    types = {"principal": "ad_user", "device": "ad_computer", "group": "ad_group"}
    if identifier.namespace not in aliases or not re.fullmatch(r"ad-domain:[1-9][0-9]*", identifier.scope_id):
        return ()
    cursor.execute(
        """select distinct a.entity_id from ad_context_entity_aliases a
           join entities_v2 e on e.id=a.entity_id join storage_v2_entity_type t on t.id=e.entity_type_id
           where a.domain_id=%s and a.alias_type=%s and a.normalized_value=%s and t.value=%s
           order by a.entity_id""",
        (int(identifier.scope_id.split(":", 1)[1]), aliases[identifier.namespace], identifier.value.casefold(), types[kind]),
    )
    return tuple(int(row["entity_id"]) for row in cursor.fetchall())


def observe_directory_identity(repository: IdentityRepository, entity_id: int, observation: EntityObservation) -> IdentityResolution:
    """The trusted AD projection supplies its existing entities_v2 ID."""
    if type(entity_id) is not int or entity_id <= 0:
        raise ValueError("invalid_directory_entity")
    identifiers = [item for item in observation.identifiers if item.strength == "stable"]
    if not identifiers or any(item.namespace not in {"sli.ad.sid", "sli.ad.guid"} for item in identifiers):
        raise ValueError("directory_identifier_required")
    candidates = {entity_id}
    for identifier in identifiers:
        candidates.update(repository.find_identifier(observation.kind, identifier))
    if len(candidates) > 1:
        resolution = IdentityResolution(None, "ambiguous", tuple(sorted(candidates)), "directory_identifier_conflict")
    else:
        for identifier in observation.identifiers:
            repository.add_identifier(entity_id, observation.kind, identifier)
        resolution = IdentityResolution(entity_id, "resolved")
    repository.record_observation(observation, resolution)
    return resolution


def directory_identifiers(*, domain_id: int, sid: str | None = None, guid: str | None = None) -> tuple[EntityIdentifier, ...]:
    if type(domain_id) is not int or domain_id <= 0:
        raise ValueError("invalid_directory_scope")
    scope = f"ad-domain:{domain_id}"
    identifiers = []
    if sid and sid.strip():
        if not re.fullmatch(r"S-1-([0-9]+-)+[0-9]+", sid.strip().upper()):
            raise ValueError("invalid_directory_sid")
        identifiers.append(EntityIdentifier("sli.ad.sid", scope, sid.strip().upper(), "stable"))
    if guid and guid.strip():
        try:
            canonical_guid = str(UUID(guid.strip()))
        except ValueError:
            raise ValueError("invalid_directory_guid") from None
        identifiers.append(EntityIdentifier("sli.ad.guid", scope, canonical_guid, "stable"))
    if not identifiers:
        raise ValueError("directory_identifier_required")
    return tuple(identifiers)

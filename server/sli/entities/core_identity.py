"""Plugin-neutral entity observations; aliases never imply an identity merge."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Protocol


@dataclass(frozen=True)
class EntityIdentifier:
    namespace: str
    scope_id: str
    value: str
    strength: Literal["stable", "alias"]

    def __post_init__(self):
        if self.strength not in {"stable", "alias"} or any(not isinstance(value, str) or not value.strip() or value.strip() != value or len(value) > 256 for value in (self.namespace, self.scope_id, self.value)):
            raise ValueError("invalid_entity_identifier")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{1,95}", self.namespace):
            raise ValueError("invalid_entity_namespace")

    def identity_key(self, kind: str) -> str:
        payload = json.dumps([kind, self.namespace, self.scope_id, self.value], separators=(",", ":"))
        return "core:" + hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class EntityObservation:
    plugin_id: str
    source_instance_id: str
    kind: Literal["principal", "device", "group"]
    identifiers: tuple[EntityIdentifier, ...]
    observed_at_utc: datetime
    evidence_refs: tuple[str, ...]

    def __post_init__(self):
        if self.kind not in {"principal", "device", "group"}:
            raise ValueError("invalid_entity_observation")
        if any(not isinstance(value, str) or not value.strip() or value.strip() != value or len(value) > 256 for value in (self.plugin_id, self.source_instance_id)):
            raise ValueError("invalid_entity_observation")
        if not isinstance(self.observed_at_utc, datetime) or self.observed_at_utc.utcoffset() is None:
            raise ValueError("entity_observation_requires_timezone")
        object.__setattr__(self, "observed_at_utc", self.observed_at_utc.astimezone(timezone.utc))
        if not isinstance(self.identifiers, tuple) or not self.identifiers or len(self.identifiers) > 64 or not all(isinstance(item, EntityIdentifier) for item in self.identifiers):
            raise ValueError("invalid_entity_identifiers")
        _validate_evidence(self.evidence_refs)

    @property
    def fingerprint(self) -> str:
        identifiers = sorted((item.namespace, item.scope_id, item.value, item.strength) for item in self.identifiers)
        payload = [self.plugin_id, self.source_instance_id, self.kind, identifiers, self.observed_at_utc.isoformat(), sorted(self.evidence_refs)]
        return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class IdentityResolution:
    entity_id: int | None
    state: Literal["resolved", "provisional", "ambiguous", "unresolved"]
    candidate_ids: tuple[int, ...] = ()
    reason: str | None = None


class IdentityRepository(Protocol):
    """All methods run in the caller's single transaction."""

    def find_identifier(self, kind: str, identifier: EntityIdentifier) -> tuple[int, ...]: ...
    def ensure_entity(self, kind: str, key: str, observation: EntityObservation) -> int: ...
    def add_identifier(self, entity_id: int, kind: str, identifier: EntityIdentifier) -> None: ...
    def record_observation(self, observation: EntityObservation, resolution: IdentityResolution) -> None: ...
    def association_targets(self, entity_id: int, relation: str) -> list[int]: ...
    def record_association(self, source: int, target: int, relation: str, actor_id: int, evidence_refs: tuple[str, ...]) -> None: ...


def _validate_evidence(refs: tuple[str, ...]) -> None:
    if not isinstance(refs, tuple) or not refs or len(refs) > 64 or any(not isinstance(ref, str) or not ref.strip() or len(ref) > 256 for ref in refs):
        raise ValueError("identity_evidence_required")


def observe_entity(repository: IdentityRepository, observation: EntityObservation) -> IdentityResolution:
    stable = sorted(set(item for item in observation.identifiers if item.strength == "stable"), key=lambda item: (item.namespace, item.scope_id, item.value))
    candidates = set()
    for identifier in stable:
        ids = repository.find_identifier(observation.kind, identifier)
        if not ids:
            entity_id = repository.ensure_entity(observation.kind, identifier.identity_key(observation.kind), observation)
            repository.add_identifier(entity_id, observation.kind, identifier)
            ids = (entity_id,)
        candidates.update(ids)
    if len(candidates) > 1:
        resolution = IdentityResolution(None, "ambiguous", tuple(sorted(candidates)), "conflicting_stable_identifiers")
    elif candidates:
        resolution = IdentityResolution(next(iter(candidates)), "resolved")
    else:
        # A repeat of the same observation is idempotent; a shared hostname is
        # not a stable key across observations or producers.
        entity_id = repository.ensure_entity(observation.kind, "provisional:" + observation.fingerprint, observation)
        resolution = IdentityResolution(entity_id, "provisional", reason="no_stable_identifier")
    if resolution.entity_id is not None:
        for identifier in observation.identifiers:
            if identifier.strength == "alias":
                repository.add_identifier(resolution.entity_id, observation.kind, identifier)
    repository.record_observation(observation, resolution)
    return resolution


def associate_entities(repository: IdentityRepository, source_entity_id: int, target_entity_id: int, *, actor_id: int, evidence_refs: tuple[str, ...]) -> IdentityResolution:
    """Associate an agent/device with a directory computer, retaining conflicts."""
    if any(type(value) is not int or value <= 0 for value in (source_entity_id, target_entity_id, actor_id)) or source_entity_id == target_entity_id:
        raise ValueError("invalid_identity_association")
    _validate_evidence(evidence_refs)
    relation = "directory_computer"
    # The PostgreSQL implementation locks the source association here, serializing
    # concurrent association decisions without rewriting either entity.
    targets = set(repository.association_targets(source_entity_id, relation)) | {target_entity_id}
    repository.record_association(source_entity_id, target_entity_id, relation, actor_id, evidence_refs)
    return IdentityResolution(source_entity_id, "resolved" if len(targets) == 1 else "ambiguous", tuple(sorted(targets)),
                              "conflicting_associations" if len(targets) > 1 else None)


def resolve_directory_association(repository: IdentityRepository, entity_id: int) -> IdentityResolution:
    if type(entity_id) is not int or entity_id <= 0:
        raise ValueError("invalid_identity_entity")
    targets = tuple(sorted(set(repository.association_targets(entity_id, "directory_computer"))))
    if not targets:
        return IdentityResolution(entity_id, "unresolved", reason="no_directory_association")
    return IdentityResolution(entity_id, "resolved" if len(targets) == 1 else "ambiguous", targets,
                              "conflicting_associations" if len(targets) > 1 else None)

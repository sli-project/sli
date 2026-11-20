from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.entities.core_identity import (
    EntityIdentifier,
    EntityObservation,
    associate_entities,
    observe_entity,
    resolve_directory_association,
)
from server.sli.entities.directory_identity_adapter import directory_identifiers, observe_directory_identity


class MemoryIdentityRepository:
    def __init__(self):
        self.entities = {}
        self.identifiers = {}
        self.observations = []
        self.associations = []

    def find_identifier(self, kind, identifier):
        return self.identifiers.get((kind, identifier), ())

    def ensure_entity(self, kind, key, observation):
        identity = (kind, key)
        if identity not in self.entities:
            self.entities[identity] = len(self.entities) + 1
        return self.entities[identity]

    def add_identifier(self, entity_id, kind, identifier):
        self.identifiers[(kind, identifier)] = (entity_id,)

    def record_observation(self, observation, resolution):
        self.observations.append((observation, resolution))

    def association_targets(self, entity_id, relation):
        return sorted({row[1] for row in self.associations if row[0] == entity_id and row[2] == relation})

    def record_association(self, source, target, relation, actor_id, evidence_refs):
        self.associations.append((source, target, relation, actor_id, evidence_refs))


def observation(*identifiers, kind="device", source="fixture-source", evidence="fixture-evidence"):
    return EntityObservation(
        plugin_id="sli.fixture", source_instance_id=source, kind=kind,
        identifiers=tuple(identifiers), observed_at_utc=datetime(2026, 10, 6, tzinfo=timezone.utc),
        evidence_refs=(evidence,),
    )


def stable(value="fixture-agent"):
    return EntityIdentifier("sli.agent.id", "fixture-registry", value, "stable")


@pytest.mark.parametrize("kind", ["device", "principal", "group"])
def test_identity_without_ad_is_stable_and_preserves_provenance(kind):
    repo = MemoryIdentityRepository()
    first = observe_entity(repo, observation(stable(), kind=kind))
    replay = observe_entity(repo, observation(stable(), kind=kind, source="fixture-source-2"))
    assert first.state == replay.state == "resolved"
    assert first.entity_id == replay.entity_id
    assert len(repo.entities) == 1
    assert repo.observations[-1][0].source_instance_id == "fixture-source-2"


def test_aliases_never_merge_devices_and_provisional_state_is_explicit():
    repo = MemoryIdentityRepository()
    alias = EntityIdentifier("sli.hostname", "fixture-source", "fixture-host", "alias")
    first = observe_entity(repo, observation(stable("agent-1"), alias))
    second = observe_entity(repo, observation(stable("agent-2"), alias))
    unresolved = observe_entity(repo, observation(alias))
    assert first.entity_id != second.entity_id
    assert unresolved.state == "provisional" and unresolved.reason == "no_stable_identifier"
    assert unresolved.entity_id not in {first.entity_id, second.entity_id}


def test_conflicting_stable_identifiers_remain_ambiguous():
    repo = MemoryIdentityRepository()
    first = observe_entity(repo, observation(stable("agent-1")))
    second = observe_entity(repo, observation(stable("agent-2")))
    result = observe_entity(repo, observation(stable("agent-1"), stable("agent-2")))
    assert result.state == "ambiguous" and result.entity_id is None
    assert result.candidate_ids == (first.entity_id, second.entity_id)
    assert len(repo.entities) == 2


def test_explicit_association_is_audited_and_does_not_merge_ids():
    repo = MemoryIdentityRepository()
    device = observe_entity(repo, observation(stable()))
    assert resolve_directory_association(repo, device.entity_id).state == "unresolved"
    assert associate_entities(repo, device.entity_id, 40, actor_id=7, evidence_refs=("fixture-proof",)).state == "resolved"
    conflict = associate_entities(repo, device.entity_id, 41, actor_id=7, evidence_refs=("fixture-proof-2",))
    assert conflict.state == "ambiguous" and conflict.candidate_ids == (40, 41)
    assert repo.associations[-1][3:] == (7, ("fixture-proof-2",))
    assert observe_entity(repo, observation(stable())).entity_id == device.entity_id
    assert resolve_directory_association(repo, device.entity_id).candidate_ids == (40, 41)
    assert resolve_directory_association(repo, device.entity_id).state == "ambiguous"


@pytest.mark.parametrize("kwargs", [{"actor_id": 0, "evidence_refs": ("fixture",)}, {"actor_id": 7, "evidence_refs": ()}])
def test_association_requires_actor_and_evidence(kwargs):
    with pytest.raises(ValueError):
        associate_entities(MemoryIdentityRepository(), 1, 2, **kwargs)


def test_namespace_scope_and_kind_are_part_of_identity():
    repo = MemoryIdentityRepository()
    ids = [observe_entity(repo, observation(identifier, kind=kind)).entity_id for identifier, kind in [
        (stable(), "device"), (stable(), "principal"),
        (EntityIdentifier("sli.agent.id", "other-registry", "fixture-agent", "stable"), "device"),
    ]]
    assert len(set(ids)) == 3


def test_directory_adapter_preserves_existing_ids_and_never_links_agent_implicitly():
    repo = MemoryIdentityRepository()
    directory = observation(*directory_identifiers(domain_id=1, sid="S-1-5-21-1-2-3-1001", guid="00000000-0000-0000-0000-000000000001"))
    assert observe_directory_identity(repo, 40, directory).entity_id == 40
    agent = observe_entity(repo, observation(stable()))
    assert agent.entity_id != 40 and repo.associations == []
    assert observe_entity(repo, directory).entity_id == 40
    assert repo.observations[-1][1].state == "resolved"


def test_directory_conflict_keeps_all_candidates_and_original_identifier():
    repo = MemoryIdentityRepository()
    directory = observation(*directory_identifiers(domain_id=1, sid="S-1-5-21-1-2-3-1001"))
    observe_directory_identity(repo, 40, directory)
    conflict = observe_directory_identity(repo, 41, directory)
    assert conflict.state == "ambiguous" and conflict.candidate_ids == (40, 41)
    assert observe_entity(repo, directory).entity_id == 40


def test_unknown_additional_stable_identifier_cannot_be_merged_into_known_device():
    repo = MemoryIdentityRepository()
    known = observe_entity(repo, observation(stable("agent-1")))
    result = observe_entity(repo, observation(stable("agent-1"), stable("agent-2")))
    assert result.state == "ambiguous" and known.entity_id in result.candidate_ids


def test_provisional_replay_reuses_entity_and_other_evidence_stays_separate():
    repo = MemoryIdentityRepository()
    alias = EntityIdentifier("sli.hostname", "fixture-source", "fixture-host", "alias")
    first = observe_entity(repo, observation(alias))
    assert observe_entity(repo, observation(alias)).entity_id == first.entity_id
    assert observe_entity(repo, observation(alias, evidence="other-evidence")).entity_id != first.entity_id


def test_observation_normalizes_same_instant_before_computing_stable_replay_key():
    first = observation(stable())
    offset = replace(first, observed_at_utc=first.observed_at_utc.astimezone(timezone(timedelta(hours=7))))
    assert offset.fingerprint == first.fingerprint


@pytest.mark.parametrize("kwargs", [{"sid": "not-a-sid"}, {"guid": "not-a-guid"}, {"domain_id": 0}, {}])
def test_directory_adapter_rejects_missing_or_invalid_stable_identity(kwargs):
    values = {"domain_id": 1, **kwargs}
    with pytest.raises(ValueError):
        directory_identifiers(**values)


def test_observation_rejects_naive_time_and_empty_evidence():
    with pytest.raises(ValueError, match="requires_timezone"):
        replace(observation(stable()), observed_at_utc=datetime(2026, 10, 6))
    with pytest.raises(ValueError, match="evidence_required"):
        replace(observation(stable()), evidence_refs=())

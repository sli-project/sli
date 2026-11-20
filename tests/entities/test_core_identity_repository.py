from datetime import datetime, timezone

import pytest

from server.sli.entities.core_identity import EntityIdentifier, EntityObservation, IdentityResolution
from server.sli.entities.core_identity_repository import PostgresIdentityRepository
from server.sli.entities.directory_identity_adapter import find_directory_entities


class Cursor:
    def __init__(self, results=()):
        self.results = iter(results)
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))

    def fetchone(self):
        return next(self.results)

    def fetchall(self):
        return next(self.results)


def observed():
    return EntityObservation("sli.fixture", "source-1", "device", (EntityIdentifier("sli.agent.id", "registry-1", "agent-1", "stable"),),
                             datetime(2026, 10, 6, tzinfo=timezone.utc), ("evidence-1",))


def test_creation_uses_canonical_allocation_and_never_requires_domain_or_server():
    cursor = Cursor([{"id": 2}, {"id": 105}, {"id": 105}])
    repo = PostgresIdentityRepository(cursor)
    obs = observed()
    key = obs.identifiers[0].identity_key("device")
    assert repo.ensure_entity("device", key, obs) == 105
    assert "storage_v2_entity_identity_allocations" in cursor.calls[1][0]
    assert "for update" not in cursor.calls[2][0]
    sql, params = cursor.calls[-1]
    assert "insert into entities_v2" in sql and "domain_id" not in sql and "server_id" not in sql
    assert params[:3] == (105, 2, key)
    assert "setval" not in " ".join(sql for sql, _ in cursor.calls)


def test_allocation_conflict_is_not_silently_renumbered():
    repo = PostgresIdentityRepository(Cursor([{"id": 2}, {"id": 105}, {"id": 104}]))
    with pytest.raises(ValueError, match="core_identity_allocation_conflict"):
        repo.ensure_entity("device", "core:fixture", observed())


def test_directory_lookup_is_opt_in_and_ambiguity_includes_both_repositories():
    cursor = Cursor([[{"entity_id": 105}], [{"entity_id": 40}]])
    repo = PostgresIdentityRepository(cursor, identifier_adapters=(find_directory_entities,))
    sid = EntityIdentifier("sli.ad.sid", "ad-domain:1", "S-1-5-21-1-2-3-1001", "stable")
    assert repo.find_identifier("device", sid) == (40, 105)
    assert cursor.calls[1][1] == (1, "object_sid", sid.value.casefold(), "ad_computer")
    cursor = Cursor([[{"entity_id": 105}]])
    assert PostgresIdentityRepository(cursor).find_identifier("device", sid) == (105,)
    assert len(cursor.calls) == 1


def test_stable_identifier_collision_fails_without_overwriting_existing_owner():
    cursor = Cursor([{"entity_id": 40}])
    with pytest.raises(ValueError, match="core_identity_identifier_conflict"):
        PostgresIdentityRepository(cursor).add_identifier(105, "device", observed().identifiers[0])
    assert "on conflict do nothing" in cursor.calls[0][0]


def test_provenance_append_keeps_resolution_and_evidence_and_updates_only_time():
    cursor = Cursor()
    obs = observed()
    PostgresIdentityRepository(cursor).record_observation(obs, IdentityResolution(105, "provisional", reason="no_stable_identifier"))
    assert "update entities_v2 set first_seen_utc" in cursor.calls[0][0]
    sql, params = cursor.calls[-1]
    assert "on conflict(observation_sha256) do nothing" in sql
    assert params[1:5] == ("sli.fixture", "source-1", "device", 105)
    assert params[7:] == (["evidence-1"], "provisional", [], "no_stable_identifier")


def test_association_serializes_source_and_reads_all_confirmed_candidates():
    cursor = Cursor([{"id": 105}, [{"target_entity_id": 40}, {"target_entity_id": 41}]])
    assert PostgresIdentityRepository(cursor).association_targets(105, "directory_computer") == [40, 41]
    assert "pg_advisory_xact_lock" in cursor.calls[0][0]
    assert cursor.calls[0][1] == (105,)


def test_association_records_actor_and_evidence_for_two_devices():
    cursor = Cursor([[{"id": 105, "kind": "device"}, {"id": 40, "kind": "ad_computer"}]])
    PostgresIdentityRepository(cursor).record_association(105, 40, "directory_computer", 7, ("evidence-1",))
    assert cursor.calls[-1][1] == (105, 40, "directory_computer", 7, ["evidence-1"])


@pytest.mark.parametrize("source_kind,target_kind", [("principal", "ad_computer"), ("device", "ad_user"), ("device", "device")])
def test_directory_computer_association_rejects_other_kinds(source_kind, target_kind):
    cursor = Cursor([[{"id": 105, "kind": source_kind}, {"id": 40, "kind": target_kind}]])
    with pytest.raises(ValueError, match="directory_computer_association_requires_devices"):
        PostgresIdentityRepository(cursor).record_association(105, 40, "directory_computer", 7, ("evidence-1",))
    assert len(cursor.calls) == 1

from __future__ import annotations

from copy import deepcopy

import pytest

from server.sli.sources.plugin_contract_v1 import (
    DECISION_PATH,
    FIXTURE_DIR,
    EvidenceFirstLedger,
    PluginContractError,
    inherit_access_label,
    load_json,
    route_event,
    semantic_projection_hash,
    snapshot_status,
    validate_authority_registrations,
    validate_decision_record,
    validate_fixture,
)


@pytest.fixture()
def decision():
    return load_json(DECISION_PATH)


@pytest.fixture()
def shared():
    return load_json(FIXTURE_DIR / "shared_windows_pull.json")


def test_p0a_decision_is_explicitly_fixture_only(decision):
    result = validate_decision_record(decision)
    assert result["decision_id"] == "sli.plugin-architecture.v1"
    assert "source_contact" in result["prohibited_actions"]
    assert "worker_activation" in result["prohibited_actions"]
    assert "postgresql_migration" in result["prohibited_actions"]


def test_all_three_contract_archetypes_validate(decision):
    results = [
        validate_fixture(load_json(path), decision)
        for path in sorted(FIXTURE_DIR.glob("*.json"))
    ]
    assert {item["archetype"] for item in results} == {
        "shared_bounded_pull",
        "snapshot_generation",
        "unique_continuous_transport_declaration",
    }


def test_shared_source_identity_cannot_be_plugin_owned(decision, shared):
    broken = deepcopy(shared)
    broken["source_instance"]["plugin_id"] = "sli.remote-access"
    with pytest.raises(
        PluginContractError, match="source_identity_must_be_consumer_neutral"
    ):
        validate_fixture(broken, decision)


def test_windows_stream_must_remain_full_channel_in_first_pilot(decision, shared):
    broken = deepcopy(shared)
    broken["streams"][0]["collection_policy"] = "union_subscriptions"
    with pytest.raises(PluginContractError, match="collection_policy"):
        validate_fixture(broken, decision)


def test_exact_router_uses_provider_event_key_and_supports_independent_consumers(shared):
    base = {
        "stream_id": "stream-fixture-security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "schema_version": 1,
    }
    assert route_event(shared, {**base, "event_key": "4624"}) == [
        "subscription-fixture-ad"
    ]
    assert route_event(shared, {**base, "event_key": "6272"}) == [
        "subscription-fixture-nps"
    ]
    assert route_event(
        shared, {**base, "provider": "Unrelated-Provider", "event_key": "6272"}
    ) == []


@pytest.mark.parametrize(
    "phase",
    ["evidence_write", "evidence_verify", "before_registry_transaction"],
)
def test_cursor_never_advances_before_evidence_outbox_transaction(shared, phase):
    ledger = EvidenceFirstLedger()
    record = {
        "stream_id": "stream-fixture-security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_key": "6272",
        "schema_version": 1,
        "cursor": 7,
    }
    with pytest.raises(RuntimeError, match="injected"):
        ledger.ingest(shared, record, fail_after=phase)
    assert ledger.transport_cursor == 0
    assert ledger.outbox == set()


def test_replay_is_idempotent_and_consumer_backpressure_isolated(shared):
    ledger = EvidenceFirstLedger()
    ad = {
        "stream_id": "stream-fixture-security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_key": "4624",
        "schema_version": 1,
        "cursor": 10,
    }
    nps = {**ad, "event_key": "6272", "cursor": 11}
    ledger.ingest(shared, ad)
    ledger.ingest(shared, nps)
    ledger.ingest(shared, nps)
    assert ledger.transport_cursor == 11
    assert len(ledger.outbox) == 2
    ledger.deliver("subscription-fixture-ad", 10)
    assert ledger.delivery_positions == {
        "subscription-fixture-ad": 10,
        "subscription-fixture-nps": 0,
    }


def test_authoritative_overlap_is_blocked_but_shadow_is_allowed():
    base = {
        "contract_id": "directory.vpn_entitlements.v1",
        "organization": "fixture-org",
        "authority_kind": "domain",
        "authority_partition_id": "fixture-domain-a",
        "valid_from": 1,
        "valid_to": 100,
    }
    accepted = validate_authority_registrations(
        [{**base, "mode": "authoritative"}, {**base, "mode": "shadow"}]
    )
    assert accepted["shadow_count"] == 1
    with pytest.raises(PluginContractError, match="authority_partition_overlap"):
        validate_authority_registrations(
            [
                {**base, "mode": "authoritative"},
                {
                    **base,
                    "mode": "authoritative",
                    "valid_from": 99,
                    "valid_to": 120,
                },
            ]
        )


def test_information_flow_inherits_all_groups_and_strongest_sensitivity():
    label = inherit_access_label(
        [
            {
                "resource_groups": [[{"kind": "domain", "id": 1}]],
                "row_sensitivity": "restricted",
                "evidence_access_requirement": True,
                "provenance": ["ad"],
            },
            {
                "resource_groups": [[{"kind": "server", "id": 2}]],
                "row_sensitivity": "confidential",
                "evidence_access_requirement": True,
                "provenance": ["nps"],
            },
        ],
        field_visibility_categories={"subject": "identity"},
        producer_contract_version="remote_access.assessment.v1",
    )
    assert len(label["resource_groups"]) == 2
    assert label["row_sensitivity"] == "confidential"
    assert label["provenance"] == ["ad", "nps"]


def test_snapshot_generation_never_calls_partial_complete():
    complete = {
        "expected_pages": [1, 2],
        "received_pages": [1, 2],
        "manifest_verified": True,
        "atomic_publish": True,
    }
    assert snapshot_status(complete) == "complete"
    assert snapshot_status({**complete, "received_pages": [1]}) == "partial"
    assert snapshot_status({**complete, "atomic_publish": False}) == "partial"


def test_worker_boundary_and_detach_reader_are_fail_closed(decision, shared):
    broken_worker = deepcopy(shared)
    broken_worker["worker"]["boundaries"].remove("postgres_role")
    with pytest.raises(PluginContractError, match="worker_boundaries_incomplete"):
        validate_fixture(broken_worker, decision)
    broken_reader = deepcopy(shared)
    broken_reader["detach_reader"]["source_contact"] = True
    with pytest.raises(PluginContractError, match="source_contact_must_equal_False"):
        validate_fixture(broken_reader, decision)


def test_producer_replacement_hash_ignores_only_producer_provenance():
    first = {
        "subject": "fixture",
        "entitlement": "vpn",
        "valid_from": 1,
        "producer_id": "core-ad-context",
        "producer_version": "1",
    }
    replacement = {
        **first,
        "producer_id": "sli.ad-dc",
        "producer_version": "2",
    }
    assert semantic_projection_hash(first) == semantic_projection_hash(replacement)
    assert semantic_projection_hash(first) != semantic_projection_hash(
        {**replacement, "entitlement": "admin-vpn"}
    )



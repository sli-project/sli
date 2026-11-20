"""Pure Stage 9 plugin-contract fixtures.

This module has no database, process, network, source-contact, migration, or
runtime activation entry point.  It exists only to make the accepted P0A
architecture falsifiable in fixture-only P0B tests.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[3]
DECISION_PATH = ROOT / "config" / "plugin_architecture_v1.json"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "plugin_contract_v1"


class PluginContractError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PluginContractError(f"object_required:{path.name}")
    return value


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _require_equal(source: Mapping[str, Any], key: str, expected: Any) -> None:
    if source.get(key) != expected:
        raise PluginContractError(f"{key}_must_equal_{expected}")


def _require_set(source: Mapping[str, Any], key: str, expected: set[str]) -> None:
    actual = source.get(key)
    if not isinstance(actual, list) or set(map(str, actual)) != expected:
        raise PluginContractError(f"{key}_contract_mismatch")


def validate_decision_record(record: Mapping[str, Any]) -> dict[str, Any]:
    _require_equal(record, "schema_version", 1)
    _require_equal(record, "decision_id", "sli.plugin-architecture.v1")
    _require_equal(record, "status", "accepted_for_p0a_p0b_fixture_only")
    _require_equal(record, "package_model", "bundled_reviewed")
    acquisition = dict(record.get("acquisition") or {})
    excluded = set(map(str, acquisition.get("source_identity_excludes") or []))
    forbidden_identity = {
        "plugin_id",
        "component_version",
        "subscription_selector",
        "display_name",
        "credential_generation",
        "adapter_version",
    }
    if not forbidden_identity.issubset(excluded):
        raise PluginContractError("consumer_or_mutable_source_identity_allowed")
    _require_set(
        acquisition,
        "cursor_owner_fields",
        {"source_instance_id", "stream_id", "transport_binding"},
    )
    _require_equal(
        acquisition,
        "existing_windows_stream_policy",
        "full_channel_then_core_evidence_then_subscription_routing",
    )
    routing = dict(record.get("routing") or {})
    _require_equal(routing, "kind", "compiled_subscription_registry")
    _require_equal(routing, "fan_out", True)
    if "event_key" not in set(routing.get("selector_fields") or []):
        raise PluginContractError("event_key_selector_required")
    axes = list(map(str, record.get("state_axes") or []))
    required_axes = {
        "package_lifecycle",
        "desired_activation",
        "observed_health",
        "component_runtime",
        "migration_state",
        "source_state",
        "queue_state",
        "dataset_state",
    }
    if len(axes) != len(set(axes)) or set(axes) != required_axes:
        raise PluginContractError("orthogonal_state_axes_required")
    execution = dict(record.get("execution") or {})
    _require_equal(execution, "sandbox_claimed", False)
    required_boundaries = {
        "windows_identity",
        "job_object",
        "working_directory_acl",
        "network_policy",
        "component_secret_handle",
        "allowlisted_handler",
        "postgres_role",
        "db_timeouts",
        "runtime_identity",
    }
    if set(execution.get("required_boundaries") or []) != required_boundaries:
        raise PluginContractError("worker_boundary_contract_mismatch")
    contracts = dict(record.get("contracts") or {})
    _require_equal(contracts, "owner", "core_contract_registry")
    _require_equal(
        contracts,
        "authority",
        "one_authoritative_producer_per_contract_and_partition",
    )
    _require_equal(contracts, "required_feedback_cycles", False)
    storage = dict(record.get("storage") or {})
    _require_equal(storage, "raw_owner", "core")
    _require_equal(storage, "canonical_evidence_owner", "core")
    _require_equal(
        storage, "authentication_session_warm", "core_hosted_compatibility"
    )
    access = dict(record.get("access") or {})
    required_labels = {
        "resource_groups",
        "row_sensitivity",
        "field_visibility_categories",
        "evidence_access_requirement",
        "producer_contract_version",
        "label_policy_version",
        "provenance",
    }
    if set(access.get("required_labels") or []) != required_labels:
        raise PluginContractError("information_flow_labels_incomplete")
    prohibited = set(record.get("prohibited_until_separate_owner_decision") or [])
    required_prohibitions = {
        "postgresql_migration",
        "clickhouse_migration",
        "worker_activation",
        "windows_service_change",
        "windows_firewall_change",
        "source_contact",
        "nps_radius_inventory",
        "product_runtime_ownership_transfer",
        "autostart",
        "webhook_write_lifecycle",
        "destructive_purge",
    }
    if not required_prohibitions.issubset(prohibited):
        raise PluginContractError("p0b_prohibition_missing")
    return {
        "decision_id": record["decision_id"],
        "decision_hash": canonical_hash(record),
        "state_axes": axes,
        "prohibited_actions": sorted(prohibited),
    }


def _validate_states(fixture: Mapping[str, Any], decision: Mapping[str, Any]) -> None:
    states = fixture.get("states")
    if not isinstance(states, Mapping):
        raise PluginContractError("fixture_states_required")
    if set(states) != set(decision.get("state_axes") or []):
        raise PluginContractError("fixture_state_axes_mismatch")


def _validate_storage_and_reader(fixture: Mapping[str, Any]) -> None:
    storage = dict(fixture.get("storage") or {})
    _require_equal(storage, "raw_owner", "core")
    _require_equal(storage, "canonical_evidence_owner", "core")
    _require_equal(storage, "derived_backend", "postgresql")
    reader = dict(fixture.get("detach_reader") or {})
    if reader.get("kind") not in {
        "core_immutable_snapshot",
        "reviewed_read_only_compatibility_reader",
    }:
        raise PluginContractError("detach_reader_required")
    for key in ("source_contact", "jobs_enabled", "write_rights"):
        _require_equal(reader, key, False)


def _validate_worker(worker: Mapping[str, Any], decision: Mapping[str, Any]) -> None:
    required_identity = {
        "worker_instance_id",
        "component_id",
        "component_version",
        "source_instance_id",
        "process_generation",
    }
    if any(not worker.get(key) for key in required_identity):
        raise PluginContractError("worker_runtime_identity_incomplete")
    required_boundaries = set(
        (decision.get("execution") or {}).get("required_boundaries") or []
    )
    if set(worker.get("boundaries") or []) != required_boundaries:
        raise PluginContractError("worker_boundaries_incomplete")


def validate_fixture(
    fixture: Mapping[str, Any], decision: Mapping[str, Any]
) -> dict[str, Any]:
    fixture_id = str(fixture.get("fixture_id") or "")
    archetype = str(fixture.get("archetype") or "")
    if not fixture_id or archetype not in set(decision.get("p0b_archetypes") or []):
        raise PluginContractError("unknown_fixture_archetype")
    _require_equal(fixture, "runtime_enabled", False)
    package = dict(fixture.get("package") or {})
    _require_equal(package, "delivery", "bundled_reviewed")
    if not str(package.get("handler_id") or "").endswith("fixture-handler"):
        raise PluginContractError("allowlisted_fixture_handler_required")
    _validate_states(fixture, decision)
    _validate_storage_and_reader(fixture)

    checks = ["runtime_disabled", "bundled_reviewed", "orthogonal_states"]
    if archetype == "shared_bounded_pull":
        source = dict(fixture.get("source_instance") or {})
        if "plugin_id" in source or not source.get("endpoint_identity"):
            raise PluginContractError("source_identity_must_be_consumer_neutral")
        streams = [dict(item) for item in fixture.get("streams") or []]
        subscriptions = [dict(item) for item in fixture.get("subscriptions") or []]
        if len(streams) != 1 or len(subscriptions) < 2:
            raise PluginContractError("shared_stream_requires_two_consumers")
        stream = streams[0]
        _require_equal(stream, "collection_policy", "full_channel")
        if any(item.get("stream_id") != stream.get("stream_id") for item in subscriptions):
            raise PluginContractError("subscription_stream_mismatch")
        if len({item.get("delivery_position") for item in subscriptions}) != 1:
            raise PluginContractError("fixture_delivery_positions_must_start_equal")
        if len({item.get("subscription_id") for item in subscriptions}) != len(subscriptions):
            raise PluginContractError("subscription_identity_collision")
        _validate_worker(dict(fixture.get("worker") or {}), decision)
        checks += ["consumer_neutral_source", "full_channel", "independent_subscriptions"]
    elif archetype == "snapshot_generation":
        snapshot = dict(fixture.get("snapshot") or {})
        if snapshot_status(snapshot) != "complete":
            raise PluginContractError("snapshot_fixture_not_complete")
        checks += ["snapshot_complete", "atomic_publish"]
    else:
        transport = dict(fixture.get("transport") or {})
        _require_equal(transport, "source_contact", False)
        for key in ("offset_semantics", "gap_semantics", "replay_semantics"):
            if not transport.get(key):
                raise PluginContractError(f"{key}_required")
        _validate_worker(dict(fixture.get("worker") or {}), decision)
        checks += ["continuous_declared_not_started", "gap_semantics"]
    return {
        "fixture_id": fixture_id,
        "archetype": archetype,
        "fixture_hash": canonical_hash(fixture),
        "checks": checks,
    }


def route_event(fixture: Mapping[str, Any], event: Mapping[str, Any]) -> list[str]:
    routes: list[str] = []
    for subscription in fixture.get("subscriptions") or []:
        if (
            str(subscription.get("stream_id")) == str(event.get("stream_id"))
            and str(subscription.get("provider")).casefold()
            == str(event.get("provider")).casefold()
            and str(event.get("event_key")) in set(
                map(str, subscription.get("event_keys") or [])
            )
            and int(subscription.get("schema_version") or 0)
            == int(event.get("schema_version") or 0)
        ):
            routes.append(str(subscription["subscription_id"]))
    return sorted(routes)


@dataclass
class EvidenceFirstLedger:
    transport_cursor: int = 0
    evidence: dict[str, bool] = field(default_factory=dict)
    outbox: set[tuple[str, str]] = field(default_factory=set)
    delivery_positions: dict[str, int] = field(default_factory=dict)

    def ingest(
        self,
        fixture: Mapping[str, Any],
        record: Mapping[str, Any],
        *,
        fail_after: str | None = None,
    ) -> dict[str, Any]:
        evidence_uid = canonical_hash(record)
        self.evidence.setdefault(evidence_uid, False)
        if fail_after == "evidence_write":
            raise RuntimeError("injected_after_evidence_write")
        self.evidence[evidence_uid] = True
        if fail_after == "evidence_verify":
            raise RuntimeError("injected_after_evidence_verify")
        routes = route_event(fixture, record)
        if fail_after == "before_registry_transaction":
            raise RuntimeError("injected_before_registry_transaction")
        cursor = int(record.get("cursor") or 0)
        for subscription_id in routes:
            self.outbox.add((subscription_id, evidence_uid))
            self.delivery_positions.setdefault(subscription_id, 0)
        self.transport_cursor = max(self.transport_cursor, cursor)
        return {"evidence_uid": evidence_uid, "routes": routes}

    def deliver(self, subscription_id: str, position: int) -> None:
        if subscription_id not in self.delivery_positions:
            raise PluginContractError("unknown_subscription_delivery")
        self.delivery_positions[subscription_id] = max(
            self.delivery_positions[subscription_id], int(position)
        )


def snapshot_status(snapshot: Mapping[str, Any]) -> str:
    expected = list(snapshot.get("expected_pages") or [])
    received = list(snapshot.get("received_pages") or [])
    if len(expected) != len(set(expected)) or len(received) != len(set(received)):
        return "invalid"
    if not snapshot.get("manifest_verified") or not snapshot.get("atomic_publish"):
        return "partial"
    return "complete" if set(expected) == set(received) and expected else "partial"


def validate_authority_registrations(
    registrations: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    authoritative: dict[tuple[str, str, str, str], list[tuple[int, int]]] = {}
    shadow_count = 0
    for source in registrations:
        item = dict(source)
        key = (
            str(item.get("contract_id") or ""),
            str(item.get("organization") or ""),
            str(item.get("authority_kind") or ""),
            str(item.get("authority_partition_id") or ""),
        )
        if not all(key):
            raise PluginContractError("authority_partition_identity_incomplete")
        if item.get("mode") == "shadow":
            shadow_count += 1
            continue
        if item.get("mode") != "authoritative":
            raise PluginContractError("producer_mode_invalid")
        start, end = int(item.get("valid_from") or 0), int(item.get("valid_to") or 0)
        if end <= start:
            raise PluginContractError("authority_interval_invalid")
        intervals = authoritative.setdefault(key, [])
        if any(start < old_end and old_start < end for old_start, old_end in intervals):
            raise PluginContractError("authority_partition_overlap")
        intervals.append((start, end))
    return {
        "authority_partition_count": len(authoritative),
        "authoritative_interval_count": sum(map(len, authoritative.values())),
        "shadow_count": shadow_count,
    }


SENSITIVITY_ORDER = {"internal": 1, "restricted": 2, "confidential": 3}


def inherit_access_label(
    inputs: Iterable[Mapping[str, Any]],
    *,
    field_visibility_categories: Mapping[str, str],
    producer_contract_version: str,
) -> dict[str, Any]:
    items = [dict(item) for item in inputs]
    if not items:
        raise PluginContractError("mandatory_input_labels_required")
    groups: list[list[dict[str, Any]]] = []
    evidence_required = False
    sensitivities: list[str] = []
    provenance: list[str] = []
    for item in items:
        resource_groups = item.get("resource_groups")
        if not isinstance(resource_groups, list) or not resource_groups:
            raise PluginContractError("resource_groups_required")
        groups.extend(resource_groups)
        sensitivity = str(item.get("row_sensitivity") or "")
        if sensitivity not in SENSITIVITY_ORDER:
            raise PluginContractError("row_sensitivity_invalid")
        sensitivities.append(sensitivity)
        evidence_required = evidence_required or bool(
            item.get("evidence_access_requirement")
        )
        provenance.extend(map(str, item.get("provenance") or []))
    maximum = max(sensitivities, key=SENSITIVITY_ORDER.__getitem__)
    return {
        "resource_groups": groups,
        "row_sensitivity": maximum,
        "field_visibility_categories": dict(field_visibility_categories),
        "evidence_access_requirement": evidence_required,
        "producer_contract_version": producer_contract_version,
        "label_policy_version": 1,
        "provenance": sorted(set(provenance)),
    }


def semantic_projection_hash(value: Mapping[str, Any]) -> str:
    excluded = {"producer_id", "producer_version", "observed_at"}
    return canonical_hash({key: item for key, item in value.items() if key not in excluded})

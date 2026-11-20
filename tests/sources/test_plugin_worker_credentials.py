from __future__ import annotations

import hashlib
import json

import pytest

from server.sli.sources.plugin_worker_credentials import (
    CredentialHandleBinding,
    CredentialLeaseRequest,
    InMemoryFixtureCredentialBroker,
    PluginCredentialError,
)


SECRET = "fixture-super-secret"
ALLOWED = {
    "source_read": ("SLI_PLUGIN_SOURCE_CREDENTIAL",),
    "plugin_postgres": ("SLI_PLUGIN_PG_DSN",),
}
PROHIBITED = frozenset(
    {"ADLOG_PG_DSN", "ADLOG_PG_ADMIN_USER", "ADLOG_PG_ADMIN_PASSWORD"}
)


def _handle(seed: str) -> str:
    return "credh:v1:" + hashlib.sha256(seed.encode()).hexdigest()


def _binding(generation: int) -> CredentialHandleBinding:
    return CredentialHandleBinding(
        handle_id=_handle(str(generation)),
        plugin_id="sli.vpn-radius",
        component_id="radius-acquisition",
        source_instance_id="radius-fixture",
        credential_generation=generation,
        scope="source_read",
        environment_names=("SLI_PLUGIN_SOURCE_CREDENTIAL",),
        handler_sha256=hashlib.sha256(b"handler").hexdigest(),
    )


def _request(binding: CredentialHandleBinding, **overrides) -> CredentialLeaseRequest:
    values = {
        "handle_id": binding.handle_id,
        "plugin_id": binding.plugin_id,
        "component_id": binding.component_id,
        "source_instance_id": binding.source_instance_id,
        "credential_generation": binding.credential_generation,
        "scope": binding.scope,
        "environment_names": binding.environment_names,
        "handler_sha256": binding.handler_sha256,
        "worker_instance_id": "worker-fixture-1",
        "runtime_instance_id": "runtime-fixture-1",
        "ttl_seconds": 60,
    }
    values.update(overrides)
    return CredentialLeaseRequest(**values)


def _broker(*bindings: CredentialHandleBinding) -> InMemoryFixtureCredentialBroker:
    return InMemoryFixtureCredentialBroker(
        bindings=tuple(bindings),
        fixture_materials={
            binding.handle_id: {
                "SLI_PLUGIN_SOURCE_CREDENTIAL": SECRET + str(binding.credential_generation)
            }
            for binding in bindings
        },
        allowed_scopes=ALLOWED,
        prohibited_environment_names=PROHIBITED,
    )


def test_exact_binding_materializes_only_allowlisted_child_environment():
    binding = _binding(1)
    broker = _broker(binding)
    lease = broker.issue_lease(_request(binding), now_epoch_seconds=100)
    assert broker.materialize_child_environment(lease, now_epoch_seconds=101) == {
        "SLI_PLUGIN_SOURCE_CREDENTIAL": SECRET + "1"
    }
    assert SECRET not in repr(lease)
    assert SECRET not in repr(broker)
    assert SECRET not in json.dumps(lease.audit_metadata(outcome="accepted"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("plugin_id", "sli.other"),
        ("component_id", "other-component"),
        ("source_instance_id", "other-source"),
        ("credential_generation", 2),
        ("handler_sha256", "f" * 64),
        ("runtime_instance_id", "INVALID SPACE"),
    ],
)
def test_mismatched_or_invalid_request_fails_closed(field, value):
    binding = _binding(1)
    broker = _broker(binding)
    with pytest.raises(PluginCredentialError):
        broker.issue_lease(
            _request(binding, **{field: value}), now_epoch_seconds=100
        )


def test_rotation_blocks_new_old_generation_but_existing_lease_drains_to_expiry():
    first = _binding(1)
    second = _binding(2)
    broker = _broker(first, second)
    old_lease = broker.issue_lease(_request(first), now_epoch_seconds=100)
    broker.rotate_to_generation(
        plugin_id=first.plugin_id,
        component_id=first.component_id,
        source_instance_id=first.source_instance_id,
        credential_generation=2,
    )
    with pytest.raises(
        PluginCredentialError, match="credential_generation_not_active"
    ):
        broker.issue_lease(_request(first), now_epoch_seconds=101)
    assert broker.materialize_child_environment(old_lease, now_epoch_seconds=159)
    with pytest.raises(PluginCredentialError, match="lease_expired"):
        broker.materialize_child_environment(old_lease, now_epoch_seconds=160)
    new_lease = broker.issue_lease(_request(second), now_epoch_seconds=101)
    assert broker.materialize_child_environment(new_lease, now_epoch_seconds=102)


def test_revoked_handle_and_lease_fail_closed():
    binding = _binding(1)
    broker = _broker(binding)
    lease = broker.issue_lease(_request(binding), now_epoch_seconds=100)
    broker.revoke_lease(lease.lease_id)
    with pytest.raises(PluginCredentialError, match="lease_revoked"):
        broker.materialize_child_environment(lease, now_epoch_seconds=101)
    broker.revoke_handle(binding.handle_id)
    with pytest.raises(PluginCredentialError, match="handle_revoked"):
        broker.issue_lease(_request(binding), now_epoch_seconds=101)


def test_rotation_cannot_skip_a_generation():
    first = _binding(1)
    third = _binding(3)
    broker = _broker(first, third)
    with pytest.raises(
        PluginCredentialError, match="generation_must_advance_by_one"
    ):
        broker.rotate_to_generation(
            plugin_id=first.plugin_id,
            component_id=first.component_id,
            source_instance_id=first.source_instance_id,
            credential_generation=3,
        )


def test_admin_or_generic_project_postgres_environment_is_rejected():
    broken = CredentialHandleBinding(
        **{
            **_binding(1).__dict__,
            "scope": "plugin_postgres",
            "environment_names": ("ADLOG_PG_DSN",),
        }
    )
    with pytest.raises(PluginCredentialError, match="prohibited_environment_name"):
        _broker(broken)


def test_source_identity_is_stable_across_credential_rotation():
    assert _binding(1).stable_source_identity() == _binding(2).stable_source_identity()



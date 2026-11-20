"""Fixture-only credential-handle contract for isolated plugin workers.

The module deliberately has no DPAPI, filesystem, process, network or database
integration.  It proves exact binding, bounded leases, rotation and safe audit
metadata before any live credential backend is designed or enabled.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Mapping


HANDLE_RE = re.compile(r"^credh:v1:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENVIRONMENT_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


class PluginCredentialError(ValueError):
    """Fail-closed contract violation without credential material."""


@dataclass(frozen=True)
class CredentialHandleBinding:
    handle_id: str
    plugin_id: str
    component_id: str
    source_instance_id: str
    credential_generation: int
    scope: str
    environment_names: tuple[str, ...]
    handler_sha256: str

    def stable_source_identity(self) -> str:
        payload = "\x1f".join(
            (self.plugin_id, self.component_id, self.source_instance_id)
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CredentialLeaseRequest:
    handle_id: str
    plugin_id: str
    component_id: str
    source_instance_id: str
    credential_generation: int
    scope: str
    environment_names: tuple[str, ...]
    handler_sha256: str
    worker_instance_id: str
    runtime_instance_id: str
    ttl_seconds: int


class CredentialLease:
    """A child-only materialization object whose repr/audit omit values."""

    __slots__ = (
        "lease_id",
        "handle_id",
        "plugin_id",
        "component_id",
        "source_instance_id",
        "credential_generation",
        "scope",
        "worker_instance_id",
        "runtime_instance_id",
        "environment_names",
        "issued_at_epoch_seconds",
        "expires_at_epoch_seconds",
        "_values",
    )

    def __init__(
        self,
        *,
        lease_id: str,
        binding: CredentialHandleBinding,
        request: CredentialLeaseRequest,
        issued_at_epoch_seconds: int,
        values: Mapping[str, str],
    ) -> None:
        self.lease_id = lease_id
        self.handle_id = binding.handle_id
        self.plugin_id = binding.plugin_id
        self.component_id = binding.component_id
        self.source_instance_id = binding.source_instance_id
        self.credential_generation = binding.credential_generation
        self.scope = binding.scope
        self.worker_instance_id = request.worker_instance_id
        self.runtime_instance_id = request.runtime_instance_id
        self.environment_names = binding.environment_names
        self.issued_at_epoch_seconds = issued_at_epoch_seconds
        self.expires_at_epoch_seconds = issued_at_epoch_seconds + request.ttl_seconds
        self._values = dict(values)

    def __repr__(self) -> str:
        return (
            "CredentialLease(lease_id={!r}, handle_id={!r}, plugin_id={!r}, "
            "component_id={!r}, source_instance_id={!r}, "
            "credential_generation={!r}, scope={!r}, worker_instance_id={!r}, "
            "runtime_instance_id={!r}, environment_names={!r}, "
            "issued_at_epoch_seconds={!r}, expires_at_epoch_seconds={!r})"
        ).format(
            self.lease_id,
            self.handle_id,
            self.plugin_id,
            self.component_id,
            self.source_instance_id,
            self.credential_generation,
            self.scope,
            self.worker_instance_id,
            self.runtime_instance_id,
            self.environment_names,
            self.issued_at_epoch_seconds,
            self.expires_at_epoch_seconds,
        )

    def audit_metadata(self, *, outcome: str) -> dict[str, object]:
        return {
            "lease_id": self.lease_id,
            "handle_id": self.handle_id,
            "plugin_id": self.plugin_id,
            "component_id": self.component_id,
            "source_instance_id": self.source_instance_id,
            "credential_generation": self.credential_generation,
            "scope": self.scope,
            "worker_instance_id": self.worker_instance_id,
            "runtime_instance_id": self.runtime_instance_id,
            "environment_names": list(self.environment_names),
            "issued_at_epoch_seconds": self.issued_at_epoch_seconds,
            "expires_at_epoch_seconds": self.expires_at_epoch_seconds,
            "outcome": outcome,
        }


def validate_binding(
    binding: CredentialHandleBinding,
    *,
    allowed_scopes: Mapping[str, tuple[str, ...]],
    prohibited_environment_names: frozenset[str],
    max_environment_names: int,
) -> None:
    if not HANDLE_RE.fullmatch(binding.handle_id):
        raise PluginCredentialError("invalid_handle_id")
    for name, value in (
        ("plugin_id", binding.plugin_id),
        ("component_id", binding.component_id),
        ("source_instance_id", binding.source_instance_id),
    ):
        if not IDENTIFIER_RE.fullmatch(value):
            raise PluginCredentialError(f"invalid_{name}")
    if binding.credential_generation < 1:
        raise PluginCredentialError("invalid_credential_generation")
    if not SHA256_RE.fullmatch(binding.handler_sha256):
        raise PluginCredentialError("invalid_handler_sha256")
    allowed_names = allowed_scopes.get(binding.scope)
    if allowed_names is None:
        raise PluginCredentialError("scope_not_allowed")
    if not binding.environment_names or len(binding.environment_names) > max_environment_names:
        raise PluginCredentialError("environment_name_count_out_of_bounds")
    if len(set(binding.environment_names)) != len(binding.environment_names):
        raise PluginCredentialError("duplicate_environment_name")
    for environment_name in binding.environment_names:
        if not ENVIRONMENT_RE.fullmatch(environment_name):
            raise PluginCredentialError("invalid_environment_name")
        if environment_name in prohibited_environment_names:
            raise PluginCredentialError("prohibited_environment_name")
        if environment_name not in allowed_names:
            raise PluginCredentialError("environment_name_not_allowed_for_scope")


class InMemoryFixtureCredentialBroker:
    """Deterministic fixture broker; never use as a live secret backend."""

    def __init__(
        self,
        *,
        bindings: tuple[CredentialHandleBinding, ...],
        fixture_materials: Mapping[str, Mapping[str, str]],
        allowed_scopes: Mapping[str, tuple[str, ...]],
        prohibited_environment_names: frozenset[str],
        max_environment_names: int = 8,
        max_ttl_seconds: int = 900,
    ) -> None:
        if max_environment_names < 1 or max_ttl_seconds < 1:
            raise PluginCredentialError("invalid_broker_limits")
        self._allowed_scopes = dict(allowed_scopes)
        self._prohibited_environment_names = prohibited_environment_names
        self._max_environment_names = max_environment_names
        self._max_ttl_seconds = max_ttl_seconds
        self._bindings: dict[str, CredentialHandleBinding] = {}
        self._materials: dict[str, dict[str, str]] = {}
        self._active_generations: dict[tuple[str, str, str], int] = {}
        self._revoked_handles: set[str] = set()
        self._revoked_leases: set[str] = set()
        self._issued_leases: dict[str, CredentialLease] = {}
        self._lease_sequence = 0
        for binding in bindings:
            validate_binding(
                binding,
                allowed_scopes=self._allowed_scopes,
                prohibited_environment_names=self._prohibited_environment_names,
                max_environment_names=self._max_environment_names,
            )
            if binding.handle_id in self._bindings:
                raise PluginCredentialError("duplicate_handle_id")
            material = dict(fixture_materials.get(binding.handle_id, {}))
            if tuple(sorted(material)) != tuple(sorted(binding.environment_names)):
                raise PluginCredentialError("fixture_material_shape_mismatch")
            if any(not isinstance(value, str) or not value for value in material.values()):
                raise PluginCredentialError("empty_fixture_material")
            self._bindings[binding.handle_id] = binding
            self._materials[binding.handle_id] = material
            key = self._binding_key(binding)
            current = self._active_generations.get(key)
            self._active_generations[key] = (
                binding.credential_generation
                if current is None
                else min(current, binding.credential_generation)
            )

    def __repr__(self) -> str:
        return (
            "InMemoryFixtureCredentialBroker(binding_count={!r}, "
            "active_source_count={!r})"
        ).format(len(self._bindings), len(self._active_generations))

    @staticmethod
    def _binding_key(
        binding: CredentialHandleBinding | CredentialLeaseRequest,
    ) -> tuple[str, str, str]:
        return (
            binding.plugin_id,
            binding.component_id,
            binding.source_instance_id,
        )

    def rotate_to_generation(
        self,
        *,
        plugin_id: str,
        component_id: str,
        source_instance_id: str,
        credential_generation: int,
    ) -> None:
        key = (plugin_id, component_id, source_instance_id)
        current = self._active_generations.get(key)
        if current is None:
            raise PluginCredentialError("unknown_source_binding")
        if credential_generation != current + 1:
            raise PluginCredentialError("generation_must_advance_by_one")
        if not any(
            self._binding_key(binding) == key
            and binding.credential_generation == credential_generation
            for binding in self._bindings.values()
        ):
            raise PluginCredentialError("target_generation_not_registered")
        self._active_generations[key] = credential_generation

    def revoke_handle(self, handle_id: str) -> None:
        if handle_id not in self._bindings:
            raise PluginCredentialError("unknown_handle")
        self._revoked_handles.add(handle_id)

    def revoke_lease(self, lease_id: str) -> None:
        self._revoked_leases.add(lease_id)

    def issue_lease(
        self,
        request: CredentialLeaseRequest,
        *,
        now_epoch_seconds: int,
    ) -> CredentialLease:
        binding = self._bindings.get(request.handle_id)
        if binding is None:
            raise PluginCredentialError("unknown_handle")
        if request.handle_id in self._revoked_handles:
            raise PluginCredentialError("handle_revoked")
        if request.ttl_seconds < 1 or request.ttl_seconds > self._max_ttl_seconds:
            raise PluginCredentialError("lease_ttl_out_of_bounds")
        exact = (
            request.plugin_id == binding.plugin_id
            and request.component_id == binding.component_id
            and request.source_instance_id == binding.source_instance_id
            and request.credential_generation == binding.credential_generation
            and request.scope == binding.scope
            and request.environment_names == binding.environment_names
            and request.handler_sha256 == binding.handler_sha256
        )
        if not exact:
            raise PluginCredentialError("credential_binding_mismatch")
        for instance_name, value in (
            ("worker_instance_id", request.worker_instance_id),
            ("runtime_instance_id", request.runtime_instance_id),
        ):
            if not IDENTIFIER_RE.fullmatch(value):
                raise PluginCredentialError(f"invalid_{instance_name}")
        active = self._active_generations[self._binding_key(binding)]
        if request.credential_generation != active:
            raise PluginCredentialError("credential_generation_not_active")
        self._lease_sequence += 1
        lease_id = "credlease:v1:{:016x}".format(self._lease_sequence)
        lease = CredentialLease(
            lease_id=lease_id,
            binding=binding,
            request=request,
            issued_at_epoch_seconds=now_epoch_seconds,
            values=self._materials[binding.handle_id],
        )
        self._issued_leases[lease_id] = lease
        return lease

    def materialize_child_environment(
        self,
        lease: CredentialLease,
        *,
        now_epoch_seconds: int,
    ) -> dict[str, str]:
        if self._issued_leases.get(lease.lease_id) is not lease:
            raise PluginCredentialError("lease_not_issued_by_broker")
        if lease.lease_id in self._revoked_leases:
            raise PluginCredentialError("lease_revoked")
        if now_epoch_seconds >= lease.expires_at_epoch_seconds:
            raise PluginCredentialError("lease_expired")
        binding = self._bindings.get(lease.handle_id)
        if binding is None or binding.handle_id in self._revoked_handles:
            raise PluginCredentialError("handle_revoked")
        if tuple(sorted(lease._values)) != tuple(sorted(binding.environment_names)):
            raise PluginCredentialError("lease_material_shape_mismatch")
        return dict(lease._values)

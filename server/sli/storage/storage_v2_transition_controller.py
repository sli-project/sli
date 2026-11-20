"""Sealed Storage V2 route authorization and route-consumer registry.

The controller has no database, worker, environment, or mutable-runtime
adapter, so an authorization is a bounded record rather than a live change.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Mapping


CONTROLLER_AUTHORITY = "storage-v2-transition-controller/v1"
_ISSUANCE_SEAL = object()


class StorageRouteConsumer:
    """Stable capability subjects served by the Storage V2 route."""

    ANALYSIS = "analysis"
    DASHBOARD = "dashboard"
    EVENT_DETAILS = "event-details"
    EVENT_ENTITIES = "event-entities"
    EVENT_RELATIONS = "event-relations"
    EVENT_SEARCH = "event-search"
    EVENTS = "events"
    FINDINGS = "findings"
    INVESTIGATIONS = "investigations"
    ROLE_VIEWS = "role-views"
    SECURITY_EVENTS_MONITOR = "security-events-monitor"


STORAGE_ROUTE_CONSUMERS = frozenset(
    value for name, value in vars(StorageRouteConsumer).items() if name.isupper()
)


@dataclass(frozen=True)
class CutoverAuthorization(Mapping[str, object]):
    """Immutable V2 route authorization issued only after fresh preflight."""

    preflight_digest: str
    _issuance_seal: object
    authority: str = CONTROLLER_AUTHORITY
    status: str = "AUTHORIZED"
    mode: str = "dormant"
    route: str = "v2"
    owner: str = "V2"
    authorization: str = "controller"

    def __getitem__(self, key: str) -> object:
        return self._public_values()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._public_values())

    def __len__(self) -> int:
        return len(self._public_values())

    def _public_values(self) -> dict[str, object]:
        return {
            "status": self.status,
            "mode": self.mode,
            "route": self.route,
            "owner": self.owner,
            "authorization": self.authorization,
            "authority": self.authority,
            "preflight_digest": self.preflight_digest,
            "side_effects": [],
            "recovery": _recovery_boundary(),
        }


def is_controller_authorization(value: object) -> bool:
    """Return whether ``value`` is a fresh controller-issued V2 authorization."""
    return (
        isinstance(value, CutoverAuthorization)
        and value._issuance_seal is _ISSUANCE_SEAL
        and value.authority == CONTROLLER_AUTHORITY
        and value.status == "AUTHORIZED"
        and value.mode == "dormant"
        and value.route == "v2"
        and value.owner == "V2"
        and value.authorization == "controller"
        and bool(value.preflight_digest)
    )


def issue_controller_authorization(preflight_digest: str) -> CutoverAuthorization:
    """Issue the sealed, inert V2 route authorization bound to ``preflight_digest``."""
    if not isinstance(preflight_digest, str) or not preflight_digest:
        raise ValueError("preflight_digest is required")
    return CutoverAuthorization(
        preflight_digest=preflight_digest,
        _issuance_seal=_ISSUANCE_SEAL,
    )


def _recovery_boundary() -> dict[str, object]:
    return {
        "before_v2_only_writes": {
            "classification": "IMMEDIATE_ROUTE_ROLLBACK",
            "requires": ["verified_v1_mirror_continuity"],
        },
        "after_v2_only_writes": {
            "classification": "LONG_HORIZON_RECOVERY",
            "not_rollback": "V1 cannot represent V2-only writes",
            "requires": ["verified_v2_archive", "independently_verified_backup_restore"],
        },
    }

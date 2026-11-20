import pytest

from server.sli.semantic.semantic_risk import IdentityResolution
from server.sli.semantic.semantic_risk_runtime_repository import (
    _candidate_identity_resolution,
)


def _evidence(
    role: str,
    value: str,
    *,
    state: str | None = None,
    metadata_key: str | None = None,
) -> dict[str, object]:
    quality: dict[str, object] = {}
    if state is not None:
        quality["identity_roles"] = {
            role: {
                "key": metadata_key if metadata_key is not None else value,
                "state": state,
            }
        }
    return {
        "roles_json": {role: value},
        "quality_json": quality,
    }


def test_candidate_identity_confidence_uses_weakest_ladder_state() -> None:
    evidence = [
        _evidence("affected_entity", "sid:S-1-5-21-1", state="resolved"),
        _evidence(
            "affected_entity",
            "sam:example:alice",
            state="provisional",
        ),
    ]

    assert _candidate_identity_resolution(
        evidence,
        strict_roles=("affected_entity",),
    ) is IdentityResolution.PARTIAL


def test_candidate_identity_confidence_fails_closed_without_metadata() -> None:
    assert _candidate_identity_resolution(
        [_evidence("actor", "name:operator")],
        strict_roles=("actor",),
    ) is IdentityResolution.UNKNOWN
    assert _candidate_identity_resolution(
        [_evidence("actor", "name:operator", state="unresolved")],
        strict_roles=("actor",),
    ) is IdentityResolution.UNRESOLVED


def test_candidate_session_scope_is_intrinsically_exact() -> None:
    assert _candidate_identity_resolution(
        [_evidence("session_principal", "1:0xabc")],
        strict_roles=("session_principal",),
    ) is IdentityResolution.EXACT


def test_candidate_identity_metadata_must_match_strict_role() -> None:
    with pytest.raises(RuntimeError, match="differs from strict role"):
        _candidate_identity_resolution(
            [
                _evidence(
                    "actor",
                    "sid:S-1-5-21-1",
                    state="resolved",
                    metadata_key="sid:S-1-5-21-2",
                )
            ],
            strict_roles=("actor",),
        )

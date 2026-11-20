from __future__ import annotations

from dataclasses import replace

from server.sli.storage.runtime_storage import StorageRouteAuthorizationError, resolve_storage_route
import pytest

from server.sli.storage.storage_v2_config import load_storage_v2_settings
from server.sli.storage.storage_v2_transition_controller import (
    CONTROLLER_AUTHORITY,
    is_controller_authorization,
    issue_controller_authorization,
)

_DIGEST = "a" * 64


def test_route_is_storage_v2_even_when_configuration_asks_for_v1(monkeypatch) -> None:
    """The V1 relations were dropped (migration 097, plan 6.5): no route returns to V1."""
    monkeypatch.setenv("ADLOG_STORAGE_READ_MODE", "v1")
    assert resolve_storage_route() == {
        "status": "READY",
        "route": "v2",
        "owner": "V2",
        "authorization": "configured",
    }


def test_pre_cutover_v2_profile_selects_configured_v2_without_transition(monkeypatch, tmp_path) -> None:
    """The declared V2 profile is the route before a transition state exists."""
    monkeypatch.setenv("ADLOG_STORAGE_READ_MODE", "v2")
    monkeypatch.setenv("ADLOG_STORAGE_WRITE_MODE", "v2")
    monkeypatch.setenv("ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE", "0.25")

    settings = load_storage_v2_settings()

    assert settings.valid is True
    assert settings.read_mode == settings.write_mode == "v2"
    assert resolve_storage_route() == {
        "status": "READY",
        "route": "v2",
        "owner": "V2",
        "authorization": "configured",
    }


def test_controller_authorization_is_dormant_and_selects_v2() -> None:
    """Only a controller-issued authorization object may select the V2 route."""
    authorization = issue_controller_authorization(_DIGEST)

    assert is_controller_authorization(authorization)
    assert authorization["status"] == "AUTHORIZED"
    assert authorization["mode"] == "dormant"
    assert authorization["side_effects"] == []
    assert authorization["authority"] == CONTROLLER_AUTHORITY
    assert resolve_storage_route(authorization=authorization)["route"] == "v2"
    with pytest.raises(StorageRouteAuthorizationError):
        resolve_storage_route(authorization={
            "status": "AUTHORIZED",
            "route": "v2",
            "authority": CONTROLLER_AUTHORITY,
            "preflight_digest": authorization["preflight_digest"],
        })


def test_controller_authorization_requires_a_digest() -> None:
    with pytest.raises(ValueError):
        issue_controller_authorization("")


def test_selected_or_invalid_transition_state_never_falls_back_to_v1() -> None:
    """A cutover state without a valid authorization must stop routing."""
    with pytest.raises(StorageRouteAuthorizationError):
        resolve_storage_route(transition_state={"status": "V2_SELECTED"})
    with pytest.raises(StorageRouteAuthorizationError):
        resolve_storage_route(authorization=object())


def test_modified_controller_authorization_cannot_select_a_route() -> None:
    """An immutable capability is rejected if its declared V2 route is altered."""
    authorization = issue_controller_authorization(_DIGEST)

    with pytest.raises(StorageRouteAuthorizationError):
        resolve_storage_route(authorization=replace(authorization, route="v1"))


def test_environment_write_modes_cannot_bypass_controller_authority(tmp_path) -> None:
    """ADLOG_STORAGE_* settings cannot independently activate V2 writes."""
    settings = load_storage_v2_settings({
        "ADLOG_STORAGE_READ_MODE": "v1",
        "ADLOG_STORAGE_WRITE_MODE": "v1_outbox",
    })

    assert settings.valid is False
    assert settings.outbox_enabled is False
    assert settings.v2_primary_write_enabled is False
    assert "controller" in settings.diagnostics[0]

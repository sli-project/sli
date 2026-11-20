from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from server.source_packs.radius.collection_routes import (
    RadiusCollectionRouteError,
    load_radius_collection_routes,
    require_accounting_source,
    validate_radius_collection_routes,
)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "stage10_radius_collection_routes_v1.json"


def _contract() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def test_environment_selects_external_routes(monkeypatch, tmp_path) -> None:
    value = _contract()
    host = "radius02.example.test"
    value.update(source_name=host, connect_address=host, source_instance_id="radius-source-02")
    value["accounting_route"]["share_unc"] = rf"\\{host}\Accounting$"
    path = tmp_path / "routes.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setenv("ADLOG_RADIUS_COLLECTION_ROUTES_PATH", str(path))

    result = load_radius_collection_routes()

    assert result["source_name"] == "radius02.example.test"
    assert result["source_instance_id"] == "radius-source-02"
    assert result["accounting_share_unc"] == r"\\radius02.example.test\Accounting$"


def test_environment_endpoint_overrides_keep_identity_consistent(monkeypatch) -> None:
    monkeypatch.setenv("ADLOG_RADIUS_SOURCE_NAME", "radius02.example.test")
    monkeypatch.setenv("ADLOG_RADIUS_SOURCE_INSTANCE_ID", "radius-source-02")
    monkeypatch.setenv("ADLOG_RADIUS_ACCOUNTING_SHARE_UNC", r"\\radius02.example.test\Accounting$")

    result = load_radius_collection_routes()

    assert result["source_name"] == "radius02.example.test"
    assert result["source_instance_id"] == "radius-source-02"
    assert result["accounting_ready"] is True


def test_environment_identity_reaches_registration_lease_and_consumer(monkeypatch) -> None:
    from server.source_packs.radius.accounting_manual_control import (
        load_manual_control_contract,
    )
    from server.source_packs.radius.accounting_registration import (
        load_registration_contract,
    )
    from server.source_packs.radius.session_consumer import load_consumer_contract

    monkeypatch.setenv("ADLOG_RADIUS_SOURCE_NAME", "radius02.example.test")
    monkeypatch.setenv("ADLOG_RADIUS_SOURCE_INSTANCE_ID", "radius-source-02")
    monkeypatch.setenv("ADLOG_RADIUS_OWNER_CONFIRMED_IP", "198.51.100.24")
    monkeypatch.setenv("ADLOG_RADIUS_ACCOUNTING_SHARE_UNC", r"\\radius02.example.test\Accounting$")

    registration = load_registration_contract()
    assert registration["source"]["source_instance_id"] == "radius-source-02"
    assert registration["source"]["organization_scope"] == "example.test"
    assert registration["source"]["endpoint_identity"] == "fqdn:radius02.example.test|ipv4:198.51.100.24"
    assert load_manual_control_contract()["source_instance_id"] == "radius-source-02"
    assert load_consumer_contract()["subscription_id"] == "vpn-radius-session-observations-radius02-v1"


def test_unconfigured_source_has_an_explicit_error(tmp_path) -> None:
    value = _contract()
    value.update(source_name="", connect_address="", source_instance_id="")
    path = tmp_path / "routes.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RadiusCollectionRouteError, match="radius_source_not_configured"):
        load_radius_collection_routes(path)


def test_empty_environment_source_does_not_fall_back_to_example(monkeypatch) -> None:
    monkeypatch.setenv("ADLOG_RADIUS_SOURCE_NAME", " ")
    with pytest.raises(RadiusCollectionRouteError, match="radius_source_not_configured"):
        load_radius_collection_routes()


@pytest.mark.parametrize("value", [[], None, "invalid"])
def test_environment_route_file_requires_an_object(monkeypatch, tmp_path, value) -> None:
    path = tmp_path / "routes.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setenv("ADLOG_RADIUS_COLLECTION_ROUTES_PATH", str(path))
    monkeypatch.setenv("ADLOG_RADIUS_SOURCE_NAME", "radius02.example.test")
    with pytest.raises(RadiusCollectionRouteError, match="route_contract_object_required"):
        load_radius_collection_routes()


def test_external_registration_identity_reaches_lease_and_consumer(monkeypatch, tmp_path) -> None:
    from server.source_packs.radius.accounting_manual_control import (
        load_manual_control_contract,
    )
    from server.source_packs.radius.accounting_registration import (
        load_registration_contract,
    )
    from server.source_packs.radius.session_consumer import load_consumer_contract

    monkeypatch.setenv("ADLOG_RADIUS_SOURCE_NAME", "radius02.example.test")
    monkeypatch.setenv("ADLOG_RADIUS_SOURCE_INSTANCE_ID", "radius-source-02")
    monkeypatch.setenv("ADLOG_RADIUS_OWNER_CONFIRMED_IP", "198.51.100.24")
    monkeypatch.setenv("ADLOG_RADIUS_ACCOUNTING_SHARE_UNC", r"\\radius02.example.test\Accounting$")
    registration = load_registration_contract()
    path = tmp_path / "registration.json"
    path.write_text(json.dumps(registration), encoding="utf-8")
    monkeypatch.setenv("ADLOG_RADIUS_REGISTRATION_CONTRACT_PATH", str(path))

    assert load_registration_contract() == registration
    assert load_manual_control_contract()["source_instance_id"] == "radius-source-02"
    assert load_manual_control_contract()["subscription_id"] == registration["subscription"]["subscription_id"]
    assert load_consumer_contract()["subscription_id"] == registration["subscription"]["subscription_id"]


def test_event_log_and_dedicated_accounting_routes_are_ready_but_runtime_is_off() -> None:
    result = load_radius_collection_routes()
    assert result["event_log_ready"] is True
    assert result["event_log_adapter"] == "windows-eventlog-pywin32"
    assert result["accounting_ready"] is True
    assert result["blockers"] == []
    assert result["timezone_drift_check_accepted"] is False
    assert result["timezone_owner_assumption_active"] is True
    path, timezone_id, offset = require_accounting_source()
    assert str(path).rstrip("\\") == str(result["accounting_share_unc"]).rstrip("\\")
    assert timezone_id == "N. Central Asia Standard Time"
    assert offset == 420
    assert result["runtime_enabled"] is False
    assert result["source_instance_id"] == result["source_name"]


def test_missing_dedicated_share_is_a_fail_closed_blocker() -> None:
    value = deepcopy(_contract())
    value["accounting_route"]["share_unc"] = None
    result = validate_radius_collection_routes(value)
    assert result["accounting_ready"] is False
    assert result["blockers"] == ["radius_dedicated_read_only_share_not_configured"]


@pytest.mark.parametrize("share", [
    r"\\radius01.example.invalid\c$\Windows\System32\LogFiles",
    r"\\radius01.example.invalid\admin$\System32\LogFiles",
    r"\\other.example.invalid\RadiusAccounting$",
])
def test_administrative_or_wrong_host_share_fails_closed(share: str) -> None:
    value = deepcopy(_contract())
    value["accounting_route"]["share_unc"] = share
    with pytest.raises(RadiusCollectionRouteError):
        validate_radius_collection_routes(value)


def test_dedicated_hidden_share_is_accepted_but_does_not_enable_runtime() -> None:
    value = deepcopy(_contract())
    host = value["source_name"]
    value["accounting_route"]["share_unc"] = rf"\\{host}\SLI-RadiusAccounting$"
    result = validate_radius_collection_routes(value)
    assert result["accounting_ready"] is True
    assert result["runtime_enabled"] is False
    assert result["autostart_enabled"] is False


def test_configured_non_example_source_is_accepted_when_route_is_consistent() -> None:
    value = deepcopy(_contract())
    host = "radius-prototype.example.invalid"
    value["source_name"] = host
    value["connect_address"] = host
    value["source_instance_id"] = host
    value["accounting_route"]["share_unc"] = rf"\\{host}\SLI-RadiusAccounting$"

    result = validate_radius_collection_routes(value)

    assert result["source_name"] == host
    assert result["source_instance_id"] == host


def test_empty_source_instance_id_is_rejected() -> None:
    value = deepcopy(_contract())
    value["source_instance_id"] = ""

    with pytest.raises(RadiusCollectionRouteError, match="source_instance_id_mismatch"):
        validate_radius_collection_routes(value)


def test_mismatched_configured_source_is_rejected() -> None:
    value = deepcopy(_contract())
    value["connect_address"] = "other-radius.example.invalid"

    with pytest.raises(RadiusCollectionRouteError, match="source_identity_mismatch"):
        validate_radius_collection_routes(value)


def test_remote_registry_or_runtime_cannot_be_enabled() -> None:
    value = deepcopy(_contract())
    value["accounting_route"]["timezone_descriptor"]["remote_registry_allowed"] = True
    with pytest.raises(RadiusCollectionRouteError):
        validate_radius_collection_routes(value)
    value = deepcopy(_contract())
    value["runtime_enabled"] = True
    with pytest.raises(RadiusCollectionRouteError):
        validate_radius_collection_routes(value)


def test_timezone_owner_assumption_is_explicit_and_cannot_be_silently_removed() -> None:
    value = deepcopy(_contract())
    value["accounting_route"]["timezone_descriptor"][
        "owner_assumption_active"
    ] = False
    with pytest.raises(RadiusCollectionRouteError):
        validate_radius_collection_routes(value)

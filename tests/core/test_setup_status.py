"""«Первичная настройка»: status of the first-run checklist."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from server.api.routes import setup as routes_setup
from server.sli.access.access_control_v4 import route_capability
from server.sli.core import setup_status


@pytest.fixture(autouse=True)
def fake_config(monkeypatch):
    monkeypatch.setattr("server.sli.core.app_config.load_config", lambda: SimpleNamespace(collector_interval_seconds=600))


def _patch(monkeypatch: pytest.MonkeyPatch, **sections) -> None:
    defaults = {
        "_report_domain": lambda: {"key": "reports.domain_fqdn", "value": "corp.example.test", "source": "database"},
        "_domains": lambda: [{"fqdn": "corp.example.test", "netbios_name": "CORP", "server_count": 2}],
        "_domain_controllers": lambda: {"source": "db", "items": [{"hostname": "DC1", "connect_address": "dc1.example.test", "domain": "corp.example.test", "enabled": True, "source": "db", "dns_readback": True}]},
        "_sources": lambda: [{"pack_id": "sli.windows.ad-dc", "display_name": "AD DC", "version": "1.0.0", "source_kind": "event", "channels": ["Security"], "enabled": True}],
        "_source_configuration": lambda *_a: [{"source_instance_id": "DC1", "configured": True, "enabled": True}],
        "_source_data": lambda *_a: {"dc1": datetime.now(timezone.utc) - timedelta(minutes=1)},
        "_collection": lambda: {"collection_enabled": True, "block_reason": None, "channels": 3, "last_success_utc": "2026-10-01 10:00:00+00:00"},
    }
    defaults.update(sections)
    for name, value in defaults.items():
        monkeypatch.setattr(setup_status, name, value)


def _states(status: dict) -> dict[str, str]:
    return {step["id"]: step["state"] for step in status["steps"]}


def test_status_reports_every_step_as_done_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch)
    status = setup_status.build_setup_status()
    assert status["read_only"] is True
    assert status["api_version"] == "v1"
    assert isinstance(status["sources"][0]["enabled"], bool)
    assert {"pack_id", "display_name", "version", "source_kind", "enabled"} <= status["sources"][0].keys()
    assert _states(status) == {
        "report-domain": "done", "domains": "done", "domain-controllers": "done", "sources": "done", "first-collection": "done",
    }
    assert status["domains"][0]["fqdn"] == "corp.example.test"
    assert status["domain_controllers"][0]["hostname"] == "DC1"


def test_empty_installation_shows_todo_and_manual_steps(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        _report_domain=lambda: {"key": "reports.domain_fqdn", "value": "", "source": "not_configured"},
        _domains=list, _domain_controllers=lambda: {"source": "none", "items": []},
        _source_configuration=lambda *_a: [],
        _collection=lambda: {"collection_enabled": True, "block_reason": None, "channels": 0, "last_success_utc": None},
    )
    status = setup_status.build_setup_status()
    assert _states(status) == {
        "report-domain": "todo", "domains": "todo", "domain-controllers": "todo", "sources": "todo", "first-collection": "todo",
    }
    steps = {step["id"]: step for step in status["steps"]}
    assert steps["domains"]["manual"] and steps["domains"]["doc"] == "docs/ADMIN_GUIDE.md"
    assert steps["domain-controllers"]["manual"]
    assert steps["report-domain"]["link"] == "/platform-settings"


def test_a_failing_section_is_unavailable_and_leaks_no_error_text(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken():
        raise RuntimeError("password=secret relation domains does not exist")

    _patch(monkeypatch, _domains=broken, _collection=broken, _source_data=broken)
    status = setup_status.build_setup_status()
    states = _states(status)
    assert states["domains"] == "unavailable" and states["first-collection"] == "unavailable"
    assert states["sources"] == "done"
    assert "secret" not in repr(status)
    assert status["collection"] is None and status["domains"] == []


def test_domain_query_is_parameter_free_and_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def query_rows(sql, params=(), **_kwargs):
        seen.append(" ".join(sql.split()).lower())
        return [{"fqdn": "corp.example.test", "netbios_name": None, "forest": "corp.example.test", "server_count": 1}]

    monkeypatch.setattr(setup_status.database, "query_rows", query_rows)
    assert setup_status._domains() == [{"fqdn": "corp.example.test", "netbios_name": None, "forest": "corp.example.test", "server_count": 1, "is_archived": False, "observed_at_utc": None}]
    assert all(sql.startswith("select") for sql in seen)


def test_domain_controllers_expose_source_and_state_but_not_the_confirmed_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "server.sli.sources.dc_discovery.read_file_targets",
        lambda: [{"hostname": "DC1", "connect_address": "dc1.example.test", "owner_confirmed_ip": "198.51.100.23"}],
    )
    monkeypatch.setattr("server.sli.core.setup_domain_controllers.database.query_rows", lambda *_a, **_k: [])
    info = setup_status._domain_controllers()
    assert info == {"source": "file", "items": [{
        "hostname": "DC1", "connect_address": "dc1.example.test", "domain": None,
        "enabled": True, "source": "file", "dns_readback": True,
    }]}
    assert "198.51" not in repr(info)


def test_disabled_controllers_do_not_make_the_step_done(monkeypatch: pytest.MonkeyPatch) -> None:
    off = {"hostname": "DC1", "connect_address": "dc1.example.test", "domain": None, "enabled": False, "source": "db", "dns_readback": False}
    _patch(monkeypatch, _domain_controllers=lambda: {"source": "db", "items": [off]})
    status = setup_status.build_setup_status()
    assert _states(status)["domain-controllers"] == "todo"
    assert status["domain_controllers"] == [off] and status["domain_controller_source"] == "db"


def test_source_packs_are_listed_from_the_registry() -> None:
    packs = setup_status._sources()
    assert packs and all(pack["pack_id"] for pack in packs)


@pytest.mark.parametrize("configured,enabled,age,state,action", [
    (False, False, None, "never", "configure"),
    (True, False, None, "never", "enable"),
    (True, True, None, "never", "collect"),
    (True, True, timedelta(days=3), "stale", "check_data"),
    (True, True, timedelta(minutes=1), "fresh", None),
    (None, None, None, "never", "check_configuration"),
])
def test_source_states_and_next_step_are_independent(monkeypatch, configured, enabled, age, state, action):
    stamp = datetime.now(timezone.utc) - age if age is not None else None
    _patch(monkeypatch,
           _source_configuration=lambda *_a: [{"source_instance_id": "source-1", "configured": configured, "enabled": enabled}],
           _source_data=lambda *_a: {"source-1": stamp} if stamp else {})
    status = setup_status.build_setup_status()
    pack = status["sources"][0]
    instance = pack["instances"][0]
    assert pack["installed"] is True
    assert pack["configured"] is configured
    assert pack["enabled"] is (enabled is True)
    assert instance["enabled"] is enabled
    assert instance["data_state"] == state
    assert instance["data_received"] is (state == "fresh")
    expected_sources = "unavailable" if configured is None else "done" if configured and enabled else "todo"
    expected_collection = "unavailable" if configured is None else "done" if configured and enabled and state == "fresh" else "todo"
    assert _states(status)["sources"] == expected_sources
    assert _states(status)["first-collection"] == expected_collection
    if action:
        assert status["next_step"]["action"] == action
        assert status["next_step"]["source_instance_id"] == "source-1"
        assert status["next_step"]["pack_id"] == pack["pack_id"]
    else:
        assert status["next_step"] is None


def test_installed_pack_without_instances_is_not_enabled_or_done(monkeypatch):
    _patch(monkeypatch, _source_configuration=lambda *_a: [])
    status = setup_status.build_setup_status()
    assert status["sources"][0]["enabled"] is False
    assert status["sources"][0]["configured"] is False
    assert _states(status)["sources"] == _states(status)["first-collection"] == "todo"
    assert status["next_step"]["action"] == "configure"


def test_data_failure_preserves_configuration_without_leaking_errors(monkeypatch):
    def broken(*_args):
        raise RuntimeError("private diagnostic")
    _patch(monkeypatch, _source_data=broken)
    status = setup_status.build_setup_status()
    instance = status["sources"][0]["instances"][0]
    assert instance["configured"] is True and instance["enabled"] is True
    assert instance["data_received"] is None and instance["data_state"] == "unavailable"
    assert _states(status)["first-collection"] == "unavailable"
    assert "private diagnostic" not in repr(status)


def test_dc_configuration_respects_disabled_targets_and_runtime_block():
    controllers = {"items": [{"hostname": "DC1", "enabled": True}, {"hostname": "DC2", "enabled": False}]}
    pack = {"pack_id": "sli.windows.ad-dc"}
    items = setup_status._source_configuration(pack, controllers, [], {"collection_enabled": False})
    assert all(item["configured"] is True and item["enabled"] is False for item in items)


def test_event_data_query_is_scoped_to_instance_and_requires_inserted_data(monkeypatch):
    seen = []
    def query(sql, params=()):
        seen.append((" ".join(sql.split()).lower(), params))
        return [{"source_instance_id": "DC1", "last_data_utc": "2026-10-05T00:00:00+00:00"}]
    monkeypatch.setattr(setup_status.database, "query_rows", query)
    result = setup_status._source_data({"pack_id": "sli.windows.ad-dc", "source_kind": "event", "channels": ["Security"]}, [{"source_instance_id": "DC1"}])
    assert "dc1" in result
    sql, params = seen[0]
    assert sql.startswith("select") and "collector_channel_runs" in sql and "inserted > 0" in sql
    assert "any(?)" in sql and params == (["dc1"], ["security"])


def test_radius_configuration_uses_registration_and_subscription_activation(monkeypatch):
    seen = []
    def query(sql, params=()):
        seen.append((sql, params))
        return [{"source_instance_id": "source-1", "enabled": False}]
    monkeypatch.setattr(setup_status.database, "query_rows", query)
    monkeypatch.setattr("server.source_packs.radius.collection_routes.load_radius_collection_routes", lambda: {"source_instance_id": "source-1", "source_name": "nps.example.test", "event_log_ready": True})
    items = setup_status._source_configuration({"pack_id": "sli.windows.vpn-radius"}, None, None, None)
    assert items == [{"source_instance_id": "source-1", "configured": True, "enabled": False, "collection_target": "nps.example.test"}]
    assert "radius_vpn_operations_v1" in seen[0][0]
    assert "source_activation" in seen[0][0] and "subscription_activation" in seen[0][0]


def test_context_history_does_not_assert_current_configuration(monkeypatch):
    pack = {"pack_id": "sli.windows.ad-context", "display_name": "AD context", "version": "1", "source_kind": "context"}
    now = datetime.now(timezone.utc)
    seen = []
    def query(sql, params=()):
        seen.append((sql, params))
        return [{"source_instance_id": "directory.example.test", "last_data_utc": now - timedelta(hours=1)}]
    monkeypatch.setattr(setup_status.database, "query_rows", query)
    item = setup_status._source_status(pack, None, [{"fqdn": "directory.example.test"}], None, now)
    assert item["configured"] is None and item["activation_state"] == "unavailable"
    assert item["instances"][0]["data_received"] is True
    assert item["instances"][0]["next_action"] == "check_configuration"
    assert "ad_snapshot_manifests" in seen[0][0] and "s.family = 'ad_context_base'" in seen[0][0]
    assert "s.source_state in ('complete', 'partial')" in seen[0][0]
    assert seen[0][1] == (["directory.example.test"],)


def test_radius_data_uses_exact_source_and_arrival_instead_of_event_time(monkeypatch):
    seen = []
    def query(sql, params=()):
        seen.append((" ".join(sql.split()).lower(), params))
        if "radius_vpn_session_evidence_observations_v1" in sql:
            return [{"source_instance_id": "source-1", "last_data_utc": "2026-10-01T00:00:00Z"}]
        return [{"last_data_utc": "2026-10-05T00:00:00Z"}]
    monkeypatch.setattr(setup_status.database, "query_rows", query)
    pack = {"pack_id": "sli.windows.vpn-radius", "source_kind": "event", "channels": ["Security"]}
    arrivals = setup_status._source_data(pack, [{"source_instance_id": "source-1", "collection_target": "nps.example.test"}])
    assert arrivals["source-1"] == datetime(2026, 10, 5, tzinfo=timezone.utc)
    assert seen[0][1] == (["source-1"],)
    assert seen[1][1] == (["nps.example.test"], ["security"])
    assert "inserted > 0" in seen[1][0] and "max(created_at)" in seen[1][0]


def test_malformed_data_timestamp_is_unavailable(monkeypatch):
    _patch(monkeypatch, _source_data=lambda *_a: {"dc1": "invalid"})
    instance = setup_status.build_setup_status()["sources"][0]["instances"][0]
    assert instance["data_state"] == "unavailable" and instance["data_received"] is None


def test_another_instances_data_cannot_complete_first_collection(monkeypatch):
    _patch(monkeypatch,
           _source_configuration=lambda *_a: [
               {"source_instance_id": "source-1", "configured": True, "enabled": False},
               {"source_instance_id": "source-2", "configured": True, "enabled": True},
           ],
           _source_data=lambda *_a: {"source-1": datetime.now(timezone.utc) - timedelta(minutes=1)})
    status = setup_status.build_setup_status()
    assert _states(status)["first-collection"] == "todo"
    assert status["sources"][0]["instances"][1]["data_state"] == "never"


def test_nps_route_is_configured_without_asserting_accounting_activation(monkeypatch):
    monkeypatch.setattr(setup_status.database, "query_rows", lambda *_a: [])
    monkeypatch.setattr("server.source_packs.radius.collection_routes.load_radius_collection_routes", lambda: {
        "source_instance_id": "source-1", "source_name": "nps.example.test", "event_log_ready": True,
        "owner_confirmed_ip": "192.0.2.1", "accounting_share_unc": "private", "runtime_enabled": False,
    })
    items = setup_status._source_configuration({"pack_id": "sli.windows.vpn-radius"}, None, None, None)
    assert items == [{"source_instance_id": "source-1", "configured": True, "enabled": None, "collection_target": "nps.example.test"}]
    assert "private" not in repr(items) and "192.0.2.1" not in repr(items)


def test_nps_arrival_survives_unavailable_accounting_view(monkeypatch):
    def query(sql, params=()):
        if "radius_vpn_session_evidence_observations_v1" in sql:
            raise RuntimeError("unavailable")
        return [{"last_data_utc": "2026-10-05T00:00:00Z"}]
    monkeypatch.setattr(setup_status.database, "query_rows", query)
    pack = {"pack_id": "sli.windows.vpn-radius", "source_kind": "event", "channels": ["Security"]}
    arrivals = setup_status._source_data(pack, [{"source_instance_id": "source-1", "collection_target": "nps.example.test"}])
    assert arrivals["source-1"] == datetime(2026, 10, 5, tzinfo=timezone.utc)


def test_runtime_block_points_to_configuration_instead_of_enabled_dc_target(monkeypatch):
    monkeypatch.setattr(setup_status.database, "query_rows", lambda *_a: [])
    pack = {"pack_id": "sli.windows.ad-dc", "source_kind": "event", "display_name": "AD DC", "version": "1", "channels": ["Security"]}
    status = setup_status._source_status(pack, {"items": [{"hostname": "DC1", "enabled": True}]}, [], {"collection_enabled": False}, datetime.now(timezone.utc))
    assert status["instances"][0]["next_action"] == "check_configuration"


def test_unavailable_freshness_config_does_not_mark_data_fresh(monkeypatch):
    def broken():
        raise RuntimeError("private diagnostic")
    _patch(monkeypatch)
    monkeypatch.setattr("server.sli.core.app_config.load_config", broken)
    status = setup_status.build_setup_status()
    assert status["sources"][0]["freshness_seconds"] is None
    assert status["sources"][0]["instances"][0]["data_state"] == "unavailable"
    assert "private diagnostic" not in repr(status)


@pytest.mark.parametrize("age,expected", [
    (timedelta(seconds=0), "fresh"),
    (timedelta(seconds=1230), "fresh"),
    (timedelta(seconds=1231), "stale"),
    (timedelta(seconds=-1), "unavailable"),
])
def test_data_freshness_uses_collection_schedule_boundaries(monkeypatch, age, expected):
    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    _patch(monkeypatch, _source_data=lambda *_a: {"dc1": now - age})
    pack = setup_status._sources()[0]
    status = setup_status._source_status(pack, None, None, None, now)
    assert status["freshness_seconds"] == 1230
    assert status["instances"][0]["data_state"] == expected


def test_empty_successful_poll_does_not_complete_first_collection(monkeypatch):
    _patch(monkeypatch, _source_data=lambda *_a: {})
    status = setup_status.build_setup_status()
    assert status["collection"]["last_success_utc"] is not None
    assert _states(status)["first-collection"] == "todo"
    assert status["next_step"] == {"pack_id": "sli.windows.ad-dc", "source_instance_id": "DC1", "action": "collect"}


def test_unknown_configuration_does_not_claim_no_sources_or_no_data(monkeypatch):
    _patch(monkeypatch, _source_configuration=lambda *_a: None)
    status = setup_status.build_setup_status()
    assert _states(status)["sources"] == _states(status)["first-collection"] == "unavailable"
    pack = status["sources"][0]
    assert pack["installed"] is True and pack["configured"] is None
    assert pack["activation_state"] == pack["data_state"] == "unavailable"
    assert status["next_step"]["action"] == "check_configuration"


def test_radius_route_failure_with_no_registrations_is_unknown(monkeypatch):
    def broken():
        raise RuntimeError("private diagnostic")
    monkeypatch.setattr(setup_status.database, "query_rows", lambda *_a: [])
    monkeypatch.setattr("server.source_packs.radius.collection_routes.load_radius_collection_routes", broken)
    assert setup_status._source_configuration({"pack_id": "sli.windows.vpn-radius"}, None, None, None) is None


def test_accounting_arrival_survives_unavailable_nps_history(monkeypatch):
    stamp = datetime(2026, 10, 5, tzinfo=timezone.utc)
    def query(sql, params=()):
        if "collector_channel_runs" in sql:
            raise RuntimeError("unavailable")
        return [{"source_instance_id": "source-1", "last_data_utc": stamp}]
    monkeypatch.setattr(setup_status.database, "query_rows", query)
    pack = {"pack_id": "sli.windows.vpn-radius", "source_kind": "event", "channels": ["Security"]}
    assert setup_status._source_data(pack, [{"source_instance_id": "source-1", "collection_target": "nps.example.test"}]) == {"source-1": stamp}


def test_invalid_radius_arrival_is_unknown_instead_of_no_data(monkeypatch):
    def query(sql, params=()):
        if "radius_vpn_operations_v1" in sql:
            return [{"source_instance_id": "source-1", "enabled": True}]
        if "collector_channel_runs" in sql:
            return [{"last_data_utc": None}]
        return [{"source_instance_id": "source-1", "last_data_utc": "invalid"}]
    monkeypatch.setattr(setup_status.database, "query_rows", query)
    monkeypatch.setattr("server.source_packs.radius.collection_routes.load_radius_collection_routes", lambda: {
        "source_instance_id": "source-1", "source_name": "nps.example.test", "event_log_ready": True,
    })
    pack = {"pack_id": "sli.windows.vpn-radius", "display_name": "NPS", "version": "1", "source_kind": "event", "channels": ["Security"]}
    status = setup_status._source_status(pack, None, None, None, datetime.now(timezone.utc))
    assert status["instances"][0]["data_state"] == "unavailable"
    assert status["instances"][0]["data_received"] is None


def test_status_route_requires_access_manage(monkeypatch: pytest.MonkeyPatch) -> None:
    assert route_capability("/api/v1/setup/status") == "access.manage"
    assert ("GET", "/api/v1/setup/status") in routes_setup.ROUTES
    sent: list[dict] = []

    class Handler:
        def _send_json(self, payload, *_args):
            sent.append(payload)

    monkeypatch.setattr(routes_setup, "build_setup_status", lambda: {"steps": []})
    assert routes_setup.try_handle_get(Handler(), "/api/v1/setup/status", {}) is True
    assert sent == [{"steps": []}]
    assert routes_setup.try_handle_get(Handler(), "/api/v1/setup/other", {}) is False
    assert routes_setup.try_handle_post(Handler(), "/api/v1/setup/status") is False


def test_report_domain_preserves_configured_value_and_offers_explicit_change(monkeypatch):
    monkeypatch.setattr(setup_status, "list_settings", lambda: [{
        "key": "reports.domain_fqdn", "value": "archive.example.test", "source": "database",
        "effective_value": "current.example.test", "effective_state": "available",
    }])
    monkeypatch.setattr(setup_status, "plugin_hook", lambda *_: lambda: 43200)
    calls = []
    monkeypatch.setattr("server.sli.core.report_domain.suggested_domain_fqdn", lambda *args: calls.append(args) or "current.example.test")
    result = setup_status._report_domain()
    assert result["value"] == "current.example.test"
    assert result["configured_value"] == "archive.example.test"
    assert result["suggested_value"] == "current.example.test"
    assert calls == [("archive.example.test", 86430)]


def test_unavailable_recommendation_preserves_effective_and_configured_values(monkeypatch):
    monkeypatch.setattr(setup_status, "list_settings", lambda: [{
        "key": "reports.domain_fqdn", "value": "archive.example.test", "source": "database",
        "effective_value": None, "effective_state": "unknown",
    }])
    def broken(*_):
        raise RuntimeError("private diagnostic")
    monkeypatch.setattr(setup_status, "plugin_hook", broken)
    result = setup_status._report_domain()
    assert result["value"] == ""
    assert result["configured_value"] == "archive.example.test"
    assert result["suggested_value"] is None
    assert "private" not in repr(result)

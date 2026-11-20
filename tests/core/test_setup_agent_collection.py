"""Agent-backed setup readiness; synthetic bindings never start collection."""
from datetime import datetime, timezone
from unittest import TestCase
from unittest.mock import patch

from server.sli.core import setup_status
from server.sli.plugins.ad import setup_status as ad_setup
from server.sli.agents import collection_health

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
PACK = {"pack_id": "sli.windows.ad-dc", "display_name": "AD", "version": "1", "source_kind": "event"}


def collection(state="current", *, name="dc.example.invalid", enabled=True, diagnostics=False):
    channel = {"channel": "Security", "state": state, "last_import_at": NOW.isoformat(), "last_packet_at": NOW.isoformat()}
    health = {"state": "current" if state == "current" else "error" if state == "error" else "partial",
              "active_agents": 1, "current_agents": int(state == "current"),
              "items": [{"id": "agent-1", "state": state, "modules": [{"module_id": PACK["pack_id"], "channels": [channel]}]}]}
    if diagnostics:
        health["diagnostics"] = {"state": "unavailable", "reason": "timeout"}
    return {"collection_enabled": False, "block_reason": "windows_event_log_access_denied",
            "agent_collection": health, "_agent_source_bindings": [
                {"agent_id": "agent-1", "module_id": PACK["pack_id"], "source_name": name, "domain_dns": None, "enabled": enabled}]}


def project(value, targets=None):
    with patch.object(setup_status, "_source_configuration", ad_setup.source_configuration), \
         patch.object(setup_status, "_source_data", side_effect=AssertionError("legacy history read")):
        return setup_status._source_status(PACK, {"items": targets or []}, [], value, NOW)


class SetupAgentCollectionTests(TestCase):
    def test_legacy_block_does_not_disable_exact_agent_source(self):
        result = project(collection(), [{"hostname": "DC.EXAMPLE.INVALID", "enabled": False}])
        self.assertEqual(len(result["instances"]), 1)
        item = result["instances"][0]
        self.assertIs(item["configured"], True)
        self.assertIs(item["enabled"], True)
        self.assertIs(item["data_received"], True)
        self.assertEqual(item["collection_state"], "current")

    def test_unrelated_host_does_not_enable_configured_dc(self):
        result = project(collection(name="other.example.invalid"), [{"hostname": "dc.example.invalid", "enabled": True}])
        item = next(row for row in result["instances"] if row["source_instance_id"] == "dc.example.invalid")
        self.assertIsNone(item["configured"])
        self.assertIsNone(item["enabled"])
        self.assertIsNone(item["data_received"])

    def test_no_host_claim_remains_unknown_not_disabled(self):
        item = project(collection(name=None), [{"hostname": "dc.example.invalid", "enabled": True}])["instances"][0]
        self.assertIsNone(item["configured"])
        self.assertIsNone(item["enabled"])

    def test_errors_waiting_unknown_and_paused_do_not_become_fresh(self):
        for state in ("error", "waiting", "unknown", "paused", "disabled", "lagging"):
            with self.subTest(state=state):
                result = project(collection(state, enabled=state not in ("paused", "disabled")))
                self.assertIsNot(result["data_received"], True)
                self.assertEqual(result["instances"][0]["collection_state"], state if state != "paused" else "disabled")

    def test_failed_diagnostics_preserve_assignment_but_not_current(self):
        result = project(collection(diagnostics=True))
        self.assertIs(result["configured"], True)
        self.assertIsNone(result["data_received"])
        self.assertEqual(result["instances"][0]["collection_state"], "unknown")

    def test_collection_reads_health_once_and_never_legacy_runtime(self):
        health = collection()["agent_collection"]
        with patch.object(collection_health, "get_agent_collection_health", return_value={**health, "_setup_bindings": []}) as read:
            result = setup_status._collection()
        read.assert_called_once_with(include_setup_bindings=True)
        self.assertEqual(result["agent_collection"], health)
        self.assertIsNone(result["block_reason"])

    def test_snapshot_history_without_assignment_does_not_prove_activation(self):
        pack = {**PACK, "pack_id": "sli.windows.ad-context", "source_kind": "context"}
        items = ad_setup.source_configuration(pack, None, [{"fqdn": "example.invalid"}], collection())
        self.assertIsNone(items[0]["configured"])
        self.assertIsNone(items[0]["enabled"])
        self.assertIsNone(items[0]["data_received"])

    def test_one_current_agent_does_not_mask_missing_second_assignment(self):
        value = collection()
        value["_agent_source_bindings"].append({**value["_agent_source_bindings"][0], "agent_id": "missing-agent"})
        self.assertIsNot(project(value)["data_received"], True)

    def test_source_name_is_not_matched_by_short_hostname_or_suffix(self):
        result = project(collection(name="dc.other.invalid"), [{"hostname": "dc", "enabled": True}])
        self.assertIsNone(next(item for item in result["instances"] if item["source_instance_id"] == "dc")["enabled"])

    def test_default_health_does_not_expose_policy_bindings(self):
        agent = {"id": "agent-1", "host_id": "host-1", "status": "active", "created_at": NOW,
                 "policy_revision": 1, "applied_policy_revision": 1, "applied_collection_state": "active",
                 "collection_policy": {"state": "active"}, "assigned_modules": [
                     {"module_id": "sli.windows.ad-dc", "enabled": True, "config": {
                         "source_name": "dc.example.invalid", "connect_address": "not-for-setup.invalid",
                         "credential": "never-expose", "channels": {"Security": True}}}]}
        with patch.object(collection_health, "query_rows_bounded", side_effect=[[agent], []]):
            public = collection_health.get_agent_collection_health()
        self.assertNotIn("_setup_bindings", public)
        with patch.object(collection_health, "query_rows_bounded", side_effect=[[agent], []]):
            private = collection_health.get_agent_collection_health(include_setup_bindings=True)
        bindings = private.pop("_setup_bindings")
        self.assertEqual(bindings[0]["source_name"], "dc.example.invalid")
        self.assertNotIn("never-expose", repr(private) + repr(bindings))
        self.assertNotIn("not-for-setup", repr(private) + repr(bindings))
        self.assertEqual(set(private), set(public))

    def test_public_setup_strips_internal_bindings_and_keeps_unknown(self):
        value = collection("unknown", name=None)
        with patch.multiple(setup_status, _report_domain=lambda: None, _domains=lambda: [],
                            _domain_controllers=lambda: {"items": [], "source": "none"}, _sources=lambda: [],
                            _collection=lambda: value):
            result = setup_status.build_setup_status()
        self.assertNotIn("_agent_source_bindings", repr(result))
        self.assertIn("agent_collection", result)
        self.assertNotEqual(next(step for step in result["steps"] if step["id"] == "first-collection")["state"], "done")

    def test_disabled_assignment_and_old_import_are_not_current(self):
        value = collection(enabled=False)
        value["agent_collection"]["items"][0]["modules"] = []
        item = project(value)["instances"][0]
        self.assertIs(item["configured"], True)
        self.assertIs(item["enabled"], False)
        self.assertIs(item["data_received"], False)

    def test_build_keeps_source_action_and_uses_agent_step_state(self):
        value = collection("error")
        pack = project(value)
        with patch.multiple(setup_status, _report_domain=lambda: None, _domains=lambda: [],
                            _domain_controllers=lambda: {"items": [], "source": "none"}, _sources=lambda: [PACK],
                            _source_status=lambda *args: pack, _collection=lambda: value):
            result = setup_status.build_setup_status()
        self.assertEqual(result["next_step"]["source_instance_id"], "dc.example.invalid")
        self.assertEqual(result["next_step"]["action"], "check_data")
        self.assertEqual(next(step for step in result["steps"] if step["id"] == "first-collection")["state"], "todo")

    def test_historical_snapshot_date_does_not_assert_current_collection(self):
        value = collection()
        pack = {**PACK, "pack_id": "sli.windows.ad-context", "source_kind": "context"}
        with patch.object(setup_status, "_source_configuration", ad_setup.source_configuration), \
             patch.object(setup_status, "_source_data", return_value={"example.invalid": NOW}):
            result = setup_status._source_status(pack, None, [{"fqdn": "example.invalid"}], value, NOW)
        item = result["instances"][0]
        self.assertEqual(item["last_data_utc"], NOW.isoformat())
        self.assertIsNone(item["data_received"])
        self.assertIsNone(item["enabled"])

    def test_paused_source_stays_paused(self):
        value = collection("paused", enabled=False)
        value["_agent_source_bindings"][0]["paused"] = True
        self.assertEqual(project(value)["instances"][0]["collection_state"], "paused")

    def test_unbound_or_empty_agent_source_keeps_agent_setup_destination(self):
        for value, expected in ((collection(name=None), None),
                                ({**collection(), "_agent_source_bindings": []}, False)):
            result = project(value)
            self.assertEqual(result["collection_basis"], "agents")
            self.assertIs(result["configured"], expected)

    def test_complete_setup_uses_one_health_read_for_source_and_collection(self):
        value = collection()
        response = {**value["agent_collection"], "_setup_bindings": value["_agent_source_bindings"]}
        with patch.multiple(setup_status, _report_domain=lambda: None, _domains=lambda: [],
                            _domain_controllers=lambda: {"items": [{"hostname": "dc.example.invalid", "enabled": False}], "source": "db"},
                            _sources=lambda: [PACK], _source_configuration=ad_setup.source_configuration), \
             patch.object(setup_status, "_source_data", side_effect=AssertionError("legacy history")), \
             patch.object(collection_health, "get_agent_collection_health", return_value=response) as read:
            result = setup_status.build_setup_status()
        read.assert_called_once_with(include_setup_bindings=True)
        self.assertEqual(result["sources"][0]["instances"][0]["collection_state"], "current")
        step = next(step for step in result["steps"] if step["id"] == "first-collection")
        self.assertEqual(step["state"], "done")
        self.assertEqual(step["summary"], "Сбор работает.")
        self.assertIsNone(result["collection"]["block_reason"])
        self.assertNotIn("_setup_bindings", repr(result))

    def test_registry_ids_cannot_become_source_host_bindings(self):
        for source in ("agent-1", "HOST-1", None):
            agents = [{"id": "agent-1", "host_id": "host-1", "status": "active", "assigned_modules": [
                {"module_id": "sli.windows.ad-dc", "enabled": True, "config": {"source_name": source}}]}]
            self.assertIsNone(collection_health._setup_source_bindings(agents)[0]["source_name"])


    def test_controller_step_uses_same_agent_evidence_as_source_not_legacy_flag(self):
        for target_enabled in (False, True):
            for state in ("current", "waiting", "error", "unknown", "disabled", "paused"):
                with self.subTest(target_enabled=target_enabled, state=state):
                    value = collection(state, enabled=state not in ("disabled", "paused"))
                    response = {**value["agent_collection"], "_setup_bindings": value["_agent_source_bindings"]}
                    with patch.multiple(setup_status, _report_domain=lambda: None,
                                        _domains=lambda: [{"fqdn": "example.invalid", "is_archived": False}],
                                        _domain_controllers=lambda: {"items": [{"hostname": "dc.example.invalid", "enabled": target_enabled}], "source": "db"},
                                        _sources=lambda: [PACK], _source_configuration=ad_setup.source_configuration), \
                         patch.object(setup_status, "_source_data", side_effect=AssertionError("legacy history")), \
                         patch.object(collection_health, "get_agent_collection_health", return_value=response) as read:
                        result = setup_status.build_setup_status()
                    read.assert_called_once_with(include_setup_bindings=True)
                    step = next(item for item in result["steps"] if item["id"] == "domain-controllers")
                    self.assertEqual(step["state"], "done" if state == "current" else "unavailable" if state == "unknown" else "todo")
                    self.assertIs(result["domains"][0]["is_archived"], False)
                    self.assertEqual(result["agent_collection"], value["agent_collection"])
                    self.assertEqual(result["domain_controllers"][0]["enabled"], target_enabled)

    def test_agent_only_controller_is_ready_without_legacy_target(self):
        value = collection()
        with patch.multiple(setup_status, _report_domain=lambda: None, _domains=lambda: [],
                            _domain_controllers=lambda: {"items": [], "source": "none"},
                            _sources=lambda: [PACK], _source_configuration=ad_setup.source_configuration,
                            _collection=lambda: value):
            result = setup_status.build_setup_status()
        self.assertEqual(next(step for step in result["steps"] if step["id"] == "domain-controllers")["state"], "done")
        self.assertEqual(result["domain_controllers"], [])
        self.assertEqual(result["sources"][0]["instances"][0]["source_instance_id"], "dc.example.invalid")

    def test_enabled_legacy_target_without_binding_is_not_ready(self):
        value = collection(name=None)
        with patch.multiple(setup_status, _report_domain=lambda: None, _domains=lambda: [],
                            _domain_controllers=lambda: {"items": [{"hostname": "dc.example.invalid", "enabled": True}], "source": "db"},
                            _sources=lambda: [PACK], _source_configuration=ad_setup.source_configuration,
                            _collection=lambda: value):
            result = setup_status.build_setup_status()
        self.assertEqual(next(step for step in result["steps"] if step["id"] == "domain-controllers")["state"], "unavailable")
        self.assertIsNone(result["sources"][0]["instances"][0]["configured"])

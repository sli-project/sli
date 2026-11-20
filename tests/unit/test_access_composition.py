"""Synthetic facts exercise the same composer used by database/UI and worker."""
from copy import deepcopy
import ast
from contextlib import nullcontext
from pathlib import Path
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Mapping
import unittest

from server.sli.access import access_composition as composition

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
SUBJECT = {"type": "session", "id": 7, "role": "viewer"}


def facts():
    return {
        "is_owner": [{"is_owner": False}], "groups": [],
        "role_packages": [], "subject_packages": [], "owner_packages": [],
        "package_capabilities": [], "direct_capabilities": [], "all_capabilities": [],
        "package_reports": [], "report_assignments": [{"id": 1, "subject_type": "user", "subject_id": 7,
            "source_type": "direct", "report_key": "security.queue", "effect": "allow",
            "scope_json": {"kind": "all"}, "field_categories": ["security", "identity_basic"],
            "allowed_actions": ["view", "export"]}],
        "definitions": [{"report_key": "security.queue", "version": 2, "dataset_version": 3, "discoverable": True,
            "definition_json": {"field_categories": ["security", "identity_basic"],
                "actions": ["view", "export"], "required_capabilities": []},
            "fields_json": [{"category": "security"}, {"category": "identity_basic"}],
            "actions_json": ["view", "export"]}],
        "requests": [], "preferences": [],
    }


def grant_caps(data, keys):
    data["direct_capabilities"] = [{"capability_key": key, "effect": "allow", "subject_type": "user",
        "subject_id": 7, "source_type": "direct", "scope_json": {"kind": "all"}} for key in keys]


def decide(data, subject=SUBJECT):
    result = composition.compose_access_facts(subject, data, now=NOW)
    assert "reports" in result and "capabilities" in result, "composer must return report and capability decisions"
    return result


class AccessCompositionTests(unittest.TestCase):
    def test_database_loader_preserves_single_owner_row_contract(self):
        source = Path(__file__).resolve().parents[2] / 'server/sli/access/access_control_v4.py'
        tree = ast.parse(source.read_text('utf-8'))
        tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in {'_load_access_facts', 'effective_access'}]
        namespace = {'_access_subject': composition._access_subject,
                     'compose_access_facts': composition.compose_access_facts,
                     'ensure_access_schema': lambda: None, 'datetime': datetime,
                     'timezone': timezone, 'Mapping': Mapping, 'Any': Any}
        exec(compile(tree, str(source), 'exec'), namespace)

        class Cursor:
            def execute(self, sql, params=()):
                self.sql = sql
            def fetchone(self):
                assert 'access_platform_owners' in self.sql
                return {'is_owner': self.owner}
            def fetchall(self):
                if 'from report_registry_v4 r join report_datasets_v4' in ' '.join(self.sql.split()):
                    return facts()['definitions']
                return []

        for owner in (True, False):
            with self.subTest(owner=owner):
                cursor = Cursor()
                cursor.owner = owner
                namespace['_connect'] = lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor)))
                result = namespace['effective_access'](SUBJECT, now=NOW)
                self.assertEqual(result['platform_owner'], owner)
                if owner:
                    self.assertTrue(result['reports'][0]['allowed'])
                    self.assertEqual(result['reports'][0]['grants'][0]['scope'], {'kind': 'all'})

    def test_worker_uses_access_key_and_minimal_output(self):
        data = facts()
        del data["requests"], data["preferences"]
        actor = {**SUBJECT, "is_active": True}
        result = composition.compose_schedule_access(actor, data, report_key="security.problems", now=NOW)
        self.assertEqual(set(result), {"subject", "platform_owner", "capabilities", "capability_policies", "reports"})
        self.assertEqual(result["reports"][0]["report_key"], "security.queue")

    def test_worker_rejects_inactive_user_and_unbound_report(self):
        data = facts()
        del data["requests"], data["preferences"]
        for actor, key in (({**SUBJECT, "is_active": False}, "security.problems"),
                           ({**SUBJECT, "is_active": True}, "arbitrary")):
            with self.assertRaisesRegex(ValueError, "^invalid_schedule_access_facts$"):
                composition.compose_schedule_access(actor, data, report_key=key, now=NOW)

    def test_worker_rejects_ui_facts_and_unrelated_definitions(self):
        for kind in ("requests", "preferences", "unrelated"):
            data = facts()
            del data["requests"], data["preferences"]
            if kind == "unrelated":
                data["definitions"][0]["report_key"] = "another.report"
            else:
                data[kind] = []
            with self.assertRaisesRegex(ValueError, "^invalid_schedule_access_facts$"):
                composition.compose_schedule_access({**SUBJECT, "is_active": True}, data,
                    report_key="security.problems", now=NOW)

    def test_worker_expired_group_membership_cannot_supply_permissions(self):
        data = facts()
        del data["requests"], data["preferences"]
        data["groups"] = [{"id": 9, "valid_until": "2026-10-24T00:00:00Z"}]
        data["direct_capabilities"] = [{"capability_key": "reports.export", "effect": "allow",
            "subject_type": "group", "subject_id": 9, "source_type": "group", "scope_json": {"kind": "all"}}]
        result = composition.compose_schedule_access({**SUBJECT, "is_active": True}, data,
            report_key="security.problems", now=NOW)
        self.assertNotIn("reports.export", result["capabilities"])

    def test_malformed_deny_scope_is_evaluated_in_python(self):
        data = facts()
        del data["requests"], data["preferences"]
        grant_caps(data, ["field.security"])
        data["direct_capabilities"].append({**data["direct_capabilities"][0],
            "effect": "deny", "scope_json": {"name": "malformed-policy-fixture"}})
        result = composition.compose_schedule_access({**SUBJECT, "is_active": True}, data,
            report_key="security.problems", now=NOW)
        self.assertFalse(composition.capability_decision(result, "field.security")["allowed"])

    def test_atomic_grants_are_not_multiplied(self):
        data = facts()
        grant_caps(data, ["field.security", "field.identity_basic"])
        grant = data["report_assignments"][0]
        data["report_assignments"] = [{**grant, "field_categories": ["security"]},
                                       {**grant, "field_categories": ["identity_basic"]}]
        result = decide(data)
        decision = composition.report_action_decision(result, "security.queue", "view",
            resource_groups=None, required_field_categories=["security", "identity_basic"])
        self.assertFalse(decision["allowed"])

    def test_fields_and_export_are_bounded_by_actual_capabilities(self):
        data = facts()
        grant_caps(data, ["field.security"])
        report, = decide(data)["reports"]
        self.assertTrue(report["allowed"])
        self.assertEqual(report["grants"][0]["field_categories"], ["security"])
        self.assertEqual(report["allowed_actions"], ["view"])

    def test_identity_policy_distinction_survives_global_scope(self):
        data = facts()
        grant_caps(data, ["field.security", "field.identity_basic", "reports.export"])
        report, = decide(data)["reports"]
        self.assertEqual(report["grants"][0]["field_categories"], ["identity_basic", "security"])
        self.assertEqual(report["allowed_actions"], ["export", "view"])
        self.assertEqual((report["version"], report["dataset_version"]), (2, 3))

    def test_explicit_report_deny_wins(self):
        data = facts()
        data["report_assignments"].append({**data["report_assignments"][0], "effect": "deny"})
        report, = decide(data)["reports"]
        self.assertFalse(report["allowed"])
        self.assertEqual(report["grants"], [])

    def test_invalid_deny_is_not_dropped(self):
        data = facts()
        grant_caps(data, ["field.security"])
        data["direct_capabilities"].append({**data["direct_capabilities"][0],
            "effect": "deny", "scope_json": {"kind": "unknown"}})
        result = decide(data)
        self.assertNotIn("field.security", result["capabilities"])
        self.assertFalse(composition.capability_decision(result, "field.security")["allowed"])

    def test_owner_override_uses_current_definition_bounds(self):
        data = facts()
        data["is_owner"] = [{"is_owner": True}]
        data["report_assignments"][0]["effect"] = "deny"
        report, = decide(data)["reports"]
        self.assertTrue(report["allowed"])
        self.assertEqual(report["grants"][0]["field_categories"], ["identity_basic", "security"])

    def test_viewer_role_starter_and_explicit_package_origins_differ(self):
        data = facts()
        package = {"id": 1, "package_key": "p", "effect": "allow", "source_kind": "role", "source_key": "viewer"}
        data["role_packages"] = [package]
        data["package_capabilities"] = [{"package_key": "p", "capability_key": "reports.export"}]
        self.assertNotIn("reports.export", decide(data)["capabilities"])
        data["role_packages"] = []
        data["subject_packages"] = [{**package, "source_kind": "direct", "source_key": "user:7"}]
        self.assertIn("reports.export", decide(data)["capabilities"])

    def test_denied_package_cannot_supply_its_capabilities_or_reports(self):
        data = facts()
        package = {"id": 1, "package_key": "p", "effect": "allow", "source_kind": "direct", "source_key": "user:7"}
        data["subject_packages"] = [package, {**package, "effect": "deny"}]
        data["package_capabilities"] = [{"package_key": "p", "capability_key": "reports.export"}]
        self.assertNotIn("reports.export", decide(data)["capabilities"])

    def test_published_definition_removes_old_fields_and_actions(self):
        data = facts()
        grant_caps(data, ["field.security", "field.identity_basic", "reports.export"])
        data["definitions"][0]["definition_json"]["actions"] = ["view"]
        data["definitions"][0]["fields_json"] = [{"category": "security"}]
        report, = decide(data)["reports"]
        self.assertEqual(report["field_categories"], ["security"])
        self.assertEqual(report["allowed_actions"], ["view"])

    def test_scoped_file_capability_does_not_become_global(self):
        data = facts()
        grant_caps(data, ["file-audit.view"])
        data["direct_capabilities"][0]["scope_json"] = {"kind": "domain", "ids": [9]}
        result = decide(data)
        self.assertNotIn("file-audit.view", result["capabilities"])
        self.assertFalse(composition.capability_decision(result, "file-audit.view")["allowed"])
        self.assertTrue(composition.capability_decision(result, "file-audit.view", resource={"kind": "domain", "id": 9})["allowed"])

    def test_input_is_not_mutated(self):
        data = facts()
        before = deepcopy(data)
        decide(data)
        self.assertEqual(data, before)


if __name__ == "__main__":
    unittest.main()

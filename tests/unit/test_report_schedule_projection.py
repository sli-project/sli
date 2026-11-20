"""Real ReportAccess source and file ACL, with synthetic resolved policy data."""
import ast
from copy import deepcopy
from dataclasses import dataclass, replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping
import unittest

from server.sli.access.access_composition import capability_decision
from server.sli.access.scope import AccessScope, scope_from_grant, legacy_domain_ids
from server.sli.core import report_schedule_projection as projection


def actual_report_access():
    # Load the unchanged policy class without v2.__init__'s registry/DB imports.
    # No decision method is replaced; DB grants are not tested by this harness.
    source = Path(__file__).resolve().parents[2] / "server/sli/reporting/v2/access.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    names = {"report_grant", "resolve_access_scope", "resolve_domain_scope", "ReportAccess"}
    tree.body = [ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)] + [
        node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    ast.fix_missing_locations(tree)
    namespace = dict(AccessScope=AccessScope, scope_from_grant=scope_from_grant, legacy_domain_ids=legacy_domain_ids,
                     Mapping=Mapping, Any=Any, replace=replace,
                     sha256=sha256, json=json, deepcopy=deepcopy, capability_decision=capability_decision)
    exec(compile(tree, str(source), "exec"), namespace)
    return namespace["ReportAccess"]


@dataclass(frozen=True)
class Rule:
    report_key: str
    required_fields: frozenset
    required_capabilities: frozenset = frozenset()
    scope: str = "generic"
    accepts_generic_scope: bool = True
    export_action: str = "export"


def access(key="security.queue", identity=True, export=True):
    fields = {"security", "identity_basic"} if identity else {"security"}
    if key.startswith("file-audit"):
        fields = {"security", "identity_basic", "technical", "privilege"}
    capabilities = ["field." + field for field in fields] + ["file-audit.view"]
    actions = ["view"]
    if export:
        actions.append("export")
        capabilities.extend(["reports.export", "file-audit.export"])
    return {"subject": {"coarse_role": "viewer"}, "capabilities": capabilities,
        "reports": [{"report_key": key, "allowed": True, "allowed_actions": actions,
            "grants": [{"scope": {"kind": "all"}, "field_categories": sorted(fields), "allowed_actions": actions}]}]}


def definition(file=False):
    key = "file-audit.mass-operations" if file else "security.problems"
    fields = frozenset({"identity_basic", "security", "technical", "privilege"}) if file else frozenset({"security"})
    rule = Rule(key if file else "security.queue", fields, frozenset({"file-audit.view"}) if file else frozenset())
    return SimpleNamespace(key=key, access=rule, export_csv=object(), default_limit=50)


def security_candidate():
    return {"report_key": "security.problems", "quality": "ok", "roots": [],
        "counts": {"individual": {"total": 51, "has_more": True}, "cohorts": {"total": 1, "has_more": False}}}


class ProjectionTests(unittest.TestCase):
    def test_legacy_digest_export_permission_is_independent_of_csv_renderer(self):
        source = Path(__file__).resolve().parents[2] / 'server/sli/core/report_schedules.py'
        tree = ast.parse(source.read_text('utf-8'))
        tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'report_access']
        report = definition()
        report.export_csv = None
        factory = actual_report_access()
        for allowed in (True, False):
            namespace = {'outbox': SimpleNamespace(recipient_access=lambda _: access(export=allowed)),
                'get_report': lambda _: report, 'REPORTS': {report.key}, 'ReportAccess': factory,
                'resolve_access_scope': factory.__init__.__globals__['resolve_access_scope']}
            exec(compile(tree, str(source), 'exec'), namespace)
            if allowed:
                self.assertEqual(namespace['report_access'](7, report.key, export=True)[2].scope.mode, 'all')
            else:
                with self.assertRaises(PermissionError):
                    namespace['report_access'](7, report.key, export=True)

    def test_digest_without_csv_renderer_still_requires_each_export_grant(self):
        report = definition()
        report.export_csv = None
        for denied_user in (None, 7, 8):
            actors = {user: access(export=user != denied_user) for user in (7, 8)}
            result = projection.project(report, {'owner_user_id': 7, 'actors': actors,
                'bindings': [{'recipient_user_id': 8}]}, security_candidate(), authority_factory=actual_report_access())
            self.assertEqual(result['item_count'], 1 if denied_user is None else None)
            self.assertEqual(result['selection']['include_count'], denied_user is None)

    def project(self, candidate, actors, file=False, dependency=None):
        snapshot = {"owner_user_id": 7, "actors": actors, "bindings": [{"recipient_user_id": 8}],
                    "dependencies": {"security.queue": dependency} if dependency is not None else {}}
        factory = actual_report_access()
        result = projection.project(definition(file), snapshot, candidate, authority_factory=factory,
            dependency_definition=definition(), scope_resolver=factory.__init__.__globals__["resolve_access_scope"])
        self.assertIn("item_count", result)
        return result

    def test_selected_variant_owns_has_more_and_quality(self):
        result = self.project(security_candidate(), {7: access(), 8: access()})
        self.assertEqual((result["item_count"], result["truncated"], result["quality"]), (1, False, "ok"))
        result = self.project(security_candidate(), {7: access(identity=False), 8: access()})
        self.assertEqual((result["item_count"], result["truncated"], result["quality"]), (51, True, "partial"))

    def test_recipient_export_revocation_withholds_count(self):
        result = self.project(security_candidate(), {7: access(), 8: access(export=False)})
        self.assertIsNone(result["item_count"])

    def test_owner_view_revocation_denies_snapshot(self):
        denied = access()
        denied["reports"] = []
        result = self.project(security_candidate(), {7: denied, 8: access()})
        self.assertEqual((result["quality"], result["item_count"]), ("denied", None))

    def test_file_totals_and_has_more_follow_actual_admitted_root_subset(self):
        candidate = {"report_key": "file-audit.mass-operations", "quality": "partial", "counts": {},
            "root_limit": False, "roots": [dict(agent_id="a", source_instance_id="s", collection_scope_id=r,
                source_kind="server") for r in ("one", "two")]}
        owner, recipient = access("file-audit.mass-operations"), access("file-audit.mass-operations")
        # Already-normalized resource policy exercises the existing generic
        # scope matcher. Raw generic assignments remain rejected by the loader.
        owner["capability_policies"] = [{"capability_key": "file-audit.view", "effect": "deny", "valid": True,
            "scope": {"mode": "restricted", "clauses": [{"collection_scope_ids": ["two"]}]}}]
        result = self.project(candidate, {7: owner, 8: recipient}, file=True)
        self.assertEqual(result['selection']['root_indexes'], [0])
        self.assertTrue(result['selection']['include_count'])
        self.assertIsNone(result['item_count'])  # Only fixed publication computes the final count.
        recipient["capability_policies"] = [{"capability_key": "file-audit.export", "effect": "deny", "valid": True,
            "scope": {"mode": "restricted", "clauses": [{"collection_scope_ids": ["one"]}]}}]
        self.assertIsNone(self.project(candidate, {7: owner, 8: recipient}, file=True)["item_count"])

    def test_qw_quality_probe_uses_only_owners_named_dependency(self):
        candidate = {"report_key": "file-audit.mass-operations", "quality": "partial", "counts": {},
            "root_limit": False, "roots": [dict(agent_id="a", source_instance_id="s", collection_scope_id="one",
                                                source_kind="server")]}
        actors = {7: access("file-audit.mass-operations"), 8: access("file-audit.mass-operations")}
        result = self.project(candidate, actors, file=True, dependency=access())
        self.assertEqual(result["selection"]["qw_root_indexes"], [0])
        self.assertTrue(result['selection']['include_count'])
        denied = access()
        denied["reports"] = []
        result = self.project(candidate, actors, file=True, dependency=denied)
        self.assertEqual(result["selection"]["qw_root_indexes"], [])
        self.assertTrue(result['selection']['include_count'])


if __name__ == "__main__":
    unittest.main()

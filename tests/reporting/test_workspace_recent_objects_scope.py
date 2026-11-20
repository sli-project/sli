"""Recent-object DTOs enforce the same resource policies as object details."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from server.sli.reporting import reporting_v4 as r4
from server.sli.core.database import QueryTimeoutError
from server.sli.reporting.ui_api_models import V4WorkspaceResponse


def _access(*, capabilities=(), policies=(), scoped=(), owner=False):
    return {
        "capabilities": ["workspace.view", *capabilities],
        "resource_bound_capabilities": list(scoped),
        "capability_policies": list(policies), "platform_owner": owner,
        "reports": [], "subject": {"login": "synthetic"},
        "packages": [], "groups": [], "explicit_denies": {},
    }


def _policy(capability, kind, resource_id, *, effect="deny", valid=True):
    return {"capability_key": capability, "effect": effect, "valid": valid,
            "scope": {"kind": kind, "ids": [resource_id]}}


def _row(**changes):
    return {"id": 7, "object_type": "account", "display_name": "Synthetic object",
            "natural_key": "TECHNICAL_SENTINEL", "domain_id": 11, "server_id": 22,
            "last_seen_utc": "2026-10-21T00:00:00Z", **changes}


class WorkspaceRecentObjectsScopeTests(unittest.TestCase):
    def payload(self, access, rows=None, *, error=None):
        with patch.object(r4, "query_rows_bounded", return_value=rows or [], side_effect=error) as query, \
             patch.object(r4, "_workspace_focus_metrics", return_value=[]):
            result = r4.workspace(None, access=access)
        if query.called:
            self.assertEqual(query.call_count, 1)
            sql, params = query.call_args.args
            self.assertIn("entities_v2_active", sql)
            self.assertIn("limit ?", sql.lower())
            self.assertEqual(params, (8,))
            self.assertEqual(query.call_args.kwargs, {"statement_timeout_ms": 3000})
        return result, query

    def test_query_selects_authoritative_resource_columns(self):
        _, query = self.payload(_access(capabilities=("objects.view",)), [_row()])
        sql = query.call_args.args[0]
        self.assertIn("entity.domain_id", sql)
        self.assertIn("entity.server_id", sql)

    def test_domain_and_server_deny_override_global_allow(self):
        for kind, resource_id in (("domain", 11), ("server", 22)):
            with self.subTest(kind=kind):
                result, _ = self.payload(_access(capabilities=("objects.view", "field.technical"),
                    policies=[_policy("objects.view", kind, resource_id)]), [_row()])
                self.assertEqual(result["recent_objects"], [])

    def test_other_dimension_deny_overrides_scoped_allow(self):
        for allow_kind, allow_id, deny_kind, deny_id in (
            ("domain", 11, "server", 22), ("server", 22, "domain", 11),
        ):
            with self.subTest(allow_kind=allow_kind):
                result, _ = self.payload(_access(scoped=("objects.view",), policies=[
                    _policy("objects.view", allow_kind, allow_id, effect="allow"),
                    _policy("objects.view", deny_kind, deny_id),
                ]), [_row()])
                self.assertEqual(result["recent_objects"], [])

    def test_technical_deny_redacts_key_and_display_name_fallback(self):
        for kind, resource_id in (("domain", 11), ("server", 22)):
            with self.subTest(kind=kind):
                result, _ = self.payload(_access(capabilities=("objects.view", "field.technical"),
                    policies=[_policy("field.technical", kind, resource_id)]), [_row(display_name="")])
                item = result["recent_objects"][0]
                self.assertIsNone(item["natural_key"])
                self.assertEqual(item["display_name"], "7")
                self.assertNotIn("TECHNICAL_SENTINEL", V4WorkspaceResponse(**result).model_dump_json())

    def test_scoped_only_allow_includes_only_matching_rows(self):
        result, _ = self.payload(_access(scoped=("objects.view", "field.technical"), policies=[
            _policy("objects.view", "domain", 11, effect="allow"),
            _policy("field.technical", "server", 22, effect="allow"),
        ]), [_row(display_name=""), _row(id=8, domain_id=12)])
        self.assertEqual([item["object_id"] for item in result["recent_objects"]], ["7"])
        self.assertEqual(result["recent_objects"][0]["natural_key"], "TECHNICAL_SENTINEL")
        self.assertEqual(result["recent_objects"][0]["display_name"], "TECHNICAL_SENTINEL")

    def test_owner_with_known_resources(self):
        result, query = self.payload(_access(owner=True), [_row()])
        self.assertTrue(query.called)
        self.assertEqual(result["recent_objects"][0]["object_id"], "7")

    def test_no_object_permission_does_not_query(self):
        result, query = self.payload(_access(), [_row()])
        self.assertFalse(query.called)
        self.assertEqual(result["recent_objects"], [])

    def test_missing_or_invalid_resource_context_is_omitted_even_for_owner(self):
        cases = [dict(domain_id=None, server_id=None), dict(domain_id=0), dict(server_id=-1),
                 dict(domain_id=True), dict(server_id="22"), dict(domain_id=1.5),
                 dict(domain_id="invalid", server_id=None)]
        for owner in (False, True):
            for changes in cases:
                with self.subTest(owner=owner, changes=changes):
                    result, _ = self.payload(_access(capabilities=("objects.view",), owner=owner), [_row(**changes)])
                    self.assertEqual(result["recent_objects"], [])
        for missing_keys in (("domain_id",), ("server_id",), ("domain_id", "server_id")):
            with self.subTest(missing_keys=missing_keys):
                row = _row()
                for key in missing_keys:
                    del row[key]
                result, _ = self.payload(_access(owner=True), [row])
                self.assertEqual(result["recent_objects"], [])

    def test_legitimate_partial_context_uses_available_resource(self):
        for kind, resource_id, changes in (("domain", 11, {"server_id": None}),
                                           ("server", 22, {"domain_id": None})):
            with self.subTest(kind=kind):
                result, _ = self.payload(_access(scoped=("objects.view",), policies=[
                    _policy("objects.view", kind, resource_id, effect="allow"),
                ]), [_row(**changes)])
                self.assertEqual(len(result["recent_objects"]), 1)
                result, _ = self.payload(_access(capabilities=("objects.view",), policies=[
                    _policy("objects.view", kind, resource_id),
                ]), [_row(**changes)])
                self.assertEqual(result["recent_objects"], [])

    def test_invalid_deny_fails_closed(self):
        for capability in ("objects.view", "field.technical"):
            with self.subTest(capability=capability):
                result, _ = self.payload(_access(capabilities=("objects.view", "field.technical"), policies=[
                    _policy(capability, "domain", 11, valid=False),
                ]), [_row(display_name="")])
                if capability == "objects.view":
                    self.assertEqual(result["recent_objects"], [])
                else:
                    self.assertIsNone(result["recent_objects"][0]["natural_key"])
                    self.assertEqual(result["recent_objects"][0]["display_name"], "7")

    def test_first_eight_denied_are_not_refilled(self):
        result, query = self.payload(_access(capabilities=("objects.view",), policies=[
            _policy("objects.view", "domain", 11),
        ]), [_row(id=number) for number in range(1, 9)])
        self.assertEqual(result["recent_objects"], [])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(result["recent_objects_state"], "available")

    def test_timeout_preserves_workspace_contract(self):
        result, _ = self.payload(_access(capabilities=("objects.view",)),
            error=QueryTimeoutError("synthetic timeout", timeout_ms=3000))
        self.assertEqual(result["recent_objects"], [])
        self.assertEqual(result["recent_objects_state"], "temporarily_unavailable")
        self.assertEqual(V4WorkspaceResponse(**result).limits["recent_objects"], 8)

    def test_real_dto_does_not_serialize_denied_row(self):
        result, _ = self.payload(_access(capabilities=("objects.view", "field.technical"), policies=[
            _policy("objects.view", "server", 22),
            _policy("field.technical", "domain", 11),
        ]), [_row(id=99999, display_name="DENIED_IDENTITY_SENTINEL"),
             _row(id=8, server_id=23, display_name="")])
        dto = V4WorkspaceResponse(**result)
        self.assertEqual(dto.recent_objects[0]["object_id"], "8")
        serialized = dto.model_dump_json()
        for sentinel in ("99999", "DENIED_IDENTITY_SENTINEL", "TECHNICAL_SENTINEL"):
            self.assertNotIn(sentinel, serialized)

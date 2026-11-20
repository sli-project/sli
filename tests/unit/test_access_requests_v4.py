"""Access-review transaction contracts; no database or schema changes are made."""
from copy import deepcopy
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import os
import unittest
from unittest.mock import patch

import pytest

from server.sli.access import access_requests_v4 as requests
from server.sli.core.messages import response_messages


class RequestStore:
    """Model connection commit/rollback and the submitted-only claim predicate."""

    def __init__(self):
        self.row = {
            "id": 7, "status": "submitted", "decided_by": None,
            "requester_user_id": 42, "report_key": "report.example",
            "requested_scope_json": {"kind": "server", "ids": ["s1", "s2"]},
            "requested_field_categories": ["summary", "details"],
            "requested_actions": ["view", "export"],
            "requested_valid_until": datetime.now(timezone.utc) + timedelta(days=10),
            "business_reason": "Required for operations",
        }
        self.committed_states = []

    def connect(self):
        store = self

        class Connection:
            def __enter__(self):
                self.before = deepcopy(store.row)
                return self

            def __exit__(self, exc_type, exc, traceback):
                if exc_type is not None:
                    store.row = self.before
                else:
                    store.committed_states.append(store.row["status"])

            def cursor(self):
                return Cursor()

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def execute(self, sql, params):
                sql = " ".join(sql.split())
                self.result = None
                if "set status='reviewing'" in sql:
                    if store.row["status"] == "submitted":
                        store.row.update(status="reviewing", decided_by=params[0])
                        self.result = deepcopy(store.row)
                elif "set status='submitted'" in sql:
                    if store.row["status"] == "reviewing":
                        store.row.update(status="submitted", decided_by=None)
                elif "set status='rejected'" in sql:
                    if store.row["status"] == "reviewing":
                        store.row.update(status="rejected", decision_reason=params[0])
                        self.result = deepcopy(store.row)
                elif "set status=%s" in sql:
                    if store.row["status"] == "reviewing":
                        store.row.update(status=params[0], assignment_id=params[2])
                        self.result = deepcopy(store.row)
                else:
                    raise AssertionError(f"Unexpected SQL: {sql}")

            def fetchone(self):
                return self.result

        return Connection()


class AccessRequestReviewTests(unittest.TestCase):
    actor = {"type": "session", "id": 9, "username": "reviewer"}

    def setUp(self):
        self.store = RequestStore()
        self.access = {
            "capabilities": ["access.manage", "reports.assign"],
            "reports": [{"report_key": "report.example", "allowed": True}],
        }
        self.connect = self.enterContext(patch.object(requests, "_connect", self.store.connect))
        self.enterContext(patch.object(requests, "ensure_access_schema"))
        self.effective = self.enterContext(patch.object(requests, "effective_access", return_value=self.access))
        self.assign = self.enterContext(patch.object(requests, "create_report_assignment", return_value={"id": 81}))
        self.audit = self.enterContext(patch.object(requests, "record_access_audit_with_cursor"))

    def decide(self, **changes):
        return requests.decide_report_access_request(
            7, {"decision": "approve", "decision_reason": "Reviewed request", **changes},
            actor=self.actor,
        )

    def test_malformed_approval_rolls_back_claim_and_allows_retry(self):
        cases = [
            ({"scope": {"kind": "bogus"}}, ValueError, "request_scope_not_supported"),
            ({"scope": {"kind": "server", "ids": []}}, ValueError, "invalid_request_scope"),
            ({"valid_until": "not-a-date"}, ValueError, "invalid_request_valid_until"),
            ({"valid_until": "2030-01-01T00:00:00"}, ValueError, "invalid_request_valid_until"),
            ({"field_categories": None}, TypeError, "not iterable"),
            ({"allowed_actions": None}, TypeError, "not iterable"),
        ]
        for changes, error, message in cases:
            for retry in ("approve", "reject"):
                with self.subTest(changes=changes, retry=retry):
                    self.store = RequestStore()
                    with patch.object(requests, "_connect", self.store.connect):
                        self.assign.reset_mock()
                        self.audit.reset_mock()
                        before = deepcopy(self.store.row)
                        with self.assertRaisesRegex(error, message):
                            self.decide(**changes)
                        self.assertEqual(self.store.row, before)
                        self.assertEqual(self.store.committed_states, [])
                        self.assign.assert_not_called()
                        self.audit.assert_not_called()
                        result = self.decide(decision=retry)
                        self.assertEqual(result["status"], "approved" if retry == "approve" else "rejected")

    def test_valid_approval_keeps_requested_grant(self):
        result = self.decide()
        self.assertEqual(result["status"], "approved")
        grant = self.assign.call_args.args[0]
        self.assertEqual(grant["scope"], self.store.row["requested_scope_json"])
        self.assertEqual(grant["allowed_actions"], ["export", "view"])
        self.assertEqual(grant["field_categories"], ["details", "summary"])
        self.assertEqual(grant["subject_id"], 42)
        self.assertEqual(grant["valid_until"], self.store.row["requested_valid_until"].isoformat())
        self.assertEqual(self.audit.call_args.kwargs["action"], "report_access_request_approved")

    def test_narrowed_approval_is_limited(self):
        until = self.store.row["requested_valid_until"] - timedelta(days=1)
        result = self.decide(
            scope={"kind": "server", "ids": ["s1"]},
            field_categories=["summary"], allowed_actions=["view"], valid_until=until.isoformat(),
        )
        self.assertEqual(result["status"], "approved_limited")
        grant = self.assign.call_args.args[0]
        self.assertEqual(grant["scope"], {"kind": "server", "ids": ["s1"]})
        self.assertEqual(grant["field_categories"], ["summary"])
        self.assertEqual(grant["allowed_actions"], ["view"])
        self.assertEqual(grant["valid_until"], until.isoformat())

    def test_expansion_is_rejected_without_claim_commit(self):
        for changes in (
            {"scope": {"kind": "all"}},
            {"field_categories": ["secret"]},
            {"allowed_actions": ["view", "admin"]},
            {"allowed_actions": ["export"]},
            {"valid_until": None},
            {"valid_until": (self.store.row["requested_valid_until"] + timedelta(days=1)).isoformat()},
        ):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, "decision_may_not_expand_request"):
                    self.decide(**changes)
                self.assertEqual(self.store.row["status"], "submitted")
                self.assertIsNone(self.store.row["decided_by"])
                self.assertEqual(self.store.committed_states, [])
                self.assign.assert_not_called()

    def test_rejection_ignores_unused_approval_fields(self):
        result = self.decide(decision="reject", scope={"kind": "bogus"}, valid_until="invalid")
        self.assertEqual(result["status"], "rejected")
        self.assign.assert_not_called()
        self.assertEqual(self.audit.call_args.kwargs["action"], "report_access_request_rejected")

    def test_both_review_capabilities_remain_required(self):
        for capabilities in ([], ["access.manage"], ["reports.assign"]):
            with self.subTest(capabilities=capabilities):
                self.access["capabilities"] = capabilities
                with self.assertRaisesRegex(PermissionError, "access_request_review_required"):
                    self.decide()
                self.assertEqual(self.store.committed_states, [])
                self.assign.assert_not_called()

    def test_non_pending_request_cannot_be_claimed(self):
        for status in ("reviewing", "approved", "rejected"):
            with self.subTest(status=status):
                self.store.row["status"] = status
                with self.assertRaisesRegex(ValueError, "access_request_not_pending"):
                    self.decide()
                self.assertEqual(self.store.row["status"], status)
                self.assign.assert_not_called()

    def test_assignment_failure_still_resets_claim(self):
        self.assign.side_effect = ValueError("assignment_rejected")
        with self.assertRaisesRegex(ValueError, "assignment_rejected"):
            self.decide()
        self.assertEqual(self.store.row["status"], "submitted")
        self.assertIsNone(self.store.row["decided_by"])
        self.audit.assert_not_called()


def test_request_list_name_query_is_bound_to_the_requested_version(monkeypatch):
    """The name source must share report_version used by the display localizer."""
    row = {"id": 7, "report_key": "ad.state", "report_version": 1,
           "report_name": "Active Directory", "status": "submitted"}

    class Cursor:
        def execute(self, sql, params):
            normalized = " ".join(sql.split())
            assert "where report_key=request.report_key and version=request.report_version" in normalized
            assert params == (42, 100)

        def fetchall(self):
            return [row]

    class Connection:
        def cursor(self):
            return nullcontext(Cursor())

    monkeypatch.setattr(requests, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(requests, "effective_access", lambda actor: {"capabilities": []})
    monkeypatch.setattr(requests, "_connect", lambda: nullcontext(Connection()))
    payload = requests.list_report_access_requests(actor={"type": "session", "id": 42})
    item = response_messages(payload, "en", request_path="/api/v1/access/report-requests")["items"][0]
    assert item["report_name"] == "Active Directory"
    assert item["report_version"] == 1 and item["status"] == "submitted"


@pytest.mark.postgres_integration
def test_request_names_keep_version_provenance_and_custom_values_on_postgres(monkeypatch):
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    owner_v2_name = "Состояние и риски Active Directory"
    custom_name = "Авторское имя"
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        # Session-local query fixtures; persistent schema and ACLs are untouched.
        conn.execute("create temp table auth_users(id int, username text)")
        conn.execute("create temp table report_registry_v4(report_key text, version int, name text)")
        conn.execute("""create temp table report_access_requests_v4(
            id int, requester_user_id int, report_key text, report_version int,
            status text, created_at timestamptz, business_reason text)""")
        conn.execute("insert into auth_users values (42,'synthetic-review-user')")
        with conn.cursor() as cur:
            cur.executemany("insert into report_registry_v4 values (%s,%s,%s)", [
                ("ad.state", 1, "Active Directory"), ("ad.state", 2, owner_v2_name),
                ("access.center", 1, custom_name), ("access.center", 2, "Доступы пользователей и групп"),
                ("custom.report", 1, owner_v2_name), ("missing.version", 2, owner_v2_name),
            ])
            cur.executemany("""insert into report_access_requests_v4
                values (%s,42,%s,%s,'submitted',now(),'Авторское основание')""", [
                (1, "ad.state", 1), (2, "ad.state", 2), (3, "access.center", 1),
                (4, "custom.report", 1), (5, "missing.version", 1),
            ])
        monkeypatch.setattr(requests, "ensure_access_schema", lambda: None)
        monkeypatch.setattr(requests, "effective_access", lambda actor: {"capabilities": ["access.manage"]})
        monkeypatch.setattr(requests, "_connect", lambda: nullcontext(conn))
        for include_all in (False, True):
            payload = requests.list_report_access_requests(
                actor={"type": "session", "id": 42}, include_all=include_all,
            )
            result = response_messages(payload, "en", request_path="/api/v1/access/report-requests")
            by_id = {item["id"]: item for item in result["items"]}
            assert {key: item["report_name"] for key, item in by_id.items()} == {
                1: "Active Directory", 2: owner_v2_name, 3: custom_name,
                4: owner_v2_name, 5: "missing.version",
            }
            assert by_id[1]["report_version"] == 1 and by_id[2]["report_version"] == 2
            assert all(item["business_reason"] == "Авторское основание" for item in by_id.values())
            assert all(item["status"] == "submitted" for item in by_id.values())
            assert all("presentation_messages" not in by_id[key] for key in (2, 3, 4, 5))
        latest = conn.execute("select name from report_registry_v4 where report_key='ad.state' and version=2").fetchone()
        assert latest["name"] == owner_v2_name

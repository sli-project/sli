from __future__ import annotations

from datetime import datetime, timezone
import importlib
from pathlib import Path

import pytest

from server.api.routes import reports as routes_reports
from server.api import http_server
from server.sli.reports import ad_account_state_reporting as account_reporting
from server.sli.storage.storage_v2_models import (
    canonical_json_bytes,
    event_facts_from_v1,
    sha256_bytes,
)


UTC = timezone.utc


def _event(
    event_db_id: int,
    event_id: int,
    minute: int,
    **overrides,
) -> dict:
    return {
        "event_db_id": event_db_id,
        "event_record_id": event_db_id * 10,
        "event_id": event_id,
        "time_created_utc": datetime(2026, 8, 23, 10, minute, tzinfo=UTC),
        "domain_controller": "dc01.example.test",
        "subject_user_sid": "S-1-5-21-100",
        "subject_user_name": "operator",
        "target_user_sid": "S-1-5-21-200",
        "target_user_name": "alice",
        "source_core_sha256": b"c" * 32,
        "source_facts_sha256": b"f" * 32,
        **overrides,
    }


def _events_access() -> dict:
    return {
        "platform_owner": False,
        "capabilities": ["events.view"],
        "capability_policies": [],
        "reports": [
            {
                "report_key": "ad.state",
                "allowed": True,
                "allowed_actions": ["view"],
                "grants": [
                    {
                        "allowed_actions": ["view"],
                        "scope": {"kind": "domain", "ids": [7]},
                    }
                ],
            }
        ],
    }


def test_account_change_history_preserves_event_evidence_and_observed_transitions() -> None:
    payload = account_reporting.compose_ad_account_change_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[
            _event(20, 4781, 20, account_name_before="alice", account_name_after="alice.renamed"),
            _event(10, 4722, 10),
        ],
        collection_coverage={"history_event_present": True},
    )

    assert payload["state"] == "available"
    assert payload["history_state"] == "partial"
    assert [item["event_id"] for item in payload["items"]] == [4722, 4781]
    enabled, renamed = payload["items"]
    assert enabled["change"] == {"kind": "enabled"}
    assert enabled["observed_transition"] == {
        "before": {"state": "unknown", "reason": "prior_account_state_not_observed"},
        "after": {"state": "observed", "value": "enabled"},
    }
    assert renamed["change"] == {"kind": "renamed"}
    assert renamed["observed_transition"] == {
        "before": {"state": "observed", "value": "alice"},
        "after": {"state": "observed", "value": "alice.renamed"},
    }
    assert renamed["account"]["target_user_sid"] == "S-1-5-21-200"
    assert renamed["actor"]["subject_user_name"] == "operator"
    assert renamed["domain_controller"] == "dc01.example.test"
    assert renamed["evidence"]["event_db_id"] == 20
    assert renamed["evidence"]["state"] == "complete"
    assert renamed["evidence"]["missing_fields"] == []
    assert "current_state" not in renamed


def test_account_change_history_marks_missing_facts_hash_as_partial_evidence() -> None:
    payload = account_reporting.compose_ad_account_change_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[_event(1, 4722, 10, source_facts_sha256=None)],
        collection_coverage={"history_event_present": True},
    )

    evidence = payload["items"][0]["evidence"]
    assert evidence["state"] == "partial"
    assert evidence["missing_fields"] == ["source_facts_sha256"]
    assert any(
        "Some rows have partial source provenance" in limitation
        for limitation in payload["limitations"]
    )


def test_account_created_event_exposes_its_observed_post_state_only() -> None:
    payload = account_reporting.compose_ad_account_change_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[_event(1, 4720, 10)],
        collection_coverage={"history_event_present": True},
    )

    assert payload["items"][0]["change"] == {"kind": "created"}
    assert payload["items"][0]["observed_transition"] == {
        "before": {"state": "unknown", "reason": "prior_account_state_not_observed"},
        "after": {"state": "observed", "value": "present"},
    }


def test_password_operations_remain_attempts_and_publish_only_observed_result() -> None:
    payload = account_reporting.compose_ad_account_change_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[
            _event(1, 4723, 10),
            _event(2, 4724, 20, result_code="0x0"),
        ],
        collection_coverage={"history_event_present": True},
    )

    change_attempt, reset_attempt = payload["items"]
    assert change_attempt["change"] == {"kind": "password_change_attempt"}
    assert "password_changed" not in change_attempt
    assert "result" not in change_attempt["change"]
    assert reset_attempt["change"] == {
        "kind": "password_reset_attempt",
        "result": {"state": "observed", "value": "0x0"},
    }
    assert reset_attempt["observed_transition"] == {
        "before": {"state": "unknown", "reason": "prior_account_state_not_observed"},
        "after": {"state": "unknown", "reason": "event_does_not_prove_account_state"},
    }


def test_password_result_code_is_projected_only_from_source_native_field() -> None:
    facts = event_facts_from_v1(
        {
            "id": 12,
            "channel": "Security",
            "event_id": 4724,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data_json": '{"Status":"0x0"}',
        }
    )

    assert facts is not None
    assert facts.values["result_code"] == "0x0"
    assert "password" not in facts.values


def test_account_change_history_keeps_unproven_prior_state_unknown() -> None:
    payload = account_reporting.compose_ad_account_change_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[
            _event(1, 4725, 10, target_user_sid=None, target_user_name="shared-name"),
            _event(2, 4722, 20, target_user_sid=None, target_user_name="shared-name"),
        ],
        collection_coverage={"history_event_present": True},
    )

    assert payload["items"][1]["observed_transition"]["before"] == {
        "state": "unknown",
        "reason": "prior_account_state_not_observed",
    }
    assert payload["items"][1]["account"] == {
        "state": "observed",
        "target_user_sid": None,
        "target_user_name": "shared-name",
    }


def test_account_change_history_marks_a_sid_matched_prior_observation_partial() -> None:
    payload = account_reporting.compose_ad_account_change_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[_event(1, 4725, 10), _event(2, 4722, 20)],
        collection_coverage={"history_event_present": True},
    )

    assert payload["items"][1]["observed_transition"]["before"] == {
        "state": "partial",
        "last_observed": {
            "value": "disabled",
            "event_db_id": 1,
            "time_created_utc": "2026-08-23T10:10:00Z",
        },
        "reason": "intervening_account_state_not_proven",
    }


def test_account_change_history_empty_window_is_unverified() -> None:
    payload = account_reporting.compose_ad_account_change_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[],
        collection_coverage={"history_event_present": True},
    )

    assert payload["state"] == "empty_unverified"
    assert payload["history_state"] == "unknown"
    assert payload["collection_coverage"] == {
        "state": "empty_unverified",
        "history_event_present": True,
        "source_completeness": "not_proven",
    }


def test_account_change_history_denial_precedes_database_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        account_reporting,
        "_read_ad_account_change_history_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )

    payload = account_reporting.get_ad_account_change_history(
        {"platform_owner": False, "capabilities": [], "capability_policies": []},
        source_domain_id=7,
        time_from="2026-08-23T10:00:00Z",
        time_to="2026-08-23T11:00:00Z",
    )

    assert payload["state"] == "not_authorized"
    assert payload["items"] == []


def test_account_change_source_discovery_returns_only_authorized_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        account_reporting,
        "_read_ad_account_change_domain_batch",
        lambda **_kwargs: [7, 8],
        raising=False,
    )
    inspected: list[int] = []
    monkeypatch.setattr(
        account_reporting,
        "_has_ad_account_change_source",
        lambda domain_id: inspected.append(domain_id) or domain_id == 7,
        raising=False,
    )

    payload = account_reporting.get_ad_account_change_sources(_events_access())

    assert payload["state"] == "available"
    assert payload["items"] == [{"source_domain_id": 7}]
    assert payload["bounded"] is True
    assert inspected == [7]


def test_rename_preserves_only_source_native_before_and_after_names() -> None:
    facts = event_facts_from_v1(
        {
            "id": 9,
            "channel": "Security",
            "event_id": 4781,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data_json": (
                '{"OldTargetUserName":"alice",'
                '"NewTargetUserName":"alice.renamed",'
                '"TargetSid":"S-1-5-21-200"}'
            ),
        }
    )

    assert facts is not None
    assert facts.values["account_target_sid"] == "S-1-5-21-200"
    assert facts.values["account_target_name"] == "alice.renamed"
    assert facts.values["account_name_before"] == "alice"
    assert facts.values["account_name_after"] == "alice.renamed"


def test_group_membership_facts_keep_only_source_native_member_identity() -> None:
    facts = event_facts_from_v1(
        {
            "id": 11,
            "channel": "Security",
            "event_id": 4728,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data_json": (
                '{"MemberSid":"S-1-5-21-200",'
                '"MemberName":"CN=Alice,DC=example,DC=test",'
                '"TargetSid":"S-1-5-21-512",'
                '"TargetUserName":"Domain Admins"}'
            ),
        }
    )

    assert facts is not None
    assert facts.values["membership_member_sid"] == "S-1-5-21-200"
    assert facts.values["membership_member_name"] == "CN=Alice,DC=example,DC=test"
    assert facts.source_facts_sha256 == sha256_bytes(canonical_json_bytes({
        key: value
        for key, value in facts.values.items()
        if key not in {
            "account_target_sid",
            "account_target_name",
            "account_name_before",
            "account_name_after",
        }
    }))


def test_group_membership_placeholders_are_not_persisted_as_stable_sids() -> None:
    facts = event_facts_from_v1(
        {
            "id": 13,
            "channel": "Security",
            "event_id": 4728,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_data_json": {"MemberSid": "-", "MemberName": "-"},
        }
    )

    assert facts is None


def test_non_rename_facts_keep_the_existing_hash_shape() -> None:
    facts = event_facts_from_v1(
        {
            "id": 10,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "event_id": 4103,
            "provider_name": "Microsoft-Windows-PowerShell",
            "event_data_json": '{"CommandName":"Get-ADUser"}',
        }
    )

    assert facts is not None
    assert facts.values["account_target_sid"] is None
    assert facts.values["account_target_name"] is None
    assert facts.values["account_name_before"] is None
    assert facts.values["account_name_after"] is None
    assert facts.values["membership_member_sid"] is None
    assert facts.values["membership_member_name"] is None
    legacy_values = {
        key: value
        for key, value in facts.values.items()
        if key
        not in {
            "account_target_sid",
            "account_target_name",
            "account_name_before",
            "account_name_after",
            "membership_member_sid",
            "membership_member_name",
        }
    }
    assert facts.source_facts_sha256 == sha256_bytes(canonical_json_bytes(legacy_values))


def test_postgres_importer_preserves_rename_target_sid_and_new_name() -> None:
    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")

    params = importer._event_params(
        raw_log_file_id=1,
        server_id=2,
        domain_id=7,
        site_id=3,
        log_source_id=4,
        row={
            "record_id": 9,
            "event_id": 4781,
            "channel": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "time_created": "2026-08-23T10:00:00Z",
        },
        event_data={
            "TargetSid": "S-1-5-21-200",
            "NewTargetUserName": "alice.renamed",
        },
    )

    assert params[22] == "S-1-5-21-200"
    assert params[23] == "alice.renamed"


def test_account_change_history_has_a_source_only_warm_fact_migration() -> None:
    root = Path(__file__).resolve().parents[2]
    forward = root / "config/postgres_migrations/086_ad_account_change_warm_facts.sql"
    rollback = root / "config/postgres_migrations/086_ad_account_change_warm_facts.rollback.sql"

    assert forward.is_file()
    assert rollback.is_file()
    assert "account_target_sid" in forward.read_text(encoding="utf-8")
    assert "account_target_name" in forward.read_text(encoding="utf-8")
    assert "account_name_before" in forward.read_text(encoding="utf-8")
    assert "account_name_after" in forward.read_text(encoding="utf-8")
    assert "rollback is unsafe while account rename facts exist" in rollback.read_text(
        encoding="utf-8"
    ).lower()


def test_account_history_reader_uses_source_native_rename_identity_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []

    class Cursor:
        select_count = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params=None) -> None:
            statements.append(" ".join(str(sql).split()).lower())
            if str(sql).lstrip().lower().startswith("select"):
                self.select_count += 1

        def fetchall(self):
            assert self.select_count == 1
            return [_event(1, 4781, 10)]

        def fetchone(self):
            assert self.select_count == 2
            return {"history_event_present": True}

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(account_reporting, "_connect", lambda: Connection())

    events, coverage = account_reporting._read_ad_account_change_history_data(
        domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        limit=25,
    )

    activity_sql = statements[1]
    assert events[0]["event_id"] == 4781
    assert coverage["history_event_present"] is True
    assert "facts.account_target_sid" in activity_sql
    assert "facts.account_target_name" in activity_sql
    assert "coalesce(nullif(btrim(event.target_user_sid),'')" in activity_sql
    assert "coalesce(nullif(btrim(event.target_user_name),'')" in activity_sql


def test_account_change_history_route_delegates_bounded_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_service(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {"state": "available"}

    monkeypatch.setattr(routes_reports, "get_ad_account_change_history", fake_service)

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            captured["payload"] = payload

    assert routes_reports.try_handle_get(
        FakeHandler(),
        "/api/v1/reports/ad.state/account-changes",
        {
            "domain_id": ["7"],
            "time_from": ["2026-08-23T10:00:00Z"],
            "time_to": ["2026-08-23T11:00:00Z"],
            "timezone": ["UTC"],
            "limit": ["25"],
        },
    )
    assert captured == {
        "access": {"server_built": True},
        "source_domain_id": 7,
        "time_from": "2026-08-23T10:00:00Z",
        "time_to": "2026-08-23T11:00:00Z",
        "timezone_name": "UTC",
        "limit": 25,
        "payload": {"state": "available"},
    }


def test_account_change_sources_route_delegates_server_built_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_sources(access):
        captured["access"] = access
        return {"state": "available", "items": [{"source_domain_id": 7}]}

    monkeypatch.setattr(
        routes_reports,
        "get_ad_account_change_sources",
        fake_sources,
        raising=False,
    )

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            captured["payload"] = payload

    assert routes_reports.try_handle_get(
        FakeHandler(),
        "/api/v1/reports/ad.state/account-change-sources",
        {},
    )
    assert captured == {
        "access": {"server_built": True},
        "payload": {
            "state": "available",
            "items": [{"source_domain_id": 7}],
        },
    }


def test_account_change_history_http_denial_precedes_database_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    monkeypatch.setattr(
        account_reporting,
        "_read_ad_account_change_history_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )

    handler = object.__new__(http_server.RequestHandler)
    handler.path = (
        "/api/v1/reports/ad.state/account-changes?domain_id=7"
        "&time_from=2026-08-23T10:00:00Z&time_to=2026-08-23T11:00:00Z"
    )
    handler._access_decision = lambda: {
        "platform_owner": False,
        "capabilities": [],
        "capability_policies": [],
    }
    handler._require_capability = lambda _capability: pytest.fail(
        "generic report gate must not run"
    )
    sent: list[dict] = []
    handler._send_json = lambda payload, _status=None: sent.append(payload)

    handler._do_GET()

    assert sent[0]["state"] == "not_authorized"


def test_attribute_change_is_not_promoted_to_a_prior_account_state() -> None:
    payload = account_reporting.compose_ad_account_change_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[_event(1, 4738, 10), _event(2, 4722, 20)],
        collection_coverage={"history_event_present": True},
    )

    changed, enabled = payload["items"]
    assert changed["change"] == {
        "kind": "attributes_changed",
        "detail": {
            "state": "unknown",
            "reason": "changed_attribute_fields_not_in_warm_contract",
        },
    }
    assert changed["observed_transition"]["after"] == {
        "state": "unknown",
        "reason": "event_does_not_prove_account_state",
    }
    assert enabled["observed_transition"]["before"] == {
        "state": "unknown",
        "reason": "prior_account_state_not_observed",
    }

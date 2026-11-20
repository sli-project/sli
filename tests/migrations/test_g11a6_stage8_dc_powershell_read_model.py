from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.sli.reports import dc_powershell_reporting as powershell_reporting
from server.api import http_server
from server.api.routes import reports as routes_reports


UTC = timezone.utc
ROOT = Path(__file__).resolve().parents[2]


def _event(
    event_db_id: int,
    event_id: int,
    minute: int,
    **updates,
) -> dict:
    event = {
        "event_db_id": event_db_id,
        "event_record_id": 1000 + event_db_id,
        "event_id": event_id,
        "time_created_utc": datetime(2026, 8, 21, 10, minute, tzinfo=UTC),
        "domain_controller": "dc-02.example.test",
        "subject_user_sid": "S-1-5-21-101",
        "subject_user_name": "CORP\\operator",
        "powershell_user_name": None,
        "powershell_command_name": None,
        "powershell_script_block_text": None,
        "source_core_sha256": bytes.fromhex("aa" * 32),
        "source_facts_sha256": bytes.fromhex("bb" * 32),
    }
    event.update(updates)
    return event


def _events_access(*, domain_id: int = 7) -> dict:
    return {
        "platform_owner": False,
        "capabilities": [],
        "capability_policies": [{
            "capability_key": "events.view",
            "effect": "allow",
            "valid": True,
            "scope": {"kind": "domain", "ids": [domain_id]},
        }],
    }


def _single_security_boot_scope(boot_event_db_id: int = 15) -> dict:
    return {
        "origin_process_start_boot_event_db_id": boot_event_db_id,
        "origin_process_stop_boot_event_db_id": boot_event_db_id,
        "origin_session_start_boot_event_db_id": boot_event_db_id,
        "origin_session_end_boot_event_db_id": boot_event_db_id,
    }


def test_powershell_activity_keeps_each_event_as_its_own_evidence_fact() -> None:
    payload = powershell_reporting.compose_dc_powershell_activity(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            _event(
                2,
                4103,
                2,
                subject_user_sid=None,
                subject_user_name=None,
                powershell_user_name="CORP\\operator",
                powershell_command_name="Get-ADUser",
            ),
            _event(
                1,
                4104,
                1,
                powershell_script_block_text="Get-ADUser -Identity alice",
            ),
        ],
        collection_coverage={"history_event_present": True},
        include_script_block_text=True,
    )

    assert [item["event_id"] for item in payload["items"]] == [4104, 4103]
    assert payload["items"][0]["activity"] == {
        "state": "observed",
        "kind": "script_block",
        "script_block_text": "Get-ADUser -Identity alice",
    }
    assert payload["items"][1]["activity"] == {
        "state": "observed",
        "kind": "command",
        "command_name": "Get-ADUser",
    }
    assert payload["items"][1]["actor"] == {
        "state": "observed",
        "subject_user_sid": None,
        "subject_user_name": "CORP\\operator",
    }
    assert all(item["origin"] == {
        "state": "unknown",
        "reason": "no_complete_native_origin_chain",
    } for item in payload["items"])
    assert payload["items"][0]["evidence"] == {
        "event_db_id": 1,
        "event_record_id": 1001,
        "source_core_sha256": "aa" * 32,
        "source_facts_sha256": "bb" * 32,
    }
    assert "accounting" not in str(payload).lower()
    assert "rdp_session" not in str(payload).lower()


def test_powershell_activity_publishes_only_a_complete_native_rdp_chain() -> None:
    payload = powershell_reporting.compose_dc_powershell_activity(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            _event(
                1,
                4103,
                1,
                powershell_command_name="Get-ADUser",
                origin_kind="rdp",
                origin_source_ip="192.0.2.41",
                origin_workstation_name="ADMIN-01",
                origin_process_start_event_db_id=11,
                origin_process_stop_event_db_id=12,
                origin_session_start_event_db_id=13,
                origin_session_end_event_db_id=14,
                **_single_security_boot_scope(),
            )
        ],
        collection_coverage={"history_event_present": True},
        include_script_block_text=False,
    )

    assert payload["items"][0]["origin"] == {
        "state": "observed",
        "kind": "rdp",
        "source_ip": "192.0.2.41",
        "workstation_name": "ADMIN-01",
        "evidence": {
            "process_start_event_db_id": 11,
            "process_stop_event_db_id": 12,
            "session_start_event_db_id": 13,
            "session_end_event_db_id": 14,
            "boot_start_event_db_id": 15,
        },
    }


def test_powershell_activity_does_not_promote_an_incomplete_origin_chain() -> None:
    payload = powershell_reporting.compose_dc_powershell_activity(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            _event(
                1,
                4103,
                1,
                powershell_command_name="Get-ADUser",
                origin_kind="local",
                origin_process_start_event_db_id=11,
                origin_session_start_event_db_id=13,
            )
        ],
        collection_coverage={"history_event_present": True},
        include_script_block_text=False,
    )

    assert payload["items"][0]["origin"] == {
        "state": "unknown",
        "reason": "no_complete_native_origin_chain",
    }


def test_powershell_activity_rejects_reused_pid_and_logon_id_across_boot_boundary() -> None:
    """A closed PID/LogonId lifecycle must not bridge two Security 4608 boots."""

    payload = powershell_reporting.compose_dc_powershell_activity(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            _event(
                1,
                4103,
                1,
                powershell_command_name="Get-ADUser",
                origin_kind="rdp",
                origin_source_ip="192.0.2.41",
                origin_process_start_event_db_id=11,
                origin_process_stop_event_db_id=12,
                origin_session_start_event_db_id=13,
                origin_session_end_event_db_id=14,
                origin_process_start_boot_event_db_id=101,
                origin_process_stop_boot_event_db_id=202,
                origin_session_start_boot_event_db_id=101,
                origin_session_end_boot_event_db_id=202,
            )
        ],
        collection_coverage={"history_event_present": True},
        include_script_block_text=False,
    )

    assert payload["items"][0]["origin"] == {
        "state": "unknown",
        "reason": "origin_crosses_security_boot_boundary",
    }


def test_powershell_activity_preserves_each_event_domain_controller() -> None:
    payload = powershell_reporting.compose_dc_powershell_activity(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            _event(1, 4103, 1, domain_controller="dc-01.example.test"),
            _event(2, 4104, 2, domain_controller="dc-02.example.test"),
        ],
        collection_coverage={"history_event_present": True},
        include_script_block_text=False,
    )

    assert [item["domain_controller"] for item in payload["items"]] == [
        "dc-01.example.test",
        "dc-02.example.test",
    ]


@pytest.mark.parametrize(
    ("origin_kind", "updates", "expected"),
    [
        (
            "powershell_remoting",
            {"origin_source_ip": "192.0.2.61"},
            {"state": "observed", "kind": "powershell_remoting", "source_ip": "192.0.2.61"},
        ),
        (
            "local",
            {},
            {"state": "observed", "kind": "local"},
        ),
    ],
)
def test_powershell_activity_keeps_origin_kind_source_native(
    origin_kind: str,
    updates: dict,
    expected: dict,
) -> None:
    payload = powershell_reporting.compose_dc_powershell_activity(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            _event(
                1,
                4103,
                1,
                origin_kind=origin_kind,
                origin_process_start_event_db_id=11,
                origin_process_stop_event_db_id=12,
                origin_session_start_event_db_id=13,
                origin_session_end_event_db_id=14,
                **_single_security_boot_scope(),
                **updates,
            )
        ],
        collection_coverage={"history_event_present": True},
        include_script_block_text=False,
    )

    origin = payload["items"][0]["origin"]
    assert {key: origin[key] for key in expected} == expected


def test_powershell_activity_rejects_multiple_complete_origin_chains() -> None:
    event = _event(
        1,
        4103,
        1,
        origin_kind="rdp",
        origin_source_ip="192.0.2.41",
        origin_process_start_event_db_id=11,
        origin_process_stop_event_db_id=12,
        origin_session_start_event_db_id=13,
        origin_session_end_event_db_id=14,
        **_single_security_boot_scope(),
    )
    ambiguous = {
        **event,
        "origin_kind": "local",
        "origin_process_start_event_db_id": 21,
        "origin_process_stop_event_db_id": 22,
        "origin_session_start_event_db_id": 23,
        "origin_session_end_event_db_id": 24,
        **_single_security_boot_scope(25),
    }

    payload = powershell_reporting.compose_dc_powershell_activity(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[event, ambiguous],
        collection_coverage={"history_event_present": True},
        include_script_block_text=False,
    )

    assert payload["items"][0]["origin"] == {
        "state": "unknown",
        "reason": "ambiguous_complete_native_origin_chain",
    }


def test_powershell_activity_keeps_empty_window_unverified() -> None:
    payload = powershell_reporting.compose_dc_powershell_activity(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[],
        collection_coverage={"history_event_present": True},
        include_script_block_text=False,
    )

    assert payload["state"] == "coverage_unverified"
    assert payload["collection_coverage"] == {
        "state": "coverage_unverified",
        "history_event_present": True,
        "source_completeness": "not_proven",
    }


def test_powershell_activity_denial_precedes_database_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        powershell_reporting,
        "_read_dc_powershell_activity_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )

    payload = powershell_reporting.get_dc_powershell_activity(
        {"platform_owner": False, "capabilities": [], "capability_policies": []},
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )

    assert payload["state"] == "not_authorized"
    assert payload["items"] == []


def test_powershell_activity_reads_only_for_domain_scoped_events_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        powershell_reporting,
        "_read_dc_powershell_activity_data",
        lambda **_kwargs: ([_event(1, 4103, 1, powershell_command_name="Get-ADUser")], {
            "history_event_present": True,
        }),
    )

    payload = powershell_reporting.get_dc_powershell_activity(
        _events_access(),
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )

    assert payload["state"] == "available"
    assert payload["items"][0]["activity"]["command_name"] == "Get-ADUser"


def test_powershell_warm_facts_have_a_bounded_source_only_migration() -> None:
    forward_path = ROOT / "config/postgres_migrations/084_dc_powershell_warm_facts.sql"
    rollback_path = ROOT / "config/postgres_migrations/084_dc_powershell_warm_facts.rollback.sql"

    assert forward_path.is_file()
    assert rollback_path.is_file()
    forward = forward_path.read_text(encoding="utf-8").lower()
    rollback = rollback_path.read_text(encoding="utf-8").lower()
    assert "alter table event_facts_v2" in forward
    assert "powershell_command_name" in forward
    assert "powershell_script_block_text" in forward
    assert "powershell_user_name" in forward
    assert "length(powershell_script_block_text) <= 2048" in forward
    assert "insert into schema_migrations(version,name)" in forward
    assert "rollback is unsafe while powershell warm facts exist" in rollback


def test_powershell_origin_context_has_a_bounded_source_only_migration() -> None:
    forward_path = ROOT / "config/postgres_migrations/085_dc_powershell_origin_context.sql"
    rollback_path = ROOT / "config/postgres_migrations/085_dc_powershell_origin_context.rollback.sql"

    assert forward_path.is_file()
    assert rollback_path.is_file()
    forward = forward_path.read_text(encoding="utf-8").lower()
    rollback = rollback_path.read_text(encoding="utf-8").lower()
    assert "powershell_process_id" in forward
    assert "length(powershell_process_id) <= 128" in forward
    assert "migration 085 requires migration 084" in forward
    assert "rollback is unsafe while powershell process facts exist" in rollback


def test_powershell_activity_route_delegates_the_bounded_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_service(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {"state": "available"}

    monkeypatch.setattr(
        routes_reports,
        "get_dc_powershell_activity",
        fake_service,
    )

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            captured["payload"] = payload

    assert routes_reports.try_handle_get(FakeHandler(), "/api/v1/reports/dc.powershell/activity", {
        "domain_id": ["7"],
        "time_from": ["2026-08-21T10:00:00Z"],
        "time_to": ["2026-08-21T11:00:00Z"],
        "timezone": ["UTC"],
        "limit": ["25"],
    })
    assert captured == {
        "access": {"server_built": True},
        "source_domain_id": 7,
        "time_from": "2026-08-21T10:00:00Z",
        "time_to": "2026-08-21T11:00:00Z",
        "timezone_name": "UTC",
        "limit": 25,
        "payload": {"state": "available"},
    }


def test_powershell_activity_http_dispatch_defers_to_domain_scoped_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generic reports.catalog gate cannot decide a domain-scoped grant."""
    captured: dict = {}
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    monkeypatch.setattr(
        routes_reports,
        "get_dc_powershell_activity",
        lambda access, **kwargs: captured.update(access=access, **kwargs) or {"state": "available"},
    )

    handler = object.__new__(http_server.RequestHandler)
    handler.path = (
        "/api/v1/reports/dc.powershell/activity?domain_id=7"
        "&time_from=2026-08-21T10:00:00Z&time_to=2026-08-21T11:00:00Z"
    )
    handler._access_decision = _events_access
    handler._require_capability = lambda _capability: pytest.fail("generic report gate must not run")
    sent: list[dict] = []
    handler._send_json = lambda payload, _status=None: sent.append(payload)

    handler._do_GET()

    assert captured["access"] == _events_access()
    assert captured["source_domain_id"] == 7
    assert sent == [{"state": "available"}]


def test_powershell_activity_http_dispatch_denies_before_database_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    monkeypatch.setattr(
        powershell_reporting,
        "_read_dc_powershell_activity_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )

    handler = object.__new__(http_server.RequestHandler)
    handler.path = (
        "/api/v1/reports/dc.powershell/activity?domain_id=7"
        "&time_from=2026-08-21T10:00:00Z&time_to=2026-08-21T11:00:00Z"
    )
    handler._access_decision = lambda: {"platform_owner": False, "capabilities": [], "capability_policies": []}
    handler._require_capability = lambda _capability: pytest.fail("generic report gate must not run")
    sent: list[dict] = []
    handler._send_json = lambda payload, _status=None: sent.append(payload)

    handler._do_GET()

    assert sent[0]["state"] == "not_authorized"


def test_powershell_reader_is_dc_only_and_uses_a_closed_native_origin_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []
    parameters: list[tuple] = []

    class Cursor:
        def __init__(self) -> None:
            self.select_count = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params=None) -> None:
            statements.append(" ".join(str(sql).split()).lower())
            parameters.append(tuple(_params or ()))
            if str(sql).lstrip().lower().startswith(("select", "with")):
                self.select_count += 1

        def fetchall(self):
            assert self.select_count == 1
            return [_event(1, 4103, 1, powershell_command_name="Get-ADUser")]

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

    monkeypatch.setattr(powershell_reporting, "_connect", lambda: Connection())

    events, coverage = powershell_reporting._read_dc_powershell_activity_data(
        domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        limit=25,
        include_script_block_text=False,
    )

    activity_sql, coverage_sql = statements[1:]
    assert events[0]["event_id"] == 4103
    assert coverage["history_event_present"] is True
    assert "server.role='domain_controller'" in activity_sql
    assert "event.event_id in (4103,4104)" in activity_sql
    assert "null::text as powershell_script_block_text" in activity_sql
    assert "facts.source_facts_sha256" in activity_sql
    assert "process_start.event_id=%s" in activity_sql
    assert "process_stop_event.event_id=%s" in activity_sql
    assert "login_event.event_id=%s" in activity_sql
    assert "logoff_event.event_id=%s" in activity_sql
    assert "security_boot_boundaries" in activity_sql
    assert "boot.event_id=%s" in activity_sql
    assert "process_start_boot.id=process_stop_boot.id" in activity_sql
    assert "process_start_boot.id=session_start.session_start_boot_event_db_id" in activity_sql
    assert "process_start_boot.id=session_start.session_end_boot_event_db_id" in activity_sql
    assert "process_facts.process_id=power.powershell_process_id" in activity_sql
    assert "right(lower(coalesce(process_facts.process_name,'')), 15)='wsmprovhost.exe'" in activity_sql
    assert "nullif(btrim(process_stop_event.logon_id),'')=nullif(btrim(process_start.logon_id),'')" in activity_sql
    assert "process_stop_event.time_created_utc>=power.time_created_utc" in activity_sql
    assert "make_interval(days => %s)" in activity_sql
    assert "accounting" not in activity_sql
    assert "history_event.event_id in (4103,4104)" in coverage_sql
    assert parameters[1][6:10] == (
        7,
        powershell_reporting.BOOT_START_EVENT_ID,
        powershell_reporting.SECURITY_CHANNEL,
        powershell_reporting.SECURITY_PROVIDER,
    )

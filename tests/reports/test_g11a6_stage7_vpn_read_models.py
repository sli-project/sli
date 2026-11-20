from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.sli.reports import vpn_connections_reporting as connections_reporting
from server.sli.reports import vpn_session_reporting as session_reporting
from server.sli.reports import windows_authentication_reporting as windows_authentication_reporting
from server.api.routes import reports as routes_reports
from server.source_packs.radius.session_read_model import (
    RadiusLifecycleInput,
    fold_radius_sessions,
)


UTC = timezone.utc


def _audit_access(*, evidence: bool = False, radius: bool = True) -> dict:
    capabilities = ["vpn.sessions.view"] if radius else []
    if evidence:
        capabilities.append("vpn.session.evidence.read")
    return {
        "platform_owner": False,
        "capabilities": capabilities,
        "capability_policies": [],
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "allowed_actions": ["view"],
                "scope": {"kind": "domain", "ids": [7]},
            }],
        }],
    }


def _accounting_observation(
    observation_id: str,
    lifecycle_event: str,
    minute: int,
    *,
    session_key: str,
    principal_key: str = "entity:101",
) -> dict:
    return {
        "observation_id": observation_id,
        "lifecycle_event": lifecycle_event,
        "identity_state": "exact",
        "timestamp_state": "ready",
        "session_identity_key": session_key,
        "exact_principal_key": principal_key,
        "observed_at_utc": datetime(2026, 8, 21, 9, minute, tzinfo=UTC),
        "evidence_uid": f"00000000-0000-0000-0000-{int(minute):012d}",
        "source_instance_id": "radius-source-7",
        "stream_id": "radius-accounting",
        "transport_binding": "windows-rpc-smb-readonly-tail-v1",
        "object_reference": f"evidence:radius-{minute}",
        "canonical_record_sha256": "a" * 64,
        "object_sha256": "b" * 64,
        "object_size_bytes": 123,
        "verified_at_utc": datetime(2026, 8, 21, 9, minute, tzinfo=UTC),
    }


def _folded_row_id(rows: list[dict], index: int) -> str:
    folded = fold_radius_sessions(
        RadiusLifecycleInput(
            observation_id=item["observation_id"],
            lifecycle_event=item["lifecycle_event"],
            identity_state=item["identity_state"],
            timestamp_state=item["timestamp_state"],
            session_identity_key=item["session_identity_key"],
            exact_principal_key=item["exact_principal_key"],
            observed_at_utc=item["observed_at_utc"],
            evidence_sha256=item["canonical_record_sha256"],
        )
        for item in rows
    )
    return sorted(
        folded.sessions,
        key=lambda row: (row.session_identity_key, row.generation),
    )[index].session_row_id


def test_session_evidence_drilldown_uses_only_requested_folded_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_a = "radius-session:" + "a" * 64
    key_b = "radius-session:" + "b" * 64
    rows = [
        _accounting_observation("a-start-1", "start", 1, session_key=key_a),
        _accounting_observation("a-stop-1", "stop", 2, session_key=key_a),
        _accounting_observation("a-start-2", "start", 3, session_key=key_a),
        _accounting_observation("a-interim-2", "interim_update", 4, session_key=key_a),
        _accounting_observation("b-start", "start", 5, session_key=key_b),
        _accounting_observation("b-stop", "stop", 6, session_key=key_b),
    ]
    requested_row_id = _folded_row_id(rows, 1)
    monkeypatch.setattr(
        session_reporting,
        "_read_session_evidence_observations",
        lambda **_kwargs: rows,
    )

    payload = session_reporting.get_vpn_session_evidence(
        _audit_access(evidence=True),
        source_domain_id=7,
        session_row_id=requested_row_id,
    )

    assert [item["observation_id"] for item in payload["observations"]] == [
        "a-start-2", "a-interim-2",
    ]
    assert [
        item["evidence"]["evidence_uid"] for item in payload["observations"]
    ] == [
        "00000000-0000-0000-0000-000000000003",
        "00000000-0000-0000-0000-000000000004",
    ]
    assert payload["lifecycle"]["stopped_at_utc"] is None
    assert payload["lifecycle"]["stop_evidence"] == []
    assert payload["lifecycle"]["incomplete_reason"] == "missing_stop"
    assert "session_identity_key" not in str(payload)
    assert "exact_principal_key" not in str(payload)


def test_session_evidence_closed_session_returns_start_interim_and_stop_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_key = "radius-session:" + "a" * 64
    rows = [
        _accounting_observation("closed-start", "start", 1, session_key=session_key),
        _accounting_observation("closed-interim", "interim_update", 2, session_key=session_key),
        _accounting_observation("closed-stop", "stop", 3, session_key=session_key),
    ]
    monkeypatch.setattr(
        session_reporting,
        "_read_session_evidence_observations",
        lambda **_kwargs: rows,
    )

    payload = session_reporting.get_vpn_session_evidence(
        _audit_access(evidence=True),
        source_domain_id=7,
        session_row_id=_folded_row_id(rows, 0),
    )

    assert [item["observation_id"] for item in payload["observations"]] == [
        "closed-start", "closed-interim", "closed-stop",
    ]
    assert [item["evidence"]["object_reference"] for item in payload["observations"]] == [
        "evidence:radius-1", "evidence:radius-2", "evidence:radius-3",
    ]
    assert payload["lifecycle"]["completeness"] == "complete"
    assert payload["lifecycle"]["stop_evidence"] == [{
        "evidence_uid": "00000000-0000-0000-0000-000000000003",
        "source_instance_id": "radius-source-7",
        "stream_id": "radius-accounting",
        "transport_binding": "windows-rpc-smb-readonly-tail-v1",
        "object_reference": "evidence:radius-3",
        "canonical_record_sha256": "a" * 64,
        "object_sha256": "b" * 64,
        "object_size_bytes": 123,
        "verified_at_utc": "2026-08-21T09:03:00Z",
    }]
    assert payload["lifecycle"]["incomplete_reason"] is None


def test_session_evidence_denial_does_not_touch_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        session_reporting,
        "_read_session_evidence_observations",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )

    payload = session_reporting.get_vpn_session_evidence(
        _audit_access(evidence=False),
        source_domain_id=7,
        session_row_id="radius-session-row:" + "a" * 64,
    )

    assert payload["state"] == "not_authorized"
    assert payload["observations"] == []


def test_session_evidence_route_delegates_exact_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_service(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {"state": "available"}

    monkeypatch.setattr(
        "server.api.routes.reports.get_vpn_session_evidence",
        fake_service,
    )

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            captured["payload"] = payload

    row_id = "radius-session-row:" + "a" * 64
    routes_reports._handle_vpn_session_evidence_api(FakeHandler(), {
        "domain_id": ["7"],
        "session_row_id": [row_id],
    })
    assert captured == {
        "access": {"server_built": True},
        "source_domain_id": 7,
        "session_row_id": row_id,
        "payload": {"state": "available"},
    }


def test_windows_authentication_routes_delegate_bounded_requests_and_preserve_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}
    report_payload = {
        "state": "available",
        "items": [
            {
                "event_db_id": 2,
                "evidence": {"event_record_id": 200},
                "source_native": {},
                "outcome": {"state": "unknown"},
            },
            {"event_db_id": 4, "evidence": {"event_record_id": 400}},
        ],
    }

    def fake_sources(access):
        captured["sources_access"] = access
        return {"state": "not_collected", "items": []}

    def fake_report(access, **kwargs):
        captured["report_access"] = access
        captured.update(kwargs)
        return report_payload

    monkeypatch.setattr(
        "server.api.routes.reports.get_windows_authentication_sources", fake_sources,
    )
    monkeypatch.setattr(
        "server.api.routes.reports.get_windows_authentication_report", fake_report,
    )

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            captured.setdefault("sent", []).append(payload)

    handler = FakeHandler()
    assert routes_reports.try_handle_get(
        handler, "/api/v1/reports/vpn.audit/windows-authentication-sources", {}
    ) is True
    assert routes_reports.try_handle_get(handler, "/api/v1/reports/vpn.audit/windows-authentication", {
        "domain_id": ["7"],
        "time_from": ["2026-08-21T10:00:00Z"],
        "time_to": ["2026-08-21T11:00:00Z"],
        "timezone": ["UTC"],
        "limit": ["12"],
    }) is True

    assert captured == {
        "sources_access": {"server_built": True},
        "report_access": {"server_built": True},
        "source_domain_id": 7,
        "time_from": "2026-08-21T10:00:00Z",
        "time_to": "2026-08-21T11:00:00Z",
        "timezone_name": "UTC",
        "limit": 12,
        "sent": [
            {"state": "not_collected", "items": []},
            {
                "state": "available",
                "items": [
                    {
                        "event_db_id": 2,
                        "evidence": {"event_record_id": 200},
                        "source_native": {},
                        "outcome": {"state": "unknown"},
                    },
                    {"event_db_id": 4, "evidence": {"event_record_id": 400}},
                ],
            },
        ],
    }


@pytest.mark.parametrize(("query", "error"), [
    (
        {"domain_id": ["7"], "time_from": ["2026-08-21T10:00:00Z"]},
        "windows_authentication_requires_time_bounds",
    ),
    (
        {
            "domain_id": ["7"],
            "time_from": ["2026-08-21T10:00:00Z"],
            "time_to": ["2026-08-21T11:00:00Z"],
            "limit": ["501"],
        },
        "windows_authentication_limit_invalid",
    ),
])
def test_windows_authentication_route_rejects_missing_bounds_or_invalid_limit(
    query: dict[str, list[str]],
    error: str,
) -> None:
    sent: list[tuple[dict, object]] = []

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            sent.append((payload, status))

    handler = FakeHandler()
    assert routes_reports.try_handle_get(
        handler, "/api/v1/reports/vpn.audit/windows-authentication", query
    ) is True

    assert sent == [
        ({"error": error}, routes_reports.HTTPStatus.BAD_REQUEST),
    ]


@pytest.mark.parametrize("payload", [
    {"state": "not_authorized", "items": []},
    {
        "state": "coverage_unverified",
        "items": [],
        "collection_coverage": {"state": "coverage_unverified"},
    },
    {
        "state": "empty_unverified",
        "items": [],
        "collection_coverage": {"state": "empty_unverified"},
    },
])
def test_windows_authentication_route_preserves_explicit_states(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict,
) -> None:
    monkeypatch.setattr(
        "server.api.routes.reports.get_windows_authentication_report",
        lambda *_args, **_kwargs: payload,
    )
    sent: list[tuple[dict, object]] = []

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, body, status=None):
            sent.append((body, status))

    assert routes_reports.try_handle_get(
        FakeHandler(), "/api/v1/reports/vpn.audit/windows-authentication", {
            "domain_id": ["7"],
            "time_from": ["2026-08-21T10:00:00Z"],
            "time_to": ["2026-08-21T11:00:00Z"],
        }
    ) is True

    assert sent == [(payload, None)]


def test_windows_authentication_route_denial_does_not_call_event_data_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        windows_authentication_reporting,
        "_read_windows_authentication_data",
        lambda **_kwargs: pytest.fail("event data must not be read"),
    )
    sent: list[tuple[dict, object]] = []
    denied_access = {
        "platform_owner": False,
        "capabilities": [],
        "capability_policies": [],
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [7]}}],
        }],
    }

    class FakeHandler:
        def _access_decision(self):
            return denied_access

        def _send_json(self, payload, status=None):
            sent.append((payload, status))

    assert routes_reports.try_handle_get(
        FakeHandler(), "/api/v1/reports/vpn.audit/windows-authentication", {
            "domain_id": ["7"],
            "time_from": ["2026-08-21T10:00:00Z"],
            "time_to": ["2026-08-21T11:00:00Z"],
        }
    ) is True

    assert sent[0][0]["state"] == "not_authorized"
    assert sent[0][1] is None


def _nps_event(
    event_db_id: int,
    minute: int,
    *,
    sid: str | None,
    source_ip: str | None,
    entity_id: int | None = None,
    alias_match_count: int = 0,
    event_id: int = 6273,
    correlation_id: str | None = None,
) -> dict:
    return {
        "event_db_id": event_db_id,
        "event_record_id": 10000 + event_db_id,
        "event_id": event_id,
        "time_created_utc": datetime(2026, 8, 21, 10, minute, tzinfo=UTC),
        "subject_user_sid": sid,
        "source_ip": source_ip,
        "entity_id": entity_id,
        "alias_match_count": alias_match_count,
        "reason_code": "16",
        "correlation_id": correlation_id,
        "source_core_sha256": b"c" * 32,
    }


def _nps_collection_coverage(
    *,
    history_event_count: int | None = None,
    history_event_present: bool | None = None,
    window_success_6272_count: int = 0,
    window_failed_6273_count: int = 0,
) -> dict:
    coverage = {
        "window_success_6272_count": window_success_6272_count,
        "window_failed_6273_count": window_failed_6273_count,
    }
    if history_event_count is not None:
        coverage["history_event_count"] = history_event_count
    if history_event_present is not None:
        coverage["history_event_present"] = history_event_present
    return coverage


def test_authorization_timeline_keeps_nps_facts_ordered_and_session_independent() -> None:
    payload = connections_reporting.compose_vpn_authorization_timeline(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            _nps_event(
                22, 2, sid="S-1-5-21-101", source_ip="198.51.100.7",
                entity_id=101, alias_match_count=1, event_id=6273,
                correlation_id="source-native-nps-id",
            ),
            _nps_event(11, 1, sid="S-1-5-21-102", source_ip="198.51.100.8", event_id=6272),
            _nps_event(21, 2, sid="S-1-5-21-103", source_ip=None, alias_match_count=2, event_id=6272),
        ],
        identities={101: {"entity_id": 101, "display_name": "Иванов", "netbios_name": "EXAMPLE", "sam_account_name": "ivanov"}},
        collection_coverage=_nps_collection_coverage(
            history_event_present=True,
            window_success_6272_count=2,
            window_failed_6273_count=1,
        ),
    )

    assert payload["state"] == "available"
    assert [(item["event_id"], item["event_db_id"]) for item in payload["items"]] == [(6272, 11), (6272, 21), (6273, 22)]
    allowed, ambiguous, denied = payload["items"]
    assert allowed["authorization_result"] == "allowed"
    assert "reason_code" not in allowed
    assert ambiguous["identity_state"] == "ambiguous"
    assert ambiguous["identity"]["observed_subject_sid"] == "S-1-5-21-103"
    assert denied["authorization_result"] == "denied"
    assert denied["reason_code"] == "16"
    assert denied["correlation_id"] == "source-native-nps-id"
    assert "session" not in str(payload).lower()


def test_authorization_timeline_empty_window_is_not_verified() -> None:
    payload = connections_reporting.compose_vpn_authorization_timeline(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[],
        identities={},
        collection_coverage=_nps_collection_coverage(history_event_present=True),
    )

    assert payload["state"] == "coverage_unverified"
    assert payload["items"] == []
    assert payload["collection_coverage"]["source_completeness"] == "not_proven"


def test_authorization_timeline_accepts_multiple_window_events_with_history_presence() -> None:
    payload = connections_reporting.compose_vpn_authorization_timeline(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=[
            _nps_event(1, 1, sid="S-1", source_ip="198.51.100.7", event_id=6272),
            _nps_event(2, 2, sid="S-2", source_ip="198.51.100.8", event_id=6272),
            _nps_event(3, 3, sid="S-3", source_ip="198.51.100.9", event_id=6273),
        ],
        identities={},
        collection_coverage=_nps_collection_coverage(
            history_event_count=1,
            history_event_present=True,
            window_success_6272_count=2,
            window_failed_6273_count=1,
        ),
    )

    assert payload["state"] == "available"
    assert payload["collection_coverage"]["history_event_present"] is True
    assert "history_event_count" not in payload["collection_coverage"]


def test_authorization_timeline_rejects_unbounded_input_and_out_of_window_event() -> None:
    period_start = datetime(2026, 8, 21, 10, tzinfo=UTC)
    period_end = datetime(2026, 8, 21, 11, tzinfo=UTC)
    outside = _nps_event(1, 1, sid="S-1", source_ip="198.51.100.7", event_id=6272)
    outside["time_created_utc"] = datetime(2026, 8, 21, 9, 59, tzinfo=UTC)

    with pytest.raises(ValueError, match="vpn_audit_authorization_timeline_event_outside_bounds"):
        connections_reporting.compose_vpn_authorization_timeline(
            source_domain_id=7,
            period_start=period_start,
            period_end=period_end,
            events=[outside],
            identities={},
            collection_coverage=_nps_collection_coverage(history_event_present=True),
        )
    with pytest.raises(ValueError, match="vpn_audit_authorization_timeline_input_bound_exceeded"):
        connections_reporting.compose_vpn_authorization_timeline(
            source_domain_id=7,
            period_start=period_start,
            period_end=period_end,
            events=[_nps_event(index, 1, sid="S-1", source_ip="198.51.100.7", event_id=6272)
                    for index in range(connections_reporting.MAX_AUTHORIZATION_TIMELINE_ROWS + 1)],
            identities={},
            collection_coverage=_nps_collection_coverage(
                history_event_present=True,
                window_success_6272_count=connections_reporting.MAX_AUTHORIZATION_TIMELINE_ROWS + 1,
            ),
        )


def test_authorization_timeline_requires_radius_capability_before_database_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        connections_reporting,
        "_read_vpn_authorization_timeline_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
        raising=False,
    )

    denied = connections_reporting.get_vpn_authorization_timeline(
        _audit_access(radius=False),
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )

    assert denied["state"] == "not_authorized"


def test_authorization_timeline_route_delegates_bounded_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_service(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {"state": "available"}

    monkeypatch.setattr(
        "server.api.routes.reports.get_vpn_authorization_timeline",
        fake_service,
        raising=False,
    )

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            captured["payload"] = payload

    routes_reports._handle_vpn_authorization_timeline_api(FakeHandler(), {
        "domain_id": ["7"],
        "time_from": ["2026-08-21T10:00:00Z"],
        "time_to": ["2026-08-21T11:00:00Z"],
        "timezone": ["UTC"],
    })

    assert captured == {
        "access": {"server_built": True},
        "source_domain_id": 7,
        "time_from": "2026-08-21T10:00:00Z",
        "time_to": "2026-08-21T11:00:00Z",
        "timezone_name": "UTC",
        "payload": {"state": "available"},
    }


def test_6273_series_keeps_identity_source_and_reference_bounds() -> None:
    events = [
        _nps_event(1, 1, sid="S-1-5-21-101", source_ip="198.51.100.7", entity_id=101, alias_match_count=1),
        _nps_event(2, 2, sid="S-1-5-21-101", source_ip="198.51.100.7", entity_id=101, alias_match_count=1),
        _nps_event(3, 3, sid="S-1-5-21-102", source_ip="198.51.100.7"),
        _nps_event(4, 4, sid="S-1-5-21-101", source_ip="198.51.100.8", entity_id=101, alias_match_count=1),
        _nps_event(5, 5, sid="S-1-5-21-101", source_ip=None, entity_id=101, alias_match_count=1),
        _nps_event(6, 6, sid="S-1-5-21-103", source_ip="198.51.100.7", alias_match_count=2),
    ]

    payload = connections_reporting.compose_vpn_failed_authorization_series(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=events,
        identities={101: {"entity_id": 101, "display_name": "Иванов", "netbios_name": "EXAMPLE", "sam_account_name": "ivanov"}},
        collection_coverage=_nps_collection_coverage(
            history_event_count=6,
            window_failed_6273_count=6,
        ),
        event_reference_limit=1,
    )

    items = payload["items"]
    assert len(items) == 5
    grouped = next(item for item in items if item["count"] == 2)
    assert grouped["identity_state"] == "resolved"
    assert grouped["source_ip"] == "198.51.100.7"
    assert grouped["event_references_truncated"] is True
    assert len(grouped["event_references"]) == 1
    assert all(item["time_bounds"] == payload["time_bounds"] for item in items)
    unresolved = next(item for item in items if item["identity_state"] == "unresolved")
    assert unresolved["identity"]["observed_subject_sid"] == "S-1-5-21-102"
    ambiguous = next(item for item in items if item["identity_state"] == "ambiguous")
    assert ambiguous["identity"]["observed_subject_sid"] == "S-1-5-21-103"
    missing_source = next(item for item in items if item["source_state"] == "unavailable")
    assert missing_source["count"] == 1
    assert "unknown" not in str(missing_source).lower()
    assert all(item["event_id"] == 6273 for item in items)
    forbidden = ("attack", "brute", "spray", "password")
    assert not any(token in str(payload).lower() for token in forbidden)


def test_6273_series_missing_identity_or_source_never_share_a_group() -> None:
    events = [
        _nps_event(1, 1, sid="S-1-5-21-101", source_ip=None, entity_id=101, alias_match_count=1),
        _nps_event(2, 2, sid="S-1-5-21-101", source_ip=None, entity_id=101, alias_match_count=1),
        _nps_event(3, 3, sid=None, source_ip="198.51.100.7"),
        _nps_event(4, 4, sid=None, source_ip="198.51.100.7"),
    ]

    payload = connections_reporting.compose_vpn_failed_authorization_series(
        source_domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
        events=events,
        identities={101: {"entity_id": 101, "display_name": "Иванов", "netbios_name": "EXAMPLE", "sam_account_name": "ivanov"}},
        collection_coverage=_nps_collection_coverage(
            history_event_count=4,
            window_failed_6273_count=4,
        ),
    )

    assert len(payload["items"]) == 4
    assert all(item["series_state"] == "single_event_unattributed" for item in payload["items"])
    assert all(item["count"] == 1 for item in payload["items"])
    assert sorted(
        item["event_references"][0]["event_db_id"]
        for item in payload["items"]
    ) == [1, 2, 3, 4]


def test_6273_series_collection_state_distinguishes_no_collection_from_unverified_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcomes = iter([
        (
            [],
            {},
            _nps_collection_coverage(history_event_count=0),
        ),
        (
            [],
            {},
            _nps_collection_coverage(
                history_event_count=3,
                window_success_6272_count=1,
            ),
        ),
        (
            [],
            {},
            _nps_collection_coverage(history_event_count=3),
        ),
    ])
    monkeypatch.setattr(
        connections_reporting,
        "_read_vpn_failed_authorization_series_data",
        lambda **_kwargs: next(outcomes),
    )

    not_collected = connections_reporting.get_vpn_failed_authorization_series(
        _audit_access(),
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )
    empty_with_nps_witness = connections_reporting.get_vpn_failed_authorization_series(
        _audit_access(),
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )
    coverage_unverified = connections_reporting.get_vpn_failed_authorization_series(
        _audit_access(),
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )

    assert not_collected["state"] == "not_collected"
    assert not_collected["collection_coverage"]["freshness"] == "not_asserted"
    assert empty_with_nps_witness["state"] == "empty_unverified"
    assert empty_with_nps_witness["items"] == []
    assert empty_with_nps_witness["collection_coverage"] == {
        "state": "empty_unverified",
        "history_event_count": 3,
        "window_success_6272_count": 1,
        "window_failed_6273_count": 0,
        "empty_window_basis": "durable_6272_nps_event",
        "source_completeness": "not_proven",
        "freshness": "not_asserted",
    }
    assert coverage_unverified["state"] == "coverage_unverified"
    assert coverage_unverified["collection_coverage"]["freshness"] == "not_asserted"


def test_6273_reader_establishes_one_repeatable_read_snapshot_before_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executed: list[str] = []

    class Cursor:
        def __init__(self, connection) -> None:
            self.connection = connection
            self.active_query = ""
            self.select_count = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params=None) -> None:
            normalized = " ".join(str(sql).split()).lower()
            executed.append(normalized)
            if normalized == "set transaction isolation level repeatable read, read only":
                self.connection.snapshot_established = True
                return
            if normalized.startswith("select"):
                assert self.connection.snapshot_established, (
                    "NPS events and coverage must share a repeatable-read snapshot"
                )
                self.select_count += 1
                self.active_query = (
                    "failed_events" if self.select_count == 1 else "coverage"
                )

        def fetchall(self):
            assert self.active_query == "failed_events"
            return [{
                "event_db_id": 1,
                "event_record_id": 10001,
                "event_id": 6273,
                "time_created_utc": datetime(2026, 8, 21, 10, 1, tzinfo=UTC),
                "subject_user_sid": "S-1-5-21-101",
                "source_ip": "198.51.100.7",
                "reason_code": "16",
                "alias_match_count": 0,
                "entity_id": None,
                "source_core_sha256": b"c" * 32,
            }]

        def fetchone(self):
            assert self.active_query == "coverage"
            return {
                "history_event_count": 1,
                "window_success_6272_count": 0,
                "window_failed_6273_count": 1,
            }

    class Connection:
        snapshot_established = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor(self)

    monkeypatch.setattr(connections_reporting, "_connect", lambda: Connection())

    events, identities, coverage = connections_reporting._read_vpn_failed_authorization_series_data(
        domain_id=7,
        period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
    )

    assert [event["event_id"] for event in events] == [6273]
    assert identities == {}
    assert coverage["window_failed_6273_count"] == 1
    assert executed[0] == "set transaction isolation level repeatable read, read only"
    assert len(executed) == 3


def test_6273_series_rejects_non_6273_input() -> None:
    with pytest.raises(ValueError, match="vpn_audit_failed_authorization_event_invalid"):
        connections_reporting.compose_vpn_failed_authorization_series(
            source_domain_id=7,
            period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
            period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
            events=[_nps_event(1, 1, sid="S-1", source_ip="198.51.100.7", event_id=6272)],
            identities={},
            collection_coverage=_nps_collection_coverage(
                history_event_count=1,
                window_failed_6273_count=1,
            ),
        )


def test_6273_series_rejects_events_outside_the_declared_window() -> None:
    event = _nps_event(1, 1, sid="S-1", source_ip="198.51.100.7")
    event["time_created_utc"] = datetime(2026, 8, 21, 9, 59, tzinfo=UTC)
    with pytest.raises(ValueError, match="vpn_audit_failed_authorization_event_outside_bounds"):
        connections_reporting.compose_vpn_failed_authorization_series(
            source_domain_id=7,
            period_start=datetime(2026, 8, 21, 10, tzinfo=UTC),
            period_end=datetime(2026, 8, 21, 11, tzinfo=UTC),
            events=[event],
            identities={},
            collection_coverage=_nps_collection_coverage(
                history_event_count=1,
                window_failed_6273_count=1,
            ),
        )


def test_audit_readers_keep_accounting_and_nps_boundaries_separate() -> None:
    accounting_reader = session_reporting._read_session_evidence_observations
    nps_reader = connections_reporting._read_vpn_failed_authorization_series_data
    timeline_reader = connections_reporting._read_vpn_authorization_timeline_data
    accounting_source = accounting_reader.__code__.co_consts
    nps_source = nps_reader.__code__.co_consts
    timeline_source = timeline_reader.__code__.co_consts
    assert any(
        "radius_vpn_session_evidence_observations_v1" in value
        for value in accounting_source
        if isinstance(value, str)
    )
    assert not any(
        "events_v2_core" in value
        for value in accounting_source
        if isinstance(value, str)
    )
    nps_sql = next(
        value for value in nps_source
        if isinstance(value, str) and "from events_v2_core event" in value
    )
    assert "event.event_id=6273" in nps_sql
    assert "event.event_id=6272" not in nps_sql
    assert "radius_accounting" not in nps_sql
    timeline_sql = next(
        value for value in timeline_source
        if isinstance(value, str) and "from events_v2_core event" in value
    )
    assert "event.event_id=any(%s)" in timeline_sql
    assert "from selected_events event" in timeline_sql
    assert "radius_accounting" not in timeline_sql
    coverage_sql = next(
        value for value in timeline_source
        if isinstance(value, str) and "history_event_present" in value
    )
    assert "exists(" in coverage_sql.lower()
    assert "count(*) as history_event_present" not in coverage_sql.lower()


def test_6273_series_denial_and_route_delegate_without_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        connections_reporting,
        "_read_vpn_failed_authorization_series_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )
    denied = connections_reporting.get_vpn_failed_authorization_series(
        {"platform_owner": False, "capabilities": [], "reports": []},
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )
    assert denied["state"] == "not_authorized"

    captured: dict = {}

    def fake_service(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {"state": "available"}

    monkeypatch.setattr(
        "server.api.routes.reports.get_vpn_failed_authorization_series",
        fake_service,
    )

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            captured["payload"] = payload

    routes_reports._handle_vpn_failed_authorization_series_api(FakeHandler(), {
        "domain_id": ["7"],
        "time_from": ["2026-08-21T10:00:00Z"],
        "time_to": ["2026-08-21T11:00:00Z"],
    })
    assert captured["access"] == {"server_built": True}
    assert captured["source_domain_id"] == 7
    assert captured["payload"] == {"state": "available"}


def test_6273_series_requires_radius_capability_before_database_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        connections_reporting,
        "_read_vpn_failed_authorization_series_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )

    denied = connections_reporting.get_vpn_failed_authorization_series(
        _audit_access(radius=False),
        source_domain_id=7,
        time_from="2026-08-21T10:00:00Z",
        time_to="2026-08-21T11:00:00Z",
    )

    assert denied["state"] == "not_authorized"

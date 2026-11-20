from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.api.routes import reports as routes_reports
from server.sli.reports import vpn_session_reporting as reporting


def _access(*, capability: bool, domain_id: int = 7) -> dict:
    return {
        "platform_owner": False,
        "capabilities": (
            ["vpn.sessions.view"] if capability else []
        ),
        "capability_policies": [],
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "allowed_actions": ["view"],
                "scope": {"kind": "domain", "ids": [domain_id]},
            }],
        }],
    }


def test_denied_branch_does_not_read_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_session_projection",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )
    payload = reporting.get_vpn_session_report(
        _access(capability=False),
        source_domain_id=7,
    )
    assert payload["state"] == "not_authorized"
    assert payload["coverage"] is None
    assert payload["items"] == []


def test_old_unresolved_corpus_is_not_reported_as_zero_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_session_projection",
        lambda **_kwargs: ({
            "domain_id": 7,
            "total_delivery_count": 15,
            "queued_delivery_count": 0,
            "leased_delivery_count": 0,
            "failed_delivery_count": 0,
            "delivered_delivery_count": 15,
            "quarantined_delivery_count": 0,
            "projected_receipt_count": 0,
            "identity_unresolved_count": 15,
            "timestamp_unresolved_count": 0,
            "projected_session_count": 0,
            "history_available_from_utc": datetime(
                2026, 7, 30, tzinfo=timezone.utc
            ),
            "history_available_to_utc": datetime(
                2026, 7, 30, 1, tzinfo=timezone.utc
            ),
        }, []),
    )
    payload = reporting.get_vpn_session_report(
        _access(capability=True),
        source_domain_id=7,
    )
    assert payload["state"] == "identity_incomplete"
    assert payload["coverage"]["identity_unresolved_count"] == 15
    assert payload["coverage"]["projected_session_count"] == 0


def test_projection_is_domain_scoped_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_read(**kwargs):
        captured.update(kwargs)
        coverage = {
            "domain_id": 7,
            "total_delivery_count": 2,
            "queued_delivery_count": 0,
            "leased_delivery_count": 0,
            "failed_delivery_count": 0,
            "delivered_delivery_count": 2,
            "quarantined_delivery_count": 0,
            "projected_receipt_count": 2,
            "identity_unresolved_count": 0,
            "timestamp_unresolved_count": 0,
            "projected_session_count": 1,
            "history_available_from_utc": None,
            "history_available_to_utc": None,
        }
        rows = [{
            "session_row_id": "radius-session-row:" + ("a" * 64),
            "entity_id": 101,
            "domain_id": 7,
            "last_observed_at_utc": datetime(
                2026, 7, 30, tzinfo=timezone.utc
            ),
            "anomalies": (),
        }]
        return coverage, rows

    monkeypatch.setattr(
        reporting,
        "_read_session_projection",
        fake_read,
    )
    payload = reporting.get_vpn_session_report(
        _access(capability=True),
        source_domain_id=7,
        limit=25,
        offset=5,
        time_from="2026-07-01",
        time_to="2026-08-01",
    )
    assert captured["domain_id"] == 7
    assert captured["limit"] == 25
    assert captured["offset"] == 5
    assert payload["state"] == "available"
    assert payload["items"][0]["entity_id"] == 101
    assert "exact_principal_key" not in payload["items"][0]
    assert "session_identity_key" not in payload["items"][0]


def test_unregistered_domain_and_bounds_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_session_projection",
        lambda **_kwargs: (None, []),
    )
    with pytest.raises(
        ValueError,
        match="vpn_session_source_domain_not_registered",
    ):
        reporting.get_vpn_session_report(
            _access(capability=True),
            source_domain_id=7,
        )
    with pytest.raises(ValueError, match="vpn_session_limit_invalid"):
        reporting.get_vpn_session_report(
            _access(capability=True),
            source_domain_id=7,
            limit=201,
        )


def test_source_discovery_filters_every_domain_by_server_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_session_source_domain_batch",
        lambda **_kwargs: [7, 8],
    )
    payload = reporting.get_vpn_session_sources(
        _access(capability=True, domain_id=7)
    )
    assert payload["state"] == "available"
    assert payload["items"] == [{"source_domain_id": 7}]
    assert payload["bounded"] is True


def test_source_discovery_does_not_turn_denial_into_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_session_source_domain_batch",
        lambda **_kwargs: [7],
    )
    payload = reporting.get_vpn_session_sources(_access(capability=False))
    assert payload["state"] == "not_authorized"
    assert payload["items"] == []
    assert payload["has_more"] is False


def test_source_discovery_filters_before_bounded_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_session_source_domain_batch",
        lambda **_kwargs: list(range(1, 103)),
    )
    payload = reporting.get_vpn_session_sources(
        _access(capability=True, domain_id=102)
    )
    assert payload["state"] == "available"
    assert payload["items"] == [{"source_domain_id": 102}]
    assert payload["has_more"] is False


def test_source_discovery_pages_until_authorized_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def fake_batch(*, after_domain_id: int, limit: int) -> list[int]:
        calls.append(after_domain_id)
        assert limit == reporting.DISCOVERY_BATCH_LIMIT
        if after_domain_id == 0:
            return list(range(1, 257))
        if after_domain_id == 256:
            return [257]
        return []

    monkeypatch.setattr(
        reporting,
        "_read_session_source_domain_batch",
        fake_batch,
    )
    payload = reporting.get_vpn_session_sources(
        _access(capability=True, domain_id=257)
    )
    assert payload["items"] == [{"source_domain_id": 257}]
    assert calls == [0, 256]


@pytest.mark.parametrize(
    ("plugin_state", "read_only"),
    [("enabled", False), ("disabled", True), ("unknown", True)],
)
def test_http_handler_passes_server_access_and_exact_domain(
    monkeypatch: pytest.MonkeyPatch,
    plugin_state: str,
    read_only: bool,
) -> None:
    sent: list[tuple[dict, object]] = []
    captured: dict = {}
    plugin = {
        "plugin_id": "sli.remote-access",
        "state": plugin_state,
        "read_only": read_only,
    }

    def fake_report(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {"state": "identity_incomplete"}

    monkeypatch.setattr(
        "server.api.routes.reports.get_vpn_session_report",
        fake_report,
    )

    def fake_plugin_state(report_key):
        captured["report_key"] = report_key
        return plugin

    monkeypatch.setattr(routes_reports, "report_plugin_state", fake_plugin_state)

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            sent.append((payload, status))

    routes_reports._handle_vpn_session_report_api(FakeHandler(), {
        "domain_id": ["7"],
        "limit": ["25"],
    })
    assert captured["access"] == {"server_built": True}
    assert captured["source_domain_id"] == 7
    assert captured["limit"] == 25
    assert captured["report_key"] == "vpn.audit"
    assert sent == [({"state": "identity_incomplete", "plugin": plugin}, None)]


def test_http_source_handler_uses_server_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[dict] = []
    monkeypatch.setattr(
        "server.api.routes.reports.get_vpn_session_sources",
        lambda access: {"access": access},
    )

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            sent.append(payload)

    routes_reports._handle_vpn_session_sources_api(FakeHandler())
    assert sent == [{"access": {"server_built": True}}]

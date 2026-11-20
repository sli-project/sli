from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from server.sli.events.event_catalog import (
    lookup_event_catalog,
    lookup_semantic_event_descriptor,
)
from server.sli.events.event_catalog_quality import validate_catalog_data
from server.sli.semantic.semantic_processing import StoredEvent, normalize_windows_event
from server.sli.semantic.semantic_producer import select_semantic_queue_candidates
from server.source_packs.registry import (
    catalog_paths_for_event,
    get_source_pack,
    resolve_source_normalizer,
    resolve_source_pack,
)


PROVIDER = "Microsoft-Windows-Security-Auditing"


def _event(windows_event_id: int, *, provider: str = PROVIDER) -> StoredEvent:
    return StoredEvent(
        event_id=3400 + windows_event_id,
        windows_event_id=windows_event_id,
        channel="Security",
        server="NPS01",
        occurred_at_utc=datetime(2026, 7, 30, 1, 30, tzinfo=timezone.utc),
        event_data={
            "SubjectUserSid": "S-1-5-21-100000003-200000003-300000003-1101",
            "SubjectUserName": "sample.user",
            "SubjectDomainName": "EXAMPLE",
            "AccountSessionIdentifier": "RADIUS-SESSION-001",
            "CallingStationID": "192.0.2.10",
            "AuthenticationType": "MS-CHAP-v2",
            "NetworkPolicyName": "VPN users",
            "NASIdentifier": "VPN-GW-01",
            "ReasonCode": "16",
        },
        provider=provider,
        source_host_id=32,
    )


def test_radius_catalog_is_valid_source_only_descriptor() -> None:
    path = Path("config/radius_event_catalog.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert validate_catalog_data(data) == {
        "valid": True,
        "entry_count": 2,
        "errors": [],
    }
    pack = get_source_pack("sli.windows.vpn-radius")
    assert pack is not None
    assert pack.channels == ("Security",)
    assert pack.catalog_path == path.resolve()
    assert pack.normalizer_id == "windows-nps-radius-v1"


def test_shared_security_stream_routes_by_exact_event_identity() -> None:
    assert (
        resolve_source_pack("Security", PROVIDER, "4624").pack_id
        == "sli.windows.ad-dc"
    )
    assert (
        resolve_source_pack("Security", PROVIDER, "6272").pack_id
        == "sli.windows.vpn-radius"
    )
    assert (
        resolve_source_pack("Security", PROVIDER, "6273").pack_id
        == "sli.windows.vpn-radius"
    )
    assert resolve_source_pack("Security", "Wrong-Provider", "6272") is None
    assert resolve_source_pack("Security", PROVIDER, "999999") is None
    assert (
        resolve_source_normalizer("Security").normalizer_id
        == "windows-ad-dc-v1"
    )


def test_radius_catalog_and_provider_guards_fail_closed() -> None:
    radius_path = Path("config/radius_event_catalog.json").resolve()
    assert catalog_paths_for_event("Security", PROVIDER, "6272")[0] == radius_path
    assert lookup_event_catalog(6272, "Security", PROVIDER)["source"] == (
        "sli.windows.vpn-radius"
    )
    assert lookup_event_catalog(6273, "Security", PROVIDER)["noise_class"] == (
        "signal"
    )
    assert lookup_event_catalog(6272, "Security", "Wrong-Provider") is None
    assert lookup_semantic_event_descriptor(
        "sli.windows.vpn-radius",
        "Security",
        "6272",
        "Wrong-Provider",
    ) is None


def test_radius_normalization_observes_decision_but_never_claims_session() -> None:
    allowed = normalize_windows_event(_event(6272))
    denied = normalize_windows_event(_event(6273))

    assert allowed.semantic_type == "remote_access.authentication.allowed"
    assert denied.semantic_type == "remote_access.authentication.denied"
    assert allowed.facts["session_evidence"] == (
        "nps_decision_only_accounting_required"
    )
    assert denied.facts["decision"] == "denied"
    assert allowed.quality["vpn_session_confirmed"] is False
    assert denied.quality["vpn_session_confirmed"] is False
    assert allowed.roles["session_principal"].endswith(
        ":nps:radius-session-001"
    )


def test_radius_wrong_provider_and_unknown_event_never_borrow_dc_semantics() -> None:
    wrong_provider = normalize_windows_event(_event(6272, provider="Wrong-Provider"))
    unknown_event = normalize_windows_event(_event(6999))
    assert wrong_provider.semantic_type == "event.unknown"
    assert unknown_event.semantic_type == "event.unknown"
    assert wrong_provider.quality["unknown_event_mapping"] is True
    assert unknown_event.quality["unknown_event_mapping"] is True


def test_semantic_prequeue_uses_radius_noise_class_without_publishing() -> None:
    selected, counters = select_semantic_queue_candidates(
        [
            {
                "source_event_id": 1,
                "stream": "Security",
                "provider_name": PROVIDER,
                "event_key": "6272",
            },
            {
                "source_event_id": 2,
                "stream": "Security",
                "provider_name": PROVIDER,
                "event_key": "6273",
            },
            {
                "source_event_id": 3,
                "stream": "Security",
                "provider_name": "Wrong-Provider",
                "event_key": "6273",
            },
        ]
    )
    assert [(item.source_event_id, item.selection_reason) for item in selected] == [
        (2, "signal"),
        (3, "descriptor_missing"),
    ]
    assert counters == {
        "scanned": 3,
        "signal_queued": 1,
        "unknown_queued": 1,
        "unknown_suppressed": 0,
        "context_skipped": 1,
        "noise_skipped": 0,
    }

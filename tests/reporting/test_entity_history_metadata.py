from __future__ import annotations

from datetime import datetime, timezone

import pytest


def _candidate(event_db_id: int) -> dict[str, object]:
    return {
        "event_db_id": event_db_id,
        "time_created_utc": f"2026-09-10T00:00:{event_db_id % 60:02d}Z",
        "server_id": 7,
        "domain_id": 1,
        "channel": "Security",
    }


def _metadata(event_db_id: int, *, event_id: int = 4624) -> dict[str, object]:
    return {
        "event_db_id": event_db_id,
        "event_id": event_id,
        "time_created_utc": f"2026-09-10T00:00:{event_db_id % 60:02d}Z",
        "server": "dc1.example.invalid",
        "channel": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "subject_user_name": "operator",
        "target_user_name": "alice",
        "ip_address": "192.0.2.24",
        "workstation_name": "ws-01",
    }


def _v2_route(**_kwargs):
    return {"route": "v2"}


def test_entity_history_uses_bounded_retained_metadata_for_100_sparse_exact_ids(monkeypatch) -> None:
    """A sparse entity history must not turn 100 exact IDs into an archive range scan."""
    from server.sli.reporting import ui_workspace

    candidates = [_candidate(event_db_id) for event_db_id in range(9000, 8900, -1)]
    calls: list[dict[str, object]] = []

    def evidence_rows(**kwargs):
        calls.append(kwargs)
        if kwargs.get("id_only"):
            return candidates
        assert kwargs["event_db_ids"] == [row["event_db_id"] for row in candidates]
        return [_metadata(int(row["event_db_id"])) for row in candidates]

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    monkeypatch.setattr(
        ui_workspace,
        "get_event_details_by_ids",
        lambda *_args, **_kwargs: pytest.fail("entity history must not hydrate archive payloads"),
    )

    result = ui_workspace.get_investigations_workspace_data(
        q=None,
        entity_id=5632,
        entity_evidence_allowed=lambda _event_db_id: True,
    )

    assert {item["event_db_id"] for item in result["timeline"]} == {row["event_db_id"] for row in candidates}
    assert result["summary"]["events_returned"] == 100
    assert result["summary"]["has_more"] is False
    assert [bool(call.get("id_only")) for call in calls] == [True, False]


def test_entity_history_legacy_metadata_read_stays_at_public_limit(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    candidates = [_candidate(event_db_id) for event_db_id in range(9101, 9000, -1)]
    metadata_requests: list[list[int]] = []

    def evidence_rows(**kwargs):
        if kwargs.get("id_only"):
            return candidates
        selected = list(kwargs["event_db_ids"])
        metadata_requests.append(selected)
        return [_metadata(event_db_id) for event_db_id in selected]

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)

    result = ui_workspace.get_investigations_workspace_data(
        q=None,
        entity_id=5632,
        entity_evidence_allowed=lambda _event_db_id: True,
    )

    assert len(metadata_requests[0]) == ui_workspace.INVESTIGATION_TIMELINE_LIMIT
    assert result["summary"]["events_returned"] == ui_workspace.INVESTIGATION_TIMELINE_LIMIT
    assert result["summary"]["has_more"] is True


def test_entity_history_authorizes_each_id_before_metadata_read(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    candidates = [_candidate(73), _candidate(72), _candidate(71)]
    authorized: list[int] = []
    metadata_requests: list[list[int]] = []

    def evidence_rows(**kwargs):
        if kwargs.get("id_only"):
            return candidates
        selected = list(kwargs["event_db_ids"])
        metadata_requests.append(selected)
        return [_metadata(event_db_id) for event_db_id in selected]

    def allowed(event_db_id: int) -> bool:
        authorized.append(event_db_id)
        return event_db_id != 72

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    monkeypatch.setattr(
        ui_workspace,
        "get_event_details_by_ids",
        lambda *_args, **_kwargs: pytest.fail("metadata read must replace archive hydration"),
    )

    result = ui_workspace.get_investigations_workspace_data(
        q=None,
        entity_id=5632,
        entity_evidence_allowed=allowed,
    )

    assert authorized == [73, 72, 71]
    assert metadata_requests == [[73, 71]]
    assert [item["event_db_id"] for item in result["timeline"]] == [73, 71]


def test_entity_history_missing_authorized_metadata_is_unavailable(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    def evidence_rows(**kwargs):
        if kwargs.get("id_only"):
            return [_candidate(41), _candidate(40)]
        return [_metadata(41)]

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    monkeypatch.setattr(
        ui_workspace,
        "get_event_details_by_ids",
        lambda *_args, **_kwargs: pytest.fail("metadata failure must not fall back to archive hydration"),
    )

    with pytest.raises(ui_workspace.EntityEvidenceLookupError, match="unavailable"):
        ui_workspace.get_investigations_workspace_data(
            q=None,
            entity_id=5632,
            entity_evidence_allowed=lambda _event_db_id: True,
        )


def test_entity_history_metadata_timeout_is_unavailable(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace
    from server.sli.core.database import QueryTimeoutError

    def evidence_rows(**kwargs):
        if kwargs.get("id_only"):
            return [_candidate(41)]
        raise QueryTimeoutError("metadata query cancelled", timeout_ms=3000)

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    monkeypatch.setattr(
        ui_workspace,
        "get_event_details_by_ids",
        lambda *_args, **_kwargs: pytest.fail("timeout must not fall back to archive hydration"),
    )

    with pytest.raises(ui_workspace.EntityEvidenceLookupError, match="unavailable"):
        ui_workspace.get_investigations_workspace_data(
            q=None,
            entity_id=5632,
            entity_evidence_allowed=lambda _event_db_id: True,
        )


def test_entity_history_unknown_metadata_has_no_invented_risk_or_card_fields(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    def evidence_rows(**kwargs):
        if kwargs.get("id_only"):
            return [_candidate(99)]
        return [_metadata(99, event_id=999999)]

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    monkeypatch.setattr(
        ui_workspace,
        "get_event_details_by_ids",
        lambda *_args, **_kwargs: pytest.fail("metadata must not hydrate archive payloads"),
    )
    monkeypatch.setattr(
        ui_workspace,
        "build_event_card",
        lambda _item: pytest.fail("metadata-only history must not build a full event card"),
    )

    result = ui_workspace.get_investigations_workspace_data(
        q=None,
        entity_id=5632,
        entity_evidence_allowed=lambda _event_db_id: True,
    )

    item = result["timeline"][0]
    assert item["event_db_id"] == 99
    assert item["title"] == "Event ID 999999"
    assert item["catalogued"] is False
    assert item["severity"] == "unknown"
    assert item["base_risk"] == "unknown"
    assert item["confidence"] == "unknown"
    assert item["assessment_confidence"] == "unknown"
    assert item["summary"] is None
    assert item["actor"] == "operator"
    assert item["target"] == "alice"


def test_entity_history_security_projection_reads_only_exact_catalog_identity(monkeypatch) -> None:
    """Security history may read provider identity, but not link role/confidence."""
    from server.sli.reporting import ui_workspace

    captured: dict[str, str] = {}
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        ui_workspace,
        "query_rows_bounded",
        lambda sql, *_args, **_kwargs: captured.setdefault("sql", sql) and [],
    )

    assert ui_workspace._get_entity_evidence_event_rows(
        entity_id=5632,
        limit=1,
        before_time_utc=None,
        before_event_db_id=None,
        event_db_ids=[99],
        field_projection="security_history",
    ) == []

    sql = " ".join(captured["sql"].lower().split())
    assert "select distinct event.id as event_db_id" in sql
    assert "event.id as event_db_id" in sql
    assert "event.event_id" in sql
    assert "event.time_created_utc" in sql
    assert "event.subject_user_name" in sql
    assert "event.target_user_name" in sql
    assert "left join storage_v2_provider provider on provider.id = event.provider_id" in sql
    assert "storage_v2_role" not in sql
    assert "block.role_ids" not in sql
    assert "provider.value as provider_name" in sql
    assert "role.value" not in sql
    assert "link_role" not in sql
    assert "confidence" not in sql


def test_entity_history_direct_metadata_reads_only_preauthorized_exact_ids(monkeypatch) -> None:
    """Alias-backed candidates may hydrate metadata only after per-event admission."""
    from server.sli.reporting import ui_workspace

    captured: dict[str, object] = {}
    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)

    def bounded(sql, params, **_kwargs):
        captured.update(sql=sql, params=params)
        return []

    monkeypatch.setattr(ui_workspace, "query_rows_bounded", bounded)

    assert ui_workspace._get_entity_evidence_event_rows(
        entity_id=5632,
        limit=2,
        before_time_utc=None,
        before_event_db_id=None,
        event_db_ids=[99, 98],
        field_projection="security_history",
        preauthorized_exact_event_ids=True,
    ) == []

    sql = " ".join(str(captured["sql"]).lower().split())
    assert "from events_v2_core event" in sql
    assert "event_entity_link_blocks_v2" not in sql
    assert "event.id = any(?)" in sql
    assert "provider.value as provider_name" in sql
    assert "left join storage_v2_provider provider on provider.id = event.provider_id" in sql
    assert "event.event_data" not in sql
    assert "raw_xml" not in sql
    assert captured["params"] == ([99, 98], 2)


def test_entity_history_denied_alias_candidate_never_reaches_metadata(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(
        ui_workspace,
        "_get_entity_evidence_event_rows",
        lambda **kwargs: (
            [] if kwargs.get("id_only")
            else pytest.fail("denied alias evidence reached metadata read")
        ),
    )

    result = (
        ui_workspace.get_investigations_workspace_data(
            q=None,
            entity_id=5632,
            time_from="2026-09-10T00:00:00.123001Z",
            time_to="2026-09-11T00:00:00.123999Z",
            timezone_name="UTC",
            entity_evidence_allowed=lambda _event_db_id: False,
            entity_security_event_candidates=lambda **_kwargs: {
                "state": "available", "has_more": False,
                "items": [{
                    "event_db_id": 99,
                    "time_created_utc": "2026-09-10T01:00:00.123456Z",
                }],
            },
        )
    )

    # Недоступное доказательство не раскрывается: честная пустая история, а не 404.
    assert result["state"] == "ok"
    assert result["timeline"] == []
    assert result["summary"]["events_returned"] == 0
    assert result["context"]["entity_id"] == 5632


def test_entity_history_without_any_evidence_is_empty_not_error(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    result = ui_workspace.get_investigations_workspace_data(
        q=None,
        entity_id=5632,
        time_from="2026-09-10T00:00:00Z",
        time_to="2026-09-11T00:00:00Z",
        timezone_name="UTC",
        entity_evidence_allowed=lambda _event_db_id: True,
        entity_security_event_candidates=lambda **_kwargs: {
            "state": "available", "has_more": False, "items": [],
        },
    )

    assert result["state"] == "ok" and result["timeline"] == []


def test_entity_history_uses_security_owner_candidates_and_sorts_after_authorization(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    requested: list[int] = []

    def evidence_rows(**kwargs):
        if kwargs.get("id_only"):
            pytest.fail("bounded runtime path must use the security owner's exact predicate")
        requested.extend(kwargs["event_db_ids"])
        times = {
            10: datetime(2026, 9, 10, 2, tzinfo=timezone.utc),
            12: "2026-09-10T01:00:00Z",
            11: datetime(2026, 9, 10, 0),
        }
        return [{**_metadata(event_db_id), "time_created_utc": times[event_db_id]} for event_db_id in requested]

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)

    result = ui_workspace.get_investigations_workspace_data(
        q=None,
        entity_id=5632,
        time_from="2026-09-10T00:00:00Z",
        time_to="2026-09-11T00:00:00Z",
        timezone_name="UTC",
        entity_evidence_allowed=lambda _event_db_id: True,
        entity_security_event_candidates=lambda **_kwargs: {
            "state": "available", "has_more": False,
            "items": [
                {"event_db_id": 10},
                {"event_db_id": 12},
                {"event_db_id": 11},
            ],
        },
    )

    assert requested == [10, 12, 11]
    assert [item["event_db_id"] for item in result["timeline"]] == [10, 12, 11]
    assert all("SID" in item["inclusion_reason"] for item in result["timeline"])


def test_entity_security_history_has_more_does_not_reveal_denied_candidates(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(
        ui_workspace,
        "_get_entity_evidence_event_rows",
        lambda **kwargs: (
            [_metadata(1)] if not kwargs.get("id_only")
            else pytest.fail("bounded runtime path must not read canonical candidates")
        ),
    )

    result = ui_workspace.get_investigations_workspace_data(
        q=None,
        entity_id=5632,
        time_from="2026-09-10T00:00:00Z",
        time_to="2026-09-11T00:00:00Z",
        timezone_name="UTC",
        entity_evidence_allowed=lambda event_db_id: event_db_id == 1,
        entity_security_event_candidates=lambda **_kwargs: {
            "state": "available",
            "has_more": True,
            "items": [{"event_db_id": event_db_id} for event_db_id in range(1, 102)],
        },
    )

    assert [item["event_db_id"] for item in result["timeline"]] == [1]
    assert result["summary"]["has_more"] is False


@pytest.mark.parametrize(
    ("event_id", "expected_title", "expected_category"),
    [
        (4624, "Успешный вход", "authentication"),
        (4740, "Блокировка учетной записи", "account_management"),
    ],
)
def test_entity_history_catalogues_known_exact_provider_without_exposing_it(
    monkeypatch,
    event_id: int,
    expected_title: str,
    expected_category: str,
) -> None:
    from server.sli.reporting import ui_workspace

    def evidence_rows(**kwargs):
        if kwargs.get("id_only"):
            return [_candidate(99)]
        return [_metadata(99, event_id=event_id)]

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    monkeypatch.setattr(
        ui_workspace,
        "build_event_card",
        lambda _item: pytest.fail("metadata-only history must not build a full event card"),
    )

    result = ui_workspace.get_investigations_workspace_data(
        q=None,
        entity_id=5632,
        entity_evidence_allowed=lambda _event_db_id: True,
    )

    item = result["timeline"][0]
    assert item["title"] == expected_title
    assert item["category"] == expected_category
    assert item["catalogued"] is True
    assert item["severity"] == "unknown"
    assert "provider_name" not in item


def test_entity_history_security_metadata_skips_catalog_without_provider(monkeypatch) -> None:
    """Without provider access, metadata history remains explicitly uncatalogued."""
    from server.sli.reporting import ui_workspace

    metadata_calls: list[dict[str, object]] = []

    def evidence_rows(**kwargs):
        if kwargs.get("id_only"):
            return [_candidate(99)]
        metadata_calls.append(kwargs)
        return [{
            "event_db_id": 99,
            "event_id": 4624,
            "time_created_utc": "2026-09-10T00:00:39Z",
            "server": "dc1.example.invalid",
            "channel": "Security",
            "subject_user_name": "operator",
            "target_user_name": "alice",
        }]

    monkeypatch.setattr(ui_workspace, "resolve_storage_route", _v2_route)
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", evidence_rows)
    monkeypatch.setattr(
        ui_workspace,
        "lookup_event_catalog",
        lambda *_args, **_kwargs: pytest.fail("security history must not catalog without provider"),
    )
    monkeypatch.setattr(
        ui_workspace,
        "build_event_card",
        lambda _item: pytest.fail("metadata-only history must not build a full event card"),
    )

    result = ui_workspace.get_investigations_workspace_data(
        q=None,
        entity_id=5632,
        entity_evidence_allowed=lambda _event_db_id: True,
    )

    assert [call["field_projection"] for call in metadata_calls] == ["security_history"]
    item = result["timeline"][0]
    assert item["title"] == "Event ID 4624"
    assert item["catalogued"] is False
    assert item["severity"] == "unknown"
    assert item["actor"] == "operator"
    assert item["target"] == "alice"

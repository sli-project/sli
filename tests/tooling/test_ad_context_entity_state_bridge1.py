from __future__ import annotations

import pytest


@pytest.mark.parametrize("requested,expected", [(-1, 1), (1, 1), (50, 50), (100, 100), (999, 100)])
def test_history_read_keeps_global_limit_and_exact_id_in_each_branch(monkeypatch, requested, expected):
    from server.ad_context import integration

    calls = []
    monkeypatch.setattr(integration, "query_rows_bounded", lambda sql, params, **kwargs: calls.append(params) or [])
    result = integration.get_entity_context_evidence(42, limit=requested)
    assert calls == [(42, 42, 42, 42, 42, 42, 42, expected)]
    assert result["returned_count"] == 0
    assert result["limit"] == expected


def test_bridge_query_is_exact_bounded_parameterized_and_read_only(monkeypatch) -> None:
    from server.ad_context import integration

    calls = []
    monkeypatch.setattr(
        integration,
        "query_rows_bounded",
        lambda sql, params, **kwargs: calls.append((sql, params, kwargs)) or [],
    )
    result = integration.get_entity_context_evidence(42, limit=999)
    assert result["items"] == []
    assert result["limit"] == 100
    assert result["absence_closes_state"] is False
    sql, params, kwargs = calls[0]
    normalized = " ".join(sql.lower().split())
    assert "from ad_context_entity_versions where entity_id=?" in normalized
    assert "from ad_context_relation_versions where source_entity_id=? or target_entity_id=?" in normalized
    assert "limit ?" in normalized
    assert "version.last_observed_at_utc" in normalized
    assert "relation.last_observed_at_utc" in normalized
    # Apply version priority before LIMIT so old observations cannot displace current ones.
    assert "order by current desc, last_observed_at_utc desc, observed_at_utc desc, context_evidence_id desc limit ?" in normalized
    assert params == (42, 42, 42, 42, 42, 42, 42, 100)
    assert kwargs["statement_timeout_ms"] == 5000
    # Keep the version prefix visible across the subquery boundary. Recomputing
    # it outside loses Incremental Sort and probes every historical evidence row.
    assert normalized.count("select *, (valid_to_utc is null) as current") == 2
    assert "version.current" in normalized and "relation.current" in normalized
    prefix = "order by (valid_to_utc is null) desc, last_observed_at_utc desc offset 0"
    assert normalized.count(prefix) == 2
    branches = normalized.split(" union all ")
    assert len(branches) == 2
    for branch in branches:
        # Both per-version observations and each UNION arm have a safe top-100
        # cap, after matching/filtering and the original complete sort order.
        assert "order by evidence.observed_at_utc desc, evidence.id desc limit 100 ) evidence on true" in branch
        assert "order by current desc, last_observed_at_utc desc, observed_at_utc desc, context_evidence_id desc limit 100 )" in branch
        assert branch.count("limit 100") == 2
    assert integration.MAX_CONTEXT_EVIDENCE == 100
    # A flattened join to the active view can scan/sort the entire identity
    # spine. Keep each participant lookup correlated and bounded by its PK.
    for participant, entity_id in (
        ("current_entity", "version.entity_id"),
        ("source_entity", "relation.source_entity_id"),
        ("target_entity", "relation.target_entity_id"),
    ):
        assert (
            "join lateral ( select display_name from entities_v2_active "
            f"where id={entity_id} limit 1 ) {participant} on true"
        ) in normalized
    for forbidden in (" insert ", " update ", " delete ", " alter ", " drop "):
        assert forbidden not in f" {normalized} "


def test_bridge_returns_current_names_for_exact_relation_participants(monkeypatch) -> None:
    from server.ad_context import integration

    monkeypatch.setattr(integration, "query_rows_bounded", lambda *_args, **_kwargs: [{
        "context_evidence_id": 9,
        "evidence_type": "relation_observation",
        "source_pack_id": "sli.windows.ad-context",
        "source_run_id": "run-1",
        "observed_at_utc": "2026-09-11T10:00:00Z",
        "integrity_sha256": "a" * 64,
        "context_kind": "relation",
        "subject_entity_id": 42,
        "subject_display_name": "evidence-reader",
        "related_entity_id": 77,
        "related_display_name": "VPNl2tp",
        "valid_from_utc": "2026-09-11T10:00:00Z",
        "valid_to_utc": None,
        "source_section": "vpn_membership",
        "attributes_json": {"membership_type": "direct"},
    }])

    [item] = integration.get_entity_context_evidence(42)["items"]

    assert item["subject_display_name"] == "evidence-reader"
    assert item["related_display_name"] == "VPNl2tp"
    assert item["current"] is True


def test_bridge_preserves_version_dates_attributes_and_evidence_provenance(monkeypatch) -> None:
    from server.ad_context import integration

    current = {
        "context_evidence_id": 10,
        "evidence_type": "entity_observation",
        "source_pack_id": "test-pack",
        "source_run_id": "test-run",
        "observed_at_utc": "2026-09-01T10:00:00Z",
        "last_observed_at_utc": "2026-09-11T10:00:00Z",
        "context_kind": "entity",
        "subject_entity_id": 42,
        "valid_from_utc": "2026-09-01T10:00:00Z",
        "valid_to_utc": None,
        "source_section": "directory_accounts",
        "attributes_json": {"attributes": {"enabled": False, "password_never_expires": False}},
    }
    historical = {
        **current,
        "context_evidence_id": 9,
        "observed_at_utc": "2026-08-01T10:00:00Z",
        "last_observed_at_utc": "2026-08-11T10:00:00Z",
        "valid_to_utc": "2026-09-01T10:00:00Z",
        "attributes_json": {"attributes": {"enabled": True}},
    }
    monkeypatch.setattr(integration, "query_rows_bounded", lambda *_args, **_kwargs: [current, historical])

    latest, previous = integration.get_entity_context_evidence(42)["items"]

    assert latest["current"] is True
    assert previous["current"] is False
    assert latest["observed_at_utc"] == current["observed_at_utc"]
    assert latest["last_observed_at_utc"] == current["last_observed_at_utc"]
    assert previous["last_observed_at_utc"] == historical["last_observed_at_utc"]
    for key in ("source_pack_id", "source_run_id", "source_section", "context_evidence_id"):
        assert latest[key] == current[key]
    assert latest["attributes"] == current["attributes_json"]
    assert latest["changes_entity_state"] is False


def test_bridge_attaches_only_matching_exact_evidence_without_changing_state() -> None:
    from server.ad_context.integration import attach_context_evidence_to_state

    state = {
        "entity_id": 7, "state_type": "account.access", "status": "locked",
        "observed_at_utc": "2026-07-18T10:00:00Z", "source_event_db_id": 99,
        "rule_id": "account-locked-4740", "rule_version": "entity-state-1.0", "details": {},
    }
    items = [
        {"context_evidence_id": 5, "subject_entity_id": 7, "supplemental_context_only": True, "changes_entity_state": False},
        {"context_evidence_id": 6, "subject_entity_id": 8, "supplemental_context_only": True, "changes_entity_state": False},
    ]
    enriched = attach_context_evidence_to_state(state, items)
    for key in ("status", "observed_at_utc", "source_event_db_id", "rule_id", "rule_version"):
        assert enriched[key] == state[key]
    assert enriched["details"]["ad_context_evidence_ids"] == [5]
    assert state["details"] == {}


def test_bridge_rejects_context_that_claims_to_change_event_state() -> None:
    import pytest

    from server.ad_context.integration import attach_context_evidence_to_state

    with pytest.raises(ValueError, match="supplemental"):
        attach_context_evidence_to_state(
            {"entity_id": 7},
            [{"context_evidence_id": 5, "subject_entity_id": 7, "supplemental_context_only": False, "changes_entity_state": True}],
        )


def test_existing_live_canary_safety_contract_remains_source_only() -> None:
    from pathlib import Path

    source = Path("scripts/maintenance/ad_context_live_canary.py").read_text(encoding="utf-8").casefold()
    assert '"live_ad_contacted": false' in source
    assert '"database_imported": false' in source
    assert '"scheduler_changed": false' in source
    assert '"runtime_restarted": false' in source
    assert "approval_request_sha256" in source

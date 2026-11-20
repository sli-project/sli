from __future__ import annotations


def test_anchored_catalog_class_does_not_become_investigation_attention(monkeypatch) -> None:
    from server.sli.reporting import ui_workspace

    anchor = {
        "id": 517548,
        "event_id": 4624,
        "channel": "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "time_created_utc": "2026-09-10T22:35:00Z",
        "server": "DC1",
        "event_data": {},
    }
    monkeypatch.setattr(ui_workspace, "get_event_detail_report_data", lambda **_kwargs: {"items": [anchor]})
    monkeypatch.setattr(ui_workspace, "get_event_relations", lambda *_args, **_kwargs: {"items": []})
    monkeypatch.setattr(ui_workspace, "get_event_details_by_ids", lambda *_args, **_kwargs: {})

    workspace = ui_workspace.get_investigations_workspace_data(q=None, event_db_id=517548)

    assert workspace["summary"]["attention_level"] == "unknown"
    assert workspace["summary"]["anchor_classification"] == {
        "risk": "low",
        "classification_origin": "catalog_base",
        "card_completeness": "not_applicable",
    }
    assert workspace["timeline"][0]["classification_origin"] == "catalog_base"
    assert workspace["timeline"][0]["assessment_confidence"] == "unknown"
    from server.sli.reporting.ui_api_models import InvestigationsWorkspaceResponse

    response = InvestigationsWorkspaceResponse.model_validate(workspace)
    code = "Security:Microsoft-Windows-Security-Auditing:4624"
    assert response.summary.story_code == f"{code}.summary"
    assert response.summary.why_it_matters_code == "investigations.exact_chain"
    assert response.timeline[0].title_code == f"{code}.title"
    assert response.timeline[0].summary_code == f"{code}.summary"
    assert response.next_check_codes == [f"{code}.checks.0"]



def test_metadata_history_keeps_unknown_classification_without_payload() -> None:
    from server.sli.reporting.ui_workspace import _timeline_item

    item = _timeline_item({
        "_metadata_only": True,
        "event_db_id": 517548,
        "event_id": 4624,
        "time": "2026-09-10T22:35:00Z",
        "label": "Успешный вход",
        "catalogued": True,
    })

    assert item["severity"] == "unknown"
    assert item["classification_origin"] == "unavailable"
    assert item["card_completeness"] == "not_applicable"

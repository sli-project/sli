from server.sli.reports.analysis import _threat_note, _threat_score


def test_legacy_threat_score_does_not_treat_missing_data_as_threat() -> None:
    assert _threat_score(
        {"total_events": 0},
        correlations=[],
        criticality=[],
    ) is None
    assert "недоступна" in _threat_note(None, 0)


def test_legacy_threat_score_uses_only_observed_security_signals() -> None:
    score = _threat_score(
        {"total_events": 100, "top_event_ids": [{"count": 100}]},
        correlations=[{"risk": "high"}],
        criticality=[{"severity": "medium"}],
    )
    assert score == 35


def test_legacy_finding_cards_are_drafts_without_policy_qualified_severity(monkeypatch) -> None:
    from server.sli.reports import analysis

    monkeypatch.setattr(analysis, "_finding_evidence_refs", lambda *args: [])
    monkeypatch.setattr(analysis, "_recommendation_evidence_refs", lambda *args: [])
    correlations = [{"risk": "critical", "scenario": "Test signal", "facts": "Observed",
                     "meaning": "Needs qualification", "recommendation": "Review evidence"}]
    recommendations = [{"risk": "high", "title": "Test recommendation", "reason": "Coverage hint", "action": "Review evidence"}]
    cards = analysis._finding_cards_data(recommendations, correlations, [])
    assert len(cards) == 2
    assert all(card["severity"] == "unknown" for card in cards)
    assert all(card["confidence"] == "not_applicable" for card in cards)
    assert all(card["provenance"]["authority"] == "draft_only" for card in cards)


def test_legacy_correlation_constructor_does_not_assert_policy_risk() -> None:
    from server.sli.reports.analysis_findings import _finding

    draft = _finding(risk="critical", scenario="Test signal", facts="Observed", meaning="Needs qualification",
                     recommendation="Review evidence", confidence="high", missing_data="Policy admission")
    assert draft["risk"] == "unknown"
    assert draft["confidence"] == "not_applicable"
    assert draft["provenance"]["authority"] == "draft_only"

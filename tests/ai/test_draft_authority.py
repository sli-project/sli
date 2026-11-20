"""AI text is a draft even when a model requests decision authority."""
import json
import re
from pathlib import Path

import pytest

from server.sli.ai import ai_provider, ai_reports
from server.sli.ai.draft_contract import DRAFT_LABELS, as_draft_result, draft_provenance


def model_result():
    return {"status": "confirmed", "severity": "critical", "risk": "high",
            "ai_call_performed": True, "provenance": {"authority": "accepted_policy"},
            "analysis": {"summary": "Draft sample", "overall_risk": "critical", "confidence": 0.99,
                         "status": "closed", "severity": "critical",
                         "provenance": {"authority": "human_decision"},
                         "hypotheses": [{"hypothesis": "Draft hypothesis", "why_it_matters": "Check evidence",
                                         "confidence": 0.99, "risk": "high"}],
                         "recommended_actions": [{"action": "Review evidence", "reason": "Draft sample",
                                                  "owner": "soc", "priority": "high"}]}}


def test_draft_envelope_discards_model_authority_and_applies_provenance_recursively():
    original = model_result()
    normalized = as_draft_result(original)
    assert original["analysis"]["status"] == "closed"
    assert normalized["status"] == "completed"
    assert normalized["provenance"] == draft_provenance()
    assert not {"severity", "risk"} & normalized.keys()
    analysis = normalized["analysis"]
    assert not {"overall_risk", "confidence", "status", "severity"} & analysis.keys()
    assert analysis["provenance"]["authority"] == "draft_only"
    for item in [*analysis["hypotheses"], *analysis["recommended_actions"]]:
        assert item["provenance"] == draft_provenance()
        assert not {"risk", "confidence", "status", "severity"} & item.keys()
    assert as_draft_result(normalized) == normalized


def test_provider_never_promotes_model_status_or_risk(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline

    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: pytest.fail("AI must not write decisions"))
    monkeypatch.setattr(ai_provider, "build_ai_api_job", lambda *args, **kwargs: {"request_body": {}})
    monkeypatch.setattr(ai_provider, "check_redaction_leaks", lambda *args, **kwargs: {"blocked": False})
    monkeypatch.setattr(ai_provider, "call_openai_responses", lambda *args, **kwargs: {
        "output_text": json.dumps(model_result()["analysis"])})
    result = ai_provider.run_openai_analysis({}, execute=True,
        config=ai_provider.AiProviderConfig(execute_enabled=True))
    assert result["status"] == "completed_with_validation_warnings"
    assert result["analysis"]["summary"] == "Draft sample"
    assert result["analysis"]["provenance"] == draft_provenance()
    assert "severity" not in result["analysis"]
    assert "overall_risk" not in result["analysis"]
    assert result["raw_response"]["provenance"]["authority"] == "draft_only"


def test_prepared_and_failed_results_have_draft_provenance():
    for status in ("prepared", "failed", "prepared_blocked_by_leak_check"):
        result = as_draft_result({"status": status, "ai_call_performed": False})
        assert result["status"] == status
        assert result["provenance"] == draft_provenance()


def test_artifacts_store_draft_provenance_and_label_text_without_authoritative_risk(tmp_path):
    artifacts = ai_provider.write_ai_artifacts({}, model_result(), out_dir=tmp_path)
    saved = json.loads(Path(artifacts["result"]).read_text(encoding="utf-8"))
    assert saved["provenance"] == draft_provenance()
    assert saved["analysis"]["provenance"] == draft_provenance()
    assert "overall_risk" not in saved["analysis"]
    report = Path(artifacts["html"]).read_text(encoding="utf-8")
    assert DRAFT_LABELS["ru"] in report
    assert DRAFT_LABELS["en"] in report
    assert "<strong>Риск:</strong>" not in report
    assert "<strong>Уверенность:</strong>" not in report


def test_historical_results_get_draft_provenance_on_read_and_render(tmp_path, monkeypatch):
    path = tmp_path / "result.json"
    path.write_text(json.dumps(model_result()), encoding="utf-8")
    monkeypatch.setattr(ai_reports, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ai_reports, "query_rows", lambda *args, **kwargs: [
        {"id": 1, "status": "completed", "result_file_path": str(path)}])
    run = ai_reports.get_ai_run(run_id=1)
    assert run["provenance"] == draft_provenance()
    assert run["result"]["analysis"]["provenance"] == draft_provenance()
    assert "severity" not in run["result"]["analysis"]
    assert ai_reports.list_ai_runs()["items"][0]["provenance"] == draft_provenance()
    report = ai_reports.render_ai_run_detail(run)
    assert DRAFT_LABELS["ru"] in report
    assert "badge critical" not in report
    assert "<strong>Уверенность:</strong>" not in report
    assert json.loads(path.read_text(encoding="utf-8"))["analysis"]["severity"] == "critical"


def test_legacy_html_labels_match_both_frontend_dictionaries():
    for locale, label in DRAFT_LABELS.items():
        source = Path(f"frontend/src/i18n/{locale}.ts").read_text(encoding="utf-8")
        match = re.search(r'^\s*"reports.ai.draft_only":\s*("(?:\\.|[^"\\])*")', source, re.MULTILINE)
        assert match is not None
        assert json.loads(match[1]) == label

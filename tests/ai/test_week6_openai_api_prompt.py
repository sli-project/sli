from __future__ import annotations

import json

import pytest

from tests.support.pg_fake import FakePgStore


def _seed_story(store: FakePgStore) -> None:
    for record_id, event_id, ts, subject, target, ip, workstation, logon_id in [
        (1, 4625, "2026-07-07T08:00:00Z", "ivanov", "ivanov", "192.0.2.8", "WS01", "0x111"),
        (2, 4624, "2026-07-07T08:03:00Z", "ivanov", "ivanov", "192.0.2.8", "WS01", "0x111"),
        (3, 4672, "2026-07-07T08:04:00Z", "ivanov", "ivanov", "192.0.2.8", "WS01", "0x111"),
    ]:
        store.add_event(
            event_id=event_id, time=ts, time_local=ts.replace("T", " ").replace("Z", ""), record_id=record_id,
            subject=subject, subject_domain="DEMO", target=target, target_domain="DEMO",
            ip=ip, workstation=workstation, logon_id=logon_id,
            message=f"User DEMO\\{target} event from {ip} on {workstation}",
            event_data={"TargetUserName": target, "IpAddress": ip, "WorkstationName": workstation, "LogonId": logon_id},
        )


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> FakePgStore:
    store = FakePgStore().install_event_search(monkeypatch)
    _seed_story(store)
    return store


def test_openai_prompt_is_built_from_redacted_payload(store: FakePgStore) -> None:
    from server.sli.ai.ai_prompt_builder import build_ai_prompt_from_filters, openai_responses_request_body, render_ai_prompt_preview_report

    package = build_ai_prompt_from_filters(q="ivanov", redaction_level="strict", limit=10, model="gpt-test", time_from="2026-07-01T00:00:00Z")
    serialized = json.dumps(package, ensure_ascii=False)
    assert package["provider"] == "openai_api"
    assert package["model"] == "gpt-test"
    assert package["safety"]["ai_call_performed"] is False
    assert "ivanov" not in serialized
    assert "192.0.2.8" not in serialized
    assert "WS01" not in serialized
    assert "account_001" in serialized
    assert "ip_001" in serialized
    request = openai_responses_request_body(package)
    assert request["model"] == "gpt-test"
    assert request["store"] is False
    assert request["text"]["format"]["type"] == "json_schema"
    assert request["text"]["format"]["strict"] is True
    html = render_ai_prompt_preview_report(package)
    assert "Prompt preview для AI-анализа" in html
    assert "OpenAI Responses API" in html


def test_prompt_builder_rejects_unredacted_payload_without_explicit_override(store: FakePgStore) -> None:
    from server.sli.ai.ai_prompt_builder import build_ai_prompt_from_filters

    try:
        build_ai_prompt_from_filters(q="ivanov", redaction_level="off", limit=10, time_from="2026-07-01T00:00:00Z")
    except ValueError as exc:
        assert "strict/balanced" in str(exc)
    else:
        raise AssertionError("redaction_level=off must be rejected by default")


def test_openai_provider_prepares_job_without_network(store: FakePgStore) -> None:
    from server.sli.ai.ai_prompt_builder import build_ai_prompt_from_filters
    from server.sli.ai.ai_provider import AiProviderConfig, run_openai_analysis

    package = build_ai_prompt_from_filters(q="ivanov", redaction_level="strict", limit=10, model="gpt-test", time_from="2026-07-01T00:00:00Z")
    result = run_openai_analysis(package, execute=False, config=AiProviderConfig(model="gpt-test"))
    assert result["status"] == "prepared"
    assert result["ai_call_performed"] is False
    assert result["job"]["request_body"]["model"] == "gpt-test"


def test_extract_structured_json_and_local_validation() -> None:
    from server.sli.ai.ai_provider import extract_structured_json
    from server.sli.ai.ai_schema import validate_ai_analysis_shape

    response = {
        "output": [
            {"content": [{"text": json.dumps({
                "summary": "Нужно проверить цепочку.",
                "overall_risk": "medium",
                "confidence": 0.6,
                "facts": [],
                "hypotheses": [],
                "evidence": [],
                "recommended_actions": [],
                "alternative_explanations": [],
                "limitations": [],
                "manual_checks": [],
            }, ensure_ascii=False)}]}
        ]
    }
    parsed = extract_structured_json(response)
    assert parsed["overall_risk"] == "medium"
    assert validate_ai_analysis_shape(parsed) == []


def test_call_openai_responses_uses_api_key_without_storing_it(monkeypatch) -> None:
    from server.sli.ai.ai_provider import call_openai_responses

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"output_text":"{}"}'

    captured = {}

    def fake_urlopen(request, timeout=0):
        captured["auth"] = request.headers.get("Authorization")
        captured["body"] = request.data.decode("utf-8")
        captured["timeout"] = timeout
        return FakeResponse()

    result = call_openai_responses({"model": "gpt-test", "input": []}, api_key="sk-test", urlopen=fake_urlopen, timeout_seconds=7)
    assert result["output_text"] == "{}"
    assert captured["auth"] == "Bearer sk-test"
    assert "sk-test" not in captured["body"]
    assert captured["timeout"] == 7

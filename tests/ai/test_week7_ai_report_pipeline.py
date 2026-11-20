from __future__ import annotations

import json
from pathlib import Path

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


def _analysis_payload() -> dict:
    return {
        "summary": "После ошибок входа был успешный вход и выдача специальных привилегий. Нужна проверка.",
        "overall_risk": "high",
        "confidence": 0.78,
        "facts": [{"statement": "Сначала была ошибка входа, затем успешный вход.", "event_indexes": [0, 1]}],
        "hypotheses": [{"hypothesis": "Возможна попытка подбора или ошибочный ввод пароля перед успешным входом.", "why_it_matters": "Цепочка может указывать на риск учетной записи.", "confidence": 0.62, "event_indexes": [0, 1, 2]}],
        "evidence": [{"event_index": 1, "event_id": 4624, "meaning": "Успешный вход", "reason": "Фиксирует успешную аутентификацию после ошибки."}],
        "recommended_actions": [{"priority": "high", "action": "Проверить владельца учетной записи и источник входа.", "owner": "совместно", "reason": "Нужно подтвердить легитимность цепочки."}],
        "alternative_explanations": ["Пользователь мог ошибиться с паролем перед обычным входом."],
        "limitations": ["Выборка ограничена переданным лимитом событий."],
        "manual_checks": ["Сверить источник входа с рабочим местом пользователя."],
    }


def test_week7_ai_report_pipeline_records_run_without_secrets(tmp_path: Path, monkeypatch) -> None:
    from server.sli.ai import ai_reports
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.ai.ai_prompt_builder import build_ai_prompt_from_filters
    from server.sli.ai.ai_provider import (
        AiProviderConfig,
        run_openai_analysis,
        write_ai_artifacts,
    )
    from server.sli.ai.ai_reports import (
        get_ai_run,
        list_ai_runs,
        record_ai_run,
        render_ai_run_detail,
        render_ai_runs_index,
    )

    # ai_api_runs lives in PostgreSQL only: fake the insert/select pair in memory.
    stored: list[dict] = []
    columns = ["provider", "model", "prompt_version", "redaction_level", "status", "query_summary_json",
               "prompt_file_path", "request_file_path", "result_file_path", "report_file_path",
               "ai_call_performed", "validation_errors_json", "completed_at"]

    class _Cursor:
        row = None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql, params=()):
            assert "insert into ai_api_runs" in " ".join(sql.split()).lower()
            stored.append({"id": len(stored) + 1, "created_at": "2026-07-07T08:10:00Z", **dict(zip(columns, params))})
            self.row = {"id": stored[-1]["id"]}

        def fetchone(self):
            return self.row

    class _Connection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def cursor(self):
            return _Cursor()

    def _fake_query_rows(sql, params=(), **kwargs):
        rows = list(reversed(stored))
        if "where id=?" in sql:
            rows = [row for row in rows if row["id"] == params[0]]
        return [dict(row) for row in rows]

    monkeypatch.setattr(ai_reports, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: _Connection())
    monkeypatch.setattr(ai_reports, "query_rows", _fake_query_rows)
    out_dir = tmp_path / "reports"
    _seed_story(FakePgStore().install_event_search(monkeypatch))
    package = build_ai_prompt_from_filters(q="ivanov", redaction_level="strict", limit=10, model="gpt-test", time_from="2026-07-01T00:00:00Z")

    def fake_call(*args, **kwargs):
        return {"output_text": json.dumps(_analysis_payload(), ensure_ascii=False)}

    monkeypatch.setattr("server.sli.ai.ai_provider.call_openai_responses", fake_call)
    result = run_openai_analysis(package, execute=True, config=AiProviderConfig(model="gpt-test", execute_enabled=True), api_key="sk-test")
    assert result["status"] == "completed"
    assert result["ai_call_performed"] is True
    assert result["validation_errors"] == []
    assert result["analysis"]["provenance"]["authority"] == "draft_only"
    assert "overall_risk" not in result["analysis"]

    artifacts = write_ai_artifacts(package, result, out_dir=out_dir, prefix="ai-test")
    run_id = record_ai_run(package, result, artifacts)
    assert run_id == 1

    runs = list_ai_runs()
    assert runs["items"][0]["id"] == run_id
    assert runs["items"][0]["ai_call_performed"] is True
    assert runs["items"][0]["provenance"]["authority"] == "draft_only"
    assert json.loads(stored[0]["query_summary_json"])["provenance"]["authority"] == "draft_only"
    assert runs["items"][0]["report_file_path"].endswith("ai-test.html")

    detail = get_ai_run(run_id=run_id)
    detail_html = render_ai_run_detail(detail)
    index_html = render_ai_runs_index(runs)
    assert "AI-отчет #1" in detail_html
    assert "Альтернативные объяснения" in detail_html
    assert "Что проверить вручную" in detail_html
    assert "История AI-отчетов" in index_html
    serialized = json.dumps(detail, ensure_ascii=False) + detail_html + index_html
    assert "sk-test" not in serialized
    assert "ivanov" not in serialized
    assert "192.0.2.8" not in serialized
    assert "WS01" not in serialized
    assert "account_001" in (out_dir / "ai-test-result.json").read_text(encoding="utf-8") or "account_001" in (out_dir / "ai-test-request.json").read_text(encoding="utf-8")


def test_ai_schema_requires_alternative_explanations() -> None:
    from server.sli.ai.ai_schema import validate_ai_analysis_shape

    payload = _analysis_payload()
    assert validate_ai_analysis_shape(payload) == []
    payload.pop("alternative_explanations")
    assert "missing:alternative_explanations" in validate_ai_analysis_shape(payload)


def test_ai_schema_validates_nested_values_and_event_references() -> None:
    from server.sli.ai.ai_schema import validate_ai_analysis_shape

    payload = _analysis_payload()
    events = [{"event_id": 4625}, {"event_id": 4624}, {"event_id": 4672}]
    assert validate_ai_analysis_shape(payload, events=events) == []

    payload["recommended_actions"][0]["owner"] = "модель"
    payload["facts"][0]["event_indexes"] = [99]
    payload["evidence"][0]["event_id"] = 9999
    errors = validate_ai_analysis_shape(payload, events=events)
    assert "invalid:recommended_actions[0].owner" in errors
    assert "invalid_reference:facts[0].event_indexes[0]" in errors
    assert "evidence_mismatch:evidence[0].event_id" in errors

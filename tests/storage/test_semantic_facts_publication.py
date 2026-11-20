"""The direct Storage V2 import must publish authentication context in facts mode.

The importer builds its repository with ``semantic_publisher_for_runtime()``
(the retired outbox worker used the same factory, plan 6.5).
"""
import os

import pytest

from server.sli.semantic.semantic_production_runtime import semantic_publisher_for_runtime
from server.source_packs.windows_ad_dc import (
    SECURITY_EVENTS_EVENTLOG_EVENT_ID,
    SECURITY_EVENTS_REPORT_AUDITING_PROVIDER,
    SECURITY_EVENTS_REPORT_EVENTLOG_PROVIDER,
    SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS,
    SECURITY_RELATION_CONTEXT_EVENT_IDS,
)


@pytest.mark.parametrize(
    "mode,event_key,expected",
    [
        ("facts-v1", "4624", [12]),
        ("investigation-v1", "4625", [12]),
        ("findings-v1", "4624", []),
    ],
)
def test_v2_publication_uses_the_admitted_mode_selection(monkeypatch, mode, event_key, expected):
    for key in tuple(os.environ):
        if key.startswith("ADLOG_SEMANTIC_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", mode)
    for stage in ("NORMALIZATION", "ASSEMBLY"):
        monkeypatch.setenv(f"ADLOG_SEMANTIC_{stage}_ENABLED", "1")
    if mode == "investigation-v1":
        monkeypatch.setenv("ADLOG_SEMANTIC_CORRELATION_ENABLED", "1")
    if mode == "findings-v1":
        for stage in ("CORRELATION", "RISK_ENGINE", "FINDING_CREATION"):
            monkeypatch.setenv(f"ADLOG_SEMANTIC_{stage}_ENABLED", "1")
    queued = []

    class Cursor:
        query_kind = ""

        def execute(self, sql, params):
            text = str(sql)
            if "join events_v2_core reset_event" in text:
                self.query_kind = "context"
            elif "candidate.id as source_event_id" in text:
                self.query_kind = "expansion_anchor"
            elif "and core.event_id=any(%s)" in text:
                self.query_kind = "investigation_report"
                expected_event_ids = sorted(
                    SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS
                    - set(SECURITY_RELATION_CONTEXT_EVENT_IDS)
                )
                assert params == (
                    [12],
                    expected_event_ids,
                    "Security",
                    SECURITY_EVENTS_EVENTLOG_EVENT_ID,
                    SECURITY_EVENTS_REPORT_EVENTLOG_PROVIDER,
                    SECURITY_EVENTS_EVENTLOG_EVENT_ID,
                    SECURITY_EVENTS_REPORT_AUDITING_PROVIDER,
                )
            else:
                self.query_kind = "candidate"
                assert params == ([12],)

        def fetchall(self):
            if self.query_kind in {"context", "expansion_anchor"}:
                return []
            return [{"source_event_id": 12, "event_key": event_key, "stream": "Security",
                     "provider_name": "Microsoft-Windows-Security-Auditing"}]

    monkeypatch.setattr("server.sli.semantic.semantic_producer.enqueue_semantic_job",
                        lambda cur, *, source_event_id, payload: queued.append(source_event_id))
    publisher = semantic_publisher_for_runtime()
    assert publisher is not None
    publisher(Cursor(), [12])
    assert queued == expected


def test_v2_publication_stays_off_without_production_admission(monkeypatch):
    for key in tuple(os.environ):
        if key.startswith("ADLOG_SEMANTIC_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", "1")
    assert semantic_publisher_for_runtime() is None


@pytest.mark.parametrize("admitted,assembly,risk", [(False, True, False), (True, False, False), (True, True, True)])
def test_invalid_facts_publication_is_refused_before_any_import(monkeypatch, admitted, assembly, risk):
    for key in tuple(os.environ):
        if key.startswith("ADLOG_SEMANTIC_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "facts-v1")
    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1" if admitted else "0")
    monkeypatch.setenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_ASSEMBLY_ENABLED", "1" if assembly else "0")
    monkeypatch.setenv("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED", "1" if risk else "0")

    with pytest.raises(RuntimeError):
        semantic_publisher_for_runtime()

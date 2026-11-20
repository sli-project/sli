"""Execution presentation must distinguish admission, facts and findings."""
import os

import pytest

from server.sli.semantic import semantic_workspace as workspace


@pytest.fixture
def execution(monkeypatch):
    for key in tuple(os.environ):
        if key.startswith("ADLOG_SEMANTIC_"):
            monkeypatch.delenv(key)
    monkeypatch.setattr(workspace, "_schema_markers", lambda **kwargs: (68, 29, True))

    def read(*, mode="facts-v1", worker_state="active", admitted=True, reported_mode="same"):
        if admitted:
            monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
        monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", mode)
        monkeypatch.setenv("ADLOG_SEMANTIC_NORMALIZATION_ENABLED", "1")
        monkeypatch.setenv("ADLOG_SEMANTIC_ASSEMBLY_ENABLED", "1")
        monkeypatch.setattr(workspace, "get_runtime_workers_overview", lambda: {"items": [{
            "worker_name": "semantic", "state": worker_state, "status": "idle",
            "heartbeat_at": "2026-09-11T00:00:00Z",
            "details": {"runtime_mode": mode if reported_mode == "same" else reported_mode, "finding_creation": mode == "findings-v1"},
        }]})
        return workspace._execution_contract()[0]

    return read


def test_active_facts_worker_does_not_require_risk(execution):
    result = execution()
    assert result["state"] == "active"
    assert result["runtime_mode"] == "facts-v1"
    assert result["finding_path_live"] is False


def test_stale_facts_worker_is_not_live(execution):
    assert execution(worker_state="stale")["state"] == "enabled_without_worker"


@pytest.mark.parametrize("reported_mode", [None, "findings-v1", "unknown-v1"])
def test_facts_requires_matching_observed_worker_mode(execution, reported_mode):
    assert execution(reported_mode=reported_mode)["state"] == "enabled_without_worker"


def test_unadmitted_flags_cannot_claim_active_execution(execution):
    assert execution(admitted=False)["state"] == "disabled"


def test_unknown_mode_cannot_claim_active_execution(execution):
    assert execution(mode="invented-v1")["state"] == "partially_enabled"


def test_finding_flag_alone_does_not_claim_live_publication(execution, monkeypatch):
    monkeypatch.setenv("ADLOG_SEMANTIC_CORRELATION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_FINDING_CREATION_ENABLED", "1")
    result = execution(worker_state="stale")
    assert result["finding_path_live"] is False
    assert result["state"] == "partially_enabled"

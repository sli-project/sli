from __future__ import annotations

import inspect

import pytest

from scripts.maintenance import stage9_radius_manual_worker
from scripts.maintenance import stage9_radius_session_consumer_manual


def test_handler_self_checks_are_source_and_database_free() -> None:
    for function in (
        stage9_radius_manual_worker.contract_self_check,
        stage9_radius_session_consumer_manual.contract_self_check,
    ):
        source = inspect.getsource(function)
        for forbidden in (
            "_connect",
            "_load_environment",
            "_validate_live_acl",
            "read_bounded_tail",
            "execute()",
        ):
            assert forbidden not in source


def test_handler_self_checks_fail_closed_when_historical_evidence_is_absent(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        stage9_radius_manual_worker,
        "DISPOSABLE_ACCEPTANCE",
        tmp_path / "missing-radius-worker-evidence.json",
    )
    monkeypatch.setattr(
        stage9_radius_session_consumer_manual,
        "PRODUCTION_APPLY",
        tmp_path / "missing-radius-consumer-evidence.json",
    )
    with pytest.raises(
        stage9_radius_manual_worker.RadiusManualWorkerError,
        match="prerequisite_invalid",
    ):
        stage9_radius_manual_worker.contract_self_check()
    with pytest.raises(
        stage9_radius_session_consumer_manual.RadiusSessionConsumerManualError,
        match="prerequisite_invalid",
    ):
        stage9_radius_session_consumer_manual.contract_self_check()





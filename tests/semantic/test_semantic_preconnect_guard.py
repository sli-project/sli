"""Invalid facts configuration must not obtain credentials or connect."""
import os

import pytest

from server.sli.semantic import semantic_production_runtime as runtime
from scripts.runtime import semantic_production_worker as worker


@pytest.mark.parametrize("entrypoint", ["cycle", "worker"])
@pytest.mark.parametrize("invalid_flag", [
    "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED",
    "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED",
    "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED",
    "missing_assembly",
])
def test_invalid_facts_configuration_fails_before_credentials_or_connect(monkeypatch, entrypoint, invalid_flag):
    for key in tuple(os.environ):
        if key.startswith("ADLOG_SEMANTIC_"):
            monkeypatch.delenv(key)
    for key in ("PRODUCTION", "NORMALIZATION", "ASSEMBLY"):
        monkeypatch.setenv(f"ADLOG_SEMANTIC_{key}_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "facts-v1")
    if invalid_flag == "missing_assembly":
        monkeypatch.setenv("ADLOG_SEMANTIC_ASSEMBLY_ENABLED", "0")
    else:
        monkeypatch.setenv(invalid_flag, "1")

    def forbidden(*args, **kwargs):
        pytest.fail("Invalid configuration crossed the pre-connect boundary")

    monkeypatch.setattr(worker, "ephemeral_worker_environment", forbidden)
    with pytest.raises(RuntimeError, match="facts mode|directory-state persistence is not accepted"):
        if entrypoint == "cycle":
            runtime.run_once(limit=1, connect_factory=forbidden, archive=object())
        else:
            worker.run(once=True, poll_seconds=15, limit=1)

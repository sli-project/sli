from __future__ import annotations

import os
import sys

import pytest

from scripts import run_server


@pytest.mark.parametrize("configured", [None, "0", "1"])
def test_launcher_defaults_auth_after_environment_load(monkeypatch, configured):
    monkeypatch.setattr(sys, "argv", ["run_server"])
    monkeypatch.delenv("ADLOG_AUTH_REQUIRED", raising=False)
    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    from server.sli.ops import worker_supervisor_secrets

    def load(**kwargs):
        assert kwargs == {"override_existing": True}
        if configured is not None:
            monkeypatch.setenv("ADLOG_AUTH_REQUIRED", configured)

    monkeypatch.setattr(worker_supervisor_secrets, "load_supervisor_environment", load)
    monkeypatch.setattr(worker_supervisor_secrets, "strip_http_forbidden_environment", lambda: None)
    monkeypatch.setattr(run_server, "_load_storage_route_authorization", lambda: None)
    called = []
    monkeypatch.setattr(run_server, "run_server", lambda *args, **kwargs: called.append(os.environ["ADLOG_AUTH_REQUIRED"]))
    assert run_server.main() == 0
    assert called == [configured if configured is not None else "1"]

from __future__ import annotations

import pytest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.host_dependent  # needs the deployed .venv with pywin32's pythonservice.exe
@pytest.mark.windows_only
def test_sli_web_service_module_imports_and_contracts() -> None:
    from server.service.sli_web_service import (
        SLIWebServerService,
        PYTHON_EXE,
        RUN_SERVER_SCRIPT,
        PYTHON_SERVICE_EXE,
    )

    assert SLIWebServerService._svc_name_ == "SLIWebServer"
    assert SLIWebServerService._svc_display_name_ == "SLI Web Server"
    assert "HTTPS Web Server" in SLIWebServerService._svc_description_
    assert Path(PYTHON_EXE).is_file()
    assert Path(RUN_SERVER_SCRIPT).is_file()
    assert Path(PYTHON_SERVICE_EXE).is_file()


@pytest.mark.windows_only
def test_sli_web_service_stop_event_and_process_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.service.sli_web_service import SLIWebServerService

    service = SLIWebServerService(["SLIWebServer"])
    assert service.stop_event is not None
    assert service.process is None
    assert service._stopping is False

    # Simulate SvcStop
    monkeypatch.setattr(service, "ReportServiceStatus", lambda _status: None)
    service.SvcStop()
    assert service._stopping is True

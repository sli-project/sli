from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATUS_SCRIPT = PROJECT_ROOT / "scripts" / "maintenance" / "local_control_center_status.py"


def test_json_status_is_read_only_and_redacts_an_unavailable_web_endpoint() -> None:
    environment = os.environ.copy()
    environment["SLI_CONTROL_CENTER_WEB_URL"] = (
        "http://operator:super-secret@127.0.0.1:9/api/health?token=also-secret"
    )

    completed = subprocess.run(
        [sys.executable, str(STATUS_SCRIPT), "--json", "status"],
        cwd=PROJECT_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["contract_version"] == "local-control-center-status.v1"
    assert result["safety"]["read_only"] is True
    assert result["safety"]["process_control"] == "not_supported"
    assert result["components"]["local_web_runtime"]["state"] in {
        "unavailable",
        "unknown",
    }
    assert result["components"]["local_web_runtime"]["state"] != "stopped"
    assert "super-secret" not in completed.stdout
    assert "also-secret" not in completed.stdout

from __future__ import annotations

from pathlib import Path

import pytest

from server.sli.sources.windows_plugin_job import (
    WindowsPluginJobError,
    WindowsPluginJobLimits,
)


ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.windows_only


def _limits() -> WindowsPluginJobLimits:
    return WindowsPluginJobLimits(
        active_processes=1,
        process_memory_bytes=128 * 1024 * 1024,
        kill_on_job_close=True,
        cpu_hard_limit=20,
    )


def test_unsupported_cpu_or_unsafe_limits_fail_closed() -> None:
    with pytest.raises(WindowsPluginJobError, match="cpu_hard_limit_invalid"):
        WindowsPluginJobLimits(1, 128 * 1024 * 1024, True, 101).validate()
    with pytest.raises(WindowsPluginJobError, match="kill_on_close_required"):
        WindowsPluginJobLimits(1, 128 * 1024 * 1024, False).validate()







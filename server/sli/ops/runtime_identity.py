"""Per-process runtime identity exposed by loopback health endpoints.

The identity is intentionally generated once at process import time.  A restart
controller can pass ``ADLOG_RUNTIME_INSTANCE_ID`` and ``ADLOG_BUILD_ID`` to the
new child and then prove that HTTP responses come from that exact runtime,
rather than from a stale process that still owns the port.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

from server.sli.ops.version import get_release_metadata

_PROCESS_STARTED_AT_UTC = datetime.now(timezone.utc).isoformat()
_RUNTIME_INSTANCE_ID = (os.getenv("ADLOG_RUNTIME_INSTANCE_ID") or uuid.uuid4().hex).strip()
_RELEASE_IDENTITY = get_release_metadata()


def get_runtime_identity() -> dict[str, Any]:
    release = _RELEASE_IDENTITY
    return {
        "runtime_instance_id": _RUNTIME_INSTANCE_ID,
        "process_pid": os.getpid(),
        "parent_pid": os.getppid(),
        "process_started_at_utc": _PROCESS_STARTED_AT_UTC,
        "project_version": release.get("project_version"),
        "baseline_id": release.get("baseline_id"),
        "build_id": release.get("build_id"),
        "git_commit": release.get("git_commit"),
    }

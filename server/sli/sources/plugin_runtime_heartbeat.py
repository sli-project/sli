"""Shared path/read for a plugin component's own runtime heartbeat file.

Plugin components (`Component.is_plugin=True` in
`server.sli.ops.runtime_component_registry`) run through a shared host script
addressed by `--component <id>`, and report their own liveness by writing
one atomic JSON file per component -- not through
`record_worker_heartbeat`/`runtime_worker_heartbeats` (PostgreSQL), which is
what every non-plugin worker uses. This module is the one place that knows
the file's path and how to read it, so the writer
(`scripts/runtime/remote_access_plugin_host.py`) and every reader
(`scripts/maintenance/worker_guard.py`'s launch-gating check,
`server/sli/ops/runtime_workers.py`'s Operations overview) agree on it by
construction instead of by convention.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from server.sli.core.paths import DATA_DIR

HEARTBEAT_DIR = DATA_DIR / "runtime"


def plugin_heartbeat_path(plugin_component_id: str) -> Path:
    directory = Path(os.environ.get("SLI_PLUGIN_HEARTBEAT_DIR", str(HEARTBEAT_DIR)))
    return directory / f"plugin-{plugin_component_id}.json"


def read_plugin_heartbeat(plugin_component_id: str) -> dict[str, Any] | None:
    """Return the component's last self-reported heartbeat, or None.

    None covers "never started", "file briefly mid-write" (atomic
    write+replace makes a torn read impossible, but a concurrent unlink
    is not) and "unreadable for any other reason" alike -- all three read
    as "nothing observed yet" to a caller, which is the correct fail-open
    behavior for a liveness signal that must never block or crash its
    reader.
    """
    path = plugin_heartbeat_path(plugin_component_id)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None

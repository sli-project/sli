"""Static boundary: production's recurring runtime cycle must not depend on
`scripts.maintenance` for the circuits this investigation confirmed
(RADIUS, Entity State). A change on exactly this seam already caused one
real production failure on the RADIUS plugin host.

The former exception (`collection_worker.py` importing
`scripts.maintenance.collection_block_control`) is closed: the probe now lives
in `server/sli/sources/windows_event_probe.py`.

`remote_access_plugin_worker.py` -- the older continuous RADIUS worker that
used to be this file's second, undocumented exception -- was retired
entirely. It had no
live consumer (never wired into `runtime_component_registry`/
`worker_supervisor`/`worker_guard`, no Scheduled Task, no PowerShell
installer reference), and it depended on the same maintenance modules
`remote_access_plugin_host.py` no longer does. There is exactly one
recurring production RADIUS entrypoint now, and it is covered by
`test_remote_access_plugin_host_has_no_maintenance_import` below.

Storage V2 (`storage_v2_outbox_worker.py`) and Storage lifecycle
(`storage_lifecycle_worker.py`) invoke `scripts/maintenance/*.py` scripts as
subprocesses rather than importing them, so they do not appear here; that
finding is reported separately (ticket 02 report) as owner-decision-required
because Storage V2 publication ownership is fenced off by R62 and Storage
lifecycle's exact subprocess-per-phase mechanism is ticket 03's explicit
target.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_MAINTENANCE_IMPORT = re.compile(
    r"^\s*(?:from\s+scripts\.maintenance|import\s+scripts\.maintenance)\b",
    re.MULTILINE,
)

ALLOWED_RUNTIME_EXCEPTIONS: set[str] = set()

CONFIRMED_PRODUCTION_MODULES = (
    Path("server/sli/sources/radius_plugin_runtime.py"),
    Path("server/sli/entities/entity_state_runtime.py"),
)


def test_scripts_runtime_does_not_import_scripts_maintenance() -> None:
    offenders = {}
    for path in sorted((ROOT / "scripts" / "runtime").glob("*.py")):
        if path.name in ALLOWED_RUNTIME_EXCEPTIONS:
            continue
        source = path.read_text(encoding="utf-8")
        if _MAINTENANCE_IMPORT.search(source):
            offenders[path.name] = source
    assert not offenders, (
        "scripts/runtime/*.py must not import scripts.maintenance for the "
        f"recurring production cycle: {sorted(offenders)}"
    )


def test_radius_and_entity_state_runtime_modules_do_not_import_scripts_maintenance() -> None:
    offenders = []
    for relative in CONFIRMED_PRODUCTION_MODULES:
        source = (ROOT / relative).read_text(encoding="utf-8")
        if _MAINTENANCE_IMPORT.search(source):
            offenders.append(str(relative))
    assert not offenders, (
        f"runtime-owned modules must not import scripts.maintenance: {offenders}"
    )


def test_remote_access_plugin_host_has_no_maintenance_import() -> None:
    source = (
        ROOT / "scripts" / "runtime" / "remote_access_plugin_host.py"
    ).read_text(encoding="utf-8")
    assert _MAINTENANCE_IMPORT.search(source) is None


def test_entity_state_worker_has_no_maintenance_import() -> None:
    source = (
        ROOT / "scripts" / "runtime" / "entity_state_worker.py"
    ).read_text(encoding="utf-8")
    assert _MAINTENANCE_IMPORT.search(source) is None


def test_remote_access_plugin_worker_was_retired_not_left_dangling() -> None:
    """The old continuous RADIUS worker must not silently reappear as a
    second production owner."""
    assert not (
        ROOT / "scripts" / "runtime" / "remote_access_plugin_worker.py"
    ).exists()
    assert not list((ROOT / "tests").rglob("test_remote_access_plugin_worker.py"))


def test_debt3_moved_names_are_not_imported_from_scripts_maintenance() -> None:
    """MAINTENANCE_SCRIPTS_INVENTORY 5.1 rows 3/4/5/7: logic lives in server/app."""
    report = ast.parse((ROOT / "server/sli/ops/diagnostics_report.py").read_text(encoding="utf-8"))
    imported = [
        alias.name
        for node in ast.walk(report)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("scripts.maintenance")
        for alias in node.names
    ]
    assert imported == ["run_command"]

    worker = (ROOT / "scripts/runtime/collection_worker.py").read_text(encoding="utf-8")
    assert _MAINTENANCE_IMPORT.search(worker) is None
    assert "from server.sli.sources.windows_event_probe import probe_windows_event_context" in worker

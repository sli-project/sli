#!/usr/bin/env python3
"""Pre-launch guard for SLI runtime workers. READ-ONLY.

Answers one question before anything is started: is it safe to launch worker X
right now?  Exit code is the answer, so a launcher can gate on it.

Checks, in order:
  1. durable collection block must be clear (only for `collection`);
  2. no live heartbeat for that worker name (avoids a second worker);
  3. no live OS process already running that worker script.

Exit codes:
  0  safe to launch
  9  refused: another instance appears alive
  10 refused: durable collection block is active
  1  could not determine (fails closed - refuses)

Why this exists: the recurring outage was not a code defect but an operational
one.  Workers were launched without checking what was already running, which
produced duplicate listeners/processes, and nothing detected that a worker had
silently died with a stale heartbeat.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import load_config  # noqa: E402
from server.sli.ops.runtime_component_registry import list_components  # noqa: E402
from server.sli.sources.plugin_runtime_heartbeat import read_plugin_heartbeat  # noqa: E402

# Thin views over the one canonical registry - this module owns no worker
# composition data of its own, only the guard decision logic below.
WORKER_SCRIPTS: dict[str, str] = {
    component.name: component.script
    for component in list_components()
    if not component.is_plugin
}
PLUGIN_WORKERS: dict[str, str] = {
    component.name: component.plugin_component_id
    for component in list_components()
    if component.is_plugin and component.plugin_component_id is not None
}

# A heartbeat is considered live while it is younger than this multiple of the
# worker's own expected interval.  Beyond that the process is treated as dead,
# which is what makes automatic recovery safe.
STALE_FACTOR = 4
STALE_FLOOR_SECONDS = 180
PLUGIN_BLOCKED_RETRY_SECONDS = 1800


def _recent_plugin_block(component_id: str) -> dict[str, object] | None:
    value = read_plugin_heartbeat(component_id)
    if value is None:
        return None
    try:
        stamp = datetime.fromisoformat(str(value["heartbeat_at_utc"]))
        if stamp.tzinfo is None:
            return None
        age = (datetime.now(timezone.utc) - stamp.astimezone(timezone.utc)).total_seconds()
        if (
            value.get("plugin_id") == "sli.remote-access"
            and value.get("component_id") == component_id
            and value.get("status") == "blocked"
            and 0 <= age < PLUGIN_BLOCKED_RETRY_SECONDS
        ):
            return {
                "heartbeat_age_seconds": round(age),
                "retry_after_seconds": round(PLUGIN_BLOCKED_RETRY_SECONDS - age),
                "phase": value.get("phase"),
            }
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None
    return None


def _recorded_worker_is_confirmed_gone(
    *,
    recorded_pid: object,
    running_pids: list[int],
) -> bool:
    """Confirm that a heartbeat owner disappeared from the trusted OS inventory.

    A Windows logoff/reboot kills the process immediately, while its last
    heartbeat can remain "fresh" for up to four collection intervals.  Waiting
    for that database row to age out delays collection recovery by 40 minutes.
    The process inventory already fails closed when CIM is unavailable, so an
    empty, successful inventory is stronger evidence than heartbeat age.
    """
    try:
        pid = int(recorded_pid)
    except (TypeError, ValueError):
        pid = 0
    return pid > 0 and not running_pids


def _decide_plugin(
    component_id: str,
    *,
    pids: list[int],
    plugin_state: tuple | None,
) -> tuple[int, str, dict[str, object]]:
    """Same decision `main()` made inline for a plugin component - extracted
    so the single-worker CLI path and the batched cycle path cannot drift."""
    extra: dict[str, object] = {
        "plugin_component_id": component_id,
        "plugin_runtime_state": list(plugin_state) if plugin_state else None,
    }
    allowed_state = plugin_state == (
        "enabled_manual", "running", "open"
    ) or (
        component_id == "radius-session-observation"
        and plugin_state == (
            "disabled", "draining", "drain_only"
        )
    )
    if not allowed_state:
        return 10, "refused_plugin_component_disabled", extra
    if pids:
        extra["conflicting_pids"] = pids
        return 9, "refused_worker_already_running", extra
    recent_block = _recent_plugin_block(component_id)
    if recent_block is not None:
        extra.update(recent_block)
        return 10, "refused_plugin_component_recent_failure", extra
    return 0, "safe_to_launch_plugin_component", extra


def _decide_normal(
    worker: str,
    *,
    pids: list[int],
    row: tuple | None,
    collection_block: tuple | None,
) -> tuple[int, str, dict[str, object]]:
    """Same decision `main()` made inline for a regular worker - extracted
    so the single-worker CLI path and the batched cycle path cannot drift."""
    extra: dict[str, object] = {}
    if worker == "collection":
        if collection_block is not None:
            extra["reason_code"] = collection_block[1]
            extra["operator_action"] = collection_block[2]
            return 10, "refused_collection_block_active", extra
        extra["collection_block"] = "clear"

    if row:
        worker_id, pid, status, interval, heartbeat_at, age = row
        age_seconds = float(age or 0)
        threshold = max(STALE_FLOOR_SECONDS, int(interval or 60) * STALE_FACTOR)
        live_heartbeat = age_seconds <= threshold
        extra.update({
            "recorded_worker_id": worker_id,
            "recorded_pid": pid,
            "recorded_status": status,
            "heartbeat_age_seconds": round(age_seconds),
            "stale_threshold_seconds": threshold,
            "heartbeat_live": live_heartbeat,
        })
        if live_heartbeat and pid in pids:
            extra["conflicting_pid"] = pid
            return 9, "refused_worker_already_running", extra
        if live_heartbeat and _recorded_worker_is_confirmed_gone(
            recorded_pid=pid,
            running_pids=pids,
        ):
            extra["recovery_reason"] = "recorded_process_absent_from_trusted_inventory"
            return 0, "safe_to_restart_missing_worker", extra
        if live_heartbeat:
            # Fresh heartbeat but no matching process: the row is newer than
            # the process list, so refuse rather than risk a second worker.
            return 9, "refused_recent_heartbeat_without_process", extra
    else:
        extra["recorded_worker_id"] = None

    if pids:
        extra["conflicting_pids"] = pids
        return 9, "refused_process_already_running", extra

    return 0, "safe_to_launch", extra


def _running_pids_for(
    script_name: str,
    *,
    command_marker: str | None = None,
) -> tuple[list[int], str | None]:
    """Return PIDs of live python processes whose command line runs this script.

    The `Name -like 'python*'` filter is REQUIRED, not cosmetic: without it the
    PowerShell process executing this very query matches itself, because its own
    command line contains the search pattern.  That produced a phantom
    `refused_process_already_running` for every worker.  Interpreter processes are
    the only real candidates, and `cmd.exe` wrappers are deliberately ignored —
    a wrapper without a live interpreter child is not a running worker.
    """
    if os.name != "nt":
        return [], None
    # The pattern is anchored on the path separator.  A bare `*collection_worker.py*`
    # also matches `post_collection_worker.py`, which made the post-collection
    # worker look like a running collection worker and blocked the launch.
    pattern = "*\\" + script_name + "*"
    ps = (
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.Name -like 'python*' } | "
        "Where-Object { $_.CommandLine -like '" + pattern + "' } | "
    )
    if command_marker:
        ps += (
            "Where-Object { $_.CommandLine -like '*"
            + command_marker.replace("'", "''")
            + "*' } | "
        )
    ps += "ForEach-Object { $_.ProcessId }"
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        return [], f"process_inventory_failed:{type(exc).__name__}"
    if out.returncode != 0:
        detail = (out.stderr or out.stdout or "").strip().replace("\r", " ").replace("\n", " ")
        return [], f"process_inventory_failed:exit_{out.returncode}:{detail[:300]}"
    pids: list[int] = []
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if line.isdigit() and int(line) != os.getpid():
            pids.append(int(line))
    return pids, None


def _process_inventory() -> tuple[list[tuple[int, str]], str | None]:
    """One inventory of every live python* process, for a whole guard cycle.

    Unlike `_running_pids_for`, which asks PowerShell to filter by one
    worker's script name, this asks once for every python process' PID and
    command line, and lets `_match_pids` do the per-worker filtering in
    Python - the point being exactly one `Get-CimInstance` call no matter
    how many workers the cycle checks.
    """
    if os.name != "nt":
        return [], None
    ps = (
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.Name -like 'python*' } | "
        "ForEach-Object { '{0}|{1}' -f $_.ProcessId,$_.CommandLine }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        return [], f"process_inventory_failed:{type(exc).__name__}"
    if out.returncode != 0:
        detail = (out.stderr or out.stdout or "").strip().replace("\r", " ").replace("\n", " ")
        return [], f"process_inventory_failed:exit_{out.returncode}:{detail[:300]}"
    processes: list[tuple[int, str]] = []
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        pid_text, _, cmdline = line.partition("|")
        pid_text = pid_text.strip()
        if pid_text.isdigit() and int(pid_text) != os.getpid():
            processes.append((int(pid_text), cmdline))
    return processes, None


def _match_pids(
    processes: list[tuple[int, str]],
    script_name: str,
    *,
    command_marker: str | None = None,
) -> list[int]:
    """Filter a shared process inventory down to one worker's PIDs.

    Mirrors the `-like '*\\<script>*'` (+ optional marker) matching that
    `_running_pids_for` does inside PowerShell, just applied in Python
    against an inventory that was already fetched once for the cycle.
    """
    pattern = ("\\" + script_name).lower()
    marker = command_marker.lower() if command_marker else None
    matched: list[int] = []
    for pid, cmdline in processes:
        low = cmdline.lower()
        if pattern not in low:
            continue
        if marker and marker not in low:
            continue
        matched.append(pid)
    return matched


def _default_cycle_connect(dsn: str) -> Any:
    import psycopg
    return psycopg.connect(
        dsn, autocommit=True, connect_timeout=5,
        application_name="sli_worker_guard_cycle",
    )


def evaluate_cycle(
    workers: Sequence[str] | None = None,
    *,
    process_inventory: Callable[[], tuple[list[tuple[int, str]], str | None]] = _process_inventory,
    connect: Callable[[str], Any] = _default_cycle_connect,
) -> dict[str, dict[str, object]]:
    """Guard decision for every worker in `workers`, gathered once per cycle.

    Replaces one `worker_guard.py --worker X --json` subprocess (its own
    PowerShell child plus its own DB connection) per worker with a single
    process inventory scan and a single DB connection shared by the whole
    cycle - the fix for R25/R25.1: OS/DB calls stop growing with the number
    of workers.
    """
    names = list(workers) if workers is not None else sorted({*WORKER_SCRIPTS, *PLUGIN_WORKERS})
    processes, inventory_error = process_inventory()

    if inventory_error:
        return {
            name: {
                "worker": name, "code": 1,
                "decision": "refused_process_inventory_unavailable",
                "os_pids_running_script": [],
                "error": inventory_error,
            }
            for name in names
        }

    pids_by_worker: dict[str, list[int]] = {}
    for name in names:
        component_id = PLUGIN_WORKERS.get(name)
        script = "remote_access_plugin_host.py" if component_id else WORKER_SCRIPTS.get(name)
        marker = f"--component {component_id}" if component_id else None
        pids_by_worker[name] = (
            _match_pids(processes, script, command_marker=marker) if script else []
        )

    dsn = os.getenv("ADLOG_PG_DSN") or load_config().postgres_dsn
    if not dsn:
        return {
            name: {
                "worker": name, "code": 1, "decision": "refused_dsn_missing",
                "os_pids_running_script": pids_by_worker.get(name, []),
            }
            for name in names
        }

    try:
        conn = connect(str(dsn))
    except Exception as exc:
        return {
            name: {
                "worker": name, "code": 1, "decision": "refused_db_unreachable",
                "os_pids_running_script": pids_by_worker.get(name, []),
                "error": f"{type(exc).__name__}: {exc}",
            }
            for name in names
        }

    collection_block: tuple | None = None
    rows_by_worker: dict[str, tuple] = {}
    plugin_states: dict[str, tuple | None] = {}
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("set statement_timeout = 10000")
                cur.execute("set default_transaction_read_only = on")

                if "collection" in names:
                    cur.execute(
                        """
                        select active, reason_code, operator_action
                        from runtime_collection_blocks
                        where singleton_id = 1 and active
                        """
                    )
                    collection_block = cur.fetchone()

                normal_names = [n for n in names if n not in PLUGIN_WORKERS]
                if normal_names:
                    cur.execute(
                        """
                        select worker_name, worker_id, process_pid, status,
                               expected_interval_seconds, heartbeat_at,
                               extract(epoch from (now() - heartbeat_at)) as age_seconds
                        from runtime_worker_heartbeats
                        where worker_name = any(%s)
                        """,
                        (normal_names,),
                    )
                    for record in cur.fetchall():
                        worker_name, *rest = record
                        rows_by_worker[str(worker_name)] = tuple(rest)

                for name in names:
                    component_id = PLUGIN_WORKERS.get(name)
                    if component_id is None:
                        continue
                    cur.execute(
                        """
                        select desired_activation,component_runtime,
                               admission_mode
                        from read_plugin_component_runtime_guard_v1(%s,%s)
                        """,
                        ("sli.remote-access", component_id),
                    )
                    plugin_states[name] = cur.fetchone()
    except Exception as exc:
        return {
            name: {
                "worker": name, "code": 1, "decision": "refused_db_unreachable",
                "os_pids_running_script": pids_by_worker.get(name, []),
                "error": f"{type(exc).__name__}: {exc}",
            }
            for name in names
        }

    results: dict[str, dict[str, object]] = {}
    for name in names:
        pids = pids_by_worker.get(name, [])
        component_id = PLUGIN_WORKERS.get(name)
        if component_id is not None:
            code, decision, extra = _decide_plugin(
                component_id, pids=pids, plugin_state=plugin_states.get(name),
            )
        else:
            code, decision, extra = _decide_normal(
                name, pids=pids, row=rows_by_worker.get(name),
                collection_block=collection_block if name == "collection" else None,
            )
        results[name] = {
            "worker": name, "code": code, "decision": decision,
            "os_pids_running_script": pids, **extra,
        }
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--worker",
        required=True,
        choices=sorted((*WORKER_SCRIPTS, *PLUGIN_WORKERS)),
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report: dict[str, object] = {"worker": args.worker, "decision": "unknown"}

    def emit(code: int, decision: str, **extra: object) -> int:
        report["decision"] = decision
        report.update(extra)
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str)
              if args.json else f"{args.worker}: {decision}")
        return code

    component_id = PLUGIN_WORKERS.get(args.worker)
    script = (
        "remote_access_plugin_host.py"
        if component_id is not None
        else WORKER_SCRIPTS[args.worker]
    )
    marker = f"--component {component_id}" if component_id else None
    pids, inventory_error = _running_pids_for(
        script,
        command_marker=marker,
    )
    report["os_pids_running_script"] = pids
    if inventory_error:
        return emit(1, "refused_process_inventory_unavailable", error=inventory_error)

    dsn = os.getenv("ADLOG_PG_DSN") or load_config().postgres_dsn
    if not dsn:
        return emit(1, "refused_dsn_missing")

    try:
        import psycopg
    except Exception as exc:
        return emit(1, "refused_psycopg_missing", error=str(exc))

    try:
        with psycopg.connect(str(dsn), autocommit=True, connect_timeout=5,
                             application_name="sli_worker_guard") as conn:
            with conn.cursor() as cur:
                cur.execute("set statement_timeout = 10000")
                cur.execute("set default_transaction_read_only = on")

                if component_id is not None:
                    cur.execute(
                        """
                        select desired_activation,component_runtime,
                               admission_mode
                        from read_plugin_component_runtime_guard_v1(%s,%s)
                        """,
                        ("sli.remote-access", component_id),
                    )
                    plugin_state = cur.fetchone()
                    code, decision, extra = _decide_plugin(
                        component_id, pids=pids, plugin_state=plugin_state,
                    )
                    return emit(code, decision, **extra)

                collection_block = None
                if args.worker == "collection":
                    cur.execute(
                        """
                        select active, reason_code, operator_action
                        from runtime_collection_blocks
                        where singleton_id = 1 and active
                        """
                    )
                    collection_block = cur.fetchone()

                cur.execute(
                    """
                    select worker_id, process_pid, status, expected_interval_seconds,
                           heartbeat_at,
                           extract(epoch from (now() - heartbeat_at)) as age_seconds
                    from runtime_worker_heartbeats
                    where worker_name = %s
                    """,
                    (args.worker,),
                )
                row = cur.fetchone()
    except Exception as exc:
        return emit(1, "refused_db_unreachable", error=f"{type(exc).__name__}: {exc}")

    code, decision, extra = _decide_normal(
        args.worker, pids=pids, row=row, collection_block=collection_block,
    )
    return emit(code, decision, **extra)


if __name__ == "__main__":
    raise SystemExit(main())

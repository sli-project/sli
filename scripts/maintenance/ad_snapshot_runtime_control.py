#!/usr/bin/env python3
"""Fail-closed plan/apply control for the seven-root AD runtime cutover.

This controller never launches a worker itself.  An authorized apply can only
remove exact legacy root trees, then asks the existing supervisor to reload.
The coordinator's post-handoff heartbeat is read back before the handoff is
accepted.  ``plan`` is inventory-only and has no process, supervisor, or
heartbeat side effect beyond its one complete process observation.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RUNTIME = (ROOT / "scripts" / "runtime").resolve()
SUPERVISOR = (ROOT / "scripts" / "maintenance" / "worker_supervisor.py").resolve()
SUPERVISOR_RESTART = (ROOT / "scripts" / "ops" / "Restart-SLIWorkerSupervisor.ps1").resolve()
APPLY_TOKEN = "APPLY-EXACT-AD-SNAPSHOT-SOURCE-RUNTIME-CONTROL"
SUPERVISOR_RESTART_TOKEN = "RESTART-SLI-WORKER-SUPERVISOR-FOR-PLUGIN-AUTOSTART"

# Kept as explicit path anchors for manual diagnosis and compatibility callers.
AD_CONTEXT = (RUNTIME / "ad_context_snapshot_worker.py").resolve()
COORDINATOR = (RUNTIME / "ad_snapshot_manifest_coordinator_worker.py").resolve()
PROJECTION = (RUNTIME / "ad_snapshot_projection_worker.py").resolve()
V5 = (RUNTIME / "computers_report_v5_snapshot_worker.py").resolve()
V6_SOURCE = (RUNTIME / "computers_v6_source_worker.py").resolve()
COMPUTERS_V6 = (RUNTIME / "computers_report_v6_snapshot_worker.py").resolve()
USERS_V2 = (RUNTIME / "users_report_v2_snapshot_worker.py").resolve()

CANONICAL_AD_ROOT = "ad_snapshot_manifest_coordinator"
LEGACY_AD_ROOTS = (
    "ad_context_snapshot",
    "ad_snapshot_projection",
    "computers_v5_snapshot",
    "computers_v6_source",
    "computers_v6_snapshot",
    "users_v2_snapshot",
)
ALL_AD_RUNTIME_ROOTS = (CANONICAL_AD_ROOT, *LEGACY_AD_ROOTS)
UNRELATED_SUPERVISED_ROOTS = (
    "collection",
    "entity_state",
    "plugin_radius_acquisition",
    "plugin_radius_session_observation",
    "post_collection",
    "semantic",
    "storage_lifecycle",
    "what_where_when_projection",
)

# Names only are ever returned to the caller; values are never exposed.
CANONICAL_ADMISSION_KEYS = (
    "ADLOG_AD_CONTEXT_DIRECTORY_SERVER",
    "ADLOG_AD_CONTEXT_DOMAIN",
    "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS",
    "ADLOG_AD_CONTEXT_SEARCH_BASE",
    "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES",
    "ADLOG_COLLECTION_PRINCIPAL",
    "ADLOG_COLLECTION_PRINCIPAL_SID",
    "ADLOG_PG_DSN",
)


@dataclass(frozen=True)
class RuntimeRoot:
    """One process identity allowed in the closed runtime inventory."""

    name: str
    script: Path
    component_marker: str | None = None


ROOT_SPECS: dict[str, RuntimeRoot] = {
    "collection": RuntimeRoot("collection", RUNTIME / "collection_worker.py"),
    "ad_context_snapshot": RuntimeRoot("ad_context_snapshot", AD_CONTEXT),
    CANONICAL_AD_ROOT: RuntimeRoot(CANONICAL_AD_ROOT, COORDINATOR),
    "ad_snapshot_projection": RuntimeRoot("ad_snapshot_projection", PROJECTION),
    "computers_v5_snapshot": RuntimeRoot("computers_v5_snapshot", V5),
    "computers_v6_source": RuntimeRoot("computers_v6_source", V6_SOURCE),
    "computers_v6_snapshot": RuntimeRoot("computers_v6_snapshot", COMPUTERS_V6),
    "users_v2_snapshot": RuntimeRoot("users_v2_snapshot", USERS_V2),
    "entity_state": RuntimeRoot("entity_state", RUNTIME / "entity_state_worker.py"),
    "plugin_radius_acquisition": RuntimeRoot(
        "plugin_radius_acquisition",
        RUNTIME / "remote_access_plugin_host.py",
        "radius-acquisition",
    ),
    "plugin_radius_session_observation": RuntimeRoot(
        "plugin_radius_session_observation",
        RUNTIME / "remote_access_plugin_host.py",
        "radius-session-observation",
    ),
    "post_collection": RuntimeRoot("post_collection", RUNTIME / "post_collection_worker.py"),
    "semantic": RuntimeRoot("semantic", RUNTIME / "semantic_production_worker.py"),
    "storage_lifecycle": RuntimeRoot(
        "storage_lifecycle", RUNTIME / "storage_lifecycle_worker.py"
    ),
    "what_where_when_projection": RuntimeRoot(
        "what_where_when_projection", RUNTIME / "what_where_when_projection_worker.py"
    ),
}

# These roots can be absent only when the supervisor's pre-existing admission
# is explicitly false.  All other unrelated roots are mandatory preservation
# baselines for an apply.
_ADMISSION_GATED_UNRELATED_ROOTS = frozenset({"semantic", "storage_lifecycle"})
_TOKEN_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'|([^\s]+)')


def _norm(value: object) -> str:
    return str(value or "").replace("\\", "/").strip().casefold()


def _command_tokens(command_line: object) -> list[str]:
    """Return a conservative Windows-command token view without echoing it."""

    value = str(command_line or "")
    return [next((part for part in match if part), "") for match in _TOKEN_RE.findall(value)]


def _normalized_basename(value: object) -> str:
    token = _norm(value).strip("\"'")
    return token.rsplit("/", 1)[-1]


def _absolute_script_path(value: object) -> str | None:
    value = str(value or "").replace("\\", "/")
    if not value or value != value.strip() or "\x00" in value:
        return None
    if not (value.startswith("/") or re.match(r"^[A-Za-z]:/", value)):
        return None
    if any(part in {".", ".."} for part in value.split("/")):
        return None
    return value.casefold()


def _has_exact_script(command_line: object, path: Path) -> bool:
    """Authorize only Python's absolute script operand, never arbitrary args.

    Relative paths, command/module execution and unknown interpreter options are
    deliberately excluded: inventory has no trustworthy working directory.
    """
    command = str(command_line or "")
    if not re.fullmatch(r"\s*(?:\"[^\"]*\"|[^\s\"']+)(?:\s+(?:\"[^\"]*\"|[^\s\"']+))*\s*", command):
        return False
    tokens = _command_tokens(command)
    if not tokens or not re.fullmatch(r"python(?:[0-9]+(?:\.[0-9]+)?)?(?:w)?(?:\.exe)?", _normalized_basename(tokens[0])):
        return False
    index = 1
    while index < len(tokens) and tokens[index] in {"-u", "-B", "-E", "-I", "-s", "-S", "-O", "-OO"}:
        index += 1
    if index < len(tokens) and tokens[index] == "--":
        index += 1
    expected = _absolute_script_path(path)
    return expected is not None and index < len(tokens) and _absolute_script_path(tokens[index]) == expected


def _has_exact_component_marker(command_line: object, marker: str | None) -> bool:
    if marker is None:
        return True
    tokens = [_norm(token).strip("\"'") for token in _command_tokens(command_line)]
    expected = _norm(marker)
    for index, token in enumerate(tokens):
        if token == "--component" and index + 1 < len(tokens) and tokens[index + 1] == expected:
            return True
        if token == f"--component={expected}":
            return True
    return False


def _matches_root(command_line: object, root: RuntimeRoot) -> bool:
    return _has_exact_script(command_line, root.script) and _has_exact_component_marker(
        command_line, root.component_marker
    )


def _root_spec(value: RuntimeRoot | Path) -> RuntimeRoot:
    if isinstance(value, RuntimeRoot):
        return value
    return RuntimeRoot("anonymous", Path(value), None)


def _tree(
    processes: Sequence[Mapping[str, object]], script: RuntimeRoot | Path
) -> tuple[list[int], list[int]]:
    """Find exact component roots and their complete descendant closure."""

    root = _root_spec(script)
    parents = {int(row["pid"]): int(row.get("parent_pid") or 0) for row in processes}
    candidates = {
        int(row["pid"])
        for row in processes
        if _matches_root(row.get("command_line"), root)
    }

    def has_matching_ancestor(pid: int) -> bool:
        seen = {pid}
        current = parents.get(pid, 0)
        while current and current not in seen:
            if current in candidates:
                return True
            seen.add(current)
            current = parents.get(current, 0)
        return False

    roots = sorted(pid for pid in candidates if not has_matching_ancestor(pid))
    selected = set(roots)
    while True:
        added = {
            int(row["pid"])
            for row in processes
            if int(row.get("parent_pid") or 0) in selected
        } - selected
        if not added:
            break
        selected.update(added)
    return roots, sorted(selected)


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("utc_now_must_return_timezone_aware_datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: object) -> datetime | None:
    if isinstance(value, datetime):
        stamp = value
    elif isinstance(value, str):
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        return None
    return stamp.astimezone(timezone.utc)


def _coerce_inventory(
    observed: object,
) -> tuple[list[Mapping[str, object]], bool, str]:
    if isinstance(observed, Mapping):
        rows = observed.get("processes")
        complete = observed.get("complete") is True
        source = str(observed.get("source") or "unspecified")
    else:
        rows = observed
        complete = isinstance(rows, (list, tuple))
        source = "injected"
    if not complete:
        raise RuntimeError("process_inventory_incomplete")
    if not isinstance(rows, (list, tuple)) or not all(isinstance(row, Mapping) for row in rows):
        raise RuntimeError("process_inventory_invalid")
    return list(rows), complete, source


def _validate_process_rows(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    pids: set[int] = set()
    for row in rows:
        raw_pid = row.get("pid")
        raw_parent = row.get("parent_pid", 0)
        if isinstance(raw_pid, bool) or isinstance(raw_parent, bool):
            raise RuntimeError("process_inventory_invalid_pid")
        try:
            pid = int(raw_pid)  # type: ignore[arg-type]
            parent_pid = int(raw_parent or 0)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise RuntimeError("process_inventory_invalid_pid") from exc
        # Win32_Process can include the System Idle Process (PID 0).  It is
        # not a worker and has no topology identity, so exclude only its known
        # pid=0,parent_pid=0 shape before applying the real-process checks.
        if pid == 0 and parent_pid == 0:
            continue
        if pid <= 0 or parent_pid < 0 or pid in pids:
            raise RuntimeError("process_inventory_ambiguous_pid")
        pids.add(pid)
        normalized.append(
            {
                "pid": pid,
                "parent_pid": parent_pid,
                "command_line": str(row.get("command_line") or ""),
                "creation_time": str(row.get("creation_time") or ""),
            }
        )
    parents = {int(row["pid"]): int(row["parent_pid"]) for row in normalized}
    for pid in parents:
        seen: set[int] = set()
        current = pid
        while current in parents:
            if current in seen:
                raise RuntimeError("process_inventory_ambiguous_tree")
            seen.add(current)
            current = parents[current]
    return normalized


def _snapshot(
    observed: object,
    *,
    utc_now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    rows, complete, source = _coerce_inventory(observed)
    processes = _validate_process_rows(rows)
    values: dict[str, object] = {
        "observed_at_utc": _utc_timestamp(utc_now()),
        "inventory_complete": complete,
        "inventory_source": source,
    }
    supervisor_roots, supervisor_tree = _tree(processes, SUPERVISOR)
    values["supervisor_root_pids"] = supervisor_roots
    values["supervisor_tree_pids"] = supervisor_tree

    ad_roots: dict[str, dict[str, list[int]]] = {}
    unrelated_roots: dict[str, dict[str, list[int]]] = {}
    for name in ALL_AD_RUNTIME_ROOTS + UNRELATED_SUPERVISED_ROOTS:
        roots, tree = _tree(processes, ROOT_SPECS[name])
        values[f"{name}_root_pids"] = roots
        values[f"{name}_tree_pids"] = tree
        destination = ad_roots if name in ALL_AD_RUNTIME_ROOTS else unrelated_roots
        destination[name] = {"root_pids": roots, "tree_pids": tree}
    values["ad_roots"] = ad_roots
    values["unrelated_roots"] = unrelated_roots

    legacy_root_pids = sorted(
        {pid for name in LEGACY_AD_ROOTS for pid in values[f"{name}_root_pids"]}  # type: ignore[index]
    )
    legacy_tree_pids = sorted(
        {pid for name in LEGACY_AD_ROOTS for pid in values[f"{name}_tree_pids"]}  # type: ignore[index]
    )
    by_pid = {int(row["pid"]): row for row in processes}
    values["legacy_target_identities"] = {
        pid: {"creation_time": by_pid[pid]["creation_time"], "root_name": name}
        for name in LEGACY_AD_ROOTS for pid in values[f"{name}_root_pids"]
    }
    values["legacy_target_root_pids"] = legacy_root_pids
    values["legacy_target_tree_pids"] = legacy_tree_pids
    values["legacy_target_wrapper_pids"] = sorted(set(legacy_tree_pids) - set(legacy_root_pids))
    return values


def inventory_processes() -> dict[str, object]:
    """Capture the full local Windows process inventory through one CIM query."""

    if os.name != "nt":
        raise RuntimeError("exact_runtime_control_requires_windows_cim_inventory")
    script = (
        "$ErrorActionPreference='Stop'; Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,ParentProcessId,CommandLine,CreationDate | ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("process_inventory_failed")
    try:
        raw = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError("process_inventory_invalid_json") from exc
    rows = raw if isinstance(raw, list) else [raw]
    if not all(isinstance(row, Mapping) for row in rows):
        raise RuntimeError("process_inventory_invalid")
    return {
        "complete": True,
        "source": "powershell_cim",
        "processes": [
            {
                "pid": int(row["ProcessId"]),
                "parent_pid": int(row.get("ParentProcessId") or 0),
                "command_line": str(row.get("CommandLine") or ""),
                "creation_time": str(row.get("CreationDate") or ""),
            }
            for row in rows
        ],
    }


def _revalidate_target(pid: int, expected: Mapping[str, object]) -> None:
    """Fresh identity check immediately before PID-based termination.

    This narrows PID reuse exposure; taskkill is not an atomic identity-bound
    operation, so a residual check-to-use race remains.
    """
    rows, complete, _source = _coerce_inventory(inventory_processes())
    rows = _validate_process_rows(rows)
    current = next((row for row in rows if row["pid"] == pid), None)
    root = ROOT_SPECS[str(expected["root_name"])]
    if (not complete or not expected.get("creation_time") or current is None
            or current["creation_time"] != expected["creation_time"]
            or not _matches_root(current["command_line"], root)):
        raise RuntimeError(f"target_identity_changed_or_unavailable:{pid}")


def _stop_tree(pid: int) -> None:
    completed = subprocess.run(
        ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"exact_tree_stop_failed:{int(pid)}")


def _restart_supervisor(token: str) -> None:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SUPERVISOR_RESTART),
            "-Action",
            "Restart",
            "-Confirmation",
            token,
        ],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("canonical_supervisor_restart_failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("canonical_supervisor_restart_invalid_response") from exc
    if not isinstance(payload, Mapping) or payload.get("status") != "accepted":
        raise RuntimeError("canonical_supervisor_restart_not_accepted")


def _heartbeat() -> dict[str, object]:
    """Read exactly one coordinator heartbeat; never write or start a worker."""

    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            """select worker_name,worker_id,process_pid,status,phase,
                      expected_interval_seconds,heartbeat_at
                 from runtime_worker_heartbeats
                 where worker_name='ad_snapshot_manifest_coordinator'"""
        )
        rows = [dict(row) for row in cursor.fetchall()]
    if len(rows) != 1:
        raise RuntimeError("coordinator_heartbeat_not_exactly_one")
    return rows[0]


def _supervisor_allows_old_workers() -> bool:
    from server.sli.ops.runtime_component_registry import get

    return any(get(name).supervised or get(name).feature_enabled for name in LEGACY_AD_ROOTS)


def _canonical_admission(
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    values = environ if environ is not None else os.environ
    usable = sorted(
        key for key in CANONICAL_ADMISSION_KEYS if str(values.get(key) or "").strip()
    )
    missing = sorted(set(CANONICAL_ADMISSION_KEYS) - set(usable))
    return {
        "status": "ok" if not missing else "blocked",
        "canonical_admission_keys": usable,
        "missing_key_names": missing,
    }


def _load_sealed_supervisor_environment() -> None:
    """Populate this controller's process environment from the DPAPI payload."""

    from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment

    result = load_supervisor_environment(override_existing=True)
    if not isinstance(result, Mapping) or result.get("status") != "ok":
        raise RuntimeError("sealed_supervisor_environment_invalid")


def _static_ownership_check(
    *,
    identity_check: Callable[[], Mapping[str, object]] | None = None,
    admission_check: Callable[[], Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Validate static ownership without exposing identity or config values."""

    # Direct controller admission reads its own process environment.  Use the
    # same canonical sealed payload as the supervisor before either default
    # identity or admission verification; fully injected checks stay isolated.
    if identity_check is None or admission_check is None:
        _load_sealed_supervisor_environment()

    from scripts.maintenance import worker_supervisor
    from server.sli.ops.runtime_component_registry import list_components
    from server.sli.sources.windows_runtime_identity import verify_collection_identity

    identity = dict((identity_check or verify_collection_identity)() or {})
    admission = dict((admission_check or _canonical_admission)() or {})
    components = {component.name: component for component in list_components()}
    managed = set(worker_supervisor.MANAGED)
    start_order = set(worker_supervisor.START_ORDER)
    reasons: list[str] = []

    if identity.get("status") != "ok":
        reasons.append("collection_identity_invalid")
    if admission.get("status") != "ok":
        reasons.append("canonical_admission_missing")
    usable_keys = sorted(
        str(key)
        for key in admission.get("canonical_admission_keys", [])
        if str(key) in CANONICAL_ADMISSION_KEYS
    )
    if set(usable_keys) != set(CANONICAL_ADMISSION_KEYS):
        reasons.append("canonical_admission_keys_incomplete")

    if set(name for name in managed if name in ALL_AD_RUNTIME_ROOTS) != {CANONICAL_AD_ROOT}:
        reasons.append("managed_ad_membership_invalid")
    if set(name for name in start_order if name in ALL_AD_RUNTIME_ROOTS) != {CANONICAL_AD_ROOT}:
        reasons.append("start_order_ad_membership_invalid")
    if not set(UNRELATED_SUPERVISED_ROOTS) <= managed:
        reasons.append("managed_unrelated_membership_invalid")
    if not set(UNRELATED_SUPERVISED_ROOTS) <= start_order:
        reasons.append("start_order_unrelated_membership_invalid")

    canonical = components.get(CANONICAL_AD_ROOT)
    canonical_spec = ROOT_SPECS[CANONICAL_AD_ROOT]
    if (
        canonical is None
        or not canonical.feature_enabled
        or not canonical.supervised
        or canonical.expected_interval_seconds != 43200
        or canonical.script != canonical_spec.script.name
        or worker_supervisor.MANAGED.get(CANONICAL_AD_ROOT)
        != (canonical_spec.script.name, ["--no-initial-delay"])
    ):
        reasons.append("canonical_component_contract_invalid")
    for name in LEGACY_AD_ROOTS:
        component = components.get(name)
        spec = ROOT_SPECS[name]
        if (
            component is None
            or component.feature_enabled
            or component.supervised
            or component.script != spec.script.name
        ):
            reasons.append(f"legacy_component_contract_invalid:{name}")

    admission_refused_roots = sorted(
        name
        for name in _ADMISSION_GATED_UNRELATED_ROOTS
        if (
            name == "semantic"
            and not worker_supervisor.semantic_production_admitted()
        )
        or (
            name == "storage_lifecycle"
            and not worker_supervisor.storage_lifecycle_admitted()
        )
    )
    return {
        "status": "ok" if not reasons else "blocked",
        "identity_status": "ok" if identity.get("status") == "ok" else "blocked",
        "canonical_admission_keys": usable_keys,
        "unrelated_admission_refused_roots": admission_refused_roots,
        "reasons": sorted(reasons),
    }


def _safe_static_result(raw: Mapping[str, object]) -> dict[str, object]:
    status = "ok" if raw.get("status") == "ok" else "blocked"
    keys = sorted(
        {str(key) for key in raw.get("canonical_admission_keys", []) if str(key) in CANONICAL_ADMISSION_KEYS}
    )
    refused = sorted(
        {
            str(name)
            for name in raw.get("unrelated_admission_refused_roots", [])
            if str(name) in _ADMISSION_GATED_UNRELATED_ROOTS
        }
    )
    return {
        "status": status,
        "identity_status": "ok" if raw.get("identity_status") == "ok" else "blocked",
        "canonical_admission_keys": keys,
        "unrelated_admission_refused_roots": refused,
    }


def _validate_static(
    *,
    static_check: Callable[[], Mapping[str, object]] | None,
    supervisor_allows: Callable[[], bool] | None,
    identity_check: Callable[[], Mapping[str, object]] | None,
    admission_check: Callable[[], Mapping[str, object]] | None,
) -> dict[str, object]:
    raw = (
        static_check()
        if static_check is not None
        else _static_ownership_check(
            identity_check=identity_check,
            admission_check=admission_check,
        )
    )
    if not isinstance(raw, Mapping):
        raise RuntimeError("static_runtime_ownership_invalid")
    static = _safe_static_result(raw)
    if supervisor_allows is not None and supervisor_allows():
        raise RuntimeError("supervisor_configuration_can_relaunch_legacy_worker")
    if static["status"] != "ok" or static["identity_status"] != "ok":
        raise RuntimeError("static_runtime_ownership_invalid")
    if set(static["canonical_admission_keys"]) != set(CANONICAL_ADMISSION_KEYS):
        raise RuntimeError("canonical_admission_keys_missing")
    return static


def _roots(snapshot: Mapping[str, object], name: str) -> list[int]:
    return list(snapshot[f"{name}_root_pids"])  # type: ignore[arg-type,index]


def _tree_pids(snapshot: Mapping[str, object], name: str) -> list[int]:
    return list(snapshot[f"{name}_tree_pids"])  # type: ignore[arg-type,index]


def _owned(
    processes: Sequence[Mapping[str, object]], child_pid: int, supervisor_pids: set[int]
) -> bool:
    parents = {int(row["pid"]): int(row.get("parent_pid") or 0) for row in processes}
    seen: set[int] = set()
    current = int(child_pid)
    while current and current not in seen:
        if current in supervisor_pids:
            return True
        seen.add(current)
        current = parents.get(current, 0)
    return False


def _validate_before(
    before: Mapping[str, object], static: Mapping[str, object]
) -> None:
    if len(_roots(before, "supervisor")) != 1:
        raise RuntimeError("exact_supervisor_baseline_missing_or_ambiguous")
    for name in ALL_AD_RUNTIME_ROOTS + UNRELATED_SUPERVISED_ROOTS:
        if len(_roots(before, name)) > 1:
            raise RuntimeError(f"exact_worker_inventory_has_multiple_roots:{name}")

    for index, left in enumerate(LEGACY_AD_ROOTS):
        left_tree = set(_tree_pids(before, left))
        for right in LEGACY_AD_ROOTS[index + 1 :]:
            right_tree = set(_tree_pids(before, right))
            if set(_roots(before, right)) & left_tree or set(_roots(before, left)) & right_tree:
                raise RuntimeError("legacy_descendant_closure_cross_component")

    target = set(before["legacy_target_tree_pids"])  # type: ignore[arg-type,index]
    protected = set(_roots(before, "supervisor")) | set(_tree_pids(before, CANONICAL_AD_ROOT))
    for name in UNRELATED_SUPERVISED_ROOTS:
        protected.update(_tree_pids(before, name))
    if target & protected:
        raise RuntimeError("legacy_target_intersects_protected_tree")

    refused = set(static["unrelated_admission_refused_roots"])  # type: ignore[arg-type,index]
    supervisor_tree = set(_tree_pids(before, "supervisor"))
    for name in UNRELATED_SUPERVISED_ROOTS:
        roots = _roots(before, name)
        if not roots:
            if name not in refused:
                raise RuntimeError(f"unrelated_root_missing_without_admission_refusal:{name}")
            continue
        if name in refused:
            raise RuntimeError(f"unrelated_root_conflicts_with_admission_refusal:{name}")
        if roots[0] not in supervisor_tree:
            raise RuntimeError(f"unrelated_root_not_supervisor_owned:{name}")


def _assert_legacy_absent(snapshot: Mapping[str, object], *, phase: str) -> None:
    if any(_roots(snapshot, name) or _tree_pids(snapshot, name) for name in LEGACY_AD_ROOTS):
        raise RuntimeError(f"legacy_target_tree_present_{phase}")


def _validate_after(
    *,
    before: Mapping[str, object],
    after: Mapping[str, object],
    static: Mapping[str, object],
) -> None:
    if len(_roots(after, "supervisor")) != 1:
        raise RuntimeError("post_handoff_supervisor_missing_or_ambiguous")
    if len(_roots(after, CANONICAL_AD_ROOT)) != 1:
        raise RuntimeError("post_handoff_canonical_missing_or_ambiguous")
    supervisor_tree = set(_tree_pids(after, "supervisor"))
    canonical_root = _roots(after, CANONICAL_AD_ROOT)[0]
    if canonical_root not in supervisor_tree:
        raise RuntimeError("post_handoff_canonical_not_supervisor_owned")
    _assert_legacy_absent(after, phase="after")

    refused = set(static["unrelated_admission_refused_roots"])  # type: ignore[arg-type,index]
    for name in UNRELATED_SUPERVISED_ROOTS:
        before_roots = _roots(before, name)
        after_roots = _roots(after, name)
        if before_roots:
            if len(after_roots) != 1 or after_roots[0] not in supervisor_tree:
                raise RuntimeError(f"unrelated_root_not_preserved:{name}")
        elif name not in refused:
            raise RuntimeError(f"unrelated_baseline_missing:{name}")
        elif after_roots:
            raise RuntimeError(f"admission_refused_unrelated_root_started:{name}")


def _safe_heartbeat(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    allowed = (
        "worker_name",
        "worker_id",
        "process_pid",
        "status",
        "phase",
        "expected_interval_seconds",
        "heartbeat_at",
    )
    return {name: value.get(name) for name in allowed}


def _heartbeat_ready(
    value: object,
    *,
    after: Mapping[str, object],
    handoff_marker: datetime,
) -> tuple[bool, dict[str, object] | None]:
    rows: list[object]
    if isinstance(value, Mapping):
        rows = [value]
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        rows = list(value)
    else:
        return False, None
    if len(rows) != 1:
        return False, None
    row = _safe_heartbeat(rows[0])
    if row is None:
        return False, None
    try:
        process_pid = int(row.get("process_pid") or 0)
        interval = int(row.get("expected_interval_seconds") or 0)
    except (TypeError, ValueError):
        return False, None
    heartbeat_at = _parse_utc(row.get("heartbeat_at"))
    status = str(row.get("status") or "").strip().casefold()
    canonical_roots = _roots(after, CANONICAL_AD_ROOT)
    canonical_tree = set(_tree_pids(after, CANONICAL_AD_ROOT))
    supervisor_tree = set(_tree_pids(after, "supervisor"))
    ready = (
        row.get("worker_name") == CANONICAL_AD_ROOT
        and bool(str(row.get("worker_id") or "").strip())
        and len(canonical_roots) == 1
        and process_pid in canonical_tree
        and process_pid in supervisor_tree
        and interval == 43200
        and bool(status)
        and status not in {"failed", "failure", "error", "blocked", "stopped", "unknown"}
        and heartbeat_at is not None
        and heartbeat_at > handoff_marker
    )
    return ready, row if ready else None


def _rollback_plan() -> dict[str, object]:
    return {
        "automatic_legacy_relaunch": False,
        "automatic_rollback": False,
        "manual_rollback_only": True,
        "legacy_root_names": list(LEGACY_AD_ROOTS),
    }


def run(
    *,
    action: str,
    confirmation: str | None,
    inventory: Callable[[], object] = inventory_processes,
    stop_tree: Callable[[int], None] = _stop_tree,
    validate_target: Callable[[int, Mapping[str, object]], None] = _revalidate_target,
    restart_supervisor: Callable[[str], None] = _restart_supervisor,
    heartbeat: Callable[[], object] = _heartbeat,
    supervisor_allows: Callable[[], bool] | None = _supervisor_allows_old_workers,
    static_check: Callable[[], Mapping[str, object]] | None = None,
    identity_check: Callable[[], Mapping[str, object]] | None = None,
    admission_check: Callable[[], Mapping[str, object]] | None = None,
    readiness_timeout_seconds: float = 60,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Any] = time.sleep,
    utc_now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, object]:
    """Build an inventory-only plan or execute the bounded six-root handoff."""

    if action not in {"plan", "apply"}:
        raise ValueError("unsupported_action")
    if readiness_timeout_seconds <= 0:
        raise ValueError("readiness_timeout_seconds_must_be_positive")

    if action == "plan":
        before = _snapshot(inventory(), utc_now=utc_now)
        return {
            "status": "planned",
            "state": "planned",
            "action": "plan",
            "confirmation_required": APPLY_TOKEN,
            "surveyed_systems_contacted": False,
            "before": before,
            "rollback_plan": _rollback_plan(),
        }

    # No inventory, identity, or process mutation runs before exact confirmation.
    if confirmation != APPLY_TOKEN:
        raise RuntimeError(f"apply_requires_exact_confirmation:{APPLY_TOKEN}")
    static = _validate_static(
        static_check=static_check,
        supervisor_allows=supervisor_allows,
        identity_check=identity_check,
        admission_check=admission_check,
    )
    before = _snapshot(inventory(), utc_now=utc_now)
    _validate_before(before, static)

    target_roots = list(before["legacy_target_root_pids"])  # type: ignore[arg-type,index]
    # The ordered loop is deliberately over root PIDs only.  Descendants are
    # never passed directly to taskkill, and no coordinator launch path exists.
    identities = before["legacy_target_identities"]
    # Validate every captured identity before any mutation, then refresh each
    # root immediately before its individual stop.
    for pid in target_roots:
        if not identities[pid]["creation_time"]:
            raise RuntimeError(f"target_identity_missing:{pid}")
    for pid in target_roots:
        validate_target(int(pid), identities[pid])
        stop_tree(int(pid))

    after_stop = _snapshot(inventory(), utc_now=utc_now)
    _assert_legacy_absent(after_stop, phase="after_stop")

    restart_supervisor(SUPERVISOR_RESTART_TOKEN)
    handoff_marker = utc_now()
    if handoff_marker.tzinfo is None or handoff_marker.utcoffset() is None:
        raise ValueError("utc_now_must_return_timezone_aware_datetime")
    handoff_marker = handoff_marker.astimezone(timezone.utc)
    deadline = monotonic() + readiness_timeout_seconds

    while True:
        candidate = _snapshot(inventory(), utc_now=utc_now)
        _assert_legacy_absent(candidate, phase="poll")
        structural_ready = True
        try:
            _validate_after(before=before, after=candidate, static=static)
        except RuntimeError:
            structural_ready = False

        heartbeat_row: dict[str, object] | None = None
        if structural_ready:
            try:
                heartbeat_value = heartbeat()
            except Exception:
                heartbeat_value = None
            heartbeat_ready, heartbeat_row = _heartbeat_ready(
                heartbeat_value,
                after=candidate,
                handoff_marker=handoff_marker,
            )
            if heartbeat_ready:
                return {
                    "status": "accepted",
                    "state": "accepted",
                    "action": "apply",
                    "confirmation_required": APPLY_TOKEN,
                    "surveyed_systems_contacted": False,
                    "static": static,
                    "before": before,
                    "after_stop": after_stop,
                    "after": candidate,
                    "legacy_target_root_pids": target_roots,
                    "legacy_target_tree_pids": list(before["legacy_target_tree_pids"]),  # type: ignore[arg-type,index]
                    "all_legacy_roots_absent": True,
                    "coordinator_supervisor_owned": True,
                    "unrelated_roots_preserved": True,
                    "coordinator_pid": _roots(candidate, CANONICAL_AD_ROOT)[0],
                    "heartbeat": heartbeat_row,
                    "rollback_plan": _rollback_plan(),
                }

        if monotonic() >= deadline:
            raise RuntimeError("coordinator_readiness_timeout")
        sleep(min(1.0, max(0.0, deadline - monotonic())))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    action = "apply" if args.apply else "plan"
    try:
        result = run(action=action, confirmation=args.confirm)
    except Exception as exc:
        # Do not serialize arbitrary exception strings: subprocess/driver errors
        # can contain sensitive command or configuration fragments.
        result = {
            "status": "error",
            "state": "blocked",
            "action": action,
            "error_type": type(exc).__name__,
            "error_code": "runtime_control_failed",
        }
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0 if result["status"] in {"planned", "accepted"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

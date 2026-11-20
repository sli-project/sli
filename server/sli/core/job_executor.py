"""Core executor pools with disposable, bounded Linux handler/publisher processes."""
from __future__ import annotations

import argparse
import builtins
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from threading import Event
import time

from server.sli.core import job_queue as queue
from server.sli.core.job_registry import PROFILES, pilot_registry
from server.sli.core.secret_files import secret_value
from server.sli.plugins.registry import plugin_job_handlers, plugin_installed
from server.sli.plugins.update_runtime import admission, optional_admission, pin_job

FLAG = "SLI_CORE_JOB_RADIUS_PILOT"
HEARTBEAT = Path("/tmp/sli-executor-{profile}.json")
STOP = Event()
ERROR_CODES = frozenset({
    "executor_profile_invalid", "executor_secret_missing", "executor_purpose_invalid",
    "executor_secret_file_required", "executor_identity_invalid", "radius_pilot_source_required",
    "manifest_shape_invalid", "handler_core_api_incompatible", "handler_dependency_unavailable",
    "handler_not_allowlisted", "handler_registration_duplicate", "schedule_reference_invalid",
    "schedule_trigger_invalid", "handler_version_unavailable", "plugin_update_invalid_id",
    "plugin_update_invalid_generation", "plugin_update_draining",
})


def report_failure(error: Exception) -> None:
    """Log only known codes and machine diagnostics, never SQL, rows or exception text."""
    import psycopg

    kind = type(error)
    name = kind.__name__
    trusted_type = (getattr(builtins, name, None) is kind
                    or getattr(psycopg, name, None) is kind
                    or getattr(psycopg.errors, name, None) is kind)
    diagnostic = {"error_type": name if trusted_type else "Exception", "error_code": "unexpected_error"}
    if kind in {ValueError, RuntimeError} and error.args and type(error.args[0]) is str:
        if error.args[0] in ERROR_CODES:
            diagnostic["error_code"] = error.args[0]
    if isinstance(error, OSError):
        diagnostic["error_code"] = "os_error"
        if type(error.errno) is int:
            diagnostic["errno"] = error.errno
    if isinstance(error, psycopg.Error):
        diagnostic["error_code"] = "database_error"
        if isinstance(error.sqlstate, str) and re.fullmatch(r"[0-9A-Z]{5}", error.sqlstate):
            diagnostic["sqlstate"] = error.sqlstate
        if (error.sqlstate == "23514" and error.diag.schema_name == "sli_jobs"
                and error.diag.table_name == "jobs" and error.diag.constraint_name == "jobs_check1"):
            diagnostic["error_code"] = "job_deadline_constraint"
    print("core_executor_failed", queue.canonical(diagnostic), file=sys.stderr, flush=True)


def pilot_enabled() -> bool:
    return os.environ.get(FLAG, "0") == "1" and plugin_installed("sli.remote-access")


def connection_settings(profile: str, purpose: str) -> dict:
    """Each identity connects directly; shared sessions never change their role."""
    if profile not in PROFILES or purpose not in {"dispatcher", "executor", "publisher"}:
        raise ValueError("executor_profile_invalid")
    password = secret_value(f"SLI_JOB_{purpose.upper()}_{profile.upper()}_PASSWORD")
    if not password:
        raise ValueError("executor_secret_missing")
    return {
        "host": os.environ.get("SLI_JOB_PG_HOST", "postgres"),
        "port": 5432, "dbname": "sli", "user": f"sli_job_{purpose}_{profile}",
        "password": password,
        "connect_timeout": 5, "autocommit": True,
        "options": "-c statement_timeout=10000 -c lock_timeout=1000 -c search_path=pg_catalog,public",
    }


@contextmanager
def connect(profile: str, purpose: str):
    import psycopg

    with psycopg.connect(**connection_settings(profile, purpose)) as conn:
        yield conn


def kill_group(process) -> None:
    """Also remove descendants after success, crash, lost lease or shutdown."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_child(job: dict, purpose: str, *, heartbeat=None, deadline: float,
              clock=time.monotonic, sleep=time.sleep, popen=subprocess.Popen,
              terminate=kill_group) -> dict:
    profile = job["resource_profile"]
    started = time.monotonic()
    peak_memory = 0
    drain_deadline = None
    if purpose not in {"handler", "publisher"}:
        raise ValueError("executor_purpose_invalid")
    identity = "executor" if purpose == "handler" else "publisher"
    password_name = f"SLI_JOB_{identity.upper()}_{profile.upper()}_PASSWORD"
    password_file = os.environ.get(f"{password_name}_FILE")
    if not password_file:
        raise ValueError("executor_secret_file_required")
    settings = connection_settings(profile, identity)
    settings.pop("password", None)
    # No runtime/admin/other-profile credentials in the child's environment.
    env = {key: os.environ[key] for key in ("PATH", "PYTHONPATH", "LANG", "SLI_PLUGIN_RUNTIME_DIR", "SLI_PLUGIN_LOCK_DIR")
           if key in os.environ}
    env.update(PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1",
               SLI_JOB_CHILD_CONNECTION=queue.canonical(settings))
    env[f"{password_name}_FILE"] = password_file
    # Preserve registration switches in disposable children; never forward secrets.
    from server.sli.sources.ad_gpo_jobs import FLAG as snapshot_flag, enabled as snapshots_enabled

    if snapshots_enabled():
        env[snapshot_flag] = "1"
    from server.sli.plugins.workstations.jobs import FLAG as workstation_flag, enabled as workstations_enabled

    if os.environ.get(workstation_flag, "0") == "1" and workstations_enabled():
        env[workstation_flag] = "1"
    from server.sli.plugins.workstations import projection_jobs

    env[projection_jobs.FLAG] = "1" if projection_jobs.enabled() else "0"
    if job["plugin_id"] == "sli.workstations" and job["handler_id"] != projection_jobs.HANDLER_ID:
        # Only the history publisher needs this secret file; never forward passwords.
        for name in ("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS", "ADLOG_HISTORY_READ_MODE"):
            if name in os.environ:
                env[name] = os.environ[name]
        if purpose == "publisher":
            for name in ("ADLOG_HISTORY_CLICKHOUSE_HOST", "ADLOG_HISTORY_CLICKHOUSE_PORT",
                         "ADLOG_HISTORY_CLICKHOUSE_USER", "ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE",
                         "ADLOG_DATA_DIR"):
                if name in os.environ:
                    env[name] = os.environ[name]
    with tempfile.TemporaryDirectory(prefix="sli-job-") as directory:
        request = Path(directory) / "request.json"
        response = Path(directory) / "response.json"
        request.write_text(queue.canonical(job), encoding="utf-8")
        with request.open("rb") as stdin, response.open("wb") as stdout:
            process = popen([sys.executable, "-m", __name__, "--child", purpose,
                             "--profile", profile], stdin=stdin, stdout=stdout,
                            stderr=subprocess.DEVNULL, env=env, start_new_session=True)
            next_heartbeat = clock() + 10
            try:
                while process.poll() is None:
                    now = clock()
                    if STOP.is_set() and drain_deadline is None:
                        drain_deadline = now + 30
                    if drain_deadline is not None:
                        deadline = min(deadline, drain_deadline)
                    if now >= deadline:
                        raise TimeoutError("job_deadline_exceeded")
                    try:
                        status = Path(f"/proc/{process.pid}/status").read_text("ascii")
                        peak_memory = max(peak_memory, next(
                            int(line.split()[1]) * 1024 for line in status.splitlines()
                            if line.startswith("VmHWM:")))
                    except (OSError, StopIteration, ValueError):
                        pass
                    if heartbeat is not None and now >= next_heartbeat:
                        heartbeat()
                        next_heartbeat = now + 10
                    sleep(0.1)
                if clock() >= deadline:
                    raise TimeoutError("job_deadline_exceeded")
                if process.returncode != 0:
                    raise RuntimeError("job_child_failed")
            finally:
                terminate(process)
        if response.stat().st_size > job["budget"]["max_result_bytes"]:
            raise ValueError("job_result_budget_exceeded")
        result = json.loads(response.read_text("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("job_result_invalid")
        return {**result, "resource_usage": {"wall_seconds": time.monotonic()-started,
                                              "peak_memory_bytes": peak_memory or None}}


def stage_radius(conn, job: dict) -> dict:
    stage, _ = plugin_job_handlers("sli.remote-access", job["handler_id"])
    return stage(conn, job)


def apply_radius(conn, job: dict, result: dict) -> None:
    _, apply = plugin_job_handlers("sli.remote-access", job["handler_id"])
    apply(conn, job, result)


def child_connection_settings(profile: str, purpose: str) -> dict:
    """Read only the declared identity's secret file; never accept env passwords."""
    if profile not in PROFILES or purpose not in {"handler", "publisher"}:
        raise ValueError("executor_profile_invalid")
    identity = "executor" if purpose == "handler" else "publisher"
    settings = json.loads(os.environ.pop("SLI_JOB_CHILD_CONNECTION"))
    if settings.get("user") != f"sli_job_{identity}_{profile}" or "password" in settings:
        raise ValueError("executor_identity_invalid")
    password_name = f"SLI_JOB_{identity.upper()}_{profile.upper()}_PASSWORD"
    if not os.environ.get(f"{password_name}_FILE") or os.environ.get(password_name):
        raise ValueError("executor_secret_file_required")
    settings["password"] = secret_value(password_name)
    return settings


def child_main(profile: str, purpose: str) -> int:
    import resource
    import psycopg

    job = json.load(sys.stdin)
    handler = pilot_registry().resolve(job)
    if job["resource_profile"] != profile:
        raise ValueError("executor_profile_invalid")
    budget = handler["budget"]
    resource.setrlimit(resource.RLIMIT_AS, (budget["memory_bytes"], budget["memory_bytes"]))
    resource.setrlimit(resource.RLIMIT_CPU, (budget["cpu_seconds"], budget["cpu_seconds"]))
    resource.setrlimit(resource.RLIMIT_FSIZE, (budget["max_result_bytes"], budget["max_result_bytes"]))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    settings = child_connection_settings(profile, purpose)
    settings["options"] = (f"-c statement_timeout={budget['statement_timeout_ms']} "
                           f"-c lock_timeout={budget['lock_timeout_ms']} -c search_path=pg_catalog,public")
    # Keep admission through publication and connection commit, including receipts.
    with admission(job["plugin_id"]), psycopg.connect(**settings) as conn:
        from server.sli.plugins.workstations import projection_jobs

        bundled = (projection_jobs.MANIFEST if job["plugin_id"] == "sli.workstations"
                   and job["handler_id"] == projection_jobs.HANDLER_ID
                   else f"config/plugin_packages/{job['plugin_id']}.jobs-v3.json")
        pin_job(job["plugin_id"], job["plugin_version"], job["manifest_sha256"],
                Path(__file__).resolve().parents[3] / bundled)
        stage_handler, publisher = plugin_job_handlers(job["plugin_id"], job["handler_id"])
        if purpose == "handler":
            result = stage_handler(conn, job)
        else:
            result = {"status": queue.publish(conn, job, job["staged_result"], publisher)}
    print(queue.canonical(result))
    return 0


def execute_job(conn, registry, job: dict, *, child=run_child, clock=time.monotonic) -> None:
    deadline = clock() + min(job["budget"]["wall_seconds"], float(job["remaining_seconds"]))

    def heartbeat():
        with conn.cursor() as cur:
            queue.heartbeat(cur, job)
        write_heartbeat(job["resource_profile"], enabled=True)

    try:
        registry.resolve(job)
        heartbeat()
        result = child(job, "handler", heartbeat=heartbeat, deadline=deadline)
        if result.get("status") == "lease_lost":
            raise queue.LeaseLost("job_lease_lost")
        if result.get("status") == "retryable_error":
            raise RuntimeError("job_handler_retryable")
        if result.get("status") not in {"success", "partial", "blocked", "cancelled"}:
            raise ValueError("job_result_invalid")
        heartbeat()
        # Publication holds the row lock. Its hard deadline is below the lease,
        # and finish rechecks PG time before committing the complete transaction.
        outcome = child({**job, "staged_result": result}, "publisher",
                        deadline=min(deadline, clock() + 20))
        if outcome.get("status") == "lease_lost":
            raise queue.LeaseLost("job_lease_lost")
        if outcome.get("status") not in {"committed", "duplicate", "conflict"}:
            raise ValueError("job_publication_invalid")
    except queue.LeaseLost:
        return  # The watchdog already killed the child; the reaper owns recovery.
    except (TimeoutError, RuntimeError, ValueError) as exc:
        code = "job_deadline_exceeded" if isinstance(exc, TimeoutError) else "job_execution_failed"
        with conn.cursor() as cur:
            try:
                queue.fail(cur, job, code, permanent=isinstance(exc, ValueError))
            except queue.LeaseLost:
                pass


def write_heartbeat(profile: str, *, enabled: bool) -> None:
    directory = os.environ.get("SLI_EXECUTOR_STATUS_DIR")
    path = (Path(directory) / f"sli-executor-{profile}.json" if directory
            else Path(str(HEARTBEAT).format(profile=profile)))
    temporary = path.with_suffix(".tmp")
    temporary.write_text(queue.canonical({"profile": profile, "pid": os.getpid(),
        "enabled": enabled, "at_utc": datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
    temporary.replace(path)


def serve(profile: str, *, once: bool = False) -> int:
    from server.sli.core.job_registry import schedule_jobs
    from server.sli.sources import ad_gpo_jobs
    from server.sli.plugins.workstations import jobs as workstation_jobs

    while True:
        if STOP.is_set():
            return 0
        radius_enabled = pilot_enabled()
        snapshots_enabled = ad_gpo_jobs.enabled()
        workstations_enabled = workstation_jobs.enabled()
        enabled = radius_enabled or snapshots_enabled or workstations_enabled
        write_heartbeat(profile, enabled=enabled)
        if enabled:
            with ExitStack() as admissions, connect(profile, "dispatcher") as conn, conn.cursor() as cur:
                admitted = admissions.enter_context(optional_admission("sli.remote-access")) if radius_enabled else True
                radius_enabled = radius_enabled and admitted
                registry = pilot_registry()
                # The same lock used by the legacy host prevents two writers during
                # rollout/rollback even when the old host has not seen the flag yet.
                owns_pilot = True
                if radius_enabled and profile == "light":
                    cur.execute("select pg_try_advisory_lock(hashtext(%s))",
                                ("sli.remote-access:radius-session-observation:host:v1",))
                    owns_pilot = bool(cur.fetchone()[0])
                if radius_enabled and owns_pilot and profile == "light":
                    source_id = os.environ.get("SLI_CORE_JOB_RADIUS_SOURCE_INSTANCE_ID", "")
                    if not source_id:
                        raise ValueError("radius_pilot_source_required")
                    cur.execute("select public.read_radius_job_source_v1(%s)", (source_id,))
                    source = cur.fetchone()[0]
                    if source and not STOP.is_set():
                        schedule_jobs(cur, registry, profile, source)
                if snapshots_enabled and not STOP.is_set():
                    ad_gpo_jobs.schedule(cur, registry, profile)
                if workstations_enabled and not STOP.is_set():
                    workstation_jobs.schedule(cur, registry, profile)
                if owns_pilot and not STOP.is_set():
                    identities = [item for item in registry.identities(profile)
                                  if (radius_enabled if item["plugin_id"] == "sli.remote-access"
                                      else workstations_enabled if item["plugin_id"] == "sli.workstations"
                                      else snapshots_enabled and item["plugin_id"] in ad_gpo_jobs.allowed_plugins())]
                    job = queue.claim(cur, profile, f"executor-{profile}-{os.getpid()}", identities)
                    if job is not None:
                        if job["plugin_id"] != "sli.remote-access":
                            admissions.close()  # Other owners never hold the VPN drain lock during execution.
                        execute_job(conn, registry, job)
        if once or STOP.is_set():
            return 0
        time.sleep(5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=tuple(PROFILES))
    parser.add_argument("--child", choices=("handler", "publisher"))
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.child:
            return child_main(args.profile, args.child)
        STOP.clear()

        def stop(_signum, _frame):
            STOP.set()

        signal.signal(signal.SIGTERM, stop)
        return serve(args.profile, once=args.once)
    except (InterruptedError, KeyboardInterrupt):
        return 0
    except queue.LeaseLost:
        if args.child:
            print(queue.canonical({"status": "lease_lost"}))
            return 0
        return 1
    except ValueError as exc:
        if args.child:
            print(queue.canonical({"status": "permanent_error", "error_code": "job_contract_invalid"}))
            return 0
        report_failure(exc)
        return 1
    except Exception as exc:  # noqa: BLE001 - connection/handler failures may contain private fields
        report_failure(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

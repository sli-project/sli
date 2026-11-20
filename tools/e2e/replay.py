"""Run the current checkout against disposable PostgreSQL, never the live stack."""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "--project-name", "sli-e2e", "--file",
           str(ROOT / "tools/e2e/compose.yml")]
LOCK = "sli-e2e-replay-lock"


class ReplayError(RuntimeError):
    """Only safe, fixed codes cross the command boundary."""


def command(args, *, input=None, timeout=600, failure="command_failed"):
    result = subprocess.run(args, input=input, capture_output=True, text=True,
                            encoding="utf-8", timeout=timeout, check=False)
    if result.returncode:
        raise ReplayError(failure)
    return result.stdout


def copy_dump(compose=COMPOSE):
    # No dump on the host, no shell pipeline (including on Windows). The only
    # file lives on the disposable postgres container's private /dump volume.
    source = subprocess.Popen([
        "docker", "exec", "-e", "PGOPTIONS=-c default_transaction_read_only=on",
        "sli-postgres-1", "sh", "-c",
        'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --compress=zstd:1',
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        target = subprocess.run(compose + ["exec", "-T", "postgres", "sh", "-c",
            "umask 077; cat > /dump/replay.dump"], stdin=source.stdout,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800, check=False)
        source.stdout.close()
        if source.wait(timeout=1800) or target.returncode:
            raise ReplayError("dump_copy_failed")
    finally:
        if source.poll() is None:
            source.kill()
        source.wait()


def execute(*, mode, hours, project="sli-e2e", port=18443, family=None, command=command):
    if not re.fullmatch(r"sli-e2e(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?", project):
        raise ReplayError("replay_project_invalid")
    if not 1024 <= port <= 65535:
        raise ReplayError("replay_port_invalid")
    compose = ["docker", "compose", "--project-name", project, "--file",
               str(ROOT / "tools/e2e/compose.yml")]
    lock = project + "-replay-lock"
    started = time.monotonic()
    os.environ["SLI_E2E_SOURCE"] = str(ROOT)
    os.environ["SLI_E2E_PROJECT"] = project
    os.environ["SLI_E2E_PORT"] = str(port)
    os.environ["SLI_E2E_IMAGE"] = project + "-code:local"
    occupied = command(["docker", "container", "ls", "--all", "--quiet", "--filter",
                        "label=com.docker.compose.project=" + project])
    if occupied.strip():
        raise ReplayError("project_already_exists")
    # Atomic daemon-side reservation prevents concurrent cleanup of another run.
    command(["docker", "create", "--name", lock, "--label",
             "com.docker.compose.project=" + project, "--label",
             "com.docker.compose.service=replay-lock", "postgres:18.6-bookworm", "true"])
    try:
        command(compose + ["up", "--detach", "--build", "--wait", "postgres", "app"], failure="stack_start_failed")
        print("stack: ready", flush=True)
        if mode == "clone":
            roles = command(["docker", "exec", "-e", "PGOPTIONS=-c default_transaction_read_only=on",
                "sli-postgres-1", "sh", "-c",
                'exec pg_dumpall -U "$POSTGRES_USER" --roles-only --no-role-passwords'], failure="source_roles_read_failed")
            # The target's postgres already exists. Password hashes are never copied.
            roles = "\n".join(line for line in roles.splitlines()
                              if not line.startswith(("CREATE ROLE postgres;", "ALTER ROLE postgres ")))
            command(compose + ["exec", "-T", "postgres", "psql", "-U", "postgres",
                               "-d", "postgres", "-v", "ON_ERROR_STOP=1"], input=roles, failure="copy_roles_restore_failed")
            print("clone: dump (source read only)", flush=True)
            copy_dump(compose)
            print("clone: restore", flush=True)
            command(compose + ["exec", "-T", "postgres", "pg_restore", "-U", "postgres",
                "-d", "sli_e2e", "--jobs=4", "--exit-on-error", "/dump/replay.dump"], timeout=1800, failure="copy_database_restore_failed")
        print("replay: synchronous handlers", flush=True)
        scenario_args = ["--mode", mode, "--hours", str(hours)]
        if family:
            scenario_args += ["--family", family]
        result = command(compose + ["exec", "-T", "app", "python", "-m", "tools.e2e.scenario",
            *scenario_args], timeout=3600)
        print(result, end="")
        if '"status": "failed"' in result:
            raise ReplayError("replay_chain_failed")
    finally:
        try:
            command(compose + ["down", "--volumes", "--remove-orphans"])
        finally:
            command(["docker", "rm", "--force", lock])
        print(f"cleanup: verified; total_seconds={time.monotonic() - started:.1f}", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("clone", "synthetic"), default="clone")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--project-name", "--project", dest="project", default="sli-e2e")
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--family", choices=("ad-dc", "file-audit", "workstations"))
    args = parser.parse_args(argv)
    if not 1 <= args.hours <= 168:
        parser.error("hours must be 1..168")
    try:
        execute(mode=args.mode, hours=args.hours, project=args.project, port=args.port, family=args.family)
    except (ReplayError, subprocess.SubprocessError, OSError) as exc:
        code = str(exc) if isinstance(exc, ReplayError) else "replay_command_unavailable"
        print(f"replay: {code}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

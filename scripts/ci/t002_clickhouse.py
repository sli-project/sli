"""Bounded synthetic T002 CI only; never reuse a configured/production CH service."""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

LABEL = "sli.ci.t002.owner"
HOST = "unix:///var/run/docker.sock"
TEST = "tests/reporting/test_new_logon_pairs_native.py"


class LifecycleError(RuntimeError):
    """Fixed messages only; subprocess args/output can contain credentials."""


def read_clickhouse_pin(path):
    """Use the repository's Docker pin; reject floating or foreign image tags."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        pin = document["clickhouse_modes"]["docker"]
        version, reference = pin["version"], pin["image"]["reference"]
        if (document["schema_version"] != 1 or not isinstance(version, str)
                or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", version)
                or reference != f"clickhouse/clickhouse-server:{version}"):
            raise ValueError("invalid image pin")
    except (OSError, UnicodeError, KeyError, TypeError, ValueError) as exc:
        raise LifecycleError("t002_clickhouse_pin_invalid") from exc
    return version, reference


VERSION, IMAGE = read_clickhouse_pin(Path(__file__).resolve().parents[2] / "deploy/linux/native_pins.json")


def docker(*args, timeout=30, env=None):
    try:
        completed = subprocess.run(
            ["docker", "--host", HOST, *args], check=False, capture_output=True,
            text=True, timeout=timeout, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LifecycleError("t002_docker_unavailable_or_timeout") from exc
    if completed.returncode:
        # Emit only an allowlisted operation/category, never stderr/arguments.
        operation = args[0] if args and args[0] in {
            "info", "pull", "image", "volume", "container", "create", "start", "port",
        } else "command"
        error = (completed.stderr or "").casefold()
        reason = ("permission_denied" if "permission denied" in error else
                  "daemon_unreachable" if "cannot connect" in error or "is the docker daemon running" in error or "failed to connect" in error else
                  "operation_denied" if "operation not permitted" in error or "denied" in error else
                  "api_incompatible" if "client version" in error or "api version" in error else
                  "image_unavailable" if "manifest unknown" in error else "command_failed")
        raise LifecycleError(f"t002_docker_{operation}_{reason}")
    return completed.stdout.strip()


def state_path(path):
    path = Path(path)
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if path.parent.resolve(strict=True) != root or not re.fullmatch(r"sli-t002-[a-zA-Z0-9_-]+\.json", path.name):
        raise LifecycleError("t002_invalid_state_path")
    if path.is_symlink():
        raise LifecycleError("t002_state_symlink")
    return path


def local_socket_state():
    try:
        mode = Path("/var/run/docker.sock").stat().st_mode
    except FileNotFoundError:
        return "absent"
    except PermissionError:
        return "access_denied"
    return "socket" if stat.S_ISSOCK(mode) else "not_socket"


def preflight():
    if os.environ.get("DOCKER_HOST", HOST) != HOST or os.environ.get("DOCKER_CONTEXT", "default") != "default":
        raise LifecycleError("t002_remote_docker_refused")
    state = local_socket_state()
    if state != "socket":
        raise LifecycleError(f"t002_local_docker_socket_{state}")
    if docker("info", "--format", "{{.OSType}}") != "linux":
        raise LifecycleError("t002_linux_docker_required")


def owned(kind, name, owner):
    # Listing first distinguishes an absent object from failed daemon/inspect.
    found = docker(kind, "ls", "--filter", f"name=^{name}$", "--format", "{{.Name}}" if kind == "volume" else "{{.Names}}", *([] if kind == "volume" else ["--all"]))
    if not found:
        return False
    if found != name:
        raise LifecycleError("t002_resource_lookup_ambiguous")
    values = json.loads(docker(kind, "inspect", name))
    labels = values[0].get("Labels") if kind == "volume" else values[0].get("Config", {}).get("Labels")
    if (labels or {}).get(LABEL) != owner:
        raise LifecycleError("t002_resource_not_owned")
    return True


def cleanup(path):
    path = state_path(path)
    if not path.exists():
        return
    preflight()
    state = json.loads(path.read_text())
    owner = state.get("owner", "")
    if not re.fullmatch(r"[a-f0-9]{32}", owner):
        raise LifecycleError("t002_invalid_owner")
    container, volume = f"sli-t002-{owner}", f"sli-t002-{owner}-data"
    # Never trust arbitrary resource names from a file; derive both from nonce.
    if owned("container", container, owner):
        docker("container", "rm", "--force", container)
    if owned("volume", volume, owner):
        docker("volume", "rm", volume)
    (path.parent / f"sli-t002-{owner}-junit.xml").unlink(missing_ok=True)
    path.unlink()


def verify_native_result(report):
    try:
        cases = list(ET.parse(report).getroot().iter("testcase"))
    except (OSError, ET.ParseError) as exc:
        raise LifecycleError("t002_native_result_missing_or_invalid") from exc
    if len(cases) != 1 or cases[0].get("name") != "test_actual_report_native_context_history_and_volume":
        raise LifecycleError("t002_native_expected_case_not_run")
    if any(cases[0].find(tag) is not None for tag in ("skipped", "failure", "error")):
        raise LifecycleError("t002_native_expected_case_not_passed")


def query_version(port, password):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    authorization = base64.b64encode(f"t002_ci:{password}".encode()).decode()
    try:
        connection.request("POST", "/", body="SELECT version()", headers={"Authorization": f"Basic {authorization}"})
        response = connection.getresponse()
        body = response.read(128)
        return body.decode().strip() if response.status == 200 else None
    finally:
        connection.close()


def run(path):
    path = state_path(path)
    preflight()
    owner = uuid.uuid4().hex
    container, volume = f"sli-t002-{owner}", f"sli-t002-{owner}-data"
    # A pre-existing name is not ours, even if its label happens to match.
    # Do this before recording cleanup ownership or entering the cleanup block.
    if owned("container", container, owner) or owned("volume", volume, owner):
        raise LifecycleError("t002_resource_collision")
    report = path.parent / f"sli-t002-{owner}-junit.xml"
    if report.exists() or report.is_symlink():
        raise LifecycleError("t002_native_result_collision")
    # Persist ownership intention before any object creation, for always cleanup.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        json.dump({"owner": owner}, handle)
    started = time.monotonic()
    try:
        docker("pull", IMAGE, timeout=120)
        metadata = json.loads(docker("image", "inspect", IMAGE))[0]
        digests = sorted(value for value in metadata.get("RepoDigests", []) if re.fullmatch(
            r"clickhouse/clickhouse-server@sha256:[a-f0-9]{64}", value))
        if not digests or metadata.get("Os") != "linux" or metadata.get("Architecture") != "amd64":
            raise LifecycleError("t002_image_identity_unverified")
        image = digests[0]  # Immutable registry digest, never config-id-as-digest.
        password = secrets.token_urlsafe(32)
        env = {**os.environ, "CLICKHOUSE_PASSWORD": password}
        docker("volume", "create", "--label", f"{LABEL}={owner}", volume)
        if not owned("volume", volume, owner):
            raise LifecycleError("t002_volume_missing")
        docker("create", "--name", container, "--label", f"{LABEL}={owner}",
               "--cpus", "2", "--memory", "2g", "--memory-swap", "2g", "--pids-limit", "512",
               "--publish", "127.0.0.1::8123", "--mount", f"type=volume,source={volume},target=/var/lib/clickhouse",
               "--env", "CLICKHOUSE_USER=t002_ci", "--env", "CLICKHOUSE_PASSWORD",
               "--env", "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1", image, env=env)
        if not owned("container", container, owner):
            raise LifecycleError("t002_container_missing")
        docker("start", container)
        address = docker("port", container, "8123/tcp")
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", address)
        if not match or not 0 < int(match[1]) <= 65535:
            raise LifecycleError("t002_non_loopback_port_refused")
        port = int(match[1])
        readiness = time.monotonic() + 60
        while True:
            try:
                version = query_version(port, password)
            except (OSError, http.client.HTTPException):
                version = None
            if version:
                if version != VERSION:
                    raise LifecycleError("t002_clickhouse_version_mismatch")
                break
            if time.monotonic() >= readiness:
                raise LifecycleError("t002_clickhouse_not_ready")
            time.sleep(1)
        print(json.dumps({"t002_image": image, "version": version, "cpus": 2, "memory_gib": 2}), flush=True)
        remaining = min(480, max(1, 600 - (time.monotonic() - started)))
        env = {**os.environ, "SLI_T002_NATIVE_CH": "1", "ADLOG_HISTORY_READ_MODE": "primary",
               "ADLOG_HISTORY_CLICKHOUSE_HOST": "127.0.0.1",
               "ADLOG_HISTORY_CLICKHOUSE_PORT": str(port), "ADLOG_HISTORY_CLICKHOUSE_USER": "t002_ci",
               "ADLOG_HISTORY_CLICKHOUSE_PASSWORD": password}
        env.pop("ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE", None)
        try:
            completed = subprocess.run([sys.executable, "-m", "pytest", "-q", "-s", TEST, f"--junitxml={report}"], env=env, timeout=remaining, check=False)
        except subprocess.TimeoutExpired as exc:
            raise LifecycleError("t002_native_measurement_timeout") from exc
        if completed.returncode:
            raise LifecycleError("t002_native_measurement_failed")
        verify_native_result(report)
    finally:
        cleanup(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run", "cleanup", "preflight"))
    parser.add_argument("--state", required=True)
    args = parser.parse_args()
    try:
        if args.action == "preflight":
            preflight()
        else:
            (run if args.action == "run" else cleanup)(args.state)
    except LifecycleError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError):
        # Do not print chained exception details, docker args, env or secrets.
        print("T002 isolated ClickHouse lifecycle failed; inspect the fixed gate and cleanup status.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

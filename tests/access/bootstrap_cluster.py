"""Private Linux/nonroot PG18 fixture; importing this module starts nothing."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4


def require_owned_cluster_configuration(bin_dir: Path) -> Path:
    if os.environ.get("SLI_BOOTSTRAP_DISPOSABLE_CLUSTER") != "1":
        raise RuntimeError("bootstrap_cluster_explicit_opt_in_required")
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("bootstrap_cluster_requires_linux_nonroot: use Linux as a non-root user")
    if not bin_dir.is_absolute():
        raise RuntimeError("bootstrap_cluster_requires_absolute_pg18_bin_directory")
    bin_dir = bin_dir.resolve()
    if not all((bin_dir / name).is_file() for name in ("initdb", "pg_ctl", "postgres", "psql")):
        raise RuntimeError("bootstrap_cluster_requires_installed_pg18_binaries")
    return bin_dir


@contextmanager
def owned_cluster(bin_dir: Path):
    """Own a fresh entire cluster, including all fixed migration role names.

    No ambient DSN, installed service, Docker daemon or TCP endpoint is used.
    Failed/uncertain stop preserves the private directory for manual inspection.
    """
    bin_dir = require_owned_cluster_configuration(bin_dir)
    root = Path(tempfile.mkdtemp(prefix="sli-pg-", dir="/tmp"))
    data = root / "data"
    socket = root / "socket"
    environment = {"PATH": str(bin_dir) + os.pathsep + os.defpath, "LC_ALL": "C"}
    start_attempted = False
    init_attempted = init_returned = False

    def run(args, stage):
        try:
            return subprocess.run(
                [str(arg) for arg in args], env=environment,
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=45, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            # Do not echo subprocess exception/command/output or credentials.
            raise RuntimeError(f"bootstrap_cluster_{stage}_failed") from None

    try:
        socket.mkdir(mode=0o700)
        version = run([bin_dir / "initdb", "--version"], "version")
        if version.returncode or not re.search(r"\(PostgreSQL\) 18(?:\.|\b)", version.stdout):
            raise RuntimeError("bootstrap_cluster_requires_postgresql18")
        init_attempted = True
        initialized = run([
            bin_dir / "initdb", "-D", data, "--username=postgres", "--no-locale",
            "--encoding=UTF8", "--auth-local=trust", "--auth-host=reject",
        ], "init")
        init_returned = True
        if initialized.returncode:
            raise RuntimeError("bootstrap_cluster_init_failed")
        # The socket directory is private and unique, so port 5432 is not shared.
        options = f"-c listen_addresses='' -c unix_socket_directories='{socket}' -c unix_socket_permissions=0700 -p 5432"
        start_attempted = True
        started = run([
            bin_dir / "pg_ctl", "-D", data, "-l", root / "postgres.log",
            "-o", options, "-w", "-t", "30", "start",
        ], "start")
        if started.returncode:
            raise RuntimeError("bootstrap_cluster_start_failed")
        yield SimpleNamespace(
            data=data, host=str(socket), port=5432, psql=bin_dir / "psql",
            database="sli_test_bootstrap_" + uuid4().hex,
        )
    finally:
        stopped = not start_attempted and (not init_attempted or init_returned)
        if start_attempted:
            try:
                result = run([
                    bin_dir / "pg_ctl", "-D", data, "-m", "immediate",
                    "-w", "-t", "30", "stop",
                ], "stop")
                stopped = result.returncode == 0
                # A failed start may still complete in the background. A
                # missing PID/status alone is not authority to delete its data.
            except RuntimeError:
                stopped = False
        if not stopped:
            raise RuntimeError(
                f"bootstrap_cluster_cleanup_incomplete_preserved:{root}"
            ) from None
        shutil.rmtree(root)


def assert_owned_connection(connection, cluster) -> None:
    """Read-only identity gate before any bootstrap SQL or migration execution."""
    row = connection.execute(
        "select current_setting('data_directory'), "
        "current_setting('server_version_num')::integer, inet_server_addr(), current_user"
    ).fetchone()
    if (not row or len(row) != 4 or Path(str(row[0])).resolve() != cluster.data.resolve()
            or int(row[1]) // 10000 != 18 or row[2] is not None or row[3] != "postgres"):
        raise RuntimeError("bootstrap_cluster_connection_identity_mismatch")

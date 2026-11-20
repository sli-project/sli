"""Owned, local-only resources for the explicitly opted-in Stage6s E2E.

Importing this helper has no external effects. The Docker adapter never inherits
Docker contexts, remote hosts, credentials, or user configuration. Images must
already exist on the separately approved disposable Linux executor.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
import re
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from uuid import uuid4

LABEL = "sli.stage6s.disposable.run"
CH_IMAGE = "clickhouse/clickhouse-server:25.8.28.1"
PG_IMAGE = "postgres:16"
MOUNTS = {
    "ch": ("/var/lib/clickhouse", "/var/log/clickhouse-server"),
    "pg": ("/var/lib/postgresql/data",),
}


def require_opt_in():
    if os.environ.get("SLI_STAGE6S_DISPOSABLE_E2E") != "1":
        raise RuntimeError("stage6s_disposable_explicit_opt_in_required")


@contextmanager
def local_docker():
    require_opt_in()
    with TemporaryDirectory(prefix="stage6s-docker-") as config:
        def docker(args):
            # No implicit context/config, remote daemon, helper, or image pull.
            try:
                result = subprocess.run(
                    ["/usr/bin/docker", "--config", config,
                     "--host", "unix:///var/run/docker.sock", *args],
                    env={"PATH": "/usr/bin:/bin", "HOME": config},
                    capture_output=True, timeout=120, check=False,
                )
                if result.returncode:
                    raise RuntimeError
                return result.stdout.decode("utf-8", errors="strict").strip()
            except Exception:
                # CLI output and TimeoutExpired.cmd can contain credentials.
                raise RuntimeError("stage6s_disposable_docker_failed") from None
        yield docker


def _inspect(docker, cid, run_id, kind, *, running=None):
    """Prove exact identity and isolation. Never use names or port discovery."""
    try:
        records = json.loads(docker(["inspect", cid]))
        if not isinstance(records, list) or len(records) != 1:
            raise ValueError
        record = records[0]
        image = CH_IMAGE if kind == "ch" else PG_IMAGE
        if (record["Id"] != cid
                or record["Config"]["Labels"].get(LABEL) != run_id
                or record["Config"]["Image"] != image
                or record["HostConfig"]["NetworkMode"] != "bridge"
                or type(record["State"]["Running"]) is not bool):
            raise ValueError
        if running is not None and record["State"]["Running"] is not running:
            raise ValueError
        mounts = record["Mounts"]
        if (len(mounts) != len(MOUNTS[kind])
                or {m["Destination"] for m in mounts} != set(MOUNTS[kind])
                or any(m["Type"] != "tmpfs" for m in mounts)):
            raise ValueError
        if record["State"]["Running"] is not True:
            return None  # Docker allocates the published port only on start.
        port_key = "8123/tcp" if kind == "ch" else "5432/tcp"
        bindings = record["NetworkSettings"]["Ports"][port_key]
        if not isinstance(bindings, list) or len(bindings) != 1:
            raise ValueError
        binding = bindings[0]
        if binding["HostIp"] != "127.0.0.1":
            raise ValueError
        raw_port = binding["HostPort"]
        if not isinstance(raw_port, str) or not re.fullmatch(r"[0-9]{1,5}", raw_port):
            raise ValueError
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError
        return port
    except Exception:
        raise RuntimeError("stage6s_disposable_ownership_unverified") from None


@contextmanager
def owned_resources(docker):
    require_opt_in()
    run_id = uuid4().hex
    password = uuid4().hex
    captured = []
    proven = set()
    ids = {}
    ports = {}
    try:
        for kind, image, inner_port in (("ch", CH_IMAGE, 8123), ("pg", PG_IMAGE, 5432)):
            args = ["create", "--pull=never", "--label", f"{LABEL}={run_id}",
                    "--network", "bridge", "--publish", f"127.0.0.1::{inner_port}"]
            for mount in MOUNTS[kind]:
                args += ["--mount", f"type=tmpfs,destination={mount}"]
            env = ({"CLICKHOUSE_USER": "stage6s", "CLICKHOUSE_PASSWORD": password,
                    "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1"} if kind == "ch" else
                   {"POSTGRES_USER": "stage6s", "POSTGRES_PASSWORD": password,
                    "POSTGRES_DB": "stage6s"})
            for key, value in env.items():
                args += ["--env", f"{key}={value}"]
            try:
                cid = docker([*args, image])
            except Exception:
                raise RuntimeError("stage6s_disposable_create_failed_resources_may_remain") from None
            if not isinstance(cid, str) or not re.fullmatch(r"[0-9a-f]{64}", cid):
                raise RuntimeError("stage6s_disposable_create_identity_unverified_resources_may_remain")
            captured.append((cid, kind))
            _inspect(docker, cid, run_id, kind, running=False)
            proven.add(cid)
            docker(["start", cid])
            ids[kind] = cid
            ports[kind] = _inspect(docker, cid, run_id, kind, running=True)
        yield SimpleNamespace(
            run_id=run_id, ch_id=ids["ch"], pg_id=ids["pg"],
            ch_host="127.0.0.1", ch_port=ports["ch"], ch_auth=("stage6s", password),
            # Explicit libpq fields exclude inherited host/auth/service settings.
            pg_dsn=(f"host=127.0.0.1 hostaddr=127.0.0.1 port={ports['pg']} "
                    f"dbname=stage6s user=stage6s password={password} "
                    "connect_timeout=2 sslmode=disable gssencmode=disable"),
        )
    finally:
        leftovers = False
        for cid, kind in reversed(captured):
            if cid not in proven:
                leftovers = True
                continue
            try:
                _inspect(docker, cid, run_id, kind)
                docker(["rm", "--force", "--volumes", cid])
            except Exception:
                leftovers = True
        if leftovers:
            # Safe generic error; deliberately leave anything not proven owned.
            raise RuntimeError("stage6s_disposable_ownership_cleanup_incomplete_resources_left") from None


def pin_clickhouse(monkeypatch, resource, io, *aliases):
    """Pin actual IO, including imported aliases and executor's late imports."""
    original_query = io._http_query

    def query(port, sql, **kwargs):
        if port != resource.ch_port:
            raise RuntimeError("stage6s_disposable_port_mismatch")
        if (kwargs.get("host", resource.ch_host) != resource.ch_host
                or kwargs.get("auth", resource.ch_auth) != resource.ch_auth):
            raise RuntimeError("stage6s_disposable_endpoint_mismatch")
        return original_query(port, sql, **{**kwargs, "host": resource.ch_host, "auth": resource.ch_auth})

    def container_port(container):
        if container != resource.ch_id:
            raise RuntimeError("stage6s_disposable_container_mismatch")
        return resource.ch_port

    for module in (io, *aliases):
        if hasattr(module, "_http_query"):
            monkeypatch.setattr(module, "_http_query", query)
        if hasattr(module, "_container_port"):
            monkeypatch.setattr(module, "_container_port", container_port)
        if hasattr(module, "CONTAINER"):
            monkeypatch.setattr(module, "CONTAINER", resource.ch_id)

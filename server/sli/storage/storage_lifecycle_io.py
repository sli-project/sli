#!/usr/bin/env python3
"""Storage lifecycle low-level IO primitives: ClickHouse HTTP client and the
read-only PostgreSQL connection used by warm-tier/retention runtime
modules.

These primitives were previously borrowed by
``scripts/maintenance/warm_tier_incremental_copy.py`` from three historical,
unrelated scripts (``scripts/maintenance/stage7_clickhouse_candidate_a.py``,
``scripts/maintenance/stage7_control_benchmark.py``,
``runner/_tasks/tier_move_step1_copy.py``). They now have their own home here
so both production runtime and maintenance CLI depend on this module instead
of borrowing from scripts that own no relationship to Storage lifecycle. The
three historical scripts are unchanged and keep their own copies for their
own callers.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import subprocess
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from threading import Timer
from time import monotonic
from typing import Any
from urllib.parse import urlencode

CONTAINER = "sli-warm-tier-step1"
DATABASE = "sli_warm"
WARM_ENV_PREFIX = "ADLOG_WARM_CLICKHOUSE_"

CREATE_PLACEMENT_INPUT = """
CREATE TABLE {db}.placement_input
(
 event_id UInt64,normalized_hash_hex String,archive_file String,
 archive_line UInt32
) ENGINE=MergeTree ORDER BY event_id
"""


def _warm_endpoint() -> tuple[str, int, tuple[str, str]] | None:
    """Explicit network settings take precedence over Windows port discovery."""
    settings = {
        key: os.environ.get(WARM_ENV_PREFIX + key, "").strip()
        for key in ("HOST", "PORT", "USER", "PASSWORD_FILE")
    }
    if not any(settings.values()):
        return None
    if not settings["HOST"] or not settings["PASSWORD_FILE"]:
        raise RuntimeError("warm_clickhouse_settings_incomplete")
    try:
        port = int(settings["PORT"] or "8123")
    except ValueError:
        raise RuntimeError("warm_clickhouse_port_invalid") from None
    if not 1 <= port <= 65535:
        raise RuntimeError("warm_clickhouse_port_invalid")
    try:
        password = Path(settings["PASSWORD_FILE"]).read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError):
        raise RuntimeError("warm_clickhouse_password_file_unreadable") from None
    if not password or any(char in password for char in "\r\n\0"):
        raise RuntimeError("warm_clickhouse_password_file_invalid")
    return settings["HOST"], port, (settings["USER"] or "default", password)


def _http_endpoint(
    host: str | None, auth: tuple[str, str] | None,
) -> tuple[str, tuple[str, str] | None]:
    # History supplies its own credentials; never route it to the warm tier.
    if host is None and auth is None:
        endpoint = _warm_endpoint()
        if endpoint is not None:
            return endpoint[0], endpoint[2]
    if host is None and auth is not None:
        host = os.environ.get("ADLOG_HISTORY_CLICKHOUSE_HOST", "127.0.0.1")
    return host or "127.0.0.1", auth


def _docker(
    args: list[str],
    *,
    timeout: int = 3600,
    input_bytes: bytes | None = None,
) -> str:
    result = subprocess.run(
        ["docker", *args],
        input=input_bytes,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace")[-3000:]
        raise RuntimeError(f"docker command failed:{args[0]}:{message}")
    return result.stdout.decode("utf-8", errors="strict").strip()


def _connect_before_deadline(address, timeout, source_address=None, *, deadline):
    """Share the report budget across addresses; OS DNS remains synchronous."""
    def remaining_timeout():
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("ClickHouse report deadline exceeded")
        return min(timeout, remaining)

    remaining_timeout()
    addresses = socket.getaddrinfo(address[0], address[1], 0, socket.SOCK_STREAM)
    remaining_timeout()  # An expired DNS result must not initiate a connection.
    last_error = None
    for family, kind, protocol, _, target in addresses:
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(remaining_timeout())
            if source_address:
                sock.bind(source_address)
            sock.connect(target)
            sock.settimeout(remaining_timeout())
            return sock
        except OSError as error:
            sock.close()
            last_error = error
    if last_error is not None:
        raise last_error
    raise OSError("getaddrinfo returns an empty list")


def _http_query(
    port: int,
    query: str,
    *,
    timeout: float = 300,
    params: dict[str, str] | None = None,
    auth: tuple[str, str] | None = None,
    host: str | None = None,
    deadline: float | None = None,
) -> bytes:
    host, auth = _http_endpoint(host, auth)
    if deadline is not None:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("ClickHouse report deadline exceeded")
        timeout = min(timeout, remaining)
    timer = None
    connection = http.client.HTTPConnection(host, int(port), timeout=timeout)
    path = f"/?{urlencode(params)}" if params else "/"
    try:
        if deadline is not None:
            connection._create_connection = lambda address, timeout, source_address: _connect_before_deadline(
                address, timeout, source_address, deadline=deadline,
            )
            connection.connect()
            connected_socket = connection.sock

            def interrupt():
                try:
                    connected_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # The request owns and closes the socket.

            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError("ClickHouse report deadline exceeded")
            timer = Timer(remaining, interrupt)
            timer.daemon = True
            timer.start()
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        if auth is not None:
            encoded = base64.b64encode(f"{auth[0]}:{auth[1]}".encode())
            headers["Authorization"] = "Basic " + encoded.decode("ascii")
        connection.request(
            "POST",
            path,
            body=query.encode("utf-8"),
            headers=headers,
        )
        response = connection.getresponse()
        payload = response.read()
        if deadline is not None and monotonic() >= deadline:
            raise TimeoutError("ClickHouse report deadline exceeded")
    except (OSError, http.client.HTTPException):
        if deadline is not None and monotonic() >= deadline:
            raise TimeoutError("ClickHouse report deadline exceeded") from None
        raise
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()
    if response.status != 200:
        # ClickHouse error bodies can echo inserted AD records or SQL literals.
        raise RuntimeError(f"ClickHouse HTTP {response.status}:request_failed")
    return payload


def _http_insert_json_rows(
    port: int,
    table: str,
    rows: Iterable[dict[str, Any]],
    *,
    timeout: int = 300,
    auth: tuple[str, str] | None = None,
) -> tuple[int, bool]:
    """INSERT a batch of rows in one ClickHouse HTTP request.

    Same query-in-body mechanism `_http_query` already uses for reads: the
    leading `INSERT ... FORMAT JSONEachRow` statement plus the row data
    both go in the same POST body, so one HTTP round trip replaces one
    `docker exec -i clickhouse-client` subprocess launch per call site per
    batch -- this is what keeps `warm_tier_incremental_copy_runtime.py`'s
    per-batch drain loop from spawning a new OS process for every batch it
    processes (see that module's docstring).

    Returns `(inserted_count, interrupted)` -- the same shape
    `runner._tasks.tier_move_step1_copy._insert_json_rows` returns, so
    call sites written against that contract need no other change.
    `interrupted` is always False here: an HTTP POST has no
    kill-mid-write concept to report, a failed or partial request raises
    instead (unlike the subprocess version, which a caller can choose to
    kill deliberately mid-stream -- only one such caller exists, a
    stand-alone interruption-safety pilot drill unrelated to this
    function).
    """
    lines = [
        json.dumps(row, ensure_ascii=False, separators=(",", ":"))
        for row in rows
    ]
    if not lines:
        return 0, False
    query = f"INSERT INTO {table} FORMAT JSONEachRow\n" + "\n".join(lines)
    if auth is None:
        _http_query(port, query, timeout=timeout)
    else:
        _http_query(port, query, timeout=timeout, auth=auth)
    return len(lines), False


def _http_stream_json_rows(
    port: int, query: str, *, timeout: int = 3600,
    params: dict[str, str] | None = None,
    auth: tuple[str, str] | None = None,
    host: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream one JSONEachRow result without buffering the whole history."""
    host, auth = _http_endpoint(host, auth)
    connection = http.client.HTTPConnection(host, int(port), timeout=timeout)
    path = f"/?{urlencode(params)}" if params else "/"
    try:
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        if auth is not None:
            encoded = base64.b64encode(f"{auth[0]}:{auth[1]}".encode())
            headers["Authorization"] = "Basic " + encoded.decode("ascii")
        connection.request("POST", path, body=query.encode("utf-8"), headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"ClickHouse HTTP {response.status}:request_failed")
        while True:
            line = response.readline()
            if not line:
                break
            if line.strip():
                yield json.loads(line)
    finally:
        connection.close()


def _container_port(container: str) -> int:
    if container == CONTAINER:
        endpoint = _warm_endpoint()
        if endpoint is not None:
            return endpoint[1]
        if sys.platform != "win32":
            raise RuntimeError("warm_clickhouse_settings_required")
    value = _docker(["port", container, "8123/tcp"])
    return int(value.rsplit(":", 1)[1])


def _drop_database(port: int, database: str) -> None:
    _http_query(port, f"DROP DATABASE IF EXISTS {database} SYNC")


def _connection_parts() -> dict[str, Any]:
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    from server.sli.core.app_config import load_config

    cfg = load_config()
    if not cfg.postgres_dsn:
        raise RuntimeError("postgres_dsn_not_configured")
    parts = conninfo_to_dict(cfg.postgres_dsn)
    admin_user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    admin_password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not admin_user or not admin_password:
        raise RuntimeError("protected_read_only_admin_credentials_required")
    parts.update(
        user=admin_user,
        password=admin_password,
        connect_timeout=max(1, int(cfg.postgres_connect_timeout_seconds)),
        application_name="sli_stage7_control_d_benchmark",
        options=(
            "-c default_transaction_read_only=on "
            "-c statement_timeout=180000 -c lock_timeout=3000"
        ),
    )
    # Keep the import guard useful for source-only tests.
    if psycopg is None:  # pragma: no cover
        raise RuntimeError("psycopg_not_available")
    return parts


def _connect():
    import psycopg
    from psycopg.rows import dict_row

    # Linux installations already provision this NOINHERIT login and its
    # file-backed password. Activate the canonical worker role before reads;
    # never require an additional admin credential for a deployed lifecycle.
    if (os.environ.get("ADLOG_STORAGE_V2_WORKER_DSN", "").strip()
            or "ADLOG_STORAGE_V2_WORKER_DSN_FILE" in os.environ):
        from server.sli.storage.storage_v2_worker_connection import (
            connect_storage_v2_worker,
        )

        conn = connect_storage_v2_worker()
        try:
            with conn.cursor() as cur:
                cur.execute("set default_transaction_read_only = on")
                cur.execute("set statement_timeout = 180000")
                cur.execute("set lock_timeout = 3000")
            conn.commit()
            return conn
        except Exception:
            conn.close()
            raise
    # Retain the explicitly protected local maintenance connection.
    return psycopg.connect(**_connection_parts(), row_factory=dict_row)

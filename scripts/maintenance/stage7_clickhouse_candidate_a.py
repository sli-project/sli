#!/usr/bin/env python3
"""Full-corpus isolated ClickHouse candidate A benchmark.

Candidate A keeps a fully typed atomic event, its complete payload and compact
entity-link tuples in ClickHouse.  The verified Storage V2 archive remains the
canonical RAW source.  Production PostgreSQL and collection runtime are read
only and are never reconfigured by this command.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import uuid
from typing import Any, Iterable, Iterator
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.stage7_control_benchmark import (  # noqa: E402
    _connect as _connect,
    _exported_snapshot,
    _snapshot_source,
    _verify_snapshot_corpus,
    _digest_rows,
    _normalize_timeline,
    _workloads as _control_workloads,
    TIMELINE_CONTRACT_VERSION,
    _load_contract,
    _p95,
    _query_seeds,
    _relation_sizes,
)
from scripts.maintenance.stage7_event_identity import (  # noqa: E402
    event_uid,
    initial_log_epoch_uid,
    initial_source_instance_uid,
    stream_uid,
)


IMAGE = "clickhouse/clickhouse-server:192.0.2.21"
DATABASE = "stage7"
TABLE = "events_a"
INSERT_COLUMNS = (
    "source_id",
    "event_uid",
    "raw_log_file_id",
    "server_id",
    "domain_id",
    "site_id",
    "log_source_id",
    "event_record_id",
    "event_id",
    "version",
    "level",
    "task",
    "opcode",
    "keywords",
    "provider_name",
    "provider_guid",
    "channel",
    "computer",
    "time_created_utc",
    "time_created_local",
    "subject_user_sid",
    "subject_user_name",
    "subject_domain_name",
    "target_user_sid",
    "target_user_name",
    "target_domain_name",
    "ip_address",
    "workstation_name",
    "logon_id",
    "correlation_id",
    "normalized_at",
    "normalized_hash",
    "event_data_json",
    "message_text",
    "record_xml",
    "entity_ids",
    "entity_role_ids",
)


CREATE_DATABASE_SQL = f"CREATE DATABASE IF NOT EXISTS {DATABASE}"
CREATE_TABLE_SQL = f"""
CREATE TABLE {DATABASE}.{TABLE}
(
    source_id UInt64 CODEC(Delta, ZSTD(3)),
    event_uid FixedString(77),
    raw_log_file_id UInt64 CODEC(Delta, ZSTD(3)),
    server_id UInt32 CODEC(ZSTD(3)),
    domain_id UInt32 CODEC(ZSTD(3)),
    site_id UInt32 CODEC(ZSTD(3)),
    log_source_id UInt32 CODEC(ZSTD(3)),
    event_record_id UInt64 CODEC(Delta, ZSTD(3)),
    event_id UInt32 CODEC(ZSTD(3)),
    version Nullable(UInt16) CODEC(ZSTD(3)),
    level UInt8 CODEC(ZSTD(3)),
    task UInt16 CODEC(ZSTD(3)),
    opcode Nullable(UInt16) CODEC(ZSTD(3)),
    keywords LowCardinality(String),
    provider_name LowCardinality(String),
    provider_guid Nullable(String) CODEC(ZSTD(3)),
    channel LowCardinality(String),
    computer LowCardinality(String),
    time_created_utc DateTime64(6, 'UTC') CODEC(Delta, ZSTD(3)),
    time_created_local Nullable(String) CODEC(ZSTD(3)),
    subject_user_sid Nullable(String) CODEC(ZSTD(3)),
    subject_user_name Nullable(String) CODEC(ZSTD(3)),
    subject_domain_name Nullable(String) CODEC(ZSTD(3)),
    target_user_sid Nullable(String) CODEC(ZSTD(3)),
    target_user_name Nullable(String) CODEC(ZSTD(3)),
    target_domain_name Nullable(String) CODEC(ZSTD(3)),
    ip_address Nullable(String) CODEC(ZSTD(3)),
    workstation_name Nullable(String) CODEC(ZSTD(3)),
    logon_id Nullable(String) CODEC(ZSTD(3)),
    correlation_id Nullable(String) CODEC(ZSTD(3)),
    normalized_at DateTime64(6, 'UTC') CODEC(Delta, ZSTD(3)),
    normalized_hash FixedString(64),
    event_data_json String CODEC(ZSTD(6)),
    message_text Nullable(String) CODEC(ZSTD(6)),
    record_xml String CODEC(ZSTD(6)),
    entity_ids Array(UInt64) CODEC(Delta, ZSTD(3)),
    entity_role_ids Array(UInt16) CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(time_created_utc)
ORDER BY (server_id, channel, event_id, time_created_utc, source_id)
SETTINGS index_granularity = 8192;
"""


def _docker(
    args: list[str],
    *,
    timeout: int = 3600,
    input_bytes: bytes | None = None,
) -> str:
    result = subprocess.run(
        ["docker", *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace")[-3000:]
        raise RuntimeError(f"docker command failed:{args[0]}:{message}")
    return result.stdout.decode("utf-8", errors="strict").strip()


def _http_query(
    port: int,
    query: str,
    *,
    timeout: int = 300,
    params: dict[str, str] | None = None,
) -> bytes:
    connection = http.client.HTTPConnection("127.0.0.1", int(port), timeout=timeout)
    path = f"/?{urlencode(params)}" if params else "/"
    try:
        connection.request(
            "POST",
            path,
            body=query.encode("utf-8"),
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        response = connection.getresponse()
        payload = response.read()
    finally:
        connection.close()
    if response.status != 200:
        raise RuntimeError(
            f"ClickHouse HTTP {response.status}:"
            f"{payload.decode('utf-8', errors='replace')[-3000:]}"
        )
    return payload


def _http_insert_json_rows(
    port: int,
    table: str,
    rows: Iterable[dict[str, Any]],
    *,
    timeout: int = 300,
) -> tuple[int, bool]:
    """INSERT a batch of rows in one ClickHouse HTTP request.

    Same query-in-body mechanism `_http_query` already uses for reads: the
    leading `INSERT ... FORMAT JSONEachRow` statement plus the row data
    both go in the same POST body, so one HTTP round trip replaces one
    `docker exec -i clickhouse-client` subprocess launch per call site per
    batch -- this is what keeps `warm_tier_incremental_copy.py`'s
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
    _http_query(port, query, timeout=timeout)
    return len(lines), False


def _wait_ready(container: str) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = subprocess.run(
            [
                "docker",
                "exec",
                container,
                "clickhouse-client",
                "--query",
                "select 1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(0.5)
    raise RuntimeError("ClickHouse candidate container did not become ready")


def _container_port(container: str) -> int:
    value = _docker(["port", container, "8123/tcp"])
    return int(value.rsplit(":", 1)[1])


def _volume_bytes(container: str, path: str) -> int:
    value = _docker(
        [
            "exec",
            container,
            "sh",
            "-c",
            f"du -sx -B1 {path} | cut -f1",
        ]
    )
    return int(value.splitlines()[-1])


def _published_blocks(conn: Any, archive_kind: str) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select first_event_id,last_event_id,row_count,raw_bytes,
                   compressed_bytes,raw_sha256,archive_sha256,object_location
            from storage_v2_archive_blocks
            where archive_kind=%s and state='published'
            order by first_event_id,last_event_id,archive_set_id,block_index
            """,
            (archive_kind,),
        )
        return [dict(row) for row in cur.fetchall()]


def _iter_verified_rows(
    blocks: Iterable[dict[str, Any]],
    *,
    expected_kind: str,
) -> Iterator[dict[str, Any]]:
    for block in blocks:
        path = Path(str(block["object_location"]))
        compressed = path.read_bytes()
        if (
            len(compressed) != int(block["compressed_bytes"])
            or hashlib.sha256(compressed).digest()
            != bytes(block["archive_sha256"])
        ):
            raise RuntimeError(f"archive compressed mismatch:{path.name}")
        raw = gzip.decompress(compressed)
        if (
            len(raw) != int(block["raw_bytes"])
            or hashlib.sha256(raw).digest() != bytes(block["raw_sha256"])
        ):
            raise RuntimeError(f"archive raw mismatch:{path.name}")
        rows = 0
        for line in raw.splitlines():
            envelope = json.loads(line)
            if envelope.get("kind") != expected_kind:
                raise RuntimeError("archive kind mismatch")
            row = envelope.get("row")
            if not isinstance(row, dict):
                raise RuntimeError("archive row is malformed")
            yield row
            rows += 1
        if rows != int(block["row_count"]):
            raise RuntimeError("archive block row count mismatch")


def _stream_contracts(conn: Any) -> dict[tuple[int, str], dict[str, str]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select distinct on (core.server_id, core.channel_id)
                   core.server_id, core.event_record_id,core.time_created_utc,
                   domain.domain_sid,domain.fqdn as domain_fqdn,
                   coalesce(nullif(server.fqdn,''),server.hostname) as server_fqdn,
                   channel.value as channel
            from events_v2_core core
            join servers server on server.id=core.server_id
            join domains domain on domain.id=server.domain_id
            join storage_v2_channel channel on channel.id=core.channel_id
            order by core.server_id,core.channel_id,
                     core.time_created_utc,core.id
            """
        )
        rows = [dict(row) for row in cur.fetchall()]
    result: dict[tuple[int, str], dict[str, str]] = {}
    for row in rows:
        source = initial_source_instance_uid(
            domain_sid=(
                str(row["domain_sid"])
                if str(row.get("domain_sid") or "").strip()
                else None
            ),
            domain_fqdn=str(row["domain_fqdn"]),
            server_fqdn=str(row["server_fqdn"]),
        )
        stream = stream_uid(
            source_instance_uid=source,
            stream_key=str(row["channel"]),
        )
        epoch = initial_log_epoch_uid(
            stream_uid_value=stream,
            first_event_record_id=int(row["event_record_id"]),
            first_event_time_utc=row["time_created_utc"],
        )
        result[(int(row["server_id"]), str(row["channel"]))] = {
            "source_instance_uid": source,
            "stream_uid": stream,
            "log_epoch_uid": epoch,
        }
    return result


def _ch_time(value: Any) -> str:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _sql_literal(value: Any) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _payload_sha256(row: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    for name in ("event_data_json", "message_text", "record_xml"):
        value = row.get(name)
        if value is None:
            digest.update(b"-1:")
            continue
        encoded = str(value).encode("utf-8")
        digest.update(str(len(encoded)).encode("ascii"))
        digest.update(b":")
        digest.update(encoded)
    return digest.hexdigest().upper()


def _update_link_digest(
    digest: Any,
    source_id: int,
    entity_ids: list[int],
    role_ids: list[int],
) -> None:
    if len(entity_ids) != len(role_ids):
        raise RuntimeError("entity/role arrays have different lengths")
    digest.update(struct.pack(">QI", int(source_id), len(entity_ids)))
    for entity_id, role_id in zip(entity_ids, role_ids, strict=True):
        digest.update(struct.pack(">QH", int(entity_id), int(role_id)))


def _verification_row_digest(
    *,
    source_id: int,
    event_uid_value: str,
    payload_hash: str,
    entity_ids: list[int],
    role_ids: list[int],
) -> bytes:
    digest = hashlib.sha256()
    digest.update(struct.pack(">Q", int(source_id)))
    digest.update(str(event_uid_value).encode("ascii"))
    digest.update(bytes.fromhex(str(payload_hash)))
    _update_link_digest(
        digest,
        int(source_id),
        entity_ids,
        role_ids,
    )
    return digest.digest()


def _update_multiset_accumulator(
    xor_value: int,
    sum_value: int,
    row_digest: bytes,
) -> tuple[int, int]:
    integer = int.from_bytes(row_digest, byteorder="big", signed=False)
    return xor_value ^ integer, (sum_value + integer) % (1 << 256)


def _render_multiset_accumulator(
    xor_value: int,
    sum_value: int,
) -> dict[str, str]:
    return {
        "verification_multiset_xor_sha256": f"{xor_value:064x}",
        "verification_multiset_sum_sha256": f"{sum_value:064x}",
    }


def _prepare_insert_row(
    row: dict[str, Any],
    *,
    portable_uid: str,
    entity_ids: list[int],
    role_ids: list[int],
) -> dict[str, Any]:
    prepared = {name: row.get(name) for name in INSERT_COLUMNS}
    prepared["source_id"] = int(row["id"])
    prepared["event_uid"] = portable_uid
    prepared["time_created_utc"] = _ch_time(row["time_created_utc"])
    prepared["normalized_at"] = _ch_time(row["normalized_at"])
    prepared["entity_ids"] = entity_ids
    prepared["entity_role_ids"] = role_ids
    return prepared


def _stream_insert(
    *,
    container: str,
    event_blocks: list[dict[str, Any]],
    link_blocks: list[dict[str, Any]],
    contracts: dict[tuple[int, str], dict[str, str]],
) -> dict[str, Any]:
    query = f"INSERT INTO {DATABASE}.{TABLE} FORMAT JSONEachRow"
    process = subprocess.Popen(
        [
            "docker",
            "exec",
            "-i",
            container,
            "clickhouse-client",
            "--query",
            query,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stderr is None:
        raise RuntimeError("ClickHouse insert pipe was not created")
    uid_sequence = hashlib.sha256()
    payload_sequence = hashlib.sha256()
    link_sequence = hashlib.sha256()
    link_iterator = _iter_verified_rows(
        link_blocks,
        expected_kind="link_detail",
    )
    current_link = next(link_iterator, None)
    rows = 0
    links = 0
    json_bytes = 0
    multiset_xor = 0
    multiset_sum = 0
    started = time.perf_counter()
    buffer = bytearray()
    try:
        for row in _iter_verified_rows(event_blocks, expected_kind="event"):
            source_id = int(row["id"])
            entity_ids: list[int] = []
            role_ids: list[int] = []
            while (
                current_link is not None
                and int(current_link["event_id"]) < source_id
            ):
                raise RuntimeError("link archive contains an unknown event id")
            while (
                current_link is not None
                and int(current_link["event_id"]) == source_id
            ):
                entity_ids.append(int(current_link["entity_id"]))
                role_ids.append(int(current_link["role_id"]))
                links += 1
                current_link = next(link_iterator, None)
            contract = contracts[(int(row["server_id"]), str(row["channel"]))]
            portable_uid = event_uid(
                source_instance_uid=contract["source_instance_uid"],
                stream_uid_value=contract["stream_uid"],
                log_epoch_uid=contract["log_epoch_uid"],
                event_record_id=int(row["event_record_id"]),
                event_time_utc=row["time_created_utc"],
                normalized_sha256=str(row["normalized_hash"]),
            )
            uid_sequence.update(portable_uid.encode("ascii"))
            uid_sequence.update(b"\n")
            payload_hash = _payload_sha256(row)
            payload_sequence.update(payload_hash.encode("ascii"))
            payload_sequence.update(b"\n")
            _update_link_digest(
                link_sequence,
                source_id,
                entity_ids,
                role_ids,
            )
            multiset_xor, multiset_sum = _update_multiset_accumulator(
                multiset_xor,
                multiset_sum,
                _verification_row_digest(
                    source_id=source_id,
                    event_uid_value=portable_uid,
                    payload_hash=payload_hash,
                    entity_ids=entity_ids,
                    role_ids=role_ids,
                ),
            )
            prepared = _prepare_insert_row(
                row,
                portable_uid=portable_uid,
                entity_ids=entity_ids,
                role_ids=role_ids,
            )
            encoded = (
                json.dumps(
                    prepared,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            buffer.extend(encoded)
            json_bytes += len(encoded)
            rows += 1
            if len(buffer) >= 4 * 1024 * 1024:
                process.stdin.write(buffer)
                buffer.clear()
        if current_link is not None:
            raise RuntimeError("link archive extends beyond the event corpus")
        if buffer:
            process.stdin.write(buffer)
        process.stdin.close()
        stderr = process.stderr.read()
        returncode = process.wait(timeout=1800)
    except BaseException:
        process.kill()
        process.wait(timeout=30)
        raise
    if returncode != 0:
        raise RuntimeError(
            "ClickHouse full-corpus insert failed:"
            + stderr.decode("utf-8", errors="replace")[-3000:]
        )
    elapsed = time.perf_counter() - started
    result = {
        "rows": rows,
        "link_tuples": links,
        "json_input_bytes": json_bytes,
        "elapsed_seconds": elapsed,
        "rows_per_second": rows / elapsed,
        "input_bytes_per_second": json_bytes / elapsed,
        "event_uid_sequence_sha256": uid_sequence.hexdigest(),
        "payload_sequence_sha256": payload_sequence.hexdigest(),
        "link_tuple_sequence_sha256": link_sequence.hexdigest(),
    }
    result.update(_render_multiset_accumulator(multiset_xor, multiset_sum))
    return result


PAYLOAD_HASH_EXPRESSION = """
hex(SHA256(concat(
    toString(length(event_data_json)), ':', event_data_json,
    if(isNull(message_text), '-1:',
       concat(toString(length(assumeNotNull(message_text))), ':',
              assumeNotNull(message_text))),
    toString(length(record_xml)), ':', record_xml
)))
"""


def _readback_digests(port: int, table: str) -> dict[str, Any]:
    query = (
        f"SELECT source_id,event_uid,{PAYLOAD_HASH_EXPRESSION} AS payload_hash,"
        f"entity_ids,entity_role_ids FROM {DATABASE}.{table} "
        "SETTINGS max_threads=1,max_block_size=4096,"
        "max_memory_usage=1073741824 "
        "FORMAT JSONEachRow"
    )
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        int(port),
        timeout=1800,
    )
    try:
        connection.request(
            "POST",
            "/",
            body=query.encode("utf-8"),
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        response = connection.getresponse()
        if response.status != 200:
            payload = response.read()
            raise RuntimeError(
                f"ClickHouse readback HTTP {response.status}:"
                f"{payload.decode('utf-8', errors='replace')[-3000:]}"
            )
        rows = 0
        links = 0
        multiset_xor = 0
        multiset_sum = 0
        for line in response:
            row = json.loads(line)
            entity_ids = [int(value) for value in row["entity_ids"]]
            role_ids = [int(value) for value in row["entity_role_ids"]]
            multiset_xor, multiset_sum = _update_multiset_accumulator(
                multiset_xor,
                multiset_sum,
                _verification_row_digest(
                    source_id=int(row["source_id"]),
                    event_uid_value=str(row["event_uid"]),
                    payload_hash=str(row["payload_hash"]),
                    entity_ids=entity_ids,
                    role_ids=role_ids,
                ),
            )
            links += len(entity_ids)
            rows += 1
    finally:
        connection.close()
    result = {
        "rows": rows,
        "link_tuples": links,
    }
    result.update(_render_multiset_accumulator(multiset_xor, multiset_sum))
    return result


def _query_seed_values(conn: Any) -> dict[str, Any]:
    seeds = _query_seeds(conn)
    with conn.cursor() as cur:
        cur.execute(
            "select value from storage_v2_channel where id=%s",
            (int(seeds["channel_id"]),),
        )
        seeds["channel"] = str(cur.fetchone()["value"])
        cur.execute(
            """
            select encode(normalized_hash,'hex') as normalized_hash,
                   event_record_id,time_created_utc,event_id,server_id,channel_id
            from events_v2_core where id=%s
            """,
            (int(seeds["detail_event_id"]),),
        )
        seeds["detail"] = dict(cur.fetchone())
        cur.execute(
            "select value from storage_v2_channel where id=%s",
            (int(seeds["detail"]["channel_id"]),),
        )
        seeds["detail"]["channel"] = str(cur.fetchone()["value"])
    return seeds


def _workloads(seeds: dict[str, Any]) -> dict[str, str]:
    detail = seeds["detail"]
    workloads = {
        "latest_events": (
            f"select source_id,event_id,event_record_id,time_created_utc "
            f"from {DATABASE}.{TABLE} order by time_created_utc desc,"
            "source_id desc limit 100 format JSONEachRow"
        ),
        "event_id_time": (
            f"select source_id,event_id,event_record_id,time_created_utc "
            f"from {DATABASE}.{TABLE} where event_id={int(seeds['event_id'])} "
            "order by time_created_utc desc,source_id desc limit 100 "
            "format JSONEachRow"
        ),
        "server_time": (
            f"select source_id,event_id,event_record_id,time_created_utc "
            f"from {DATABASE}.{TABLE} where server_id={int(seeds['server_id'])} "
            "order by time_created_utc desc,source_id desc limit 100 "
            "format JSONEachRow"
        ),
        "channel_event_time": (
            f"select source_id,event_id,event_record_id,time_created_utc "
            f"from {DATABASE}.{TABLE} "
            f"where channel={_sql_literal(seeds['channel'])} "
            f"and event_id={int(seeds['event_id'])} "
            "order by time_created_utc desc,source_id desc limit 100 "
            "format JSONEachRow"
        ),
        "entity_timeline": (
            f"select source_id as event_id,role_id from {DATABASE}.{TABLE} "
            "array join entity_ids as entity_id,entity_role_ids as role_id "
            f"where entity_id={int(seeds['entity_id'])} "
            "order by source_id desc,role_id asc limit 100 format JSONEachRow"
        ),
        "event_detail": (
            f"select * from {DATABASE}.{TABLE} "
            f"where server_id={int(detail['server_id'])} "
            f"and channel={_sql_literal(detail['channel'])} "
            f"and event_id={int(detail['event_id'])} "
            f"and event_record_id={int(detail['event_record_id'])} "
            f"and source_id={int(seeds['detail_event_id'])} "
            "limit 1 format JSONEachRow"
        ),
    }
    for name, column in (
        ("subject_account_time", "subject_user_name"),
        ("target_account_time", "target_user_name"),
        ("ip_time", "ip_address"),
        ("logon_id_time", "logon_id"),
    ):
        value = seeds.get(column)
        if value is None:
            continue
        workloads[name] = (
            f"select source_id,event_id,event_record_id,time_created_utc "
            f"from {DATABASE}.{TABLE} "
            f"where {column}={_sql_literal(value)} "
            "order by time_created_utc desc,source_id desc limit 100 "
            "format JSONEachRow"
        )
    return workloads


def _reference_timeline(seeds: dict[str, Any], connect) -> list[dict[str, int]]:
    sql, params = _control_workloads(seeds)["entity_timeline"]
    with connect() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return _normalize_timeline([dict(row) for row in cur.fetchall()])


def _assert_timeline_parity(port: int, seeds: dict[str, Any], query: str, *, connect, table: str) -> list[dict[str, int]]:
    if connect is None:
        raise RuntimeError("timeline requires a snapshot-bound reference connector")
    invalid = _http_query(port, (
        f"select count() from {DATABASE}.{table} "
        "where length(entity_ids)!=length(entity_role_ids) format TabSeparated"
    ))
    if int(invalid.strip()) != 0:
        raise RuntimeError("timeline entity/role arrays have different lengths")
    reference = _reference_timeline(seeds, connect)
    candidate = _normalize_timeline([json.loads(line) for line in _http_query(port, query).splitlines()])
    if candidate != reference:
        raise RuntimeError("timeline cross-engine semantic mismatch")
    return reference


def _validate_detail_result(payload: bytes, seeds: dict[str, Any]) -> None:
    rows = [json.loads(line) for line in payload.splitlines() if line.strip()]
    if len(rows) != 1:
        raise RuntimeError("ClickHouse detail did not return exactly one row")
    row, detail = rows[0], seeds["detail"]
    expected = {"source_id": seeds["detail_event_id"], "server_id": detail["server_id"],
                "event_id": detail["event_id"], "event_record_id": detail["event_record_id"]}
    if any(int(row[key]) != int(value) for key, value in expected.items()):
        raise RuntimeError("ClickHouse detail identity mismatch")
    if row["channel"] != detail["channel"]:
        raise RuntimeError("ClickHouse detail channel mismatch")


def _cleanup_owned_resources(
    container: str | None, volumes: list[str],
) -> list[dict[str, Any]]:
    failures = []
    commands = []
    if container is not None:
        commands.append(("container", ["docker", "rm", "-f", container]))
    if volumes:
        commands.append(("volumes", ["docker", "volume", "rm", *volumes]))
    for target, command in commands:
        try:
            cleanup = subprocess.run(command, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, check=False)
            if cleanup.returncode != 0:
                failure = {"target": target, "returncode": cleanup.returncode}
                stderr = getattr(cleanup, "stderr", b"")
                if stderr:
                    failure["error"] = stderr.decode("utf-8", errors="replace")[-1000:]
                failures.append(failure)
        except Exception as exc:
            # Never replace the acquisition/build/query exception with cleanup failure.
            failures.append({"target": target, "error": str(exc)})
    return failures


def _measure_queries(
    port: int,
    seeds: dict[str, Any],
    *,
    independent_runs: int,
    warmups: int,
    measured: int,
    reference_connect=None,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, query in _workloads(seeds).items():
        reference = _assert_timeline_parity(port, seeds, query, connect=reference_connect, table=TABLE) if name == "entity_timeline" else None
        samples: list[float] = []
        semantic_hash: str | None = None
        rows = 0
        for _run in range(independent_runs):
            for _ in range(warmups):
                _http_query(port, query)
            for _ in range(measured):
                started = time.perf_counter()
                payload = _http_query(port, query)
                elapsed_ms = (time.perf_counter() - started) * 1000
                if name == "entity_timeline":
                    current = _normalize_timeline([json.loads(line) for line in payload.splitlines()])
                    if current != reference:
                        raise RuntimeError("timeline cross-engine semantic mismatch")
                if name == "event_detail":
                    _validate_detail_result(payload, seeds)
                samples.append(elapsed_ms)
                current_hash = hashlib.sha256(payload).hexdigest()
                if semantic_hash not in (None, current_hash):
                    raise RuntimeError(f"non-deterministic ClickHouse query:{name}")
                semantic_hash = current_hash
                rows = len(payload.splitlines())
        result[name] = {
            "sample_count": len(samples),
            "p50_ms": sorted(samples)[len(samples) // 2],
            "p95_ms": _p95(samples),
            "max_ms": max(samples),
            "result_rows": rows,
            "result_sha256": semantic_hash,
            **({"timeline_contract_version": TIMELINE_CONTRACT_VERSION,
                "cross_engine_parity": True, "entity_id": int(seeds["entity_id"]),
                "semantic_sha256": _digest_rows(reference)}
               if name == "entity_timeline" else {}),
        }
    return result


def _table_storage(port: int, table: str) -> dict[str, int]:
    query = (
        "select coalesce(sum(bytes_on_disk),0) bytes_on_disk,"
        "coalesce(sum(data_compressed_bytes),0) data_compressed_bytes,"
        "coalesce(sum(data_uncompressed_bytes),0) data_uncompressed_bytes,"
        "coalesce(sum(marks_bytes),0) marks_bytes "
        "from system.parts where active and database='stage7' "
        f"and table={_sql_literal(table)} format JSONEachRow"
    )
    rows = _http_query(port, query)
    return {key: int(value) for key, value in json.loads(rows).items()}


def run() -> dict[str, Any]:
    with _exported_snapshot(_snapshot_source()) as (connect, receipt):
        return _run_candidate(connect, receipt)


def _run_candidate(connect, receipt) -> dict[str, Any]:
    contract = _load_contract()
    expected = contract["canonical_corpus"]
    performance = contract["performance_gates"]
    recovery_evidence = json.loads(
        (
            ROOT / "artifacts/stage7/evidence/control-d-prime-recovery.json"
        ).read_text(encoding="utf-8")
    )
    with connect() as conn:
        snapshot_corpus = _verify_snapshot_corpus(conn, expected)
        event_blocks = _published_blocks(conn, "event")
        link_blocks = _published_blocks(conn, "link_detail")
        contracts = _stream_contracts(conn)
        seeds = _query_seed_values(conn)
        relation_sizes = _relation_sizes(conn)

    suffix = uuid.uuid4().hex[:10]
    container = f"sli-stage7-a-{suffix}"
    data_volume = f"sli-stage7-a-data-{suffix}"
    backup_volume = f"sli-stage7-a-backup-{suffix}"
    config_path = (
        ROOT / "config" / "stage7_clickhouse_backup.xml"
    ).resolve()
    started = False
    result: dict[str, Any] | None = None
    cleanup_failures: list[dict[str, Any]] = []
    owned_volumes: list[str] = []
    try:
        for volume in (data_volume, backup_volume):
            _docker(["volume", "create", volume])
            owned_volumes.append(volume)
        _docker(
            [
                "run",
                "-d",
                "--rm",
                "--name",
                container,
                "--memory",
                "4g",
                "--memory-swap",
                "6g",
                "--ulimit",
                "nofile=262144:262144",
                "-e",
                "CLICKHOUSE_SKIP_USER_SETUP=1",
                "-p",
                "127.0.0.1::8123",
                "-v",
                f"{data_volume}:/var/lib/clickhouse",
                "-v",
                f"{backup_volume}:/var/lib/clickhouse/backups",
                "--mount",
                (
                    f"type=bind,source={config_path},"
                    "target=/etc/clickhouse-server/config.d/"
                    "stage7_backup.xml,readonly"
                ),
                IMAGE,
            ],
            timeout=120,
        )
        started = True
        _wait_ready(container)
        port = _container_port(container)
        _http_query(port, CREATE_DATABASE_SQL)
        _http_query(port, CREATE_TABLE_SQL)
        inserted = _stream_insert(
            container=container,
            event_blocks=event_blocks,
            link_blocks=link_blocks,
            contracts=contracts,
        )
        if (
            inserted["rows"] != int(expected["events"])
            or inserted["link_tuples"] != int(expected["event_entity_links"])
            or inserted["event_uid_sequence_sha256"]
            != str(expected["event_uid_sequence_sha256"])
        ):
            raise RuntimeError("candidate A source corpus identity mismatch")
        _http_query(port, f"OPTIMIZE TABLE {DATABASE}.{TABLE} FINAL")
        readback = _readback_digests(port, TABLE)
        if readback != {
            key: inserted[key]
            for key in (
                "rows",
                "link_tuples",
                "verification_multiset_xor_sha256",
                "verification_multiset_sum_sha256",
            )
        }:
            raise RuntimeError("candidate A ClickHouse readback mismatch")
        query_benchmarks = _measure_queries(
            port,
            seeds,
            reference_connect=connect,
            independent_runs=int(performance["independent_runs"]),
            warmups=int(performance["warmup_runs_per_query"]),
            measured=int(performance["measured_runs_per_query"]),
        )
        table_storage = _table_storage(port, TABLE)
        live_clickhouse_volume = _volume_bytes(
            container,
            "/var/lib/clickhouse",
        )
        backup_name = "candidate-a.zip"
        _http_query(
            port,
            (
                f"BACKUP TABLE {DATABASE}.{TABLE} "
                f"TO Disk('backups','{backup_name}') "
                "SETTINGS compression_method='zstd',compression_level=9"
            ),
            timeout=1800,
        )
        backup_bytes = _volume_bytes(
            container,
            "/var/lib/clickhouse/backups",
        )
        _http_query(
            port,
            (
                f"RESTORE TABLE {DATABASE}.{TABLE} AS "
                f"{DATABASE}.{TABLE}_restore "
                f"FROM Disk('backups','{backup_name}')"
            ),
            timeout=1800,
        )
        restored_readback = _readback_digests(port, f"{TABLE}_restore")
        if restored_readback != readback:
            raise RuntimeError("candidate A restored readback mismatch")
        restored_storage = _table_storage(port, f"{TABLE}_restore")
        restore_volume_total = _volume_bytes(
            container,
            "/var/lib/clickhouse",
        )
        restore_temporary_bytes = max(
            int(restored_storage["bytes_on_disk"]),
            restore_volume_total - live_clickhouse_volume,
        )
        image_digest = _docker(
            ["image", "inspect", "--format", "{{index .RepoDigests 0}}", IMAGE]
        )

        raw_bytes = int(expected["archive_compressed_bytes"])
        common_pg_control = int(
            relation_sizes["common_postgres_control_plane_bytes"]
        )
        live_without_registry = (
            live_clickhouse_volume + raw_bytes + common_pg_control
        )
        full_without_registry = (
            live_without_registry
            + raw_bytes
            + backup_bytes
            + restore_temporary_bytes
        )
        result = {
            "status": "measured_restored_registry_pending",
            "candidate": "A",
            "mode": "isolated_single_node_full_corpus",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "image": image_digest,
            "schema_sha256": hashlib.sha256(
                CREATE_TABLE_SQL.encode("utf-8")
            ).hexdigest(),
            "corpus": {
                "source": inserted,
                "clickhouse_readback": readback,
                "restored_readback": restored_readback,
                "semantic_parity": True,
            },
            "ingest": inserted,
            "query_benchmarks": query_benchmarks,
            "storage": {
                "clickhouse_table": table_storage,
                "clickhouse_live_volume_bytes": live_clickhouse_volume,
                "canonical_raw_bytes": raw_bytes,
                "postgresql_common_control_plane_bytes": common_pg_control,
                "independent_raw_copy_bytes": raw_bytes,
                "clickhouse_backup_bytes": backup_bytes,
                "restore_temporary_bytes": restore_temporary_bytes,
                "live_bytes_without_event_registry": live_without_registry,
                "full_managed_storage_bytes_without_event_registry": None,
                "diagnostic_live_file_full_managed_storage_bytes_without_event_registry": (
                    full_without_registry
                ),
                "event_registry_bytes": None,
                "full_managed_storage_bytes": None,
                "control_d_prime_full_managed_storage_bytes": None,
                "historical_unbound_control_d_prime_full_managed_storage_bytes": int(
                    recovery_evidence["storage"]["full_managed_storage_bytes"]
                ),
            },
            "pending_gates": [
            "isolated PostgreSQL physical-size measurement bound to verified corpus",
                "shared PostgreSQL event registry and delivery ledger size",
                "report and access semantic parity suite",
                "sustained live-batch ingest relative to measured peak",
            ],
            "production_mutated": False,
            "snapshot": receipt,
            "postgresql_physical_size_scope": relation_sizes["postgresql_physical_size_scope"],
            "source_snapshot_corpus": snapshot_corpus,
            "collection_started": False,
            "temporary_container_and_volumes_removed": None,
            "payload_values_in_evidence": False,
        }
    finally:
        cleanup_failures.extend(_cleanup_owned_resources(
            container if started else None, owned_volumes,
        ))
        if result is not None:
            result["temporary_container_and_volumes_removed"] = (
                not cleanup_failures
            )
            result["cleanup_failures"] = cleanup_failures
            if cleanup_failures:
                result["status"] = "measurement_complete_cleanup_failed"
    if result is None:
        raise RuntimeError("candidate A did not produce a result")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Измерить ClickHouse-кандидат A на полном корпусе."
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run()
    output = (ROOT / args.output).resolve()
    output.relative_to(ROOT.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    print(
        "ClickHouse A измерен и восстановлен; "
        f"объём без общего event registry: "
        "ожидает изолированного измерения PostgreSQL; диагностические значения в JSON."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

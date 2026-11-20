#!/usr/bin/env python3
"""Full-corpus ClickHouse candidate B with compact core and RAW locator."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.stage7_clickhouse_candidate_a import (  # noqa: E402
    IMAGE,
    _ch_time,
    _assert_timeline_parity,
    _validate_detail_result,
    _normalize_timeline,
    TIMELINE_CONTRACT_VERSION,
    _cleanup_owned_resources,
    _connect as _connect,
    _exported_snapshot,
    _snapshot_source,
    _verify_snapshot_corpus,
    _container_port,
    _docker,
    _http_query,
    _iter_verified_rows,
    _load_contract,
    _p95,
    _published_blocks,
    _query_seed_values,
    _relation_sizes,
    _render_multiset_accumulator,
    _sql_literal,
    _stream_contracts,
    _table_storage,
    _update_link_digest,
    _update_multiset_accumulator,
    _volume_bytes,
    _wait_ready,
)
from scripts.maintenance.stage7_control_d_prime_benchmark import (  # noqa: E402
    FramedArchiveBuilder,
    FramedArchiveReader,
    _digest_rows,
    _stream_source_into_builders,
)
from scripts.maintenance.stage7_event_identity import event_uid  # noqa: E402


DATABASE = "stage7"
TABLE = "events_b"
RAW_FRAME_ROWS = 512
B_COLUMNS = (
    "source_id",
    "event_uid_hex",
    "raw_frame_no",
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
    "channel",
    "computer",
    "time_created_utc",
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
    "normalized_hash",
    "entity_ids",
    "entity_role_ids",
)

CREATE_TABLE_SQL = f"""
CREATE TABLE {DATABASE}.{TABLE}
(
    source_id UInt64 CODEC(Delta, ZSTD(3)),
    event_uid_hex FixedString(64),
    raw_frame_no UInt32 CODEC(Delta, ZSTD(3)),
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
    channel LowCardinality(String),
    computer LowCardinality(String),
    time_created_utc DateTime64(6, 'UTC') CODEC(Delta, ZSTD(3)),
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
    normalized_hash FixedString(64),
    entity_ids Array(UInt64) CODEC(ZSTD(3)),
    entity_role_ids Array(UInt16) CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(time_created_utc)
ORDER BY (server_id, channel, event_id, time_created_utc, source_id)
SETTINGS index_granularity = 8192;
"""


def _prepare_b_row(
    row: dict[str, Any],
    *,
    portable_uid: str,
    raw_frame_no: int,
    entity_ids: list[int],
    role_ids: list[int],
) -> dict[str, Any]:
    prepared = {name: row.get(name) for name in B_COLUMNS}
    prepared["source_id"] = int(row["id"])
    prepared["event_uid_hex"] = portable_uid.removeprefix("sli-event-v1:")
    prepared["raw_frame_no"] = int(raw_frame_no)
    prepared["time_created_utc"] = _ch_time(row["time_created_utc"])
    prepared["normalized_hash"] = str(row["normalized_hash"]).casefold()
    prepared["entity_ids"] = entity_ids
    prepared["entity_role_ids"] = role_ids
    return prepared


def _row_digest(row: dict[str, Any]) -> bytes:
    encoded = json.dumps(
        row,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).digest()


def _stream_insert(
    *,
    container: str,
    event_blocks: list[dict[str, Any]],
    link_blocks: list[dict[str, Any]],
    contracts: dict[tuple[int, str], dict[str, str]],
) -> dict[str, Any]:
    process = subprocess.Popen(
        [
            "docker",
            "exec",
            "-i",
            container,
            "clickhouse-client",
            "--query",
            f"INSERT INTO {DATABASE}.{TABLE} FORMAT JSONEachRow",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stderr is None:
        raise RuntimeError("ClickHouse B insert pipe was not created")
    link_iterator = _iter_verified_rows(link_blocks, expected_kind="link_detail")
    current_link = next(link_iterator, None)
    uid_sequence = hashlib.sha256()
    link_sequence = hashlib.sha256()
    multiset_xor = 0
    multiset_sum = 0
    rows = 0
    links = 0
    json_bytes = 0
    buffer = bytearray()
    started = time.perf_counter()
    try:
        for row in _iter_verified_rows(event_blocks, expected_kind="event"):
            source_id = int(row["id"])
            entity_ids: list[int] = []
            role_ids: list[int] = []
            while (
                current_link is not None
                and int(current_link["event_id"]) < source_id
            ):
                raise RuntimeError("B link archive contains an unknown event")
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
            uid_sequence.update(portable_uid.encode("ascii") + b"\n")
            _update_link_digest(
                link_sequence,
                source_id,
                entity_ids,
                role_ids,
            )
            prepared = _prepare_b_row(
                row,
                portable_uid=portable_uid,
                raw_frame_no=rows // RAW_FRAME_ROWS,
                entity_ids=entity_ids,
                role_ids=role_ids,
            )
            multiset_xor, multiset_sum = _update_multiset_accumulator(
                multiset_xor,
                multiset_sum,
                _row_digest(prepared),
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
            raise RuntimeError("B link archive extends beyond event corpus")
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
            "ClickHouse B full-corpus insert failed:"
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
        "link_tuple_sequence_sha256": link_sequence.hexdigest(),
    }
    result.update(_render_multiset_accumulator(multiset_xor, multiset_sum))
    return result


def _readback(port: int, table: str) -> dict[str, Any]:
    columns = ",".join(B_COLUMNS)
    query = (
        f"SELECT {columns} FROM {DATABASE}.{table} "
        "SETTINGS max_threads=1,max_block_size=4096,"
        "max_memory_usage=1073741824 FORMAT JSONEachRow"
    )
    import http.client

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
                f"ClickHouse B readback HTTP {response.status}:"
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
            row["entity_ids"] = entity_ids
            row["entity_role_ids"] = role_ids
            multiset_xor, multiset_sum = _update_multiset_accumulator(
                multiset_xor,
                multiset_sum,
                _row_digest(row),
            )
            rows += 1
            links += len(entity_ids)
    finally:
        connection.close()
    result = {"rows": rows, "link_tuples": links}
    result.update(_render_multiset_accumulator(multiset_xor, multiset_sum))
    return result


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
                samples.append(elapsed_ms)
                current_hash = hashlib.sha256(payload).hexdigest()
                if semantic_hash not in (None, current_hash):
                    raise RuntimeError(f"non-deterministic B query:{name}")
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


def _measure_detail(
    port: int,
    seeds: dict[str, Any],
    *,
    data_path: Path,
    index_path: Path,
    independent_runs: int,
    warmups: int,
    measured: int,
) -> dict[str, Any]:
    detail = seeds["detail"]
    query = (
        f"select source_id,server_id,channel,event_id,event_record_id,event_uid_hex,raw_frame_no from {DATABASE}.{TABLE} "
        f"where server_id={int(detail['server_id'])} "
        f"and channel={_sql_literal(detail['channel'])} "
        f"and event_id={int(detail['event_id'])} "
        f"and event_record_id={int(detail['event_record_id'])} "
        f"and source_id={int(seeds['detail_event_id'])} "
        "limit 1 format JSONEachRow"
    )
    expected_id = int(seeds["detail_event_id"])
    cold: list[float] = []
    warm: list[float] = []
    semantic_sha: str | None = None
    for _run in range(independent_runs):
        started = time.perf_counter()
        reader = FramedArchiveReader(data_path, index_path)
        try:
            core_payload = _http_query(port, query)
            _validate_detail_result(core_payload, seeds)
            raw_row = reader.read_event(expected_id)
            cold.append((time.perf_counter() - started) * 1000)
            current_sha = _digest_rows([raw_row])
            if semantic_sha not in (None, current_sha):
                raise RuntimeError("non-deterministic B RAW detail")
            semantic_sha = current_sha
            if len(core_payload.splitlines()) != 1:
                raise RuntimeError("B detail locator did not return one row")
            for _ in range(warmups):
                _http_query(port, query)
                reader.read_event(expected_id)
            for _ in range(measured):
                started = time.perf_counter()
                core_payload = _http_query(port, query)
                _validate_detail_result(core_payload, seeds)
                raw_row = reader.read_event(expected_id)
                warm.append((time.perf_counter() - started) * 1000)
                if (
                    len(core_payload.splitlines()) != 1
                    or _digest_rows([raw_row]) != semantic_sha
                ):
                    raise RuntimeError("B detail semantic mismatch")
        finally:
            reader.close()
    return {
        "cold_sample_count": len(cold),
        "cold_p50_ms": sorted(cold)[len(cold) // 2],
        "cold_p95_ms": _p95(cold),
        "warm_sample_count": len(warm),
        "warm_p50_ms": sorted(warm)[len(warm) // 2],
        "warm_p95_ms": _p95(warm),
        "warm_max_ms": max(warm),
        "result_rows": 1,
        "raw_semantic_sha256": semantic_sha,
    }


def run() -> dict[str, Any]:
    with _exported_snapshot(_snapshot_source()) as (connect, receipt):
        return _run_candidate(connect, receipt)


def _run_candidate(connect, receipt) -> dict[str, Any]:
    contract = _load_contract()
    expected = contract["canonical_corpus"]
    performance = contract["performance_gates"]
    recovery = json.loads(
        (ROOT / "artifacts/stage7/evidence/control-d-prime-recovery.json")
        .read_text(encoding="utf-8")
    )
    with connect() as conn:
        snapshot_corpus = _verify_snapshot_corpus(conn, expected)
        event_blocks = _published_blocks(conn, "event")
        link_blocks = _published_blocks(conn, "link_detail")
        contracts = _stream_contracts(conn)
        seeds = _query_seed_values(conn)
        relation_sizes = _relation_sizes(conn)

    work_root = ROOT / "artifacts/stage7/tmp"
    work_root.mkdir(parents=True, exist_ok=True)
    suffix = uuid.uuid4().hex[:10]
    container = f"sli-stage7-b-{suffix}"
    data_volume = f"sli-stage7-b-data-{suffix}"
    backup_volume = f"sli-stage7-b-backup-{suffix}"
    cleanup_failures: list[dict[str, Any]] = []
    result: dict[str, Any] | None = None
    started = False
    owned_volumes: list[str] = []
    try:
        for volume in (data_volume, backup_volume):
            _docker(["volume", "create", volume])
            owned_volumes.append(volume)
        with tempfile.TemporaryDirectory(
            prefix="candidate-b-",
            dir=work_root,
        ) as temporary:
            temporary_path = Path(temporary)
            raw_data = temporary_path / "events-512.frames"
            raw_index = temporary_path / "events-512.idx"
            builder = FramedArchiveBuilder(
                data_path=raw_data,
                index_path=raw_index,
                target_rows=RAW_FRAME_ROWS,
            )
            source_archive = _stream_source_into_builders(
                event_blocks,
                [builder],
            )
            raw_build = builder.finish()
            config_path = (
                ROOT / "config/stage7_clickhouse_backup.xml"
            ).resolve()
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
            _http_query(port, f"CREATE DATABASE IF NOT EXISTS {DATABASE}")
            _http_query(port, CREATE_TABLE_SQL)
            inserted = _stream_insert(
                container=container,
                event_blocks=event_blocks,
                link_blocks=link_blocks,
                contracts=contracts,
            )
            if (
                inserted["rows"] != int(expected["events"])
                or inserted["link_tuples"]
                != int(expected["event_entity_links"])
                or inserted["event_uid_sequence_sha256"]
                != str(expected["event_uid_sequence_sha256"])
                or int(raw_build["event_rows"]) != int(expected["events"])
            ):
                raise RuntimeError("candidate B source corpus mismatch")
            _http_query(port, f"OPTIMIZE TABLE {DATABASE}.{TABLE} FINAL")
            readback = _readback(port, TABLE)
            expected_readback = {
                key: inserted[key]
                for key in (
                    "rows",
                    "link_tuples",
                    "verification_multiset_xor_sha256",
                    "verification_multiset_sum_sha256",
                )
            }
            if readback != expected_readback:
                raise RuntimeError("candidate B ClickHouse readback mismatch")
            query_benchmarks = _measure_queries(
                port,
                seeds,
                reference_connect=connect,
                independent_runs=int(performance["independent_runs"]),
                warmups=int(performance["warmup_runs_per_query"]),
                measured=int(performance["measured_runs_per_query"]),
            )
            query_benchmarks["event_detail"] = _measure_detail(
                port,
                seeds,
                data_path=raw_data,
                index_path=raw_index,
                independent_runs=int(performance["independent_runs"]),
                warmups=int(performance["warmup_runs_per_query"]),
                measured=int(performance["measured_runs_per_query"]),
            )
            table_storage = _table_storage(port, TABLE)
            live_volume = _volume_bytes(container, "/var/lib/clickhouse")
            backup_name = "candidate-b.zip"
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
            restored = _readback(port, f"{TABLE}_restore")
            if restored != readback:
                raise RuntimeError("candidate B restored readback mismatch")
            restored_storage = _table_storage(port, f"{TABLE}_restore")
            restore_volume_total = _volume_bytes(
                container,
                "/var/lib/clickhouse",
            )
            restore_temporary = max(
                int(restored_storage["bytes_on_disk"]),
                restore_volume_total - live_volume,
            )
            link_archive_bytes = int(
                recovery["independent_recovery_copy"]["link_detail"]["bytes"]
            )
            raw_live_bytes = (
                int(raw_build["archive_and_index_bytes"])
                + link_archive_bytes
            )
            recovery_copy_bytes = int(
                recovery["independent_recovery_copy"]["bytes"]
            )
            common_pg = int(
                relation_sizes["common_postgres_control_plane_bytes"]
            )
            live_without_registry = live_volume + raw_live_bytes + common_pg
            full_without_registry = (
                live_without_registry
                + recovery_copy_bytes
                + backup_bytes
                + restore_temporary
            )
            result = {
                "status": "measured_restored_registry_pending",
                "candidate": "B",
                "mode": "compact_clickhouse_core_plus_single_raw_locator",
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "image": _docker(
                    [
                        "image",
                        "inspect",
                        "--format",
                        "{{index .RepoDigests 0}}",
                        IMAGE,
                    ]
                ),
                "schema_sha256": hashlib.sha256(
                    CREATE_TABLE_SQL.encode("utf-8")
                ).hexdigest(),
                "corpus": {
                    "source": inserted,
                    "clickhouse_readback": readback,
                    "restored_readback": restored,
                    "raw_archive_source": source_archive,
                    "raw_locator_archive": raw_build,
                    "link_provenance_recovery": recovery[
                        "independent_recovery_copy"
                    ]["link_detail"],
                    "semantic_parity": True,
                },
                "ingest": inserted,
                "query_benchmarks": query_benchmarks,
                "storage": {
                    "clickhouse_table": table_storage,
                    "clickhouse_live_volume_bytes": live_volume,
                    "raw_event_frames_and_index_bytes": int(
                        raw_build["archive_and_index_bytes"]
                    ),
                    "link_provenance_archive_bytes": link_archive_bytes,
                    "raw_live_bytes": raw_live_bytes,
                    "postgresql_common_control_plane_bytes": common_pg,
                    "independent_recovery_copy_bytes": recovery_copy_bytes,
                    "clickhouse_backup_bytes": backup_bytes,
                    "restore_temporary_bytes": restore_temporary,
                    "live_bytes_without_event_registry": live_without_registry,
                    "full_managed_storage_bytes_without_event_registry": None,
                "diagnostic_live_file_full_managed_storage_bytes_without_event_registry": (
                        full_without_registry
                    ),
                    "event_registry_bytes": None,
                    "full_managed_storage_bytes": None,
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
                "temporary_raw_frames_removed": None,
                "payload_values_in_evidence": False,
            }
    finally:
        cleanup_failures.extend(_cleanup_owned_resources(
            container if started else None, owned_volumes,
        ))
        if result is not None:
            result["temporary_container_and_volumes_removed"] = not cleanup_failures
            result["cleanup_failures"] = cleanup_failures
            if cleanup_failures:
                result["status"] = "measurement_complete_cleanup_failed"
    if result is None:
        raise RuntimeError("candidate B did not produce a result")
    result["temporary_raw_frames_removed"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Измерить ClickHouse-кандидат B на полном корпусе."
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run()
    output = (ROOT / args.output).resolve()
    output.relative_to(ROOT.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "ClickHouse B измерен и восстановлен; "
        f"объём без event registry: "
        "ожидает изолированного измерения PostgreSQL; диагностические значения в JSON."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

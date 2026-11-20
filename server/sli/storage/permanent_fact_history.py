"""Bounded, restartable copy of compact V2 facts and links to ClickHouse.

The published batch is written only after exact ClickHouse readback. This
module never deletes a PostgreSQL row or an archive file.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from array import array
from bisect import bisect_left
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

from server.sli.core.secret_files import secret_value
from server.sli.events.event_catalog import lookup_event_catalog
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.storage.storage_lifecycle_io import (
    _connect,
    _container_port,
)
from server.sli.storage.storage_lifecycle_io import (
    _http_insert_json_rows as _transport_insert_json_rows,
)
from server.sli.storage.storage_lifecycle_io import (
    _http_query as _transport_query,
)
from server.sli.storage.storage_lifecycle_io import (
    _http_stream_json_rows as _transport_stream_json_rows,
)
from server.sli.storage.storage_v2_archive import ArchiveReader
from server.sli.storage.storage_v2_models import canonical_json_bytes, json_safe
from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / "config" / "clickhouse" / "002_permanent_fact_history.sql"
DATABASE = "sli_history"
CONTAINER = "sli-history"
LOCK_NAME = "sli_permanent_fact_history_copy"
MAX_BATCH_EVENTS = 1_000
READ_PORT_ENV = "ADLOG_HISTORY_CLICKHOUSE_PORT"
READ_MODE_ENV = "ADLOG_HISTORY_READ_MODE"
USER_ENV = "ADLOG_HISTORY_CLICKHOUSE_USER"
PASSWORD_ENV = "ADLOG_HISTORY_CLICKHOUSE_PASSWORD"


def _history_auth() -> tuple[str, str]:
    user = os.environ.get(USER_ENV, "").strip()
    password = secret_value(PASSWORD_ENV)
    if not user or not password:
        raise RuntimeError("history_clickhouse_credentials_missing")
    return user, password


def _http_query(port: int, query: str, *, timeout: int = 300,
                params: dict[str, str] | None = None) -> bytes:
    from server.sli.core.database import QueryTimeoutError
    from server.sli.reporting.read_timeout import remaining_read_ms

    remaining = remaining_read_ms()
    deadline_args = {"deadline": monotonic() + remaining / 1000} if remaining is not None else {}
    with _history_transport():
        try:
            return _transport_query(port, query, timeout=timeout, params=params,
                                    auth=_history_auth(), **deadline_args)
        except TimeoutError:
            if remaining is not None:
                raise QueryTimeoutError("History read budget exhausted", timeout_ms=remaining) from None
            raise


@contextmanager
def _history_transport():
    """Only availability failures are retryable; auth/SQL/integrity still fail."""
    try:
        yield
    except (OSError, http.client.HTTPException):
        raise RuntimeError("history_clickhouse_unavailable") from None
    except RuntimeError as error:
        if str(error) in {f"ClickHouse HTTP {status}:request_failed"
                          for status in (429, 502, 503, 504)}:
            raise RuntimeError("history_clickhouse_unavailable") from None
        raise


def _http_insert_json_rows(port: int, table: str,
                           rows: list[dict[str, Any]], *, timeout: int = 300
                           ) -> tuple[int, bool]:
    with _history_transport():
        return _transport_insert_json_rows(port, table, rows, timeout=timeout,
                                           auth=_history_auth())


def _stream_rows(port: int, sql: str):
    params = {
        "readonly": "1",
        "max_execution_time": "21600",
        "max_threads": "1",
        "max_bytes_before_external_sort": "50000000",
        "max_memory_usage": "4000000000",
    }
    with _history_transport():
        yield from _transport_stream_json_rows(
            port, sql + " FORMAT JSONEachRow", timeout=21630,
            params=params, auth=_history_auth(),
        )


def _fact_payload(values):
    # An additive NULL file column must not change already-published row hashes.
    return json_safe({key: value for key, value in values.items()
                      if key not in {"event_id", "migrated_at"}
                      and (key != "file_audit_facts_json" or value is not None)})


def _ch_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _json_ch_time(value: Any) -> str:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return _ch_time(parsed)


def _ch_time_micros(value: str) -> int:
    parsed = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000
            + delta.microseconds)


def _rows(port: int, sql: str, *, query_params: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    from server.sli.reporting.read_timeout import remaining_read_ms

    remaining = remaining_read_ms()
    timeout = min(65, remaining / 1000) if remaining is not None else 65
    params = {"readonly": "1", "max_execution_time": str(min(60, timeout))}
    params.update({f"param_{key}": value for key, value in (query_params or {}).items()})
    data = _http_query(
        port, sql.rstrip().rstrip(";") + " FORMAT JSONEachRow",
        params=params, timeout=timeout,
    )
    return [json.loads(line) for line in data.split(b"\n") if line]


def _sequence_sha(rows: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(str(row["row_sha256"]).encode("ascii") + b"\n")
    return digest.hexdigest().upper()


def _payload_sha(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest().upper()


def _source_batch(
    after_id: int, limit: int, *, exact_ids: list[int] | None = None,
    history_port: int | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if exact_ids is not None and (not exact_ids or len(exact_ids) > MAX_BATCH_EVENTS):
        raise ValueError("exact event ID batch out of range")
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read read only")
        selection = (
            "e.id=any(%s::bigint[])" if exact_ids is not None
            else "e.id > %s"
        )
        cur.execute(
            f"""
            select e.*, provider.value as provider_name,
                   channel.value as channel, computer.value as computer,
                   keywords.value as keywords,
                   subject_domain.value as subject_domain_name,
                   target_domain.value as target_domain_name
            from events_v2_core e
            left join storage_v2_provider provider on provider.id=e.provider_id
            join storage_v2_channel channel on channel.id=e.channel_id
            left join storage_v2_computer computer on computer.id=e.computer_id
            left join storage_v2_keywords keywords on keywords.id=e.keywords_id
            left join storage_v2_domain_name subject_domain on subject_domain.id=e.subject_domain_id
            left join storage_v2_domain_name target_domain on target_domain.id=e.target_domain_id
            where {selection} order by e.id limit %s
            """,
            (sorted({int(value) for value in exact_ids}), int(limit))
            if exact_ids is not None else (int(after_id), int(limit)),
        )
        cores = [dict(row) for row in cur.fetchall()]
        if exact_ids is not None and {int(row["id"]) for row in cores} != set(exact_ids):
            raise RuntimeError("exact_source_event_missing")
        if not cores:
            return [], []
        ids = [int(row["id"]) for row in cores]
        cur.execute("select * from event_facts_v2 where event_id=any(%s::bigint[])", (ids,))
        facts = {int(row["event_id"]): dict(row) for row in cur.fetchall()}
        min_id = ids[0]
        max_id = ids[-1]
        cur.execute(
            """
            select expanded.event_id, block.entity_id, expanded.role_id, role.value as link_role
            from event_entity_link_blocks_v2 block
            cross join lateral unnest(block.event_ids, block.role_ids) expanded(event_id, role_id)
            join storage_v2_role role on role.id=expanded.role_id
            where block.first_event_id <= %s and block.last_event_id >= %s
              and expanded.event_id = any(%s::bigint[])
            order by expanded.event_id, block.entity_id, expanded.role_id
            """,
            (max_id, min_id, ids),
        )
        source_links = [dict(row) for row in cur.fetchall()]

    events: list[dict[str, Any]] = []
    time_by_id: dict[int, str] = {}
    no_archive_ids: set[int] = set()
    for core in cores:
        event_id = int(core["id"])
        entry = lookup_event_catalog(
            int(core["event_id"]), core.get("channel"), core.get("provider_name"),
        )
        promotion = (((entry or {}).get("lifecycle") or {}).get("promotion") or {})
        if promotion.get("archive_requirement") == "no_archive":
            no_archive_ids.add(event_id)
        time_value = _ch_time(core["time_created_utc"])
        time_by_id[event_id] = time_value
        compact = json_safe({key: value for key, value in core.items() if key != "migrated_at"})
        fact = _fact_payload(facts.get(event_id, {}))
        payload = {"core": compact, "facts": fact}
        events.append({
            "event_db_id": event_id,
            "time_created_utc": time_value,
            "event_key": int(core["event_id"]),
            "server_id": int(core["server_id"]),
            "noise_class": str(core.get("noise_class") or ""),
            "core_json": canonical_json_bytes(compact).decode("utf-8"),
            "facts_json": canonical_json_bytes(fact).decode("utf-8"),
            "row_sha256": _payload_sha(payload),
        })

    if history_port is not None:
        # After archive retirement, retained details are the canonical owner.
        # Their hashes/publication are checked, while core, facts and the exact
        # link identity set are still independently read from PostgreSQL.
        details = read_published_links_many(history_port, ids)
    else:
        archive_ids = [event_id for event_id in ids if event_id not in no_archive_ids]
        archive = ArchiveReader(
            PostgresArchiveManifestStore(_connect),
        )
        try:
            details = archive.read_link_details_many(archive_ids, max_blocks=64) if archive_ids else {}
        except FileNotFoundError:
            raise RuntimeError("history_source_archive_unavailable") from None
        except PermissionError:
            raise RuntimeError("history_source_archive_permission_denied") from None
    detail_by_key: dict[tuple[int, int, str], dict[str, Any]] = {}
    for event_id, rows in details.items():
        for row in rows:
            key = (int(event_id), int(row["entity_id"]), str(row["link_role"]))
            if key in detail_by_key:
                existing = detail_by_key[key]
                if {k: v for k, v in existing.items() if k != "created_at"} == {
                    k: v for k, v in dict(row).items() if k != "created_at"
                }:
                    continue
                raise RuntimeError("history_source_link_detail_duplicate")
            detail_by_key[key] = dict(row)
    links: list[dict[str, Any]] = []
    source_keys: set[tuple[int, int, str]] = set()
    for link in source_links:
        key = (int(link["event_id"]), int(link["entity_id"]), str(link["link_role"]))
        if key in source_keys:
            raise RuntimeError("history_source_link_duplicate")
        source_keys.add(key)
        detail = detail_by_key.get(key)
        if detail is None and key[0] in no_archive_ids:
            detail = {
                "event_id": key[0], "entity_id": key[1], "link_role": key[2],
                "role_id": int(link["role_id"]), "confidence": None,
                "extracted_from": None, "extracted_from_id": None,
                "created_at": None, "evidence_json": None,
                "attributes_json": None, "detail_source": "compact_v2",
            }
        if detail is None:
            raise RuntimeError("history_source_link_details_missing")
        if int(detail["role_id"]) != int(link["role_id"]):
            raise RuntimeError("history_source_link_role_mismatch")
        compact = json_safe(detail)
        links.append({
            "event_db_id": key[0],
            "entity_id": key[1],
            "time_created_utc": time_by_id[key[0]],
            "link_role": key[2],
            "details_json": canonical_json_bytes(compact).decode("utf-8"),
            "row_sha256": _payload_sha(compact),
        })
    if not set(detail_by_key).issubset(source_keys):
        raise RuntimeError("link_detail_set_mismatch")
    links.sort(key=lambda row: (row["event_db_id"], row["entity_id"], row["link_role"]))
    return events, links


def _identity(events: list[dict[str, Any]], links: list[dict[str, Any]]) -> dict[str, Any]:
    value = {
        "first_event_db_id": events[0]["event_db_id"],
        "last_event_db_id": events[-1]["event_db_id"],
        "event_count": len(events),
        "link_count": len(links),
        "event_sequence_sha256": _sequence_sha(events),
        "link_sequence_sha256": _sequence_sha(links),
    }
    value["batch_sha256"] = _payload_sha(value)
    return value


def _readback(
    port: int, events: list[dict[str, Any]], links: list[dict[str, Any]],
    *, check_batch: bool = True,
) -> tuple[set[int], set[tuple[int, int, str]], dict[int, str]]:
    ids = ",".join(str(row["event_db_id"]) for row in events)
    actual_events = _rows(port, f"SELECT event_db_id,time_created_utc,event_key,server_id,noise_class,core_json,facts_json,row_sha256,batch_sha256 FROM {DATABASE}.events WHERE event_db_id IN ({ids})")
    actual_links = _rows(port, f"SELECT event_db_id,entity_id,time_created_utc,link_role,details_json,row_sha256,batch_sha256 FROM {DATABASE}.links WHERE event_db_id IN ({ids})")
    expected_events = {
        int(row["event_db_id"]): (
            row["row_sha256"], row.get("batch_sha256"),
            row["core_json"], row["facts_json"],
            row["time_created_utc"], int(row["event_key"]),
            int(row["server_id"]), row["noise_class"],
        )
        for row in events
    }
    expected_links = {
        (int(row["event_db_id"]), int(row["entity_id"]), row["link_role"]): (
            row["row_sha256"], row.get("batch_sha256"), row["details_json"],
            row["time_created_utc"],
        )
        for row in links
    }
    found_events: set[int] = set()
    found_links: set[tuple[int, int, str]] = set()
    event_batches: dict[int, str] = {}
    for row in actual_events:
        key = int(row["event_db_id"])
        expected = expected_events.get(key)
        if (
            key in found_events or expected is None or expected[0] != row["row_sha256"]
            or expected[2] != row["core_json"] or expected[3] != row["facts_json"]
            or expected[4] != row["time_created_utc"]
            or expected[5] != int(row["event_key"])
            or expected[6] != int(row["server_id"])
            or expected[7] != row["noise_class"]
            or (check_batch and expected[1] != row["batch_sha256"])
        ):
            raise RuntimeError("clickhouse_event_duplicate_or_mismatch")
        found_events.add(key)
        event_batches[key] = str(row["batch_sha256"])
    for row in actual_links:
        key = (int(row["event_db_id"]), int(row["entity_id"]), str(row["link_role"]))
        expected = expected_links.get(key)
        if (
            key in found_links or expected is None or expected[0] != row["row_sha256"]
            or expected[2] != row["details_json"]
            or expected[3] != row["time_created_utc"]
            or event_batches.get(key[0]) != row["batch_sha256"]
            or (check_batch and expected[1] != row["batch_sha256"])
        ):
            raise RuntimeError("clickhouse_link_duplicate_or_mismatch")
        found_links.add(key)
    return found_events, found_links, event_batches


def _published(port: int, first_id: int) -> list[dict[str, Any]]:
    return _rows(port, f"SELECT * FROM {DATABASE}.published_batches WHERE first_event_db_id={int(first_id)}")


def configured_read_port() -> int | None:
    value = os.environ.get(READ_PORT_ENV, "").strip()
    if not value:
        return None
    try:
        port = int(value)
    except ValueError:
        raise ValueError("history_clickhouse_port_invalid") from None
    if not 1 <= port <= 65535:
        raise ValueError("history_clickhouse_port_invalid")
    return port


def primary_read_enabled() -> bool:
    mode = os.environ.get(READ_MODE_ENV, "disabled").strip().lower()
    if mode not in {"disabled", "primary"}:
        raise ValueError("history_read_mode_invalid")
    if mode == "primary" and configured_read_port() is None:
        raise RuntimeError("history_clickhouse_port_missing")
    if mode == "primary":
        _history_auth()
    return mode == "primary"


def read_published_event(port: int, event_db_id: int) -> dict[str, Any]:
    """Return derived facts for one event, never unpublished or raw payload."""
    event_id = int(event_db_id)
    if event_id <= 0:
        raise ValueError("event_db_id must be positive")
    batches = _rows(
        port, f"SELECT batch_sha256,first_event_db_id,last_event_db_id "
        f"FROM {DATABASE}.published_batches "
        f"WHERE first_event_db_id<={event_id} AND last_event_db_id>={event_id}",
    )
    if len(batches) != 1:
        raise KeyError(f"history batch unavailable for event {event_id}")
    rows = _rows(
        port, f"SELECT * FROM {DATABASE}.events WHERE event_db_id={event_id}",
    )
    if len(rows) != 1:
        raise RuntimeError(f"published_history_event_missing_or_duplicate:{event_id}")
    row = rows[0]
    if row["batch_sha256"] != batches[0]["batch_sha256"]:
        raise RuntimeError(f"published_history_event_batch_mismatch:{event_id}")
    core = json.loads(str(row["core_json"]))
    facts = json.loads(str(row["facts_json"]))
    if _payload_sha({"core": core, "facts": facts}) != row["row_sha256"]:
        raise RuntimeError(f"published_history_event_hash_mismatch:{event_id}")
    if (
        int(core["id"]) != event_id
        or int(core["event_id"]) != int(row["event_key"])
        or int(core["server_id"]) != int(row["server_id"])
        or _json_ch_time(core["time_created_utc"]) != row["time_created_utc"]
        or str(core.get("noise_class") or "") != row["noise_class"]
    ):
        raise RuntimeError(f"published_history_event_identity_mismatch:{event_id}")
    return {
        **core,
        **facts,
        "id": event_id,
        "event_data_json": None,
        "message_text": None,
        "record_xml": None,
        "source_payload_state": "expired",
        "retained_facts": facts,
    }


def read_published_links(port: int, event_db_id: int) -> list[dict[str, Any]]:
    """Return all retained relation details for one published event."""
    event = read_published_event(port, event_db_id)
    event_batch = _rows(
        port, f"SELECT batch_sha256 FROM {DATABASE}.events WHERE event_db_id={int(event_db_id)}",
    )
    rows = _rows(
        port, f"SELECT entity_id,time_created_utc,link_role,details_json,row_sha256 "
        f",batch_sha256 FROM {DATABASE}.links WHERE event_db_id={int(event_db_id)}",
    )
    found: set[tuple[int, str]] = set()
    details: list[dict[str, Any]] = []
    for row in rows:
        key = (int(row["entity_id"]), str(row["link_role"]))
        if key in found:
            raise RuntimeError("published_history_link_duplicate")
        found.add(key)
        if len(event_batch) != 1 or row["batch_sha256"] != event_batch[0]["batch_sha256"]:
            raise RuntimeError("published_history_link_batch_mismatch")
        detail = json.loads(str(row["details_json"]))
        if (
            _payload_sha(detail) != row["row_sha256"]
            or int(detail["event_id"]) != int(event_db_id)
            or int(detail["entity_id"]) != key[0]
            or str(detail["link_role"]) != key[1]
            or _json_ch_time(event["time_created_utc"]) != row["time_created_utc"]
        ):
            raise RuntimeError("published_history_link_mismatch")
        details.append(detail)
    return details


def read_published_links_many(
    port: int, event_db_ids: list[int],
) -> dict[int, list[dict[str, Any]]]:
    """Read a bounded link batch with payload, identity and publication checks."""
    if not event_db_ids:
        return {}
    events = read_published_events_many(port, event_db_ids)
    ids = ",".join(str(int(value)) for value in sorted(set(event_db_ids)))
    rows = _rows(port, f"SELECT * FROM {DATABASE}.links WHERE event_db_id IN ({ids})")
    result: dict[int, list[dict[str, Any]]] = {value: [] for value in events}
    seen: set[tuple[int, int, str]] = set()
    for row in rows:
        event_id = int(row["event_db_id"])
        key = (event_id, int(row["entity_id"]), str(row["link_role"]))
        if key in seen:
            raise RuntimeError("published_history_link_duplicate")
        seen.add(key)
        event = events.get(event_id)
        detail = json.loads(row["details_json"])
        if (
            event is None
            or row["batch_sha256"] != event["_history_batch_sha256"]
            or row["time_created_utc"] != _json_ch_time(event["time_created_utc"])
            or _payload_sha(detail) != row["row_sha256"]
            or int(detail["event_id"]) != event_id
            or int(detail["entity_id"]) != key[1]
            or str(detail["link_role"]) != key[2]
        ):
            raise RuntimeError("published_history_link_mismatch")
        result[event_id].append(detail)
    return result


def read_published_events_many(port: int, event_db_ids: list[int]) -> dict[int, dict[str, Any]]:
    ids = sorted({int(value) for value in event_db_ids})
    if not ids:
        return {}
    if len(ids) > MAX_BATCH_EVENTS or ids[0] <= 0:
        raise ValueError("historical event batch out of range")
    selected = ",".join(str(value) for value in ids)
    rows = _rows(
        port, f"SELECT event_db_id,time_created_utc,event_key,server_id,noise_class,core_json,facts_json,row_sha256,batch_sha256 FROM {DATABASE}.events "
        f"WHERE event_db_id IN ({selected}) AND batch_sha256 IN "
        f"(SELECT batch_sha256 FROM {DATABASE}.published_batches)",
    )
    batches = _rows(
        port, f"SELECT batch_sha256,first_event_db_id,last_event_db_id "
        f"FROM {DATABASE}.published_batches "
        f"WHERE first_event_db_id<={ids[-1]} AND last_event_db_id>={ids[0]}",
    )
    # Index this read's catalog only. Keep every original row (including
    # duplicates): exactly one matching publication range must still witness
    # each fact. Lists hold references, not payload copies or a cross-read cache.
    batches_by_hash: dict[str, list[dict[str, Any]]] = {}
    for batch in batches:
        batches_by_hash.setdefault(batch["batch_sha256"], []).append(batch)
    result: dict[int, dict[str, Any]] = {}
    for row in rows:
        event_id = int(row["event_db_id"])
        if event_id in result:
            raise RuntimeError("published_history_event_duplicate")
        core = json.loads(row["core_json"])
        facts = json.loads(row["facts_json"])
        if (
            int(core["id"]) != event_id
            or _json_ch_time(core["time_created_utc"]) != row["time_created_utc"]
            or int(core["event_id"]) != int(row["event_key"])
            or int(core["server_id"]) != int(row["server_id"])
            or str(core.get("noise_class") or "") != row["noise_class"]
            or _payload_sha({"core": core, "facts": facts}) != row["row_sha256"]
            or sum(
                int(batch["first_event_db_id"]) <= event_id <= int(batch["last_event_db_id"])
                for batch in batches_by_hash.get(row["batch_sha256"], ())
            ) != 1
        ):
            raise RuntimeError("published_history_event_mismatch")
        result[event_id] = {
            **core, **facts, "id": event_id, "retained_facts": facts,
            "_history_batch_sha256": row["batch_sha256"],
            "record_xml": None, "message_text": None,
            "event_data_json": None, "source_payload_state": "expired",
        }
    if set(result) != set(ids):
        raise RuntimeError("published_history_event_batch_incomplete")
    return result


def ensure_schema(port: int) -> None:
    for statement in SCHEMA.read_text(encoding="utf-8").split(";"):
        if statement.strip():
            _http_query(port, statement.strip())


def copy_one_batch(port: int, *, after_id: int, limit: int = MAX_BATCH_EVENTS, apply: bool = False) -> dict[str, Any]:
    if not 1 <= int(limit) <= MAX_BATCH_EVENTS:
        raise ValueError("batch limit out of range")
    events, links = _source_batch(after_id, limit)
    if not events:
        return {"status": "complete", "event_count": 0, "link_count": 0, "after_id": after_id}
    batch = _identity(events, links)
    for row in (*events, *links):
        row["batch_sha256"] = batch["batch_sha256"]
    if not apply:
        return {"status": "dry_run", **batch, "after_id": after_id}
    found_events, found_links, _ = _readback(port, events, links)
    missing_events = [row for row in events if row["event_db_id"] not in found_events]
    missing_links = [row for row in links if (row["event_db_id"], row["entity_id"], row["link_role"]) not in found_links]
    _http_insert_json_rows(port, f"{DATABASE}.events", missing_events)
    _http_insert_json_rows(port, f"{DATABASE}.links", missing_links)
    confirmed_events, confirmed_links, _ = _readback(port, events, links)
    if len(confirmed_events) != len(events) or len(confirmed_links) != len(links):
        raise RuntimeError("clickhouse_fact_history_readback_incomplete")
    published = _published(port, int(batch["first_event_db_id"]))
    if len(published) > 1:
        raise RuntimeError("clickhouse_batch_manifest_duplicate")
    if published:
        if any(published[0].get(key) != value for key, value in batch.items()):
            raise RuntimeError("clickhouse_batch_manifest_mismatch")
        return {"status": "already_published", **batch, "after_id": after_id}
    _http_insert_json_rows(port, f"{DATABASE}.published_batches", [{
        **batch, "published_at_utc": _ch_time(datetime.now(timezone.utc)),
    }])
    published = _published(port, int(batch["first_event_db_id"]))
    if len(published) != 1 or any(published[0].get(key) != value for key, value in batch.items()):
        raise RuntimeError("clickhouse_batch_publication_incomplete")
    return {"status": "published", **batch, "after_id": after_id}


def next_after_id(port: int) -> int:
    rows = _rows(port, f"SELECT max(last_event_db_id) AS last_id FROM {DATABASE}.published_batches")
    return int((rows[0] if rows else {}).get("last_id") or 0)


def verify_published_batch(port: int, batch: Mapping[str, Any]) -> dict[str, int]:
    """Check an entire published batch, including stored payload and links."""
    digest = str(batch["batch_sha256"])
    if len(digest) != 64 or any(character not in "0123456789ABCDEF" for character in digest):
        raise RuntimeError("history_batch_digest_invalid")
    events = _rows(
        port, f"SELECT * FROM {DATABASE}.events WHERE batch_sha256='{digest}' "
        "ORDER BY event_db_id",
    )
    links = _rows(
        port, f"SELECT * FROM {DATABASE}.links WHERE batch_sha256='{digest}' "
        "ORDER BY event_db_id,entity_id,link_role",
    )
    if not events or len(events) != int(batch["event_count"]) or len(links) != int(batch["link_count"]):
        raise RuntimeError("history_batch_row_count_mismatch")
    event_ids: set[int] = set()
    event_times: dict[int, str] = {}
    link_keys: set[tuple[int, int, str]] = set()
    for row in events:
        event_id = int(row["event_db_id"])
        core = json.loads(row["core_json"])
        facts = json.loads(row["facts_json"])
        if (
            event_id in event_ids or int(core["id"]) != event_id
            or int(core["event_id"]) != int(row["event_key"])
            or int(core["server_id"]) != int(row["server_id"])
            or _json_ch_time(core["time_created_utc"]) != row["time_created_utc"]
            or str(core.get("noise_class") or "") != row["noise_class"]
            or _payload_sha({"core": core, "facts": facts}) != row["row_sha256"]
        ):
            raise RuntimeError("history_batch_event_mismatch")
        event_ids.add(event_id)
        event_times[event_id] = row["time_created_utc"]
    for row in links:
        key = (int(row["event_db_id"]), int(row["entity_id"]), str(row["link_role"]))
        detail = json.loads(row["details_json"])
        if (
            key in link_keys or key[0] not in event_ids
            or int(detail["event_id"]) != key[0]
            or int(detail["entity_id"]) != key[1]
            or str(detail["link_role"]) != key[2]
            or event_times[key[0]] != row["time_created_utc"]
            or _payload_sha(detail) != row["row_sha256"]
        ):
            raise RuntimeError("history_batch_link_mismatch")
        link_keys.add(key)
    identity = _identity(events, links)
    if any(identity[key] != batch[key] for key in identity):
        raise RuntimeError("history_batch_manifest_mismatch")
    return {"events": len(events), "links": len(links)}


def verify_all_published_batches(port: int) -> dict[str, int]:
    """Verify every physical row in one ordered pass per ClickHouse table."""
    batches = _rows(port, f"SELECT * FROM {DATABASE}.published_batches ORDER BY first_event_db_id")
    totals = {"batches": len(batches), "events": 0, "links": 0}
    previous_last = 0
    seen_digests: set[str] = set()
    last_ids: list[int] = []
    states: list[dict[str, Any]] = []
    for batch in batches:
        first_id = int(batch["first_event_db_id"])
        last_id = int(batch["last_event_db_id"])
        digest = str(batch["batch_sha256"])
        if first_id <= previous_last or last_id < first_id or digest in seen_digests:
            raise RuntimeError("history_batch_manifest_order_or_duplicate")
        if len(digest) != 64 or any(char not in "0123456789ABCDEF" for char in digest):
            raise RuntimeError("history_batch_digest_invalid")
        last_ids.append(last_id)
        states.append({
            "manifest": batch, "event_ids": array("Q"),
            "event_times": array("q"),
            "event_count": 0, "link_count": 0,
            "first_seen": 0, "last_seen": 0,
            "event_sha": hashlib.sha256(), "link_sha": hashlib.sha256(),
        })
        previous_last = last_id
        seen_digests.add(digest)

    def index_for(event_id: int) -> int:
        index = bisect_left(last_ids, event_id)
        if index >= len(states) or event_id < int(batches[index]["first_event_db_id"]):
            raise RuntimeError("history_physical_row_without_manifest")
        return index

    previous_event_id = 0
    for row in _stream_rows(port, f"SELECT * FROM {DATABASE}.events ORDER BY event_db_id"):
        event_id = int(row["event_db_id"])
        if event_id <= previous_event_id:
            raise RuntimeError("history_physical_event_duplicate_or_order")
        previous_event_id = event_id
        state = states[index_for(event_id)]
        core = json.loads(row["core_json"])
        facts = json.loads(row["facts_json"])
        if (
            row["batch_sha256"] != state["manifest"]["batch_sha256"]
            or int(core["id"]) != event_id
            or int(core["event_id"]) != int(row["event_key"])
            or int(core["server_id"]) != int(row["server_id"])
            or _json_ch_time(core["time_created_utc"]) != row["time_created_utc"]
            or str(core.get("noise_class") or "") != row["noise_class"]
            or _payload_sha({"core": core, "facts": facts}) != row["row_sha256"]
        ):
            raise RuntimeError("history_physical_event_mismatch")
        if not state["event_count"]:
            state["first_seen"] = event_id
        state["last_seen"] = event_id
        state["event_count"] += 1
        state["event_ids"].append(event_id)
        state["event_times"].append(_ch_time_micros(row["time_created_utc"]))
        state["event_sha"].update(row["row_sha256"].encode("ascii") + b"\n")
        totals["events"] += 1

    previous_link: tuple[int, int, str] = (0, 0, "")
    active_index = -1
    active_times: dict[int, int] = {}
    for row in _stream_rows(
        port,
        f"SELECT * FROM {DATABASE}.links ORDER BY event_db_id,entity_id,link_role",
    ):
        key = (int(row["event_db_id"]), int(row["entity_id"]), str(row["link_role"]))
        if key <= previous_link:
            raise RuntimeError("history_physical_link_duplicate_or_order")
        previous_link = key
        index = index_for(key[0])
        state = states[index]
        if index != active_index:
            active_index = index
            active_times = dict(zip(state["event_ids"], state["event_times"]))
        detail = json.loads(row["details_json"])
        if (
            key[0] not in active_times
            or row["batch_sha256"] != state["manifest"]["batch_sha256"]
            or int(detail["event_id"]) != key[0]
            or int(detail["entity_id"]) != key[1]
            or str(detail["link_role"]) != key[2]
            or _ch_time_micros(row["time_created_utc"]) != active_times[key[0]]
            or _payload_sha(detail) != row["row_sha256"]
        ):
            raise RuntimeError("history_physical_link_mismatch")
        state["link_count"] += 1
        state["link_sha"].update(row["row_sha256"].encode("ascii") + b"\n")
        totals["links"] += 1

    for state in states:
        manifest = state["manifest"]
        identity = {
            "first_event_db_id": state["first_seen"],
            "last_event_db_id": state["last_seen"],
            "event_count": state["event_count"],
            "link_count": state["link_count"],
            "event_sequence_sha256": state["event_sha"].hexdigest().upper(),
            "link_sequence_sha256": state["link_sha"].hexdigest().upper(),
        }
        if any(identity[key] != manifest[key] for key in identity):
            raise RuntimeError("history_physical_manifest_mismatch")
        if _payload_sha(identity) != manifest["batch_sha256"]:
            raise RuntimeError("history_physical_batch_digest_mismatch")
    totals["last_event_db_id"] = previous_last
    return totals


def verify_source_parity(
    port: int, *, max_batches: int | None = None,
    after_verified_event_db_id: int = 0,
) -> dict[str, int | str]:
    """Compare the PostgreSQL tail after a previously verified backup."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("select coalesce(max(id),0) as max_id from events_v2_core")
        source_max_id = int(cur.fetchone()["max_id"])
    batches = _rows(port, f"SELECT * FROM {DATABASE}.published_batches ORDER BY first_event_db_id")
    if after_verified_event_db_id:
        if not any(
            int(batch["last_event_db_id"]) == after_verified_event_db_id
            for batch in batches
        ):
            raise RuntimeError("source_parity_checkpoint_not_published")
        batches = [
            batch for batch in batches
            if int(batch["first_event_db_id"]) > after_verified_event_db_id
        ]
    if max_batches is not None:
        batches = batches[:max_batches]
    totals: dict[str, int | str] = {
        "batches": 0, "events": 0, "links": 0,
        "last_event_db_id": after_verified_event_db_id,
    }
    after_id = after_verified_event_db_id
    for batch in batches:
        count = int(batch["event_count"])
        if not 1 <= count <= MAX_BATCH_EVENTS:
            raise RuntimeError("source_parity_batch_size_invalid")
        events, links = _source_batch(after_id, count)
        if len(events) != count:
            raise RuntimeError("source_parity_event_count_mismatch")
        identity = _identity(events, links)
        if any(identity[key] != batch[key] for key in identity):
            raise RuntimeError("source_parity_manifest_mismatch")
        for row in (*events, *links):
            row["batch_sha256"] = identity["batch_sha256"]
        found_events, found_links, _ = _readback(port, events, links)
        if len(found_events) != count or len(found_links) != len(links):
            raise RuntimeError("source_parity_clickhouse_incomplete")
        after_id = int(identity["last_event_db_id"])
        totals["batches"] = int(totals["batches"]) + 1
        totals["events"] = int(totals["events"]) + count
        totals["links"] = int(totals["links"]) + len(links)
        totals["last_event_db_id"] = after_id
    totals["source_max_event_db_id"] = source_max_id
    totals["status"] = (
        "partial" if max_batches is not None and len(batches) == max_batches
        else "complete" if after_id >= source_max_id else "source_tail_not_copied"
    )
    return totals


def verify_preserved_candidates(port: int, candidates: list[Mapping[str, Any]]) -> None:
    """Fail closed before hot deletion unless every fact and link is published."""
    if not candidates:
        return
    for start in range(0, len(candidates), MAX_BATCH_EVENTS):
        part = candidates[start:start + MAX_BATCH_EVENTS]
        ids = sorted({int(row["id"]) for row in part})
        events, links = _source_batch(0, len(ids), exact_ids=ids, history_port=port)
        if len(events) != len(ids) or {int(row["event_db_id"]) for row in events} != set(ids):
            raise RuntimeError("retention_candidate_source_count_mismatch")
        expected_hashes = {
            int(row["id"]): bytes(row["normalized_hash"]).hex().upper()
            for row in part
        }
        for event in events:
            core = json.loads(event["core_json"])
            if str(core["normalized_hash"]).upper() != expected_hashes[event["event_db_id"]]:
                raise RuntimeError("retention_candidate_source_hash_changed")
        found_events, found_links, event_batches = _readback(
            port, events, links, check_batch=False,
        )
        if len(found_events) != len(events) or len(found_links) != len(links):
            raise RuntimeError("retention_candidate_history_incomplete")
        batches = _rows(
            port, f"SELECT batch_sha256,first_event_db_id,last_event_db_id "
            f"FROM {DATABASE}.published_batches "
            f"WHERE first_event_db_id<={ids[-1]} AND last_event_db_id>={ids[0]}",
        )
        for event_id in ids:
            if sum(
                int(row["first_event_db_id"]) <= event_id <= int(row["last_event_db_id"])
                and row["batch_sha256"] == event_batches[event_id]
                for row in batches
            ) != 1:
                raise RuntimeError("retention_candidate_history_not_published")


def main() -> None:
    parser = argparse.ArgumentParser(description="Copy bounded V2 facts and links to permanent ClickHouse history")
    parser.add_argument("--apply", action="store_true", help="copy and verify; never deletes sources")
    parser.add_argument("--verify-all", action="store_true", help="verify every published ClickHouse batch without source deletion")
    parser.add_argument("--verify-source", action="store_true", help="compare published ClickHouse batches with PostgreSQL source")
    parser.add_argument("--batch-events", type=int, default=200)
    parser.add_argument("--batches", type=int, help="copy at most this many batches; with --verify-source, check this prefix")
    parser.add_argument("--until-complete", action="store_true", help="continue copying until the PostgreSQL tail is reached")
    parser.add_argument("--supervisor-env-file", type=Path)
    parser.add_argument("--port", type=int, help="existing loopback ClickHouse HTTP port")
    args = parser.parse_args()
    if args.batches is not None and not 1 <= args.batches <= 1000:
        raise SystemExit("batches must be between 1 and 1000")
    if args.until_complete and (not args.apply or args.batches is not None):
        raise SystemExit("--until-complete requires --apply and no --batches")
    if args.supervisor_env_file is not None:
        from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment

        load_supervisor_environment(path=args.supervisor_env_file)
    port = int(args.port) if args.port else _container_port(CONTAINER)
    if not 1 <= port <= 65535:
        raise SystemExit("ClickHouse port out of range")
    if args.verify_all:
        if args.apply or args.verify_source:
            raise SystemExit("verification and --apply are mutually exclusive")
        totals = verify_all_published_batches(port)
        print(json.dumps({"status": "verified", **totals}, sort_keys=True))
        return
    if args.verify_source:
        if args.apply:
            raise SystemExit("--verify-source and --apply are mutually exclusive")
        totals = verify_source_parity(port, max_batches=args.batches)
        print(json.dumps(totals, sort_keys=True))
        return
    if args.apply:
        ensure_schema(port)
    with session_advisory_lock(_connect, LOCK_NAME) as acquired:
        if not acquired:
            raise SystemExit("fact_history_copy_lock_held")
        after_id = next_after_id(port) if args.apply else 0
        remaining = None if args.until_complete else (args.batches or 1)
        batch_idx = 0
        while remaining is None or remaining > 0:
            result = copy_one_batch(port, after_id=after_id, limit=args.batch_events, apply=args.apply)
            print(json.dumps(result, sort_keys=True), flush=True)
            if result["status"] == "complete" or not args.apply:
                break
            after_id = int(result["last_event_db_id"])
            if remaining is not None:
                remaining -= 1
            batch_idx += 1
            if batch_idx % 50 == 0:
                import gc
                gc.collect()


if __name__ == "__main__":
    main()

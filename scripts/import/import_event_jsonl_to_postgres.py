from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import load_config
from server.sli.entities.entity_model import extract_event_entities
from server.sli.entities.entity_state_model import state_for_entity_link
from server.sli.entities.entity_state_projector import enqueue_projection_job
from server.sli.ops.logging_config import log_event
from server.sli.ops.performance import log_performance_stage, monotonic_ms
from server.sli.semantic.event_card_semantics import catalog_role_values
from server.sli.semantic.semantic_production_runtime import (
    semantic_publisher_for_runtime,
)
from server.sli.sources.collection_packet_import import event_rows_from_packet
from server.sli.sources.source_capture_continuity import (
    AUTHENTICATION_EVENT_KEYS,
    AUTHENTICATION_LIFECYCLE_KEYS,
    CaptureContinuityError,
    build_capture_declaration,
    capture_scope_from_collection_summary,
    persist_capture_declaration,
)
from server.sli.storage.event_source_identity import event_identity_hash
from server.sli.storage.storage_policy import resolve_descriptor_retention
from server.sli.storage.storage_v2_archive import ArchivePublisher
from server.sli.storage.storage_v2_backfill import SourceBatch, publish_direct_batch
from server.sli.storage.storage_v2_repository import (
    PostgresArchiveManifestStore,
    PostgresStorageV2Repository,
)
from server.sli.storage.storage_v2_runtime_authorization import (
    is_persisted_runtime_authorization,
    load_runtime_authorization,
)
from server.sli.storage.storage_v2_transition_controller import (
    is_controller_authorization,
)
from server.sli.storage.storage_v2_worker_connection import connect_storage_v2_worker
from server.sli.storage.xml_safety import UnsafeXmlError, parse_bounded_xml
from server.source_packs.registry import resolve_source_normalizer, resolve_source_pack

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dsn(cli_dsn: str | None = None) -> str:
    dsn = (cli_dsn or load_config().postgres_dsn or "").strip()
    if not dsn:
        raise RuntimeError("ADLOG_PG_DSN / postgres_dsn is not configured")
    return dsn


def connect(cli_dsn: str | None = None):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except Exception as exc:  # pragma: no cover - depends on runtime environment
        raise RuntimeError(f"psycopg is not available: {exc}") from exc
    return psycopg.connect(_dsn(cli_dsn), row_factory=dict_row)


def entity_state_projection_schema_available(cur) -> bool:
    """Return whether durable V2 state projection tables are installed."""
    cur.execute(
        """
        select to_regclass('public.entity_state_projection_jobs') is not null as jobs_ready,
               to_regclass('public.entity_state_current') is not null as current_ready,
               exists (
                   select 1 from schema_migrations
                   where version=19 and name='entity_state_projection'
               ) as migration_ready
        """
    )
    row = cur.fetchone()
    if isinstance(row, dict):
        return all(bool(row.get(key)) for key in ("jobs_ready", "current_ready", "migration_ready"))
    return bool(row and all(row[:3]))


def require_entity_state_projection_schema(cur) -> None:
    """Fail before importing any row when the V2 projection capability is absent."""
    if not entity_state_projection_schema_available(cur):
        raise RuntimeError(
            "storage_v2 outbox requires accepted migration 019 before import; "
            "no event rows were processed"
        )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_direct_file_digest(expected: str, actual: str) -> None:
    if str(expected).lower() != str(actual).lower():
        raise RuntimeError("raw JSONL changed during direct import after identity reservation")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Compatibility helper for bounded callers; the production importer streams."""
    return list(iter_jsonl(path))


def iter_jsonl(path: Path, *, digest: Any | None = None):
    """Yield JSON objects in one binary pass, optionally hashing exact source bytes."""
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open("rb") as f:
        first_line = True
        for raw_line in f:
            if digest is not None:
                digest.update(raw_line)
            line = raw_line.decode("utf-8-sig" if first_line else "utf-8").strip()
            first_line = False
            if line:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("jsonl_row_must_be_object")
                if "contract" in value:
                    yield from event_rows_from_packet(value)
                else:
                    yield value


def _iter_chunks(items, size: int):
    chunk: list[Any] = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def parse_event_data(xml_text: str | None) -> dict[str, Any]:
    if not xml_text:
        return {}
    try:
        root = parse_bounded_xml(xml_text)
    except (ET.ParseError, UnsafeXmlError, UnicodeEncodeError) as exc:
        return {
            "_sli_data_quality": {
                "event_data_parse_status": "failed",
                "error_type": type(exc).__name__,
            }
        }
    data: dict[str, Any] = {}
    for item in root.findall(".//e:EventData/e:Data", NS):
        name = item.attrib.get("Name")
        value = item.text
        if name:
            data[name] = value
        else:
            data.setdefault("Data", [])
            assert isinstance(data["Data"], list)
            data["Data"].append(value)
    for item in root.findall(".//e:UserData/*", NS):
        data[item.tag.split("}", 1)[-1]] = item.text
    execution = root.find(".//e:System/e:Execution", NS)
    process_id = execution.attrib.get("ProcessID") if execution is not None else None
    if process_id not in (None, ""):
        data["SystemExecutionProcessId"] = process_id
    return data


def pick(data: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = data.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def _fetch_id(cur, sql: str, params: tuple[Any, ...]) -> int:
    cur.execute(sql, params)
    row = cur.fetchone()
    if row is None:
        raise RuntimeError("expected row id was not returned")
    return int(row["id"])


def get_or_create_forest(cur, name: str) -> int:
    return _fetch_id(
        cur,
        """
        insert into forests(name) values (%s)
        on conflict(name) do update set name = excluded.name
        returning id
        """,
        (name,),
    )


def get_or_create_domain(cur, forest_id: int, fqdn: str, netbios: str | None) -> int:
    return _fetch_id(
        cur,
        """
        insert into domains(forest_id, fqdn, netbios_name) values (%s, %s, %s)
        on conflict(forest_id, fqdn) do update set netbios_name = coalesce(domains.netbios_name, excluded.netbios_name)
        returning id
        """,
        (forest_id, fqdn, netbios),
    )


def get_or_create_site(cur, domain_id: int, name: str) -> int:
    return _fetch_id(
        cur,
        """
        insert into sites(domain_id, name, site_type) values (%s, %s, 'unknown')
        on conflict(domain_id, name) do update set name = excluded.name
        returning id
        """,
        (domain_id, name),
    )


def get_or_create_server(cur, domain_id: int, site_id: int, hostname: str) -> int:
    return _fetch_id(
        cur,
        """
        insert into servers(domain_id, site_id, hostname, role, is_active)
        values (%s, %s, %s, 'domain_controller', true)
        on conflict(domain_id, hostname) do update set
            site_id = excluded.site_id,
            is_active = true,
            updated_at = now()
        returning id
        """,
        (domain_id, site_id, hostname),
    )


def get_log_source(cur, channel: str) -> int:
    return _fetch_id(
        cur,
        """
        insert into log_sources(name) values (%s)
        on conflict(name) do update set name = excluded.name
        returning id
        """,
        (channel,),
    )


def finalize_raw_log_file(
    cur, *, raw_log_file_id: int, server_id: int, log_source_id: int,
    sha256_value: str, rows_count: int, collection_run_id: int | None = None,
    repair_v1_references: bool = False,
) -> int:
    """Finalize provisional metadata and preserve content-hash idempotency."""
    cur.execute("select id,sha256 from raw_log_files where id=%s for update", (raw_log_file_id,))
    current = cur.fetchone()
    if not current:
        raise RuntimeError("raw_log_file_not_found_during_finalize")
    if not str(current.get("sha256") or "").startswith("pending:"):
        cur.execute(
            """update raw_log_files
               set event_count=%s,collection_run_id=coalesce(collection_run_id,%s)
               where id=%s""",
            (rows_count, collection_run_id, raw_log_file_id),
        )
        return raw_log_file_id
    cur.execute(
        """select id from raw_log_files
           where id<>%s and server_id=%s and log_source_id=%s and sha256=%s
           order by id limit 1 for update""",
        (raw_log_file_id, server_id, log_source_id, sha256_value),
    )
    duplicate = cur.fetchone()
    if duplicate:
        # Direct Storage V2 reservations are canonical by content hash; the V1
        # reference repair that used to follow here wrote the dropped ``events``.
        raise RuntimeError("direct raw log reservation must already be canonical")
    cur.execute(
        """update raw_log_files
           set sha256=%s,event_count=%s,collection_run_id=coalesce(collection_run_id,%s)
           where id=%s""",
        (sha256_value, rows_count, collection_run_id, raw_log_file_id),
    )
    return raw_log_file_id


def _collection_summary(path: Path) -> dict[str, Any] | None:
    """Return the adjacent collector sidecar only when it is a JSON object."""
    summary_path = path.parent / "collection-summary.json"
    try:
        value = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _source_capture_rows(
    cur, *, raw_log_file_id: int, storage_route: str,
) -> list[dict[str, Any]]:
    del storage_route  # Storage V2 is the only store (plan 6.5).
    cur.execute(
        """
        select core.id,core.event_record_id,core.event_id,core.normalized_hash,
               channel.value as channel,provider.value as provider_name,
               raw.sha256 as raw_log_sha256
        from events_v2_core core
        join storage_v2_channel channel on channel.id=core.channel_id
        left join storage_v2_provider provider on provider.id=core.provider_id
        join raw_log_files raw on raw.id=core.raw_log_file_id
        where core.raw_log_file_id=%s
        order by core.event_record_id,core.id
        """,
        (raw_log_file_id,),
    )
    return [dict(row) for row in cur.fetchall()]


def _persist_source_capture_continuity(
    cur,
    *,
    path: Path,
    collection_run_id: int,
    raw_log_file_id: int,
    raw_log_sha256: str,
    server_id: int,
    log_source_id: int,
    storage_route: str = "v1",
) -> bool:
    """Persist a declaration only when the collector itself proves completeness.

    Missing/legacy sidecars intentionally leave the raw import usable while
    denying any later no-archive promotion.  This importer is the existing
    collection-to-storage boundary; it does not invent a second worker.
    """
    summary = _collection_summary(path)
    if summary is None:
        return False
    rows = _source_capture_rows(
        cur,
        raw_log_file_id=raw_log_file_id,
        storage_route=storage_route,
    )
    descriptor_candidates: set[tuple[str, str, str]] = set()
    for row in rows:
        try:
            pack = resolve_source_pack(
                str(row.get("channel") or ""),
                str(row.get("provider_name") or ""),
                str(row.get("event_id") or ""),
            )
            if pack is None:
                continue
            resolution = resolve_descriptor_retention(
                pack.pack_id, str(row["channel"]), str(row["event_id"]),
            )
        except (KeyError, TypeError, ValueError):
            continue
        if resolution.rollup == "authentication_session":
            descriptor_candidates.add((pack.pack_id, str(row["channel"]), str(row["provider_name"])))
    if len(descriptor_candidates) == 1:
        descriptor_source, descriptor_stream, provider_name = next(iter(descriptor_candidates))
    elif not rows:
        matching_channels = [
            item for item in summary.get("channels") or ()
            if isinstance(item, dict)
            and (
                str(item.get("file") or "").replace("\\", "/").endswith("/" + path.name)
                or str(item.get("file") or "") == path.name
            )
        ]
        if len(matching_channels) != 1:
            return False
        continuity = matching_channels[0].get("continuity")
        if not isinstance(continuity, dict):
            return False
        try:
            selector = {int(value) for value in continuity.get("selector_event_ids") or ()}
        except (TypeError, ValueError):
            return False
        if (
            str(matching_channels[0].get("channel") or path.stem) != "Security"
            or not AUTHENTICATION_LIFECYCLE_KEYS.issubset(selector)
            or not selector.issubset(AUTHENTICATION_EVENT_KEYS)
        ):
            return False
        descriptor_source = "sli.windows.ad-dc"
        descriptor_stream = "Security"
        provider_name = "Microsoft-Windows-Security-Auditing"
    else:
        return False
    scope = capture_scope_from_collection_summary(
        summary,
        raw_file_name=path.name,
        base_scope={
            "collection_run_id": collection_run_id,
            "raw_log_file_id": raw_log_file_id,
            "raw_log_sha256": str(raw_log_sha256 or "").lower(),
            "server_id": server_id,
            "log_source_id": log_source_id,
            "descriptor_source": descriptor_source,
            "descriptor_stream": descriptor_stream,
            "provider_name": provider_name,
            "channel_value": descriptor_stream,
        },
        source_events=[
            {
                "id": int(row["id"]),
                "record_id": int(row["event_record_id"]),
                "event_key": int(row["event_id"]),
                "normalized_hash": (
                    row["normalized_hash"].hex()
                    if isinstance(row.get("normalized_hash"), bytes)
                    else str(row.get("normalized_hash") or "").lower()
                ),
            }
            for row in rows
        ],
    )
    if scope is None:
        return False
    try:
        persist_capture_declaration(cur, build_capture_declaration(scope))
    except CaptureContinuityError:
        # Raw evidence remains importable; only irreversible source
        # disposition is denied until a later complete collection can prove
        # this scope.  Do not manufacture a partial declaration.
        return False
    return True


DEFAULT_EVENT_BATCH_SIZE = 500
DEFAULT_ENTITY_BATCH_SIZE = 1000
DEFAULT_LINK_BATCH_SIZE = 2000
DEFAULT_STORAGE_V2_OUTBOX_BATCH_SIZE = 5000
MAX_EVENT_BATCH_SIZE = 1000
MAX_ENTITY_BATCH_SIZE = 2000
MAX_LINK_BATCH_SIZE = 4000
MAX_STORAGE_V2_OUTBOX_BATCH_SIZE = 50000
_DIRECT_RUNTIME_SEAL = object()


@dataclass(frozen=True)
class DirectImportRuntime:
    repository: Any
    publisher: Any
    connect_factory: Callable[[], Any]
    normalized_at: str
    compatibility_mirror: Callable[[Any, SourceBatch], None] | None
    _seal: object
    route: str = "v2"


def authorized_direct_import_runtime(
    *,
    authorization: object,
    repository: Any,
    publisher: Any,
    connect_factory: Callable[[], Any],
    normalized_at: str,
    compatibility_mirror: Callable[[Any, SourceBatch], None] | None = None,
) -> DirectImportRuntime:
    controller_authorized = is_controller_authorization(authorization)
    persisted_authorized = is_persisted_runtime_authorization(authorization)
    if not (controller_authorized or persisted_authorized):
        raise RuntimeError("controller-authorized Storage V2 cutover is required")
    route = str(getattr(authorization, "route", "v2"))
    if route != "v2" or compatibility_mirror is not None:
        # The V1 compatibility mirror wrote the relations migration 097 dropped.
        raise RuntimeError(f"unsupported authorized direct route: {route}")
    return DirectImportRuntime(
        repository=repository,
        publisher=publisher,
        connect_factory=connect_factory,
        normalized_at=str(normalized_at),
        compatibility_mirror=compatibility_mirror,
        _seal=_DIRECT_RUNTIME_SEAL,
        route=route,
    )


def is_authorized_direct_runtime(value: object) -> bool:
    return isinstance(value, DirectImportRuntime) and value._seal is _DIRECT_RUNTIME_SEAL

EVENT_COLUMNS = (
    "raw_log_file_id", "server_id", "domain_id", "site_id", "log_source_id",
    "event_record_id", "event_id", "version", "level", "task", "opcode", "keywords",
    "provider_name", "channel", "computer", "time_created_utc", "record_xml",
    "message_text", "event_data_json", "subject_user_sid", "subject_user_name",
    "subject_domain_name", "target_user_sid", "target_user_name", "target_domain_name",
    "ip_address", "workstation_name", "logon_id", "correlation_id",
    "normalized_hash",
)


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _env_batch(name: str, default: int, maximum: int) -> int:
    return _bounded_int(os.environ.get(name), default, 1, maximum)


def _chunks(items: list[Any], size: int):
    for offset in range(0, len(items), size):
        yield items[offset : offset + size]


def _time_key(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value).replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return str(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _event_key(channel: Any, event_record_id: Any, time_created: Any) -> tuple[str, int, str]:
    return (str(channel or ""), int(event_record_id or 0), _time_key(time_created))


def event_normalized_hash(row: dict[str, Any]) -> str:
    return event_identity_hash(row)


class ResolvedEventRow(dict):
    """Internal hash binding; source JSON cannot inject this attribute."""

    def __init__(self, row, retained_hash):
        super().__init__(row)
        self.retained_normalized_hash = (retained_hash if isinstance(retained_hash, str)
                                         else bytes(retained_hash).hex())


def _event_params(
    *,
    raw_log_file_id: int,
    server_id: int,
    domain_id: int,
    site_id: int,
    log_source_id: int,
    row: dict[str, Any],
    event_data: dict[str, Any],
) -> tuple[Any, ...]:
    normalized_hash = getattr(row, "retained_normalized_hash", None) or event_normalized_hash(row)
    catalog_roles = catalog_role_values({**row, "event_data": event_data})
    source_normalizer = resolve_source_normalizer(
        row.get("channel"),
        row.get("provider_name"),
        str(row.get("event_id") or ""),
    )
    return (
        raw_log_file_id,
        server_id,
        domain_id,
        site_id,
        log_source_id,
        row.get("record_id"),
        row.get("event_id"),
        row.get("version"),
        row.get("level"),
        row.get("task"),
        row.get("opcode"),
        row.get("keywords"),
        row.get("provider_name"),
        row.get("channel"),
        row.get("machine_name") or row.get("computer_name"),
        row.get("time_created"),
        row.get("xml"),
        row.get("message"),
        json.dumps(event_data, ensure_ascii=False),
        pick(event_data, "SubjectUserSid"),
        pick(event_data, "SubjectUserName") or catalog_roles.get("initiator"),
        pick(event_data, "SubjectDomainName"),
        pick(event_data, "TargetUserSid", "TargetSid"),
        pick(event_data, "TargetUserName", "NewTargetUserName", "TargetAccount"),
        pick(event_data, "TargetDomainName"),
        pick(event_data, "IpAddress", "ClientAddress", "SourceAddress"),
        pick(event_data, "WorkstationName", "Workstation"),
        pick(event_data, "LogonId", "TargetLogonId", "SubjectLogonId"),
        source_normalizer.correlation_id(
            channel=row.get("channel"),
            event_id=row.get("event_id"),
            event_data=event_data,
        ) if source_normalizer else None,
        normalized_hash,
    )


def resolve_direct_event_ids(
    *,
    repository: Any,
    server_id: int,
    channel_ids: dict[str, int],
    items: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[tuple[int, bool, dict[str, Any], dict[str, Any]]]:
    """Resolve immutable V2 source identities and allocate IDs only for new rows."""
    if not items:
        return []
    reservations: list[dict[str, Any]] = []
    for row, _event_data in items:
        channel = str(row.get("channel") or "")
        if channel not in channel_ids:
            raise RuntimeError(f"Storage V2 channel dictionary is missing {channel!r}")
        event_record_id = int(row.get("record_id") or 0)
        if event_record_id <= 0:
            raise RuntimeError("Storage V2 direct event requires a positive record id")
        reservations.append({
            "server_id": int(server_id),
            "channel_id": int(channel_ids[channel]),
            "event_record_id": event_record_id,
            "time_created_utc": row.get("time_created"),
            "normalized_hash": event_normalized_hash(row),
            "source_row": row,
        })
    rows = list(repository.reserve_event_identities(reservations) or [])
    if len(rows) != len(items):
        raise RuntimeError("Storage V2 source identity reservation returned an incomplete set")
    resolved: dict[int, tuple[int, bool, dict[str, Any]]] = {}
    for result in rows:
        ordinal = int(result["ordinal"])
        if ordinal in resolved or not 0 <= ordinal < len(items):
            raise RuntimeError("Storage V2 source identity reservation returned invalid ordinals")
        preferred = result.get("source_row", items[ordinal][0])
        if result.get("normalized_hash") is not None:
            preferred = ResolvedEventRow(preferred, result["normalized_hash"])
        resolved[ordinal] = (int(result["id"]), not bool(result.get("published")), preferred)
    if len(resolved) != len(items):
        raise RuntimeError("Storage V2 source identity reservation omitted an ordinal")

    return [
        (resolved[index][0], resolved[index][1], resolved[index][2],
         event_data if resolved[index][2].get("xml") == row.get("xml")
         else parse_event_data(resolved[index][2].get("xml")))
        for index, (row, event_data) in enumerate(items)
    ]


def _direct_publication_results(
    event_results: list[tuple[int, bool, dict[str, Any], dict[str, Any]]],
) -> list[tuple[int, bool, dict[str, Any], dict[str, Any]]]:
    """Exclude immutable events that were already published by an overlap batch."""
    return [result for result in event_results if result[1]]


def build_direct_event_source_row(
    *,
    event_db_id: int,
    raw_log_file_id: int,
    server_id: int,
    domain_id: int,
    site_id: int | None,
    log_source_id: int,
    normalized_at: str,
    row: dict[str, Any],
    event_data: dict[str, Any],
) -> dict[str, Any]:
    """Build the canonical archive/transform row without touching Storage V1."""
    values = dict(zip(
        EVENT_COLUMNS,
        _event_params(
            raw_log_file_id=raw_log_file_id,
            server_id=server_id,
            domain_id=domain_id,
            site_id=site_id,
            log_source_id=log_source_id,
            row=row,
            event_data=event_data,
        ),
    ))
    return {
        "id": int(event_db_id),
        **values,
        "provider_guid": row.get("provider_guid"),
        "time_created_local": row.get("time_created_local"),
        "normalized_at": str(normalized_at),
    }


@dataclass
class EntityState:
    entity_type: str
    natural_key: str
    display_name: str
    domain_id: int | None
    server_id: int | None
    first_seen: str | None
    last_seen: str | None
    attributes_json: str
    entity_id: int | None = None
    effective_entity_id: int | None = None
    dirty: bool = False

    def merge(self, *, display_name: str, domain_id: int | None, server_id: int | None, seen_at: str | None, attributes: dict[str, Any]) -> None:
        self.display_name = display_name
        self.domain_id = self.domain_id or domain_id
        self.server_id = self.server_id or server_id
        if seen_at:
            if not self.first_seen or _time_key(seen_at) < _time_key(self.first_seen):
                self.first_seen = seen_at
            if not self.last_seen or _time_key(seen_at) > _time_key(self.last_seen):
                self.last_seen = seen_at
        self.attributes_json = json.dumps(attributes, ensure_ascii=False, sort_keys=True)
        self.dirty = True


@dataclass
class ImportProfile:
    file: str
    rows: int = 0
    inserted: int = 0
    skipped: int = 0
    events_relinked: int = 0
    event_batches: int = 0
    entity_upsert_batches: int = 0
    entity_update_batches: int = 0
    link_batches: int = 0
    unique_entities: int = 0
    entity_cache_hits: int = 0
    links_queued: int = 0
    entity_states_queued: int = 0
    entity_states_deferred_v2: int = 0
    entity_state_projection_jobs_queued: int = 0
    storage_v2_outbox_batches: int = 0
    storage_v2_outbox_events: int = 0
    source_capture_continuity_persisted: bool = False
    stage_ms: dict[str, int] = field(default_factory=dict)

    def add_ms(self, stage: str, started_ms: int) -> None:
        self.stage_ms[stage] = self.stage_ms.get(stage, 0) + max(0, monotonic_ms() - started_ms)

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "rows": self.rows,
            "inserted": self.inserted,
            "skipped": self.skipped,
            "events_relinked": self.events_relinked,
            "event_batches": self.event_batches,
            "entity_upsert_batches": self.entity_upsert_batches,
            "entity_update_batches": self.entity_update_batches,
            "link_batches": self.link_batches,
            "unique_entities": self.unique_entities,
            "entity_cache_hits": self.entity_cache_hits,
            "links_queued": self.links_queued,
            "entity_states_queued": self.entity_states_queued,
            "entity_states_deferred_v2": self.entity_states_deferred_v2,
            "entity_state_projection_jobs_queued": self.entity_state_projection_jobs_queued,
            "storage_v2_outbox_batches": self.storage_v2_outbox_batches,
            "storage_v2_outbox_events": self.storage_v2_outbox_events,
            "source_capture_continuity_persisted": (
                self.source_capture_continuity_persisted
            ),
            "stage_ms": dict(self.stage_ms),
        }


def _entity_merge_resolver_available(cur) -> bool:
    cur.execute(
        "select to_regprocedure('resolve_entity_identity_v2(integer)') is not null as available"
    )
    return bool(dict(cur.fetchone() or {}).get("available"))


def _effective_entity_ids(cur, source_ids: list[int]) -> dict[int, int]:
    ordered = sorted({int(value) for value in source_ids})
    if not ordered:
        return {}
    cur.execute(
        """
        select source_id,resolve_entity_identity_v2(source_id) as effective_id
        from unnest(%s::integer[]) source_id
        order by source_id
        """,
        (ordered,),
    )
    result = {
        int(row["source_id"]): int(row["effective_id"])
        for row in (cur.fetchall() or [])
    }
    if set(result) != set(ordered):
        raise RuntimeError("entity identity merge resolver returned an incomplete set")
    return result


def assign_direct_entity_ids(
    cur,
    *,
    states: list[EntityState],
    repository: Any,
    resolve_identity_merges: bool,
) -> None:
    """Bind extracted entities to V2 identities without writing Storage V1."""
    if not states:
        return
    type_ids = {
        entity_type: int(repository.dictionary_id("entity_type", entity_type))
        for entity_type in sorted({state.entity_type for state in states})
    }
    reservation_input: list[dict[str, Any]] = []
    for state in states:
        reservation_input.append({
            "entity_type_id": type_ids[state.entity_type],
            "natural_key": state.natural_key,
        })
    reservations = list(repository.reserve_entity_identities(reservation_input) or [])
    if len(reservations) != len(states):
        raise RuntimeError("Storage V2 entity identity reservation returned an incomplete set")
    reserved_ids: dict[int, int] = {}
    for result in reservations:
        ordinal = int(result["ordinal"])
        if ordinal in reserved_ids or not 0 <= ordinal < len(states):
            raise RuntimeError("Storage V2 entity identity reservation returned invalid ordinals")
        reserved_ids[ordinal] = int(result["id"])
    if len(reserved_ids) != len(states):
        raise RuntimeError("Storage V2 entity identity reservation omitted an ordinal")

    one = "(%s::integer,%s::integer)"
    params: list[Any] = []
    for ordinal, state in enumerate(states):
        state.entity_id = reserved_ids[ordinal]
        params.extend((ordinal, state.entity_id))
    cur.execute(
        f"""
        with wanted(ordinal,id)
        as (values {', '.join([one] * len(states))})
        select wanted.ordinal,entity.id,entity.display_name,entity.domain_id,entity.server_id,
               entity.first_seen_utc,entity.last_seen_utc,details.attributes_json
        from wanted
        left join entities_v2 entity
          on entity.id=wanted.id
        left join entity_details_v2 details on details.entity_id=entity.id
        order by wanted.ordinal
        """,
        tuple(params),
    )
    rows = list(cur.fetchall() or [])
    if len(rows) != len(states):
        raise RuntimeError("Storage V2 entity identity lookup returned an incomplete set")

    for result in rows:
        ordinal = int(result["ordinal"])
        state = states[ordinal]
        entity_id = result.get("id")
        if entity_id is None:
            continue
        if int(entity_id) != reserved_ids[ordinal]:
            raise RuntimeError("Storage V2 entity readback returned the wrong identity")
        state.domain_id = result.get("domain_id") or state.domain_id
        state.server_id = result.get("server_id") or state.server_id
        existing_first = result.get("first_seen_utc")
        existing_last = result.get("last_seen_utc")
        if existing_first is not None and (
            state.first_seen is None or _time_key(existing_first) < _time_key(state.first_seen)
        ):
            state.first_seen = existing_first
        if existing_last is not None and (
            state.last_seen is None or _time_key(existing_last) > _time_key(state.last_seen)
        ):
            state.last_seen = existing_last


    source_ids = [int(state.entity_id) for state in states if state.entity_id is not None]
    if len(source_ids) != len(states):
        raise RuntimeError("Storage V2 entity allocator left an identity unresolved")
    effective = (
        _effective_entity_ids(cur, source_ids)
        if resolve_identity_merges
        else {value: value for value in source_ids}
    )
    for state in states:
        assert state.entity_id is not None
        state.effective_entity_id = effective[state.entity_id]
        state.dirty = False


def _collect_links_for_batch(
    event_results: list[tuple[int, bool, dict[str, Any], dict[str, Any]]],
    *,
    server_id: int,
    domain_id: int,
    entity_cache: dict[tuple[str, str], EntityState],
    relink_existing_events: bool,
    profile: ImportProfile,
) -> list[tuple[int, tuple[str, str], dict[str, Any]]]:
    pending: list[tuple[int, tuple[str, str], dict[str, Any]]] = []
    new_states: dict[tuple[str, str], EntityState] = {}
    for event_id, was_inserted, event_row, event_data in event_results:
        if not was_inserted and not relink_existing_events:
            continue
        if not was_inserted:
            profile.events_relinked += 1
        for link in extract_event_entities(event_row, event_data):
            key = (str(link["entity_type"]), str(link["natural_key"]))
            domain_scope = domain_id if link.get("domain_scoped", True) else None
            server_scope = server_id if link.get("server_scoped", False) else None
            seen_at = event_row.get("time_created")
            attributes = link.get("attributes") or {}
            cached = entity_cache.get(key)
            if cached is not None:
                cached.merge(
                    display_name=link["display_name"],
                    domain_id=domain_scope,
                    server_id=server_scope,
                    seen_at=seen_at,
                    attributes=attributes,
                )
                profile.entity_cache_hits += 1
            else:
                state = new_states.get(key)
                if state is None:
                    state = EntityState(
                        entity_type=key[0],
                        natural_key=key[1],
                        display_name=link["display_name"],
                        domain_id=domain_scope,
                        server_id=server_scope,
                        first_seen=seen_at,
                        last_seen=seen_at,
                        attributes_json=json.dumps(attributes, ensure_ascii=False, sort_keys=True),
                    )
                    new_states[key] = state
                else:
                    state.merge(
                        display_name=link["display_name"],
                        domain_id=domain_scope,
                        server_id=server_scope,
                        seen_at=seen_at,
                        attributes=attributes,
                    )
                    profile.entity_cache_hits += 1
            pending.append((event_id, key, link))
    entity_cache.update(new_states)
    return pending


def build_direct_source_batch(
    *,
    event_results: list[tuple[int, bool, dict[str, Any], dict[str, Any]]],
    pending: list[tuple[int, tuple[str, str], dict[str, Any]]],
    entity_cache: dict[tuple[str, str], EntityState],
    raw_log_file_id: int,
    server_id: int,
    domain_id: int,
    site_id: int | None,
    log_source_id: int,
    normalized_at: str,
) -> SourceBatch:
    events = tuple(
        build_direct_event_source_row(
            event_db_id=event_db_id,
            raw_log_file_id=raw_log_file_id,
            server_id=server_id,
            domain_id=domain_id,
            site_id=site_id,
            log_source_id=log_source_id,
            normalized_at=normalized_at,
            row=row,
            event_data=event_data,
        )
        for event_db_id, _inserted, row, event_data in event_results
    )
    affected_keys = sorted({key for _event_id, key, _link in pending})
    entities: list[dict[str, Any]] = []
    for key in affected_keys:
        state = entity_cache[key]
        if state.entity_id is None:
            raise RuntimeError(f"Storage V2 entity id missing for direct batch: {key}")
        entities.append({
            "id": int(state.entity_id),
            "entity_type": state.entity_type,
            "natural_key": state.natural_key,
            "display_name": state.display_name,
            "domain_id": state.domain_id,
            "server_id": state.server_id,
            "first_seen_utc": state.first_seen,
            "last_seen_utc": state.last_seen,
            "attributes_json": state.attributes_json,
        })
    links: list[dict[str, Any]] = []
    for event_id, key, link in pending:
        state = entity_cache[key]
        if state.entity_id is None:
            raise RuntimeError(f"Storage V2 entity id missing for direct link: {key}")
        links.append({
            "event_id": int(event_id),
            "entity_id": int(state.entity_id),
            "link_role": str(link["link_role"]),
            "confidence": float(link.get("confidence", 1.0)),
            "evidence_json": json.dumps(link.get("evidence") or {}, ensure_ascii=False),
            "extracted_from": link.get("extracted_from") or "event_data",
            "attributes_json": json.dumps(
                link.get("attributes") or {}, ensure_ascii=False, sort_keys=True
            ),
            "created_at": str(normalized_at),
        })
    return SourceBatch(events, tuple(entities), tuple(links))


def load_authorized_direct_runtime(
    cur, *, connect_factory: Callable[[], Any], publish_archive: bool = True
) -> DirectImportRuntime | None:
    cur.execute(
        "select to_regclass('public.storage_v2_runtime_authorizations') is not null as available"
    )
    availability = cur.fetchone()
    if not availability or not bool(availability.get("available")):
        return None
    authorization = load_runtime_authorization(cur)
    if authorization is None:
        return None
    publisher = None
    if publish_archive:
        archive_root = Path(authorization.archive_root)
        manifest = PostgresArchiveManifestStore(connect_factory)
        publisher = ArchivePublisher(archive_root, manifest)
    repository = PostgresStorageV2Repository(
        connect_factory,
        semantic_publisher=semantic_publisher_for_runtime(),
    )
    return authorized_direct_import_runtime(
        authorization=authorization,
        repository=repository,
        publisher=publisher,
        connect_factory=connect_factory,
        normalized_at=authorization.authorized_at.isoformat(),
    )


def import_direct_event_batch(
    cur, chunk, *, direct_runtime, server_id, domain_id, site_id, log_source_id,
    raw_log_file_id, normalized_at, batch_identity, entity_cache, profile,
    relink_existing_events=False, resolve_identity_merges=False, fallback_channel="",
):
    """The shared collector/agent projection path; no metadata commits here."""
    if not is_authorized_direct_runtime(direct_runtime):
        raise RuntimeError("storage_v2_admission_required")
    direct_normalized_at = normalized_at
    events_started = monotonic_ms()
    channel_ids = {
        value: int(direct_runtime.repository.dictionary_id("channel", value))
        for value in sorted({str(row.get("channel") or fallback_channel) for row, _data in chunk})
    }
    event_results = resolve_direct_event_ids(
        repository=direct_runtime.repository,
        server_id=server_id,
        channel_ids=channel_ids,
        items=chunk,
    )
    profile.event_batches += 1
    profile.add_ms("event_batches", events_started)
    inserted = sum(1 for _id, was_inserted, _row, _data in event_results if was_inserted)
    skipped = sum(1 for _id, was_inserted, _row, _data in event_results if not was_inserted)

    entity_started = monotonic_ms()
    previous_keys = set(entity_cache)
    pending = _collect_links_for_batch(
        event_results,
        server_id=server_id,
        domain_id=domain_id,
        entity_cache=entity_cache,
        relink_existing_events=relink_existing_events,
        profile=profile,
    )
    new_states = [state for key, state in entity_cache.items() if key not in previous_keys]
    if new_states:
        assign_direct_entity_ids(
            cur,
            states=new_states,
            repository=direct_runtime.repository,
            resolve_identity_merges=resolve_identity_merges,
        )
        profile.entity_upsert_batches += 1
    profile.add_ms("entity_upsert", entity_started)

    publication_results = _direct_publication_results(event_results)
    if publication_results:
        publication_ids = {event_id for event_id, _new, _row, _data in publication_results}
        source_batch = build_direct_source_batch(
            event_results=publication_results,
            pending=[item for item in pending if item[0] in publication_ids],
            entity_cache=entity_cache,
            raw_log_file_id=raw_log_file_id,
            server_id=server_id,
            domain_id=domain_id,
            site_id=site_id,
            log_source_id=log_source_id,
            normalized_at=direct_normalized_at,
        )
        event_ids = [event_id for event_id, _new, _row, _data in publication_results]
        with direct_runtime.connect_factory() as direct_conn, direct_conn.cursor() as direct_cur:
            publish_direct_batch(
                batch_identity=batch_identity(event_ids, profile.event_batches),
                batch=source_batch,
                repository=direct_runtime.repository,
                publisher=direct_runtime.publisher,
                cur=direct_cur,
                compatibility_mirror=None,
            )

    links_started = monotonic_ms()
    state_candidates_by_event: dict[int, list[dict[str, Any]]] = {}
    event_payloads = {event_id: (row, data) for event_id, _inserted, row, data in event_results}
    for event_id, key, link in pending:
        entity_id = entity_cache[key].effective_entity_id
        if entity_id is None:
            raise RuntimeError(f"Entity id missing after batch upsert: {key}")
        profile.links_queued += 1
        event_row, event_data = event_payloads[event_id]
        state = state_for_entity_link(event_row, event_data, link)
        if state and state.get("observed_at_utc"):
            state_candidates_by_event.setdefault(event_id, []).append({
                **state,
                "entity_id": entity_id,
                "source_event_db_id": event_id,
            })
    profile.add_ms("link_batches", links_started)
    for event_id, candidates in sorted(state_candidates_by_event.items()):
        enqueue_projection_job(cur, source_event_db_id=event_id, candidates=candidates)
        profile.entity_state_projection_jobs_queued += 1

    return inserted, skipped


def import_file(
    cur,
    path: Path,
    collection_run_id: int,
    server_id: int,
    domain_id: int,
    site_id: int,
    *,
    event_batch_size: int = DEFAULT_EVENT_BATCH_SIZE,
    entity_batch_size: int = DEFAULT_ENTITY_BATCH_SIZE,
    link_batch_size: int = DEFAULT_LINK_BATCH_SIZE,
    storage_v2_outbox_batch_size: int = DEFAULT_STORAGE_V2_OUTBOX_BATCH_SIZE,
    relink_existing_events: bool = False,
    resolve_identity_merges: bool = False,
    direct_runtime: DirectImportRuntime | None = None,
    commit_direct_metadata: Callable[[], None] | None = None,
) -> tuple[int, int, dict[str, Any]]:
    """Import one JSONL file straight into Storage V2 (the only store, plan 6.5).

    The V1 relations were dropped by migration 097, so there is no V1 write or
    V1-to-V2 outbox path left: an import needs the recorded Storage V2
    admission (``storage_v2_runtime_authorizations``) and stops before reading
    rows without it.
    """
    del entity_batch_size, link_batch_size, storage_v2_outbox_batch_size  # V1-era tuning knobs
    if not is_authorized_direct_runtime(direct_runtime):
        raise RuntimeError(
            "storage_v2_admission_required: no recorded Storage V2 admission; "
            "nothing was imported"
        )
    assert direct_runtime is not None
    if commit_direct_metadata is None:
        raise RuntimeError("direct Storage V2 import requires a metadata commit boundary")
    final_file_sha256 = sha256_file(path)
    digest = hashlib.sha256()
    iterator = iter_jsonl(path, digest=digest)
    first_row = next(iterator, None)
    profile = ImportProfile(file=path.name, rows=0)
    if first_row is None:
        return 0, 0, profile.as_dict()
    channel = first_row.get("channel") or path.stem
    log_source_id = get_log_source(cur, str(channel))
    commit_direct_metadata()
    reserved_raw = direct_runtime.repository.reserve_raw_log_file(
        server_id=server_id,
        log_source_id=log_source_id,
        file_path=str(path),
        sha256=final_file_sha256,
        size_bytes=path.stat().st_size,
        file_format="jsonl",
    )
    raw_log_file_id = int(reserved_raw["id"])
    direct_normalized_at = str(reserved_raw["imported_at"])

    entity_cache: dict[tuple[str, str], EntityState] = {}
    require_entity_state_projection_schema(cur)
    inserted = 0
    skipped = 0
    for raw_chunk in _iter_chunks(chain((first_row,), iterator), event_batch_size):
        profile.rows += len(raw_chunk)
        parse_started = monotonic_ms()
        chunk = [(row, parse_event_data(row.get("xml"))) for row in raw_chunk]
        profile.add_ms("parse_xml", parse_started)
        chunk_inserted, chunk_skipped = import_direct_event_batch(
            cur, chunk, direct_runtime=direct_runtime, server_id=server_id,
            domain_id=domain_id, site_id=site_id, log_source_id=log_source_id,
            raw_log_file_id=raw_log_file_id, normalized_at=direct_normalized_at,
            batch_identity=lambda ids, batch: f"{server_id}:{final_file_sha256}:{batch}:{min(ids)}-{max(ids)}",
            entity_cache=entity_cache, profile=profile,
            relink_existing_events=relink_existing_events, resolve_identity_merges=resolve_identity_merges,
            fallback_channel=str(channel),
        )
        inserted += chunk_inserted
        skipped += chunk_skipped

    verify_direct_file_digest(final_file_sha256, digest.hexdigest())
    raw_log_file_id = finalize_raw_log_file(
        cur, raw_log_file_id=raw_log_file_id, server_id=server_id,
        log_source_id=log_source_id, sha256_value=digest.hexdigest(), rows_count=profile.rows,
        collection_run_id=collection_run_id,
        repair_v1_references=False,
    )
    profile.source_capture_continuity_persisted = _persist_source_capture_continuity(
        cur,
        path=path,
        collection_run_id=collection_run_id,
        raw_log_file_id=raw_log_file_id,
        raw_log_sha256=digest.hexdigest(),
        server_id=server_id,
        log_source_id=log_source_id,
        storage_route="v2",
    )
    profile.inserted = inserted
    profile.skipped = skipped
    profile.unique_entities = len(entity_cache)
    return inserted, skipped, profile.as_dict()


def _aggregate_profiles(file_profiles: list[dict[str, Any]], *, started_ms: int, event_batch_size: int, entity_batch_size: int, link_batch_size: int, storage_v2_outbox_batch_size: int, relink_existing_events: bool) -> dict[str, Any]:
    stage_ms: dict[str, int] = {}
    for item in file_profiles:
        for stage, value in (item.get("stage_ms") or {}).items():
            stage_ms[stage] = stage_ms.get(stage, 0) + int(value or 0)
    return {
        "package_type": "POSTGRES_IMPORT_PROFILE",
        "profile_version": 1,
        "generated_at_utc": utc_now(),
        "duration_ms": max(0, monotonic_ms() - started_ms),
        "configuration": {
            "event_batch_size": event_batch_size,
            "entity_batch_size": entity_batch_size,
            "link_batch_size": link_batch_size,
            "storage_v2_outbox_batch_size": storage_v2_outbox_batch_size,
            "relink_existing_events": relink_existing_events,
        },
        "summary": {
            "files": len(file_profiles),
            "rows": sum(int(item.get("rows") or 0) for item in file_profiles),
            "inserted": sum(int(item.get("inserted") or 0) for item in file_profiles),
            "skipped": sum(int(item.get("skipped") or 0) for item in file_profiles),
            "events_relinked": sum(int(item.get("events_relinked") or 0) for item in file_profiles),
            "event_batches": sum(int(item.get("event_batches") or 0) for item in file_profiles),
            "entity_upsert_batches": sum(int(item.get("entity_upsert_batches") or 0) for item in file_profiles),
            "entity_update_batches": sum(int(item.get("entity_update_batches") or 0) for item in file_profiles),
            "link_batches": sum(int(item.get("link_batches") or 0) for item in file_profiles),
            "unique_entities": sum(int(item.get("unique_entities") or 0) for item in file_profiles),
            "entity_cache_hits": sum(int(item.get("entity_cache_hits") or 0) for item in file_profiles),
            "links_queued": sum(int(item.get("links_queued") or 0) for item in file_profiles),
            "entity_states_queued": sum(int(item.get("entity_states_queued") or 0) for item in file_profiles),
            "entity_states_deferred_v2": sum(int(item.get("entity_states_deferred_v2") or 0) for item in file_profiles),
            "entity_state_projection_jobs_queued": sum(int(item.get("entity_state_projection_jobs_queued") or 0) for item in file_profiles),
            "storage_v2_outbox_batches": sum(int(item.get("storage_v2_outbox_batches") or 0) for item in file_profiles),
            "storage_v2_outbox_events": sum(int(item.get("storage_v2_outbox_events") or 0) for item in file_profiles),
            "stage_ms": stage_ms,
        },
        "files": file_profiles,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Import DC JSONL event exports into PostgreSQL.")
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--forest", default="example.invalid")
    parser.add_argument("--domain", default="EXAMPLE")
    parser.add_argument("--site", default="Default-First-Site-Name")
    parser.add_argument("--server", required=True)
    parser.add_argument("--job-id", type=int)
    parser.add_argument("--trace-id")
    parser.add_argument("--backend")
    parser.add_argument("--dsn")
    parser.add_argument("--event-batch-size", type=int, default=_env_batch("ADLOG_POSTGRES_EVENT_BATCH_SIZE", DEFAULT_EVENT_BATCH_SIZE, MAX_EVENT_BATCH_SIZE))
    parser.add_argument("--entity-batch-size", type=int, default=_env_batch("ADLOG_POSTGRES_ENTITY_BATCH_SIZE", DEFAULT_ENTITY_BATCH_SIZE, MAX_ENTITY_BATCH_SIZE))
    parser.add_argument("--link-batch-size", type=int, default=_env_batch("ADLOG_POSTGRES_LINK_BATCH_SIZE", DEFAULT_LINK_BATCH_SIZE, MAX_LINK_BATCH_SIZE))
    parser.add_argument("--storage-v2-outbox-batch-size", type=int, default=_env_batch("ADLOG_STORAGE_V2_OUTBOX_BATCH_SIZE", DEFAULT_STORAGE_V2_OUTBOX_BATCH_SIZE, MAX_STORAGE_V2_OUTBOX_BATCH_SIZE))
    parser.add_argument("--relink-existing-events", action="store_true")
    parser.add_argument("--profile-output", type=Path)
    args = parser.parse_args()

    from server.sli.sources.collection_quarantine import blocked_batch_marker

    blocked_batch = blocked_batch_marker(args.input_dir)
    if blocked_batch:
        print(json.dumps(blocked_batch, ensure_ascii=False), file=sys.stderr)
        log_event(
            "postgres_importer", "import_blocked_quarantined_batch",
            "PostgreSQL import rejected a quarantined collection batch.",
            level=logging.ERROR, path=str(args.input_dir), server=args.server,
            error=blocked_batch.get("failure_code"),
        )
        return 74

    event_batch_size = _bounded_int(args.event_batch_size, DEFAULT_EVENT_BATCH_SIZE, 1, MAX_EVENT_BATCH_SIZE)
    entity_batch_size = _bounded_int(args.entity_batch_size, DEFAULT_ENTITY_BATCH_SIZE, 1, MAX_ENTITY_BATCH_SIZE)
    link_batch_size = _bounded_int(args.link_batch_size, DEFAULT_LINK_BATCH_SIZE, 1, MAX_LINK_BATCH_SIZE)
    storage_v2_outbox_batch_size = _bounded_int(args.storage_v2_outbox_batch_size, DEFAULT_STORAGE_V2_OUTBOX_BATCH_SIZE, 1, MAX_STORAGE_V2_OUTBOX_BATCH_SIZE)
    files = sorted(args.input_dir.glob("*.jsonl"))
    if not files:
        print(f"No JSONL files found in {args.input_dir}")
        log_event("postgres_importer", "import_failed", "No JSONL files found.", level=logging.ERROR, path=str(args.input_dir), server=args.server, error="no_jsonl_files")
        return 2

    import_started_ms = monotonic_ms()
    log_event(
        "postgres_importer",
        "import_started",
        "PostgreSQL JSONL import started.",
        path=str(args.input_dir),
        server=args.server,
        event_batch_size=event_batch_size,
        entity_batch_size=entity_batch_size,
        link_batch_size=link_batch_size,
        storage_v2_outbox_batch_size=storage_v2_outbox_batch_size,
        relink_existing_events=args.relink_existing_events,
    )
    total_inserted = 0
    total_skipped = 0
    file_profiles: list[dict[str, Any]] = []
    connect_factory = lambda: connect(args.dsn)
    with connect_factory() as conn, conn.cursor() as cur:
        direct_runtime = load_authorized_direct_runtime(
            cur, connect_factory=connect_storage_v2_worker
        )
        forest_id = get_or_create_forest(cur, args.forest)
        domain_id = get_or_create_domain(cur, forest_id, args.domain, args.domain)
        site_id = get_or_create_site(cur, domain_id, args.site)
        server_id = get_or_create_server(cur, domain_id, site_id, args.server)
        now = utc_now()
        cur.execute(
            """
            insert into collection_runs(run_started_at, run_finished_at, mode, status, tool_version, notes)
            values (%s, %s, 'remote_read', 'completed', 'pilot-0.1', %s)
            returning id
            """,
            (now, now, f"PostgreSQL import from {args.input_dir}"),
        )
        collection_run_id = int(cur.fetchone()["id"])
        resolve_identity_merges = _entity_merge_resolver_available(cur)
        for path in files:
            file_started_ms = monotonic_ms()
            inserted, skipped, profile = import_file(
                cur,
                path,
                collection_run_id,
                server_id,
                domain_id,
                site_id,
                event_batch_size=event_batch_size,
                entity_batch_size=entity_batch_size,
                link_batch_size=link_batch_size,
                storage_v2_outbox_batch_size=storage_v2_outbox_batch_size,
                relink_existing_events=args.relink_existing_events,
                resolve_identity_merges=resolve_identity_merges,
                direct_runtime=direct_runtime,
                commit_direct_metadata=conn.commit,
            )
            print(
                f"{path.name}: inserted={inserted}, skipped={skipped}, "
                "source_capture_continuity_persisted="
                f"{int(bool(profile.get('source_capture_continuity_persisted')))}"
            )
            total_inserted += inserted
            total_skipped += skipped
            file_profiles.append(profile)
            log_performance_stage(
                "import_jsonl_file_postgres",
                trace_id=args.trace_id,
                job_id=args.job_id,
                server=args.server,
                channel=path.stem,
                backend=args.backend,
                started_ms=file_started_ms,
                events_count=inserted + skipped,
                bytes_count=path.stat().st_size if path.exists() else None,
                inserted=inserted,
                skipped=skipped,
                batch_profile=profile,
            )
    aggregate = _aggregate_profiles(
        file_profiles,
        started_ms=import_started_ms,
        event_batch_size=event_batch_size,
        entity_batch_size=entity_batch_size,
        link_batch_size=link_batch_size,
        storage_v2_outbox_batch_size=storage_v2_outbox_batch_size,
        relink_existing_events=args.relink_existing_events,
    )
    if args.profile_output:
        args.profile_output.parent.mkdir(parents=True, exist_ok=True)
        args.profile_output.write_text(json.dumps(aggregate, ensure_ascii=False, indent=2), encoding="utf-8")
    log_event(
        "postgres_importer",
        "import_completed",
        "PostgreSQL JSONL import completed.",
        path=str(args.input_dir),
        server=args.server,
        status="completed",
        inserted=total_inserted,
        skipped=total_skipped,
        import_profile=aggregate,
    )
    print("import_profile=" + json.dumps(aggregate, ensure_ascii=False, separators=(",", ":")))
    print(f"total_inserted={total_inserted}, total_skipped={total_skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

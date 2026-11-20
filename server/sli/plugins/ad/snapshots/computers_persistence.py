"""Source snapshot persistence without acquisition or worker lifecycle."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from server.sli.sources.computers_v6_source import (
    base_inventory_status, canonical_computers_v6_snapshot, validate_computers_v6_snapshot,
)

APPROVED_REFERENCE_SHA256 = (
    "caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5"
)
APPROVED_REFERENCE_SHA256_BYTES = bytes.fromhex(APPROVED_REFERENCE_SHA256)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("capture_timestamp_must_be_timezone_aware")
    return value.astimezone(timezone.utc)


def _source_timestamp(value: Any) -> datetime:
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("source_timestamp_invalid") from exc
    return _utc(stamp)


def _domain_id(connection: Any, domain_fqdn: str) -> int:
    with connection.cursor() as cursor:
        cursor.execute(
            "select id from domains where lower(fqdn)=lower(%s) order by id limit 1",
            (str(domain_fqdn).lower(),),
        )
        row = cursor.fetchone()
    if not row:
        raise RuntimeError("computers_v6_source_domain_not_registered")
    return int(dict(row)["id"])


def persist_computers_v6_source_snapshot(
    connection: Any,
    *,
    snapshot: Mapping[str, Any],
    captured_at: datetime,
    capture_options: Mapping[str, Any],
    collector_exit_code: int,
    collector_sha256: bytes = APPROVED_REFERENCE_SHA256_BYTES,
) -> dict[str, Any]:
    if not isinstance(collector_sha256, bytes) or len(collector_sha256) != 32:
        raise ValueError("computers_v6_collector_sha256_invalid")
    validated = validate_computers_v6_snapshot(snapshot)
    metadata = validated["metadata"]
    captured = _utc(captured_at)
    started = _source_timestamp(metadata["started_at"])
    completed = _source_timestamp(metadata["completed_at"])
    if completed > captured:
        raise ValueError("source_completed_after_capture")
    domain_id = _domain_id(connection, str(metadata["domain"]))
    payload_text, payload_sha256 = canonical_computers_v6_snapshot(validated)
    options = {
        "server": capture_options.get("server"),
        "search_base": capture_options.get("search_base"),
        "skip_dns": bool(capture_options.get("skip_dns", False)),
        "collect_ad_site": bool(capture_options.get("collect_ad_site", False)),
        "collect_exact_last_logon": bool(
            capture_options.get("collect_exact_last_logon", False)
        ),
    }
    options_text = json.dumps(
        options, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    collection_status = str(metadata["collection_status"])
    base_status = base_inventory_status(validated)
    object_count = len(validated["objects"])
    snapshot_uuid = str(metadata["snapshot_id"])
    with connection.cursor() as cursor:
        cursor.execute(
            """
            insert into computers_v6_source_snapshots(
                domain_id,snapshot_uuid,schema_version,source_started_at_utc,
                source_completed_at_utc,captured_at_utc,query_dc,search_base,
                collector_version,collector_sha256,collection_status,
                base_inventory_status,object_count,source_options_json,
                payload_json,payload_sha256,collector_exit_code
            ) values (
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,
                %s::jsonb,%s,%s
            )
            on conflict(domain_id,snapshot_uuid) do nothing
            returning source_snapshot_id
            """,
            (
                domain_id,
                snapshot_uuid,
                str(validated["schema_version"]),
                started,
                completed,
                captured,
                str(metadata["query_dc"]),
                metadata.get("search_base"),
                str(metadata["collector_version"]),
                collector_sha256,
                collection_status,
                base_status,
                object_count,
                options_text,
                payload_text,
                payload_sha256,
                int(collector_exit_code),
            ),
        )
        inserted = cursor.fetchone()
        if not inserted:
            cursor.execute(
                """
                select source_snapshot_id,object_count,payload_sha256,snapshot_uuid
                from computers_v6_source_snapshots
                where domain_id=%s and snapshot_uuid=%s
                """,
                (domain_id, snapshot_uuid),
            )
            conflict = dict(cursor.fetchone() or {})
            conflict_hash = conflict.get("payload_sha256")
            if isinstance(conflict_hash, memoryview):
                conflict_hash = conflict_hash.tobytes()
            conflict_count = conflict.get("object_count")
            if (
                conflict_count is None
                or int(conflict_count) != object_count
                or bytes(conflict_hash or b"") != payload_sha256
                or str(conflict.get("snapshot_uuid") or "") != snapshot_uuid
            ):
                raise RuntimeError(
                    "computers_v6_source_snapshot_conflict_readback_mismatch"
                )
            return {
                "status": "already_captured",
                "source_snapshot_id": int(conflict["source_snapshot_id"]),
                "domain_id": domain_id,
                "snapshot_uuid": snapshot_uuid,
                "object_count": object_count,
                "collection_status": collection_status,
                "base_inventory_status": base_status,
                "retired_snapshots": 0,
            }
        source_snapshot_id = int(dict(inserted)["source_snapshot_id"])
        cursor.execute(
            """
            select object_count,payload_sha256,snapshot_uuid
            from computers_v6_source_snapshots
            where source_snapshot_id=%s
            """,
            (source_snapshot_id,),
        )
        readback = dict(cursor.fetchone() or {})
        readback_hash = readback.get("payload_sha256")
        if isinstance(readback_hash, memoryview):
            readback_hash = readback_hash.tobytes()
        readback_count = readback.get("object_count")
        if (
            readback_count is None
            or int(readback_count) != object_count
            or bytes(readback_hash or b"") != payload_sha256
            or str(readback.get("snapshot_uuid") or "") != snapshot_uuid
        ):
            raise RuntimeError("computers_v6_source_snapshot_readback_mismatch")
    return {
        "status": "captured",
        "source_snapshot_id": source_snapshot_id,
        "domain_id": domain_id,
        "snapshot_uuid": snapshot_uuid,
        "object_count": object_count,
        "collection_status": collection_status,
        "base_inventory_status": base_status,
        "retired_snapshots": 0,
    }

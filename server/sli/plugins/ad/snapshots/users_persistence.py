"""Source snapshot persistence without acquisition or worker lifecycle."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from server.sli.reports.users_v2_reporting import CONTRACT_ID


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("snapshot timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def snapshot_bucket_start(value: datetime) -> datetime:
    stamp = _utc(value)
    return stamp.replace(hour=12 if stamp.hour >= 12 else 0, minute=0, second=0, microsecond=0)


def _canonical(value: Mapping[str, Any]) -> tuple[str, bytes]:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return text, hashlib.sha256(text.encode("utf-8")).digest()


def persist_users_v2_snapshot(connection: Any, *, snapshot: Mapping[str, Any], domain_id: int, captured_at: datetime) -> dict[str, Any]:
    metadata = dict(snapshot.get("metadata") or {})
    if metadata.get("contract_id") != CONTRACT_ID:
        raise RuntimeError("users_v2_snapshot_contract_mismatch")
    state = str(metadata.get("collection_status") or "")
    if state not in {"complete", "partial"}:
        raise RuntimeError("users_v2_snapshot_source_not_usable")
    payload_text, payload_hash = _canonical(snapshot)
    scope = {"domain_ids": [int(domain_id)], "report_key": "ad.users.v2"}
    scope_text, scope_hash = _canonical(scope)
    observed = metadata.get("observed_at")
    observed_at = datetime.fromisoformat(str(observed).replace("Z", "+00:00")) if observed else None
    users = list(snapshot.get("users") or [])
    bucket = snapshot_bucket_start(captured_at)
    with connection.cursor() as cur:
        cur.execute(
            """insert into users_report_v2_snapshots(
                   domain_id,contract_id,scope_json,scope_sha256,bucket_start_utc,
                   captured_at_utc,source_observed_at_utc,source_state,user_count,
                   payload_json,payload_sha256
               ) values(%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
               on conflict(domain_id,scope_sha256,source_observed_at_utc,contract_id,schema_version)
               do nothing returning snapshot_id""",
            (domain_id, CONTRACT_ID, scope_text, scope_hash, bucket, _utc(captured_at), observed_at, state, len(users), payload_text, payload_hash),
        )
        inserted = dict(cur.fetchone() or {})
        if not inserted:
            return {"status": "already_captured", "user_count": len(users), "retired_snapshots": 0}
        snapshot_id = int(inserted["snapshot_id"])
        cur.execute("select user_count,payload_sha256 from users_report_v2_snapshots where snapshot_id=%s", (snapshot_id,))
        readback = dict(cur.fetchone() or {})
        if int(readback.get("user_count", -1)) != len(users) or bytes(readback.get("payload_sha256") or b"") != payload_hash:
            raise RuntimeError("users_v2_snapshot_readback_mismatch")
    return {"status": "captured", "snapshot_id": snapshot_id, "user_count": len(users), "retired_snapshots": 0}

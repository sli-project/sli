"""Bounded semantic shadow comparison for dormant Storage V2 reads."""
from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from server.sli.storage.storage_v2_config import StorageV2Settings
from server.sli.storage.storage_v2_models import canonical_json_bytes
from server.sli.storage.storage_v2_repository import StorageV2Repository

ALLOWED_QUERY_KINDS = {
    "latest_events", "event_id_time", "server_time", "channel_event_time",
    "subject_account_time", "target_account_time", "ip_time", "logon_id_time",
    "entity_timeline", "event_detail_archive_lookup",
}


@dataclass(frozen=True)
class ShadowComparison:
    query_kind: str
    identity_match: bool
    count_match: bool
    v1_duration_ms: float
    v2_duration_ms: float
    v1_result_sha256: bytes
    v2_result_sha256: bytes
    mismatch_summary: str | None = None

    def public_dict(self) -> dict[str, Any]:
        return {
            "query_kind": self.query_kind,
            "identity_match": self.identity_match,
            "count_match": self.count_match,
            "v1_duration_ms": round(self.v1_duration_ms, 6),
            "v2_duration_ms": round(self.v2_duration_ms, 6),
            "mismatch_summary": self.mismatch_summary,
            "payload_content_persisted": False,
        }


def _digest(rows: Sequence[Mapping[str, Any]]) -> bytes:
    # Query contracts in this module are ordered.  Preserve sequence so shadow
    # comparison catches regressions in latest/timeline ordering instead of
    # silently treating a permutation as equivalent.
    return hashlib.sha256(canonical_json_bytes([dict(row) for row in rows])).digest()


def compare_shadow_query(
    *,
    query_kind: str,
    sample_key: Mapping[str, Any],
    v1_query: Callable[[], Sequence[Mapping[str, Any]]],
    v2_query: Callable[[], Sequence[Mapping[str, Any]]],
    repository: StorageV2Repository,
) -> ShadowComparison:
    if query_kind not in ALLOWED_QUERY_KINDS:
        raise ValueError(f"unsupported shadow query kind: {query_kind}")
    started = time.perf_counter()
    v1_rows = list(v1_query())
    v1_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    v2_rows = list(v2_query())
    v2_ms = (time.perf_counter() - started) * 1000
    v1_hash = _digest(v1_rows)
    v2_hash = _digest(v2_rows)
    count_match = len(v1_rows) == len(v2_rows)
    identity_match = v1_hash == v2_hash
    mismatch = None if identity_match and count_match else f"count {len(v1_rows)} != {len(v2_rows)} or semantic hash mismatch"
    payload = {
        "query_kind": query_kind,
        "sample_key_sha256": hashlib.sha256(canonical_json_bytes(sample_key)).digest(),
        "v1_result_sha256": v1_hash,
        "v2_result_sha256": v2_hash,
        "identity_match": identity_match,
        "count_match": count_match,
        "v1_duration_ms": v1_ms,
        "v2_duration_ms": v2_ms,
        "mismatch_summary": mismatch,
    }
    repository.record_shadow(payload)
    return ShadowComparison(
        query_kind=query_kind,
        identity_match=identity_match,
        count_match=count_match,
        v1_duration_ms=v1_ms,
        v2_duration_ms=v2_ms,
        v1_result_sha256=v1_hash,
        v2_result_sha256=v2_hash,
        mismatch_summary=mismatch,
    )


def compare_shadow_rows(
    *,
    query_kind: str,
    sample_key: Mapping[str, Any],
    v1_rows: Sequence[Mapping[str, Any]],
    v2_query: Callable[[], Sequence[Mapping[str, Any]]],
    repository: StorageV2Repository,
) -> ShadowComparison:
    """Compare already-fetched V1 rows with a bounded V2 query.

    HTTP handlers use this variant so a sampled shadow does not repeat the
    authoritative V1 query merely to obtain its comparison input.
    """
    if query_kind not in ALLOWED_QUERY_KINDS:
        raise ValueError(f"unsupported shadow query kind: {query_kind}")
    v1_rows = list(v1_rows)
    started = time.perf_counter()
    v2_rows = list(v2_query())
    v2_ms = (time.perf_counter() - started) * 1000
    v1_hash = _digest(v1_rows)
    v2_hash = _digest(v2_rows)
    count_match = len(v1_rows) == len(v2_rows)
    identity_match = v1_hash == v2_hash
    mismatch = None if identity_match and count_match else f"count {len(v1_rows)} != {len(v2_rows)} or semantic hash mismatch"
    payload = {
        "query_kind": query_kind,
        "sample_key_sha256": hashlib.sha256(canonical_json_bytes(sample_key)).digest(),
        "v1_result_sha256": v1_hash,
        "v2_result_sha256": v2_hash,
        "identity_match": identity_match,
        "count_match": count_match,
        "v1_duration_ms": 0.0,
        "v2_duration_ms": v2_ms,
        "mismatch_summary": mismatch,
    }
    repository.record_shadow(payload)
    return ShadowComparison(
        query_kind=query_kind,
        identity_match=identity_match,
        count_match=count_match,
        v1_duration_ms=0.0,
        v2_duration_ms=v2_ms,
        v1_result_sha256=v1_hash,
        v2_result_sha256=v2_hash,
        mismatch_summary=mismatch,
    )


def should_shadow(settings: StorageV2Settings, *, random_value: float | None = None) -> bool:
    if not settings.shadow_read_enabled:
        return False
    value = random.random() if random_value is None else float(random_value)
    return 0.0 <= value < settings.shadow_sample_rate

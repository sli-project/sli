# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``source_capture_continuity`` at call time.
from __future__ import annotations

"""Immutable source-capture continuity declarations for descriptor promotion.

This is deliberately a narrow provenance contract, not a new collection or
storage pipeline.  Existing collectors publish source-native cursor bounds;
the importer persists the declaration and the warm lifecycle later reads it
back from PostgreSQL before it can derive a no-archive representation.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Mapping

from server.source_packs.windows_ad_dc import (
    DC_POWERSHELL_ORIGIN_EVENT_IDS,
    event_ids_for_analysis_family,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
CONTRACT_ID = "sli.source-capture-continuity.v1"
MAX_CONTINUITY_DECLARATION_MEMBERS = 10_000
MAX_CONTINUITY_SOURCE_REFERENCES = 10_000


class CaptureContinuityError(ValueError):
    """A source capture cannot honestly support an immutable declaration."""


@dataclass(frozen=True)
class CaptureDeclaration:
    scope_identity: str
    declaration_sha256: str
    collection_run_id: int
    raw_log_file_id: int
    raw_log_sha256: str
    server_id: int
    log_source_id: int
    descriptor_source: str
    descriptor_stream: str
    provider_name: str
    channel_value: str
    channel_generation_identity: str
    selector_event_ids: tuple[int, ...]
    query_exhausted: bool
    capture_after_record_id: int
    capture_latest_record_id: int
    first_event_record_id: int
    last_event_record_id: int
    source_event_ids: tuple[int, ...]
    source_record_ids: tuple[int, ...]
    source_event_keys: tuple[int, ...]
    source_hashes: tuple[str, ...]
    recorded_at_utc: datetime
    complete: bool = True

    def to_record(self) -> dict[str, Any]:
        return {
            "scope_identity": self.scope_identity,
            "declaration_sha256": self.declaration_sha256,
            "collection_run_id": self.collection_run_id,
            "raw_log_file_id": self.raw_log_file_id,
            "raw_log_sha256": self.raw_log_sha256,
            "server_id": self.server_id,
            "log_source_id": self.log_source_id,
            "descriptor_source": self.descriptor_source,
            "descriptor_stream": self.descriptor_stream,
            "provider_name": self.provider_name,
            "channel_value": self.channel_value,
            "channel_generation_identity": self.channel_generation_identity,
            "selector_event_ids": list(self.selector_event_ids),
            "query_exhausted": self.query_exhausted,
            "capture_after_record_id": self.capture_after_record_id,
            "capture_latest_record_id": self.capture_latest_record_id,
            "first_event_record_id": self.first_event_record_id,
            "last_event_record_id": self.last_event_record_id,
            "completeness": "complete",
            "covered_source_events": [
                {
                    "id": event_id,
                    "record_id": record_id,
                    "event_key": event_key,
                    "sha256": digest,
                }
                for event_id, record_id, event_key, digest in zip(
                    self.source_event_ids,
                    self.source_record_ids,
                    # Event keys are deliberately retained in immutable raw
                    # provenance, so the descriptor selector never asks a
                    # caller to name its lifecycle facts.
                    self.source_event_keys,
                    self.source_hashes,
                )
            ],
        }


def capture_scope_from_collection_summary(
    summary: Mapping[str, Any],
    *,
    raw_file_name: str,
    base_scope: Mapping[str, Any],
    source_events: list[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Translate one collector-produced sidecar into an importer input.

    A sidecar is a producer assertion, not a hint: legacy summaries and
    partial/ambiguous summaries deliberately return ``None``.  The importer
    may still ingest their raw evidence, but no later promotion can use it as
    a continuity proof.
    """
    channels = summary.get("channels")
    if not isinstance(channels, list) or not raw_file_name:
        return None
    matches = [
        item for item in channels
        if isinstance(item, Mapping)
        and str(item.get("file") or "").replace("\\", "/").endswith("/" + raw_file_name)
        or isinstance(item, Mapping) and str(item.get("file") or "") == raw_file_name
    ]
    if len(matches) != 1:
        return None
    continuity = matches[0].get("continuity")
    if not isinstance(continuity, Mapping):
        return None
    if (
        continuity.get("contract") != CONTRACT_ID
        or continuity.get("status") != "complete"
        or continuity.get("truncated") is not False
    ):
        return None
    after = continuity.get("after_record_id")
    latest = continuity.get("latest_record_id")
    generation_identity = continuity.get("channel_generation_identity")
    try:
        _nonnegative_int(after, "capture_after_record_id")
        _positive_int(latest, "capture_latest_record_id")
        _required_text(generation_identity, "channel_generation_identity")
        selector_event_ids = _selector_event_ids(continuity.get("selector_event_ids"))
    except CaptureContinuityError:
        return None
    if continuity.get("query_exhausted") is not True:
        return None
    return {
        **dict(base_scope),
        "capture_status": "completed",
        "cursor_strategy": "record_id",
        "capture_after_record_id": after,
        "capture_latest_record_id": latest,
        "channel_generation_identity": generation_identity,
        "selector_event_ids": list(selector_event_ids),
        "query_exhausted": True,
        "truncated": False,
        "source_events": [dict(item) for item in source_events],
    }


def _required_text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise CaptureContinuityError(f"{field}_required")
    return result


def _positive_int(value: Any, field: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise CaptureContinuityError(f"{field}_invalid") from exc
    if result <= 0:
        raise CaptureContinuityError(f"{field}_invalid")
    return result


def _nonnegative_int(value: Any, field: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise CaptureContinuityError(f"{field}_invalid") from exc
    if result < 0:
        raise CaptureContinuityError(f"{field}_invalid")
    return result


def _digest(value: Any, field: str) -> str:
    result = value.hex() if isinstance(value, bytes) else str(value or "")
    result = result.lower()
    if HEX64.fullmatch(result) is None:
        raise CaptureContinuityError(f"{field}_invalid")
    return result


def _selector_event_ids(value: Any) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise CaptureContinuityError("capture_selector_event_ids_required")
    normalized: set[int] = set()
    for item in value:
        if isinstance(item, bool):
            raise CaptureContinuityError("capture_selector_event_ids_invalid")
        normalized.add(_positive_int(item, "capture_selector_event_ids"))
    if not normalized:
        raise CaptureContinuityError("capture_selector_event_ids_required")
    return tuple(sorted(normalized))


def build_capture_declaration(scope: Mapping[str, Any]) -> CaptureDeclaration:
    """Build a declaration only from an exact, bounded complete capture.

    A successful read without an exact cursor range is intentionally not enough:
    callers must retain the source as soon as collection completeness is not
    proved by the producer's own contract.
    """
    if scope.get("capture_status") != "completed":
        raise CaptureContinuityError("capture_status_not_complete")
    if bool(scope.get("truncated")):
        raise CaptureContinuityError("capture_truncated")
    after = _nonnegative_int(scope.get("capture_after_record_id"), "capture_after_record_id")
    latest = _positive_int(scope.get("capture_latest_record_id"), "capture_latest_record_id")
    if scope.get("cursor_strategy") != "record_id" or latest <= after:
        raise CaptureContinuityError("capture_cursor_not_continuous")
    selector_event_ids = _selector_event_ids(scope.get("selector_event_ids"))
    if scope.get("query_exhausted") is not True:
        raise CaptureContinuityError("capture_query_not_exhausted")

    rows = list(scope.get("source_events") or ())
    normalized: list[tuple[int, int, int, str]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise CaptureContinuityError("capture_source_event_invalid")
        normalized.append((
            _positive_int(row.get("id"), "capture_source_event_id"),
            _positive_int(row.get("record_id"), "capture_source_record_id"),
            _positive_int(row.get("event_key"), "capture_source_event_key"),
            _digest(row.get("normalized_hash"), "capture_source_hash"),
        ))
    normalized.sort(key=lambda item: (item[1], item[0]))
    if len({item[0] for item in normalized}) != len(normalized):
        raise CaptureContinuityError("capture_source_event_ids_not_unique")
    if len({item[1] for item in normalized}) != len(normalized):
        raise CaptureContinuityError("capture_source_record_ids_not_unique")
    record_ids = [item[1] for item in normalized]
    if any(record_id <= after or record_id > latest for record_id in record_ids):
        raise CaptureContinuityError("capture_source_record_out_of_bounds")
    if any(item[2] not in selector_event_ids for item in normalized):
        raise CaptureContinuityError("capture_source_event_not_selected")

    collection_run_id = _positive_int(scope.get("collection_run_id"), "collection_run_id")
    raw_log_file_id = _positive_int(scope.get("raw_log_file_id"), "raw_log_file_id")
    values = {
        "contract": CONTRACT_ID,
        "collection_run_id": collection_run_id,
        "raw_log_file_id": raw_log_file_id,
        "raw_log_sha256": _digest(scope.get("raw_log_sha256"), "raw_log_sha256"),
        "server_id": _positive_int(scope.get("server_id"), "server_id"),
        "log_source_id": _positive_int(scope.get("log_source_id"), "log_source_id"),
        "descriptor_source": _required_text(scope.get("descriptor_source"), "descriptor_source"),
        "descriptor_stream": _required_text(scope.get("descriptor_stream"), "descriptor_stream"),
        "provider_name": _required_text(scope.get("provider_name"), "provider_name"),
        "channel_value": _required_text(scope.get("channel_value"), "channel_value"),
        "channel_generation_identity": _required_text(
            scope.get("channel_generation_identity"), "channel_generation_identity"
        ),
        "selector_event_ids": list(selector_event_ids),
        "query_exhausted": True,
        "capture_after_record_id": after,
        "capture_latest_record_id": latest,
        "first_event_record_id": after + 1,
        "last_event_record_id": latest,
        "source_events": [
            {"id": event_id, "record_id": record_id, "event_key": event_key, "sha256": digest}
            for event_id, record_id, event_key, digest in normalized
        ],
    }
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = sha256(canonical.encode("utf-8")).hexdigest()
    recorded_at = scope.get("recorded_at_utc")
    if not isinstance(recorded_at, datetime):
        recorded_at = datetime.now(timezone.utc)
    if recorded_at.tzinfo is None:
        raise CaptureContinuityError("recorded_at_timezone_required")
    return CaptureDeclaration(
        scope_identity=f"{CONTRACT_ID}:{raw_log_file_id}:{digest}",
        declaration_sha256=digest,
        collection_run_id=collection_run_id,
        raw_log_file_id=raw_log_file_id,
        raw_log_sha256=values["raw_log_sha256"],
        server_id=values["server_id"],
        log_source_id=values["log_source_id"],
        descriptor_source=values["descriptor_source"],
        descriptor_stream=values["descriptor_stream"],
        provider_name=values["provider_name"],
        channel_value=values["channel_value"],
        channel_generation_identity=values["channel_generation_identity"],
        selector_event_ids=selector_event_ids,
        query_exhausted=True,
        capture_after_record_id=after,
        capture_latest_record_id=latest,
        first_event_record_id=after + 1,
        last_event_record_id=latest,
        source_event_ids=tuple(item[0] for item in normalized),
        source_record_ids=tuple(item[1] for item in normalized),
        source_event_keys=tuple(item[2] for item in normalized),
        source_hashes=tuple(item[3] for item in normalized),
        recorded_at_utc=recorded_at.astimezone(timezone.utc),
    )


def persist_capture_declaration(cur: Any, declaration: CaptureDeclaration) -> CaptureDeclaration:
    """Append one immutable declaration and prove replay identity.

    The unique identity is deterministic.  An interrupted importer may safely
    retry the exact same capture, while a changed source material produces a
    different digest and can never overwrite the prior declaration.
    """
    record = declaration.to_record()
    cur.execute(
        """
        insert into source_capture_continuity_declarations(
            collection_run_id,raw_log_file_id,raw_log_sha256,server_id,log_source_id,
            scope_identity,descriptor_source,descriptor_stream,provider_name,channel_value,
            channel_generation_identity,
            selector_event_ids,query_exhausted,
            capture_after_record_id,capture_latest_record_id,
            first_event_record_id,last_event_record_id,completeness,
            covered_source_events,declaration_sha256
        ) values (
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s,'complete',%s::jsonb,%s
        )
        on conflict(scope_identity,declaration_sha256) do nothing
        """,
        (
            declaration.collection_run_id, declaration.raw_log_file_id,
            declaration.raw_log_sha256, declaration.server_id,
            declaration.log_source_id, declaration.scope_identity,
            declaration.descriptor_source, declaration.descriptor_stream,
            declaration.provider_name, declaration.channel_value,
            declaration.channel_generation_identity,
            json.dumps(list(declaration.selector_event_ids), separators=(",", ":")),
            declaration.query_exhausted,
            declaration.capture_after_record_id,
            declaration.capture_latest_record_id,
            declaration.first_event_record_id, declaration.last_event_record_id,
            json.dumps(record["covered_source_events"], sort_keys=True, separators=(",", ":")),
            declaration.declaration_sha256,
        ),
    )
    cur.execute(
        """
        select raw_log_sha256,server_id,log_source_id,descriptor_source,
               descriptor_stream,provider_name,channel_value,channel_generation_identity,
               selector_event_ids,query_exhausted,
               capture_after_record_id,
               capture_latest_record_id,first_event_record_id,last_event_record_id,
               completeness,covered_source_events,declaration_sha256
        from source_capture_continuity_declarations
        where scope_identity=%s and declaration_sha256=%s
        """,
        (declaration.scope_identity, declaration.declaration_sha256),
    )
    row = cur.fetchone()
    if not row:
        raise CaptureContinuityError("capture_declaration_persistence_missing")
    actual = dict(row)
    expected_events = record["covered_source_events"]
    if (
        str(actual.get("raw_log_sha256") or "").lower() != declaration.raw_log_sha256
        or int(actual.get("server_id") or 0) != declaration.server_id
        or int(actual.get("log_source_id") or 0) != declaration.log_source_id
        or str(actual.get("descriptor_source") or "") != declaration.descriptor_source
        or str(actual.get("descriptor_stream") or "") != declaration.descriptor_stream
        or str(actual.get("provider_name") or "") != declaration.provider_name
        or str(actual.get("channel_value") or "") != declaration.channel_value
        or str(actual.get("channel_generation_identity") or "")
        != declaration.channel_generation_identity
        or list(actual.get("selector_event_ids") or []) != list(declaration.selector_event_ids)
        or actual.get("query_exhausted") is not True
        or int(actual.get("capture_after_record_id") or 0) != declaration.capture_after_record_id
        or int(actual.get("capture_latest_record_id") or 0) != declaration.capture_latest_record_id
        or int(actual.get("first_event_record_id") or 0) != declaration.first_event_record_id
        or int(actual.get("last_event_record_id") or 0) != declaration.last_event_record_id
        or str(actual.get("completeness") or "") != "complete"
        or str(actual.get("declaration_sha256") or "") != declaration.declaration_sha256
        or list(actual.get("covered_source_events") or []) != expected_events
    ):
        raise CaptureContinuityError("capture_declaration_persistence_mismatch")
    return declaration


BOOT_EVENT_KEY = int(DC_POWERSHELL_ORIGIN_EVENT_IDS["boot_start"])
OPEN_EVENT_KEY, = event_ids_for_analysis_family("successful_logon")
CLOSE_EVENT_KEY, = event_ids_for_analysis_family("logoff")
PRIVILEGE_EVENT_KEY, = event_ids_for_analysis_family("special_privileges")
AUTHENTICATION_LIFECYCLE_KEYS = frozenset({
    BOOT_EVENT_KEY, OPEN_EVENT_KEY, CLOSE_EVENT_KEY,
})
AUTHENTICATION_SUPPLEMENTAL_KEYS = frozenset({PRIVILEGE_EVENT_KEY})
AUTHENTICATION_EVENT_KEYS = (
    AUTHENTICATION_LIFECYCLE_KEYS | AUTHENTICATION_SUPPLEMENTAL_KEYS
)
RANGE_CONTRACT_ID = "sli.source-capture-continuity-range.v1"










from server.sli.sources.source_capture_continuity_descriptor import (
    _normalized_source_row,
    _rebuild_durable_declaration,
    prepare_descriptor_range,
    prepare_descriptor_selection,
)
from server.sli.sources.source_capture_continuity_lifecycle import (
    _load_verified_lifecycle_range_context,
    load_verified_lifecycle_context,
    recheck_durable_promotion_continuity,
)

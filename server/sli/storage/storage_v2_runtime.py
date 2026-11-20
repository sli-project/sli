"""Read-side building blocks for a future Storage V2 runtime cutover.

This module is deliberately not wired into HTTP handlers by this stage.  It
provides the concrete, testable contract those handlers must use during shadow
validation: compact summaries come from PostgreSQL, full payload comes only
from a hash-verified published archive, and payload search is always bounded.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

from server.sli.storage.storage_v2_archive import (
    ArchiveIntegrityError,
    ArchiveObjectUnavailableError,
    ArchiveReader,
)
from server.sli.storage.storage_v2_models import parse_utc_timestamp

DEEP_SEARCH_CANDIDATE_LIMIT = 10_000


class StorageV2ReadStore(Protocol):
    def get_event_summary(self, event_id: int) -> Mapping[str, Any] | None: ...


class PostgresStorageV2ReadStore:
    """Read-only SQL adapter using a caller-owned connection factory."""

    def __init__(self, connect: Callable[[], Any]) -> None:
        self._connect = connect

    def get_event_summary(self, event_id: int) -> Mapping[str, Any] | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                select
                    e.*,
                    provider.value as provider_name,
                    channel.value as channel,
                    computer.value as computer,
                    keywords.value as keywords,
                    subject_domain.value as subject_domain_name,
                    target_domain.value as target_domain_name,
                    facts.process_name,
                    facts.process_id,
                    facts.target_server_name,
                    facts.service_name,
                    facts.task_name,
                    facts.task_action,
                    facts.task_author,
                    facts.run_as,
                    facts.logon_type,
                    facts.result_code,
                    facts.object_name,
                    facts.share_name,
                    facts.message_sample
                from events_v2_core e
                left join storage_v2_provider provider on provider.id=e.provider_id
                join storage_v2_channel channel on channel.id=e.channel_id
                left join storage_v2_computer computer on computer.id=e.computer_id
                left join storage_v2_keywords keywords on keywords.id=e.keywords_id
                left join storage_v2_domain_name subject_domain on subject_domain.id=e.subject_domain_id
                left join storage_v2_domain_name target_domain on target_domain.id=e.target_domain_id
                left join event_facts_v2 facts on facts.event_id=e.id
                where e.id=%s
                """,
                (int(event_id),),
            )
            row = cur.fetchone()
        return dict(row) if row else None

    def get_agent_event_payload(self, summary: Mapping[str, Any]) -> Mapping[str, Any] | None:
        """Read only the imported inbox packet addressed by this core's raw file."""
        from server.sli.storage.agent_event_payload import verified_agent_event_payload

        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                select i.event_rows, r.sha256 as raw_sha256,i.packet as attested_packet,
                    i.envelope as attested_envelope,receipt.envelope_sha256,i.packet_id::text as packet_id
                from raw_log_files r
                join sli_agent_packet_inbox i on r.file_path='agent-packet:' || i.packet_id::text
                join sli_agent_receipts receipt on receipt.packet_id=i.packet_id and receipt.envelope=i.envelope
                where r.id=%s and r.server_id=%s and r.log_source_id=%s
                    and i.imported_at is not null
                limit 1
                """,
                (int(summary["raw_log_file_id"]), int(summary["server_id"]), int(summary["log_source_id"])),
            )
            packet = cur.fetchone()
        return verified_agent_event_payload(summary, packet) if packet else None

    def get_preferred_event_payload(self, summary: Mapping[str, Any]) -> Mapping[str, Any] | None:
        from server.sli.storage.event_source_representation import (
            verified_preferred_payload,
        )

        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("select * from event_source_representations_v2 where event_id=%s", (int(summary["id"]),))
            row = cur.fetchone()
        return verified_preferred_payload(summary, row) if row else None


class StorageV2RuntimeReader:
    """Fail-closed facade for compact reads and canonical archive hydration."""

    def __init__(self, store: StorageV2ReadStore, archive: ArchiveReader) -> None:
        self.store = store
        self.archive = archive

    def event_summary(self, event_id: int) -> Mapping[str, Any]:
        summary = self.store.get_event_summary(int(event_id))
        if summary is None:
            raise KeyError(f"V2 event core not found for event {event_id}")
        return summary

    def event_details(self, event_id: int) -> Mapping[str, Any]:
        summary = self.event_summary(event_id)
        preferred = getattr(self.store, "get_preferred_event_payload", None)
        try:
            payload = self.archive.read_event(archive_kind="event", event_id=int(event_id))
        except (FileNotFoundError, ArchiveObjectUnavailableError):
            # Agent imports retain the attested source in the inbox without an archive.
            load_packet = getattr(self.store, "get_agent_event_payload", None)
            payload = preferred(summary) if preferred else None
            if payload is not None:
                self._verify_core_identity(summary, payload)
                return payload
            payload = load_packet(summary) if load_packet else None
            if payload is None:
                raise
        self._verify_core_identity(summary, payload)
        richer = preferred(summary) if preferred else None
        if richer is not None:
            self._verify_core_identity(summary, richer)
            return richer
        return payload

    def deep_search(
        self,
        *,
        term: str,
        min_event_id: int,
        max_event_id: int,
        max_blocks: int = 8,
        max_results: int = 100,
    ) -> list[Mapping[str, Any]]:
        rows = self.archive.search_events(
            term=term,
            min_event_id=min_event_id,
            max_event_id=max_event_id,
            max_blocks=max_blocks,
            max_results=max_results,
        )
        for row in rows:
            summary = self.store.get_event_summary(int(row["id"]))
            if summary is None:
                raise ArchiveIntegrityError(
                    f"archive event {row['id']} has no V2 core row"
                )
            self._verify_core_identity(summary, row)
        return rows

    def deep_search_candidates(
        self,
        *,
        term: str,
        candidates: Sequence[Mapping[str, Any]],
        max_blocks: int = 8,
        max_results: int = 100,
        account_values: Sequence[str] | None = None,
    ) -> list[Mapping[str, Any]]:
        """Search an exact, bounded metadata selection in its keyset order.

        Missing payload evidence rejects the window rather than reporting an
        incomplete search as exhausted. Verify every candidate, including text
        nonmatches, before applying the page limit.
        """
        needle = str(term).strip().casefold()
        if len(needle) < 2:
            raise ValueError("archive search term must contain at least two characters")
        if not 1 <= int(max_results) <= 1000:
            raise ValueError("archive search max_results must be between 1 and 1000")
        if len(candidates) > DEEP_SEARCH_CANDIDATE_LIMIT:
            raise ValueError("archive search exceeds candidate limit; narrow the event range")
        payloads = self.archive.read_events_many(
            [int(row["id"]) for row in candidates], max_blocks=max_blocks,
        )
        matches: list[Mapping[str, Any]] = []
        accounts = set(account_values) if account_values is not None else None
        for summary in candidates:
            payload = payloads[int(summary["id"])]
            self._verify_core_identity(summary, payload)
            haystack = "\n".join(
                json.dumps(payload.get(field), ensure_ascii=False, sort_keys=True)
                if isinstance(payload.get(field), (Mapping, list))
                else str(payload.get(field) or "")
                for field in ("message_text", "event_data_json", "record_xml")
            ).casefold()
            if needle not in haystack:
                continue
            if accounts is not None and not (
                payload.get("subject_user_name") in accounts
                or payload.get("target_user_name") in accounts
            ):
                continue
            if len(matches) < int(max_results):
                matches.append({
                    **payload,
                    # Cursor keys must match the metadata SQL ordering, even
                    # when record IDs are absent or differ in older archives.
                    "time_created_utc": summary["time_created_utc"],
                    "event_record_id": summary.get("event_record_id"),
                })
        return matches

    @staticmethod
    def _verify_core_identity(
        summary: Mapping[str, Any], payload: Mapping[str, Any]
    ) -> None:
        for field in ("id", "server_id", "domain_id", "log_source_id", "event_id"):
            if int(summary[field]) != int(payload[field]):
                raise ArchiveIntegrityError(
                    f"archive/core identity mismatch for {field} on event {payload.get('id')}"
                )
        summary_time = parse_utc_timestamp(summary["time_created_utc"])
        payload_time = parse_utc_timestamp(payload["time_created_utc"])
        if summary_time != payload_time:
            raise ArchiveIntegrityError(
                f"archive/core timestamp mismatch on event {payload.get('id')}"
            )

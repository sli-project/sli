"""Bounded on-demand context hydration for semantic correlation dispatch.

Context events never receive independent semantic jobs.  A leased correlation
dispatch may hydrate only exact source-pack identities in its own host/time
window, then persist their normalized facts in the same transaction.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from server.sli.semantic.semantic_dispatch import MAX_MATCH_EVENTS
from server.sli.semantic.semantic_processing import (
    NORMALIZER_ID,
    NORMALIZER_VERSION,
    SEMANTIC_CONTRACT_VERSION,
    normalize_semantic_source_payload,
)
from server.sli.semantic.semantic_processing_repository import (
    load_agent_semantic_source_event,
    persist_normalized_event,
    semantic_source_identity,
)
from server.sli.storage.storage_v2_archive import ArchiveReader
from server.sli.storage.storage_v2_runtime import StorageV2RuntimeReader
from server.source_packs.registry import (
    semantic_core_role_filters_for_identity,
    semantic_event_identities_for_types,
)

MAX_CONTEXT_ARCHIVE_BLOCKS = 8
MAX_CONTEXT_EVENTS_PER_IDENTITY = 256
_ALLOWED_CONTEXT_CORE_FIELDS = frozenset(
    {
        "subject_user_sid",
        "subject_user_name",
        "target_user_sid",
        "target_user_name",
        "logon_id",
        "ip_address",
    }
)
_CASEFOLD_CONTEXT_CORE_FIELDS = frozenset(
    {
        "subject_user_sid",
        "subject_user_name",
        "target_user_sid",
        "target_user_name",
        "logon_id",
    }
)


def hydrate_dispatch_context(
    cur: Any,
    *,
    archive: ArchiveReader,
    semantic_types: Sequence[str],
    join_roles: Sequence[str],
    trigger_roles: dict[str, str],
    partition_key: str,
    start_utc: datetime,
    end_utc: datetime,
) -> int:
    """Hydrate bounded nearest context evidence without scanning a whole window."""

    if start_utc.tzinfo is None or end_utc.tzinfo is None:
        raise ValueError("semantic context window must be timezone-aware")
    if end_utc < start_utc:
        raise ValueError("semantic context window is inverted")
    try:
        server_id = int(str(partition_key).strip())
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "semantic context partition must be an exact numeric source host"
        ) from exc
    if server_id <= 0:
        raise RuntimeError(
            "semantic context partition must be an exact numeric source host"
        )

    identities = tuple(
        identity
        for identity in semantic_event_identities_for_types(
            tuple(str(value) for value in semantic_types)
        )
        if identity.noise_class == "context"
    )
    if not identities:
        return 0

    prepared_identities: list[tuple[str, tuple[object, ...]]] = []
    for identity in identities:
        try:
            event_id = int(identity.event_key)
        except ValueError as exc:
            raise RuntimeError(
                "semantic context hydration requires a source-specific numeric "
                "Storage V2 event identity adapter"
            ) from exc
        role_filters = semantic_core_role_filters_for_identity(
            identity,
            join_roles=tuple(str(value) for value in join_roles),
            trigger_roles=trigger_roles,
        )
        if role_filters is None:
            continue
        clauses = [
            "core.event_id=%s",
            "lower(channel.value)=lower(%s)",
            "lower(coalesce(provider.value,''))=lower(%s)",
        ]
        params: list[object] = [
            event_id,
            identity.stream,
            identity.provider_name,
        ]
        for role_filter in role_filters:
            fields = {
                role_filter.primary_field,
                role_filter.fallback_field,
            } - {None}
            if not fields.issubset(_ALLOWED_CONTEXT_CORE_FIELDS):
                raise RuntimeError(
                    "source pack requested an unsupported semantic core role field"
                )
            if role_filter.fallback_field:
                expression = (
                    "case when nullif(btrim(core."
                    + role_filter.primary_field
                    + "), '') is not null then btrim(core."
                    + role_filter.primary_field
                    + ") else btrim(core."
                    + role_filter.fallback_field
                    + ") end"
                )
                if fields.issubset(_CASEFOLD_CONTEXT_CORE_FIELDS):
                    expression = f"lower({expression})"
                    clauses.append(expression + "=lower(%s)")
                else:
                    clauses.append(expression + "=%s")
            else:
                expression = f"btrim(core.{role_filter.primary_field})"
                if role_filter.primary_field in _CASEFOLD_CONTEXT_CORE_FIELDS:
                    clauses.append(f"lower({expression})=lower(%s)")
                else:
                    clauses.append(expression + "=%s")
            params.append(role_filter.value)
        prepared_identities.append((" and ".join(clauses), tuple(params)))
    if not prepared_identities:
        return 0

    anchor_utc = start_utc + (end_utc - start_utc) / 2
    summaries: list[dict[str, Any]] = []
    for identity_clause, identity_params in prepared_identities:
        cur.execute(
            """
            select core.id,core.server_id,core.domain_id,core.log_source_id,
                   core.event_id,core.time_created_utc,core.normalized_hash,
                   core.correlation_id,core.migrated_at,
                   core.noise_class as stored_noise_class,
                   core.noise_catalog_version as stored_noise_catalog_version,
                   provider.value as provider_name,
                   channel.value as channel,
                   computer.value as computer
            from events_v2_core core
            join storage_v2_channel channel on channel.id=core.channel_id
            left join storage_v2_provider provider on provider.id=core.provider_id
            left join storage_v2_computer computer on computer.id=core.computer_id
            left join normalized_events normalized
              on normalized.source_event_id=core.id
             and normalized.semantic_contract_version=%s
             and normalized.normalizer_id=%s
             and normalized.normalizer_version=%s
            where core.server_id=%s
              and core.time_created_utc between %s and %s
              and ("""
            + identity_clause
            + """)
              and normalized.source_event_id is null
            order by abs(extract(epoch from (core.time_created_utc-%s))),
                     core.time_created_utc,core.id
            limit %s
            """,
            (
                SEMANTIC_CONTRACT_VERSION,
                NORMALIZER_ID,
                NORMALIZER_VERSION,
                server_id,
                start_utc,
                end_utc,
            )
            + identity_params
            + (anchor_utc, MAX_CONTEXT_EVENTS_PER_IDENTITY),
        )
        summaries.extend(dict(row) for row in (cur.fetchall() or []))
    if len(summaries) > MAX_MATCH_EVENTS:
        raise RuntimeError("semantic on-demand context exceeds matcher bound")
    if not summaries:
        return 0

    summary_by_id = {int(row["id"]): row for row in summaries}
    if len(summary_by_id) != len(summaries):
        raise RuntimeError("semantic context core query returned duplicate identities")
    try:
        payloads = archive.read_events_many(
            summary_by_id,
            max_blocks=MAX_CONTEXT_ARCHIVE_BLOCKS,
        )
    except KeyError as exc:
        if not str(exc.args[0]).startswith("event archive is missing requested identities:"):
            raise
        payloads = {}
        for source_event_id, summary in summary_by_id.items():
            # A published block with a missing row is corrupt, not an inbox
            # fallback candidate. Keep the archive's integrity checks intact.
            if archive.manifest.find_published("event", source_event_id) is not None:
                continue
            payload = load_agent_semantic_source_event(
                cur, source_event_id=source_event_id,
                summary=semantic_source_identity(summary),
            )
            if payload is not None:
                payloads[source_event_id] = payload
        remaining = summary_by_id.keys() - payloads.keys()
        if remaining:
            payloads.update(archive.read_events_many(
                remaining, max_blocks=MAX_CONTEXT_ARCHIVE_BLOCKS,
            ))
    wanted_types = {str(value) for value in semantic_types}
    for source_event_id in sorted(summary_by_id):
        summary = summary_by_id[source_event_id]
        payload = dict(payloads[source_event_id])
        StorageV2RuntimeReader._verify_core_identity(summary, payload)
        payload.setdefault("provider_name", summary.get("provider_name"))
        payload.setdefault("channel", summary.get("channel"))
        payload.setdefault("computer", summary.get("computer"))
        payload["source_host_id"] = int(summary["server_id"])
        payload["source_ingested_at"] = summary["migrated_at"]
        payload["source_event_sha256"] = bytes(summary["normalized_hash"])
        normalized = normalize_semantic_source_payload(payload)
        if normalized.semantic_type not in wanted_types:
            raise RuntimeError(
                "semantic context descriptor and normalized type disagree "
                f"for event {source_event_id}"
            )
        persist_normalized_event(
            cur,
            event=normalized,
            source_identity=summary,
        )
    return len(summaries)

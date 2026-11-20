"""Split out of ``server.sli.semantic.semantic_risk_runtime_repository`` (plan 7.2b).

Module-level names of ``semantic_risk_runtime_repository`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.semantic.semantic_risk_runtime_repository as _src


def _source_channel_measurements(
    cur: _src.Any,
    *,
    source_kind: _src.ScenarioSourceKind,
    source_id: str,
    partition_key: str,
) -> list[dict[str, _src.Any]]:
    if source_kind is _src.ScenarioSourceKind.CANONICAL_ACTION:
        cur.execute(
            """
            select distinct
                   coalesce(computer.value,%s) as server_name,
                   channel.value as channel_name,
                   source.event_id,
                   provider.value as provider_name
            from canonical_action_evidence evidence
            join normalized_events normalized
              on normalized.normalized_event_id=evidence.normalized_event_id
            join events_v2_core source on source.id=normalized.source_event_id
            join storage_v2_channel channel on channel.id=source.channel_id
            left join storage_v2_computer computer on computer.id=source.computer_id
            left join storage_v2_provider provider on provider.id=source.provider_id
            where evidence.canonical_action_id=%s
            order by server_name,channel_name,source.event_id,provider_name
            limit 64
            """,
            (partition_key, source_id),
        )
        return [dict(item) for item in (cur.fetchall() or [])]
    if source_kind is _src.ScenarioSourceKind.CORRELATION_CANDIDATE:
        cur.execute(
            """
            select distinct
                   coalesce(computer.value,%s) as server_name,
                   channel.value as channel_name,
                   source.event_id,
                   provider.value as provider_name
            from semantic_correlation_candidate_evidence evidence
            join normalized_events normalized
              on normalized.normalized_event_id=evidence.normalized_event_id
            join events_v2_core source on source.id=normalized.source_event_id
            join storage_v2_channel channel on channel.id=source.channel_id
            left join storage_v2_computer computer on computer.id=source.computer_id
            left join storage_v2_provider provider on provider.id=source.provider_id
            where evidence.candidate_id=%s
            order by server_name,channel_name,source.event_id,provider_name
            limit 64
            """,
            (partition_key, source_id),
        )
        return [dict(item) for item in (cur.fetchall() or [])]
    if source_kind is _src.ScenarioSourceKind.CONTROL_HEALTH:
        return [
            {
                "server_name": partition_key,
                "channel_name": "Security",
                "event_id": None,
                "provider_name": None,
            }
        ]
    return []


def _capture_completeness_snapshot(
    cur: _src.Any,
    *,
    policy: _src.CompiledRiskPolicy,
    proposal: _src.ScenarioProposal,
    source_id: str,
    captured_at_utc: _src.datetime | None = None,
) -> _src.CompletenessSnapshot:
    """Capture values only; it never contacts a surveyed source."""

    captured = (captured_at_utc or _src.datetime.now(_src.timezone.utc)).astimezone(
        _src.timezone.utc
    )
    catalogue = _src.catalog_completeness({"entries": _src.all_event_catalog_entries()})
    measurements = _src._source_channel_measurements(
        cur,
        source_kind=policy.source_kind,
        source_id=source_id,
        partition_key=proposal.partition_key,
    )
    required = tuple(
        dict.fromkeys(
            f"{str(item['server_name']).strip()}|{str(item['channel_name']).strip()}"
            for item in measurements
            if str(item.get("server_name") or "").strip()
            and str(item.get("channel_name") or "").strip()
        )
    )
    available: list[str] = []
    ages: list[int] = []
    for channel_ref in required:
        server_name, channel_name = channel_ref.split("|", 1)
        cur.execute(
            """
            select last_successful_collection_utc,backfill_completed
            from collection_channel_state
            where lower(server_hostname)=lower(%s) and lower(channel)=lower(%s)
            limit 1
            """,
            (server_name, channel_name),
        )
        state = dict(cur.fetchone() or {})
        last_success = state.get("last_successful_collection_utc")
        if last_success is None:
            continue
        if last_success.tzinfo is None:
            last_success = last_success.replace(tzinfo=_src.timezone.utc)
        age = max(0, int((captured - last_success.astimezone(_src.timezone.utc)).total_seconds()))
        ages.append(age)
        if (
            age <= _src.COMPLETENESS_FRESHNESS_BUDGET_SECONDS
            and bool(state.get("backfill_completed"))
        ):
            available.append(channel_ref)

    descriptor_timeouts: list[int] = []
    descriptor_missing = False
    for item in measurements:
        event_id = item.get("event_id")
        if event_id is None:
            descriptor_missing = True
            continue
        descriptor = _src.lookup_event_catalog(
            int(event_id),
            str(item.get("channel_name") or ""),
            str(item.get("provider_name") or ""),
        )
        correlation = (descriptor or {}).get("correlation")
        timeout = (
            correlation.get("close_timeout_seconds")
            if isinstance(correlation, _src.Mapping)
            else None
        )
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            descriptor_missing = True
        else:
            descriptor_timeouts.append(timeout)
    descriptor_timeout = (
        max(descriptor_timeouts)
        if descriptor_timeouts and not descriptor_missing
        else None
    )
    allowed_lateness = policy.allowed_lateness_seconds
    close_deadline = (
        proposal.step.occurred_at_utc
        + _src.timedelta(seconds=descriptor_timeout + allowed_lateness)
        if descriptor_timeout is not None and allowed_lateness is not None
        else None
    )
    return _src.CompletenessSnapshot(
        captured_at_utc=captured,
        catalog_entry_count=int(catalogue["entry_count"]),
        catalog_fully_classified=int(catalogue["fully_classified"]),
        catalog_schema_v2_ready=int(catalogue["schema_v2_ready"]),
        freshness_max_age_seconds=max(ages) if len(ages) == len(required) and ages else None,
        freshness_budget_seconds=_src.COMPLETENESS_FRESHNESS_BUDGET_SECONDS,
        required_channels=required,
        available_channels=tuple(available),
        window_end_utc=proposal.step.occurred_at_utc,
        descriptor_close_timeout_seconds=descriptor_timeout,
        allowed_lateness_seconds=allowed_lateness,
        close_deadline_utc=close_deadline,
        window_closed=bool(close_deadline is not None and captured >= close_deadline),
    )

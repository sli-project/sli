"""Split out of ``server.sli.core.postgres_runtime_pipeline`` (plan 7.2b).

Module-level names of ``postgres_runtime_pipeline`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.core.postgres_runtime_pipeline as _src


def record_collector_channel_runs_pg(
    *,
    server: str,
    summary: dict[str, _src.Any],
    import_stats: dict[str, dict[str, int]],
    job_id: int | None = None,
    import_duration_ms: int | None = None,
    import_queue_wait_ms: int | None = None,
    import_retry_count: int | None = None,
    report_duration_ms: int | None = None,
    adaptive_state_mode: str = "update",
) -> None:
    """Persist collector history and optionally mutate adaptive state in PostgreSQL."""
    from server.sli.sources.collector_adaptive import (
        SECURITY_CHANNEL,
        adaptive_observation_action,
        compute_non_security_adaptive_transition,
        compute_security_adaptive_transition,
        log_security_adaptive_observation,
        log_security_adaptive_transition,
        normalize_adaptive_state_mode,
    )

    adaptive_state_mode = normalize_adaptive_state_mode(adaptive_state_mode)
    with _src.connect() as conn:
        with conn.cursor() as cur:
            for item in summary.get("channels") or []:
                channel = str(item.get("channel") or "")
                if not channel:
                    continue
                stats = import_stats.get(channel, {})
                inserted = int(stats.get("inserted") or 0)
                skipped = int(stats.get("skipped") or 0)
                status = str(item.get("status") or "unknown")
                count = int(item.get("count") or 0)
                partial_count = count if status == "partial_timeout" else int(item.get("partial_count") or 0)
                latest = _src._latest_event_for_channel_pg(cur, server, channel)
                latest_record_id = _src._safe_int(latest.get("event_record_id") if latest else None)
                if latest_record_id is None:
                    latest_record_id = _src._safe_int(item.get("latest_event_record_id") or item.get("latest_record_id"))
                lag_minutes = _src._lag_minutes(latest.get("time_created_utc") if latest else item.get("latest_event_time_utc"))
                timeout_seconds = _src._safe_int(item.get("timeout_seconds"))
                limit_used = _src._safe_int(item.get("max_events")) or _src._safe_int(item.get("limit")) or _src._safe_int(item.get("limit_used"))
                query_duration_ms = _src._duration_seconds_to_ms(item.get("duration_seconds")) or _src._duration_seconds_to_ms(item.get("query_duration_seconds")) or _src._safe_int(item.get("query_duration_ms"))
                total_duration_ms = (query_duration_ms or 0) + int(import_queue_wait_ms or 0) + int(import_duration_ms or 0) + int(report_duration_ms or 0)
                events_per_second = _src._events_per_second(count, query_duration_ms)
                previous = _src._previous_run_for_channel_pg(cur, server, channel)
                last_record_id_delta = None
                lag_delta_minutes = None
                if previous and latest_record_id is not None and previous.get("latest_event_record_id") is not None:
                    last_record_id_delta = int(latest_record_id) - int(previous["latest_event_record_id"])
                if previous and lag_minutes is not None and previous.get("lag_minutes") is not None:
                    lag_delta_minutes = int(lag_minutes) - int(previous["lag_minutes"])

                adaptive_action = None
                if channel == SECURITY_CHANNEL:
                    if adaptive_state_mode == "update":
                        cur.execute(
                            """
                            select server, channel, current_limit, consecutive_completed, recovery_mode,
                                   last_status, last_lag_minutes, last_action, updated_at
                            from collector_adaptive_state
                            where server = %s and channel = %s
                            """,
                            (server, SECURITY_CHANNEL),
                        )
                        state_row = cur.fetchone()
                        transition = compute_security_adaptive_transition(
                            state=dict(state_row) if state_row else None,
                            status=status,
                            inserted=inserted,
                            skipped=skipped,
                            lag_minutes=lag_minutes,
                            previous_limit=limit_used,
                            partial_kind=str(item.get("partial_kind") or "") or None,
                        )
                        cur.execute(
                            """
                            insert into collector_adaptive_state(
                                server, channel, current_limit, consecutive_completed, recovery_mode,
                                last_status, last_lag_minutes, last_action, updated_at
                            ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            on conflict(server, channel) do update set
                                current_limit = excluded.current_limit,
                                consecutive_completed = excluded.consecutive_completed,
                                recovery_mode = excluded.recovery_mode,
                                last_status = excluded.last_status,
                                last_lag_minutes = excluded.last_lag_minutes,
                                last_action = excluded.last_action,
                                updated_at = excluded.updated_at
                            """,
                            (
                                server,
                                SECURITY_CHANNEL,
                                transition["current_limit"],
                                transition["consecutive_completed"],
                                transition["recovery_mode"],
                                transition["last_status"],
                                transition["last_lag_minutes"],
                                transition["last_action"],
                                transition["updated_at"],
                            ),
                        )
                        adaptive_action = str(transition["last_action"])
                        log_security_adaptive_transition(server=server, transition=transition)
                    else:
                        adaptive_action = adaptive_observation_action(adaptive_state_mode)
                        log_security_adaptive_observation(
                            server=server,
                            status=status,
                            inserted=inserted,
                            skipped=skipped,
                            lag_minutes=lag_minutes,
                            limit_used=limit_used,
                            mode=adaptive_state_mode,
                        )
                elif adaptive_state_mode == "update":
                    cur.execute(
                        """
                        select server, channel, current_limit, consecutive_completed,
                               recovery_mode, last_status, last_lag_minutes,
                               last_action, updated_at
                        from collector_adaptive_state
                        where server = %s and channel = %s
                        """,
                        (server, channel),
                    )
                    state_row = cur.fetchone()
                    continuity = item.get("continuity")
                    transition = compute_non_security_adaptive_transition(
                        state=dict(state_row) if state_row else None,
                        status=status,
                        previous_limit=limit_used,
                        truncated=bool(
                            isinstance(continuity, dict)
                            and continuity.get("truncated") is True
                        ),
                        partial_kind=str(item.get("partial_kind") or "") or None,
                    )
                    cur.execute(
                        """
                        insert into collector_adaptive_state(
                            server, channel, current_limit, consecutive_completed,
                            recovery_mode, last_status, last_lag_minutes,
                            last_action, updated_at
                        ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        on conflict(server, channel) do update set
                            current_limit = excluded.current_limit,
                            consecutive_completed = excluded.consecutive_completed,
                            recovery_mode = excluded.recovery_mode,
                            last_status = excluded.last_status,
                            last_lag_minutes = excluded.last_lag_minutes,
                            last_action = excluded.last_action,
                            updated_at = excluded.updated_at
                        """,
                        (
                            server,
                            channel,
                            transition["current_limit"],
                            transition["consecutive_completed"],
                            transition["recovery_mode"],
                            transition["last_status"],
                            transition["last_lag_minutes"],
                            transition["last_action"],
                            transition["updated_at"],
                        ),
                    )
                    adaptive_action = str(transition["last_action"])

                cur.execute(
                    """
                    insert into collector_channel_runs(
                        job_id, server, channel, started_utc, finished_utc, status,
                        inserted, skipped, count, partial_count, latest_event_record_id,
                        lag_minutes, timeout_seconds, limit_used, adaptive_action, error,
                        query_duration_ms, import_duration_ms, import_queue_wait_ms, import_retry_count,
                        report_duration_ms, total_duration_ms, events_per_second,
                        last_record_id_delta, lag_delta_minutes,
                        collection_mode, requested_collection_mode, cursor_strategy, cursor_fallback_reason,
                        collector_backend, backend_reason, partial_kind, failure_stage,
                        cursor_commit_allowed
                    ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        job_id,
                        server,
                        channel,
                        item.get("started_at"),
                        item.get("finished_at") or summary.get("finished_at"),
                        status,
                        inserted,
                        skipped,
                        count,
                        partial_count,
                        latest_record_id,
                        lag_minutes,
                        timeout_seconds,
                        limit_used,
                        adaptive_action,
                        item.get("error"),
                        query_duration_ms,
                        import_duration_ms,
                        import_queue_wait_ms,
                        import_retry_count,
                        report_duration_ms,
                        total_duration_ms,
                        events_per_second,
                        last_record_id_delta,
                        lag_delta_minutes,
                        summary.get("collection_mode"),
                        summary.get("requested_collection_mode"),
                        item.get("cursor_strategy"),
                        item.get("cursor_fallback_reason"),
                        item.get("collector_backend") or summary.get("collector_backend"),
                        item.get("backend_reason") or summary.get("backend_reason"),
                        item.get("partial_kind"),
                        item.get("failure_stage"),
                        item.get("cursor_commit_allowed"),
                    ),
                )
    _src.log_event("postgres_runtime", "collector_channel_runs_recorded", "PostgreSQL collector channel history recorded.", server=server, adaptive_state_mode=adaptive_state_mode)


def record_collector_stage_metrics_pg(
    *,
    server: str,
    summary: dict[str, _src.Any],
    import_duration_ms: int | None = None,
    import_profile: dict[str, _src.Any] | None = None,
    job_id: int | None = None,
) -> None:
    records: list[tuple[_src.Any, ...]] = []
    backend = summary.get("collector_backend")
    for item in summary.get("channels") or []:
        channel = str(item.get("channel") or "")
        for metric in item.get("stage_metrics") or []:
            records.append((
                job_id,
                server,
                channel,
                metric.get("backend") or item.get("collector_backend") or backend,
                metric.get("stage"),
                metric.get("status") or "completed",
                _src._safe_int(metric.get("duration_ms")),
                _src._safe_int(metric.get("events_count")),
                _src._safe_int(metric.get("bytes_count")),
                metric.get("error"),
            ))
    if import_duration_ms is not None:
        records.append((
            job_id, server, "_all", backend, "import_postgres", "completed",
            int(import_duration_ms), None, None, None,
        ))
    profile_summary = import_profile.get("summary") if isinstance(import_profile, dict) else None
    if isinstance(profile_summary, dict):
        stage_ms = profile_summary.get("stage_ms")
        if isinstance(stage_ms, dict):
            for stage, duration in stage_ms.items():
                records.append((
                    job_id,
                    server,
                    "_all",
                    backend,
                    f"import_postgres_{stage}",
                    "completed",
                    _src._safe_int(duration),
                    _src._safe_int(profile_summary.get("rows")),
                    None,
                    None,
                ))
    if records:
        with _src.connect() as conn:
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    insert into collector_stage_metrics(
                        job_id, server, channel, backend, stage, status, duration_ms,
                        events_count, bytes_count, error
                    ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    records,
                )
    _src.log_event("postgres_runtime", "collector_stage_metrics_recorded", "PostgreSQL collector stage metrics recorded.", server=server)

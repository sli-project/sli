# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``postgres_runtime_pipeline`` at call time.
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from server.sli.core.app_config import load_config
from server.sli.ops.logging_config import log_event


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dsn() -> str:
    dsn = (load_config().postgres_dsn or "").strip()
    if not dsn:
        raise RuntimeError("ADLOG_PG_DSN / postgres_dsn is not configured")
    return dsn


def connection_policy() -> dict[str, int | str]:
    from server.sli.reporting.read_timeout import remaining_read_ms

    cfg = load_config()
    remaining = remaining_read_ms()
    return {
        "connect_timeout_seconds": min(max(1, int(cfg.postgres_connect_timeout_seconds)), max(1, (remaining + 999) // 1000)) if remaining is not None else max(1, int(cfg.postgres_connect_timeout_seconds)),
        "statement_timeout_ms": min(max(1000, int(cfg.postgres_statement_timeout_ms)), remaining) if remaining is not None else max(1000, int(cfg.postgres_statement_timeout_ms)),
        "lock_timeout_ms": max(100, int(cfg.postgres_lock_timeout_ms)),
        "application_name": "ad_log_reports_runtime",
    }


def connect():
    try:
        import psycopg
        from psycopg.rows import dict_row
    except Exception as exc:  # pragma: no cover - depends on runtime environment
        raise RuntimeError(f"psycopg is not available: {exc}") from exc
    policy = connection_policy()
    options = (
        f"-c statement_timeout={policy['statement_timeout_ms']} "
        f"-c lock_timeout={policy['lock_timeout_ms']}"
    )
    connection = psycopg.connect(
        _dsn(),
        row_factory=dict_row,
        connect_timeout=policy["connect_timeout_seconds"],
        application_name=policy["application_name"],
        options=options,
    )
    from server.sli.reporting.read_timeout import watch_read_connection

    try:
        watch_read_connection(connection)
    except Exception:
        connection.close()
        raise
    return connection


def get_runtime_pipeline_status() -> dict[str, Any]:
    try:
        conn = connect()
        with conn:
            with conn.cursor() as cur:
                cur.execute("select 1 as ok")
                cur.fetchone()
        return {"postgres_importer_available": True, "postgres_pipeline_status": "ready"}
    except Exception as exc:
        return {"postgres_importer_available": False, "postgres_pipeline_status": "failed", "error": str(exc)}


def parse_utc(value: str) -> datetime:
    normalized = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def get_archive_status_pg() -> dict[str, Any]:
    """Return archive/watermark state from PostgreSQL only.

    This is the PostgreSQL runtime counterpart of ``archive_state.get_archive_status``.
    It intentionally does not seed from SQLite and does not scan the large events
    table during status calls; status endpoints must stay fast and must not touch
    the old SQLite backend after cutover.
    """
    archive_start = _ensure_archive_start_pg()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select server_hostname, channel, last_successful_collection_utc,
                       last_event_time_utc, last_event_record_id, backfill_completed
                from collection_channel_state
                order by server_hostname, channel
                """
            )
            states = [dict(row) for row in cur.fetchall()]
    return {"archive_start_utc": archive_start, "channel_states": states, "backend": "postgres"}


def get_collection_plan_for_server_pg(
    server: str,
    channels: list[str] | None = None,
    *,
    overlap_minutes: int = 5,
) -> dict[str, dict[str, object]]:
    """Build archive/watermark collection plan from PostgreSQL state.

    Previous DB-0.12 scheduler tests mixed PostgreSQL import/update with SQLite
    watermark reads.  That made the runtime inconsistent and could make API/status
    paths touch the old 20GB SQLite DB during PostgreSQL runs.  This function keeps
    archive cursor reads on the active PostgreSQL backend.
    """
    archive_start = _ensure_archive_start_pg()
    archive_dt = parse_utc(archive_start)
    channels = channels or [
        "Security",
        "System",
        "Directory Service",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "DNS Server",
    ]
    plan: dict[str, dict[str, object]] = {}
    with connect() as conn:
        with conn.cursor() as cur:
            for channel in channels:
                start = archive_dt
                after_record_id = None
                cur.execute(
                    """
                    select last_event_time_utc, last_event_record_id,
                           last_successful_collection_utc, channel_generation_identity
                    from collection_channel_state
                    where server_hostname = %s and channel = %s
                    """,
                    (server, channel),
                )
                row = cur.fetchone()
                if row and row.get("last_event_record_id") is not None:
                    after_record_id = int(row["last_event_record_id"])
                if row and row.get("last_event_time_utc"):
                    start = parse_utc(str(row["last_event_time_utc"])) - timedelta(minutes=overlap_minutes)
                elif row and row.get("last_successful_collection_utc"):
                    start = parse_utc(str(row["last_successful_collection_utc"])) - timedelta(minutes=overlap_minutes)
                else:
                    latest = _latest_event_for_channel_pg(cur, server, channel)
                    if latest and latest.get("time_created_utc"):
                        start = parse_utc(str(latest["time_created_utc"])) - timedelta(minutes=overlap_minutes)
                        if latest.get("event_record_id") is not None:
                            after_record_id = int(latest["event_record_id"])
                if start < archive_dt:
                    start = archive_dt
                plan[channel] = {
                    "start_time_utc": format_utc(start),
                    "after_record_id": after_record_id,
                    "channel_generation_identity": (
                        str(row["channel_generation_identity"])
                        if row and row.get("channel_generation_identity")
                        else None
                    ),
                    "cursor_event_time_utc": (
                        str(row["last_event_time_utc"])
                        if row and row.get("last_event_time_utc")
                        else None
                    ),
                }
    return plan



def get_adaptive_plan_state_pg(
    server: str,
    *,
    channels: list[str],
    security_channel: str = "Security",
    fairness_enabled: bool = True,
    fairness_stale_minutes: int = 360,
) -> dict[str, Any]:
    """Read adaptive planning inputs exclusively from PostgreSQL."""
    fairness_channels: list[str] = []
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select last_event_time_utc
                from collection_channel_state
                where server_hostname = %s and channel = %s
                """,
                (server, security_channel),
            )
            security_state = cur.fetchone()
            security_marker = security_state.get("last_event_time_utc") if security_state else None
            if not security_marker:
                latest = _latest_event_for_channel_pg(cur, server, security_channel)
                security_marker = latest.get("time_created_utc") if latest else None
            security_lag_minutes = _lag_minutes(security_marker)
            cur.execute(
                """
                select server, channel, current_limit, consecutive_completed, recovery_mode,
                       last_status, last_lag_minutes, last_action, updated_at
                from collector_adaptive_state
                where server = %s and channel = %s
                """,
                (server, security_channel),
            )
            state_row = cur.fetchone()
            adaptive_state = dict(state_row) if state_row else None
            cur.execute(
                """
                select server, channel, current_limit, consecutive_completed,
                       recovery_mode, last_status, last_lag_minutes, last_action,
                       updated_at
                from collector_adaptive_state
                where server = %s
                """,
                (server,),
            )
            adaptive_states = {
                str(row["channel"]): dict(row) for row in cur.fetchall()
            }

            if fairness_enabled:
                now = datetime.now(timezone.utc)
                stale_minutes = max(1, int(fairness_stale_minutes))
                for channel in channels:
                    if channel == security_channel:
                        continue
                    cur.execute(
                        """
                        select last_successful_collection_utc, last_event_time_utc, updated_at
                        from collection_channel_state
                        where server_hostname = %s and channel = %s
                        """,
                        (server, channel),
                    )
                    row = cur.fetchone()
                    if not row:
                        continue
                    marker = row.get("last_successful_collection_utc") or row.get("updated_at") or row.get("last_event_time_utc")
                    if not marker:
                        fairness_channels.append(channel)
                        continue
                    try:
                        age_minutes = int((now - parse_utc(str(marker))).total_seconds() // 60)
                    except Exception:
                        fairness_channels.append(channel)
                        continue
                    if age_minutes >= stale_minutes:
                        fairness_channels.append(channel)

    return {
        "backend": "postgres",
        "security_lag_minutes": security_lag_minutes,
        "adaptive_state": adaptive_state,
        "adaptive_states": adaptive_states,
        "fairness_channels": fairness_channels,
    }

def ensure_cursor_audit_schema_pg() -> dict[str, object]:
    from server.sli.ops.postgres_schema_guard import require_table_columns

    return require_table_columns(
        "collector_cursor_audit",
        (
            "id", "job_id", "trace_id", "server", "channel",
            "collection_status", "import_inserted", "import_skipped",
            "old_record_id", "proposed_record_id", "new_record_id",
            "old_event_time_utc", "proposed_event_time_utc",
            "new_event_time_utc", "decision", "reason",
            "cursor_strategy", "cursor_fallback_reason", "created_at",
        ),
    )














def _channel_backfill_completed(item: Mapping[str, Any], *, require_query_exhaustion: bool) -> bool:
    if item.get("status") != "completed":
        return False
    if not require_query_exhaustion:
        return True
    continuity = item.get("continuity") or {}
    return (continuity.get("query_exhausted") is True
            and continuity.get("generation_stable_during_read") is True
            and continuity.get("truncated") is False)


def update_collection_state_from_summary_pg(
    *,
    server: str,
    collection_start_utc: str,
    summary: dict[str, Any],
    import_stats: dict[str, dict[str, int]] | None = None,
    job_id: int | None = None,
    trace_id: str | None = None,
    require_query_exhaustion: bool = False,
) -> None:
    """Commit PostgreSQL watermarks only after successful import and audit every decision."""
    archive_start = _ensure_archive_start_pg()
    finished_at = summary.get("finished_at") or utc_now()
    channels = summary.get("channels") or []
    stats_by_channel = import_stats or {}
    with connect() as conn:
        with conn.cursor() as cur:
            for item in channels:
                channel = str(item.get("channel") or "")
                if not channel:
                    continue
                status = str(item.get("status") or "unknown")
                count = int(item.get("count") or 0)
                stats = stats_by_channel.get(channel, {})
                inserted = int(stats.get("inserted") or 0)
                skipped = int(stats.get("skipped") or 0)
                cur.execute(
                    """
                    select last_event_record_id, last_event_time_utc,
                           channel_generation_identity
                    from collection_channel_state
                    where server_hostname = %s and channel = %s
                    """,
                    (server, channel),
                )
                old = dict(cur.fetchone() or {})
                old_record_id = _safe_int(old.get("last_event_record_id"))
                old_event_time = old.get("last_event_time_utc")
                old_generation_identity = old.get("channel_generation_identity")
                observed_generation_identity = item.get("channel_generation_identity")
                latest = _latest_event_for_channel_pg(cur, server, channel)
                published_record_id = _safe_int(latest.get("event_record_id") if latest else None)
                proposed_event_time = latest.get("time_created_utc") if latest else None

                # Batch-scoped cursor proof.
                #
                # `_latest_event_for_channel_pg` answers from the shared published
                # `events_v2_core` and orders by `time_created_utc desc` first,
                # so the row it returns is not guaranteed to hold the maximum
                # `event_record_id` — and it can include rows this run never read
                # (manual import, asynchronous V2 publication).  Committing that
                # value can move the cursor past events this run never imported.
                #
                # The collector already reports the maximum record id it actually
                # wrote for this channel.  Commit the minimum of the two: never
                # ahead of what this batch proved, never ahead of what is
                # published.
                batch_max_record_id = _safe_int(
                    item.get("batch_max_record_id")
                    or item.get("latest_available_record_id")
                    or item.get("latest_record_id")
                )
                filtered_boundary = filtered_continuity_boundary(item, stats)
                if filtered_boundary is not None:
                    proposed_record_id = filtered_boundary
                    cursor_bound = "filtered_query_exhausted_boundary"
                    # The boundary may be a non-matching channel record and thus
                    # intentionally absent from Storage V2. Keep the newest
                    # matching event time while advancing the record cursor by
                    # the durable selector-exhaustion proof.
                    proposed_event_time = (
                        proposed_event_time if proposed_event_time is not None
                        else old_event_time
                    )
                else:
                    proposed_record_id, cursor_bound = resolve_cursor_watermark(
                        batch_max_record_id=batch_max_record_id,
                        published_record_id=published_record_id,
                    )
                probed_channel_record_id = _safe_int(
                    item.get("channel_latest_record_id_before_read")
                )
                generation_fallback = item.get("cursor_fallback_reason") in {
                    "channel_generation_missing",
                    "channel_generation_changed",
                    "oldest_record_id_after_saved_cursor",
                }
                proven_epoch_reset = (
                    old_record_id is not None
                    and probed_channel_record_id is not None
                    and item.get("cursor_strategy") == "time_window_fallback"
                    and (
                        (
                            probed_channel_record_id < old_record_id
                            and item.get("cursor_fallback_reason")
                            == "latest_record_id_before_saved_cursor"
                        )
                        or (
                            generation_fallback
                            and observed_generation_identity
                            and observed_generation_identity != old_generation_identity
                        )
                    )
                )

                is_completed = status == "completed"
                backfill_completed = _channel_backfill_completed(
                    item, require_query_exhaustion=require_query_exhaustion,
                )
                is_partial_timeout = status == "partial_timeout" and count > 0
                # A partial FAILURE never advances the cursor: the tail of the
                # channel was not read, so the batch maximum is not a watermark.
                # The wire status stays `partial_timeout`; the collector reports
                # the distinction through `partial_kind` / `cursor_commit_allowed`.
                is_partial_failed = item.get("partial_kind") == "failure"
                collector_forbids_commit = item.get("cursor_commit_allowed") is False
                import_succeeded = inserted > 0 or skipped > 0 or count == 0
                eligible = (
                    (is_completed or is_partial_timeout)
                    and import_succeeded
                    and not is_partial_failed
                    and not collector_forbids_commit
                )
                decision = "not_committed"
                reason = "collection_status_not_eligible"
                new_record_id = old_record_id
                new_event_time = old_event_time

                if not eligible:
                    if is_partial_failed or collector_forbids_commit:
                        # Distinguish "broke mid-stream" from "nothing to confirm".
                        # Previously this arrived as partial_timeout and committed.
                        reason = "partial_failure_cursor_withheld"
                    elif is_completed or is_partial_timeout:
                        reason = "import_not_confirmed"
                elif proven_epoch_reset and is_completed:
                    # A Windows channel may be cleared/recreated and start a new
                    # EventRecordID epoch. This is not a generic rollback:
                    # the collector must have proved before the read that the
                    # channel maximum is below the saved cursor, switched to the
                    # bounded time-window query, completed that query, and
                    # confirmed the import. The audit row retains old/proposed/
                    # new ids and the exact fallback reason.
                    channel_collection_start = item.get("start_time_utc") or item.get("channel_start_time_utc") or collection_start_utc
                    reset_record_id = proposed_record_id
                    reset_event_time = proposed_event_time if reset_record_id is not None else None
                    cur.execute(
                        """
                        update collection_channel_state
                        set last_collection_start_utc = %s,
                            last_successful_collection_utc = %s,
                            last_event_time_utc = %s,
                            last_event_record_id = %s,
                            backfill_completed = %s,
                            updated_at = now()
                        where server_hostname = %s and channel = %s
                        """,
                        (
                            channel_collection_start,
                            finished_at,
                            reset_event_time,
                            reset_record_id,
                            backfill_completed,
                            server,
                            channel,
                        ),
                    )
                    new_record_id = reset_record_id
                    new_event_time = reset_event_time
                    decision = "committed"
                    reason = (
                        "completed_import_committed:cursor_epoch_reset"
                        if reset_record_id is not None
                        else "completed_zero_event_collection:cursor_epoch_reset"
                    )
                elif proposed_record_id is None:
                    # A completed zero-event read is still operational evidence.
                    # Persist it so Collector Health can distinguish "checked,
                    # nothing new" from a channel that was never collected.
                    channel_collection_start = item.get("start_time_utc") or item.get("channel_start_time_utc") or collection_start_utc
                    cur.execute(
                        """
                        insert into collection_channel_state(
                            server_hostname, channel, archive_start_utc,
                            last_collection_start_utc, last_successful_collection_utc,
                            last_event_time_utc, last_event_record_id,
                            backfill_completed, updated_at
                        ) values (%s, %s, %s, %s, %s, null, null, %s, now())
                        on conflict(server_hostname, channel) do update set
                            last_collection_start_utc = excluded.last_collection_start_utc,
                            last_successful_collection_utc = excluded.last_successful_collection_utc,
                            backfill_completed = excluded.backfill_completed,
                            updated_at = excluded.updated_at
                        """,
                        (server, channel, archive_start, channel_collection_start, finished_at, backfill_completed),
                    )
                    decision = "committed"
                    reason = "completed_zero_event_collection"
                elif old_record_id is not None and proposed_record_id < old_record_id:
                    # Reject the cursor rollback, but retain the independent fact
                    # that the remote channel was read successfully.  Otherwise a
                    # quiet channel looks uncollected forever even though every
                    # cycle reaches it and returns normally.
                    if is_completed:
                        channel_collection_start = item.get("start_time_utc") or item.get("channel_start_time_utc") or collection_start_utc
                        cur.execute(
                            """
                            update collection_channel_state
                            set last_collection_start_utc = %s,
                                last_successful_collection_utc = %s,
                                backfill_completed = %s,
                                updated_at = now()
                            where server_hostname = %s and channel = %s
                            """,
                            (channel_collection_start, finished_at, backfill_completed, server, channel),
                        )
                    decision = "rejected"
                    reason = "record_id_rollback_detected"
                else:
                    channel_collection_start = item.get("start_time_utc") or item.get("channel_start_time_utc") or collection_start_utc
                    last_successful_collection_utc = finished_at if is_completed else None
                    cur.execute(
                        """
                        insert into collection_channel_state(
                            server_hostname, channel, archive_start_utc,
                            last_collection_start_utc, last_successful_collection_utc,
                            last_event_time_utc, last_event_record_id,
                            backfill_completed, updated_at
                        )
                        values (%s, %s, %s, %s, %s, %s, %s, %s, now())
                        on conflict(server_hostname, channel) do update set
                            last_collection_start_utc = excluded.last_collection_start_utc,
                            last_successful_collection_utc = coalesce(excluded.last_successful_collection_utc, collection_channel_state.last_successful_collection_utc),
                            last_event_time_utc = case
                                when excluded.last_event_record_id is not null
                                     and (collection_channel_state.last_event_record_id is null
                                          or excluded.last_event_record_id > collection_channel_state.last_event_record_id)
                                then excluded.last_event_time_utc
                                else collection_channel_state.last_event_time_utc
                            end,
                            last_event_record_id = case
                                when excluded.last_event_record_id is not null
                                     and (collection_channel_state.last_event_record_id is null
                                          or excluded.last_event_record_id > collection_channel_state.last_event_record_id)
                                then excluded.last_event_record_id
                                else collection_channel_state.last_event_record_id
                            end,
                            backfill_completed = case
                                when %s then excluded.backfill_completed
                                when excluded.backfill_completed then true
                                else collection_channel_state.backfill_completed
                            end,
                            updated_at = excluded.updated_at
                        """,
                        (
                            server,
                            channel,
                            archive_start,
                            channel_collection_start,
                            last_successful_collection_utc,
                            proposed_event_time,
                            proposed_record_id,
                            backfill_completed,
                            require_query_exhaustion,
                        ),
                    )
                    cur.execute(
                        """
                        select last_event_record_id, last_event_time_utc
                        from collection_channel_state
                        where server_hostname = %s and channel = %s
                        """,
                        (server, channel),
                    )
                    committed = dict(cur.fetchone() or {})
                    new_record_id = _safe_int(committed.get("last_event_record_id"))
                    new_event_time = committed.get("last_event_time_utc")
                    if old_record_id == new_record_id:
                        decision = "no_change"
                        reason = "record_id_not_advanced"
                    else:
                        decision = "committed"
                        base_reason = "partial_import_committed" if is_partial_timeout else "completed_import_committed"
                        # Record which bound produced the committed watermark so the
                        # audit can prove the cursor never ran ahead of this batch.
                        # Folded into `reason` deliberately: no schema change needed.
                        reason = f"{base_reason}:{cursor_bound}"

                if (
                    decision in {"committed", "no_change"}
                    and observed_generation_identity
                ):
                    cur.execute(
                        """
                        update collection_channel_state
                        set channel_generation_identity = %s,
                            updated_at = now()
                        where server_hostname = %s and channel = %s
                        """,
                        (observed_generation_identity, server, channel),
                    )

                cur.execute(
                    """
                    insert into collector_cursor_audit(
                        job_id, trace_id, server, channel, collection_status,
                        import_inserted, import_skipped,
                        old_record_id, proposed_record_id, new_record_id,
                        old_event_time_utc, proposed_event_time_utc, new_event_time_utc,
                        decision, reason, cursor_strategy, cursor_fallback_reason
                    ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        job_id,
                        trace_id,
                        server,
                        channel,
                        status,
                        inserted,
                        skipped,
                        old_record_id,
                        proposed_record_id,
                        new_record_id,
                        old_event_time,
                        proposed_event_time,
                        new_event_time,
                        decision,
                        reason,
                        item.get("cursor_strategy"),
                        item.get("cursor_fallback_reason"),
                    ),
                )
    log_event(
        "postgres_runtime",
        "collection_state_updated",
        "PostgreSQL collection state and cursor audit updated from imported summary.",
        server=server,
        job_id=job_id,
        trace_id=trace_id,
    )


def get_cursor_audit_overview_pg(*, limit: int = 50) -> dict[str, Any]:
    clean_limit = max(1, min(int(limit or 50), 200))
    ensure_cursor_audit_schema_pg()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select distinct on (server, channel)
                       id, job_id, trace_id, server, channel, collection_status,
                       import_inserted, import_skipped, old_record_id,
                       proposed_record_id, new_record_id, old_event_time_utc,
                       proposed_event_time_utc, new_event_time_utc,
                       decision, reason, cursor_strategy, cursor_fallback_reason, created_at
                from collector_cursor_audit
                order by server, channel, id desc
                """
            )
            latest = [dict(row) for row in cur.fetchall()]
            cur.execute(
                """
                select id, job_id, trace_id, server, channel, collection_status,
                       import_inserted, import_skipped, old_record_id,
                       proposed_record_id, new_record_id, decision, reason,
                       cursor_strategy, cursor_fallback_reason, created_at
                from collector_cursor_audit
                order by id desc
                limit %s
                """,
                (clean_limit,),
            )
            recent = [dict(row) for row in cur.fetchall()]
    summary: dict[str, int] = {}
    for item in recent:
        decision = str(item.get("decision") or "unknown")
        summary[decision] = summary.get(decision, 0) + 1
    return {"backend": "postgres", "summary": summary, "latest": latest, "recent": recent, "generated_at_utc": utc_now()}


ARCHIVE_START_CANDIDATE_QUERY = """
    select min(value)::text as value from (
        select min(run_started_at) as value from collection_runs
        union all
        select min(time_created_utc) as value from events_v2_core
    ) q where value is not null
"""


def _ensure_archive_start_pg() -> str:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select value from archive_settings where key = 'archive_start_utc'")
            row = cur.fetchone()
            if row:
                return str(row["value"])
            cur.execute(ARCHIVE_START_CANDIDATE_QUERY)
            row = cur.fetchone()
            archive_start = str(row["value"] if row and row.get("value") else utc_now())
            cur.execute(
                """
                insert into archive_settings(key, value, created_at, updated_at)
                values ('archive_start_utc', %s, now(), now())
                on conflict(key) do update set value = archive_settings.value
                """,
                (archive_start,),
            )
            return archive_start


def resolve_cursor_watermark(
    *,
    batch_max_record_id: int | None,
    published_record_id: int | None,
) -> tuple[int | None, str]:
    """Bound the proposed cursor by what THIS batch actually proved.

    `published_record_id` comes from the shared `events_v2_core` read, which
    orders by `time_created_utc desc` first and therefore does not guarantee the
    maximum `event_record_id`; it can also include rows this run never imported
    (manual import, asynchronous V2 publication).  `batch_max_record_id` is the
    maximum record id the collector actually wrote for this channel.

    Returns (watermark, bound_label).  Pure function so the cursor contract is
    testable without PostgreSQL.
    """
    if batch_max_record_id is not None and published_record_id is not None:
        if batch_max_record_id <= published_record_id:
            return batch_max_record_id, "batch_scoped"
        # The batch claims more than what is published: publication lags.
        # Commit only what is actually readable.
        return published_record_id, "published_clamped"
    if batch_max_record_id is not None:
        return batch_max_record_id, "batch_only"
    return published_record_id, "published_only"


def filtered_continuity_boundary(
    channel_summary: Mapping[str, Any], import_stats: Mapping[str, Any],
) -> int | None:
    """Return a frozen filtered boundary only after durable declaration write.

    Unlike an emitted-event watermark, this record may identify a channel row
    that did not match the selector and therefore was intentionally not stored.
    The cursor may use it only when the importer confirms that the exact
    exhausted declaration was persisted in the same successful import.
    """
    continuity = channel_summary.get("continuity")
    if not isinstance(continuity, Mapping):
        return None
    selector = continuity.get("selector_event_ids")
    if (
        channel_summary.get("cursor_strategy") != "record_id"
        or continuity.get("status") != "complete"
        or continuity.get("query_exhausted") is not True
        or not isinstance(selector, list)
        or not selector
        or import_stats.get("source_capture_continuity_persisted") is not True
    ):
        return None
    boundary = _safe_int(channel_summary.get("channel_latest_record_id_before_read"))
    return boundary if boundary is not None and boundary > 0 else None


def _latest_event_for_channel_pg(cur, server: str, channel: str) -> dict[str, Any] | None:
    cur.execute(
        """
        select e.time_created_utc, e.event_record_id
        from events_v2_core e
        join servers s on s.id = e.server_id
        join storage_v2_channel channel_name on channel_name.id = e.channel_id
        where s.hostname = %s and channel_name.value = %s
        order by e.time_created_utc desc, e.event_record_id desc
        limit 1
        """,
        (server, channel),
    )
    return cur.fetchone()




def _previous_run_for_channel_pg(cur, server: str, channel: str) -> dict[str, Any] | None:
    cur.execute(
        """
        select latest_event_record_id, lag_minutes
        from collector_channel_runs
        where server = %s and channel = %s
        order by id desc
        limit 1
        """,
        (server, channel),
    )
    row = cur.fetchone()
    return dict(row) if row else None





def _lag_minutes(value: Any) -> int | None:
    if not value:
        return None
    try:
        dt = parse_utc(str(value))
    except Exception:
        return None
    return max(0, int((datetime.now(timezone.utc) - dt).total_seconds() // 60))

def _safe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _duration_seconds_to_ms(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(float(value) * 1000)
    except (TypeError, ValueError):
        return None


def _events_per_second(count: int, duration_ms: int | None) -> float | None:
    if not duration_ms or duration_ms <= 0:
        return None
    return round(float(count or 0) / (duration_ms / 1000.0), 3)


from server.sli.core.postgres_runtime_pipeline_metrics import (
    record_collector_channel_runs_pg,
    record_collector_stage_metrics_pg,
)
from server.sli.core.postgres_runtime_pipeline_raw_batch import (
    authorize_raw_batch_cleanup_pg,
    begin_raw_batch_lifecycle_pg,
    raw_batch_cursor_outcome,
    record_raw_batch_cleanup_outcome_pg,
    record_raw_batch_cursor_outcome_pg,
    record_raw_batch_import_outcome_pg,
)

"""Local, payload-free control-health observations from persisted collector state."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from server.sli.core.postgres_runtime_pipeline import connect


CONTROL_ID = "windows.security.collection"
MAX_SOURCES = 20


def _as_utc_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid_collection_timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def classify_collection_coverage(
    last_successful_collection_utc: datetime | None,
    *,
    observed_at_utc: datetime,
    attention_minutes: int = 30,
    unavailable_minutes: int = 120,
) -> tuple[str, str, int | None]:
    """Classify the local collection proof; event age is deliberately separate."""
    if observed_at_utc.tzinfo is None:
        raise ValueError("observed_at_utc_must_be_timezone_aware")
    if last_successful_collection_utc is None:
        return "unavailable", "no_successful_collection_observation", None
    last = last_successful_collection_utc
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    age_minutes = max(0, int((observed_at_utc - last).total_seconds() // 60))
    if age_minutes >= unavailable_minutes:
        return "unavailable", "successful_collection_older_than_unavailable_budget", age_minutes
    if age_minutes >= attention_minutes:
        return "partial", "successful_collection_older_than_attention_budget", age_minutes
    return "complete", "successful_collection_inside_attention_budget", age_minutes


def _key(payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).digest()


def record_current_security_control_health(
    *,
    execute: bool,
    max_sources: int = MAX_SOURCES,
    connection: Any | None = None,
    observed_at_utc: datetime | None = None,
) -> dict[str, Any]:
    """Preview or persist immutable observations without contacting any source."""
    if connection is None:
        with connect() as local_connection:
            return record_current_security_control_health(
                execute=execute,
                max_sources=max_sources,
                connection=local_connection,
                observed_at_utc=observed_at_utc,
            )
    clean_limit = max(1, min(int(max_sources), MAX_SOURCES))
    observed_at = observed_at_utc or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        raise ValueError("observed_at_utc_must_be_timezone_aware")
    observed_at = observed_at.astimezone(timezone.utc).replace(microsecond=0)
    conn = connection
    with conn.cursor() as cur:
        cur.execute(
            """
            select server_hostname,channel,last_successful_collection_utc,
                   last_event_time_utc,last_event_record_id,backfill_completed
            from collection_channel_state
            where lower(channel)=lower('Security')
            order by server_hostname
            limit %s
            """,
            (clean_limit,),
        )
        rows = [dict(row) for row in cur.fetchall()]
        items: list[dict[str, Any]] = []
        inserted = 0
        for row in rows:
            last_success = _as_utc_datetime(row.get("last_successful_collection_utc"))
            status, reason_code, age_minutes = classify_collection_coverage(
                last_success, observed_at_utc=observed_at,
            )
            partition = str(row["server_hostname"])
            reason = (
                f"{reason_code};collection_age_minutes={age_minutes if age_minutes is not None else 'unknown'};"
                f"last_event_time_utc={row.get('last_event_time_utc') or 'unknown'};"
                f"backfill_completed={bool(row.get('backfill_completed'))}"
            )
            source_timestamp = (
                last_success.isoformat() if last_success is not None else "never"
            )
            source_reference = (
                f"collection_channel_state:{partition}:Security:{source_timestamp}"
            )
            identity = {
                "control_id": CONTROL_ID,
                "partition_key": partition,
                "coverage_status": status,
                "observed_at_utc": observed_at,
                "source_reference": source_reference,
            }
            observation_key = _key(identity)
            observation_id = str(uuid5(NAMESPACE_URL, f"adlog:control-health:{observation_key.hex()}"))
            item = {
                "observation_id": observation_id,
                "control_id": CONTROL_ID,
                "partition_key": partition,
                "coverage_status": status,
                "reason": reason,
                "observed_at_utc": observed_at,
                "source_reference": source_reference,
            }
            if execute:
                cur.execute(
                    """
                    insert into semantic_control_health_observations(
                        observation_id,observation_key,control_id,partition_key,
                        coverage_status,reason,observed_at_utc,source_reference
                    ) values (%s,%s,%s,%s,%s,%s,%s,%s)
                    on conflict(observation_key) do nothing
                    """,
                    (
                        observation_id, observation_key, CONTROL_ID, partition,
                        status, reason, observed_at, source_reference,
                    ),
                )
                inserted += cur.rowcount
            items.append(item)
        if not execute:
            conn.rollback()
    return {
        "status": "ok", "mode": "execute" if execute else "preview",
        "source": "local_postgresql_collection_channel_state",
        "surveyed_servers_contacted": False,
        "payload_read": False,
        "items": items,
        "observations_considered": len(items),
        "observations_inserted": inserted,
        "max_sources": clean_limit,
    }

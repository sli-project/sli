"""Period reader of confirmed AD/GPO differences, with explicit coverage gaps."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.core import database, platform_settings
from server.sli.reporting.v2.definition import AccessRule, Column, View, result, source_state
from server.sli.sources.ad_snapshot_history_policy import SETTING_KEY
from server.sli.storage import ad_snapshot_change_history as history

LIMIT = 2000
CONFIRMATION_LIMIT = 50_000


def change_view(title: str, *, access: AccessRule | None = None) -> View:
    return View("table", "changes", title, source="changes",
                access=access,
                note="Изменения за выбранный период. Значения атрибутов представлены отпечатками; неполное покрытие отмечается явно.",
                columns=(
                    Column("observed_at", "Снимок", "datetime"),
                    Column("object_type", "Тип объекта", "code"),
                    Column("object_id", "Объект", "code"),
                    Column("related_object_id", "Связанный объект", "code"),
                    Column("kind", "Изменение", "state", labels={
                        "object_added": "Объект добавлен", "object_removed": "Объект удалён",
                        "attribute_changed": "Атрибут изменён", "membership_added": "Членство добавлено",
                        "membership_removed": "Членство удалено",
                    }),
                    Column("field", "Поле", "code"),
                    Column("before_sha256", "Прежний отпечаток", "code"),
                    Column("after_sha256", "Новый отпечаток", "code"),
                ))


def coverage_state(confirmations: list[dict], *, domains: list[int], families: tuple[str, ...],
                   start: datetime, end: datetime, cutoff: datetime) -> dict:
    reasons = set()
    if start < cutoff:
        reasons.add("outside_retention")
    starts = []
    ends = []
    for domain in domains:
        for family in families:
            rows = sorted((row for row in confirmations if int(row["domain_id"]) == domain
                           and row["family"] == family), key=lambda row: history._stamp(row["observed_at"]))
            if not rows:
                reasons.add("history_not_collected")
                continue
            starts.append(history._stamp(rows[0]["observed_at"]))
            ends.append(history._stamp(rows[-1]["observed_at"]))
            if starts[-1] > start:
                reasons.add("history_starts_later")
            if ends[-1] < end:
                reasons.add("history_ends_earlier")
            previous = None
            for row in rows:
                observed = history._stamp(row["observed_at"])
                if start <= observed < end and row["coverage_state"] != "complete":
                    reasons.add("partial_snapshot_pair")
                if previous is not None and observed >= start and observed <= end:
                    if str(row["previous_manifest_id"]) != str(previous["manifest_id"]):
                        reasons.add("history_gap")
                    if observed - history._stamp(previous["observed_at"]) > timedelta(hours=12):
                        reasons.add("snapshot_schedule_gap")
                previous = row
    state = "not_collected" if not starts else "partial" if reasons else "complete"
    return {"state": state, "reasons": sorted(reasons),
            "history_from_utc": max(starts).isoformat() if starts else None,
            "history_to_utc": min(ends).isoformat() if ends else None,
            "retained_from_utc": cutoff.isoformat()}


def read_changes(*, domain_ids: list[int] | None, families: tuple[str, ...], period: dict,
                 query: str = "", now: datetime | None = None) -> dict[str, Any]:
    now = history._stamp(now or datetime.now(timezone.utc))
    start, end = history._stamp(period["from_utc"]), history._stamp(period["to_utc"])
    if start >= end or end - start > timedelta(days=3650):
        raise ValueError("report_period_invalid")
    if not families or not set(families).issubset(history.FAMILIES):
        raise ValueError("snapshot_history_family_invalid")
    days = int(platform_settings.get_setting(SETTING_KEY))
    cutoff = now - timedelta(days=days)
    empty = {"state": "unavailable", "items": [], "coverage": {"state": "unavailable"}, "truncated": False}
    if domain_ids == []:
        return empty
    port = history.ch.configured_read_port()
    if port is None:
        return empty
    try:
        domains = sorted(set(domain_ids)) if domain_ids is not None else [int(row["domain_id"]) for row in database.query_rows(
            "select distinct domain_id from public.ad_snapshot_history_confirmations")]
        if not domains:
            return {**empty, "state": "not_collected",
                    "coverage": {"state": "not_collected", "reasons": ["history_not_collected"]}}
        confirmations = database.query_rows_bounded(
            """select manifest_id,previous_manifest_id,domain_id,family,batch_id,record_count,
                      records_sha256,observed_at,coverage_state
                 from public.ad_snapshot_history_confirmations
                where domain_id=any(?) and family=any(?) and observed_at>=? and observed_at<=?
                order by observed_at,manifest_id,family limit ?""",
            (domains, list(families), max(start, cutoff) - timedelta(hours=12), end + timedelta(hours=12), CONFIRMATION_LIMIT + 1),
            statement_timeout_ms=5000,
        )
        if len(confirmations) > CONFIRMATION_LIMIT:
            return {**empty, "coverage": {"state": "unavailable", "reason": "confirmation_limit"}}
        # Even a confirmed zero-change period requires the mandatory history
        # component to be reachable. PostgreSQL metadata is not a fallback.
        history.ch._rows(port, f"SELECT batch_id FROM {history.TABLE} LIMIT 0")
        coverage = coverage_state(confirmations, domains=domains, families=families, start=start, end=end, cutoff=cutoff)
        coverage["history_days"] = days
        eligible = [row for row in confirmations if max(start, cutoff) <= history._stamp(row["observed_at"]) < end]
        count = sum(int(row["record_count"]) for row in eligible)
        # Read each batch separately so its exact count/digest is verified before
        # any rows become report evidence. The output bound never hides a gap.
        rows = []
        needle = query.strip().casefold()
        scanned = 0
        truncated = False
        for confirmation in reversed(eligible):
            if not int(confirmation["record_count"]):
                continue
            batch_id = str(confirmation["batch_id"])
            if len(batch_id) != 64 or any(char not in "0123456789abcdef" for char in batch_id):
                raise ValueError("snapshot_history_batch_identity_invalid")
            batch = history.ch._rows(port, f"SELECT record_id,payload_json FROM {history.TABLE} FINAL "
                                    "WHERE batch_id={batch:String} AND domain_id={domain:UInt64} "
                                    "AND family={family:String} AND observed_at={observed:DateTime64(6)} ORDER BY record_id",
                                    query_params={"batch": batch_id, "domain": str(confirmation["domain_id"]),
                                                  "family": confirmation["family"],
                                                  "observed": history.ch._ch_time(history._stamp(confirmation["observed_at"]))})
            pairs = [(row["record_id"], row["payload_json"]) for row in batch]
            if len(batch) != int(confirmation["record_count"]) or history._hash(pairs) != confirmation["records_sha256"]:
                raise RuntimeError("snapshot_history_report_readback_mismatch")
            for row in batch:
                payload = json.loads(row["payload_json"])
                if history._hash([batch_id, payload]) != row["record_id"]:
                    raise RuntimeError("snapshot_history_record_hash_mismatch")
                if not needle or needle in row["payload_json"].casefold():
                    rows.append({**payload, "id": row["record_id"], "domain_id": confirmation["domain_id"],
                                 "manifest_id": str(confirmation["manifest_id"]),
                                 "previous_manifest_id": str(confirmation["previous_manifest_id"]),
                                 "observed_at": history._stamp(confirmation["observed_at"]).isoformat()})
            scanned += len(batch)
            if len(rows) > LIMIT or scanned >= 50_000:
                truncated = len(rows) > LIMIT or scanned < count
                break
        if truncated:
            coverage["state"] = "partial"
            coverage["reasons"] = sorted(set(coverage["reasons"]) | {"history_truncated"})
        state = coverage["state"] if coverage["state"] in {"partial", "not_collected"} else "ok" if rows else "empty"
        return {"state": state, "items": rows[:LIMIT], "coverage": coverage, "truncated": truncated}
    except Exception:
        # Database/ClickHouse failures must not become an empty or complete period.
        return empty


def query_history(report, context, families: tuple[str, ...]) -> dict[str, Any]:
    raw = read_changes(domain_ids=context.domain_ids, families=families,
                       period=context.params["period"], query=str(context.params.get("q") or ""))
    limitations = []
    if raw["state"] == "unavailable":
        limitations.append({"code": "history_unavailable", "text": "Подтверждённая история изменений недоступна."})
    elif raw["state"] == "not_collected":
        limitations.append({"code": "history_not_collected", "text": "Подтверждённая история изменений за выбранный период ещё не собрана."})
    elif raw["state"] == "partial":
        limitations.append({"code": "history_partial", "text": "История покрывает выбранный период не полностью. Пустой список не доказывает отсутствие изменений."})
    if "history_starts_later" in raw["coverage"].get("reasons", []):
        limitations.append({"code": "history_starts_later", "text": "Сбор подтверждённой истории начался позже начала выбранного периода."})
    return result(report, state=source_state(raw["state"]), collections={"changes": raw["items"]},
                  coverage=raw["coverage"], filtered_count=len(raw["items"]), limitations=limitations,
                  window={"from_utc": context.params["period"]["from_utc"],
                          "to_utc_exclusive": context.params["period"]["to_utc"]})

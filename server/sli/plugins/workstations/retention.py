"""Finite retention handler; delete only after durable exact history readback."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from functools import partial

from server.sli.plugins.workstations.contracts import HistoryAdapter
from server.sli.plugins.workstations.importer import digest
from server.sli.plugins.workstations.settings import DEFAULT_DAYS, retention_days
from server.sli.storage.purge_audit import PurgeRun, failure_reason

SETTING_KEY = "workstations.evidence_retention_days"
HANDLER_ID = "workstations.evidence-retention"
MAX_BATCH = 50


def retain_batch(conn, *, history=None, now: datetime, limit: int = MAX_BATCH, exact_ids=None,
                 expected_days=None):
    audit = PurgeRun("workstations")
    try:
        result = _retain_batch(conn, history=history, now=now, limit=limit,
                               tables=audit.payload["tables"], exact_ids=exact_ids, expected_days=expected_days)
    except Exception as error:
        # The core executor owns rollback and lease fencing.
        audit.finish({"status": "blocked", "reason": failure_reason(error),
                      "transaction": "caller_rollback_required"})
        raise
    audit.finish({**result, "transaction": "caller_owned_unconfirmed"})
    return result


def _retain_batch(conn, *, history, now: datetime, limit: int, tables: dict, exact_ids=None,
                  expected_days=None):
    if now.utcoffset() is None or type(limit) is not int or not 1 <= limit <= MAX_BATCH:
        raise ValueError("workstation_retention_budget_invalid")
    if history is None:
        return {"status": "blocked", "reason": "history_adapter_unavailable", "moved": 0}
    if exact_ids is not None and (not exact_ids or len(exact_ids) > limit
            or len(set(exact_ids)) != len(exact_ids)
            or any(not isinstance(key, str) or len(key) != 64
                   or any(ch not in "0123456789abcdef" for ch in key) for key in exact_ids)):
        raise ValueError("workstation_retention_budget_invalid")
    moved = 0
    logical_bytes = 0
    with conn.cursor() as cur:
        cur.execute("set local statement_timeout = '5000ms'")
        cur.execute("set local lock_timeout = '1000ms'")
        # Destructive work must not treat a settings read failure as an unset
        # value. Read using this same transaction; DB errors abort the handler.
        cur.execute("select value from public.platform_settings where key=%s", (SETTING_KEY,))
        setting = cur.fetchone()
        days = retention_days(setting["value"] if setting else
                              os.environ.get("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS") or DEFAULT_DAYS)
        if expected_days is not None and int(days) != expected_days:
            raise RuntimeError("workstation_retention_plan_changed")
        cutoff = now - timedelta(days=int(days))
        exact = " and observation.id=any(%s)" if exact_ids is not None else ""
        params = (cutoff,) + ((list(exact_ids),) if exact_ids is not None else ()) + (limit,)
        cur.execute(f"""
            select observation.*,pg_column_size(observation) as purge_row_bytes
            from sli_plugin_workstations.observations observation
            where family in ('processes','usb') and observed_at<%s
              {exact}
              and not exists (select 1 from sli_plugin_workstations.observation_holds h
                              where h.observation_id=observation.id)
            order by observed_at,id for update skip locked limit %s
        """, params)
        rows = [dict(row) for row in cur.fetchall()]
        tables["sli_plugin_workstations.observations"]["selected_count"] = len(rows)
        if exact_ids is not None and len(rows) != len(exact_ids):
            raise RuntimeError("workstation_retention_plan_changed")
        for row in rows:
            row_bytes = int(row.pop("purge_row_bytes"))
            if digest(row["observation"]) != row["observation_sha256"]:
                raise ValueError("workstation_observation_hash_mismatch")
            if hashlib.sha256(row["source_xml"].encode()).hexdigest() != row["observation"]["source_sha256"]:
                raise ValueError("workstation_source_hash_mismatch")
            # Canonical transport matches history's immutable receipt. A retry
            # after PG rollback may repeat preserve, which must be idempotent.
            transport = json.loads(json.dumps(row, default=lambda value: value.astimezone(timezone.utc).isoformat()))
            expected = digest(transport)
            if history.preserve(transport) != expected:
                raise ValueError("workstation_history_receipt_mismatch")
            cur.execute("delete from sli_plugin_workstations.observations where id=%s and observation_sha256=%s",
                        (row["id"], row["observation_sha256"]))
            if cur.rowcount != 1:
                raise ValueError("workstation_delete_count_mismatch")
            cur.execute("/* workstation_delete_readback */ select id from sli_plugin_workstations.observations where id=%s",
                        (row["id"],))
            if cur.fetchone() is not None:
                raise ValueError("workstation_delete_readback_mismatch")
            moved += 1
            logical_bytes += row_bytes
    # Commit and lease fencing belong to the core executor, never the plugin.
    return {"status": "partial" if len(rows) == limit else "success", "moved": moved,
            "retention_days": int(days), "cutoff_utc": cutoff.isoformat(),
            "tables": {"sli_plugin_workstations.observations": {
                "selected_count": len(rows), "deleted_count": moved,
                "logical_bytes_deleted": logical_bytes, "partitions": [],
            }}, "logical_bytes_deleted": logical_bytes, "bytes_reclaimed": 0,
            "physical_reclaim_performed": False,
            "continuation": {"before_utc": cutoff.isoformat()} if len(rows) == limit else None}


def register_jobs(queue, *, history: HistoryAdapter | None = None, core: bool = False):
    if core:
        from server.sli.plugins.workstations.jobs import apply, stage

        queue.jobs[HANDLER_ID] = (stage, partial(apply, history=history))
        return
    from server.sli.core.paths import CONFIG_DIR
    manifest = json.loads((CONFIG_DIR / "plugin_packages/v3/sli.workstations.json").read_text(encoding="utf-8"))
    # The admitting host supplies the verified history dependency explicitly.
    # Registration performs no I/O; an unbound handler still fails closed.
    queue.register(manifest=manifest, handlers={HANDLER_ID: partial(retain_batch, history=history)})

"""Durable, bounded projection work; the caller owns the publication transaction.

Queue IDs order pending work only. They are never an import watermark: a lower
ID can commit later and must still be selected on the next invocation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

MAX_BATCH = 100
PROJECTOR = "workstations.overview"


@dataclass(frozen=True)
class Projector:
    key: str
    version: int
    apply: Callable


def projectors() -> tuple[Projector, ...]:
    from server.sli.plugins.workstations import devices, local_admin, logon_policy, password_failures, process_paths, protection, service_tasks

    return (
        Projector(local_admin.PROJECTOR, local_admin.RULE_VERSION, local_admin.apply),
        Projector(service_tasks.PROJECTOR, service_tasks.RULE_VERSION, service_tasks.apply),
        Projector(devices.PROJECTOR, devices.RULE_VERSION, devices.apply),
        Projector("workstations.protection", 1, protection.apply),
        Projector("workstations.last-interactive-login", 1, logon_policy.apply_last_login),
        Projector(logon_policy.PROJECTOR, logon_policy.RULE_VERSION, logon_policy.apply),
        Projector(password_failures.PROJECTOR, password_failures.RULE_VERSION, password_failures.apply),
        Projector(process_paths.PROJECTOR, process_paths.RULE_VERSION, process_paths.apply),
    )


def batch_limit(limit: int) -> int:
    if type(limit) is not int or not 1 <= limit <= MAX_BATCH:
        raise ValueError("workstation_projection_batch_invalid")
    return limit


STATION_JOIN = """join sli_plugin_workstations.station_inventory s
    on (q.kind='station_inventory' and s.station_id=q.station_id)
        or (q.kind<>'station_inventory' and s.agent_key=q.agent_key)"""


def validate_evaluators(evaluators):
    identities = [(item.key, item.version) for item in evaluators]
    if (len(set(identities)) != len(identities)
            or any(type(key) is not str or not key or len(key) > 128 or type(version) is not int or version < 1
                   for key, version in identities)):
        raise ValueError("workstation_projection_evaluator_invalid")
    return ([key for key, _ in identities], [version for _, version in identities])


def pending(cur, *, evaluators: tuple[Projector, ...], limit: int = MAX_BATCH) -> list[int]:
    keys, versions = validate_evaluators(evaluators)
    cur.execute(f"""select distinct q.work_id from sli_plugin_workstations.projection_work q
        join sli_plugin_workstations.projection_receipts r using(work_id) {STATION_JOIN}
        where r.applied_at is null and (r.projector_key,r.projection_version)
            in (select * from unnest(%s::text[],%s::integer[]))
        order by q.work_id limit %s""", (keys, versions, batch_limit(limit)))
    return [row["work_id"] for row in cur.fetchall()]


def run_batch(conn, *, evaluators: tuple[Projector, ...], work_ids: list[int] | None = None,
              limit: int = MAX_BATCH) -> dict:
    """Apply each immutable input once, atomically with its receipt/checkpoint.

    Evaluators write through this same connection and must not commit or perform
    external I/O. The core publisher fences the enclosing transaction. A crash
    rolls back findings, receipts and completion together; no lease repair or
    in-memory continuation is required.
    """
    limit = batch_limit(limit)
    if not evaluators:
        return {"status": "blocked", "processed": 0}
    keys, versions = validate_evaluators(evaluators)
    handlers = {(item.key, item.version): item.apply for item in evaluators}
    if work_ids is not None and (len(work_ids) > limit
            or any(type(value) is not int or value < 1 for value in work_ids)
            or len(set(work_ids)) != len(work_ids)):
        raise ValueError("workstation_projection_input_invalid")
    processed = 0
    with conn.cursor() as cur:
        # Serializes publication across schedule retries and overlapping batches,
        # including two inputs for the same station. No long-lived lease to lose.
        cur.execute("select pg_try_advisory_xact_lock(hashtext(%s)) as acquired", (PROJECTOR,))
        if not cur.fetchone()["acquired"]:
            return {"status": "partial", "processed": 0}
        exact = " and q.work_id=any(%s)" if work_ids is not None else ""
        params = (keys, versions) + ((work_ids,) if work_ids is not None else ()) + (limit,)
        # Select only small metadata first; large facts are read one at a time.
        cur.execute(f"""select q.work_id,s.station_id,r.projector_key,r.projection_version,r.payload_sha256
            from sli_plugin_workstations.projection_work q
            join sli_plugin_workstations.projection_receipts r using(work_id) {STATION_JOIN}
            where r.applied_at is null and (r.projector_key,r.projection_version)
                in (select * from unnest(%s::text[],%s::integer[])) {exact}
            order by q.work_id,r.projector_key,r.projection_version
            limit %s for update of r skip locked""", params)
        rows = list(cur.fetchall())
        for row in rows:
            work_id, station_id = row["work_id"], row["station_id"]
            cur.execute("""select kind,source_id,payload,payload_sha256,
                    encode(sha256(convert_to(payload::text,'UTF8')),'hex') as actual_sha256
                from sli_plugin_workstations.projection_work where work_id=%s""", (work_id,))
            fact = dict(cur.fetchone())
            if fact.pop("actual_sha256") != fact["payload_sha256"] or row["payload_sha256"] != fact["payload_sha256"]:
                raise ValueError("workstation_projection_input_conflict")
            key, version = row["projector_key"], row["projection_version"]
            handlers[key, version](conn, station_id, fact)
            cur.execute("""update sli_plugin_workstations.projection_receipts set applied_at=now()
                where work_id=%s and projector_key=%s and projection_version=%s and applied_at is null""",
                (work_id, key, version))
            cur.execute("""insert into sli_plugin_workstations.projection_checkpoints
                (projector_key,partition_key,projection_version,committed_position)
                values(%s,%s,%s,jsonb_build_object('processed_count',1))
                on conflict(projector_key,partition_key) do update set
                    projection_version=excluded.projection_version,
                    committed_position=jsonb_build_object('processed_count',
                        (projection_checkpoints.committed_position->>'processed_count')::bigint+1),
                    revision=projection_checkpoints.revision+1,updated_at=now()""",
                (key, station_id, version))
            processed += 1
    return {"status": "partial" if len(rows) == limit else "success", "processed": processed}


def prepare_consumers(conn, *, evaluators: tuple[Projector, ...], limit: int = MAX_BATCH) -> dict:
    """Register versioned consumers and seed one bounded receipt page.

    New checks/versions have independent receipts, so deploying C02 after C01
    cannot lose facts that C01 has already processed.
    """
    limit = batch_limit(limit)
    validate_evaluators(evaluators)
    with conn.cursor() as cur:
        for item in evaluators:
            cur.execute("select sli_plugin_workstations.register_projection_consumer(%s,%s)", (item.key, item.version))
        cur.execute("""select projector_key,projection_version,backfill_position
            from sli_plugin_workstations.projection_consumers where not backfill_complete
            order by projector_key,projection_version limit 1 for update skip locked""")
        consumer = cur.fetchone()
        if not consumer:
            return {"status": "success", "enqueued": 0}
        cur.execute("""select work_id,payload_sha256 from sli_plugin_workstations.projection_work
            where work_id>%s order by work_id limit %s""", (consumer["backfill_position"], limit))
        rows = list(cur.fetchall())
        for row in rows:
            cur.execute("""insert into sli_plugin_workstations.projection_receipts
                (work_id,projector_key,projection_version,payload_sha256) values(%s,%s,%s,%s)
                on conflict do nothing""", (row["work_id"], consumer["projector_key"],
                                           consumer["projection_version"], row["payload_sha256"]))
        cur.execute("""update sli_plugin_workstations.projection_consumers
            set backfill_position=%s,backfill_complete=%s where projector_key=%s and projection_version=%s""",
            (rows[-1]["work_id"] if rows else consumer["backfill_position"], len(rows) < limit,
             consumer["projector_key"], consumer["projection_version"]))
        return {"status": "partial", "enqueued": len(rows)}


def backfill_batch(conn, *, limit: int = MAX_BATCH) -> dict:
    """Seed old sources in bounded pages; triggers cover concurrent late inserts.

    The key cursor is safe ONLY for this initial enumeration, after all source
    triggers have been installed. The live worker always scans pending work.
    """
    limit = batch_limit(limit)
    sources = (("observations", "id"), ("protection_state", "agent_key"), ("station_inventory", "station_id"))
    with conn.cursor() as cur:
        cur.execute("select pg_try_advisory_xact_lock(hashtext(%s)) as acquired", ("workstations.backfill",))
        if not cur.fetchone()["acquired"]:
            return {"status": "partial", "enqueued": 0}
        for table, key in sources:
            cur.execute("""select committed_position from sli_plugin_workstations.projection_checkpoints
                where projector_key='workstations.backfill' and partition_key=%s""", (table,))
            checkpoint = cur.fetchone()
            position = checkpoint["committed_position"] if checkpoint else {}
            if position.get("complete"):
                continue
            cur.execute(f"""select {key} as source_key
                from sli_plugin_workstations.{table} s where {key}>%s order by {key} limit %s""",
                (position.get("last_key", ""), limit))
            rows = list(cur.fetchall())
            for row in rows:
                cur.execute("select sli_plugin_workstations.backfill_projection_input(%s,%s)",
                            (table, row["source_key"]))
            last = rows[-1]["source_key"] if rows else position.get("last_key", "")
            cur.execute("""insert into sli_plugin_workstations.projection_checkpoints
                (projector_key,partition_key,projection_version,committed_position)
                values('workstations.backfill',%s,1,jsonb_build_object('last_key',%s::text,'complete',%s))
                on conflict(projector_key,partition_key) do update set
                    committed_position=excluded.committed_position,
                    revision=projection_checkpoints.revision+1,updated_at=now()""",
                (table, last, len(rows) < limit))
            return {"status": "partial", "enqueued": len(rows)}
    return {"status": "success", "enqueued": 0}

"""RU: адресная сверка карантина. EN: targeted, dry-run-first quarantine replay."""
from __future__ import annotations

import argparse
import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from uuid import UUID

from server.sli.sources.collection_packet_import import event_rows_from_packet
from server.sli.storage.event_source_identity import (
    REASONS,
    RepresentationConflict,
    event_identity_hash,
)
from server.sli.storage.storage_v2_repository import (
    PostgresStorageV2Repository,
    SourceEventIdentityConflict,
)

MODULE = "sli.windows.ad-dc"


def dispatch_packet(*args, **kwargs):
    # Read-only comparison and --help need no publication/crypto dependency.
    from server.sli.agents.consumer import dispatch_packet as dispatch

    return dispatch(*args, **kwargs)


@contextmanager
def readonly_connection(factory):
    with factory() as conn:
        conn.execute("set transaction read only")
        yield conn


def check_packet(conn, row, repository):
    rows = event_rows_from_packet(row["packet"])
    if rows != row["event_rows"]:
        raise RepresentationConflict("event_representation_invalid")
    envelope, header = row["envelope"], row["packet"]["header"]
    with conn.cursor() as cur:
        cur.execute("""select s.id as server_id,b.source_name,c.id as channel_id
            from sli_agent_module_bindings b join servers s on s.hostname=b.source_name
                and s.role='domain_controller' and s.is_active
            left join storage_v2_channel c on c.value=%s
            where b.agent_id=%s and b.module_id=%s""",
            (header["channel"], envelope["agent_id"], MODULE))
        sources = cur.fetchall()
    if len(sources) != 1 or sources[0]["source_name"] != header["source"]:
        raise RepresentationConflict("agent_source_not_configured")
    source = sources[0]
    reservations = []
    for event in rows:
        fingerprint = event_identity_hash(event)
        if source["channel_id"] is None:
            # No channel identity exists, hence there can be no retained key.
            from server.sli.storage.event_source_identity import (
                preferred_representation,
            )
            preferred_representation(event, event)
            continue
        reservations.append({"server_id": source["server_id"], "channel_id": source["channel_id"],
            "event_record_id": event["record_id"], "time_created_utc": event["time_created"],
            "normalized_hash": fingerprint, "source_row": event})
    repository.reserve_event_identities(reservations, read_only=True)


def reprocess(*, connect, storage_connect, agent_id, channel="Security", packet_ids=(),
              received_from=None, received_until=None, limit=1000, apply=False):
    """One bounded snapshot, no polling; payloads and exception text never leave DB."""
    agent_id = str(UUID(str(agent_id)))
    packet_ids = [str(UUID(str(value))) for value in packet_ids]
    if type(limit) is not int or not 1 <= limit <= 5000:
        raise ValueError("limit must be 1..5000")
    filters = ["i.imported_at is null", "i.envelope->>'agent_id'=%s", "i.envelope->>'module_id'=%s",
               "i.packet->'header'->>'channel'=%s"]
    params = [agent_id, MODULE, channel]
    if packet_ids:
        filters.append("i.packet_id=any(%s::uuid[])")
        params.append(packet_ids)
    for value, operator in ((received_from, ">="), (received_until, "<")):
        if value is not None:
            filters.append("i.received_at" + operator + "%s::timestamptz")
            params.append(value)
    with readonly_connection(connect) as conn, conn.cursor() as cur:
        cur.execute("""select i.packet_id from sli_agent_packet_quarantine q
            join sli_agent_packet_inbox i using(packet_id) where """ + " and ".join(filters) +
            " order by i.received_at,i.packet_id limit %s", (*params, limit + 1))
        candidates = cur.fetchall()
    truncated = len(candidates) > limit
    repository = PostgresStorageV2Repository(lambda: readonly_connection(storage_connect))
    report = {"dry_run": not apply, "compatible": 0, "incompatible": 0, "imported": 0,
              "failed": 0, "skipped": 0, "has_more": truncated, "packets": []}
    for candidate in candidates[:limit]:
        packet_id = str(candidate["packet_id"])
        reason, ordinal, compatible = None, None, False
        with (connect() if apply else readonly_connection(connect)) as conn:
            with conn.cursor() as cur:
                cur.execute("""select i.packet_id,i.envelope,i.packet,i.event_rows from sli_agent_packet_inbox i
                    join sli_agent_packet_quarantine q using(packet_id)
                    where i.packet_id=%s and i.imported_at is null""" + (" for update of i" if apply else ""),
                    (packet_id,))
                row = cur.fetchone()
            if row is None:
                report["skipped"] += 1
                continue
            try:
                with conn.transaction():
                    check_packet(conn, row, repository)
                    compatible = True
                    if apply:
                        dispatch_packet(conn, row["event_rows"], packet=row["packet"], envelope=row["envelope"])
                        with conn.cursor() as cur:
                            cur.execute("update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=%s",
                                        (packet_id,))
                            cur.execute("select public.recheck_agent_quarantine_v284(%s,null) as resolved", (packet_id,))
                            if not cur.fetchone()["resolved"]:
                                raise RuntimeError("quarantine resolution incomplete")
            except SourceEventIdentityConflict as exc:
                reason = exc.detail or "event_retained_hash_differs"
                ordinal = exc.ordinal
                compatible = False
            except RepresentationConflict as exc:
                reason = exc.reason
            except (ValueError, TypeError, KeyError):
                reason = "event_representation_invalid" if not compatible else "agent_projection_failed"
            except Exception:  # noqa: BLE001 -- never print source/DB exception text
                reason = "agent_projection_failed"
            if reason and apply:
                with conn.cursor() as cur:
                    cur.execute("select public.recheck_agent_quarantine_v284(%s,%s)", (packet_id, reason))
            if compatible:
                report["compatible"] += 1
                report["failed" if reason else "imported"] += int(apply)
            else:
                report["incompatible"] += 1
            item = {"packet_id": packet_id, "compatible": compatible,
                    "status": "retained" if reason else ("imported" if apply else "compatible")}
            if reason:
                ru, en = REASONS[reason]
                item.update(reason_code=reason, reason_ru=ru, reason_en=en, event_ordinal=ordinal)
            report["packets"].append(item)
    report["summary_ru"] = f"{report['compatible']} совместимо / {report['incompatible']} нет"
    report["summary_en"] = f"{report['compatible']} compatible / {report['incompatible']} incompatible"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Сверка карантина / Targeted quarantine recheck (dry run by default)")
    parser.add_argument("--agent-id", required=True, type=UUID)
    parser.add_argument("--channel", default="Security")
    parser.add_argument("--packet-id", action="append", type=UUID, default=[])
    parser.add_argument("--received-from", type=datetime.fromisoformat)
    parser.add_argument("--received-until", type=datetime.fromisoformat)
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--apply", action="store_true", help="Импортировать совместимые / Import compatible packets")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    from server.sli.core.postgres_runtime_pipeline import connect
    from server.sli.storage.storage_v2_worker_connection import (
        connect_storage_v2_worker,
    )

    try:
        result = reprocess(connect=connect, storage_connect=connect_storage_v2_worker,
            agent_id=args.agent_id, channel=args.channel, packet_ids=args.packet_id,
            received_from=args.received_from, received_until=args.received_until, limit=args.limit, apply=args.apply)
    except Exception:  # noqa: BLE001 -- credentials/source data must not enter CLI output
        parser.exit(2, "Сверка не завершена: проверьте конфигурацию/доступ / Recheck incomplete: check configuration/access\n")
    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.report:
        args.report.write_text(output + "\n", encoding="utf-8")
    print(output)
    return int(bool(result["incompatible"] or result["failed"] or result["has_more"]))


if __name__ == "__main__":
    raise SystemExit(main())

"""Server-owned adapters from acquisition packets to existing import inputs."""
from __future__ import annotations

from typing import Any

from sli_collect.packets import validate_packet


def event_rows_from_packet(packet: dict[str, Any]) -> list[dict[str, Any]]:
    validate_packet(packet)
    header = packet["header"]
    rows = []
    for record in packet["records"]:
        row = record["payload"]
        if (record["format"] != "event_xml" or not isinstance(row.get("xml"), str)
                or row.get("record_id") != record["record_id"]
                or row.get("computer_name") != header["source"]
                or row.get("channel") != header["channel"]):
            raise ValueError("collection_packet_event_mismatch")
        rows.append(dict(row))
    return rows


def snapshot_bundle_from_packet(packet: dict[str, Any]) -> dict[str, Any]:
    from server.ad_context.contracts import validate_bundle

    validate_packet(packet)
    records = packet["records"]
    if len(records) != 1 or records[0]["format"] != "snapshot_json":
        raise ValueError("collection_packet_snapshot_invalid")
    bundle = records[0]["payload"]
    if (bundle.get("run_id") != packet["header"]["generation"]
            or packet["header"]["cursor"] != {"run_id": bundle.get("run_id")}
            or bundle.get("domain", {}).get("sid") != packet["header"]["source"]):
        raise ValueError("collection_packet_snapshot_mismatch")
    return validate_bundle(bundle)


def import_snapshot_packet(conn: Any, packet: dict[str, Any]) -> dict[str, int]:
    from server.ad_context.repository import import_bundle

    return import_bundle(conn, snapshot_bundle_from_packet(packet))


def import_workstation_packet(conn: Any, packet: dict[str, Any], *, agent_key: str,
                              identity: Any) -> dict[str, int]:
    """Project an enrolled workstation's packet inside the core transaction.

    The core authenticates the agent and attests workstation applicability.
    Never derive that authority from source names or packet payload fields.
    """
    from server.sli.plugins.workstations.importer import project_packet

    return project_packet(conn, packet, event_rows_from_packet(packet),
                          agent_key=agent_key, identity=identity)


def store_agent_packet(cur: Any, *, packet_id: str, envelope: dict, packet: dict,
                       event_rows: list[dict]) -> None:
    """Durable import input, in the same transaction as the agent receipt.

    Acquisition metadata stays outside the unchanged collection packet v1.
    Pending rows survive server restart and downstream importer failures.
    """
    import json

    if envelope["module_id"] == "sli.radius-accounting":
        validate_packet(packet)
        if event_rows or any(record["format"] != "accounting_line" for record in packet["records"]):
            raise ValueError("agent_import_rows_mismatch")
    elif event_rows_from_packet(packet) != event_rows:
        raise ValueError("agent_import_rows_mismatch")
    cur.execute("""insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows)
        values(%s,%s::jsonb,%s::jsonb,%s::jsonb)""",
        (packet_id, json.dumps(envelope), json.dumps(packet), json.dumps(event_rows)))


def consume_agent_packets(conn: Any, *, import_rows: Any, limit: int = 16,
                          module_id: str | None = None, after: tuple | None = None,
                          on_scan: Any = None) -> int:
    """Bounded server/plugin import seam; sink and inbox progress commit together.

    The server-owned importer receives the connection, validated rows, unchanged
    collection packet and envelope. It must publish durably on this connection,
    without committing itself. This function does not run collection or enable a
    plugin. A failure rolls back progress and leaves evidence pending for retry.
    A sink returning False leaves its row pending. Pollers may retain a scan
    position (received_at, packet_id) and wrap after an empty batch so deferred
    inputs do not indefinitely hide later ready inputs. on_scan is bookkeeping,
    not a durable import acknowledgement.
    """
    if type(limit) is not int or not 1 <= limit <= 128:
        raise ValueError("agent_import_limit_invalid")
    if module_id is not None and (not isinstance(module_id, str) or not module_id):
        raise ValueError("agent_import_module_invalid")
    imported = 0
    with conn.transaction(), conn.cursor() as cur:
        module_filter = " and envelope->>'module_id'=%s" if module_id else ""
        clause = " and (received_at,packet_id) > (%s,%s)" if after else ""
        params = ((module_id,) if module_id else ()) + (tuple(after) if after else ()) + (limit,)
        cur.execute("""select packet_id,envelope,packet,event_rows,received_at from sli_agent_packet_inbox
            where imported_at is null and not exists (
                select 1 from sli_agent_packet_quarantine quarantine
                where quarantine.packet_id=sli_agent_packet_inbox.packet_id
            )""" + module_filter + clause + """ order by received_at,packet_id
            limit %s for update skip locked""", params)
        pending = cur.fetchall()
        for row in pending:
            # False explicitly defers projection; legacy sinks return None.
            if on_scan:
                on_scan((row["received_at"], row["packet_id"]))
            if import_rows(conn, row["event_rows"], packet=row["packet"], envelope=row["envelope"]) is False:
                continue
            cur.execute("update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=%s",
                        (row["packet_id"],))
            imported += 1
    return imported

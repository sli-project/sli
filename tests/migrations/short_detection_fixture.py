"""Synthetic accepted packet -> current short storage, without retired core rows."""
from hashlib import sha256
import json
from xml.etree import ElementTree as ET


def store_short_event(conn, *, server, domain, packet, row, digest):
    from psycopg.types.json import Jsonb

    fields = {node.attrib["Name"]: node.text for node in ET.fromstring(row["xml"]).findall("{*}EventData/{*}Data")}
    channel = conn.execute("insert into storage_v2_channel(value) values('Security') on conflict(value) do update set value=excluded.value returning id").fetchone()["id"]
    conn.execute("insert into log_sources(name) values('Security') on conflict(name) do nothing")
    event = conn.execute("select nextval('storage_v2_event_id_seq') as id").fetchone()["id"]
    representation = row | {"provider_name": "Microsoft-Windows-Security-Auditing"}
    conn.execute("""insert into storage_v2_event_identity_allocations(id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
        values(%s,%s,%s,%s,%s,%s)""", (event, server, channel, row["record_id"], row["time_created"], digest))
    conn.execute("""insert into event_source_representations_v2(event_id,normalized_hash,identity_version,canonical_hash,representation,representation_sha256)
        values(%s,%s,2,%s,%s,%s)""", (event, digest, digest, Jsonb(representation), sha256(json.dumps(representation, sort_keys=True).encode()).digest()))
    method = {"$server_id": server, "$channel": "Security", "$provider": representation["provider_name"],
              "$machine_name": row["computer_name"], "$principals": fields,
              "$packet_id": str(packet), "$packet_ordinal": 0}
    payload = {"event_id": event, "time_created_utc": row["time_created"], "event_kind": row["event_id"],
               "domain_id": domain, "computer": row["computer_name"], "method": method,
               "fields": fields, "outcome": {}, "layer": "summary"}
    conn.execute("set local role adlog_storage_worker")
    result = conn.execute("select * from write_short_events349(%s)", (Jsonb([payload]),)).fetchone()
    conn.execute("reset role")
    assert result == {"groups": 1, "summaries": 1, "attested": 1}, result
    stored = conn.execute("select source_sha256,event_record_id from event_hot where event_id=%s and time_created_utc=%s",
                          (event, row["time_created"])).fetchone()
    assert stored == {"source_sha256": digest, "event_record_id": row["record_id"]}
    return event


def run_semantic_worker(worker_dsn, directory, *, commands=("semantic-production-worker",)):
    """Run the shipped .NET pipeline; no Python detector/publication adapter."""
    import os
    from pathlib import Path
    import shutil
    import subprocess

    root = Path(__file__).resolve().parents[2]
    host = os.environ.get("DOTNET_HOST_PATH") or shutil.which("dotnet")
    assembly = root / "server-dotnet/src/Sli.Server/bin/Debug/net10.0/Sli.Server.dll"
    assert host and assembly.is_file(), "Build server-dotnet/Sli.Server.slnx before PostgreSQL conveyor tests"
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("ADLOG_", "SLI_", "Sli__"))}
    environment.update(ADLOG_SEMANTIC_WORKER_DSN=worker_dsn,
                       ADLOG_SEMANTIC_PRODUCTION_ENABLED="1", ADLOG_SEMANTIC_RUNTIME_MODE="findings-v1",
                       ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED="0", Sli__Storage__ShortEventReads="true",
                       SLI_PLUGIN_LOCK_DIR=str(root / "config/plugin_packages/v3"), ADLOG_DATA_DIR=str(directory))
    for stage in ("NORMALIZATION", "ASSEMBLY", "CORRELATION", "RISK_ENGINE", "FINDING_CREATION"):
        environment["ADLOG_SEMANTIC_" + stage + "_ENABLED"] = "1"
    for command in commands:
        result = subprocess.run([host, str(assembly), command, "--once"],
                                cwd=root, env=environment, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert result.returncode == 0, (result.stdout, result.stderr)

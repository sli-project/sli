"""Small native Windows packets with synthetic identities and current timestamps."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from xml.sax.saxutils import escape

from cryptography.hazmat.primitives.asymmetric import ec
from psycopg.types.json import Jsonb

from server.sli.sources.collection_packet_import import (
    event_rows_from_packet,
    store_agent_packet,
)
from sli_agent.ad_dc import ADDCModule
from sli_agent.envelope import digest, make_packet
from sli_agent.file_audit_collection import FileAuditModule
from sli_agent.file_audit_policy import policy
from sli_agent.workstations import (
    DEFENDER_CHANNEL,
    PROTECTION_COMPONENTS,
    WorkstationsModule,
)

DOMAIN = 1275
PROVIDER = "Microsoft-Windows-Security-Auditing"


def xml(source, event, now, fields):
    at = (now - timedelta(minutes=5)).isoformat()
    data = "".join(f'<Data Name="{key}">{escape(value)}</Data>' for key, value in fields.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{PROVIDER}"/><EventID>{event}</EventID><Version>0</Version>'
            '<Keywords>0x8020000000000000</Keywords><EventRecordID>1</EventRecordID>'
            f'<Channel>Security</Channel><Computer>{source}</Computer>'
            f'<TimeCreated SystemTime="{at}"/></System><EventData>{data}</EventData></Event>')


def seed(conn, *, disabled_plugin=None):
    now = datetime.now(timezone.utc)
    with conn.transaction(), conn.cursor() as cur:
        forest = cur.execute("select id from forests order by id limit 1").fetchone()["id"]
        cur.execute("insert into domains(id,forest_id,fqdn,netbios_name,domain_sid) values(%s,%s,%s,%s,%s)",
                    (DOMAIN, forest, "replay.example.test", "REPLAY", "S-1-5-21-100000001-200000001-300000001"))
        cur.execute("update plugin_installations_v1 set package_lifecycle='registered',"
                    "desired_activation='enabled_manual' where plugin_id=any(%s)",
                    (["sli.ad", "sli.file-audit", "sli.workstations"],))
        # The V2 gate is issued by the existing maintenance controller on this
        # disposable DB; neither admission nor plugin state changes on the source.
        from server.sli.storage.storage_v2_runtime_authorization import (
            bootstrap_fresh_runtime_authorization,
        )
        bootstrap_fresh_runtime_authorization(cur, archive_root="/tmp/sli-e2e-archive",
            authorized_by="synthetic-e2e", expires_at=now + timedelta(hours=1))
        fields = {"TargetUserName": "replay-user", "TargetUserSid": "S-1-5-21-100000001-200000001-300000001-1001",
                  "SubjectUserSid": "S-1-5-21-100000001-200000001-300000001-1002", "SubjectUserName": "replay-admin",
                  "TargetDomainName": "REPLAY", "SubjectDomainName": "REPLAY", "LogonType": "2"}
        for family in ("ad-dc", "file-audit", "workstations"):
            agent, host = str(uuid4()), str(uuid4())
            source = "replay-" + family
            if family == "ad-dc":
                module, config = "sli.windows.ad-dc", {"source_name": source, "connect_address": source,
                    "channels": {"Security": True, "System": False, "Directory Service": False},
                    "initial_read_hours": "all"}
                native = xml(source, 4728, now, {**fields, "TargetUserName": "replay-group",
                    "TargetSid": "S-1-5-21-100000001-200000001-300000001-512", "MemberSid": "S-1-5-21-100000001-200000001-300000001-1001",
                    "MemberName": "CN=replay-user,DC=replay,DC=example,DC=test"})
                collector = ADDCModule(host, config, reader=lambda *_, value=native: [(value, "bookmark")])
            elif family == "file-audit":
                module = "sli.file-audit"
                config = {"source_name": source, "policy_revision": "1", "roots": [{
                    "collection_scope_id": "replay-root", "share_name": "replay", "path": r"C:\replay",
                    "important": False, "sacl": {"trustee_sids": ["S-1-1-0"],
                    "inherit_files": True, "inherit_directories": True}}]}
                native = xml(source, 4663, now, {**fields, "ObjectName": r"C:\replay\file.txt",
                    "ObjectType": "File", "SubjectLogonId": "0x10", "ProcessId": "0x20",
                    "HandleId": "0x30", "AccessMask": "0x2"})
                collector = FileAuditModule(host, config, reader=lambda *_, value=native: [(value, "bookmark")],
                                           path_check=lambda *_: "file")
                config = policy(config)
                cur.execute("insert into sli_plugin_file_audit.policy_revisions values(%s,%s,1,%s,"
                    "'session',1,%s,%s)", (agent, host, now, Jsonb(config), digest(config)))
                cur.execute("insert into sli_plugin_file_audit.settings(agent_id,source_instance_id,enabled) "
                            "values(%s,%s,true)", (agent, host))
            else:
                module, config = "sli.workstations", {}
                native = xml(host, 4624, now, fields)
                collector = WorkstationsModule(host, config, reader=lambda *_, value=native: [(value, "bookmark")])
            assigned = [{"module_id": module, "enabled": True, "config": config}]
            cur.execute("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(%s,%s,%s,%s)",
                        (agent, host, "0" * 64, Jsonb(assigned)))
            if family != "workstations":
                cur.execute("insert into servers(domain_id,hostname,role) values(%s,%s,%s)",
                            (DOMAIN, source, "domain_controller" if family == "ad-dc" else "file_server"))
            sample = collector.collect(now=now)
            value = make_packet(ec.generate_private_key(ec.SECP256R1()), agent_id=agent,
                                sequence=1, sample=sample, now=now)
            envelope, packet = value["envelope"], value["payload"]
            if family == "ad-dc":
                cur.execute("insert into sli_agent_module_bindings values(%s,%s,%s,%s,%s,%s,%s)",
                            (agent, module, host, source, envelope["channel"], "1.0.0", "1"))
            cur.execute("insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,"
                "envelope,receipt) values(%s,%s,1,%s,%s,%s,%s)",
                (agent, module, envelope["packet_id"], digest(envelope), Jsonb(envelope), Jsonb({"status": "committed"})))
            store_agent_packet(cur, packet_id=envelope["packet_id"], envelope=envelope, packet=packet,
                               event_rows=event_rows_from_packet(packet))
            if family == "workstations":
                # Explicit synthetic AD association for domain-scoped report
                # access. The real resolver still creates the registered device.
                cur.execute("select * from resolve_agent_workstation_v160(%s,%s)", (agent, envelope["packet_id"]))
                entity = cur.fetchone()["entity_id"]
                cur.execute("update entities_v2 set domain_id=%s where id=%s", (DOMAIN, entity))
                # Protection is a current measurement even when no native
                # Defender event has occurred. Exercise that production seam.
                state_collector = WorkstationsModule(host, config, reader=lambda *_: [],
                    protection_reader=lambda: {"state": "available", "components": {
                        **dict.fromkeys(PROTECTION_COMPONENTS, True), "real_time_protection_enabled": False}})
                sample = state_collector.collect(envelope, now=now, channel=DEFENDER_CHANNEL)
                value = make_packet(ec.generate_private_key(ec.SECP256R1()), agent_id=agent,
                                    sequence=2, sample=sample, now=now)
                state_envelope, state_packet = value["envelope"], value["payload"]
                cur.execute("insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,"
                    "envelope,receipt) values(%s,%s,2,%s,%s,%s,%s)",
                    (agent, module, state_envelope["packet_id"], digest(state_envelope),
                     Jsonb(state_envelope), Jsonb({"status": "committed"})))
                store_agent_packet(cur, packet_id=state_envelope["packet_id"], envelope=state_envelope,
                                   packet=state_packet, event_rows=[])
        if disabled_plugin:
            cur.execute("update plugin_installations_v1 set desired_activation='disabled' where plugin_id=%s",
                        (disabled_plugin,))
    return now

"""All frozen DC identities, optional XML shapes and unknown-import fallback."""
from datetime import datetime, timedelta, timezone
import copy
import importlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path.cwd()))
from sli_collect.eventlog import parse_event_xml
from server.sli.entities.entity_model import extract_event_entities
from server.sli.entities.entity_state_model import state_for_entity_link
from server.sli.events.event_catalog import event_noise_classification
from server.sli.storage.event_source_identity import event_identity_hash
from server.sli.storage.storage_v2_models import event_facts_from_v1, event_source_core_sha256

importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
directory = Path(__file__).resolve().parent
ns = "http://schemas.microsoft.com/win/2004/08/events/event"
ET.register_namespace("", ns)
fields = {
    "SubjectUserName": "operator", "SubjectDomainName": "EXAMPLE",
    "SubjectUserSid": "S-1-5-21-100000001-200000002-300000003-1101",
    "TargetUserName": "Domain Admins", "TargetDomainName": "EXAMPLE",
    "TargetSid": "S-1-5-21-100000001-200000002-300000003-1102",
    "MemberName": "CN=member,DC=example,DC=test",
    "MemberSid": "S-1-5-21-100000001-200000002-300000003-1103",
    "ServiceName": "fixture-service", "TargetServerName": "dc-target.example.test",
    "TaskName": "fixture-task", "TaskContent": "<Task/>", "ClientProcessId": "0x10",
    "NewProcessName": "fixture-new.exe", "NewProcessId": "0x20",
    "ProcessName": "fixture.exe", "ProcessId": "0x30", "CreatorProcessId": "0x40",
    "CommandLine": "fixture.exe --example", "SubjectLogonId": "0x50",
    "OldTargetUserName": "before", "NewTargetUserName": "after",
    "ServiceFileName": "fixture.exe", "ServiceAccount": "EXAMPLE\\fixture",
    "ServiceStartType": "2", "User": "fixture", "CommandName": "Get-Fixture",
    "ScriptBlockText": "Get-Fixture", "Status": "0x0", "SubStatus": "0xc000006a",
    "WorkstationName": "fixture-ws", "IpAddress": "192.0.2.10", "LogonType": "3",
    "InstanceId": "4ce2230c-9e8c-4b53-8263-711371c38e58",
    "TaskInstanceId": "4ce2230c-9e8c-4b53-8263-711371c38e58",
}
catalog = json.loads(Path("config/event_catalog.json").read_text("utf-8"))
identities = sorted({(e["channel"], e["provider_name"], e["event_id"]) for e in catalog["entries"]})
vectors = []
for index, (channel, provider, kind) in enumerate(identities + [("Security", "Microsoft-Windows-Security-Auditing", 65000)]):
    root = ET.Element("{" + ns + "}Event")
    system = ET.SubElement(root, "System")
    ET.SubElement(system, "Provider", {"Name": provider})
    ET.SubElement(system, "EventID", {"Qualifiers": "0"}).text = str(kind)
    ET.SubElement(system, "EventRecordID").text = str(index + 1)
    ET.SubElement(system, "TimeCreated", {"SystemTime": "2026-10-07T00:00:00Z"})
    ET.SubElement(system, "Channel").text = channel
    ET.SubElement(system, "Computer").text = "dc-fixture.example.test"
    ET.SubElement(system, "Execution", {"ProcessID": "80", "ThreadID": "4"})
    data = ET.SubElement(root, "EventData")
    for key, value in fields.items():
        ET.SubElement(data, "Data", {"Name": key}).text = value
    shapes = [("fields", root)]
    if kind == 4624:
        empty = copy.deepcopy(root)
        empty.remove(empty.find("EventData"))
        shapes.append(("no-event-data", empty))
        unusual = copy.deepcopy(root)
        unusual.find("EventData").append(ET.Element("Data", {"Name": "TargetUserName"}))
        ET.SubElement(unusual.find("EventData"), "Data").text = "unnamed"
        ET.SubElement(ET.SubElement(unusual, "UserData"), "NativeValue").text = "native"
        shapes.append(("duplicate-empty-unnamed-user-data", unusual))
    if kind in {140, 7036, 4776}:
        without_subject=copy.deepcopy(root)
        for element in list(without_subject.find("EventData")):
            if element.attrib.get("Name", "").startswith("Subject"):
                without_subject.find("EventData").remove(element)
        ET.SubElement(without_subject.find("EventData"), "Data", {"Name":"UserName"}).text="catalog-operator"
        shapes.append(("catalog-initiator",without_subject))
    for shape, document in shapes:
        # Namespace all native elements, as real event XML does.
        for element in document.iter():
            if not element.tag.startswith("{"):
                element.tag = "{" + ns + "}" + element.tag
        xml = ET.tostring(document, encoding="unicode")
        row = parse_event_xml(xml, source_name="dc-fixture.example.test", connect_address="fixture", channel=channel)
        data = importer.parse_event_data(xml)
        facts = event_facts_from_v1({**row, "id": 42, "event_data_json": data})
        source = importer.build_direct_event_source_row(event_db_id=42, raw_log_file_id=2, server_id=3,
            domain_id=4, site_id=None, log_source_id=5, normalized_at="2026-10-07 00:00:00+00:00", row=row, event_data=data)
        vectors.append({"source_hash":event_source_core_sha256(source).hex(), "source":source, "name": f"{channel}:{kind}:{shape}", "row": row,
            "hash": event_identity_hash(row), "entities": extract_event_entities(row, data),
            "states": [state_for_entity_link({**row,"id":42},data,link) for link in extract_event_entities(row,data)],
            "facts": facts.values if facts else None,
            "facts_hash": facts.source_facts_sha256.hex() if facts else None,
            "noise": event_noise_classification(kind, channel, provider)})
(directory / "ad-dc-import-source.json").write_text(json.dumps(vectors, ensure_ascii=True) + "\n", "utf-8")
print(f"Generated {len(vectors)} frozen Python import vectors")

time_vectors=[]
for offset in (0,25200,-12600,20700):
    instant=datetime(2026,10,7,0,0,0,123456,tzinfo=timezone.utc)
    stamp=str(instant.astimezone(timezone(timedelta(seconds=offset))))
    source=importer.build_direct_event_source_row(event_db_id=42,raw_log_file_id=2,server_id=3,
        domain_id=4,site_id=None,log_source_id=5,normalized_at=stamp,row=vectors[0]["row"],event_data=importer.parse_event_data(vectors[0]["row"]["xml"]))
    time_vectors.append({"offset":offset,"timestamp":stamp,"source_hash":event_source_core_sha256(source).hex()})
(directory / "ad-dc-timezone-source.json").write_text(json.dumps(time_vectors)+"\n","utf-8")

from unittest.mock import MagicMock, patch
from server.sli.plugins.ad import event_import
source_vectors=[]
for count in (0,1,2):
    sources=[{"server_id":10+i,"domain_id":20+i,"site_id":None} for i in range(count)]
    connection=MagicMock()
    cursor=connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value={"source_instance_id":"fixture","source_name":"dc-fixture.example.test","channel":"ad-dc","module_version":"1.0.0"}
    cursor.fetchall.return_value=sources
    envelope={"module_id":"sli.windows.ad-dc","agent_id":"fixture","source_instance_id":"fixture","channel":"ad-dc","module_version":"1.0.0"}
    with patch.object(importer,"is_authorized_direct_runtime",return_value=True), patch.object(event_import,"event_rows_from_packet",return_value=[]), patch.object(event_import,"authorize_packet"), patch.object(event_import,"authorize_plugin"), patch.object(event_import,"plugin_hook",return_value=lambda *args:[]), patch.object(event_import,"import_event_rows",side_effect=lambda *args,**kwargs:kwargs["source"]):
        try:
            expected=event_import.import_ad_dc_packet(connection,[],packet={"header":{"source":"dc-fixture.example.test"}},envelope=envelope,direct_runtime=object())
            error=None
        except ValueError as exc:
            expected=None
            error=str(exc)
    source_vectors.append({"sources":sources,"expected":expected,"error":error})
(directory / "ad-dc-configuration-source.json").write_text(json.dumps(source_vectors)+"\n","utf-8")

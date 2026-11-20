"""Synthetic real agent packets and frozen Python normalization results."""
import dataclasses
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path.cwd()))
from sli_agent.ad_dc import DCHistoryModule
from server.sli.entities.entity_model import extract_event_entities
from server.sli.plugins.ad.agent_policy import dc_event_rows
from server.sli.plugins.ad.windows_ad_dc.facts import event_facts_for_event
from server.sli.storage.event_source_identity import event_identity_hash

directory = Path(__file__).resolve().parent
fixture = json.loads((directory / "ad-dc-history-vectors.json").read_text("utf-8"))[0]
native = fixture["sample"]["payload"]["records"][0]["payload"]["xml"]
namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
vectors = []
for name, additions in (
    ("native-system", {}),
    ("large-unmapped-and-process", {"UnusedField": "z" * 4096, "ProcessName": "x" * 513,
                                    "LogonType": " " + "3" * 70 + " ", "TaskName": "  synthetic-task  ",
                                    "Action": "a" * 1050, "ObjectName": "b" * 600}),
    ("unicode-principals", {"TargetUserName": "  оператор  ", "TargetDomainName": "EXAMPLE",
                            "TargetUserSid": "S-1-5-21-100000001-200000002-300000003-1101"}),
):
    root = ET.fromstring(native)
    data = root.find(namespace + "EventData")
    for key, value in additions.items():
        item = data.find(f"{namespace}Data[@Name='{key}']")
        if item is None:
            item = ET.SubElement(data, namespace + "Data", {"Name": key})
        item.text = value
    xml = ET.tostring(root, encoding="unicode")
    module = DCHistoryModule(fixture["sample"]["source_instance_id"], fixture["config"],
                            reader=lambda channel, cursor, limit: [(xml, "bookmark")])
    sample = module.collect(now=datetime(2026, 10, 7, 12, tzinfo=timezone.utc))
    rows = dc_event_rows(dataclasses.asdict(sample), sample.payload,
                         {"source_name": "fixture-dc"}, module.config)
    assert len(rows) == 1
    row = rows[0]
    fields = {item.attrib["Name"]: item.text for item in data}
    vectors.append({"name": name, "packet": sample.payload, "hash": event_identity_hash(row),
                    "entities": extract_event_entities(row, fields),
                    "facts": {"event_id": 42, **event_facts_for_event(row=row, event_data=fields)}})
(directory / "ad-dc-projection-source.json").write_text(json.dumps(vectors, ensure_ascii=True) + "\n", "utf-8")
print(f"Generated {len(vectors)} synthetic Python agent projection vectors")

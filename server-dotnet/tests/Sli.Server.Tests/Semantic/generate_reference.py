"""Generate synthetic semantic vectors from the frozen Python implementation."""
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from copy import deepcopy

from server.sli.semantic.semantic_processing import (
    StoredEvent, assemble_canonical_actions, normalize_windows_event,
)

DATA = {
    "SubjectUserSid": "S-1-5-21-100000001-200000002-300000003-1001", "SubjectUserName": "SyntheticActor",
    "SubjectDomainName": "SYNTHETIC", "SubjectLogonId": "0x123",
    "TargetUserSid": "S-1-5-21-100000001-200000002-300000003-1002", "TargetSid": "S-1-5-21-100000001-200000002-300000003-1002",
    "TargetUserName": "SyntheticTarget", "TargetDomainName": "SYNTHETIC",
    "TargetLogonId": "0x234", "IpAddress": "192.0.2.1", "LogonType": "3",
    "Status": "0x0", "SubStatus": "0xc000006a", "MemberSid": "S-1-5-21-100000001-200000002-300000003-1003",
    "SubcategoryGuid": "{00000000-0000-0000-0000-000000000001}", "AuditPolicyChanges": "%%8448",
    "ObjectGUID": "00000000-0000-0000-0000-000000000002", "AttributeLDAPDisplayName": "test",
    "OperationType": "add", "AttributeValue": "Synthetic", "OpCorrelationID": "operation-1",
    "NewProcessId": "0x1234", "CreatorProcessId": "0x1111", "NewProcessName": "C:\\synthetic.exe",
    "ProcessId": "0x1234", "ProcessName": "C:\\synthetic.exe", "CommandLine": "synthetic --test",
    "ServiceName": "SyntheticService", "ServiceFileName": "C:\\synthetic.exe", "TaskName": "SyntheticTask",
    "AccountSessionIdentifier": "session-1", "CallingStationID": "192.0.2.2",
    "AuthenticationType": "EAP", "ReasonCode": "16",
}
vectors = []
for event_id in (4608, 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702,
                 4719, 4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734,
                 4735, 4737, 4738, 4740, 4754, 4755, 4756, 4757, 4758, 4764, 4767, 4768, 4769, 4770, 4771,
                 4772, 4773, 4776, 4781, 5136, 6272, 6273, 1102, 9999):
    provider = "Microsoft-Windows-Eventlog" if event_id == 1102 else "Microsoft-Windows-Security-Auditing"
    source = {"id": event_id, "event_id": event_id, "channel": "Security", "provider_name": provider,
              "computer": "dc.example.test", "source_host_id": 1, "server_id": 1, "domain_id": 2,
              "event_data_json": DATA, "time_created_utc": "2026-01-01T00:00:00+00:00",
              "normalized_hash": "a" * 64, "event_record_id": 3, "keywords": "Audit Success"}
    event = normalize_windows_event(StoredEvent(event_id=event_id, windows_event_id=event_id, channel="Security",
        provider=provider, server="dc.example.test", source_host_id=1, domain_id=2, event_record_id=3,
        source_event_sha256="a" * 64, occurred_at_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
        event_data=DATA, keywords="Audit Success"))
    actions = [asdict(action) for action in assemble_canonical_actions((event,))]
    vectors.append({"source": source, "expected": asdict(event), "actions": actions})
Path(__file__).with_name("normalization-reference.json").write_text(json.dumps(vectors, ensure_ascii=False, default=str, indent=2) + "\n", encoding="utf-8")

from server.sli.semantic import account_decoy, account_watch
from server.sli.storage.evidence_ref import EvidenceScope

scope = EvidenceScope(installation_id="11111111-1111-1111-1111-111111111111",
    plugin_id="sli.windows.ad-dc", source_instance_id="synthetic", source_generation="1", collection_scope_id="")
identity = {"sid": DATA["TargetSid"], "guid": "22222222-2222-2222-2222-222222222222"}
key = "sid:" + identity["sid"]
label = {"id": "33333333-3333-3333-3333-333333333333", "revision": 1, "kind": "account",
    "active": True, "identity": identity, "active_from": "2025-01-01T00:00:00+00:00", "active_to": None,
    "valid_from": "2025-01-01T00:00:00+00:00", "valid_to": None, "expires_at": "2027-01-01T00:00:00+00:00"}
base = {"event_id": 4625, "semantic_type": "authentication.session.failed", "source_event_id": 7,
    "occurred_at_utc": "2026-01-01T00:00:00+00:00", "normalized_event_id": "44444444-4444-4444-4444-444444444444",
    "sha256": "a" * 64, "roles_json": {"affected_entity": key},
    "quality_json": {"identity_roles": {"affected_entity": {"key": key, "state": "resolved", "provisional": False}}},
    "identities": [{"role": "affected_entity", "key": key, "identity": identity}], "labels": [label], "entries": [label],
    "event_item": {"event_id": 4625, "channel": "Security", "provider_name": "Microsoft-Windows-Security-Auditing",
                   "server": "dc.example.test", "event_data": {}}}
now = datetime(2026, 1, 2, tzinfo=timezone.utc)
detections = []
for watch in (False, True):
    module = account_watch if watch else account_decoy
    rule = (account_watch.WatchRule if watch else account_decoy.DecoyRule)(scope=scope, evaluation_mode="enabled")
    for case in ("exact", "ambiguous", "expired", "future", "wrong_type", "provisional"):
        row = deepcopy(base)
        if case == "ambiguous":
            row["identities"].append(deepcopy(row["identities"][0]))
        elif case == "expired":
            for name in ("entries", "labels"):
                row[name][0]["expires_at"] = row[name][0]["active_to"] = row["occurred_at_utc"]
        elif case == "future":
            row["occurred_at_utc"] = "2026-01-03T00:00:00+00:00"
        elif case == "wrong_type":
            row["semantic_type"] = "authentication.session.created"
        elif case == "provisional":
            fallback = "sam:example.test\\synthetic"
            row["roles_json"]["affected_entity"] = row["identities"][0]["key"] = fallback
            row["quality_json"]["identity_roles"]["affected_entity"] = {"key": fallback, "state": "provisional", "provisional": True}
        signals, state = module.evaluate(rule, row, now=now)
        detections.append({"case": case, "watch": watch, "scope": asdict(scope), "row": row,
            "now": now.isoformat(), "expected_state": state, "expected": [signal.document for signal in signals]})
Path(__file__).with_name("detection-reference.json").write_text(json.dumps(detections, ensure_ascii=False, default=str, indent=2) + "\n", encoding="utf-8")

"""Generate parser vectors by executing the Python reference functions unchanged.

The T109 Python branches are not included in the frozen server/ tree. Pass the
two reference runtime paths explicitly; no stand data or network is used.
"""
import argparse
import ast
import json
from datetime import datetime
from pathlib import Path

from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope
from server.sli.storage.xml_safety import parse_bounded_xml


def function(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    namespace = {"datetime": datetime, "parse_bounded_xml": parse_bounded_xml,
                 "NS": "{http://schemas.microsoft.com/win/2004/08/events/event}", "EvidenceRef": EvidenceRef}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[name]


def generate(identity_path, precursor_path):
    identity = function(identity_path, "parse_events")
    precursor = function(precursor_path, "native_event")
    scope = EvidenceScope("00000000-0000-4000-8000-000000000001", "sli.windows.ad-dc", "synthetic", "synthetic", "")
    template = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                '<System><EventID>1102</EventID><TimeCreated SystemTime="STAMP"/>'
                '<Computer>dc.example.test</Computer></System>PAYLOAD</Event>')
    variants = {
        "optional_absent": "", "empty_data": "<EventData><Data Name='Status'/></EventData>",
        "whitespace": "<EventData><Data Name='Status'> \t </Data></EventData>",
        "numeric_string": "<EventData><Data Name='Status'>0x0</Data></EventData>",
        "case_preserved": "<EventData><Data Name='SubjectUserName'>SYNTHETIC</Data></EventData>",
        "binary": "<EventData><Binary>00</Binary></EventData>",
        "data_and_binary": "<EventData><Data Name='Status'>0</Data><Binary>00</Binary></EventData>",
        "multiple_eventdata": "<EventData><Data Name='Status'>0</Data></EventData><EventData><Data Name='CommandLine'>synthetic</Data></EventData>",
        "duplicate_across_eventdata": "<EventData><Data Name='Status'>0</Data></EventData><EventData><Data Name='Status'>1</Data></EventData>",
        "userdata_1102": "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'/></UserData>",
        "missing_name": "<EventData><Data/></EventData>",
        "nested": "<EventData><Data Name='Status'><value/></Data></EventData>",
        "duplicate": "<EventData><Data Name='Status'>0</Data><Data Name='Status'>1</Data></EventData>",
        "untrusted_name": "<EventData><Data Name='private-host-token'/><Data Name='private-host-token'/></EventData>",
    }
    cases = []
    for name, payload in variants.items():
        cases.append((name, template.replace("STAMP", "2026-11-01T00:00:00Z").replace("PAYLOAD", payload), "2026-11-01T00:00:00+00:00"))
    for stamp in ("2026-11-01T00:00:00.1234567Z", "2026-11-01T07:00:00.123456+07:00",
                  "2026-11-01T00:00:00,123456+0000", "2026-11-01T00:00:30.123456+00:00:30"):
        cases.append(("time_" + str(len(cases)), template.replace("STAMP", stamp).replace("PAYLOAD", ""), "2026-11-01T00:00:00.123456+00:00"))
    cases.append(("missing_computer", cases[0][1].replace("<Computer>dc.example.test</Computer>", ""), cases[0][2]))
    result = []
    for name, xml, at in cases:
        for mode, parse in (("identity", identity), ("precursor", precursor)):
            row = {"source_event_id": 1, "native_id": "1", "event_id": 1102,
                   "occurred_at_utc": datetime.fromisoformat(at), "sha256": "a" * 64, "source_xml": xml}
            try:
                parsed = parse([row])[0] if mode == "identity" else parse(row, scope)
                expected = {"fields": parsed["event_data"], "host": parsed.get("hostname") if mode == "identity" else parsed["host"]}
            except ValueError:
                expected = None
            result.append({"name": name, "identity": mode == "identity", "row": row | {"occurred_at_utc": at}, "expected": expected})
    # Preserve the reference's failure and identify the intentionally corrected
    # .NET expectation separately: only storage rounding or truncation is valid.
    rounded = {"source_event_id": 1, "native_id": "1", "event_id": 1102,
               "occurred_at_utc": datetime.fromisoformat("2026-11-01T00:00:00.123457+00:00"),
               "sha256": "a" * 64, "source_xml": template.replace("STAMP", "2026-11-01T00:00:00.1234567Z").replace("PAYLOAD", "")}
    try:
        identity([rounded])
    except ValueError:
        result.append({"name": "rounded_storage_time_mismatch", "identity": True,
                       "row": rounded | {"occurred_at_utc": rounded["occurred_at_utc"].isoformat()}, "expected": None,
                       "corrected_expected": {"fields": {}, "host": "dc.example.test"}})
    else:
        raise AssertionError("Python identity unexpectedly accepted rounded XML time")
    # Native ACL fixture and expected classification come from the unchanged Python producer.
    from tests.migrations.test_file_audit_acl_bridge_migration264 import inventory
    from server.sli.plugins.file_audit.rules import permission_findings
    from server.sli.semantic.file_acl import classify_acl_result
    snapshot = inventory()
    agent, source = "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000003"
    config = {"policy_revision": "1", "source_name": "dc.example.test", "source_kind": "server",
              "roots": [{"collection_scope_id": "synthetic-root", "path": "C:\\synthetic", "share_name": "synthetic", "important": True}],
              "service_account_exclusions": []}
    bound = snapshot | {"agent_id": agent, "source_instance_id": source}
    acl_result = next(r for r in permission_findings(bound, config=config)
                      if r["rule_code"] == "file-audit.broad-write" and r["details"]["layer"] == "ntfs")
    classified = classify_acl_result(acl_result, snapshot=bound, config=config, installation_id=scope.installation_id)
    return {"scope": vars(scope), "vectors": result,
            "acl": {"snapshot": snapshot, "config": config, "result": acl_result, "severity": classified["severity"]}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity-runtime", type=Path, required=True)
    parser.add_argument("--precursor-runtime", type=Path, required=True)
    args = parser.parse_args()
    Path(__file__).with_name("Fixtures").joinpath("native-reference.json").write_text(
        json.dumps(generate(args.identity_runtime, args.precursor_runtime), indent=2) + "\n", encoding="utf-8")

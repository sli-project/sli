"""Synthetic inputs and expected responses from the frozen read-only UI adapters."""
import json
from datetime import datetime, timezone
from pathlib import Path

from server.sli.agents.collection_health import collection_health_view, _requested_streams
from server.sli.reporting.v2.registry import catalog, registered_reports

HERE = Path(__file__).resolve().parent
NOW = datetime(2026, 1, 2, 12, tzinfo=timezone.utc)
agents = []
streams = []
for index, module in enumerate(("sli.windows.ad-dc", "sli.workstations", "sli.ad-snapshot", "sli.file-audit", "sli.vpn-nps", "sli.radius-accounting", "sli.gpo-snapshot")):
    agent = {"id": f"00000000-0000-4000-8000-{index+1:012}", "host_id": f"00000000-0000-4000-9000-{index+1:012}",
             "instance_name": f"agent-{index}", "registration_host_name": f"host-{index}.example.test",
             "status": "active", "last_seen": "2026-01-02T11:59:00+00:00", "created_at": "2026-01-01T00:00:00+00:00",
             "policy_revision": 4, "applied_policy_revision": 4, "applied_collection_state": "active",
             "collection_policy": {"state": "active", "interval_seconds": 60},
             "assigned_modules": [{"module_id": module, "enabled": True, "config": {"policy_revision": "7", "domain_dns": "example.test"}}]}
    if module == "sli.workstations":
        del agent["assigned_modules"][0]["config"]["domain_dns"]
    if index == 1:
        agent["last_accepted_gap_at"] = "2026-01-01T10:00:00+00:00"
    agents.append(agent)
    for request in _requested_streams([agent]):
        streams.append({**{k: v for k, v in request.items() if k != "snapshot"},
                        "last_packet_at": "2026-01-02T11:59:00+00:00", "last_import_at": "2026-01-02T11:59:30+00:00",
                        "read_error": False})
scenarios = []
def add(name, agents, streams, diagnostics=True):
    scenarios.append({"name": name, "agents": agents, "streams": streams, "diagnostics": diagnostics,
                      "requested": _requested_streams(agents),
                      "expected": collection_health_view(agents, streams, now=NOW, diagnostics_available=diagnostics)})
add("current", agents, streams)
add("diagnostics_unavailable", agents, [], False)
for reason in ("read_error", "import_pending", "packet_missing", "packet_stale", "import_stale", "file_audit_unknown", "historical"):
    altered = json.loads(json.dumps(streams))
    for stream in altered:
        if reason == "read_error": stream["read_error"] = True
        if reason == "import_pending": stream["pending_since"] = "2026-01-02T10:00:00+00:00"
        if reason == "packet_missing": stream["last_packet_at"] = stream["last_import_at"] = None
        if reason == "packet_stale": stream["last_packet_at"] = "2026-01-01T00:00:00+00:00"
        if reason == "import_stale": stream["last_import_at"] = "2026-01-01T00:00:00+00:00"
        if reason == "file_audit_unknown": stream["read_error"] = None
        if reason == "historical":
            stream["historical_unimported_packets"] = 3
            stream["historical_error_at"] = "2025-12-01T00:00:00+00:00"
    add(reason, agents, altered)
for name in ("paused", "disabled", "policy_waiting", "offline", "grace", "families_disabled", "lagging"):
    altered = json.loads(json.dumps(agents))
    data = json.loads(json.dumps(streams))
    for agent in altered:
        if name == "paused": agent["collection_policy"]["state"] = "paused"
        if name == "disabled": agent["status"] = "revoked"
        if name == "policy_waiting": agent["applied_policy_revision"] = 3
        if name == "offline": agent["applied_policy_revision"] = 3; agent["last_seen"] = "2026-01-01T00:00:00+00:00"
        if name == "grace": agent["policy_applied_at"] = "2026-01-02T11:59:00+00:00"; data = []
        if name == "families_disabled":
            module = agent["assigned_modules"][0]["module_id"]
            config = agent["assigned_modules"][0]["config"]
            if module == "sli.workstations": config["families"] = dict.fromkeys(("logons", "processes", "usb", "protection", "local_admins"), False)
            elif module == "sli.windows.ad-dc": config["channels"] = dict.fromkeys(("Security", "System", "Directory Service"), False)
            elif module in ("sli.vpn-nps", "sli.radius-accounting"): config["families"] = {"nps": False, "radius_accounting": False}
    if name == "lagging":
        for stream in data: stream["pending_since"] = "2026-01-02T11:59:00+00:00"
    add(name, altered, data)

reports = []
capabilities = set()
for definition in registered_reports():
    capabilities.update(getattr(definition.access, "required_capabilities", ()))
    reports.append({"report_key": definition.access.report_key, "allowed": True, "allowed_actions": ["view"],
                    "grants": [{"scope": {"kind": "all"}, "field_categories": sorted(definition.access.required_fields), "allowed_actions": ["view"]}]})
access = {"reports": reports, "capabilities": sorted(capabilities), "subject": {"coarse_role": "admin"}}
states = [{"plugin_id": "sli.remote-access", "enabled": True}, {"plugin_id": "sli.file-audit", "enabled": False}]
(HERE / "reference.json").write_text(json.dumps({"health": scenarios, "access": access, "states": states,
    "catalog": catalog(access, plugin_states=states)}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

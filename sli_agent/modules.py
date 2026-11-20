# SPDX-License-Identifier: Apache-2.0
"""Versioned collection modules, loaded only from the local allowlist."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


@dataclass(frozen=True)
class Sample:
    module_id: str
    source_instance_id: str
    channel: str
    generation: str
    cursor_before: dict
    cursor_after: dict
    payload: dict
    module_version: str = "1.0.0"
    policy_revision: str = "1"
    continuity_state: str = "not_proven"
    filtered_count: int = 0
    lost_count: int | None = None


class CollectionModule(Protocol):
    module_id: str

    def collect(self, captured: dict | None, *, now: datetime) -> Sample | None: ...


@dataclass(frozen=True)
class RightsProfile:
    source_pack: str | None
    extra_channels: tuple[str, ...] = ()
    ad: bool = False
    sysvol: bool = False
    accounting: bool = False


# Rights metadata is independent of collector availability (AD/DC may be merged
# separately). Adding a collector must also register its actual read requirements.
RIGHTS_REGISTRY = {
    "sli.workstations": RightsProfile("workstations.json", (
        "System", "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-PowerShell/Operational")),
    "sli.ad-dc": RightsProfile("dc.json", ad=True, sysvol=True),
    "sli.windows.ad-dc": RightsProfile("dc.json"),
    "sli.windows.ad-dc-history": RightsProfile("dc.json"),
    "sli.vpn-nps": RightsProfile("radius.json", accounting=True),
    "sli.radius-accounting": RightsProfile("radius.json", accounting=True),
    "sli.remote-access": RightsProfile("radius.json", accounting=True),
    "sli.file-audit": RightsProfile("file_audit.json"),
    "sli.ad-snapshot": RightsProfile(None, ad=True),
    "sli.gpo-snapshot": RightsProfile(None, ad=True, sysvol=True),
}


class HeartbeatModule:
    module_id = "sli.heartbeat"

    def __init__(self, host_id):
        self.host_id = host_id

    def collect(self, captured=None, *, now=None):
        before = captured["cursor_after"] if captured else {"strategy": "record_id", "token": ""}
        after = {"strategy": "record_id", "token": str(int(before["token"] or "0") + 1)}
        return Sample(self.module_id, self.host_id, "heartbeat", self.host_id, before, after,
                      {"contract": "sli.heartbeat.v1", "status": "alive"})


class EventLogModule:
    module_id = "sli.windows-eventlog"

    def __init__(self, *, source_instance_id, source_name, channel, generation,
                 policy_revision="1", reader=None):
        self.source_instance_id = source_instance_id
        self.source_name = source_name
        self.channel = channel
        self.generation = generation
        self.policy_revision = policy_revision
        self.reader = reader or self._read_local

    def _read_local(self, after):
        import win32evtlog

        from sli_collect.eventlog import query_event_source, render_event_source
        # Bounded local reads; no remote session and no stored account passwords.
        selector = "*" if after is None else f"*[System[EventRecordID > {after}]]"
        handle = query_event_source(win32evtlog, None, self.channel, selector)
        try:
            handles = win32evtlog.EvtNext(handle, 1, 1000, 0)
            try:
                return [render_event_source(win32evtlog, event) for event in handles]
            finally:
                for event in handles:
                    event.Close()
        except win32evtlog.error as exc:
            if exc.winerror == 259:  # ERROR_NO_MORE_ITEMS
                return []
            raise RuntimeError("agent_eventlog_read_failed") from None
        finally:
            handle.Close()

    def collect(self, captured=None, *, now=None):
        from sli_collect.eventlog import parse_event_xml
        from sli_collect.packets import make_packet as collection_packet
        reset = captured is not None and captured["generation"] != self.generation
        before = (captured["cursor_after"] if captured and not reset
                  else {"strategy": "record_id", "token": ""})
        after_id = int(before["token"]) if before["token"] else None
        xml_rows = self.reader(after_id)
        rows = [parse_event_xml(xml, source_name=self.source_name, connect_address="localhost",
                              channel=self.channel) for xml in xml_rows]
        ids = [row["record_id"] for row in rows]
        if any(type(n) is not int or n < 0 for n in ids) or ids != sorted(set(ids)) or any(
                after_id is not None and n <= after_id for n in ids):
            raise ValueError("agent_eventlog_range_invalid")
        last = ids[-1] if ids else after_id
        payload = collection_packet(source=self.source_name, channel=self.channel, generation=self.generation,
            cursor={"after_record_id": after_id, "last_record_id": last},
            records=[{"format": "event_xml", "record_id": row["record_id"], "payload": row} for row in rows],
            continuity={"status": "not_proven"}, observed_at=now or datetime.now(timezone.utc))
        return Sample(self.module_id, self.source_instance_id, self.channel, self.generation, before,
            {"strategy": "record_id", "token": str(last) if last is not None else ""}, payload,
            policy_revision=self.policy_revision, continuity_state="gap" if reset else "not_proven")


def configured_modules(config, host_id, assigned_modules=()):
    modules = [HeartbeatModule(host_id)]
    if config.collection_enabled:
        if len(config.event_channels) != 1:
            # v1 has one cursor owner per module; multi-channel owners need a
            # distinct versioned module ID before they can share the ledger.
            raise ValueError("agent_single_channel_required")
        modules.append(EventLogModule(**config.event_channels[0]))
    # Only explicit, server-issued configuration can enable the shipped plugin.
    # String-only legacy assignments do not opt a workstation into collection.
    if not isinstance(assigned_modules, (list, tuple)) or len(assigned_modules) > 64:
        raise ValueError("agent_module_config_invalid")
    file_assignments = [item for item in assigned_modules
                        if isinstance(item, dict) and item.get("module_id") == "sli.file-audit"]
    if len(file_assignments) > 1 or file_assignments and type(file_assignments[0].get("enabled", False)) is not bool:
        raise ValueError("agent_module_config_invalid")
    if file_assignments and file_assignments[0].get("enabled", False):
        from sli_agent.file_audit_collection import FileAuditModule
        modules.append(FileAuditModule(host_id, file_assignments[0].get("config", {})))
    workstation = [item for item in assigned_modules
                   if isinstance(item, dict) and item.get("module_id") == "sli.workstations"]
    if len(workstation) > 1:
        raise ValueError("agent_module_config_invalid")
    if workstation:
        assignment = workstation[0]
        if type(assignment.get("enabled", False)) is not bool:
            raise ValueError("agent_module_config_invalid")
        if assignment.get("enabled", False):
            from sli_agent.workstations import WorkstationsModule
            module_config = assignment.get("config", {})
            if not isinstance(module_config, dict):
                raise ValueError("agent_module_config_invalid")
            modules.append(WorkstationsModule(host_id, module_config))
    dc = [item for item in assigned_modules
          if isinstance(item, dict) and item.get("module_id") == "sli.windows.ad-dc"]
    if len(dc) > 1:
        raise ValueError("agent_module_config_invalid")
    if dc:
        assignment = dc[0]
        if type(assignment.get("enabled", False)) is not bool:
            raise ValueError("agent_module_config_invalid")
        if assignment.get("enabled", False):
            from sli_agent.ad_dc import ADDCModule
            module_config = assignment.get("config", {})
            if not isinstance(module_config, dict):
                raise ValueError("agent_module_config_invalid")
            if any(module.module_id not in ("sli.heartbeat", "sli.file-audit") for module in modules):
                # The DC pack excludes file-audit-owned event IDs. Both bounded
                # readers may coexist; generic/workstation readers still conflict.
                raise ValueError("agent_channel_owner_conflict")
            modules.append(ADDCModule(host_id, module_config))
    history = [item for item in assigned_modules
               if isinstance(item, dict) and item.get("module_id") == "sli.windows.ad-dc-history"]
    if len(history) > 1 or history and type(history[0].get("enabled", False)) is not bool:
        raise ValueError("agent_module_config_invalid")
    if history and history[0].get("enabled", False):
        from sli_agent.ad_dc import DCHistoryModule
        live = next((m for m in modules if m.module_id == "sli.windows.ad-dc"), None)
        module = DCHistoryModule(host_id, history[0].get("config"))
        if live is None or any(live.config[key] != module.config[key] for key in ("source_name", "connect_address")):
            raise ValueError("agent_channel_owner_conflict")
        modules.append(module)
    if any(isinstance(item, dict) and item.get("module_id") in ("sli.vpn-nps", "sli.radius-accounting")
           for item in assigned_modules):
        from sli_agent.nps import (
            FAMILIES,
            MODULES,
            AccountingModule,
            NPSModule,
            assignment_for,
        )

        for module_id, collector in zip(MODULES, (NPSModule, AccountingModule)):
            assignments = [item for item in assigned_modules
                           if isinstance(item, dict) and item.get("module_id") == module_id]
            if len(assignments) > 1 or assignments and type(assignments[0].get("enabled", False)) is not bool:
                raise ValueError("agent_module_config_invalid")
            if assignments and assignments[0].get("enabled") is True:
                settings = assignment_for(assigned_modules, module_id, active=False)
                if not settings["paused"] and settings["families"][FAMILIES[module_id]]:
                    modules.append(collector(host_id, settings))
    for module_id in ("sli.ad-snapshot", "sli.gpo-snapshot"):
        matches = [item for item in assigned_modules if isinstance(item, dict) and item.get("module_id") == module_id]
        if len(matches) > 1 or matches and type(matches[0].get("enabled", False)) is not bool:
            raise ValueError("agent_module_config_invalid")
        if matches and matches[0].get("enabled", False):
            from sli_agent.ad_snapshot import ADSnapshotModule
            from sli_agent.gpo_snapshot import GPOSnapshotModule
            factory = ADSnapshotModule if module_id == "sli.ad-snapshot" else GPOSnapshotModule
            modules.append(factory(matches[0].get("config", {})))
    if any(module.module_id == "sli.file-audit" for module in modules):
        local_files = file_assignments[0].get("config", {}).get("source_kind") == "workstation"
        if local_files and not any(module.module_id == "sli.workstations" for module in modules):
            raise ValueError("agent_file_audit_workstation_required")
        for module in modules:
            if (module.module_id == "sli.windows-eventlog" and module.channel == "Security"
                    or module.module_id == "sli.workstations" and "Security" in module.enabled_channels() and not local_files
                    or module.module_id == "sli.vpn-nps"):
                raise ValueError("agent_channel_owner_conflict")
    return modules

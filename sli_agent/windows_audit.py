# SPDX-License-Identifier: Apache-2.0
"""GUID-only Windows audit requirements and durable, reversible management."""
from __future__ import annotations

import csv
import io
import json
import os
from uuid import UUID

from sli_agent.envelope import canonical
from sli_agent.protection import atomic_write, directory_lock


def _guid(suffix):
    return f"0cce{suffix}-69ae-11d9-bed3-505054503030"


# Ntsecapi.h identities. Masks are Success=1, Failure=2; never localized names.
SUBCATEGORIES = {
    "logon": (_guid("9215"), 3),
    "logoff": (_guid("9216"), 1),
    "process_creation": (_guid("922b"), 1),
    "security_group_management": (_guid("9237"), 1),
    "security_system_extension": (_guid("9211"), 1),
    "other_object_access": (_guid("9227"), 1),
    "audit_policy_change": (_guid("922f"), 1),
    "pnp_activity": (_guid("9248"), 1),
}
FAMILY_SUBCATEGORIES = {
    "logons": ("logon", "logoff"),
    "processes": ("process_creation",),
    "local_admins": ("security_group_management",),
    "protection": ("security_system_extension", "other_object_access", "audit_policy_change"),
    "usb": ("pnp_activity",),
}
NON_SECURITY_CHANNELS = {
    "protection": ["System", "Microsoft-Windows-Windows Defender/Operational",
                   "Microsoft-Windows-TaskScheduler/Operational"],
    "usb": ["Microsoft-Windows-DriverFrameworks-UserMode/Operational",
            "Microsoft-Windows-Kernel-PnP/Configuration"],
}
KNOWN_GUIDS = {spec[0] for spec in SUBCATEGORIES.values()}
FILE_GUIDS = {_guid(suffix) for suffix in ("921d", "9224", "9244", "922f", "9215", "9223")}
KNOWN_GUIDS |= FILE_GUIDS


def required_families(assignments):
    """Only explicitly enabled workstation families authorize audit changes."""
    result = {}
    for item in assignments:
        if not isinstance(item, dict) or item.get("module_id") != "sli.workstations" or item.get("enabled") is not True:
            continue
        families = item.get("config", {}).get("families", {})
        for family, names in FAMILY_SUBCATEGORIES.items():
            if families.get(family, True):
                result[family] = [{"subcategory": name, "guid": SUBCATEGORIES[name][0],
                                   "success": bool(SUBCATEGORIES[name][1] & 1),
                                   "failure": bool(SUBCATEGORIES[name][1] & 2)} for name in names]
    return result


def parse_backup_csv(text):
    """Parse fixed auditpol /backup columns using GUID and numeric Setting Value.

    Column headings, subcategory names and Inclusion Setting are localized.
    Per-user rows must not replace the effective system policy.
    """
    if len(text) > 1024 * 1024:
        raise ValueError("agent_audit_csv_invalid")
    result = {}
    rows = csv.reader(io.StringIO(text.lstrip("\ufeff")))
    for index, row in enumerate(rows):
        if index > 4096:
            raise ValueError("agent_audit_csv_invalid")
        if len(row) != 7:
            continue
        try:
            guid = str(UUID(row[3].strip()))
        except ValueError:
            continue
        # Auditpol's system policy has an empty target or the System token.
        # Per-user targets are SIDs; never return them or any source labels.
        if row[1].strip().upper().startswith("S-"):
            continue
        if row[6].strip() not in ("0", "1", "2", "3") or guid in result:
            raise ValueError("agent_audit_csv_invalid")
        result[guid] = int(row[6])
    if not result:
        raise ValueError("agent_audit_csv_invalid")
    return result


def gpo_override(*, force_subcategories, domain_audit_policy=False, legacy_policy=False, evidence_known=True):
    """Do not compete with domain audit CSE or an effective basic audit policy."""
    if domain_audit_policy or force_subcategories != 1 and legacy_policy:
        return "managed_by_gpo"
    return "ok" if evidence_known else "unknown"


def family_report(requirements, actual, ownership):
    result = {}
    for family, required in requirements.items():
        rows = []
        for spec in required:
            mask = actual.get(spec["guid"])
            rows.append({**spec, "actual_success": bool(mask & 1) if mask is not None else None,
                         "actual_failure": bool(mask & 2) if mask is not None else None})
        missing = any((row["success"] and row["actual_success"] is False
                       or row["failure"] and row["actual_failure"] is False) for row in rows)
        state = (ownership if ownership != "ok" else "unknown" if any(
            row["actual_success"] is None for row in rows) else "missing" if missing else "ok")
        result[family] = {"state": state, "required": rows,
                          "non_security_channels": NON_SECURITY_CHANNELS.get(family, [])}
    return result


class AuditManager:
    """Persist intent before mutation, verify readback, and never retry a drift.

    External changes after our write are conflicts: keep the original snapshot
    for operator recovery and stop writing rather than fighting a GPO refresh.
    """
    def __init__(self, root, *, api=None):
        self.root = root
        self.api = api

    def _save(self, state):
        atomic_write(self.root / "state.json", canonical(state))

    def _read(self):
        path = self.root / "state.json"
        if not path.exists():
            return {"subcategories": {}, "command_line": None}
        if path.is_symlink() or path.stat().st_size > 16384:
            raise ValueError("agent_audit_state_invalid")
        value = json.loads(path.read_bytes())
        if (not isinstance(value, dict) or set(value) != {"subcategories", "command_line"}
                or not isinstance(value["subcategories"], dict) or set(value["subcategories"]) - KNOWN_GUIDS):
            raise ValueError("agent_audit_state_invalid")
        for spec in value["subcategories"].values():
            if (not isinstance(spec, dict) or set(spec) != {"previous", "applied", "phase"}
                    or spec["phase"] not in ("pending", "confirmed", "restoring", "conflict")
                    or any(type(spec[key]) is not int or not 0 <= spec[key] <= 3 for key in ("previous", "applied"))):
                raise ValueError("agent_audit_state_invalid")
        command = value["command_line"]
        if command is not None and (not isinstance(command, dict) or set(command) != {"previous", "applied", "phase"}
                or command["previous"] is not None and (type(command["previous"]) is not int or command["previous"] not in (0, 1))
                or type(command["applied"]) is not int or command["applied"] != 1
                or command["phase"] not in ("pending", "confirmed", "restoring", "conflict")):
            raise ValueError("agent_audit_state_invalid")
        return value

    def reconcile(self, assignments, control, revision, *, file_masks=None, file_manage=False):
        requirements = required_families(assignments)
        actual = {}
        ownership = "unknown"
        management = "unknown"
        command_line = None
        command_line_known = False
        try:
            file_masks = file_masks or {}
            if (set(file_masks) - FILE_GUIDS or type(file_manage) is not bool
                    or any(type(mask) is not int or not 1 <= mask <= 3 for mask in file_masks.values())):
                raise ValueError("agent_audit_file_masks_invalid")
            if self.api is None:
                if os.name != "nt":
                    raise OSError("agent_audit_windows_required")
                from sli_agent.windows_audit_native import WindowsAuditAPI
                self.api = WindowsAuditAPI()
            with directory_lock(self.root):
                state = self._read()
                needed = {}
                for specs in requirements.values():
                    for spec in specs:
                        needed[spec["guid"]] = needed.get(spec["guid"], 0) | int(spec["success"]) | (int(spec["failure"]) << 1)
                for guid, mask in file_masks.items():
                    needed[guid] = needed.get(guid, 0) | mask
                actual = self.api.query(set(needed) | set(state["subcategories"]))
                ownership = self.api.ownership()
                command_line = self.api.command_line()
                command_line_known = True
                manage = control["manage_windows_audit"]
                want_command = manage and control["audit_process_command_line"] and "processes" in requirements
                if want_command or state["command_line"]:
                    command_ownership = self.api.command_line_ownership()
                    if command_ownership != "ok":
                        ownership = command_ownership
                management = "disabled" if not manage else "blocked"
                had_previous = bool(state["subcategories"] or state["command_line"])
                # Reading is allowed under any identity. All writes require SYSTEM
                # and proven ownership, including restore after an opt-out.
                if ownership == "ok" and self.api.is_system():
                    changes = {}
                    restored = []
                    conflict = False
                    for guid, saved in state["subcategories"].items():
                        current = actual[guid]
                        target = saved["previous"] | file_masks.get(guid, 0)
                        if manage:
                            target |= needed.get(guid, 0)
                        if (saved["phase"] == "conflict" or saved["phase"] == "confirmed" and current != saved["applied"]
                                or current not in (saved["previous"], saved["applied"],
                                                   target if saved["phase"] == "restoring" else saved["applied"])):
                            saved["phase"] = "conflict"
                            conflict = True
                            continue
                        # File audit is restored only by its explicit command.
                        # Collection opt-out must retain its owned policy bits.
                        if target != saved["applied"]:
                            saved["phase"] = "restoring"
                            if current != target:
                                changes[guid] = target
                            if target == saved["previous"]:
                                restored.append(guid)
                    if conflict:
                        self._save(state)
                        ownership = "managed_by_gpo"
                        management = "blocked"
                    else:
                        if manage or file_manage:
                            for guid, mask in needed.items():
                                if not manage and guid not in file_masks:
                                    continue
                                if guid in state["subcategories"] and state["subcategories"][guid]["phase"] == "restoring":
                                    continue
                                previous = state["subcategories"].get(guid, {}).get("previous", actual[guid])
                                target = previous | mask
                                if target != actual[guid]:
                                    state["subcategories"][guid] = {"previous": previous, "applied": target, "phase": "pending"}
                                    changes[guid] = target
                        self._save(state)
                        if changes:
                            self.api.set(changes)
                            actual = self.api.query(set(needed) | set(state["subcategories"]))
                            if any(actual[guid] != mask for guid, mask in changes.items()):
                                for guid in changes:
                                    state["subcategories"][guid]["phase"] = "conflict"
                                self._save(state)
                                ownership = "managed_by_gpo"
                                raise OSError("agent_audit_readback_failed")
                            for guid, mask in changes.items():
                                if guid not in restored:
                                    state["subcategories"][guid].update(applied=mask, phase="confirmed")
                        for guid in restored:
                            state["subcategories"].pop(guid)
                        for saved in state["subcategories"].values():
                            saved["phase"] = "confirmed"
                        self._save(state)
                        saved_command = state["command_line"]
                        if saved_command and (saved_command["phase"] == "conflict"
                                or saved_command["phase"] == "confirmed" and command_line != saved_command["applied"]
                                or command_line not in (saved_command["previous"], saved_command["applied"])):
                            saved_command["phase"] = "conflict"
                            self._save(state)
                            ownership = "managed_by_gpo"
                            management = "blocked"
                        else:
                            if want_command and command_line != 1:
                                state["command_line"] = {"previous": command_line, "applied": 1, "phase": "pending"}
                                self._save(state)
                                self.api.set_command_line(1)
                                state["command_line"]["phase"] = "confirmed"
                                self._save(state)
                                command_line = self.api.command_line()
                                if command_line != 1:
                                    state["command_line"]["phase"] = "conflict"
                                    self._save(state)
                                    ownership = "managed_by_gpo"
                                    raise OSError("agent_audit_readback_failed")
                                state["command_line"]["phase"] = "confirmed"
                                self._save(state)
                            elif not want_command and saved_command:
                                saved_command["phase"] = "restoring"
                                self._save(state)
                                self.api.set_command_line(saved_command["previous"])
                                command_line = self.api.command_line()
                                if command_line != saved_command["previous"]:
                                    saved_command["phase"] = "conflict"
                                    self._save(state)
                                    ownership = "managed_by_gpo"
                                    raise OSError("agent_audit_readback_failed")
                                state["command_line"] = None
                                self._save(state)
                            if want_command and state["command_line"]:
                                state["command_line"]["phase"] = "confirmed"
                                self._save(state)
                            management = "applied" if manage else "restored" if had_previous and not file_masks else "disabled"
                elif state["subcategories"] or state["command_line"]:
                    management = "blocked"
        except Exception:  # noqa: BLE001 - native diagnostics can contain private host/GPO labels
            management = "blocked" if ownership == "managed_by_gpo" else "unknown"
            # Re-read on the next heartbeat; never claim a successful write.
        powershell = {"channel_enabled": None, "script_block_logging_enabled": None}
        if "protection" in requirements and self.api is not None:
            try:
                powershell = self.api.powershell_logging()
            except Exception:  # noqa: BLE001 - redact native errors, independent of auditpol health
                pass
        return {"policy_revision": revision, "management_state": management,
                **({"powershell_logging": powershell} if "protection" in requirements else {}),
                "command_line_enabled": command_line == 1 if command_line_known else None,
                "families": family_report(requirements, actual, ownership)}

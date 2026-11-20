# SPDX-License-Identifier: Apache-2.0
"""Bounded local AG-AUDIT execution. Events are collected in a later stage."""
from __future__ import annotations

import hashlib
import json
import ntpath
import time
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from sli_agent.envelope import canonical
from sli_agent.file_audit_policy import audit_command, audit_requirements, local_path, path_in_root, policy
from sli_agent.protection import atomic_write, directory_lock
from sli_agent.windows_audit import FILE_GUIDS

CONTRACT = "sli.file-audit.audit-result.v1"
PAGE_BYTES = 48 * 1024
WRITE_MASK = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def request(value):
    if not isinstance(value, dict) or set(value) != {"config", "command"}:
        raise ValueError("file_audit_request_invalid")
    config = policy(value["config"])
    return {"config": config, "command": audit_command(value["command"], config)}


def desired_aces(root):
    # Failure records attempted access, including reads, for every selected root.
    # Successful ReadData is authorized only for an important root.
    flags = int(root["sacl"]["inherit_files"]) | (int(root["sacl"]["inherit_directories"]) << 1)
    return [{"sid": sid, "flags": flags | outcome,
             "mask": WRITE_MASK | (1 if outcome == 0x80 or root["important"] else 0)}
            for sid in root["sacl"]["trustee_sids"] for outcome in (0x40, 0x80)]


def root_inventory(api, root):
    # An empty share name denotes a workstation's local NTFS scope.
    if not root["share_name"]:
        return {"name": "", "path": root["path"], "dacl": "", "complete": True}
    return api.share(root["share_name"], root["path"])


class FileAuditManager:
    """One durable SACL journal; the shared AuditManager owns all policy bits.

    Only the explicit apply/restore command changes Windows. A check, pause,
    absent request or module removal cannot silently roll back owned settings.
    Pending intents survive a service restart, including interrupted restores.
    """
    def __init__(self, root, audit_manager, *, api=None, clock=time.monotonic):
        self.root, self.audit_manager, self.api, self.clock = root, audit_manager, api, clock
        self._object_keys = {}

    def _load(self):
        self._object_keys = {}
        path = self.root / "state.json"
        if not path.exists():
            return {"masks": {}, "objects": {}, "commands": {}, "active": None,
                    "walks": {}, "pending_report": None, "scan_command": None, "completed_at": None}
        if path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("file_audit_state_invalid")
        state = json.loads(path.read_bytes())
        if (not isinstance(state, dict) or set(state) != {"masks", "objects", "commands", "active", "walks",
                                                       "pending_report", "scan_command", "completed_at"}
                or any(not isinstance(state[key], dict) for key in ("masks", "objects", "commands", "walks"))):
            raise ValueError("file_audit_state_invalid")
        if (set(state["masks"]) - FILE_GUIDS or any(type(mask) is not int or not 1 <= mask <= 3 for mask in state["masks"].values())
                or len(state["objects"]) > 100000 or len(state["commands"]) > 4096):
            raise ValueError("file_audit_state_invalid")
        if state["active"] is not None:
            policy({"roots": state["active"], **({"source_kind": "workstation"}
                   if all(not root.get("share_name") for root in state["active"]) else {})})
        for walk in state["walks"].values():
            if (not isinstance(walk, dict) or set(walk) not in ({"stack", "page", "done", "gaps", "started"},
                                                            {"stack", "page", "done", "gaps", "started", "sacl_missing"})
                    or not isinstance(walk["stack"], list) or len(walk["stack"]) > 100000
                    or type(walk["done"]) is not bool
                    or any(type(walk[key]) is not int or walk[key] < 0 for key in ("page", "gaps"))):
                raise ValueError("file_audit_state_invalid")
            # Legacy walks have no scan-wide SACL evidence. Preserve unknown
            # until a new command/daily scan starts; a clean final page cannot
            # establish that earlier pages were clean.
            walk.setdefault("sacl_missing", None)
            if walk["sacl_missing"] is not None and (
                    type(walk["sacl_missing"]) is not int or walk["sacl_missing"] < 0):
                raise ValueError("file_audit_state_invalid")
            for item in walk["stack"]:
                if not isinstance(item, list) or len(item) != 2 or type(item[1]) is not int or not 0 <= item[1] <= 64:
                    raise ValueError("file_audit_state_invalid")
                local_path(item[0])
        for path, saved in state["objects"].items():
            local_path(path)
            if (not isinstance(saved, dict) or set(saved) != {"root", "object_id", "previous", "applied", "phase"}
                    or not path_in_root(path, saved["root"])
                    or saved["phase"] not in ("pending", "confirmed", "restoring", "conflict")
                    or any(not isinstance(saved[key], str) or len(saved[key]) > 65536
                           for key in ("object_id", "previous", "applied"))):
                raise ValueError("file_audit_state_invalid")
            key = ntpath.normcase(path)
            if key in self._object_keys:
                raise ValueError("file_audit_state_invalid")
            self._object_keys[key] = path
        return state

    def _object_key(self, path):
        return self._object_keys.get(ntpath.normcase(path), path)

    def acknowledge(self, report):
        with directory_lock(self.root):
            state = self._load()
            if state["pending_report"] == report:
                state["pending_report"] = None
                self._save(state)

    def _save(self, state):
        encoded = canonical(state)
        if len(encoded) > 8 * 1024 * 1024:
            raise ValueError("file_audit_state_limit")
        atomic_write(self.root / "state.json", encoded)

    def _native(self):
        if self.api is None:
            from sli_agent.file_audit_native import LocalFileAuditAPI
            self.api = LocalFileAuditAPI()
            if self.audit_manager.api is None:
                self.audit_manager.api = self.api.audit_api
        return self.api

    def reconcile(self, assignments, control, revision, value=None, *, now=None):
        now = now or datetime.now(timezone.utc)
        if value is None and not (self.root / "state.json").exists():
            return self.audit_manager.reconcile(assignments, control, revision), None
        report = None
        # Failure to load the ownership journal must block the shared manager
        # too: otherwise it could remove masks still required by this module.
        with directory_lock(self.root):
            state = self._load()
            parsed = request(value) if value is not None else None
            if state["pending_report"] is not None and parsed is not None:
                # Upload retry must send exactly the same snapshot/hash; do not
                # advance traversal or repeat Windows writes before receipt.
                audit = self.audit_manager.reconcile(assignments, control, revision, file_masks=state["masks"])
                return audit, state["pending_report"]
            writable = False
            gpo_audit = False
            masks = state["masks"]
            if parsed:
                command, config = parsed["command"], parsed["config"]
                key = command["command_id"]
                known = state["commands"].get(key)
                if known is not None and known != digest(parsed):
                    raise ValueError("file_audit_command_reused")
                if known is None and len(state["commands"]) >= 4096:
                    raise ValueError("file_audit_command_limit")
                state["commands"][key] = digest(parsed)
                if state["scan_command"] != key or (state["completed_at"] is not None
                        and (now - datetime.fromisoformat(state["completed_at"])).total_seconds() >= 86400):
                    state.update(scan_command=key, walks={}, completed_at=None)
                if state["completed_at"] is not None:
                    audit = self.audit_manager.reconcile(assignments, control, revision, file_masks=state["masks"])
                    return audit, None
                self._save(state)
                report = {"contract_id": CONTRACT, "command_id": key,
                          "policy_revision": command["policy_revision"], "action": command["action"],
                          "observed_at_utc": now.isoformat(), "scopes": [], "snapshots": [], "ownership_remaining": True}
                selected = [root for root in config["roots"]
                            if root["collection_scope_id"] in command["collection_scope_ids"]]
                try:
                    api = self._native()
                    preflight = api.preflight(selected)
                    gpo_audit = self.audit_manager.api.ownership() == "managed_by_gpo"
                    if preflight == "ok" and gpo_audit:
                        required = audit_requirements({**config, "roots": selected})
                        effective = self.audit_manager.api.query(set(required))
                        if any(effective.get(guid) is None or effective[guid] & mask != mask
                               for guid, mask in required.items()):
                            preflight = "managed_by_gpo"
                    writable = (command["action"] != "check" and control["manage_windows_audit"]
                                and preflight == "ok")
                    if writable:
                        shared_state = self.audit_manager._read()
                        actual = self.audit_manager.api.query(set(shared_state["subcategories"]))
                        if any(saved["phase"] == "conflict" or saved["phase"] == "confirmed" and actual[guid] != saved["applied"]
                               for guid, saved in shared_state["subcategories"].items()):
                            preflight, writable = "policy_blocked", False
                    if writable:
                        for root in selected:
                            if root_inventory(api, root)["complete"] is not True:
                                raise ValueError("file_audit_share_unavailable")
                            with api.open(root["path"], root["path"]) as obj:
                                if obj.describe()["object_type"] != "directory":
                                    raise ValueError("file_audit_root_invalid")
                    # A changed policy cannot abandon old SLI ACE or alter an
                    # owned subtree implicitly. Restore the old plan first.
                    active = state["active"]
                    if command["action"] == "apply" and active and active != selected:
                        preflight, writable = "restore_required", False
                    if writable and command["action"] == "apply":
                        state["active"] = selected
                        masks = audit_requirements({**config, "roots": selected})
                        state["masks"] = masks
                        self._save(state)  # intent precedes the policy API
                    if writable and command["action"] == "restore":
                        if active and {r["collection_scope_id"] for r in active} != set(command["collection_scope_ids"]):
                            preflight, writable = "restore_scope_mismatch", False
                        else:
                            guard = self._restore_guard(state, config)
                            if guard != "ok":
                                preflight, writable = guard, False
                            else:
                                self._restore(state, config)
                            if writable and not state["objects"]:
                                state["masks"] = masks = {}
                                state["active"] = None
                                self._save(state)
                except Exception:  # noqa: BLE001 - no native path/account diagnostics
                    preflight, writable = "native_unavailable", False
            else:
                preflight = "ok"
            audit = self.audit_manager.reconcile(assignments, control, revision,
                file_masks=masks, file_manage=writable and bool(parsed) and parsed["command"]["action"] == "apply")
            if report is not None:
                try:
                    actual = self.audit_manager.api.query(set(masks) | set(audit_requirements(config)))
                    policy_ok = all(actual.get(guid, 0) & mask == mask for guid, mask in masks.items())
                    # GPO may supply the required masks while SLI owns only SACL.
                    # Unknown policy and any missing mask continue to block writes.
                    if audit["management_state"] in ("blocked", "unknown") and not (
                            gpo_audit and preflight == "ok" and policy_ok):
                        writable = False
                        if preflight == "ok":
                            preflight = "policy_blocked"
                    for root in selected:
                        if state["walks"].get(root["collection_scope_id"], {}).get("done"):
                            continue
                        scope, pages = self._inventory(state, root, config, command, now,
                            apply=writable and command["action"] == "apply" and policy_ok)
                        if command["action"] == "check" and preflight != "ok":
                            scope.update(state="blocked", reason_code=preflight)
                        elif command["action"] != "check" and not writable:
                            scope.update(state="blocked", reason_code=preflight if preflight != "ok" else "management_disabled")
                            state["walks"][root["collection_scope_id"]]["done"] = False
                            state["walks"][root["collection_scope_id"]]["stack"] = [[root["path"], 0]]
                        elif command["action"] == "restore" and state["objects"]:
                            scope.update(state="partial", reason_code="restore_incomplete")
                            state["walks"][root["collection_scope_id"]]["done"] = False
                            state["walks"][root["collection_scope_id"]]["stack"] = [[root["path"], 0]]
                        scope["required_masks"] = audit_requirements({**config, "roots": [root]})
                        scope["actual_masks"] = {guid: actual.get(guid) for guid in scope["required_masks"]}
                        if scope["state"] == "verified" and command["action"] != "restore" and any(
                                actual.get(guid, 0) & mask != mask for guid, mask in scope["required_masks"].items()):
                            scope.update(state="partial", reason_code="policy_missing")
                        report["scopes"].append(scope)
                        report["snapshots"].extend(pages)
                        break  # one bounded inventory page per heartbeat
                except Exception:  # noqa: BLE001
                    report["scopes"] = [{"collection_scope_id": scope, "state": "failed", "reason_code": "native_unavailable",
                                         "required_masks": {}, "actual_masks": {}}
                                        for scope in command["collection_scope_ids"]]
                    report["snapshots"] = []
                report["ownership_remaining"] = bool(state["objects"] or state["masks"])
                state["pending_report"] = report
                if all(state["walks"].get(scope, {}).get("done") for scope in command["collection_scope_ids"]):
                    state["completed_at"] = now.isoformat()
                self._save(state)
            return audit, report

    def _restore_guard(self, state, config):
        """Check ownership across the scope before starting a bounded rollback.

        New children can inherit audit ACE after the initial bounded walk. Their
        prior ACL was not observed, so guessing ownership would erase evidence.
        Foreign changes to journaled objects also block the entire command.
        Keep the journal for an explicit administrator resolution instead;
        _restore still checks each handle again immediately before writing.
        """
        if not state["objects"]:
            return "ok"
        deadline = self.clock() + config["wall_seconds"]
        seen = 0
        for root in state["active"] or []:
            stack = [(root["path"], 0)]
            ancestors = [saved for saved in state["objects"].values() if ntpath.normcase(saved["root"]) == ntpath.normcase(root["path"])]
            while stack:
                if seen >= config["inventory_objects"] or self.clock() >= deadline:
                    return "restore_scan_incomplete"
                path, depth = stack.pop()
                seen += 1
                try:
                    with self.api.open(path, root["path"]) as obj:
                        row = obj.describe()
                        saved = state["objects"].get(self._object_key(path))
                        if saved:
                            allowed = (saved["applied"], saved["previous"]) if saved["phase"] in ("pending", "restoring") else (saved["applied"],)
                            if saved["phase"] == "conflict" or row["object_id"] != saved["object_id"] or row["sacl"] not in allowed:
                                saved["phase"] = "conflict"
                                self._save(state)
                                return "restore_conflict"
                        elif any(obj.inherited_from(saved["previous"], saved["applied"]) for saved in ancestors):
                            return "inheritance_untracked"
                        if row["object_type"] == "directory" and (path == root["path"] or not row["sacl_protected"]):
                            for name in obj.children():
                                if depth >= config["inventory_depth"] or seen + len(stack) >= config["inventory_objects"]:
                                    return "restore_scan_incomplete"
                                child = local_path(ntpath.join(path, name))
                                if ntpath.dirname(child).lower() != path.rstrip("\\").lower():
                                    return "restore_scan_incomplete"
                                stack.append((child, depth + 1))
                except Exception:  # noqa: BLE001
                    return "restore_scan_incomplete"
        return "ok"

    def _restore(self, state, config):
        deadline = self.clock() + config["wall_seconds"]
        for index, (path, saved) in enumerate(list(state["objects"].items())):
            if index >= config["inventory_objects"] or self.clock() >= deadline:
                break
            try:
                with self.api.open(path, saved["root"]) as obj:
                    current = obj.describe()
                    allowed = (saved["applied"], saved["previous"]) if saved["phase"] in ("pending", "restoring") else (saved["applied"],)
                    if saved["phase"] == "conflict" or current["object_id"] != saved["object_id"] or current["sacl"] not in allowed:
                        saved["phase"] = "conflict"
                        self._save(state)
                        continue
                    saved["phase"] = "restoring"
                    self._save(state)
                    if current["sacl"] != saved["previous"]:
                        obj.set_sacl(saved["previous"])
                    after = obj.describe()
                    if after["sacl"] != saved["previous"] or (after["owner_sid"], after["dacl"]) != (current["owner_sid"], current["dacl"]):
                        saved["phase"] = "conflict"
                        self._save(state)
                        continue
                    del state["objects"][path]
                    self._save(state)
            except Exception:  # noqa: BLE001 - retain intent and resume next command
                continue

    def _inventory(self, state, root, config, command, now, *, apply):
        api = self.api
        deadline = self.clock() + config["wall_seconds"]
        walk = state["walks"].setdefault(root["collection_scope_id"],
            {"stack": [[root["path"], 0]], "page": 0, "done": False, "gaps": 0, "started": now.isoformat(), "sacl_missing": 0})
        rows, gaps, stack, seen = [], 0, walk["stack"], 0
        share = root_inventory(api, root)
        groups = api.local_groups(config["inventory_objects"])
        if not share["complete"] or not groups["complete"]:
            gaps += 1
        while stack:
            if seen >= config["inventory_objects"] or self.clock() >= deadline:
                gaps += 1
                break
            path, depth = stack.pop()
            seen += 1
            try:
                if not path_in_root(path, root["path"]):
                    raise ValueError("file_audit_scope_escape")
                with api.open(path, root["path"]) as obj:
                    row = obj.describe()
                    protected = path != root["path"] and row["sacl_protected"]
                    eligible = path == root["path"] or root["sacl"]["inherit_directories" if row["object_type"] == "directory" else "inherit_files"]
                    plan = obj.plan(desired_aces(root)) if eligible and not protected else row["sacl"]
                    if protected:
                        gaps += 1
                    conflicted = False
                    if apply and eligible and not protected:
                        key = self._object_key(path)
                        saved = state["objects"].get(key)
                        if saved:
                            expected = getattr(obj, "expected_sacl", None)
                            # Accept only the exact native normalization of the
                            # journaled write on the same pinned object.
                            if (saved["phase"] in ("pending", "conflict") and expected is not None
                                    and row["object_id"] == saved["object_id"]
                                    and row["sacl"] != saved["applied"]
                                    and row["sacl"] == expected(saved["applied"])):
                                saved.update(applied=row["sacl"], phase="confirmed")
                                self._save(state)
                            allowed = (saved["previous"], saved["applied"]) if saved["phase"] == "pending" else (saved["applied"],)
                            if (saved["phase"] in ("conflict", "restoring") or row["object_id"] != saved["object_id"]
                                    or row["sacl"] not in allowed):
                                saved["phase"] = "conflict"
                                self._save(state)
                                gaps += 1
                                conflicted = True
                                plan = row["sacl"]
                        if plan != row["sacl"]:
                            state["objects"][key] = {"root": saved["root"] if saved else root["path"], "object_id": row["object_id"],
                                "previous": saved["previous"] if saved else row["sacl"], "applied": plan, "phase": "pending"}
                            self._object_keys[ntpath.normcase(path)] = key
                            self._save(state)
                            obj.set_sacl(plan)
                            after = obj.describe()
                            if after["sacl"] != plan or (after["owner_sid"], after["dacl"]) != (row["owner_sid"], row["dacl"]):
                                state["objects"][key]["phase"] = "conflict"
                                self._save(state)
                                raise ValueError("file_audit_readback_failed")
                            state["objects"][key]["phase"] = "confirmed"
                            self._save(state)
                            row = after
                        elif saved and saved["phase"] == "pending":
                            saved["phase"] = "confirmed"
                            self._save(state)
                    missing = eligible and not protected and obj.plan(desired_aces(root)) != row["sacl"]
                    candidate = {"path": path, **row, "sacl_missing": missing}
                    if len(canonical(rows + [candidate])) > min(config["max_bytes"], PAGE_BYTES - 16384):
                        stack.append([path, depth])
                        if not rows:
                            # An oversized descriptor is a coverage gap; never
                            # stall the scan forever on this object.
                            stack.pop()
                            gaps += 1
                        break
                    rows.append(candidate)
                    # Count only admitted rows: a size-limited object can be
                    # requeued and inspected again on the next page.
                    if walk["sacl_missing"] is not None:
                        walk["sacl_missing"] += int(missing)
                    # Lazy enumeration holds the no-reparse directory handle.
                    if row["object_type"] == "directory" and not protected and not conflicted:
                        for name in obj.children():
                            if depth >= config["inventory_depth"] or len(stack) + seen >= config["inventory_objects"] or self.clock() >= deadline:
                                gaps += 1
                                break
                            child = local_path(ntpath.join(path, name))
                            if ntpath.dirname(child).lower() != path.rstrip("\\").lower():
                                raise ValueError("file_audit_scope_escape")
                            stack.append([child, depth + 1])
            except Exception:  # noqa: BLE001
                if state["objects"].get(self._object_key(path), {}).get("phase") == "pending":
                    stack.append([path, depth])
                    break
                gaps += 1
        walk["done"] = not stack
        walk["gaps"] += gaps
        snapshot = {"contract_id": "sli.file-audit.inventory.v1", "collection_scope_id": root["collection_scope_id"],
                    "policy_revision": command["policy_revision"], "observed_at_utc": now.isoformat(),
                    "scan_id": str(uuid5(NAMESPACE_URL, command["command_id"] + root["collection_scope_id"] + walk["started"])),
                    "page_number": walk["page"], "has_more": bool(stack),
                    "completeness": "partial" if gaps or stack or walk["page"] else "complete", "unread_objects": gaps,
                    "share": share, "local_groups": groups, "objects": rows}
        # A bounded partial snapshot is append-only and never replaces a full one.
        hashed = digest(snapshot)
        snapshot["snapshot_sha256"] = hashed
        snapshot["snapshot_id"] = str(uuid5(NAMESPACE_URL, command["command_id"] + hashed))
        walk["page"] += 1
        if len(canonical(snapshot)) > PAGE_BYTES:
            raise ValueError("file_audit_snapshot_limit")
        missing = command["action"] != "restore" and bool(walk["sacl_missing"])
        incomplete = bool(walk["gaps"] or stack or (
            command["action"] != "restore" and walk["sacl_missing"] is None))
        scope = {"collection_scope_id": root["collection_scope_id"],
                 "state": "partial" if incomplete or missing else "verified",
                 "reason_code": "coverage_incomplete" if incomplete else "sacl_missing" if missing else "ok"}
        return scope, [snapshot]

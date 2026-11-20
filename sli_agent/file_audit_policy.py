# SPDX-License-Identifier: Apache-2.0
"""File-server policy contracts; no reads or Windows audit writes on import."""
from __future__ import annotations

import ntpath
import re

MODULE_ID = "sli.file-audit"
PACK_ID = "sli.windows.file-audit"
PROVIDER = "Microsoft-Windows-Security-Auditing"
EVENT_IDS = (4656, 4659, 4660, 4663, 4670, 4907, 5140, 5142, 5143, 5144, 5145, 5168)
OPTIONAL_EVENT_IDS = (4658, 4664)
# These are consumed as shared context, never normalized by this package.
CONTEXT_EVENT_IDS = (4608, 4624, 4625, 4634, 4719, 1102)
SID = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+")


def local_path(value):
    """Require a local, absolute, unambiguous path before normalization.

    This is lexical validation only. The later collector must check every
    opened component for reparse points; this contract never authorizes them.
    """
    if (not isinstance(value, str) or not 3 <= len(value) <= 4096
            or not re.match(r"^[a-zA-Z]:[\\/]", value)
            or any(ord(char) < 32 or char in '*?"<>|' for char in value)
            or ":" in value[2:]):
        raise ValueError("file_audit_path_invalid")
    parts = value[3:].replace("/", "\\").split("\\")
    if any(part in (".", "..") or part and part.rstrip(" .") != part for part in parts):
        raise ValueError("file_audit_path_invalid")
    return ntpath.normpath(value)


def path_in_root(path, root):
    path, root = (ntpath.normcase(local_path(value)) for value in (path, root))
    return path == root or path.startswith(root.rstrip("\\") + "\\")


def policy(config):
    """Strict, bounded administrator selection; read auditing is per root."""
    fields = {"policy_revision", "source_name", "roots", "max_events", "max_bytes", "wall_seconds",
              "spool_bytes", "inventory_depth", "inventory_objects", "optional_events",
              "service_account_exclusions", "mass_operation_files", "mass_operation_seconds", "source_kind", "initial_read_hours"}
    if not isinstance(config, dict) or set(config) - fields:
        raise ValueError("file_audit_policy_invalid")
    depth = config.get('initial_read_hours', 'all')
    if depth != 'all' and (type(depth) is not int or not 0 <= depth <= 876000):
        raise ValueError('file_audit_policy_invalid')
    source_kind = config.get("source_kind", "server")
    if not isinstance(source_kind, str) or source_kind not in ("server", "workstation"):
        raise ValueError("file_audit_policy_invalid")
    revision = config.get("policy_revision", "1")
    if (not isinstance(revision, str) or not re.fullmatch(r"[1-9][0-9]{0,15}", revision)
            or int(revision) > 9007199254740991):
        raise ValueError("file_audit_policy_invalid")
    roots = config.get("roots")
    if not isinstance(roots, list) or not 1 <= len(roots) <= 100:
        raise ValueError("file_audit_policy_invalid")
    normalized = []
    scope_ids = set()
    for root in roots:
        if not isinstance(root, dict) or set(root) != {
                "collection_scope_id", "share_name", "path", "important", "sacl"}:
            raise ValueError("file_audit_policy_invalid")
        scope = root["collection_scope_id"]
        share = root["share_name"]
        sacl = root["sacl"]
        if (not isinstance(scope, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,256}", scope)
                or scope in scope_ids or type(root["important"]) is not bool
                or not isinstance(share, str)
                or (share != "" if source_kind == "workstation" else not 1 <= len(share) <= 80)
                or any(ord(char) < 32 or char in '\\/:*?"<>|' for char in share)
                or share.strip() != share
                or not isinstance(sacl, dict) or set(sacl) != {"trustee_sids", "inherit_files", "inherit_directories"}
                or any(type(sacl[key]) is not bool for key in ("inherit_files", "inherit_directories"))
                or not isinstance(sacl["trustee_sids"], list) or not 1 <= len(sacl["trustee_sids"]) <= 100
                or any(not isinstance(sid, str) or len(sid) > 184 or not SID.fullmatch(sid) for sid in sacl["trustee_sids"])
                or len(set(sacl["trustee_sids"])) != len(sacl["trustee_sids"])):
            raise ValueError("file_audit_policy_invalid")
        scope_ids.add(scope)
        normalized.append({**root, "path": local_path(root["path"]),
                           "sacl": {**sacl, "trustee_sids": list(sacl["trustee_sids"])}})
    limits = {"max_events": (1000, 1, 10000), "max_bytes": (1048576, 1024, 8388608),
              "wall_seconds": (30, 1, 120), "spool_bytes": (268435456, 1048576, 1073741824),
              "inventory_depth": (16, 0, 64), "inventory_objects": (10000, 1, 100000),
              "mass_operation_files": (100, 1, 1000000), "mass_operation_seconds": (300, 1, 86400)}
    result = {"policy_revision": revision, "roots": normalized}
    if "source_kind" in config:
        result["source_kind"] = source_kind
    if "source_name" in config:
        name = config["source_name"]
        if (not isinstance(name, str) or not 1 <= len(name) <= 255 or name.strip() != name
                or any(ord(char) < 33 or char in '/\\' for char in name)):
            raise ValueError("file_audit_policy_invalid")
        result["source_name"] = name
    for key, (default, low, high) in limits.items():
        value = config.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError("file_audit_policy_invalid")
        result[key] = value
    optional = config.get("optional_events", False)
    exclusions = config.get("service_account_exclusions", [])
    if (type(optional) is not bool or not isinstance(exclusions, list) or len(exclusions) > 100
            or any(not isinstance(sid, str) or len(sid) > 184 or not SID.fullmatch(sid) for sid in exclusions)
            or len(set(exclusions)) != len(exclusions)):
        raise ValueError("file_audit_policy_invalid")
    return {**result, "optional_events": optional, "service_account_exclusions": list(exclusions),
            **({'initial_read_hours': depth} if 'initial_read_hours' in config else {})}


def audit_requirements(config):
    """AG-AUDIT plan only; management permission remains in core control policy."""
    config = policy(config)
    masks = {"921d": 3, "9224": 3, "9244": 3 if any(root["important"] for root in config["roots"]) else 2,
             "922f": 1, "9215": 3}
    if config.get("source_kind") == "workstation":
        del masks["9224"]
        del masks["9244"]
    if config["optional_events"]:
        masks["9223"] = 1  # Handle Manipulation; never enable Kernel Object.
    return {f"0cce{suffix}-69ae-11d9-bed3-505054503030": mask for suffix, mask in masks.items()}


def audit_command(value, config):
    """Check is safe by default. Apply/restore require an explicit revision."""
    config = policy(config)
    if (not isinstance(value, dict) or set(value) != {"contract_id", "command_id", "action", "policy_revision", "collection_scope_ids"}
            or value["contract_id"] != "sli.file-audit.audit-command.v1"
            or not isinstance(value["command_id"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", value["command_id"])
            or not isinstance(value["action"], str) or value["action"] not in ("check", "apply", "restore")
            or type(value["policy_revision"]) is not str or value["policy_revision"] != config["policy_revision"]
            or not isinstance(value["collection_scope_ids"], list) or not value["collection_scope_ids"]
            or any(not isinstance(item, str) for item in value["collection_scope_ids"])
            or len(set(value["collection_scope_ids"])) != len(value["collection_scope_ids"])
            or not set(value["collection_scope_ids"]) <= {root["collection_scope_id"] for root in config["roots"]}):
        raise ValueError("file_audit_command_invalid")
    return {**value, "collection_scope_ids": list(value["collection_scope_ids"])}

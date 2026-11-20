# SPDX-License-Identifier: Apache-2.0
"""Service-identity GPO capture into the existing evidence/governance contracts."""
from __future__ import annotations

import json
import re
import time
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

from sli_agent.ad_snapshot import PowerShellDirectoryReader
from sli_agent.envelope import canonical
from sli_agent.gpo_privacy import mask_gpo
from sli_agent.snapshot_stream import SnapshotModule

ARRAYS = ("gpos", "scopes", "links", "settings", "permissions", "acl", "wmi_filters", "unresolved_links", "collection_errors")
SOURCES = ("gpo_list", "gpo_reports", "gpc_directory", "sysvol_gpt", "links", "permissions", "wmi_filters")
SNAPSHOT_KEYS = frozenset({"schema_version", "collector_version", "demo", "demo_notice", "started_at", "completed_at",
    "observed_at", "collection_status", "domain", "scope", "source_states", *ARRAYS})


def confined_gpt_path(path, config):
    """Pin only the exact domain Policies/{GUID}/GPT.INI path to the chosen DC."""
    dc = config["dc"][0] if config["dc"] else config["domain_dns"]
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", dc):
        raise ValueError("agent_gpo_sysvol_path_invalid")
    parts = path.split("\\")
    if (len(parts) != 7 or parts[:2] != ["", ""] or parts[2].casefold() not in
            {config["domain_dns"], dc.casefold()} or parts[3].casefold() != "sysvol"
            or parts[4].casefold() != config["domain_dns"] or parts[5].casefold() != "policies"
            or not re.fullmatch(r"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}", parts[6])):
        raise ValueError("agent_gpo_sysvol_path_invalid")
    return "\\\\" + dc + "\\SYSVOL\\" + config["domain_dns"] + "\\Policies\\" + parts[6] + "\\GPT.INI"


def normalize_capture(raw, config):
    """No raw files; a bounded partial receipt never authorizes reconciliation."""
    if raw.get("error_code") in {"agent_gpo_group_policy_unavailable", "agent_gpo_capture_failed"}:
        raise ValueError(raw["error_code"])
    domain = raw["domain"]
    snapshot = {key: deepcopy(value) for key, value in raw["snapshot"].items() if key in SNAPSHOT_KEYS}
    expected_base = ",".join("DC=" + label for label in config["domain_dns"].split("."))
    if (domain["sid"] != config["domain_sid"] or domain["dns_name"].casefold() != config["domain_dns"]
            or snapshot["domain"]["dns_name"].casefold() != config["domain_dns"]
            or snapshot["domain"].get("sid") != config["domain_sid"]):
        raise ValueError("agent_gpo_domain_mismatch")
    if domain["default_nc"].casefold() != expected_base.casefold() or config["search_bases"] not in ([], [expected_base]):
        raise ValueError("agent_gpo_scope_mismatch")
    if config["dc"] and snapshot["domain"]["query_dc"].casefold() != config["dc"][0].casefold():
        raise ValueError("agent_gpo_dc_mismatch")
    records = deepcopy(raw["records"])
    stamp = snapshot["observed_at"]
    snapshot.setdefault("acl", [])
    bundle = {"schema_version": "ad-context-bundle/v1", "source_pack_id": "sli.windows.ad-context", "source_pack_version": "0.9.0",
        "run_id": str(uuid4()), "mode": "full", "domain": {"sid": config["domain_sid"], "dns_name": config["domain_dns"]},
        "scope": {"search_base": expected_base, "collection_profile": "gpo_governance_v4", "privileged_group_sids": [], "vpn_group_sids": []},
        "observed_at_utc": stamp, "records": records,
        "sections": [{"name": "gpo_governance", "status": "complete" if snapshot["collection_status"] == "complete" else "partial",
            "record_count": len(records), "duration_ms": 0, "error_code": None if snapshot["collection_status"] == "complete" else "agent_gpo_source_partial"}]}
    original = {"gpo_v2": snapshot, "ad_gpo_governance": bundle}
    masked = mask_gpo(original)
    was_masked = masked != original or set(raw["snapshot"]) - SNAPSHOT_KEYS
    masked["gpo_v2"]["privacy"] = {"masked": bool(was_masked), "raw_content_collected": False}
    families = {name: (masked[name], len(masked[name]["gpos" if name == "gpo_v2" else "records"])) for name in config["families"]}
    if (raw.get("overflow") or len(snapshot["gpos"]) > config["max_objects"] or len(records) > config["max_objects"]
            or sum(len(canonical(data)) for data, _ in families.values()) > config["max_bytes"]):
        snapshot = masked["gpo_v2"]
        snapshot.update(collection_status="partial", collection_errors=[{"code": "agent_gpo_size_limit", "status": "partial"}])
        for name in ARRAYS:
            if name != "collection_errors":
                snapshot[name] = []
        snapshot["source_states"] = {name: {"status": "partial", "source": name, "error": "agent_gpo_size_limit"} for name in SOURCES}
        bundle = masked["ad_gpo_governance"]
        bundle.update(mode="targeted", records=[])
        bundle["sections"][0].update(status="partial", record_count=0, error_code="agent_gpo_size_limit")
        families = {name: (masked[name], 0) for name in config["families"]}
        if sum(len(canonical(data)) for data, _ in families.values()) > config["max_bytes"]:
            raise ValueError("agent_gpo_size_limit")
    return families


class PowerShellGPOReader(PowerShellDirectoryReader):
    script_path = Path(__file__).with_suffix(".ps1")
    error_prefix = "agent_gpo"


class GPOSnapshotModule(SnapshotModule):
    def __init__(self, config, *, reader=None):
        super().__init__("sli.gpo-snapshot", config)
        self.reader = reader or PowerShellGPOReader()

    def capture(self, config, *, deadline, stop):
        if stop.is_set() or time.monotonic() >= deadline:
            raise ValueError("agent_gpo_capture_cancelled")
        raw = self.reader(config, deadline=deadline, stop=stop)
        if stop.is_set() or time.monotonic() >= deadline:
            raise ValueError("agent_gpo_capture_cancelled")
        try:
            return normalize_capture(json.loads(raw) if isinstance(raw, str) else raw, config)
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            code = str(exc)
            if code in {"agent_gpo_group_policy_unavailable", "agent_gpo_capture_failed", "agent_gpo_size_limit"}:
                raise ValueError(code) from None
            raise ValueError("agent_gpo_capture_invalid") from None

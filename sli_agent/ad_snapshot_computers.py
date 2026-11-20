# SPDX-License-Identifier: Apache-2.0
"""The existing Computers V6 source contract, with explicit optional states."""
from __future__ import annotations

import re
import ipaddress
from uuid import uuid4


def computer_snapshot(records, *, config, observed, query_dc, search_base=None, optional=None):
    names = ("ad", "dns", "os", "site", "last_logon_timestamp", "exact_last_logon", "dc_events")
    flags = config["expensive_flags"]
    optional = optional or {}
    objects = []
    for record in records:
        attrs, identity = record["attributes"], record["identity"]
        guid = identity["object_guid"]
        addresses = attrs.get("ip_addresses", [])
        site = None
        sources = {}
        for name in names:
            status = "observed" if name in {"ad", "os", "last_logon_timestamp"} else "not_collected"
            value = None
            if name == "os":
                value = attrs.get("operating_system")
                status = "observed" if value else "missing_in_source"
            elif name == "last_logon_timestamp":
                value = attrs.get("last_logon_timestamp_utc")
                status = "observed" if value else "missing_in_source"
            elif name == "exact_last_logon":
                value = attrs.get("exact_last_logon_utc")
                status = attrs.get("exact_last_logon_status", "not_collected")
                if status == "no_record":
                    status = "missing_in_source"
            elif name == "dns" and flags.get("dns"):
                data = optional.get("dns", {}).get("values", {}).get(guid, {})
                value, status = addresses, data.get("status", "not_evaluated")
            elif name == "site" and flags.get("ad_site"):
                status = optional.get("ad_site", {}).get("status", "not_evaluated")
                if status == "observed":
                    matches = []
                    for subnet in optional.get("ad_site", {}).get("subnets", []):
                        try:
                            network = ipaddress.ip_network(subnet["name"], strict=False)
                            if any(ipaddress.ip_address(address) in network for address in addresses):
                                matches.append((network.prefixlen, subnet["siteobject"]))
                        except (ValueError, KeyError):
                            continue
                    site_dn = max(matches, default=(0, None))[1]
                    site = site_dn.split(",", 1)[0][3:] if site_dn else None
                    value, status = site, "observed" if site else "no_record" if addresses else "not_evaluated"
            elif flags.get({"dns": "dns", "site": "ad_site"}.get(name, "")):
                status = "not_evaluated"
            sources[name] = {"status": status, "source": name, "value": value,
                             "observed_at": observed if status not in {"not_collected", "not_evaluated"} else None,
                             "error": None, "details": None}
        sources["exact_last_logon"]["details"] = {
            "discovered_dc_count": attrs.get("exact_last_logon_discovered_dc_count", 0),
            "successful_dc_count": attrs.get("exact_last_logon_successful_dc_count", 0),
            "failed_dcs": attrs.get("exact_last_logon_failed_dcs", []),
        }
        os_name = attrs.get("operating_system")
        device_type = "server" if os_name and "server" in os_name.casefold() else "workstation" if os_name and "windows" in os_name.casefold() else "unknown"
        is_dc = bool((attrs.get("user_account_control") or 0) & 8192)
        if is_dc:
            device_type = "domain_controller"
        version = attrs.get("operating_system_version")
        build = re.search(r"\((\d+)\)", version or "")
        dn = attrs.get("distinguished_name")
        objects.append({
            "id": identity["object_guid"], "objectGuid": identity["object_guid"],
            "name": attrs.get("display_name"), "dnsHostName": attrs.get("dns_host_name"),
            "enabled": attrs.get("enabled"), "deviceType": device_type,
            "classification": {"result": device_type, "state": "observed" if device_type != "unknown" else "unknown",
                               "source": "userAccountControl" if is_dc else "operatingSystem"},
            "ipv4s": [a for a in addresses if ipaddress.ip_address(a).version == 4],
            "ipv6s": [a for a in addresses if ipaddress.ip_address(a).version == 6], "osName": os_name, "osVersion": version,
            "osBuild": build[1] if build else None,
            "osFamily": "Windows" if os_name and "windows" in os_name.casefold() else "Unknown",
            "servicePack": attrs.get("operating_system_service_pack"),
            "ou": dn.split(",", 1)[1] if dn and "," in dn else None,
            "distinguishedName": dn, "canonicalName": attrs.get("canonical_name"), "domain": config["domain_dns"],
            "adSite": site, "lastLogonTimestamp": attrs.get("last_logon_timestamp_utc"),
            "exactLastLogon": attrs.get("exact_last_logon_utc"), "eventLastSeen": None,
            "passwordLastSet": attrs.get("password_last_set_utc"), "whenCreated": attrs.get("created_utc"),
            "whenChanged": attrs.get("when_changed_utc"), "description": attrs.get("description"),
            "location": attrs.get("location"), "managedBy": attrs.get("managed_by"), "sid": identity.get("object_sid"),
            "userAccountControl": attrs.get("user_account_control"), "spns": attrs.get("service_principal_names") or [],
            "trustedForDelegation": attrs.get("trusted_for_delegation"),
            "trustedToAuthForDelegation": attrs.get("trusted_to_auth_for_delegation"),
            "allowedToDelegateTo": attrs.get("allowed_to_delegate_to"),
            "resourceBasedDelegationPresent": attrs.get("resource_based_delegation_present"),
            "resourceBasedDelegationSids": attrs.get("resource_based_delegation_sids"),
            "resourceBasedDelegationStatus": attrs.get("resource_based_delegation_status"),
            "resourceBasedDelegationDescriptorSha256": attrs.get("resource_based_delegation_descriptor_sha256"),
            "lapsPasswordExpiration": attrs.get("laps_password_expiration_utc"),
            "legacyLapsPasswordExpiration": attrs.get("legacy_laps_password_expiration_utc"),
            "lapsPasswordExpirationStatus": attrs.get("laps_password_expiration_status"),
            "legacyLapsPasswordExpirationStatus": attrs.get("legacy_laps_password_expiration_status"),
            "passwordLastSetStatus": attrs.get("password_last_set_status"),
            "roleHint": None, "roleEvidence": [], "collectedAt": observed, "queryDc": query_dc,
            "collectorVersion": "sli-agent/ad-snapshot/1", "sources": sources, "collectionErrors": [],
        })
    stages = [{"name": name, "status": "observed" if name in {"ad", "os", "last_logon_timestamp"} else
               "partial" if name == "exact_last_logon" and flags.get("exact_last_logon") else
               "not_evaluated" if flags.get({"dns": "dns", "site": "ad_site"}.get(name, "")) else "not_collected",
               "requested": name in {"ad", "os", "last_logon_timestamp"} or flags.get({"dns": "dns", "site": "ad_site", "exact_last_logon": "exact_last_logon"}.get(name, ""), False)} for name in names]
    for stage in stages:
        if objects:
            statuses = {obj["sources"][stage["name"]]["status"] for obj in objects}
            stage["status"] = next(iter(statuses)) if len(statuses) == 1 else "partial"
    return {"schema_version": "2.0", "metadata": {
        "snapshot_id": str(uuid4()), "label": "SLI AD snapshot", "started_at": observed, "completed_at": observed,
        "query_dc": query_dc, "domain": config["domain_dns"], "search_base": search_base or (config["search_bases"][0] if config["search_bases"] else config["scope"]),
        "collection_status": "partial" if any(s["requested"] and s["status"] != "observed" for s in stages) else "complete",
        "object_count": len(objects), "collector_version": "sli-agent/ad-snapshot/1", "sources": stages, "errors": [],
    }, "objects": objects}

# SPDX-License-Identifier: Apache-2.0
"""Service-identity AD capture. Only allowlisted, normalized data reaches spool."""
from __future__ import annotations

import json
import hashlib
import ipaddress
import os
import re
import subprocess
import threading
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

from sli_agent.envelope import canonical
from sli_agent.snapshot_stream import SnapshotModule
from sli_agent.ad_snapshot_security import DATE_ATTRIBUTES, security_attributes

# LDAP source names for the existing AD Context attribute contract. Never use
# PropertiesToLoad='*': password material is excluded at acquisition as well as
# at normalization. Keep the destination allowlist checked against contracts.py.
ATTRIBUTE_MAP = {
    "name": "display_name", "samaccountname": "sam_account_name",
    "distinguishedname": "distinguished_name", "userprincipalname": "user_principal_name",
    "givenname": "given_name", "sn": "surname", "canonicalname": "canonical_name",
    "department": "department", "title": "title", "company": "company", "manager": "manager",
    "employeeid": "employee_id", "employeenumber": "employee_number", "location": "location",
    "mail": "mail", "physicaldeliveryofficename": "office", "telephonenumber": "telephone_number",
    "mobile": "mobile", "ipphone": "ip_phone", "facsimiletelephonenumber": "fax",
    "othertelephone": "other_telephones", "streetaddress": "street_address", "l": "city",
    "st": "state", "postalcode": "postal_code", "co": "country", "proxyaddresses": "proxy_addresses",
    "scriptpath": "script_path", "homedirectory": "home_directory", "homedrive": "home_drive",
    "profilepath": "profile_path", "admincount": "admin_count", "primarygroupid": "primary_group_id",
    "managedby": "managed_by", "description": "description", "dnshostname": "dns_host_name",
    "operatingsystem": "operating_system", "operatingsystemversion": "operating_system_version",
    "operatingsystemservicepack": "operating_system_service_pack",
    "serviceprincipalname": "service_principal_names", "sidhistory": "sid_history",
    "msds-supportedencryptiontypes": "msds_supported_encryption_types",
    "msds-allowedtodelegateto": "allowed_to_delegate_to", "badpwdcount": "bad_password_count_at_query_dc",
    "trustpartner": "trust_partner", "flatname": "trust_flat_name", "trustattributes": "trust_attributes",
    "minpwdlength": "password_min_length", "pwdhistorylength": "password_history_length",
    "msds-minimumpasswordlength": "password_min_length", "msds-passwordhistorylength": "password_history_length",
    "msds-lockoutthreshold": "lockout_threshold",
    "pwdproperties": "password_properties", "lockoutthreshold": "lockout_threshold",
    "ms-ds-machineaccountquota": "machine_account_quota", "msds-behavior-version": "domain_mode",
}
DATE_MAP = {"lastlogontimestamp": "last_logon_timestamp_utc", "pwdlastset": "password_last_set_utc",
            "whencreated": "when_created_utc", "whenchanged": "when_changed_utc",
            "accountexpires": "account_expiration_utc", "badpasswordtime": "last_bad_password_attempt_utc",
            "msds-userpasswordexpirytimecomputed": "password_expiry_utc",
            "mslaps-passwordexpirationtime": "laps_password_expiration_utc",
            "ms-mcs-admpwdexpirationtime": "legacy_laps_password_expiration_utc"}
INTERVAL_MAP = {"maxpwdage": "password_max_age", "minpwdage": "password_min_age",
                "lockoutduration": "lockout_duration", "lockoutobservationwindow": "lockout_observation_window",
                "msds-maximumpasswordage": "password_max_age", "msds-minimumpasswordage": "password_min_age",
                "msds-lockoutduration": "lockout_duration", "msds-lockoutobservationwindow": "lockout_observation_window"}
UAC_FLAGS = {"password_not_required": 32, "password_never_expires": 65536,
             "allow_reversible_password_encryption": 128, "smartcard_logon_required": 262144,
             "trusted_for_delegation": 524288, "account_not_delegated": 1048576,
             "use_des_key_only": 2097152, "does_not_require_preauth": 4194304,
             "password_expired": 8388608, "trusted_to_auth_for_delegation": 16777216}
LDAP_ATTRIBUTES = tuple(sorted(set(ATTRIBUTE_MAP) | set(DATE_MAP) | set(INTERVAL_MAP) | {
    "objectguid", "objectsid", "objectclass", "useraccountcontrol", "memberof", "member", "lastlogon",
    "displayname", "ldapdisplayname",
    "grouptype", "msds-user-account-control-computed", "msds-resultantpso", "fsmoroleowner",
    "trustdirection", "trusttype", "serverreference", "fromserver", "options",
    "msds-isrodc", "msds-hasmasterncs",
    "msds-enabledfeature", "netbiosname", "ncname", "msds-passwordsettingsprecedence",
    "msds-passwordcomplexityenabled", "msds-passwordreversibleencryptionenabled",
    "siteobject", "msds-allowedtoactonbehalfofotheridentity",
}))
MULTI = frozenset({"othertelephone", "proxyaddresses", "serviceprincipalname", "sidhistory", "msds-allowedtodelegateto"})
SECTIONS = {"ad_context_base": ("directory_accounts", "directory_group_graph", "directory_exact_logon"),
            "ad_privileged_membership": ("privileged_membership",), "ad_vpn_membership": ("vpn_membership",),
            "ad_domain_posture": ("domain_posture",), "ad_domain_health": ("domain_health",)}
PROFILES = {"ad_context_base": "ad_snapshot_base_v1", "ad_privileged_membership": "privileged_membership_v1",
            "ad_vpn_membership": "vpn_security_v1", "ad_domain_posture": "domain_posture_v1",
            "ad_domain_health": "domain_health_v1"}


def _utc(value):
    if value in (None, "", 0, "0", 9223372036854775807, "9223372036854775807"):
        return None
    if isinstance(value, (int, float)) or str(value).isdecimal():
        result = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value) // 10)
    else:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("agent_ad_date_invalid")
    return result.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _values(value):
    return value if isinstance(value, list) else [] if value is None else [value]


def _stable_guid(value):
    raw = bytearray(hashlib.sha256(value.lower().encode("utf-8")).digest()[:16])
    raw[7], raw[8] = (raw[7] & 15) | 64, (raw[8] & 63) | 128
    return str(UUID(bytes_le=bytes(raw)))


def _attributes(props, kind, schema=None):
    attrs = {}
    for source, target in ATTRIBUTE_MAP.items():
        if source in props:
            value = props[source]
            attrs[target] = [str(v) for v in _values(value)] if source in MULTI else value
    if kind == "ad_user" and props.get("displayname"):
        attrs["display_name"] = props["displayname"]
    if kind in {"ad_user", "ad_computer"}:
        attrs["object_class"] = "user" if kind == "ad_user" else "computer"
        attrs["object_classes"] = [str(value) for value in _values(props.get("objectclass"))]
    for source, target in DATE_MAP.items():
        if kind not in {"ad_user", "ad_computer"} or source not in DATE_ATTRIBUTES:
            attrs[target] = _utc(props.get(source))
    for source, target in INTERVAL_MAP.items():
        if source in props:
            seconds = abs(int(props[source])) // 10_000_000
            days, remaining = divmod(seconds, 86400)
            hours, remaining = divmod(remaining, 3600)
            minutes, seconds = divmod(remaining, 60)
            attrs[target] = (f"{days}." if days else "") + f"{hours:02}:{minutes:02}:{seconds:02}"
    if kind in {"ad_user", "ad_computer"}:
        attrs.update(security_attributes(props, schema or {}, _utc))
        uac = int(props["useraccountcontrol"]) if props.get("useraccountcontrol") is not None else None
        attrs["user_account_control"] = uac
        attrs["enabled"] = not bool(uac & 2) if uac is not None else None
        attrs.update({name: bool(uac & bit) if uac is not None else None for name, bit in UAC_FLAGS.items()})
        computed = props.get("msds-user-account-control-computed")
        attrs["locked_out"] = bool(int(computed) & 16) if computed is not None else None
        attrs["password_expired"] = bool(int(computed) & 8388608) if computed is not None else None
        attrs["kerberos_preauth_required"] = not bool(uac & 4194304) if uac is not None else None
        attrs["password_expiry_status"] = "observed" if attrs["password_expiry_utc"] else "not_applicable" if uac and uac & 65536 else "missing_in_source"
        attrs["effective_password_policy_dn"] = props.get("msds-resultantpso")
        attrs["effective_password_policy_source"] = "fine_grained" if props.get("msds-resultantpso") else "default_domain"
        attrs["last_logon_utc"] = attrs["last_logon_timestamp_utc"]
    if kind == "ad_computer":
        # Provenance uses the legacy reference field names, not fabricated values.
        sources = {"enabled": "Enabled", "last_logon_utc": "LastLogonDate", "dns_host_name": "DNSHostName",
                   "operating_system": "OperatingSystem", "operating_system_version": "OperatingSystemVersion",
                   "operating_system_service_pack": "OperatingSystemServicePack", "canonical_name": "CanonicalName",
                   "description": "Description", "location": "Location", "managed_by": "ManagedBy",
                   "password_last_set_utc": "PasswordLastSet", "created_utc": "whenCreated",
                   "when_changed_utc": "whenChanged", "service_principal_names": "servicePrincipalName",
                   "trusted_for_delegation": "TrustedForDelegation", "trusted_to_auth_for_delegation": "TrustedToAuthForDelegation",
                   "user_account_control": "userAccountControl"}
        attrs["created_utc"] = attrs.get("when_created_utc")
        attrs["technical_inventory_status"] = "not_collected"
        states = {key: {"state": "present" if attrs.get(key) is not None else "absent_in_source", "source_attribute": source}
                  for key, source in sources.items()}
        attrs["attribute_states"] = {key: states[key] for key in list(sources)[:5]}
        attrs["computer_reference_attribute_states"] = states
    if kind == "ad_group":
        group_type = int(props.get("grouptype") or 0)
        attrs.update(group_category="Security" if group_type & 0x80000000 else "Distribution",
                     group_scope="Global" if group_type & 2 else "DomainLocal" if group_type & 4 else "Universal" if group_type & 8 else None)
    if kind == "domain_trust":
        attrs["trust_direction"] = {1: "Inbound", 2: "Outbound", 3: "BiDirectional"}.get(int(props.get("trustdirection") or 0), "Unknown")
        attrs["trust_type"] = {1: "Downlevel", 2: "Uplevel", 3: "MIT", 4: "DCE"}.get(int(props.get("trusttype") or 0), "Unknown")
    return attrs


def _members(props):
    if "member" in props:
        return _values(props["member"]), True
    ranges = []
    for name, values in props.items():
        match = re.fullmatch(r"member;range=(\d+)-(\d+|\*)", name)
        if match:
            ranges.append((int(match[1]), match[2], _values(values)))
    if not ranges:
        return [], True
    members, offset, terminal = [], 0, False
    for start, end, values in sorted(ranges):
        if start != offset or terminal:
            return members, False
        members.extend(values)
        terminal = end == "*"
        if not terminal and len(values) != int(end) - start + 1:
            return members, False
        offset = start + len(values)
    return members, terminal


def normalize_capture(raw, config, *, observed_at):
    """Map one source pass to existing family contracts; never infer deletions."""
    domain = raw["domain"]
    if domain["sid"] != config["domain_sid"] or domain["dns_name"].casefold() != config["domain_dns"]:
        raise ValueError("agent_ad_domain_mismatch")
    observed = observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    domain_sid = config["domain_sid"]
    search_base = config["search_bases"][0] if config["search_bases"] else domain["default_nc"]
    states = raw.get("states", {})
    section_states = {s: states.get(s, "complete") for values in SECTIONS.values() for s in values}
    records = {s: [] for s in section_states}
    objects, by_dn, by_sid = {}, {}, {}
    masked = False
    for item in raw["objects"]:
        props = {key.lower(): value for key, value in item["properties"].items()}
        masked |= any(key not in LDAP_ATTRIBUTES and not key.startswith("member;range=") for key in props)
        guid = str(UUID(props["objectguid"]))
        key = f"ad:{domain_sid.lower()}:{guid}"
        kind = item["kind"]
        classes = _values(props.get("objectclass"))
        section = "directory_group_graph" if kind == "ad_group" or "foreignSecurityPrincipal" in classes else "directory_accounts" if kind in {"ad_user", "ad_computer"} else "domain_health" if kind in {"domain_controller", "replication_link"} else "domain_posture"
        record = {"record_type": "entity", "record_key": key, "section": section, "observed_at_utc": observed,
                  "identity": {"kind": kind, "domain_sid": domain_sid, "object_guid": guid, "object_sid": props.get("objectsid")},
                  "attributes": _attributes(props, kind, raw.get("schema_attributes", {}))}
        attrs = record["attributes"]
        if kind == "domain":
            attrs["display_name"] = config["domain_dns"]
            attrs.update({name: raw.get("fsmo", {}).get(name) for name in
                          ("pdc_emulator", "rid_master", "infrastructure_master", "schema_master", "domain_naming_master")})
            attrs.update(forest_name=".".join(part[3:] for part in domain.get("forest_nc", "").split(",") if part.upper().startswith("DC=")),
                         ldap_signing_requirement="not_collected", ldap_channel_binding_requirement="not_collected")
        elif kind == "security_principal":
            attrs["infrastructure_role"] = "organizational_unit" if "organizationalUnit" in classes else "site" if "site" in classes else "security_principal"
        elif kind == "domain_controller":
            attrs.update(infrastructure_role="domain_controller", is_global_catalog=bool(int(props.get("options") or 0) & 1),
                         is_read_only=props.get("msds-isrodc"), operation_master_roles=[],
                         site_name=props.get("distinguishedname", "").split(",CN=Sites,", 1)[0].rsplit(",CN=", 1)[-1])
            attrs.update({name: "not_collected" for name in
                          ("advertising_state", "connectivity_state", "services_state", "sysvol_state", "netlogon_state", "dns_state")})
        elif kind == "replication_link":
            attrs.update(source_dc=props.get("fromserver"), destination_dc=props.get("distinguishedname", "").split(",", 1)[-1],
                         replication_state="not_collected")
        elif kind == "domain_trust":
            attrs["display_name"] = attrs.get("trust_partner") or attrs.get("display_name")
        if key in objects:
            raise ValueError("agent_ad_duplicate_object")
        objects[key] = (record, props)
        if props.get("distinguishedname"):
            by_dn[props["distinguishedname"].casefold()] = key
        if props.get("objectsid"):
            by_sid[props["objectsid"].casefold()] = key
        records[section].append(record)

    for record, _ in list(objects.values()):
        if record["identity"]["kind"] == "domain":
            stable = config["domain_dns"] + ":default-password-policy"
            policy_record = {**deepcopy(record), "record_key": f"ad-infrastructure:password_policy:{stable}",
                "identity": {"kind": "password_policy", "domain_sid": domain_sid, "object_guid": _stable_guid(stable), "object_sid": None},
                "attributes": {key: value for key, value in record["attributes"].items() if key.startswith("password_") or key.startswith("lockout_")}}
            policy_record["attributes"]["display_name"] = "Default domain policy"
            records["domain_posture"].append(policy_record)
    for item in raw.get("health", []):
        props = {key.lower(): value for key, value in item["properties"].items()}
        attrs = _attributes(props, "ad_computer")
        attrs.pop("attribute_states", None)
        attrs.pop("computer_reference_attribute_states", None)
        attrs["infrastructure_role"] = "domain_controller"
        attrs.update({key: item.get("metadata", {}).get(key) for key in
                      ("site_name", "is_global_catalog", "is_read_only", "operation_master_roles")})
        attrs.update({key: item.get("checks", {}).get(key, "not_collected") for key in
                      ("advertising_state", "connectivity_state", "services_state", "sysvol_state", "netlogon_state", "dns_state")})
        attrs["health_error_codes"] = [f"{key}_{value}" for key, value in item.get("checks", {}).items()
                                       if key in {"advertising_state", "connectivity_state", "services_state", "sysvol_state", "netlogon_state", "dns_state"}
                                       and value in {"failed", "timeout", "unavailable", "not_collected"}]
        hostname = str(props.get("dnshostname") or props.get("name"))
        records["domain_health"].append({"record_type": "entity", "record_key": f"ad-infrastructure:ad_computer:{hostname.lower()}",
            "section": "domain_health", "observed_at_utc": observed, "identity": {"kind": "ad_computer", "domain_sid": domain_sid,
                "object_guid": str(UUID(props["objectguid"])), "object_sid": props.get("objectsid")}, "attributes": attrs})
    for item in raw.get("replication", []):
        attrs = {key: item.get(key) for key in ("source_dc", "destination_dc", "naming_context", "last_replication_attempt_utc",
            "last_replication_success_utc", "consecutive_failure_count", "last_replication_result")}
        stable = "|".join(str(attrs[key]) for key in ("source_dc", "destination_dc", "naming_context"))
        attrs.update(display_name=f"{attrs['source_dc']} -> {attrs['destination_dc']}",
                     replication_state="passed" if attrs["consecutive_failure_count"] == 0 and attrs["last_replication_result"] == 0 else "failed")
        records["domain_health"].append({"record_type": "entity", "record_key": f"ad-infrastructure:replication_link:{stable.lower()}",
            "section": "domain_health", "observed_at_utc": observed, "identity": {"kind": "replication_link", "domain_sid": domain_sid,
                "object_guid": _stable_guid(stable), "object_sid": None}, "attributes": attrs})

    edges = set()
    unresolved = False
    def edge(source, target, membership="direct"):
        edges.add((source, target, membership))

    for key, (record, props) in objects.items():
        attrs = record["attributes"]
        kind = record["identity"]["kind"]
        if kind not in {"ad_user", "ad_computer", "ad_group"}:
            continue
        missing = []
        for dn in _values(props.get("memberof")):
            parent = by_dn.get(dn.casefold())
            if parent and objects[parent][0]["identity"]["kind"] == "ad_group":
                edge(key, parent)
            else:
                missing.append(dn)
                unresolved = True
        attrs["unresolved_parent_dns" if kind == "ad_group" else "unresolved_group_dns"] = missing[:256]
        if kind == "ad_group":
            members, complete = _members(props)
            unresolved |= not complete
            for dn in members:
                member = by_dn.get(dn.casefold())
                if member:
                    edge(member, key)
                else:
                    unresolved = True
                    digest = hashlib.sha256((key + "|" + dn.casefold()).encode("utf-8")).hexdigest()
                    records["directory_group_graph"].append({"record_type": "data_quality", "record_key": f"quality:unresolved-member:{digest}",
                        "section": "directory_group_graph", "observed_at_utc": observed, "classification": "DataQuality",
                        "code": "directory_group_links_unresolved", "message": "Unresolved member DN: " + dn})
            continue
        if props.get("primarygroupid") is not None:
            sid = f"{domain_sid}-{int(props['primarygroupid'])}"
            target = by_sid.get(sid.casefold())
            if target and objects[target][0]["identity"]["kind"] == "ad_group":
                edge(key, target, "primary")
            else:
                attrs["unresolved_primary_group_sid"] = sid
                unresolved = True
        # Graph endpoints must be in this bundle. Accounts already supply them.
    for source, target, membership in sorted(edges):
        records["directory_group_graph"].append({"record_type": "relation", "record_key": f"member-of:{source}:{target}:{membership}",
            "section": "directory_group_graph", "observed_at_utc": observed, "relation_kind": "member_of",
            "source_record_key": source, "target_record_key": target,
            "attributes": {"membership_type": membership, "source_section": "directory_group_graph"}})
    if unresolved:
        section_states["directory_group_graph"] = "partial"
        records["directory_group_graph"].append({"record_type": "data_quality", "record_key": "quality:directory_group_links_unresolved",
            "section": "directory_group_graph", "observed_at_utc": observed, "classification": "DataQuality",
            "code": "directory_group_links_unresolved", "message": "Unresolved references or incomplete member ranges were retained."})

    surveys = raw.get("surveys", []) if config["expensive_flags"].get("exact_last_logon", False) else []
    successful = [s for s in surveys if s["status"] == "complete"]
    failed = [s["dc"] for s in surveys if s["status"] != "complete"]
    if not config["expensive_flags"].get("exact_last_logon", False):
        section_states["directory_exact_logon"] = "skipped"
    elif failed or not successful:
        section_states["directory_exact_logon"] = "partial" if successful else "failed"
    for record, props in objects.values():
        if record["identity"]["kind"] not in {"ad_user", "ad_computer"}:
            continue
        guid = record["identity"]["object_guid"]
        values = [int(s["values"].get(guid, 0)) for s in successful]
        exact_utc = _utc(max(values, default=0))
        exact = {"exact_last_logon_utc": exact_utc,
                 "exact_last_logon_status": "not_collected" if not config["expensive_flags"].get("exact_last_logon", False) else "partial" if failed and successful else "failed" if not successful else "observed" if exact_utc else "no_record",
                 "exact_last_logon_discovered_dc_count": len(surveys), "exact_last_logon_successful_dc_count": len(successful),
                 "exact_last_logon_failed_dcs": failed[:256]}
        records["directory_exact_logon"].append({**deepcopy(record), "record_key": record["record_key"] + ":exact-logon",
                                               "section": "directory_exact_logon", "attributes": exact})
        record["attributes"].update(exact)

    optional = raw.get("optional", {})
    for record, _ in objects.values():
        if record["identity"]["kind"] != "ad_computer":
            continue
        attrs = record["attributes"]
        guid = record["identity"]["object_guid"]
        dns = optional.get("dns", {}).get("values", {}).get(guid, {})
        if config["expensive_flags"].get("dns"):
            attrs["ip_addresses"] = [str(ipaddress.ip_address(value)) for value in dns.get("value", [])][:256]
        inventory = optional.get("inventory", {}).get("values", {}).get(guid, {})
        if config["expensive_flags"].get("inventory"):
            attrs["technical_inventory_status"] = inventory.get("status", "not_evaluated")
            attrs["technical_inventory_observed_at_utc"] = observed
            attrs["logical_disks"] = [canonical({key: item[key] for key in ("device_id", "size", "free_space") if key in item}).decode("ascii")
                                      for item in inventory.get("value", [])[:64]]

    group_refs = {"privileged_membership": [], "vpn_membership": []}
    for reference in config["groups"]:
        area, _, value = reference.partition(":")
        group_refs["vpn_membership" if area == "vpn" else "privileged_membership"].append(value if area in {"vpn", "privileged"} else reference)
    for section, refs in group_refs.items():
        if not refs:
            section_states[section] = "skipped"
            continue
        targets = set()
        for reference in refs:
            target = by_sid.get(reference.casefold()) or by_dn.get(reference.casefold())
            if not target:
                section_states[section] = "partial"
            else:
                targets.add(target)
        # Walk only groups, retaining direct/primary edges. Cycles terminate
        # here; effective membership remains the existing server projector's job.
        children = {}
        for relation in records["directory_group_graph"]:
            if relation["record_type"] == "relation":
                children.setdefault(relation["target_record_key"], []).append(relation)
        pending, selected = list(targets), []
        while pending:
            target = pending.pop()
            for relation in children.get(target, []):
                selected.append(relation)
                source = relation["source_record_key"]
                if objects[source][0]["identity"]["kind"] == "ad_group" and source not in targets:
                    targets.add(source)
                    pending.append(source)
        keys = targets | {r["source_record_key"] for r in selected}
        records[section] = [{**deepcopy(objects[key][0]), "section": section} for key in sorted(keys)]
        for record in records[section]:
            record["attributes"].pop("attribute_states", None)
            record["attributes"].pop("computer_reference_attribute_states", None)
        records[section] += [{**deepcopy(r), "section": section, "attributes": {**r["attributes"], "source_section": section}} for r in selected]
        if section_states["directory_group_graph"] != "complete":
            section_states[section] = "partial"

    if masked:
        records["directory_accounts"].append({"record_type": "data_quality", "record_key": "quality:sensitive_fields_masked",
            "section": "directory_accounts", "observed_at_utc": observed, "classification": "DataQuality",
            "code": "sensitive_fields_masked", "message": "Unallowlisted source fields were excluded before persistence."})

    families = {}
    for family in config["families"]:
        if family == "computers_v6":
            from sli_agent.ad_snapshot_computers import computer_snapshot
            snapshot = computer_snapshot([r for r, _ in objects.values() if r["identity"]["kind"] == "ad_computer"],
                                         config=config, observed=observed, query_dc=raw.get("query_dc") or config["domain_dns"], search_base=search_base, optional=optional)
            families[family] = (snapshot, len(snapshot["objects"]))
            continue
        sections = SECTIONS[family]
        scope = {"search_base": search_base, "collection_profile": PROFILES[family],
                 "privileged_group_sids": [], "vpn_group_sids": []}
        for s, scope_key in (("privileged_membership", "privileged_group_sids"), ("vpn_membership", "vpn_group_sids")):
            if s in sections:
                references = group_refs[s]
                root_keys = {by_sid.get(ref.casefold()) or by_dn.get(ref.casefold()) for ref in references}
                scope[scope_key] = sorted({r["identity"]["object_sid"] for r in records[s]
                    if r["record_type"] == "entity" and r["record_key"] in root_keys and r["identity"].get("object_sid")})
                if not scope[scope_key] and references:
                    section_states[s] = "failed"
                    records[s] = []
        family_records = [r for s in sections for r in records[s]]
        if family == "ad_context_base":
            scope["computer_membership_collected"] = section_states["directory_group_graph"] == "complete"
        bundle = {"schema_version": "ad-context-bundle/v1", "source_pack_id": "sli.windows.ad-context", "source_pack_version": "0.9.0",
                  "run_id": str(uuid4()), "mode": "full" if not config["search_bases"] else "targeted",
                  "domain": {"sid": domain_sid, "dns_name": config["domain_dns"]}, "scope": scope,
                  "observed_at_utc": observed, "records": family_records,
                  "sections": [{"name": s, "status": section_states[s], "record_count": len(records[s]), "duration_ms": 0,
                                "error_code": None if section_states[s] == "complete" else "not_collected" if section_states[s] == "skipped" else "collection_incomplete"} for s in sections]}
        families[family] = (bundle, len(family_records))
    attribute_limit = any(
        (isinstance(value, str) and len(value) > 4096) or (isinstance(value, list) and (
            len(value) > 256 or any(not isinstance(item, str) or len(item) > 4096 for item in value)))
        for family, (data, _) in families.items() if family != "computers_v6"
        for record in data["records"] for value in record.get("attributes", {}).values()
    )
    if (attribute_limit or sum(count for _, count in families.values()) > config["max_objects"]
            or sum(len(canonical(data)) for family, (data, _) in families.items() if family != "computers_v6") > config["max_bytes"]):
        # Do not ship a truncated entity/edge graph that could be mistaken for
        # absence. Keep an explicit bounded partial receipt for every family.
        for family, (data, _) in list(families.items()):
            if family == "computers_v6":
                data["objects"] = []
                data["metadata"].update(object_count=0, collection_status="failed", errors=["agent_ad_size_limit"])
                next(s for s in data["metadata"]["sources"] if s["name"] == "ad")["status"] = "partial"
            else:
                data["records"] = []
                data["mode"] = "targeted"
                data["scope"]["privileged_group_sids"] = []
                data["scope"]["vpn_group_sids"] = []
                data["scope"]["computer_membership_collected"] = False
                for section in data["sections"]:
                    section.update(status="skipped" if section["name"] in {"privileged_membership", "vpn_membership"} or section["status"] == "skipped" else "partial", error_code="agent_ad_size_limit", record_count=0)
            families[family] = (data, 0)
        if sum(len(canonical(data)) for family, (data, _) in families.items() if family != "computers_v6") > config["max_bytes"]:
            raise ValueError("agent_ad_size_limit")
    return families


class PowerShellDirectoryReader:
    """No credentials, source files or diagnostic text; cancellation kills reader."""
    script_path = Path(__file__).with_suffix(".ps1")
    error_prefix = "agent_ad"
    @staticmethod
    def _terminate(process):
        if os.name == "nt":
            binary = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/taskkill.exe"
            try:
                subprocess.run([str(binary), "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if process.poll() is None:
            process.kill()

    def __call__(self, config, *, deadline, stop):
        executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        try:
            process = subprocess.Popen([str(executable), "-NoProfile", "-NonInteractive", "-File",
                str(self.script_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError:
            raise ValueError(self.error_prefix + "_capture_failed") from None
        done = threading.Event()
        result = bytearray()
        error = []
        def read():
            try:
                while block := process.stdout.read(65536):
                    if len(result) + len(block) > 64 * 1024**2:
                        error.append(self.error_prefix + "_size_limit")
                        self._terminate(process)
                        break
                    result.extend(block)
            finally:
                done.set()
        worker = threading.Thread(target=read, daemon=True)
        worker.start()
        try:
            request = {**config, "ldap_attributes": LDAP_ATTRIBUTES}
            process.stdin.write(canonical(request))
            process.stdin.close()
            while not done.wait(0.1):
                if stop.is_set() or time.monotonic() >= deadline:
                    raise ValueError(self.error_prefix + "_capture_cancelled")
            process.wait(timeout=max(0.1, deadline - time.monotonic()))
            if error or process.returncode:
                raise ValueError(error[0] if error else self.error_prefix + "_capture_failed")
            return json.loads(result.decode("utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError, subprocess.TimeoutExpired):
            raise ValueError(self.error_prefix + "_capture_failed") from None
        finally:
            if process.poll() is None:
                self._terminate(process)
            process.wait()
            worker.join(timeout=1)
            process.stdout.close()


class ADSnapshotModule(SnapshotModule):
    def __init__(self, config, *, reader=None):
        super().__init__("sli.ad-snapshot", config)
        self.reader = reader or PowerShellDirectoryReader()

    def capture(self, config, *, deadline, stop):
        if stop.is_set() or time.monotonic() >= deadline:
            raise ValueError("agent_ad_capture_cancelled")
        raw = self.reader(config, deadline=deadline, stop=stop)
        if stop.is_set() or time.monotonic() >= deadline:
            raise ValueError("agent_ad_capture_cancelled")
        try:
            if isinstance(raw, str):
                raw = json.loads(raw)
            return normalize_capture(raw, config, observed_at=datetime.now(timezone.utc))
        except (ValueError, TypeError, KeyError, OverflowError):
            raise ValueError("agent_ad_capture_invalid") from None

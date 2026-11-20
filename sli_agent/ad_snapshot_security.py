# SPDX-License-Identifier: Apache-2.0
"""Non-secret daily directory evidence; missing reads remain unknown."""
from __future__ import annotations

import re


RBCD_ATTRIBUTE = "msds-allowedtoactonbehalfofotheridentity"
DATE_ATTRIBUTES = {
    "pwdlastset": "password_last_set",
    "mslaps-passwordexpirationtime": "laps_password_expiration",
    "ms-mcs-admpwdexpirationtime": "legacy_laps_password_expiration",
}


def security_attributes(props, schema, utc):
    attrs = {}
    for source, target in DATE_ATTRIBUTES.items():
        value = props.get(source)
        status = "schema_absent" if schema.get(source) == "absent" else "not_returned"
        stamp = None
        if value is not None:
            try:
                if isinstance(value, bool) or isinstance(value, (int, float)) and value < 0:
                    raise ValueError("agent_ad_filetime_invalid")
                stamp = utc(value)
                status = "observed" if stamp else "not_set"
            except (ValueError, OverflowError, TypeError):
                status = "parse_error"
        attrs[target + "_utc"] = stamp
        attrs[target + "_status"] = status

    value = props.get(RBCD_ATTRIBUTE)
    present, sids, digest = None, None, None
    status = "schema_absent" if schema.get(RBCD_ATTRIBUTE) == "absent" else "not_returned"
    if isinstance(value, bool):
        # Older agents only captured presence, never trustee information.
        present = value
        status = "not_collected" if value else "observed"
        sids = None if value else []
    elif value is not None:
        status = "parse_error"
        if isinstance(value, dict) and value.get("present") is True:
            present = True
            candidate = value.get("descriptor_sha256")
            if isinstance(candidate, str) and re.fullmatch(r"[0-9a-f]{64}", candidate):
                digest = candidate
            candidate = value.get("sids")
            if (value.get("status") in {"observed", "partial"}
                    and isinstance(candidate, list) and len(candidate) <= 256
                    and all(isinstance(sid, str) and len(sid) <= 256
                            and re.fullmatch(r"S-1-(?:\d+-)+\d+", sid) for sid in candidate)):
                sids = sorted(set(candidate))
                status = value["status"]
    attrs.update(resource_based_delegation_present=present,
                 resource_based_delegation_sids=sids,
                 resource_based_delegation_status=status,
                 resource_based_delegation_descriptor_sha256=digest)
    return attrs

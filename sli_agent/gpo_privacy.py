# SPDX-License-Identifier: Apache-2.0
"""GPO-specific masking before capture/spool, independent of the backend."""
from __future__ import annotations

import hashlib
import re

from sli_agent.envelope import canonical

HIDDEN = "значение скрыто"
SENSITIVE = re.compile(
    r"password|cpassword|passwd|pwd|secret|privatekey|token|credential|apikey|accesskey|"
    r"sharedkey|presharedkey|psk|encryptionkey|decryptionkey|symmetrickey|signingkey|"
    r"keymaterial|passphrase|connectionstring"
)
RAW = frozenset({"rawxml", "rawsysvol", "xml", "xmltext", "sysvolcontent", "script", "scriptcontent", "scriptbody"})
NAMED = frozenset({"name", "key", "valuename", "property", "setting_name", "path", "source_xml_path"})
VALUES = frozenset({"value", "values", "value_display", "data", "text", "valuedata", "defaultvalue", "properties"})
ASSIGNMENT = re.compile(r'''(?:^|[\s;,{<])["']?(?P<name>[\w.:-]+)["']?\s*(?:=|:)\s*["']?(?P<label>[\w.:-]+)?''')
SCRIPT_REFERENCE = re.compile(r'''(?i)^[^\r\n";<>]+\.(?:ps1|psm1|cmd|bat|vbs|js|wsf|exe)$''')


def sensitive(name):
    return bool(SENSITIVE.search(re.sub(r"[^a-z0-9]", "", name.lower())))


def sensitive_value(value):
    return (bool(re.search(r"-----BEGIN .*PRIVATE KEY-----", value, re.I)) or any(
        sensitive(m["name"]) or (m["name"].lower() in NAMED and m["label"] and sensitive(m["label"]))
        for m in ASSIGNMENT.finditer(value)))


def script_value(value):
    # A filename is normalized metadata, never the content of that file.
    return isinstance(value, str) and (not value or bool(SCRIPT_REFERENCE.fullmatch(value)))


def mask_gpo(value, *, registry=False):
    """Drop raw blobs; keep registry paths and redaction evidence, never secrets."""
    if isinstance(value, list):
        return [mask_gpo(item, registry=registry) for item in value]
    if not isinstance(value, dict):
        if isinstance(value, (bytes, bytearray)):
            return HIDDEN
        if isinstance(value, str) and (value.lstrip().startswith("<") or sensitive_value(value)):
            return HIDDEN
        return value
    named = any(isinstance(item, str) and sensitive(item) for key, item in value.items() if key.lower() in NAMED)
    script = any(isinstance(value.get(key), str) and re.search(r"(?i)(?:^|/)scripts?(?:/|$)", value[key])
                 for key in ("kind", "path", "source_xml_path"))
    registry_fact = str(value.get("kind") or "").casefold() == "registry" or any(
        isinstance(value.get(key), str) and re.search(r"(?i)(?:^|/)registry(?:/|$)", value[key])
        for key in ("path", "source_xml_path"))
    result = {}
    for key, item in value.items():
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized in RAW or normalized.startswith("rawsysvol") or normalized.startswith("rawxml"):
            continue
        if key in {"redacted_fields", "sensitive_value_present", "truncated_fields"}:
            result[key] = item
        elif sensitive(key) or (normalized == "key" and not registry and isinstance(item, str) and not re.match(
                r"(?i)^(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|Software|System)(?:\\|$)", item)) or (named and key.lower() in VALUES) or (
                script and key.lower() in VALUES | {"command", "arguments", "parameters"} and not script_value(item)):
            result[key] = None if item is None else HIDDEN
        elif key.lower() == "source_state" and named and isinstance(item, dict):
            result[key] = {name: HIDDEN if name in {"value", "detail", "error"} and data is not None else mask_gpo(data)
                           for name, data in item.items()}
        else:
            result[key] = mask_gpo(item, registry=registry_fact and key.lower() == "properties")
    # Governance properties forbid sensitive keys; preserve ordinary hashes.
    if {"scope", "kind", "properties", "sha256"} <= value.keys():
        props = value["properties"]
        if not isinstance(props, dict):
            raise ValueError("agent_gpo_settings_invalid")
        removed = {key.lower() for key in props if sensitive(key) or re.sub(r"[^a-z0-9]", "", key.lower()) in RAW}
        cleaned = {key: item for key, item in mask_gpo(props, registry=registry_fact).items() if key.lower() not in removed}
        if named or script:
            cleaned = {key: HIDDEN if key.lower() in VALUES | {"command", "arguments", "parameters"} and (
                       named or not script_value(item)) else item
                       for key, item in cleaned.items()}
        result["properties"] = cleaned
        if cleaned != props:
            fields = removed | {key.lower() for key in cleaned if cleaned[key] != props[key]}
            result["redacted_fields"] = sorted(set(value.get("redacted_fields", [])) | {
                field for field in fields if sensitive(field)} | ({"secret"} if any(not sensitive(field) for field in fields) else set()))
            result["truncated_fields"] = [field for field in value.get("truncated_fields", []) if field in cleaned]
            result["sensitive_value_present"] = True
            hashed = {key: result[key] for key in ("scope", "kind", "path", "properties", "redacted_fields",
                "truncated_fields", "sensitive_value_present")}
            result["sha256"] = hashlib.sha256(canonical(hashed)).hexdigest()
    return result

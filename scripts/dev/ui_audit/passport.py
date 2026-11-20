#!/usr/bin/env python3
"""Fail-closed admission of a structured L06 dataset; never print source values.

Candidates are directories containing manifest.json and JSON/JSONL exports only.
Opaque dumps, SQL, screenshots and archives cannot be certified by this scanner.
Identity values must be replaced with anon_<category>_<number> tokens; free text
must be removed or replaced with [redacted]. This deliberately conservative
format needs no reverse mapping and supports both synthetic and anonymized data.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from pathlib import Path

VERSION = "sli.audit-passport.v1"
CATEGORIES = ("names", "logins", "emails", "ips", "dns", "hostnames", "sids", "free_text", "secrets")
FIELD_PATTERNS = {
    "names": r"(^|_)(name|displayname|givenname|surname|owner|person)($|_)",
    "logins": r"login|username|samaccountname|userprincipalname|account_name",
    "emails": r"email|mail",
    "ips": r"(^|_)(ip|address|clientaddress|callingstationid)($|_)",
    "dns": r"(^|_)(dn|distinguishedname)($|_)",
    "hostnames": r"hostname|computer|fqdn|domain|server|workstation",
    "sids": r"(^|_)sid($|_)",
    "free_text": r"text|description|message|xml|payload|evidence|comment|note",
    "secrets": r"password|secret|token|credential|api_key|private_key|hash",
}
PATTERNS = {
    "emails": r"[^\s@]+@[^\s@]+",
    "dns": r"(?i)(?:CN|OU|DC)\s*=",
    "hostnames": r"(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b",
    "sids": r"(?i)\bS-\d-\d+(?:-\d+)+\b",
    "secrets": r"(?i)bearer\s+|-----BEGIN .*PRIVATE KEY|(?:password|secret|token)\s*[:=]",
}
TOKEN = re.compile(r"anon_(?:name|login|email|ip|dn|host|sid|domain|id)_\d+")
SAFE_CODES = frozenset({"ok", "empty", "partial", "stale", "not_collected", "processing", "denied", "error",
                        "available", "unavailable", "enabled", "disabled", "active", "closed",
                        "low", "medium", "high", "critical", "info", "warning", "danger", "synthetic"})
MAPPING = re.compile(r"(?i)mapping|reident|pseudonym.*map|original|real_value|source_value|reverse_map")


def field_category(key: str) -> str | None:
    key = re.sub(r"(?<=[a-z])(?=[A-Z])", "_", key).lower()
    compact = key.replace("_", "")
    order = ("secrets", "logins", "emails", "dns", "sids", "ips", "hostnames", "names", "free_text")
    # Joining words can turn counters such as not_evaluated into a "note" field.
    return next((category for category in order if re.search(FIELD_PATTERNS[category], key)
                 or (category != "free_text" and re.search(FIELD_PATTERNS[category], compact))), None)


def verify_dataset(candidate: Path) -> dict:
    findings: dict[str, int] = {}

    def fail(category):
        findings[category] = findings.get(category, 0) + 1

    digest = hashlib.sha256()
    manifest = {}
    transformed = []
    files = []
    try:
        if candidate.is_symlink() or not candidate.is_dir():
            raise ValueError("invalid candidate")
        files = sorted(candidate.rglob("*"))
        for file in files:
            if file.is_symlink():
                fail("symlink")
            if MAPPING.search(file.name):
                fail("mapping_present")
        manifest = json.loads((candidate / "manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("invalid manifest")
        transformed = manifest.get("transformed_fields", [])
        if manifest.get("mapping_present") is True:
            fail("mapping_present")
        if set(manifest) != {"dataset_id", "snapshot_version", "kind", "mapping_present", "transformed_fields"}:
            fail("manifest")
        if (manifest.get("kind") not in {"synthetic", "anonymized"}
                or manifest.get("mapping_present") is not False
                or not all(re.fullmatch(r"[a-z0-9_-]{1,64}", str(manifest.get(k, ""))) for k in ("dataset_id", "snapshot_version"))
                or not isinstance(transformed, list) or not transformed):
            fail("manifest")
            transformed = []
        categories = set()
        for entry in transformed:
            if (not isinstance(entry, dict) or set(entry) != {"category", "method", "field"} or entry.get("category") not in CATEGORIES
                    or entry.get("method") not in {"removed", "tokenized", "synthetic", "redacted"}
                    or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", str(entry.get("field", "")))):
                fail("transformed_fields")
            else:
                categories.add(entry["category"])
        if categories != set(CATEGORIES):
            fail("transformed_fields")
    except (OSError, ValueError, TypeError):
        fail("manifest")

    def scan(value, key="", field=""):
        if isinstance(value, dict):
            for k, v in value.items():
                if MAPPING.search(k):
                    fail("mapping_present")
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                    fail("field_name")
                scan(v, k, f"{field}.{k}".strip("."))
        elif isinstance(value, list):
            for item in value:
                scan(item, key, field)
        elif isinstance(value, str) and value:
            category = field_category(key)
            if category and not any(e.get("field") == field and e.get("category") == category
                                    for e in transformed if isinstance(e, dict)):
                fail("undeclared_transformation")
            if value == "[redacted]":
                return
            if category == "secrets":
                fail("secrets")
                return
            if TOKEN.fullmatch(value):
                return
            if not category and (value in SAFE_CODES or re.fullmatch(
                    r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", value)):
                return
            for kind, pattern in PATTERNS.items():
                if re.search(pattern, value):
                    fail(kind)
            # IPv4 and IPv6, including embedded addresses in arbitrary text.
            for part in re.findall(r"[0-9a-fA-F:.%]+", value):
                try:
                    ipaddress.ip_address(part)
                except ValueError:
                    continue
                fail("ips")
            if category:
                fail(category)
            elif value not in SAFE_CODES and not re.fullmatch(
                    r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", value):
                fail("free_text")
        elif value is not None and not isinstance(value, str):
            category = field_category(key)
            if category and (category == "secrets" or not key.endswith("_id")):
                fail(category)

    count = 0
    for file in files:
        if not file.is_file() or file.is_symlink():
            continue
        relative = file.relative_to(candidate).as_posix()
        try:
            raw = file.read_bytes()
            digest.update(relative.encode() + b"\0" + raw + b"\0")
            if relative == "manifest.json":
                continue
            if file.suffix not in {".json", ".jsonl"}:
                fail("unsupported_format")
                continue
            records = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()] if file.suffix == ".jsonl" else [json.loads(raw)]
            for value in records:
                scan(value)
                count += 1
        except (OSError, ValueError, UnicodeError, RecursionError):
            fail("unreadable_data")
    if not count:
        fail("empty_dataset")
    return {"schema": VERSION, "status": "fail" if findings else "pass",
            "dataset_id": manifest.get("dataset_id") if not findings else None,
            "snapshot_version": manifest.get("snapshot_version") if not findings else None,
            "sha256": digest.hexdigest(), "transformed_fields": transformed if not findings else [],
            "scan": {category: "fail" if findings.get(category) else "pass" for category in CATEGORIES},
            "mapping_present": bool(findings.get("mapping_present")), "findings": findings}


def require_passport(candidate: Path, passport: Path) -> dict:
    current = verify_dataset(candidate)
    saved = json.loads(passport.read_text(encoding="utf-8"))
    if current["status"] != "pass" or saved != current:
        raise ValueError("dataset_passport_rejected")
    return current


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    from scripts.dev.ui_audit.stand import require_external_path
    require_external_path(args.out)
    if args.out.resolve().is_relative_to(args.candidate.resolve()):
        parser.error("passport must be outside the candidate")
    result = verify_dataset(args.candidate)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "findings": result["findings"]}))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())

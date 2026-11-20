from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.dev.ui_audit.passport import CATEGORIES, require_passport, verify_dataset


FIELDS = dict(zip(CATEGORIES, ("display_name", "login", "email", "ip", "dn", "hostname", "sid", "description", "password"), strict=True))


@pytest.fixture
def candidate(tmp_path: Path) -> Path:
    folder = tmp_path / "candidate"
    folder.mkdir()
    manifest = {"dataset_id": "synthetic_1", "snapshot_version": "v1", "kind": "synthetic", "mapping_present": False,
                "transformed_fields": [{"category": category, "field": f"records.{field}", "method": "synthetic"}
                                       for category, field in FIELDS.items()]}
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    write_records(folder, {"id": 1, "display_name": "anon_name_1", "login": "anon_login_1",
                           "email": "anon_email_1", "ip": "anon_ip_1", "dn": "anon_dn_1",
                           "hostname": "anon_host_1", "sid": "anon_sid_1", "description": "[redacted]",
                           "password": None, "status": "available", "observed_at": "2026-10-07T00:00:00.123Z"})
    return folder


def write_records(folder, record):
    (folder / "records.json").write_text(json.dumps({"records": [record]}), encoding="utf-8")


@pytest.mark.parametrize("kind", ["synthetic", "anonymized"])
def test_passport_passes_only_transformed_structured_dataset(candidate, tmp_path, kind):
    manifest = json.loads((candidate / "manifest.json").read_text())
    manifest["kind"] = kind
    (candidate / "manifest.json").write_text(json.dumps(manifest))
    result = verify_dataset(candidate)
    assert result["status"] == "pass"
    assert result["scan"] == dict.fromkeys(CATEGORIES, "pass")
    assert len(result["transformed_fields"]) == len(CATEGORIES)
    passport = tmp_path / "passport.json"
    passport.write_text(json.dumps(result))
    assert require_passport(candidate, passport) == result


@pytest.mark.parametrize("field,value,category", [
    ("display_name", "Synthetic Person", "names"), ("login", "synthetic_login", "logins"),
    ("email", "synthetic@example.test", "emails"), ("ip", "192.0.2.1", "ips"),
    ("ip", "2001:db8::1", "ips"), ("dn", "CN=Synthetic,DC=example,DC=test", "dns"),
    ("hostname", "synthetic-host", "hostnames"), ("hostname", "host.example.test", "hostnames"),
    ("sid", "S-1-5-21-1-2-3-1001", "sids"), ("description", "Synthetic unrestricted message", "free_text"),
    ("password", "anon_login_1", "secrets"), ("password", 123, "secrets"),
    ("unexpected", "Bearer synthetic-secret", "secrets"), ("unexpected", "synthetic@example.test", "emails"),
    ("unexpected", "prefix 192.0.2.1 suffix", "ips"),
])
def test_residual_values_fail_without_disclosing_values(candidate, field, value, category):
    write_records(candidate, {field: value})
    result = verify_dataset(candidate)
    assert result["status"] == "fail"
    assert result["scan"][category] == "fail"
    if isinstance(value, str):
        assert value not in json.dumps(result)


@pytest.mark.parametrize("change", ["extra_mapping_file", "embedded_mapping", "manifest_mapping", "undeclared", "opaque", "malformed"])
def test_rejects_mapping_incomplete_transformations_and_unscannable_data(candidate, change):
    if change == "extra_mapping_file":
        (candidate / "reverse_mapping.json").write_text("{}")
    elif change == "embedded_mapping":
        write_records(candidate, {"original": "anon_name_1"})
    elif change == "manifest_mapping":
        manifest = json.loads((candidate / "manifest.json").read_text())
        manifest["reverse_mapping"] = {}
        (candidate / "manifest.json").write_text(json.dumps(manifest))
    elif change == "undeclared":
        write_records(candidate, {"nested": {"display_name": "anon_name_1"}})
    elif change == "opaque":
        (candidate / "database.dump").write_bytes(b"opaque")
    else:
        (candidate / "records.json").write_text("{")
    assert verify_dataset(candidate)["status"] == "fail"


def test_rejects_changed_dataset_and_forged_pass(candidate, tmp_path):
    passport = tmp_path / "passport.json"
    result = verify_dataset(candidate)
    passport.write_text(json.dumps(result))
    write_records(candidate, {"id": 2})
    with pytest.raises(ValueError, match="passport_rejected"):
        require_passport(candidate, passport)
    write_records(candidate, {"email": "synthetic@example.test"})
    forged = verify_dataset(candidate)
    forged["status"] = "pass"
    passport.write_text(json.dumps(forged))
    with pytest.raises(ValueError, match="passport_rejected"):
        require_passport(candidate, passport)


def test_jsonl_and_symlinks(candidate, tmp_path):
    (candidate / "records.jsonl").write_text('{"status":"ok"}\n', encoding="utf-8")
    assert verify_dataset(candidate)["status"] == "pass"
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (candidate / "linked.json").symlink_to(outside)
    assert verify_dataset(candidate)["status"] == "fail"


def test_declared_reverse_mapping_is_a_failure(candidate):
    manifest = json.loads((candidate / "manifest.json").read_text())
    manifest["mapping_present"] = True
    (candidate / "manifest.json").write_text(json.dumps(manifest))
    result = verify_dataset(candidate)
    assert result["status"] == "fail"
    assert result["mapping_present"] is True

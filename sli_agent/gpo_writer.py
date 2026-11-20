# SPDX-License-Identifier: Apache-2.0
"""Local GPO writer boundary, stage 1: diagnostics only, no AD write commands.

This has its own configuration and service identity. It is deliberately not a
collector module and cannot receive scripts or commands from the platform.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from uuid import UUID


STATUSES = frozenset({"available", "denied", "unavailable", "not_applicable"})
BASE_CHECKS = ("identity", "domain", "gpo_create", "gpt_create", "gpo_edit", "gpo_acl", "gpt_edit", "package")
REASONS = frozenset({"verified", "access_denied", "read_failed", "identity_rejected", "domain_mismatch",
    "scope_rejected", "no_managed_gpo", "signature_invalid", "local_protection_failed"})


def _guid(value):
    if not isinstance(value, str):
        raise ValueError("gpo_writer_config_invalid")
    result = str(UUID(value))
    if UUID(result).int == 0:
        raise ValueError("gpo_writer_config_invalid")
    return result


@dataclass(frozen=True)
class WriterConfig:
    domain_dns: str
    domain_sid: str
    dc: str
    writer_sid: str
    allowed_ou_guids: tuple[str, ...]
    msi_path: str
    msi_sha256: str
    signer_sha256: str
    managed_gpo_guid: str | None = None

    def __post_init__(self):
        try:
            for name in (self.domain_dns, self.dc):
                if not isinstance(name, str) or len(name) > 253 or not re.fullmatch(
                        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+", name):
                    raise ValueError()
            if not re.fullmatch(r"S-1-5-21-\d+-\d+-\d+", self.domain_sid):
                raise ValueError()
            if (not re.fullmatch(re.escape(self.domain_sid) + r"-\d+", self.writer_sid)
                    or int(self.writer_sid.rsplit("-", 1)[1]) < 1000):
                raise ValueError()
            if not isinstance(self.allowed_ou_guids, tuple) or not 1 <= len(self.allowed_ou_guids) <= 128:
                raise ValueError()
            guids = tuple(_guid(value) for value in self.allowed_ou_guids)
            if len(set(guids)) != len(guids):
                raise ValueError()
            object.__setattr__(self, "allowed_ou_guids", guids)
            if self.managed_gpo_guid is not None:
                object.__setattr__(self, "managed_gpo_guid", _guid(self.managed_gpo_guid))
            path = PureWindowsPath(self.msi_path)
            if (not isinstance(self.msi_path, str) or not path.is_absolute() or path.drive.startswith("\\")
                    or path.suffix.lower() != ".msi" or ".." in path.parts
                    or ":" in str(path)[2:] or "\x00" in str(path)):
                raise ValueError()
            if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                   for value in (self.msi_sha256, self.signer_sha256)):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ValueError("gpo_writer_config_invalid") from None

    @classmethod
    def load(cls, path):
        try:
            body = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            if not isinstance(body, dict) or not isinstance(body.get("allowed_ou_guids"), list):
                raise ValueError()
            body["allowed_ou_guids"] = tuple(body["allowed_ou_guids"])
            return cls(**body)
        except (OSError, ValueError, TypeError):
            raise ValueError("gpo_writer_config_invalid") from None

    def payload(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


def expected_checks(config):
    # Results carry only ordinal references, never OU names, DNs, SIDs or GUIDs.
    return (*BASE_CHECKS, *(f"ou_{index}" for index in range(len(config.allowed_ou_guids))))


def unavailable(config, reason="read_failed"):
    return {key: {"status": "unavailable", "reason": reason} for key in expected_checks(config)}


class WindowsPreflightReader:
    def inspect(self, config):
        if os.name != "nt":
            raise RuntimeError("gpo_writer_windows_required")
        executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        script = Path(__file__).with_suffix(".ps1")
        result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-File", str(script)],
            input=json.dumps(config.payload()), capture_output=True, text=True, encoding="utf-8", timeout=90,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode or len(result.stdout) > 65536:
            raise RuntimeError("gpo_writer_read_failed")
        return json.loads(result.stdout)


def preflight(config, *, reader=None):
    try:
        raw = (reader or WindowsPreflightReader()).inspect(config)
    except Exception:
        # Native/LDAP exception text can contain source identities and paths.
        raw = unavailable(config)
    checks = []
    for key in expected_checks(config):
        value = raw.get(key) if isinstance(raw, dict) else None
        status, reason = "unavailable", "read_failed"
        if (isinstance(value, dict) and isinstance(value.get("status"), str) and value["status"] in STATUSES
                and isinstance(value.get("reason"), str) and value["reason"] in REASONS):
            status, reason = value["status"], value["reason"]
            # Only existing-GPO checks may be skipped, and only in create mode.
            if status == "not_applicable" and not (config.managed_gpo_guid is None
                    and key in {"gpo_edit", "gpo_acl", "gpt_edit"} and reason == "no_managed_gpo"):
                status, reason = "unavailable", "read_failed"
            if status == "available" and reason != "verified":
                status, reason = "unavailable", "read_failed"
        required = not (config.managed_gpo_guid is not None and key in {"gpo_create", "gpt_create"})
        checks.append({"check": key, "status": status, "reason": reason, "required": required})
    return {"schema_version": 1, "mode": "read_only", "write_enabled": False,
        "observed_at": datetime.now(timezone.utc).isoformat(), "allowed_ou_count": len(config.allowed_ou_guids),
        "ready": all(not row["required"] or row["status"] in {"available", "not_applicable"} for row in checks),
        "checks": checks}


def main(argv=None):
    parser = argparse.ArgumentParser(description="SLI GPO writer: read-only preflight")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = preflight(WriterConfig.load(args.config))
    except Exception:
        print('{"ready":false,"write_enabled":false,"error_code":"gpo_writer_config_invalid"}')
        return 1
    print(json.dumps(report, ensure_ascii=True))
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

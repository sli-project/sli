# SPDX-License-Identifier: Apache-2.0
"""Small local configuration, deliberately independent of server settings."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID


def validate_instance_name(value):
    if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", value)):
        raise ValueError("agent_config_invalid")
    return value


def service_name(instance=None):
    validate_instance_name(instance)
    return "SLIAgent" if instance is None else "SLI-Agent-" + instance


def machine_config_path(instance=None):
    import os
    root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SLI" / "Agent"
    if instance is not None:
        root = root / "instances" / service_name(instance)
    return root / "agent.json"


@dataclass(frozen=True)
class AgentConfig:
    server_url: str
    ca_bundle: Path
    state_dir: Path
    collection_enabled: bool = False
    event_channels: tuple[dict, ...] = field(default_factory=tuple)
    spool_max_bytes: int = 64 * 1024 * 1024
    spool_max_age_seconds: int = 7 * 86400
    renew_before_seconds: int = 3 * 86400
    interval_seconds: int = 60
    update_root: Path | None = None
    update_trust_store: Path | None = None
    service_python: Path | None = None
    instance_name: str | None = None
    host_id: str | None = None
    service_identity_sid: str | None = None
    allow_missing_rights: bool = False
    # Installation preview only; never enables a collector without server assignment.
    probe_modules: tuple[dict, ...] = field(default_factory=tuple)
    ca_fingerprint: str | None = None

    def __post_init__(self):
        if self.ca_fingerprint is not None and (not isinstance(self.ca_fingerprint, str) or
                re.fullmatch(r"[0-9a-f]{64}", self.ca_fingerprint) is None):
            raise ValueError("agent_config_invalid")
        validate_instance_name(self.instance_name)
        # Named instances share an operator-provisioned opaque host UUID, never
        # a writable machine-wide identity file or another instance's state.
        if self.instance_name is not None and self.host_id is None:
            raise ValueError("agent_config_invalid")
        if self.host_id is not None:
            try:
                object.__setattr__(self, "host_id", str(UUID(self.host_id)))
            except (ValueError, TypeError, AttributeError):
                raise ValueError("agent_config_invalid") from None
        try:
            url = urlsplit(self.server_url)
            port = url.port
            valid = (url.scheme == "https" and url.hostname and not url.username and not url.password
                     and not url.query and not url.fragment and url.path in ("", "/")
                     and (port is None or 1 <= port <= 65535))
        except (ValueError, TypeError):
            valid = False
        limits = (self.spool_max_bytes, self.spool_max_age_seconds, self.renew_before_seconds, self.interval_seconds)
        if not valid or type(self.collection_enabled) is not bool or any(type(n) is not int or n <= 0 for n in limits):
            raise ValueError("agent_config_invalid")
        if not isinstance(self.event_channels, tuple) or len(self.event_channels) > 32:
            raise ValueError("agent_config_invalid")
        if (type(self.allow_missing_rights) is not bool or
                self.service_identity_sid is not None and (
                    not isinstance(self.service_identity_sid, str) or
                    re.fullmatch(r"S-1-\d+(?:-\d+){1,15}", self.service_identity_sid) is None) or
                not isinstance(self.probe_modules, tuple) or len(self.probe_modules) > 64):
            raise ValueError("agent_config_invalid")
        object.__setattr__(self, "ca_bundle", Path(self.ca_bundle))
        object.__setattr__(self, "state_dir", Path(self.state_dir))
        update_fields = (self.update_root, self.update_trust_store, self.service_python)
        if any(p is not None for p in update_fields) and any(p is None for p in update_fields):
            raise ValueError("agent_config_invalid")
        if self.update_root is not None:
            root, trust, interpreter = Path(self.update_root), Path(self.update_trust_store), Path(self.service_python)
            state = self.state_dir.resolve()
            if (not root.is_absolute() or not trust.is_absolute() or not interpreter.is_absolute() or not self.state_dir.is_absolute()
                    or not self.ca_bundle.is_absolute()
                    or state.is_relative_to(root.resolve()) or root.resolve().is_relative_to(state)
                    or trust.resolve().is_relative_to(root.resolve()) or trust.resolve().is_relative_to(state)
                    or interpreter.resolve().is_relative_to(root.resolve()) or interpreter.resolve().is_relative_to(state)):
                raise ValueError("agent_config_invalid")
            object.__setattr__(self, "update_root", root)
            object.__setattr__(self, "update_trust_store", trust)
            object.__setattr__(self, "service_python", interpreter)

    @property
    def release_root(self):
        if self.update_root is None or self.instance_name is None:
            return self.update_root
        return self.update_root / "instances" / service_name(self.instance_name)

    @property
    def storage_dir(self):
        if self.instance_name is None:
            return self.state_dir
        return self.state_dir / "instances" / service_name(self.instance_name)

    @classmethod
    def load(cls, path: Path):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(body, dict):
                raise ValueError()
            body["event_channels"] = tuple(body.get("event_channels", ()))
            body["probe_modules"] = tuple(body.get("probe_modules", ()))
            return cls(**body)
        except (OSError, ValueError, TypeError, KeyError):
            raise ValueError("agent_config_invalid") from None

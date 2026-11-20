"""Shared, content-bound native evidence identity; never a fabricated event ID."""
from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID


class EvidenceRefError(RuntimeError):
    """Fixed codes only; source identifiers and database errors stay private."""


@dataclass(frozen=True, repr=False)
class EvidenceScope:
    installation_id: str
    plugin_id: str
    source_instance_id: str
    source_generation: str
    collection_scope_id: str = ""

    def __post_init__(self):
        try:
            valid = str(UUID(self.installation_id)) == self.installation_id
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid or any(
            not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= limit
            for value, limit in ((self.plugin_id, 128), (self.source_instance_id, 256),
                                 (self.source_generation, 512))
        ) or (not isinstance(self.collection_scope_id, str)
              or self.collection_scope_id != self.collection_scope_id.strip()
              or len(self.collection_scope_id) > 256):
            raise EvidenceRefError("evidence_scope_invalid")


@dataclass(frozen=True, repr=False)
class EvidenceRef:
    """Hash of the core normalized row, WS observation, or FS native payload.

    These hash domains are distinguished by storage_kind. The WS verifier also
    checks the XML digest retained in that immutable observation. Cold-only or
    expired sources without a supported verifier block new publication.
    """

    storage_kind: str
    native_id: str
    sha256: str
    scope: EvidenceScope

    def __post_init__(self):
        plugins = {"core_event": "sli.windows.ad-dc", "workstation_observation": "sli.workstations",
                   "file_audit_observation": "sli.file-audit", "file_audit_snapshot": "sli.file-audit"}
        if (not isinstance(self.storage_kind, str) or self.storage_kind not in plugins
                or not isinstance(self.scope, EvidenceScope)
                or (self.scope.plugin_id != plugins[self.storage_kind]
                    and not (self.storage_kind == "core_event" and self.scope.plugin_id == "sli.vpn-nps"))):
            raise EvidenceRefError("evidence_type_unsupported")
        if (not isinstance(self.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.sha256)
                or not isinstance(self.native_id, str)):
            raise EvidenceRefError("evidence_reference_invalid")
        if self.storage_kind == "core_event":
            valid = bool(re.fullmatch(r"[1-9][0-9]{0,18}", self.native_id)) and int(self.native_id) < 2**63
        elif self.storage_kind == "file_audit_snapshot":
            try:
                valid = str(UUID(self.native_id)) == self.native_id
            except ValueError:
                valid = False
            valid = valid and bool(re.fullmatch(r"audit-command:[a-zA-Z0-9_-]{1,128}",
                                                self.scope.source_generation))
        else:
            valid = bool(re.fullmatch(r"[0-9a-f]{64}", self.native_id))
        if (not valid or (self.storage_kind in {"file_audit_observation", "file_audit_snapshot"})
                != bool(self.scope.collection_scope_id)):
            raise EvidenceRefError("evidence_reference_invalid")

    @property
    def params(self):
        return (self.scope.installation_id, self.scope.plugin_id, self.scope.source_instance_id,
                self.scope.source_generation, self.scope.collection_scope_id,
                self.storage_kind, self.native_id, self.sha256)

"""Stable identities and observation contracts; unknown facts stay unknown."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from uuid import UUID

from sli_agent.file_audit_policy import EVENT_IDS, OPTIONAL_EVENT_IDS, PROVIDER

PLUGIN_ID = "sli.file-audit"
VERSION = "1.0.0"
SCHEMA = "sli_plugin_file_audit"
REPORT_KEYS = ("overview", "actions", "mass-operations", "permission-changes",
               "access-denials", "out-of-hours", "permissions", "audit-state")
CAPABILITIES = {"view": "file-audit.view", "export": "file-audit.export",
                "manage_audit": "file-audit.audit.manage"}
RETENTION = {"source_payload_days": 7, "facts": "permanent", "acl_history_days": 365,
             "file_event_cleanup_enabled": False}


def _text(value, limit=256):
    return isinstance(value, str) and 0 < len(value) <= limit and value.strip() == value and not any(ord(c) < 32 for c in value)


@dataclass(frozen=True)
class EvidenceIdentity:
    agent_id: str
    source_instance_id: str
    generation: str
    record_id: int
    event_id: int
    event_version: int = 0
    channel: str = "Security"
    provider: str = PROVIDER

    def __post_init__(self):
        try:
            valid_agent = isinstance(self.agent_id, str) and str(UUID(self.agent_id)) == self.agent_id
        except ValueError:
            valid_agent = False
        if (not valid_agent or not _text(self.source_instance_id) or not _text(self.generation)
                or type(self.record_id) is not int or not 1 <= self.record_id <= 9223372036854775807
                or type(self.event_id) is not int or self.event_id not in (*EVENT_IDS, *OPTIONAL_EVENT_IDS)
                or type(self.event_version) is not int or not 0 <= self.event_version <= 255
                or self.channel != "Security" or self.provider != PROVIDER):
            raise ValueError("file_audit_evidence_identity_invalid")

    @property
    def key(self):
        # Agent/source provenance is part of identity, not the delivery packet ID.
        value = [self.agent_id, self.source_instance_id, self.channel, self.generation, self.record_id]
        return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class FileObservation:
    evidence: EvidenceIdentity
    policy_revision: str
    collection_scope_id: str
    payload_sha256: str
    observed_at_utc: str
    outcome: str = "unknown"
    correlation_state: str = "not_attempted"

    def __post_init__(self):
        try:
            observed = datetime.fromisoformat(self.observed_at_utc) if isinstance(self.observed_at_utc, str) else None
        except ValueError:
            observed = None
        if (not isinstance(self.evidence, EvidenceIdentity) or not _text(self.policy_revision, 16)
                or not re.fullmatch(r"[1-9][0-9]{0,15}", self.policy_revision)
                or int(self.policy_revision) > 9007199254740991
                or not _text(self.collection_scope_id)
                or observed is None or observed.utcoffset() != timezone.utc.utcoffset(observed)
                or not isinstance(self.payload_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", self.payload_sha256)
                or not isinstance(self.outcome, str) or self.outcome not in ("unknown", "success", "failure")
                or not isinstance(self.correlation_state, str)
                or self.correlation_state not in ("not_attempted", "complete", "partial", "ambiguous")):
            raise ValueError("file_audit_observation_invalid")


def report_contracts():
    """Published data/access contracts; publication never assigns user grants."""
    from server.sli.plugins.file_audit.report_intents import report_intent

    return tuple({"report_key": f"file-audit.{key}", "dataset_id": f"file-audit.{key}",
                  "contract_id": "sli.report-result.v2", "contract_version": "2.0.0",
                  "status": "published", "actions": ("view", "export"),
                  "field_categories": ("identity_basic", "technical", "security", "privilege"),
                  "intent": report_intent(key)}
                 for key in REPORT_KEYS)

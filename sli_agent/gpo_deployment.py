# SPDX-License-Identifier: Apache-2.0
"""Stage 5 local phase journal; not a command receiver or an AD implementation.

There is deliberately no native adapter or production dispatch here. Execution
must stay disabled until the credential-bound transport, PostgreSQL domain
lease and native assertion/readback adapters have been accepted. The adapters
below are exercised with fakes only; their success is not LAB acceptance.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import UUID, uuid4

from sli_agent.gpo_links import LinkConflict
from sli_agent.protection import atomic_write, directory_lock


PHASES = ("create_disabled", "filter", "gpt", "versions", "links", "readback", "enable")
DELETE_PHASES = ("revoke", "disable", "unlink", "delete_gpo", "delete_gpt", "absent")
_HASH = re.compile(r"[0-9a-f]{64}")
_STATUSES = {"applying", "configured", "partial", "conflict", "blocked", "deleting", "deleted"}
_REASONS = {"verified", "interrupted", "access_denied", "response_lost", "expired",
    "identity_rejected", "readback_failed", "state_conflict", "operation_failed", "revocation_failed"}


class DeploymentError(ValueError):
    def __init__(self, code):
        super().__init__(code if code in _REASONS else "operation_failed")


def _uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value and UUID(value).int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Binding:
    installation_id: str
    domain_id: int
    actor: str
    operation_id: str
    plan_sha256: str
    credential_id: str
    credential_revision: int
    recipient_sha256: str
    principal_sha256: str
    # None is the preview of an absent object; an update binds exact readback.
    expected_state_sha256: str | None
    issued_at: int
    expires_at: int

    def __post_init__(self):
        if (any(not _uuid(value) for value in (self.installation_id, self.operation_id, self.credential_id))
                or type(self.domain_id) is not int or self.domain_id <= 0
                or not isinstance(self.actor, str) or not re.fullmatch(r"session:[1-9][0-9]*", self.actor)
                or type(self.credential_revision) is not int or self.credential_revision <= 0
                or any(not isinstance(value, str) or not _HASH.fullmatch(value)
                    for value in (self.plan_sha256, self.recipient_sha256, self.principal_sha256))
                or self.expected_state_sha256 is not None and (not isinstance(self.expected_state_sha256, str)
                    or not _HASH.fullmatch(self.expected_state_sha256))
                or type(self.issued_at) is not int or self.issued_at < 0 or type(self.expires_at) is not int
                or not 0 < self.expires_at - self.issued_at <= 300):
            raise DeploymentError("state_conflict")

    @property
    def sha256(self):
        return _digest(asdict(self))


@dataclass(frozen=True)
class SessionProof:
    binding_sha256: str
    ldap_principal_sha256: str
    sysvol_principal_sha256: str


@dataclass(frozen=True)
class OwnedState:
    owner_sha256: str
    state_sha256: str


class Journal:
    """One protected, atomically replaced registry per installation/domain.

    The lock is local only. A future dispatcher must additionally hold its
    durable PostgreSQL domain lease. No password, envelope, batch token, native
    error, DN or UNC path is accepted into this journal.
    """

    def __init__(self, root, installation_id, domain_id):
        if not _uuid(installation_id) or type(domain_id) is not int or domain_id <= 0:
            raise DeploymentError("state_conflict")
        self.installation_id, self.domain_id = installation_id, domain_id
        self.base = Path(root)
        self.root = self.base / installation_id / str(domain_id)
        self.path = self.root / "gpo.json"

    @contextmanager
    def locked(self):
        # Do not follow a redirected scope directory, even when the final
        # directory itself is not a symlink. The configured base is trusted.
        for path in (self.base, self.base / self.installation_id, self.root):
            if path.is_symlink() or path.is_junction():
                raise DeploymentError("state_conflict")
        with directory_lock(self.root):
            yield

    def load(self):
        if self.path.is_symlink() or self.path.is_junction():
            raise DeploymentError("state_conflict")
        if not self.path.exists():
            return {"schema_version": 1, "installation_id": self.installation_id,
                "domain_id": self.domain_id, "gpo_guid": str(uuid4()), "operations": {}}
        try:
            if not self.path.is_file() or self.path.stat().st_size > 1_048_576:
                raise ValueError()
            record = json.loads(self.path.read_bytes())
            if (set(record) != {"schema_version", "installation_id", "domain_id", "gpo_guid", "operations"}
                    or record["schema_version"] != 1 or record["installation_id"] != self.installation_id
                    or record["domain_id"] != self.domain_id or not _uuid(record["gpo_guid"])
                    or not isinstance(record["operations"], dict) or len(record["operations"]) > 1000):
                raise ValueError()
            for operation, row in record["operations"].items():
                if (not _uuid(operation) or not isinstance(row, dict)
                        or set(row) != {"binding_sha256", "status", "phase", "reason"}
                        or not isinstance(row["binding_sha256"], str) or not _HASH.fullmatch(row["binding_sha256"])
                        or row["status"] not in _STATUSES or row["phase"] not in (*PHASES, *DELETE_PHASES, None)
                        or row["reason"] not in _REASONS):
                    raise ValueError()
            return record
        except (OSError, ValueError, TypeError, KeyError):
            raise DeploymentError("state_conflict") from None

    def save(self, record):
        atomic_write(self.path, json.dumps(record, sort_keys=True).encode("ascii"))


def _guard(session, binding, clock):
    now = clock()
    if not binding.issued_at <= now < binding.expires_at:
        raise DeploymentError("expired")
    proof = session.check(binding)
    if proof != SessionProof(binding.sha256, binding.principal_sha256, binding.principal_sha256):
        raise DeploymentError("identity_rejected")
    # Reauthorization may block on remote reads. Do not start a phase on a
    # credential that expired during the check.
    if not binding.issued_at <= clock() < binding.expires_at:
        raise DeploymentError("expired")


def _reason(exc):
    if isinstance(exc, DeploymentError):
        return str(exc)
    if isinstance(exc, PermissionError):
        return "access_denied"
    if isinstance(exc, TimeoutError):
        return "response_lost"
    if isinstance(exc, LinkConflict):
        return "state_conflict"
    return "operation_failed"


def execute(binding, *, journal, session, clock=time.time):
    """Drive fixed phases under a previously authenticated, bound session.

    session.inspect(guid) returns OwnedState or None. session.perform and
    session.verify must enforce the exact signed plan, conditional versions,
    ownership, narrow filter, verified signatures and lossless link assertions.
    create_disabled must create both configurations disabled, with no links;
    it must never adopt an existing object. enable is permitted only after full
    readback. Compensation requires a NEW preview of the actual remainder;
    this driver never replays a saved gPLink or blindly deletes an object.
    """
    if (type(binding) is not Binding or binding.installation_id != journal.installation_id
            or binding.domain_id != journal.domain_id):
        raise DeploymentError("state_conflict")
    with journal.locked():
        record = journal.load()
        operations = record["operations"]
        previous = operations.get(binding.operation_id)
        if previous:
            if previous["binding_sha256"] != binding.sha256:
                raise DeploymentError("state_conflict")
            if previous["status"] == "applying":
                # A restart is not permission to repeat an ambiguous write.
                previous.update(status="partial", reason="interrupted")
                journal.save(record)
            return dict(previous)
        if len(operations) >= 1000 or any(row["status"] in {"applying", "deleting", "deleted"}
                or row["phase"] in DELETE_PHASES for row in operations.values()):
            # Deletion blocks future installation commands, including after a
            # partial delete. Re-creation needs a new confirmed policy instance.
            raise DeploymentError("state_conflict")
        row = {"binding_sha256": binding.sha256, "status": "applying", "phase": None, "reason": "verified"}
        operations[binding.operation_id] = row
        # Persist the GUID BEFORE any possible AD write or lost create reply.
        journal.save(record)
        guid = record["gpo_guid"]
        owner = _digest([binding.installation_id, binding.domain_id, guid])
        writes_started = False
        try:
            _guard(session, binding, clock)
            state = session.inspect(guid)
            if state is None:
                if binding.expected_state_sha256 is not None:
                    raise DeploymentError("state_conflict")
            elif (not isinstance(state, OwnedState) or state.owner_sha256 != owner
                    or state.state_sha256 != binding.expected_state_sha256):
                raise DeploymentError("state_conflict")
            for phase in PHASES:
                _guard(session, binding, clock)
                row["phase"] = phase
                journal.save(record)
                # 'create_disabled' on update means conditionally disabling
                # only our computer configuration, preserving the same GUID.
                writes_started = True
                session.perform(phase, guid, owner)
                _guard(session, binding, clock)
                if session.verify(phase, guid, owner) is not True:
                    raise DeploymentError("readback_failed")
            _guard(session, binding, clock)
            row.update(status="configured", reason="verified")
        except Exception as exc:
            reason = _reason(exc)
            row.update(status="partial" if writes_started else "conflict" if reason == "state_conflict" else "blocked",
                reason=reason)
        journal.save(record)
        return dict(row)

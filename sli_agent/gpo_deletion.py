# SPDX-License-Identifier: Apache-2.0
"""Stage 7 deletion kernel, using the stage 5 protected domain journal.

No native adapter, command receiver or production dispatch is enabled here.
The authenticated credential transport, durable server-side policy registry /
lease, revocation and pinned-DC readback adapters are required for LAB use.
An adapter fake passing these tests is not evidence of an AD deletion.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from sli_agent.gpo_deployment import (
    DELETE_PHASES, Binding, DeploymentError, _HASH, _digest, _guard, _reason, _uuid,
)


@dataclass(frozen=True)
class DeleteBinding(Binding):
    gpo_guid: str
    ou_entity_ids: tuple[int, ...]
    # Bind action as well as account, revision, recipient, scope and readback.
    action: str = field(default="delete", init=False)

    def __post_init__(self):
        super().__post_init__()
        if (not _uuid(self.gpo_guid) or self.expected_state_sha256 is None
                or not isinstance(self.ou_entity_ids, tuple) or not 1 <= len(self.ou_entity_ids) <= 128
                or any(type(value) is not int or not 0 < value < 2**63 for value in self.ou_entity_ids)
                or tuple(sorted(set(self.ou_entity_ids))) != self.ou_entity_ids):
            raise DeploymentError("state_conflict")


@dataclass(frozen=True)
class DeleteState:
    """Readback of BOTH owned artifacts and every actual incoming GPO link.

    The adapter verifies signed ownership/registry/GPT path, ACLs, versions,
    files and reparse points. state_sha256 covers that evidence AND all links,
    including links outside the requested OUs. No name-based adoption or
    partial domain search is allowed. With no artifacts, ownership is attested
    by the protected registry; an absent GPC alone does not prove deletion.
    """
    owner_sha256: str
    state_sha256: str
    gpo_exists: bool
    gpt_exists: bool
    link_ou_entity_ids: tuple[int, ...]

    @property
    def absent(self):
        return not self.gpo_exists and not self.gpt_exists and not self.link_ou_entity_ids


@dataclass(frozen=True)
class RevocationProof:
    binding_sha256: str
    gpo_guid: str
    tokens_revoked: bool
    commands_blocked: bool


def _binding(binding, journal):
    if (not isinstance(binding, DeleteBinding) or binding.installation_id != journal.installation_id
            or binding.domain_id != journal.domain_id):
        raise DeploymentError("state_conflict")


def _record(binding, journal):
    # Losing the registry is never permission to discover/adopt a GPO by name.
    if not journal.path.exists():
        raise DeploymentError("state_conflict")
    record = journal.load()
    if record["gpo_guid"] != binding.gpo_guid:
        raise DeploymentError("state_conflict")
    return record


def _inspect(session, binding, owner, *, expected=False):
    state = session.inspect_delete(binding.gpo_guid)
    if (not isinstance(state, DeleteState) or state.owner_sha256 != owner
            or not isinstance(state.state_sha256, str) or not _HASH.fullmatch(state.state_sha256)
            or type(state.gpo_exists) is not bool or type(state.gpt_exists) is not bool
            or not isinstance(state.link_ou_entity_ids, tuple)
            or any(type(value) is not int or not 0 < value < 2**63 for value in state.link_ou_entity_ids)
            or len(set(state.link_ou_entity_ids)) != len(state.link_ou_entity_ids)
            or not set(state.link_ou_entity_ids) <= set(binding.ou_entity_ids)
            or expected and state.state_sha256 != binding.expected_state_sha256):
        raise DeploymentError("state_conflict")
    return state


def preview(binding, *, journal, session, clock=time.time):
    """Read-only validation of the selected account and exact deletion scope.

    session.check must reauthorize Operations in AD and deletion (not creation)
    rights on this GPO/GPT and ALL links, using this credential revision only.
    The caller must persist/audit and explicitly confirm this bound preview
    before obtaining a one-shot credential session for execute().
    """
    _binding(binding, journal)
    with journal.locked():
        _record(binding, journal)
        try:
            _guard(session, binding, clock)
            owner = _digest([binding.installation_id, binding.domain_id, binding.gpo_guid])
            state = _inspect(session, binding, owner, expected=True)
            _guard(session, binding, clock)
        except Exception as exc:
            raise DeploymentError(_reason(exc)) from None
        return {"binding_sha256": binding.sha256, "gpo_guid": binding.gpo_guid,
            "gpo_exists": state.gpo_exists, "gpt_exists": state.gpt_exists,
            "link_ou_entity_ids": list(state.link_ou_entity_ids), "write_enabled": False}


def execute(binding, *, journal, session, revoker, clock=time.time):
    """Revoke first, then disable, unlink, remove the owned GPC/GPT, read back.

    revoker.revoke_and_block must atomically and durably block future policy
    commands, revoke ALL its group tokens, pending approvals and credential
    commands, and commit the audit under the server's domain lease. It must
    authenticate this binding independently of AD availability. It must never
    revoke installed agent certificates or issue uninstall commands.

    session.perform_delete must assert ownership/current versions on each
    mutation. unlink uses lossless pinned-DC compare/exchange; delete_gpo must
    NOT use an API that silently removes links outside the confirmed scope.
    delete_gpt removes only verified owned files; unexpected files stop it.
    After a failure/restart, only a NEW confirmation of the actual remainder
    may continue. There is no automatic replay or account/service fallback.
    """
    _binding(binding, journal)
    with journal.locked():
        record = _record(binding, journal)
        operations = record["operations"]
        previous = operations.get(binding.operation_id)
        if previous:
            if previous["binding_sha256"] != binding.sha256:
                raise DeploymentError("state_conflict")
            if previous["status"] == "deleting":
                previous.update(status="partial", reason="interrupted")
                journal.save(record)
            return dict(previous)
        if len(operations) >= 1000 or any(row["status"] in {"applying", "deleting"} for row in operations.values()):
            raise DeploymentError("state_conflict")
        row = {"binding_sha256": binding.sha256, "status": "deleting", "phase": None, "reason": "verified"}
        operations[binding.operation_id] = row
        journal.save(record)
        started = False
        owner = _digest([binding.installation_id, binding.domain_id, binding.gpo_guid])
        try:
            if not binding.issued_at <= clock() < binding.expires_at:
                raise DeploymentError("expired")
            row["phase"] = "revoke"
            journal.save(record)
            # A lost revocation reply is partial even if AD was never touched.
            started = True
            proof = revoker.revoke_and_block(binding)
            if (not isinstance(proof, RevocationProof)
                    or proof != RevocationProof(binding.sha256, binding.gpo_guid, True, True)
                    or proof.tokens_revoked is not True or proof.commands_blocked is not True):
                raise DeploymentError("revocation_failed")
            _guard(session, binding, clock)
            state = _inspect(session, binding, owner, expected=True)
            for phase in DELETE_PHASES[1:]:
                _guard(session, binding, clock)
                row["phase"] = phase
                journal.save(record)
                # A fresh readback of a remainder may already lack either
                # object. Do not try to recreate it just to delete it again.
                needed = {"disable": state.gpo_exists, "unlink": bool(state.link_ou_entity_ids),
                    "delete_gpo": state.gpo_exists, "delete_gpt": state.gpt_exists, "absent": False}[phase]
                if phase in {"delete_gpo", "delete_gpt"}:
                    state = _inspect(session, binding, owner)
                    if state.link_ou_entity_ids:
                        raise DeploymentError("state_conflict")
                    needed = state.gpo_exists if phase == "delete_gpo" else state.gpt_exists
                if needed:
                    _guard(session, binding, clock)
                    session.perform_delete(phase, binding.gpo_guid, owner)
                _guard(session, binding, clock)
                if session.verify_delete(phase, binding.gpo_guid, owner) is not True:
                    raise DeploymentError("readback_failed")
                state = _inspect(session, binding, owner)
                if (phase == "unlink" and state.link_ou_entity_ids
                        or phase == "delete_gpo" and state.gpo_exists
                        or phase in {"delete_gpt", "absent"} and not state.absent):
                    raise DeploymentError("readback_failed")
            _guard(session, binding, clock)
            row.update(status="deleted", reason="verified")
        except Exception as exc:
            reason = _reason(exc)
            row.update(status="partial" if started else "blocked", reason=reason)
        journal.save(record)
        return dict(row)

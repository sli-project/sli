"""Deletion kernel with fake credentials, revocation and AD; no DB or LAB."""
import json
from dataclasses import asdict, replace

import pytest

from sli_agent import gpo_deletion as subject
from sli_agent import gpo_deployment as deployment
from sli_agent.gpo_links import LinkConflict
from tests.unit.test_agent_gpo_deployment import CREDENTIAL, INSTALLATION, OPERATION, PRIVATE, SECOND, binding


GPO = "50000000-0000-4000-8000-000000000001"


def delete_binding(**changes):
    return subject.DeleteBinding(**(asdict(binding(expected_state_sha256="d" * 64))
        | {"gpo_guid": GPO, "ou_entity_ids": (2, 3)} | changes))


class Session:
    def __init__(self, journal):
        self.journal = journal
        self.owner = deployment._digest([INSTALLATION, 1, GPO])
        self.state = subject.DeleteState(self.owner, "d" * 64, True, True, (2, 3))
        self.foreign = {"gpo": "unchanged", "gpt": "unchanged", "links": "unchanged"}
        self.installed_agents = {"service": "running", "certificate": "valid", "buffer": "preserved"}
        self.calls = []
        self.now = 1010
        self.checks = 0
        self.bad_identity = None
        self.denied = False
        self.fail_phase = None
        self.failure = PermissionError(PRIVATE)
        self.crash = None
        self.bad_readback = None
        self.expire_on_check = None
        self.new_link_after_unlink = False
        self.credential_revision = 1

    def check(self, plan):
        self.checks += 1
        if self.expire_on_check == self.checks:
            self.now = 1300
        if self.denied or plan.credential_revision != self.credential_revision:
            raise PermissionError(PRIVATE)
        proof = deployment.SessionProof(plan.sha256, plan.principal_sha256, plan.principal_sha256)
        return replace(proof, **self.bad_identity) if self.bad_identity else proof

    def inspect_delete(self, guid):
        assert guid == GPO
        self.calls.append("inspect")
        return self.state

    def perform_delete(self, phase, guid, owner):
        assert guid == GPO and owner == self.owner
        record = self.journal.load()
        assert any(row["status"] == "deleting" and row["phase"] == phase for row in record["operations"].values())
        self.calls.append(phase)
        if phase == self.crash:
            raise SystemExit()
        if phase == self.fail_phase:
            raise self.failure
        if phase == "unlink":
            self.state = replace(self.state, link_ou_entity_ids=(2,) if self.new_link_after_unlink else ())
        elif phase == "delete_gpo":
            self.state = replace(self.state, gpo_exists=False)
        elif phase == "delete_gpt":
            self.state = replace(self.state, gpt_exists=False)

    def verify_delete(self, phase, guid, owner):
        self.calls.append("verify:" + phase)
        if phase == self.bad_readback:
            return False
        return True


class Revoker:
    def __init__(self, session):
        self.session = session
        self.calls = 0
        self.failure = None
        self.proof_change = {}
        self.revoked = False
        self.commands_blocked = False

    def revoke_and_block(self, plan):
        self.calls += 1
        self.session.calls.append("revoke")
        row = self.session.journal.load()["operations"][plan.operation_id]
        assert row["status"] == "deleting" and row["phase"] == "revoke"
        if self.failure:
            raise self.failure
        self.revoked = self.commands_blocked = True
        return replace(subject.RevocationProof(plan.sha256, plan.gpo_guid, True, True), **self.proof_change)


@pytest.fixture
def setup(tmp_path):
    journal = deployment.Journal(tmp_path, INSTALLATION, 1)
    with journal.locked():
        record = journal.load()
        record["gpo_guid"] = GPO
        journal.save(record)
    session = Session(journal)
    return journal, session, Revoker(session)


def execute(setup, plan=None):
    journal, session, revoker = setup
    return subject.execute(plan or delete_binding(), journal=journal, session=session, revoker=revoker,
        clock=lambda: session.now)


def test_preview_is_read_only_and_lists_all_actual_links_and_artifacts(setup):
    journal, session, revoker = setup
    before = journal.path.read_bytes()
    result = subject.preview(delete_binding(), journal=journal, session=session, clock=lambda: session.now)
    assert result == {"binding_sha256": delete_binding().sha256, "gpo_guid": GPO, "gpo_exists": True,
        "gpt_exists": True, "link_ou_entity_ids": [2, 3], "write_enabled": False}
    assert session.calls == ["inspect"] and revoker.calls == 0
    assert journal.path.read_bytes() == before


def test_order_revokes_before_directory_then_removes_only_owned_objects_and_leaves_agent(setup):
    journal, session, revoker = setup
    assert execute(setup)["status"] == "deleted"
    assert [phase for phase in session.calls if phase in deployment.DELETE_PHASES] == [
        "revoke", "disable", "unlink", "delete_gpo", "delete_gpt"]
    assert session.state.absent and revoker.revoked and revoker.commands_blocked
    assert session.calls.index("verify:unlink") < session.calls.index("delete_gpo")
    assert session.calls.index("verify:delete_gpo") < session.calls.index("delete_gpt")
    assert session.foreign == {"gpo": "unchanged", "gpt": "unchanged", "links": "unchanged"}
    assert session.installed_agents == {"service": "running", "certificate": "valid", "buffer": "preserved"}
    row = journal.load()["operations"][OPERATION]
    assert row["phase"] == "absent" and row["reason"] == "verified"


def test_retries_return_receipt_without_new_writes_or_ttl_even_after_credential_removal(setup):
    journal, session, revoker = setup
    first = execute(setup)
    calls = list(session.calls)
    session.now, session.denied = 9999, True
    assert execute(setup) == first
    assert session.calls == calls and revoker.calls == 1
    assert len(journal.load()["operations"]) == 1


@pytest.mark.parametrize("change", [{"credential_id": SECOND}, {"credential_revision": 2},
    {"ou_entity_ids": (2,)}, {"recipient_sha256": "f" * 64}, {"plan_sha256": "e" * 64}, {"expires_at": 1299}])
def test_rebinding_same_operation_never_selects_another_credential_or_scope(setup, change):
    execute(setup)
    _, session, revoker = setup
    calls = list(session.calls)
    with pytest.raises(deployment.DeploymentError, match="state_conflict"):
        execute(setup, delete_binding(**change))
    assert session.calls == calls and revoker.calls == 1


@pytest.mark.parametrize("phase", deployment.DELETE_PHASES[1:-1])
@pytest.mark.parametrize("error,reason", [(PermissionError(PRIVATE), "access_denied"),
    (TimeoutError(PRIVATE), "response_lost"), (LinkConflict(), "state_conflict"),
    (RuntimeError(PRIVATE), "operation_failed")])
def test_failure_is_partial_with_phase_and_does_not_restore_tokens_or_repeat(setup, phase, error, reason):
    journal, session, revoker = setup
    session.fail_phase, session.failure = phase, error
    result = execute(setup)
    assert result == {"binding_sha256": delete_binding().sha256, "status": "partial", "phase": phase, "reason": reason}
    assert revoker.revoked and revoker.commands_blocked
    calls = list(session.calls)
    assert execute(setup) == result and session.calls == calls
    assert PRIVATE not in journal.path.read_text() and PRIVATE not in json.dumps(result)


@pytest.mark.parametrize("error", [TimeoutError(PRIVATE), PermissionError(PRIVATE), RuntimeError(PRIVATE)])
def test_failed_or_ambiguous_revocation_prevents_all_ad_actions(setup, error):
    _, session, revoker = setup
    revoker.failure = error
    result = execute(setup)
    assert result["status"] == "partial" and result["phase"] == "revoke"
    assert session.calls == ["revoke"]


@pytest.mark.parametrize("change", [{"tokens_revoked": False}, {"commands_blocked": False},
    {"tokens_revoked": 1}, {"commands_blocked": 1}, {"binding_sha256": "f" * 64}, {"gpo_guid": SECOND}])
def test_incomplete_or_foreign_revocation_receipt_cannot_authorize_delete(setup, change):
    _, session, revoker = setup
    revoker.proof_change = change
    result = execute(setup)
    assert result["status"] == "partial" and result["reason"] == "revocation_failed"
    assert session.calls == ["revoke"]


@pytest.mark.parametrize("case", ["removed", "insufficient", "replaced"])
def test_unusable_selected_credential_never_falls_back_or_reports_deleted(setup, case):
    _, session, revoker = setup
    session.denied = case != "replaced"
    session.credential_revision = 2 if case == "replaced" else 1
    result = execute(setup)
    assert result["status"] == "partial" and result["reason"] == "access_denied"
    assert session.calls == ["revoke"] and revoker.revoked
    assert session.state.gpo_exists and session.state.gpt_exists


@pytest.mark.parametrize("field", ["binding_sha256", "ldap_principal_sha256", "sysvol_principal_sha256"])
def test_ambient_or_mixed_identity_never_reaches_ad(setup, field):
    _, session, _ = setup
    session.bad_identity = {field: "f" * 64}
    result = execute(setup)
    assert result["status"] == "partial" and result["reason"] == "identity_rejected"
    assert session.calls == ["revoke"]


@pytest.mark.parametrize("change", [{"owner_sha256": "f" * 64}, {"state_sha256": "e" * 64},
    {"link_ou_entity_ids": (2, 3, 4)}, {"link_ou_entity_ids": (2, 2)}, {"gpt_exists": None}])
def test_foreign_policy_drift_or_out_of_scope_link_stops_before_any_ad_mutation(setup, change):
    _, session, _ = setup
    session.state = replace(session.state, **change)
    result = execute(setup)
    assert result["status"] == "partial" and result["reason"] == "state_conflict"
    assert session.calls == ["revoke", "inspect"]


def test_incoming_link_remaining_after_unlink_prevents_object_deletion(setup):
    _, session, _ = setup
    session.new_link_after_unlink = True
    result = execute(setup)
    assert result["status"] == "partial" and result["phase"] == "unlink"
    assert not {"delete_gpo", "delete_gpt"} & set(session.calls)
    assert session.state.gpo_exists and session.state.gpt_exists


@pytest.mark.parametrize("phase", deployment.DELETE_PHASES[1:])
def test_failed_readback_at_any_phase_cannot_report_deleted(setup, phase):
    _, session, _ = setup
    session.bad_readback = phase
    result = execute(setup)
    assert result["status"] == "partial" and result["phase"] == phase and result["reason"] == "readback_failed"


@pytest.mark.parametrize("phase", deployment.DELETE_PHASES[1:-1])
def test_process_death_requires_new_preview_and_never_replays_uncertain_write(setup, phase):
    journal, session, revoker = setup
    session.crash = phase
    with pytest.raises(SystemExit):
        execute(setup)
    assert journal.load()["operations"][OPERATION]["status"] == "deleting"
    calls = list(session.calls)
    result = execute(setup)
    assert result["status"] == "partial" and result["reason"] == "interrupted"
    assert session.calls == calls and revoker.calls == 1


@pytest.mark.parametrize("gpo,gpt,links,expected", [(False, True, (), ["delete_gpt"]),
    (True, False, (), ["disable", "delete_gpo"]), (False, False, (), []),
    (False, False, (2,), ["unlink"])])
def test_new_confirmation_can_clean_exact_remainder_without_recreating_missing_objects(setup, gpo, gpt, links, expected):
    _, session, _ = setup
    session.fail_phase = "delete_gpo"
    assert execute(setup)["status"] == "partial"
    session.state = replace(session.state, gpo_exists=gpo, gpt_exists=gpt, link_ou_entity_ids=links)
    session.fail_phase = None
    session.calls.clear()
    assert execute(setup, delete_binding(operation_id=SECOND))["status"] == "deleted"
    assert [call for call in session.calls if call in deployment.DELETE_PHASES] == ["revoke", *expected]


@pytest.mark.parametrize("now", [999, 1300, 1301])
def test_expired_confirmation_cannot_revoke_or_touch_ad(setup, now):
    _, session, revoker = setup
    session.now = now
    result = execute(setup)
    assert result["status"] == "blocked" and result["reason"] == "expired"
    assert not session.calls and not revoker.calls


@pytest.mark.parametrize("check", [1, 2, 5, 10, 15])
def test_expiry_during_reauthorization_keeps_revocation_but_stops_before_next_write(setup, check):
    _, session, revoker = setup
    session.expire_on_check = check
    result = execute(setup)
    assert result["status"] == "partial" and result["reason"] == "expired" and revoker.revoked
    assert "verify:absent" not in session.calls


def test_missing_registry_or_wrong_registered_guid_cannot_delete_by_name(setup):
    journal, session, revoker = setup
    with pytest.raises(deployment.DeploymentError, match="state_conflict"):
        execute(setup, delete_binding(gpo_guid=SECOND))
    journal.path.unlink()
    with pytest.raises(deployment.DeploymentError, match="state_conflict"):
        execute(setup)
    assert not session.calls and not revoker.calls


def test_create_or_update_cannot_resume_after_partial_or_completed_delete(setup):
    journal, session, _ = setup
    session.fail_phase = "delete_gpt"
    assert execute(setup)["status"] == "partial"
    with pytest.raises(deployment.DeploymentError, match="state_conflict"):
        deployment.execute(binding(operation_id=SECOND), journal=journal, session=session)
    session.fail_phase = None
    assert execute(setup, delete_binding(operation_id=SECOND))["status"] == "deleted"
    with pytest.raises(deployment.DeploymentError, match="state_conflict"):
        deployment.execute(binding(), journal=journal, session=session)


@pytest.mark.parametrize("phase", [None, "revoke", "unlink", "delete_gpt"])
def test_durable_intent_or_phase_failure_prevents_that_external_action(setup, monkeypatch, phase):
    journal, session, revoker = setup
    save = journal.save

    def fail(record):
        if record["operations"][OPERATION]["phase"] == phase:
            raise OSError(PRIVATE)
        save(record)

    monkeypatch.setattr(journal, "save", fail)
    with pytest.raises(OSError):
        execute(setup)
    assert phase not in session.calls
    if phase in {None, "revoke"}:
        assert revoker.calls == 0


def test_journal_contains_only_safe_metadata_and_same_action_cannot_confuse_install_with_delete(setup):
    journal, _, _ = setup
    execute(setup)
    raw = journal.path.read_text()
    for forbidden in ("password", "envelope", "token", "username", "directory.invalid", PRIVATE, CREDENTIAL):
        assert forbidden not in raw
    assert set(journal.load()["operations"][OPERATION]) == {"binding_sha256", "status", "phase", "reason"}
    base = asdict(delete_binding())
    for field in ("gpo_guid", "ou_entity_ids", "action"):
        base.pop(field)
    assert deployment.Binding(**base).sha256 != delete_binding().sha256


def test_deletion_binding_cannot_be_passed_to_install_executor(setup):
    journal, session, revoker = setup
    with pytest.raises(deployment.DeploymentError, match="state_conflict"):
        deployment.execute(delete_binding(), journal=journal, session=session)
    assert not session.calls and not revoker.calls and not journal.load()["operations"]


@pytest.mark.parametrize("case,reason", [("account", "access_denied"), ("read", "response_lost"),
    ("scope", "state_conflict"), ("expired", "expired")])
def test_preview_failure_is_safe_and_never_revokes_or_writes(setup, monkeypatch, case, reason):
    journal, session, revoker = setup
    before = journal.path.read_bytes()
    if case == "account":
        session.denied = True
    elif case == "read":
        def fail(*args):
            raise TimeoutError(PRIVATE)
        monkeypatch.setattr(session, "inspect_delete", fail)
    elif case == "scope":
        session.state = replace(session.state, link_ou_entity_ids=(4,))
    else:
        session.now = 1300
    with pytest.raises(deployment.DeploymentError, match="^" + reason + "$"):
        subject.preview(delete_binding(), journal=journal, session=session, clock=lambda: session.now)
    assert not revoker.calls and journal.path.read_bytes() == before
    assert not {"disable", "unlink", "delete_gpo", "delete_gpt"} & set(session.calls)


@pytest.mark.parametrize("changes", [{"expected_state_sha256": None}, {"ou_entity_ids": ()},
    {"ou_entity_ids": [2]}, {"ou_entity_ids": (True,)}, {"ou_entity_ids": (3, 2)},
    {"ou_entity_ids": (2, 2)}, {"ou_entity_ids": (2**63,)}, {"gpo_guid": PRIVATE}])
def test_malformed_deletion_binding_is_rejected(changes):
    with pytest.raises(deployment.DeploymentError, match="state_conflict"):
        delete_binding(**changes)

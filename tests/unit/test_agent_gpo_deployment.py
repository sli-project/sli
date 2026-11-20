"""Stage 5 kernel tests only: no transport, directory, database or LAB access."""
import json
from dataclasses import replace

import pytest

from sli_agent import gpo_deployment as subject
from sli_agent.gpo_links import LinkConflict
from sli_agent.protection import directory_lock


INSTALLATION = "10000000-0000-4000-8000-000000000001"
OPERATION = "20000000-0000-4000-8000-000000000001"
CREDENTIAL = "30000000-0000-4000-8000-000000000001"
SECOND = "40000000-0000-4000-8000-000000000001"
PRIVATE = "synthetic-private-native-error"


def binding(**changes):
    return subject.Binding(**(dict(installation_id=INSTALLATION, domain_id=1, actor="session:1", operation_id=OPERATION,
        plan_sha256="a" * 64, credential_id=CREDENTIAL, credential_revision=1,
        recipient_sha256="b" * 64, principal_sha256="c" * 64, expected_state_sha256=None,
        issued_at=1000, expires_at=1300) | changes))


class Session:
    def __init__(self, journal):
        self.journal = journal
        self.state = None
        self.calls = []
        self.checks = 0
        self.bad_identity = None
        self.fail_phase = None
        self.failure = PermissionError(PRIVATE)
        self.bad_readback = None
        self.crash = None
        self.now = 1010
        self.expire_after = None

    def check(self, plan):
        self.checks += 1
        if self.expire_after == self.checks:
            self.now = 1300
        proof = subject.SessionProof(plan.sha256, plan.principal_sha256, plan.principal_sha256)
        return replace(proof, **self.bad_identity) if self.bad_identity else proof

    def inspect(self, guid):
        self.calls.append(("inspect", guid))
        return self.state

    def perform(self, phase, guid, owner):
        # The local intention is durable before any external side effect.
        record = self.journal.load()
        assert record["gpo_guid"] == guid
        assert any(row["status"] == "applying" and row["phase"] == phase for row in record["operations"].values())
        self.calls.append((phase, guid))
        if phase == "create_disabled":
            self.state = subject.OwnedState(owner, "d" * 64)
        if self.crash == phase:
            raise SystemExit()
        if self.fail_phase == phase:
            raise self.failure

    def verify(self, phase, guid, owner):
        self.calls.append(("verify:" + phase, guid))
        return phase != self.bad_readback


@pytest.fixture
def setup(tmp_path):
    journal = subject.Journal(tmp_path, INSTALLATION, 1)
    session = Session(journal)
    return journal, session


def execute(plan, journal, session):
    return subject.execute(plan, journal=journal, session=session, clock=lambda: session.now)


def test_order_readback_before_enable_and_repeat_returns_same_guid_without_renewing_authority(setup):
    journal, session = setup
    plan = binding()
    result = execute(plan, journal, session)
    assert result["status"] == "configured" and result["reason"] == "verified"
    phases = [phase for phase, _ in session.calls if phase in subject.PHASES]
    assert phases == list(subject.PHASES)
    assert session.calls.index(("verify:readback", journal.load()["gpo_guid"])) < session.calls.index(("enable", journal.load()["gpo_guid"]))
    assert len({guid for _, guid in session.calls}) == 1
    previous_calls = list(session.calls)
    checks = session.checks
    session.now = 9999
    assert execute(plan, journal, session) == result
    assert session.calls == previous_calls and session.checks == checks
    assert len(journal.load()["operations"]) == 1


@pytest.mark.parametrize("phase", subject.PHASES)
@pytest.mark.parametrize("failure,reason", [(PermissionError(PRIVATE), "access_denied"),
    (TimeoutError(PRIVATE), "response_lost"), (LinkConflict(), "state_conflict"),
    (RuntimeError(PRIVATE), "operation_failed")])
def test_every_phase_failure_is_partial_sanitized_and_not_automatically_repeated(setup, phase, failure, reason):
    journal, session = setup
    session.fail_phase, session.failure = phase, failure
    result = execute(binding(), journal, session)
    assert result["status"] == "partial" and result["phase"] == phase and result["reason"] == reason
    assert PRIVATE not in journal.path.read_text() and PRIVATE not in json.dumps(result)
    calls = list(session.calls)
    assert execute(binding(), journal, session) == result
    assert session.calls == calls
    if phase != "enable":
        assert not any(call[0] == "enable" for call in session.calls)


@pytest.mark.parametrize("phase", subject.PHASES)
def test_process_death_requires_new_preview_and_never_replays_an_ambiguous_phase(setup, phase):
    journal, session = setup
    session.crash = phase
    with pytest.raises(SystemExit):
        execute(binding(), journal, session)
    assert journal.load()["operations"][OPERATION]["status"] == "applying"
    # A new process reloads the same on-disk registry; it does not inspect AD.
    restarted = subject.Journal(journal.root.parents[1], INSTALLATION, 1)
    next_session = Session(restarted)
    result = execute(binding(), restarted, next_session)
    assert result["status"] == "partial" and result["reason"] == "interrupted"
    assert result["phase"] == phase and not next_session.calls


def test_explicit_new_preview_after_lost_create_uses_reserved_guid(setup):
    journal, session = setup
    session.fail_phase, session.failure = "create_disabled", TimeoutError(PRIVATE)
    assert execute(binding(), journal, session)["status"] == "partial"
    guid = journal.load()["gpo_guid"]
    session.fail_phase = None
    # New confirmation binds the actual remainder, using the same GUID.
    plan = binding(operation_id=SECOND, expected_state_sha256=session.state.state_sha256)
    assert execute(plan, journal, session)["status"] == "configured"
    assert journal.load()["gpo_guid"] == guid
    assert len({item[1] for item in session.calls}) == 1


@pytest.mark.parametrize("state", [subject.OwnedState("f" * 64, "d" * 64), subject.OwnedState("e" * 64, "d" * 64)])
def test_foreign_gpo_is_not_adopted_or_modified_even_when_preview_digest_matches(setup, state):
    journal, session = setup
    session.state = state
    result = execute(binding(expected_state_sha256="d" * 64), journal, session)
    assert result["status"] == "conflict" and result["reason"] == "state_conflict"
    assert [call[0] for call in session.calls] == ["inspect"]


def test_owned_gpo_drift_needs_new_plan_and_does_not_silently_repair(setup):
    journal, session = setup
    assert execute(binding(), journal, session)["status"] == "configured"
    session.calls.clear()
    result = execute(binding(operation_id=SECOND, expected_state_sha256="e" * 64), journal, session)
    assert result["status"] == "conflict" and [call[0] for call in session.calls] == ["inspect"]


@pytest.mark.parametrize("field", ["binding_sha256", "ldap_principal_sha256", "sysvol_principal_sha256"])
def test_ldap_and_sysvol_must_both_match_selected_account_and_binding(setup, field):
    journal, session = setup
    session.bad_identity = {field: "f" * 64}
    result = execute(binding(), journal, session)
    assert result["status"] == "blocked" and result["reason"] == "identity_rejected"
    assert not session.calls


@pytest.mark.parametrize("now", [999, 1300, 1301])
def test_expired_or_not_yet_valid_binding_never_reads_or_writes_directory(setup, now):
    journal, session = setup
    session.now = now
    result = execute(binding(), journal, session)
    assert result["status"] == "blocked" and result["reason"] == "expired"
    assert not session.calls


@pytest.mark.parametrize("check", [1, 2, 3, 8, 15])
def test_expiry_during_reauthorization_stops_before_next_phase_without_fallback(setup, check):
    journal, session = setup
    session.expire_after = check
    result = execute(binding(), journal, session)
    assert result["status"] == ("blocked" if check <= 2 else "partial")
    assert result["reason"] == "expired"


@pytest.mark.parametrize("phase", subject.PHASES)
def test_failed_phase_readback_cannot_be_reported_as_configured(setup, phase):
    journal, session = setup
    session.bad_readback = phase
    result = execute(binding(), journal, session)
    assert result["status"] == "partial" and result["reason"] == "readback_failed"
    if phase != "enable":
        assert not any(call[0] == "enable" for call in session.calls)


@pytest.mark.parametrize("change", [dict(credential_id=SECOND), dict(credential_revision=2),
    dict(recipient_sha256="f" * 64), dict(plan_sha256="e" * 64), dict(expires_at=1299), dict(actor="session:2")])
def test_same_operation_id_cannot_be_rebound_or_given_a_new_ttl(setup, change):
    journal, session = setup
    execute(binding(), journal, session)
    session.calls.clear()
    with pytest.raises(subject.DeploymentError, match="^state_conflict$"):
        execute(binding(**change), journal, session)
    assert not session.calls


def test_domain_local_lock_serializes_operations_without_touching_the_directory(setup):
    journal, session = setup
    with directory_lock(journal.root):
        with pytest.raises(OSError):
            execute(binding(), journal, session)
    assert not session.calls


@pytest.mark.parametrize("change", [dict(domain_id=True), dict(credential_revision=True), dict(expires_at=1301),
    dict(expires_at=1000), dict(operation_id="../escape"), dict(plan_sha256=PRIVATE), dict(issued_at=1000.0),
    dict(actor="owner"), dict(actor="session:0"), dict(issued_at=-1, expires_at=100)])
def test_malformed_binding_is_rejected_without_native_error_text(change):
    with pytest.raises(subject.DeploymentError, match="^state_conflict$"):
        binding(**change)


@pytest.mark.parametrize("contents", [b"not-json", b"[]", b"null", b'{"password":"synthetic-secret"}'])
def test_corrupt_or_unknown_journal_is_never_replaced_by_a_new_guid(setup, contents):
    journal, session = setup
    with directory_lock(journal.root):
        journal.path.write_bytes(contents)
    with pytest.raises(subject.DeploymentError, match="^state_conflict$"):
        execute(binding(), journal, session)
    assert journal.path.read_bytes() == contents and not session.calls


def test_only_safe_metadata_is_written_to_the_journal(setup):
    journal, session = setup
    execute(binding(), journal, session)
    record = json.loads(journal.path.read_bytes())
    assert set(record) == {"schema_version", "installation_id", "domain_id", "gpo_guid", "operations"}
    row = record["operations"][OPERATION]
    assert set(row) == {"binding_sha256", "status", "phase", "reason"}
    raw = journal.path.read_text()
    for forbidden in ("password", "envelope", "token", "username", "directory.invalid", PRIVATE, CREDENTIAL):
        assert forbidden not in raw


def test_no_automatic_new_operation_while_an_earlier_writer_is_ambiguous(setup):
    journal, session = setup
    session.crash = "links"
    with pytest.raises(SystemExit):
        execute(binding(), journal, session)
    session.calls.clear()
    with pytest.raises(subject.DeploymentError, match="state_conflict"):
        execute(binding(operation_id=SECOND), journal, session)
    assert not session.calls


def test_failed_durable_intent_never_starts_directory_work(setup, monkeypatch):
    journal, session = setup

    def fail(*args):
        raise OSError("synthetic-disk-full")

    monkeypatch.setattr(subject, "atomic_write", fail)
    with pytest.raises(OSError):
        execute(binding(), journal, session)
    assert not session.calls and not journal.path.exists()


def test_failure_to_persist_phase_prevents_that_phase_from_running(setup, monkeypatch):
    journal, session = setup
    save = journal.save

    def fail(record):
        if record["operations"][OPERATION]["phase"] == "links":
            raise OSError("synthetic-disk-full")
        save(record)

    monkeypatch.setattr(journal, "save", fail)
    with pytest.raises(OSError):
        execute(binding(), journal, session)
    assert not any(phase in {"links", "enable"} for phase, _ in session.calls)
    assert journal.load()["operations"][OPERATION]["status"] == "applying"


def test_broken_registry_symlink_is_not_treated_as_an_absent_registry(setup, tmp_path):
    journal, session = setup
    with journal.locked():
        journal.path.symlink_to(tmp_path / "nonexistent")
    with pytest.raises(subject.DeploymentError, match="state_conflict"):
        execute(binding(), journal, session)
    assert journal.path.is_symlink() and not session.calls


def test_redirected_parent_cannot_replace_another_scopes_registry(setup, tmp_path):
    journal, session = setup
    outside = tmp_path / "other-scope"
    outside.mkdir()
    (journal.base / INSTALLATION).symlink_to(outside, target_is_directory=True)
    with pytest.raises(subject.DeploymentError, match="state_conflict"):
        execute(binding(), journal, session)
    assert list(outside.iterdir()) == [] and not session.calls

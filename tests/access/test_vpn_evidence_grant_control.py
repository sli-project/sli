from __future__ import annotations

from datetime import datetime, timezone
import json
import sys
from urllib.parse import urlunparse

import pytest


def test_vpn_evidence_assignment_uses_explicit_subject_and_domain(monkeypatch):
    from server.sli.access import access_control_v4

    subject = {"id": 74, "username": "another-reader", "role": "viewer", "is_active": True}
    rows = iter((subject, {"id": 77}, {"id": 91}))
    writes = []

    class Cursor:
        def execute(self, query, parameters=()):
            if "insert into access_capability_assignments" in query:
                writes.append(parameters)

        def fetchone(self):
            return next(rows)

        def fetchall(self):
            return []

    monkeypatch.setattr(access_control_v4, "record_access_audit_with_cursor", lambda **_kwargs: None)
    result = access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
        cursor=Cursor(), subject=subject, scope={"kind": "domain", "ids": [7]},
        actor={"type": "local", "id": None}, reason="Approved evidence access",
        approved_by="owner", plan_digest="a" * 64,
    )
    assert result == {"status": "created", "assignment_id": 91, "scope": {"kind": "domain", "ids": [7]}}
    assert writes[0][:2] == (74, 77)
    assert json.loads(writes[0][2]) == {"kind": "domain", "ids": [7]}


@pytest.mark.parametrize("scope", [{"kind": "all"}, {"kind": "domain", "ids": []}, {"kind": "server", "ids": [7]}])
def test_vpn_evidence_writer_rejects_unbounded_or_invalid_scopes(scope):
    from server.sli.access import access_control_v4

    with pytest.raises(ValueError, match="vpn_evidence_scope_invalid"):
        access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
            cursor=None,
            subject={"id": 74, "username": "another-reader", "role": "viewer", "is_active": True},
            scope=scope, actor={"type": "local", "id": None},
            reason="Approved evidence access", approved_by="owner", plan_digest="a" * 64,
        )


def test_vpn_evidence_deny_on_any_requested_domain_blocks_the_assignment(monkeypatch):
    from server.sli.access import access_control_v4

    subject = {"id": 74, "username": "another-reader", "role": "viewer", "is_active": True}
    rows = iter((subject, {"id": 77}))

    class Cursor:
        def execute(self, query, _parameters=()):
            assert "insert into" not in query

        def fetchone(self):
            return next(rows)

        def fetchall(self):
            return [{"id": 92, "effect": "deny", "scope_json": {"kind": "domain", "ids": [7]}}]

    with pytest.raises(ValueError, match="vpn_evidence_matching_deny"):
        access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
            cursor=Cursor(), subject=subject, scope={"kind": "domain", "ids": [3, 7]},
            actor={"type": "local", "id": None}, reason="Approved evidence access",
            approved_by="owner", plan_digest="a" * 64,
        )


def _access(*, evidence_policy=None):
    policies = [{
        "capability_key": "vpn.sessions.view", "effect": "allow",
        "scope": {"kind": "domain", "ids": [1]}, "valid": True,
    }]
    if evidence_policy is not None:
        policies.append(evidence_policy)
    return {
        "capabilities": [],
        "capability_policies": policies,
        "reports": [{
            "report_key": "vpn.audit", "version": 1, "dataset_version": 1,
            "status": "published", "allowed": True,
            "assignment_version_state": "compatible",
            "grants": [{
                "scope": {"kind": "domain", "ids": [1]},
                "allowed_actions": ["view"], "field_categories": ["security"],
            }],
        }],
        "packages": [{"key": "ad_auditor"}],
        "package_explain": [{"package_key": "ad_auditor", "effect": "allow"}],
        "explicit_denies": {"packages": [], "capabilities": [], "reports": []},
    }


def test_plan_access_requires_vpn_report_and_session_but_allows_missing_evidence_grant():
    from scripts.maintenance import vpn_evidence_grant_control as control

    result = control.evaluate_target_access(_access(), domain_id=1)

    assert result == {"status": "ready", "domain_allowed": True, "foreign_domain_allowed": False}


def test_plan_access_blocks_existing_evidence_deny():
    from scripts.maintenance import vpn_evidence_grant_control as control

    result = control.evaluate_target_access(_access(evidence_policy={
        "capability_key": "vpn.session.evidence.read", "effect": "deny",
        "scope": {"kind": "domain", "ids": [1]}, "valid": True,
    }), domain_id=1)

    assert result == {"status": "not_ready", "reason": "vpn_evidence_matching_deny"}


def test_plan_rejects_any_existing_global_evidence_allow_that_widens_foreign_domain():
    from scripts.maintenance import vpn_evidence_grant_control as control

    access = _access(evidence_policy={
        "capability_key": "vpn.session.evidence.read", "effect": "allow",
        "scope": {"kind": "all"}, "valid": True,
    })
    result = control.evaluate_target_access(access, domain_id=1)

    assert result == {"status": "not_ready", "reason": "vpn_evidence_foreign_scope_widened"}


def test_vpn_evidence_allow_is_scoped_audited_and_idempotent(monkeypatch):
    """The approved maintenance action adds an audited domain-scoped direct allow."""
    from server.sli.access import access_control_v4

    executed: list[tuple[str, tuple[object, ...]]] = []
    rows = iter((
        {"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
        {"id": 77},  # exact registered capability
        {"id": 91, "subject_id": 34, "scope_json": {"kind": "domain", "ids": [1]}},
    ))
    audit_calls: list[dict[str, object]] = []

    class Cursor:
        def execute(self, query: str, parameters: tuple[object, ...]) -> None:
            executed.append((query, parameters))

        def fetchone(self):
            return next(rows)

        def fetchall(self):
            return []  # no existing active direct policy

    monkeypatch.setattr(
        access_control_v4,
        "record_access_audit_with_cursor",
        lambda **kwargs: audit_calls.append(kwargs) or {"id": 400},
    )

    result = access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
        cursor=Cursor(),
        scope={"kind": "domain", "ids": [1]},
        subject={"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
        actor={"type": "local", "id": None, "username": "local-maintenance"},
        reason="Owner-approved exact VPN evidence access",
        approved_by="owner",
        plan_digest="a" * 64,
        now=datetime(2026, 9, 11, tzinfo=timezone.utc),
    )

    assert result == {"status": "created", "assignment_id": 91, "scope": {"kind": "domain", "ids": [1]}}
    assert any("insert into access_capability_assignments" in query for query, _ in executed)
    assert audit_calls == [{
        "cursor": audit_calls[0]["cursor"],
        "actor": {"type": "local", "id": None, "username": "local-maintenance"},
        "action": "vpn_session_evidence_grant_created",
        "subject_type": "user",
        "subject_id": 34,
        "target_type": "capability",
        "target_key": "vpn.session.evidence.read",
        "reason": "Owner-approved exact VPN evidence access",
        "outcome": "ok",
        "details": {
            "scope": {"kind": "domain", "ids": [1]},
            "approved_by": "owner",
            "plan_digest": "a" * 64,
            "source_type": "direct",
        },
        "remote_address": None,
    }]


def test_vpn_evidence_allow_reaches_real_disabled_audit_bridge():
    """Do not hide the audit producer behind a mock: it owns transaction validity."""
    from server.sli.access import access_control_v4

    rows = iter((
        {"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
        {"id": 77},
        {"id": 91, "subject_id": 34, "scope_json": {"kind": "domain", "ids": [1]}},
        {"id": 400, "created_at": datetime(2026, 9, 11, tzinfo=timezone.utc)},
    ))
    executed: list[str] = []

    class Cursor:
        def execute(self, query: str, *_args) -> None:
            executed.append(" ".join(query.split()).lower())

        def fetchone(self):
            return next(rows)

        def fetchall(self):
            return []

    result = access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
        cursor=Cursor(),
        scope={"kind": "domain", "ids": [1]},
        subject={"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
        actor={"type": "local", "id": None, "username": "local-maintenance"},
        reason="Owner-approved exact VPN evidence access", approved_by="owner",
        plan_digest="a" * 64, now=datetime(2026, 9, 11, tzinfo=timezone.utc),
    )

    assert result["status"] == "created"
    assert any("insert into access_audit_v4" in query for query in executed)


def test_vpn_evidence_allow_never_overrides_matching_deny(monkeypatch):
    from server.sli.access import access_control_v4

    rows = iter((
        {"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
        {"id": 77},
    ))

    class Cursor:
        def execute(self, *_args) -> None:
            return None

        def fetchone(self):
            return next(rows)

        def fetchall(self):
            return [{"id": 19, "effect": "deny", "scope_json": {"kind": "domain", "ids": [1]}}]

    monkeypatch.setattr(access_control_v4, "record_access_audit_with_cursor", lambda **_kwargs: None)

    try:
        access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
            cursor=Cursor(),
            scope={"kind": "domain", "ids": [1]},
            subject={"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
            actor={"type": "local", "id": None},
            reason="Owner-approved exact VPN evidence access", approved_by="owner",
            plan_digest="a" * 64, now=datetime(2026, 9, 11, tzinfo=timezone.utc),
        )
    except ValueError as exc:
        assert str(exc) == "vpn_evidence_matching_deny"
    else:
        raise AssertionError("matching deny must block the maintenance grant")


def test_vpn_evidence_allow_rejects_non_producer_maintenance_actor():
    from server.sli.access import access_control_v4

    class Cursor:
        def execute(self, *_args) -> None:
            raise AssertionError("actor must be checked before database work")

    try:
        access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
            cursor=Cursor(),
            scope={"kind": "domain", "ids": [1]},
            subject={"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
            actor={"type": "maintenance", "id": None},
            reason="Owner-approved exact VPN evidence access", approved_by="owner",
            plan_digest="a" * 64, now=datetime(2026, 9, 11, tzinfo=timezone.utc),
        )
    except ValueError as exc:
        assert str(exc) == "vpn_evidence_audit_actor_invalid"
    else:
        raise AssertionError("maintenance is not an audited actor kind")


def test_vpn_evidence_allow_replay_is_idempotent_without_second_audit(monkeypatch):
    from server.sli.access import access_control_v4

    executed: list[str] = []
    audited: list[dict[str, object]] = []
    rows = iter((
        {"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
        {"id": 77},
    ))

    class Cursor:
        def execute(self, query: str, *_args) -> None:
            executed.append(query)

        def fetchone(self):
            return next(rows)

        def fetchall(self):
            return [{"id": 91, "effect": "allow", "scope_json": {"kind": "domain", "ids": [1]}}]

    monkeypatch.setattr(access_control_v4, "record_access_audit_with_cursor", lambda **kwargs: audited.append(kwargs))

    result = access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
        cursor=Cursor(),
        scope={"kind": "domain", "ids": [1]},
        subject={"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
        actor={"type": "local", "id": None},
        reason="Owner-approved exact VPN evidence access", approved_by="owner",
        plan_digest="a" * 64, now=datetime(2026, 9, 11, tzinfo=timezone.utc),
    )

    assert result == {"status": "already_granted", "assignment_id": 91, "scope": {"kind": "domain", "ids": [1]}}
    assert not any("insert into access_capability_assignments" in query for query in executed)
    assert audited == []


def test_existing_allow_does_not_hide_later_matching_deny(monkeypatch):
    from server.sli.access import access_control_v4
    rows = iter((
        {"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
        {"id": 77},
    ))

    class Cursor:
        def execute(self, *_args) -> None:
            return None

        def fetchone(self):
            return next(rows)

        def fetchall(self):
            return [
                {"id": 91, "effect": "allow", "scope_json": {"kind": "domain", "ids": [1]}},
                {"id": 92, "effect": "deny", "scope_json": {"kind": "domain", "ids": [1]}},
            ]

    monkeypatch.setattr(access_control_v4, "record_access_audit_with_cursor", lambda **_kwargs: None)

    try:
        access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
            cursor=Cursor(),
            scope={"kind": "domain", "ids": [1]},
            subject={"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
            actor={"type": "local", "id": None},
            reason="Owner-approved exact VPN evidence access", approved_by="owner",
            plan_digest="a" * 64, now=datetime(2026, 9, 11, tzinfo=timezone.utc),
        )
    except ValueError as exc:
        assert str(exc) == "vpn_evidence_matching_deny"
    else:
        raise AssertionError("later deny must take precedence over idempotent allow")


def test_audit_failure_bubbles_out_of_the_assignment_transaction(monkeypatch):
    from server.sli.access import access_control_v4
    from server.sli.sources import administrative_activity_producer
    rows = iter((
        {"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
        {"id": 77},
        {"id": 91},
        {"id": 400, "created_at": datetime(2026, 9, 11, tzinfo=timezone.utc)},
    ))
    executed: list[str] = []

    class Cursor:
        def execute(self, query: str, *_args) -> None:
            executed.append(" ".join(query.split()).lower())

        def fetchone(self):
            return next(rows)

        def fetchall(self):
            return []

    monkeypatch.setattr(
        administrative_activity_producer,
        "load_administrative_activity_contract",
        lambda: {"runtime_write_enabled": True},
    )
    monkeypatch.setattr(
        administrative_activity_producer,
        "append_administrative_activity_with_cursor",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("audit_unavailable")),
    )

    try:
        access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
            cursor=Cursor(),
            scope={"kind": "domain", "ids": [1]},
            subject={"id": 34, "username": "evidence-reader", "role": "viewer", "is_active": True},
            actor={"type": "local", "id": None},
            reason="Owner-approved exact VPN evidence access", approved_by="owner",
            plan_digest="a" * 64, now=datetime(2026, 9, 11, tzinfo=timezone.utc),
        )
    except RuntimeError as exc:
        assert str(exc) == "audit_unavailable"
    else:
        raise AssertionError("audit failure must abort the surrounding transaction")
    assert any("insert into access_capability_assignments" in query for query in executed)
    assert any("insert into access_audit_v4" in query for query in executed)


def test_plan_starts_read_only_transaction_before_any_database_read(monkeypatch):
    from scripts.maintenance import vpn_evidence_grant_control as control

    statements: list[str] = []

    class Cursor:
        def execute(self, query: str, *_args) -> None:
            statements.append(" ".join(query.split()).lower())

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

    class Connection:
        def cursor(self):
            return Cursor()

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

    monkeypatch.setattr(control, "_load_environment", lambda: None)
    monkeypatch.setattr(control, "_admin_dsn", lambda: "host=127.0.0.1 dbname=sli_local user=maintenance password=hidden")
    monkeypatch.setattr(control, "_connect", lambda _dsn: Connection())
    monkeypatch.setattr(control, "_check_connection_identity", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(control, "_capture_state", lambda _cursor, **_kwargs: {
        "target": {"id": 34}, "decision": {"status": "ready"}, "fingerprint": "a" * 64,
    })

    result = control.run(action="plan", subject_id=34, domain_id=1)

    assert result["status"] == "ready"
    assert statements[0] == "begin read only"


def test_apply_rejects_changed_plan_before_grant_write(monkeypatch):
    from scripts.maintenance import vpn_evidence_grant_control as control

    writes: list[str] = []

    class Cursor:
        def execute(self, query: str, *_args) -> None:
            writes.append(" ".join(query.split()).lower())

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

    class Connection:
        def cursor(self):
            return Cursor()

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

    monkeypatch.setattr(control, "_load_environment", lambda: None)
    monkeypatch.setattr(control, "_admin_dsn", lambda: "host=127.0.0.1 dbname=sli_local user=maintenance password=hidden")
    monkeypatch.setattr(control, "_connect", lambda _dsn: Connection())
    monkeypatch.setattr(control, "_check_connection_identity", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(control, "_lock_access_inputs", lambda _cursor: writes.append("locked"))
    monkeypatch.setattr(control, "_capture_state", lambda _cursor, **_kwargs: {
        "target": {"id": 34}, "decision": {"status": "ready"}, "fingerprint": "b" * 64,
    })
    monkeypatch.setattr(
        control.access_control_v4,
        "grant_vpn_session_evidence_allow_with_cursor",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("grant must not run")),
    )

    try:
        control.run(
            action="apply", subject_id=34, domain_id=1, plan_digest="a" * 64,
            confirmation=control.plan_confirmation("a" * 64),
        )
    except control.VpnEvidenceGrantError as exc:
        assert str(exc) == "vpn_evidence_plan_changed"
    else:
        raise AssertionError("changed plan must fail closed")
    assert not any("insert into access_capability_assignments" in item for item in writes)


def test_invalid_apply_confirmation_does_not_load_dpapi_or_contact_sources(monkeypatch):
    from scripts.maintenance import vpn_evidence_grant_control as control

    monkeypatch.setattr(
        control, "_load_environment",
        lambda: (_ for _ in ()).throw(AssertionError("DPAPI must not be read")),
    )

    try:
        control.run(action="apply", subject_id=34, domain_id=1, plan_digest="a" * 64, confirmation="wrong")
    except control.VpnEvidenceGrantError as exc:
        assert str(exc) == "vpn_evidence_confirmation_invalid"
    else:
        raise AssertionError("wrong confirmation must be rejected before DB/DPAPI work")


def test_cli_redacts_unlisted_failure_details(monkeypatch, capsys):
    from scripts.maintenance import vpn_evidence_grant_control as control

    monkeypatch.setattr(sys, "argv", ["vpn_evidence_grant_control.py", "plan", "--subject-id", "34", "--domain-id", "1"])
    monkeypatch.setattr(
        control,
        "run",
        lambda **_kwargs: (_ for _ in ()).throw(
            ValueError(
                urlunparse(
                    ("postgresql", "maintenance:secret@remote-host", "/not-local", "", "", "")
                )
            )
        ),
    )

    assert control.main() == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "status": "error",
        "action": "plan",
        "code": "vpn_evidence_operation_failed",
    }


def test_cli_preserves_only_known_safe_application_code(monkeypatch, capsys):
    from scripts.maintenance import vpn_evidence_grant_control as control

    monkeypatch.setattr(sys, "argv", ["vpn_evidence_grant_control.py", "apply", "--subject-id", "34", "--domain-id", "1"])
    monkeypatch.setattr(
        control,
        "run",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("vpn_evidence_matching_deny")),
    )

    assert control.main() == 1
    assert json.loads(capsys.readouterr().out) == {
        "status": "error",
        "action": "apply",
        "code": "vpn_evidence_matching_deny",
    }

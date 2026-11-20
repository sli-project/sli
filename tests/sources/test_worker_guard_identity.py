from __future__ import annotations

import subprocess


def test_process_inventory_failure_is_not_reported_as_empty(monkeypatch) -> None:
    from scripts.maintenance import worker_guard

    monkeypatch.setattr(worker_guard.os, "name", "nt")
    monkeypatch.setattr(
        worker_guard.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, "", "access denied"
        ),
    )

    pids, error = worker_guard._running_pids_for("collection_worker.py")

    assert pids == []
    assert error == "process_inventory_failed:exit_1:access denied"


def test_process_inventory_returns_exact_python_pids(monkeypatch) -> None:
    from scripts.maintenance import worker_guard

    monkeypatch.setattr(worker_guard.os, "name", "nt")
    monkeypatch.setattr(worker_guard.os, "getpid", lambda: 30)
    monkeypatch.setattr(
        worker_guard.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "10\n30\n", ""
        ),
    )

    assert worker_guard._running_pids_for("collection_worker.py") == ([10], None)


def test_worker_can_restart_when_recorded_process_is_absent() -> None:
    from scripts.maintenance.worker_guard import _recorded_worker_is_confirmed_gone

    assert _recorded_worker_is_confirmed_gone(
        recorded_pid=12356,
        running_pids=[],
    )


def test_worker_cannot_restart_without_valid_pid_or_while_process_exists() -> None:
    from scripts.maintenance.worker_guard import _recorded_worker_is_confirmed_gone

    assert not _recorded_worker_is_confirmed_gone(
        recorded_pid=12356,
        running_pids=[12356],
    )
    assert not _recorded_worker_is_confirmed_gone(
        recorded_pid=None,
        running_pids=[],
    )
    assert not _recorded_worker_is_confirmed_gone(
        recorded_pid=12356,
        running_pids=[99999],
    )


def test_collection_identity_requires_principal_sid_and_interactive_session(
    monkeypatch,
) -> None:
    from server.sli.sources import windows_runtime_identity

    monkeypatch.setattr(
        windows_runtime_identity,
        "current_windows_identity",
        lambda: {
            "principal": r"EXAMPLE\operator",
            "sid": windows_runtime_identity.EXAMPLE_COLLECTION_PRINCIPAL_SID,
            "session_id": 1,
            "interactive": True,
            "elevated": True,
            "error": None,
        },
    )
    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL", r"EXAMPLE\operator")
    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL_SID", windows_runtime_identity.EXAMPLE_COLLECTION_PRINCIPAL_SID)

    result = windows_runtime_identity.verify_collection_identity()

    assert result["status"] == "ok"
    assert result["reasons"] == []


def test_collection_identity_rejects_same_name_with_different_sid(monkeypatch) -> None:
    from server.sli.sources import windows_runtime_identity

    monkeypatch.setattr(
        windows_runtime_identity,
        "current_windows_identity",
        lambda: {
            "principal": r"EXAMPLE\operator",
            "sid": "S-1-5-21-100000001-200000001-300000001-9999",
            "session_id": 1,
            "interactive": True,
            "elevated": True,
            "error": None,
        },
    )

    result = windows_runtime_identity.verify_collection_identity()

    assert result["status"] == "failed"
    assert "sid_mismatch" in result["reasons"]


def test_collection_identity_blocks_configured_principal_when_actual_differs(monkeypatch) -> None:
    from server.sli.sources import windows_runtime_identity

    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL", r"OTHER\operator")
    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL_SID", "S-1-5-21-100000001-200000001-300000001-1000")
    monkeypatch.setattr(
        windows_runtime_identity,
        "current_windows_identity",
        lambda: {
            "principal": r"OTHER\different",
            "sid": "S-1-5-21-100000001-200000001-300000001-1999",
            "session_id": 1,
            "interactive": True,
            "elevated": True,
            "error": None,
        },
    )

    result = windows_runtime_identity.verify_collection_identity()

    assert result["status"] == "failed"
    assert "principal_mismatch" in result["reasons"]
    assert "sid_mismatch" in result["reasons"]


def test_collection_identity_does_not_require_admin_token_when_identity_is_exact(
    monkeypatch,
) -> None:
    from server.sli.sources import windows_runtime_identity

    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL", r"EXAMPLE\operator")
    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL_SID", windows_runtime_identity.EXAMPLE_COLLECTION_PRINCIPAL_SID)
    monkeypatch.setattr(
        windows_runtime_identity,
        "current_windows_identity",
        lambda: {
            "principal": r"EXAMPLE\operator",
            "sid": windows_runtime_identity.EXAMPLE_COLLECTION_PRINCIPAL_SID,
            "session_id": 1,
            "interactive": True,
            "elevated": False,
            "error": None,
        },
    )

    result = windows_runtime_identity.verify_collection_identity()

    assert result["status"] == "ok"
    assert result["reasons"] == []


def test_collection_identity_accepts_configured_prototype_principal_and_sid(monkeypatch) -> None:
    from server.sli.sources import windows_runtime_identity

    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL", r"EXAMPLE\\prototype-owner")
    monkeypatch.setenv(
        "ADLOG_COLLECTION_PRINCIPAL_SID",
        "S-1-5-21-100000004-200000004-300000004-6995",
    )
    monkeypatch.setattr(
        windows_runtime_identity,
        "current_windows_identity",
        lambda: {
            "principal": r"EXAMPLE\\prototype-owner",
            "sid": "S-1-5-21-100000004-200000004-300000004-6995",
            "session_id": 2,
            "interactive": True,
            "elevated": False,
            "error": None,
        },
    )

    assert windows_runtime_identity.verify_collection_identity()["status"] == "ok"


def test_collection_identity_requires_explicit_installation_identity(monkeypatch) -> None:
    from server.sli.sources import windows_runtime_identity

    monkeypatch.delenv("ADLOG_COLLECTION_PRINCIPAL", raising=False)
    monkeypatch.delenv("ADLOG_COLLECTION_PRINCIPAL_SID", raising=False)
    monkeypatch.setattr(
        windows_runtime_identity,
        "current_windows_identity",
        lambda: {"principal": "owner", "sid": "S-1-5-1", "interactive": True, "error": None},
    )

    result = windows_runtime_identity.verify_collection_identity()

    assert result["status"] == "failed"
    assert "expected_principal_missing" in result["reasons"]
    assert "expected_sid_missing" in result["reasons"]


def test_collection_identity_can_verify_an_explicit_protected_identity(
    monkeypatch,
) -> None:
    """Falling back to hostile process env would make this exact check fail."""

    from server.sli.sources import windows_runtime_identity

    protected_sid = "S-1-5-21-100000001-200000001-300000001-1000"
    monkeypatch.setenv("ADLOG_COLLECTION_PRINCIPAL", r"OTHER\attacker")
    monkeypatch.setenv(
        "ADLOG_COLLECTION_PRINCIPAL_SID",
        "S-1-5-21-100000001-200000001-300000001-1999",
    )
    monkeypatch.setattr(
        windows_runtime_identity,
        "current_windows_identity",
        lambda: {
            "principal": r"EXAMPLE\operator",
            "sid": protected_sid,
            "session_id": 2,
            "interactive": True,
            "elevated": False,
            "error": None,
        },
    )

    result = windows_runtime_identity.verify_collection_identity(
        expected_principal=r"EXAMPLE\operator",
        expected_sid=protected_sid,
    )

    assert result["status"] == "ok"
    assert result["expected_principal"] == r"EXAMPLE\operator"
    assert result["expected_sid"] == protected_sid

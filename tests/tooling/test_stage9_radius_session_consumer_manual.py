from __future__ import annotations

import inspect
import os

from scripts.maintenance import (
    stage9_radius_session_consumer_manual as manual,
)


def test_manual_consumer_is_one_shot_source_free_and_bounded() -> None:
    source = inspect.getsource(manual)
    assert manual.CONFIRMATION == (
        "RUN-STAGE9-RADIUS-SESSION-CONSUMER-ONCE"
    )
    assert '"deliveries": 50' in source
    assert '"runtime_seconds": 60' in source
    assert '"source_contacted": False' in source
    assert "radius_accounting_tail" not in source
    assert "read_bounded_tail" not in source
    assert "current_windows_account" in source
    assert "load_manual_control_contract" in source
    assert "radius.radius01.example.invalid" not in source




def test_child_receives_only_ephemeral_consumer_dsn() -> None:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "ADLOG_PG_DSN": "postgresql://example_admin:example_password@localhost/example_db",
        "ADLOG_PG_ADMIN_PASSWORD": "admin-password",
        "ADLOG_OTHER_TOKEN": "token",
    }
    original = manual.os.environ
    manual.os.environ = environment
    try:
        result = manual._child_environment(
            "adlog_radius_consumer_fixture",
            "fixture-password",
        )
    finally:
        manual.os.environ = original
    assert "ADLOG_PG_DSN" not in result
    assert "ADLOG_PG_ADMIN_PASSWORD" not in result
    assert "ADLOG_OTHER_TOKEN" not in result
    assert "SLI_PLUGIN_PG_DSN" in result
    assert "fixture-password" in result[
        "SLI_PLUGIN_PG_DSN"
    ]


def test_expected_live_postcondition_is_explicit() -> None:
    source = inspect.getsource(manual.execute)
    assert 'before["delivered_rows"] + before["queued_rows"]' in source
    assert 'before["receipt_rows"] + before["queued_rows"]' in source
    assert '"projected"' in source
    assert '"identity_unresolved"' in source
    assert '"timestamp_unresolved"' in source
    assert '"ephemeral_login_dropped": True' in source


def test_plan_accepts_only_one_bounded_clean_pending_batch() -> None:
    source = inspect.getsource(manual.plan)
    assert 'not 1 <= state["queued_rows"] <= 50' in source
    assert "bounded_queued_delivery_state_required" in source
    assert 'state["receipt_rows"] != state["delivered_rows"]' in source
    assert "initialized_cursor_required" in source


def test_ephemeral_role_uses_safe_sql_composition() -> None:
    source = inspect.getsource(manual._ephemeral_login)
    assert "sql.Identifier(role)" in source
    assert "sql.Literal(password)" in source
    assert "password %s" not in source

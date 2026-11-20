from __future__ import annotations

from contextlib import nullcontext

import pytest

from server.sli.sources.plugin_lifecycle import (
    PluginLifecycleError,
    initial_remote_access_state,
    plan_plugin_lifecycle,
)
from server.sli.sources.plugin_lifecycle_executor import execute_bundled_plugin_install


CAPS = {"plugins.manage"}
OPERATION_UID = "22222222-2222-2222-2222-222222222222"


class Cursor:
    def __init__(self) -> None:
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, sql, params) -> None:
        self.calls.append((sql, params))

    def fetchone(self):
        return {
            "operation_id": 7,
            "committed_revision": 2,
            "package_lifecycle": "registered",
            "desired_activation": "disabled",
        }


class Connection:
    def __init__(self, cursor: Cursor) -> None:
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def cursor(self):
        return self._cursor


def _plan():
    return plan_plugin_lifecycle(
        action="install",
        state=initial_remote_access_state(),
        actor_capabilities=CAPS,
    )


def test_exact_install_uses_one_parameterized_database_call() -> None:
    cursor = Cursor()
    plan = _plan()
    result = execute_bundled_plugin_install(
        plan=plan,
        confirmation=plan["confirmation"],
        operation_uid=OPERATION_UID,
        actor_kind="windows",
        actor_key=r"EXAMPLE\operator",
        actor_capabilities=CAPS,
        connection_factory=lambda: Connection(cursor),
    )
    assert result["status"] == "registered"
    assert result["committed_revision"] == 2
    assert result["runtime_enabled"] is False
    assert len(cursor.calls) == 1
    assert cursor.calls[0][1][0] == OPERATION_UID


def test_missing_capability_blocks_before_database_call() -> None:
    plan = _plan()
    with pytest.raises(PermissionError, match="plugins_manage_required"):
        execute_bundled_plugin_install(
            plan=plan,
            confirmation=plan["confirmation"],
            operation_uid=OPERATION_UID,
            actor_kind="windows",
            actor_key="actor",
            actor_capabilities=set(),
            connection_factory=lambda: nullcontext(),
        )


def test_wrong_confirmation_blocks_before_database_call() -> None:
    with pytest.raises(PluginLifecycleError, match="confirmation_invalid"):
        execute_bundled_plugin_install(
            plan=_plan(),
            confirmation="wrong",
            operation_uid=OPERATION_UID,
            actor_kind="windows",
            actor_key="actor",
            actor_capabilities=CAPS,
            connection_factory=lambda: nullcontext(),
        )


def test_non_install_action_is_rejected() -> None:
    state = initial_remote_access_state()
    plan = plan_plugin_lifecycle(
        action="upgrade",
        state=state,
        target_version="0.2.0",
        actor_capabilities=CAPS,
    )
    with pytest.raises(PluginLifecycleError, match="plan_invalid"):
        execute_bundled_plugin_install(
            plan=plan,
            confirmation=plan["confirmation"],
            operation_uid=OPERATION_UID,
            actor_kind="windows",
            actor_key="actor",
            actor_capabilities=CAPS,
            connection_factory=lambda: nullcontext(),
        )

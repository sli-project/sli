from datetime import datetime, timezone
from uuid import UUID

import pytest

from server.sli.sources.plugin_runtime_admission import ACQUISITION, CONSUMER
from server.sli.sources.plugin_runtime_admission_executor import (
    PluginComponentLease,
    acquire_component_lease,
    component_lease_scope,
    release_component_lease,
)


LEASE_UID = UUID("44444444-4444-4444-4444-444444444444")


class Cursor:
    def __init__(self, row):
        self.row = row
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor


class ScopeConnection:
    def __init__(self, rows):
        self.rows = list(rows)
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return Cursor(self.rows.pop(0))

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def test_acquire_uses_one_parameterized_exact_call() -> None:
    cursor = Cursor((LEASE_UID, ACQUISITION, "open", datetime.now(timezone.utc)))
    result = acquire_component_lease(
        Connection(cursor),
        lease_uid=LEASE_UID,
        component_id=ACQUISITION,
        holder_key="worker-1",
    )
    assert result.lease_uid == LEASE_UID
    assert len(cursor.calls) == 2
    assert cursor.calls[0] == (
        "set local role adlog_radius_accounting_worker",
        None,
    )
    assert cursor.calls[1][1] == (
        LEASE_UID,
        "sli.remote-access",
        ACQUISITION,
        "source_contact",
        "worker-1",
    )


def test_release_validates_outcome_before_database() -> None:
    lease = PluginComponentLease(
        LEASE_UID,
        ACQUISITION,
        "open",
        datetime.now(timezone.utc),
    )
    with pytest.raises(ValueError, match="component_lease_outcome_invalid"):
        release_component_lease(
            Connection(Cursor((True,))),
            lease=lease,
            holder_key="worker-1",
            outcome="deleted",
        )


def test_release_activates_only_the_component_role() -> None:
    cursor = Cursor((True,))
    lease = PluginComponentLease(
        LEASE_UID,
        CONSUMER,
        "open",
        datetime.now(timezone.utc),
    )
    assert release_component_lease(
        Connection(cursor),
        lease=lease,
        holder_key="consumer-1",
        outcome="completed",
    )
    assert cursor.calls[0] == (
        "set local role adlog_radius_session_consumer",
        None,
    )


def test_component_scope_commits_admission_before_work_and_completion() -> None:
    conn = ScopeConnection([
        (LEASE_UID, ACQUISITION, "open", datetime.now(timezone.utc)),
        (True,),
    ])
    with component_lease_scope(
        conn,
        component_id=ACQUISITION,
        holder_key="worker-1",
        lease_uid=LEASE_UID,
    ):
        assert conn.commits == 1
    assert conn.commits == 2
    assert conn.rollbacks == 0


def test_component_scope_releases_failed_after_rollback() -> None:
    conn = ScopeConnection([
        (LEASE_UID, ACQUISITION, "open", datetime.now(timezone.utc)),
        (True,),
    ])
    with pytest.raises(RuntimeError, match="boom"):
        with component_lease_scope(
            conn,
            component_id=ACQUISITION,
            holder_key="worker-1",
            lease_uid=LEASE_UID,
        ):
            raise RuntimeError("boom")
    assert conn.commits == 2
    assert conn.rollbacks == 1


def test_publisher_can_acquire_and_release_without_changing_role_or_committing() -> None:
    cursor = Cursor((LEASE_UID, CONSUMER, "open", datetime.now(timezone.utc)))
    conn = Connection(cursor)
    lease = acquire_component_lease(
        conn, lease_uid=LEASE_UID, component_id=CONSUMER,
        holder_key="core-job:fixture", activate_role=False,
    )
    assert len(cursor.calls) == 1
    assert "acquire_plugin_component_lease_v1" in cursor.calls[0][0]
    cursor.row = (True,)
    assert release_component_lease(
        conn, lease=lease, holder_key="core-job:fixture", outcome="completed",
        activate_role=False,
    )
    assert len(cursor.calls) == 2
    assert "release_plugin_component_lease_v1" in cursor.calls[1][0]

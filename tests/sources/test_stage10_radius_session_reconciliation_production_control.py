from __future__ import annotations

import csv
from datetime import datetime, timezone
import importlib.util
from io import StringIO
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from server.source_packs.radius.accounting import DATABASE_COMPATIBLE_COLUMNS
from server.source_packs.radius.session_reconciliation_production import (
    VerifiedEvidenceRecord,
)
from server.source_packs.radius.session_reconciliation import ReconciliationAttempt


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/maintenance/stage10_radius_session_reconciliation_production_control.py"
SPEC = importlib.util.spec_from_file_location("radius_reconciliation_control", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _line(**values: str) -> str:
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    row[DATABASE_COMPATIBLE_COLUMNS.index("ServiceName")] = "NPS"
    row[DATABASE_COMPATIBLE_COLUMNS.index("Record-Date")] = "08/11/2026"
    row[DATABASE_COMPATIBLE_COLUMNS.index("Record-Time")] = "12:00:00"
    for name, value in values.items():
        row[DATABASE_COMPATIBLE_COLUMNS.index(name)] = value
    output = StringIO()
    csv.writer(output, lineterminator="").writerow(row)
    return output.getvalue()


def test_plan_binding_refuses_cursor_drift_before_writes() -> None:
    plan = {
        "plan_schema_version": 1,
        "baseline": {
            "source_instance_sha256": "a" * 64,
            "cursor_revision": 3,
            "observations": 83,
            "terminal_unresolved_receipts": 83,
            "nonterminal_deliveries": 0,
            "attempts_table": False,
            "overlays_table": False,
            "writer_role": False,
            "migration_role_can_create_role": True,
            "attempt_count": 0,
            "overlay_count": 0,
        },
    }
    current = dict(plan["baseline"])
    MODULE.validate_plan_binding(plan, current)

    current["cursor_revision"] = 4
    with pytest.raises(MODULE.RadiusReconciliationProductionControlError):
        MODULE.validate_plan_binding(plan, current)


def test_plan_blocks_unprivileged_migration_identity_before_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = MODULE._Scope("source", "example.invalid", "subscription")
    baseline = {
        "source_instance_sha256": "a" * 64,
        "cursor_revision": 3,
        "observations": 83,
        "terminal_unresolved_receipts": 83,
        "nonterminal_deliveries": 0,
        "attempts_table": False,
        "overlays_table": False,
        "writer_role": False,
        "migration_role_can_create_role": False,
        "attempt_count": 0,
        "overlay_count": 0,
    }
    migrations = {version: False for version in MODULE.MIGRATION_NAMES}
    migrations[61] = True
    batches = [
        {"terminal_receipt_count": 17, "projected_count": 1, "still_unresolved_count": 16},
        {"terminal_receipt_count": 50, "projected_count": 1, "still_unresolved_count": 49},
        {"terminal_receipt_count": 16, "projected_count": 1, "still_unresolved_count": 15},
    ]
    discovery = {"terminal_identity_sha256": "b" * 64}
    monkeypatch.setattr(MODULE, "_validate_disposable_acceptance", lambda _path: {})
    monkeypatch.setattr(MODULE, "_scope_and_baseline", lambda: (scope, baseline, migrations))
    monkeypatch.setattr(MODULE, "_build_batches", lambda _scope: (batches, [], discovery))

    plan = MODULE.build_plan()

    assert plan["status"] == "blocked"
    assert plan["blockers"] == [
        "production_reconciliation_migration_role_create_role_required"
    ]


def test_control_has_no_source_or_queue_mutation_surface() -> None:
    source = SCRIPT.read_text(encoding="utf-8").lower()
    assert "source_contacted\": false" in source
    assert "update acquisition_stream_cursors" not in source
    assert "acquisition_delivery_outbox set" not in source
    assert "production_apply_without_plan_binding" in source
    assert "set local role adlog_radius_accounting_worker" in source
    assert "for share" in source
    assert "maximum_evidence_bytes_per_run" in source
    assert source.count("_restore_session_role(conn)") == 3


def test_control_refuses_any_scope_other_than_authorized_83_receipts() -> None:
    batches = [
        {
            "terminal_receipt_count": 17,
            "projected_count": 9,
            "still_unresolved_count": 8,
        },
        {
            "terminal_receipt_count": 50,
            "projected_count": 41,
            "still_unresolved_count": 9,
        },
        {
            "terminal_receipt_count": 16,
            "projected_count": 12,
            "still_unresolved_count": 4,
        },
    ]
    assert MODULE._authorized_reconciliation_blockers(batches) == []

    batches[-1]["terminal_receipt_count"] = 15
    assert MODULE._authorized_reconciliation_blockers(batches) == [
        "production_reconciliation_batch_scope_invalid"
    ]


def test_resolution_identity_digest_changes_when_exact_lookup_changes() -> None:
    attempt = ReconciliationAttempt(
        "a" * 64,
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "projected",
        "b" * 64,
        "resolver-v1",
        "c" * 64,
    )
    first = SimpleNamespace(
        session_identity_key="radius-session:" + "d" * 64,
        exact_principal_key="entity:101",
    )
    changed = SimpleNamespace(
        session_identity_key="radius-session:" + "e" * 64,
        exact_principal_key="entity:102",
    )

    assert MODULE._resolution_identity_sha256(
        (attempt,), {attempt.observation_id: first}
    ) != MODULE._resolution_identity_sha256(
        (attempt,), {attempt.observation_id: changed}
    )


def test_locked_discovery_includes_terminal_identity_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = MODULE._TerminalObservation(
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "start",
        "ready",
        datetime(2026, 8, 11, 5, tzinfo=timezone.utc),
        10,
    )
    evidence = MODULE._EvidenceManifest(
        observation.evidence_uid, "a" * 64, "a" * 64, 1, 10, 1
    )
    discovery = {
        "manifest_count": 1,
        "manifest_bytes": 1,
        "manifest_identity_sha256": "b" * 64,
        "selected_access_accept_count": 0,
        "selected_access_accept_sha256": "c" * 64,
    }
    expected = {
        **discovery,
        "terminal_identity_sha256": MODULE._terminal_identity_sha256(
            [observation], {observation.evidence_uid: evidence}
        ),
    }

    class Cursor:
        def __enter__(self) -> Cursor:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, _query: str, _arguments: tuple[object, ...] = ()) -> None:
            return None

        def fetchone(self) -> dict[str, int]:
            return {
                "revision": 3,
                "observations": 83,
                "terminal_unresolved_receipts": 83,
                "nonterminal_deliveries": 0,
                "attempts_table": False,
                "overlays_table": False,
                "writer_role": False,
                "migration_role_can_create_role": True,
            }

        def fetchall(self) -> list[dict[str, object]]:
            return []

    class Connection:
        def cursor(self) -> Cursor:
            return Cursor()

        def rollback(self) -> None:
            return None

    baseline = {
        "cursor_revision": 3,
        "observations": 83,
        "terminal_unresolved_receipts": 83,
        "nonterminal_deliveries": 0,
        "attempts_table": False,
        "overlays_table": False,
        "writer_role": False,
        "migration_role_can_create_role": True,
    }
    monkeypatch.setattr(
        MODULE,
        "_select_terminal_inventory",
        lambda _cursor, _scope: ({observation.evidence_uid: evidence}, [observation]),
    )
    monkeypatch.setattr(
        MODULE,
        "_scan_authorized_identity_evidence",
        lambda _scope, _evidence, conn: ([], {}, discovery),
    )

    MODULE._lock_and_validate_plan_inputs(
        Connection(),
        scope=MODULE._Scope("source", "example.invalid", "subscription"),
        plan={"baseline": baseline, "reconciliation": {"identity_evidence_discovery": expected}},
        migrations={version: False for version in MODULE.MIGRATION_NAMES},
    )


def test_apply_rejects_migration_privilege_drift_before_migration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = {
        "source_instance_sha256": "a" * 64,
        "cursor_revision": 3,
        "observations": 83,
        "terminal_unresolved_receipts": 83,
        "nonterminal_deliveries": 0,
        "attempts_table": False,
        "overlays_table": False,
        "writer_role": False,
        "migration_role_can_create_role": True,
        "attempt_count": 0,
        "overlay_count": 0,
    }

    class Cursor:
        def __init__(self) -> None:
            self.executed: list[str] = []
            self.rows = iter(
                (
                    {"revision": 3},
                    {
                        "observations": 83,
                        "terminal_unresolved_receipts": 83,
                        "nonterminal_deliveries": 0,
                        "attempts_table": False,
                        "overlays_table": False,
                        "writer_role": False,
                        "migration_role_can_create_role": False,
                    },
                )
            )

        def __enter__(self) -> Cursor:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: str, _arguments: tuple[object, ...] = ()) -> None:
            self.executed.append(query)
            if "schema_migrations" in query:
                raise AssertionError(
                    "migration-state query reached after privilege drift"
                )

        def fetchone(self) -> dict[str, object]:
            return next(self.rows)

    class Connection:
        def __init__(self) -> None:
            self.current = Cursor()

        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def cursor(self) -> Cursor:
            return self.current

        def transaction(self) -> Transaction:
            return Transaction()

    class Transaction:
        def __enter__(self) -> Transaction:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    connection = Connection()
    scope = MODULE._Scope("source", "example.invalid", "subscription")
    migrations = {version: False for version in MODULE.MIGRATION_NAMES}
    migration_reached: list[bool] = []
    monkeypatch.setattr(MODULE, "build_plan", lambda **_kwargs: {"baseline": baseline})
    monkeypatch.setattr(MODULE, "_validate_plan", lambda _plan, _fresh: None)
    monkeypatch.setattr(MODULE, "_scope_and_baseline", lambda: (scope, baseline, migrations))
    monkeypatch.setattr(MODULE, "_migration_state", lambda _migrations, _baseline: "resumable")
    monkeypatch.setattr(MODULE, "_validate_disposable_acceptance", lambda _path: {})
    monkeypatch.setattr(MODULE, "_connect", lambda: connection)
    monkeypatch.setattr(
        MODULE,
        "_apply_migrations_in_transaction",
        lambda *_args: migration_reached.append(True),
    )

    with pytest.raises(
        MODULE.RadiusReconciliationProductionControlError,
        match="production_reconciliation_plan_input_drift",
    ):
        MODULE.apply({"baseline": baseline})

    assert migration_reached == []
    assert len(connection.current.executed) == 2
    assert all("schema_migrations" not in query for query in connection.current.executed)


def test_migrations_execute_inside_the_plan_bound_outer_transaction() -> None:
    body = MODULE._migration_sql_without_outer_transaction(MODULE.MIGRATIONS[80])

    assert "begin;" not in body.lower()
    assert "commit;" not in body.lower()
    assert "radius_session_reconciliation_projection" in body


def test_migration_bodies_restore_the_session_role_after_each_version() -> None:
    class Cursor:
        def __init__(self, connection: Connection) -> None:
            self.connection = connection

        def __enter__(self) -> Cursor:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: str) -> None:
            normalized = query.strip().lower()
            if normalized == "reset role":
                self.connection.effective_role = "session_owner"
                return
            self.connection.migration_start_roles.append(
                self.connection.effective_role
            )
            if "create role adlog_radius_session_reconciliation_writer" in normalized:
                self.connection.writer_creation_roles.append(
                    self.connection.effective_role
                )
                if self.connection.effective_role != "session_owner":
                    raise PermissionError("CREATE ROLE requires the session owner")
            if "set local role adlog_storage_owner" in normalized:
                self.connection.effective_role = "adlog_storage_owner"

    class Connection:
        def __init__(self) -> None:
            self.effective_role = "session_owner"
            self.migration_start_roles: list[str] = []
            self.writer_creation_roles: list[str] = []

        def cursor(self) -> Cursor:
            return Cursor(self)

    connection = Connection()
    migrations = {version: False for version in MODULE.MIGRATIONS}

    applied = MODULE._apply_migrations_in_transaction(
        connection, "resumable", migrations
    )

    assert applied == list(MODULE.MIGRATIONS)
    assert connection.migration_start_roles == ["session_owner"] * len(
        MODULE.MIGRATIONS
    )
    assert connection.writer_creation_roles == ["session_owner"]


def test_control_uses_corpus_wide_access_accept_class_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accept_uid = "11111111-1111-1111-1111-111111111111"
    first_accounting_uid = "22222222-2222-2222-2222-222222222222"
    second_accounting_uid = "33333333-3333-3333-3333-333333333333"
    external_accept_uid = "44444444-4444-4444-4444-444444444444"
    first_observation_id = "55555555-5555-5555-5555-555555555555"
    second_observation_id = "66666666-6666-6666-6666-666666666666"
    evidence = [
        MODULE._EvidenceManifest(accept_uid, "a" * 64, "a" * 64, 1, 10, 1),
        MODULE._EvidenceManifest(
            first_accounting_uid, "b" * 64, "b" * 64, 1, 10, 2
        ),
        MODULE._EvidenceManifest(
            second_accounting_uid, "c" * 64, "c" * 64, 1, 20, 1
        ),
        MODULE._EvidenceManifest(
            external_accept_uid, "d" * 64, "d" * 64, 1, 30, 1
        ),
    ]
    observations = [
        MODULE._TerminalObservation(
            first_observation_id,
            first_accounting_uid,
            "start",
            "ready",
            datetime(2026, 8, 11, 5, tzinfo=timezone.utc),
            10,
        ),
        MODULE._TerminalObservation(
            second_observation_id,
            second_accounting_uid,
            "start",
            "ready",
            datetime(2026, 8, 11, 5, tzinfo=timezone.utc),
            20,
        ),
    ]
    records = {
        accept_uid: VerifiedEvidenceRecord(
            accept_uid,
            _line(
                **{
                    "Packet-Type": "2",
                    "Fully-Qualified-Distinguished-Name": "CN=User,DC=example,DC=invalid",
                    "Class": "cross-batch-class",
                }
            ),
        ),
        first_accounting_uid: VerifiedEvidenceRecord(
            first_accounting_uid,
            _line(
                **{
                    "Packet-Type": "4",
                    "Class": "missing-class",
                    "Acct-Status-Type": "1",
                    "Acct-Session-Id": "opaque-session-a",
                    "NAS-Identifier": "vpn-gateway",
                }
            ),
        ),
        second_accounting_uid: VerifiedEvidenceRecord(
            second_accounting_uid,
            _line(
                **{
                    "Packet-Type": "4",
                    "Class": "cross-batch-class",
                    "Acct-Status-Type": "1",
                    "Acct-Session-Id": "opaque-session",
                    "NAS-Identifier": "vpn-gateway",
                }
            ),
        ),
        external_accept_uid: VerifiedEvidenceRecord(
            external_accept_uid,
            _line(
                **{
                    "Packet-Type": "2",
                    "Fully-Qualified-Distinguished-Name": "CN=User,DC=example,DC=invalid",
                    "Class": "cross-batch-class",
                }
            ),
        ),
    }

    class Cursor:
        def __enter__(self) -> Cursor:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, _query: str, _arguments: tuple[object, ...] = ()) -> None:
            return None

        def fetchone(self) -> dict[str, str]:
            return {"exact_principal_key": "entity:101"}

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def cursor(self) -> Cursor:
            return Cursor()

        def rollback(self) -> None:
            return None

    terminal_evidence = {
        item.evidence_uid: item
        for item in evidence
        if item.evidence_uid != external_accept_uid
    }
    monkeypatch.setattr(
        MODULE,
        "_select_terminal_inventory",
        lambda _cursor, _scope: (terminal_evidence, observations),
    )
    monkeypatch.setattr(
        MODULE,
        "_select_evidence_page",
        lambda _cursor, _scope, _after: (
            evidence[:2]
            if _after is None
            else evidence[2:]
            if _after == (10, 2, first_accounting_uid)
            else []
        ),
        raising=False,
    )
    monkeypatch.setattr(MODULE, "_read_verified_record", lambda item: records[item.evidence_uid])
    monkeypatch.setattr(MODULE, "_connect", lambda: Connection())

    summary, batches, discovery = MODULE._build_batches(
        MODULE._Scope("radius.example.invalid", "example.invalid", "subscription")
    )

    assert [item["terminal_receipt_count"] for item in summary] == [1, 1]
    assert [item["projected_count"] for item in summary] == [0, 1]
    assert [item["still_unresolved_count"] for item in summary] == [1, 0]
    assert all(item["access_accept_count"] == 2 for item in summary)
    assert [attempt.outcome for _batch, attempts in batches for attempt in attempts] == [
        "still_unresolved",
        "projected",
    ]
    assert discovery["manifest_count"] == 4
    assert discovery["selected_access_accept_count"] == 2


def test_identity_evidence_scan_rejects_an_oversized_page_before_object_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests = [
        MODULE._EvidenceManifest(
            f"00000000-0000-0000-0000-{index:012d}",
            "a" * 64,
            "a" * 64,
            1,
            index,
            0,
        )
        for index in range(2251)
    ]
    scope = MODULE._Scope("source", "example.invalid", "subscription")
    monkeypatch.setattr(
        MODULE,
        "_read_evidence_page",
        lambda _scope, _after: (
                manifests[:2001]
                if _after is None
            else manifests[
                _after[0] + 1 : _after[0] + 251
            ]
        ),
        raising=False,
    )
    monkeypatch.setattr(
        MODULE,
        "_read_verified_record",
        lambda _item: pytest.fail("object read must follow page preflight"),
    )

    with pytest.raises(
        MODULE.RadiusReconciliationProductionControlError,
        match="production_reconciliation_identity_scan_limit_exceeded",
    ):
        MODULE._scan_authorized_identity_evidence(scope, {})


def test_identity_evidence_page_is_scoped_to_radius_accounting_transport() -> None:
    class Cursor:
        def __enter__(self) -> Cursor:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: str, arguments: tuple[object, ...]) -> None:
            self.query = query
            self.arguments = arguments

        def fetchall(self) -> list[object]:
            return []

    cursor = Cursor()
    page = MODULE._select_evidence_page(
        cursor,
        MODULE._Scope("source", "example.invalid", "subscription"),
        None,
    )

    assert page == []
    assert "stream_id=%s" in cursor.query
    assert "transport_binding=%s" in cursor.query
    assert cursor.arguments[:3] == (
        "source",
        MODULE.RADIUS_ACCOUNTING_STREAM_ID,
        MODULE.RADIUS_ACCOUNTING_TRANSPORT_BINDING,
    )


def test_subscription_scope_binds_the_exact_radius_transport() -> None:
    source = MODULE.SCRIPT.read_text(encoding="utf-8") if hasattr(MODULE, "SCRIPT") else SCRIPT.read_text(encoding="utf-8")

    assert "from acquisition_consumer_subscriptions" in source
    assert "and transport_binding=%s" in source
    assert "RADIUS_ACCOUNTING_TRANSPORT_BINDING" in source


def test_disposable_acceptance_binds_065_080_and_required_safety_outcomes(
    tmp_path: Path,
) -> None:
    output = tmp_path / "radius-reconciliation.json"
    output.write_text(
        json.dumps(
            {
                "status": "passed",
                "forward_sha256": MODULE.sha256(MODULE.MIGRATIONS[65].read_bytes()).hexdigest(),
                "rollback_sha256": MODULE.sha256(MODULE.RECONCILIATION_ROLLBACKS[65].read_bytes()).hexdigest(),
                "projection_forward_sha256": MODULE.sha256(MODULE.MIGRATIONS[80].read_bytes()).hexdigest(),
                "projection_rollback_sha256": MODULE.sha256(MODULE.RECONCILIATION_ROLLBACKS[80].read_bytes()).hexdigest(),
                "acceptance": {
                    "original_rows_unchanged": True,
                    "writer_role_restricted_nologin": True,
                    "original_observation_update_denied": True,
                    "terminal_receipt_update_denied": True,
                    "evidence_delete_denied": True,
                    "append_only_output_update_denied": True,
                    "consumer_overlay_update_denied": True,
                    "outer_transaction_postcondition_readable": True,
                    "conflicting_second_resolution_blocked": True,
                    "reader_rollback_guarded_after_evidence": True,
                    "rollback_guarded_after_evidence": True,
                    "attempt_counts_total_projected_unresolved": [2, 1, 1],
                    "projected_session_count": 1,
                },
                "production_database_changed": False,
                "radius_source_contacted": False,
                "runtime_enabled": False,
                "autostart_enabled": False,
                "disposable_cluster_removed": True,
                "database": {"server_version_num": 180004},
            }
        ),
        encoding="utf-8",
    )

    validated = MODULE._validate_disposable_acceptance(output)

    assert validated["evidence_sha256"] == MODULE.sha256(output.read_bytes()).hexdigest()


def test_disposable_acceptance_fails_closed_when_missing(tmp_path: Path) -> None:
    with pytest.raises(
        MODULE.RadiusReconciliationProductionControlError,
        match="production_reconciliation_disposable_acceptance_required",
    ):
        MODULE._validate_disposable_acceptance(tmp_path / "missing.json")


def test_migration_state_resumes_only_a_valid_dependency_prefix() -> None:
    clean = {version: False for version in MODULE.MIGRATION_NAMES}
    clean[61] = True
    baseline = {
        "attempts_table": False,
        "overlays_table": False,
        "writer_role": False,
        "migration_role_can_create_role": True,
    }
    assert MODULE._migration_state(clean, baseline) == "resumable"

    invalid = dict(clean)
    invalid[63] = True
    assert MODULE._migration_state(invalid, baseline) == "inconsistent"


def test_control_fails_closed_for_controlled_migration_marker_collision() -> None:
    rows = [{"version": 80, "name": "unrelated_migration"}]

    with pytest.raises(
        MODULE.RadiusReconciliationProductionControlError,
        match="production_reconciliation_migration_version_conflict",
    ):
        MODULE._migration_markers(rows)


def test_foreign_production_079_marker_leaves_candidate_080_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production_markers = [
        {"version": 79, "name": "plugin_runtime_control_requests"},
    ]

    markers = MODULE._migration_markers(production_markers)
    baseline = {
        "attempts_table": False,
        "overlays_table": False,
        "writer_role": False,
        "migration_role_can_create_role": True,
    }

    assert 80 not in {int(row["version"]) for row in production_markers}
    assert 79 not in MODULE.MIGRATIONS
    assert MODULE.MIGRATIONS[80].name == "080_radius_session_reconciliation_projection.sql"
    assert markers[80] is False
    markers[61] = True
    assert MODULE._migration_state(markers, baseline) == "resumable"

    scope = MODULE._Scope(
        source_instance_id="source",
        organization_fqdn="example.invalid",
        subscription_id="subscription",
    )
    plan_baseline = {
        "source_instance_sha256": "a" * 64,
        "cursor_revision": 3,
        "observations": 83,
        "terminal_unresolved_receipts": 83,
        "nonterminal_deliveries": 0,
        **baseline,
        "attempt_count": 0,
        "overlay_count": 0,
    }
    batches = [
        {
            "terminal_receipt_count": 17,
            "projected_count": 17,
            "still_unresolved_count": 0,
        },
        {
            "terminal_receipt_count": 50,
            "projected_count": 50,
            "still_unresolved_count": 0,
        },
        {
            "terminal_receipt_count": 16,
            "projected_count": 16,
            "still_unresolved_count": 0,
        },
    ]
    monkeypatch.setattr(
        MODULE,
        "_scope_and_baseline",
        lambda: (scope, plan_baseline, markers),
    )
    monkeypatch.setattr(MODULE, "_build_batches", lambda _scope: (batches, []))

    disposable = {"evidence_sha256": "b" * 64}
    monkeypatch.setattr(
        MODULE,
        "_validate_disposable_acceptance",
        lambda _path: disposable,
    )
    monkeypatch.setattr(MODULE, "_build_batches", lambda _scope: (batches, [], {}))

    plan = MODULE.build_plan()

    assert plan["status"] == "ready"
    assert plan["disposable_acceptance"] == disposable
    assert "79" not in plan["migration_sha256"]
    assert plan["migration_sha256"]["80"] == MODULE.sha256(
        MODULE.MIGRATIONS[80].read_bytes()
    ).hexdigest()


def test_postcondition_is_bound_to_immutable_plan_membership() -> None:
    class Cursor:
        def __init__(self) -> None:
            self.calls: list[tuple[str, tuple[object, ...]]] = []

        def __enter__(self) -> Cursor:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: str, arguments: tuple[object, ...]) -> None:
            self.calls.append((query, arguments))

        def fetchone(self) -> dict[str, int]:
            return {
                "attempt_count": 83,
                "projected_attempt_count": 83,
                "still_unresolved_attempt_count": 0,
                "overlay_count": 83,
                "projection_row_count": 1,
                "original_unresolved_observation_count": 83,
                "original_unresolved_receipt_count": 83,
            }

    class Connection:
        def __init__(self) -> None:
            self.current = Cursor()

        def cursor(self) -> Cursor:
            return self.current

    connection = Connection()
    observation_ids = [str(index) for index in range(83)]
    result = MODULE._postcondition(connection, observation_ids=observation_ids)

    assert result["attempt_count"] == 83
    query, arguments = connection.current.calls[0]
    assert query.count("observation_id=any(%s::uuid[])") == 7
    assert all(argument is observation_ids for argument in arguments)

    with pytest.raises(MODULE.RadiusReconciliationProductionControlError):
        MODULE._postcondition(connection, observation_ids=observation_ids[:-1])


def test_apply_rebuilds_only_projected_observations_in_mixed_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = {
        "source_instance_sha256": "a" * 64,
        "cursor_revision": 3,
        "observations": 83,
        "terminal_unresolved_receipts": 83,
        "nonterminal_deliveries": 0,
        "attempts_table": False,
        "overlays_table": False,
        "writer_role": False,
        "attempt_count": 0,
        "overlay_count": 0,
    }
    plan = {
        "status": "ready",
        "baseline": baseline,
        "reconciliation": {
            "terminal_candidate_count": 83,
            "projected_count": 1,
            "still_unresolved_count": 82,
        },
    }
    projected = ReconciliationAttempt(
        "b" * 64,
        "11111111-1111-1111-1111-111111111111",
        "21111111-1111-1111-1111-111111111111",
        "projected",
        "c" * 64,
        "resolver-v1",
        "d" * 64,
    )
    unresolved = ReconciliationAttempt(
        "e" * 64,
        "12222222-2222-2222-2222-222222222222",
        "22222222-2222-2222-2222-222222222222",
        "still_unresolved",
        "c" * 64,
        "resolver-v1",
        None,
    )

    class Transaction:
        def __enter__(self) -> Transaction:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def transaction(self) -> Transaction:
            return Transaction()

    calls: dict[str, object] = {}
    scope = MODULE._Scope("source", "example.invalid", "subscription")
    batch = SimpleNamespace(proposals={projected.observation_id: object()})
    receipts = (
        SimpleNamespace(outcome="projected", overlay_created=True, observation_id=projected.observation_id),
        SimpleNamespace(
            outcome="still_unresolved",
            overlay_created=False,
            observation_id=unresolved.observation_id,
        ),
    )
    monkeypatch.setattr(MODULE, "build_plan", lambda **_kwargs: plan)
    monkeypatch.setattr(MODULE, "_validate_plan", lambda _plan, _fresh: None)
    monkeypatch.setattr(MODULE, "_scope_and_baseline", lambda: (scope, baseline, {}))
    monkeypatch.setattr(MODULE, "_migration_state", lambda _migrations, _baseline: "resumable")
    monkeypatch.setattr(
        MODULE,
        "_apply_migrations_in_transaction",
        lambda _conn, _state, _migrations: [62, 63],
    )
    monkeypatch.setattr(
        MODULE,
        "_validated_batches_after_migration",
        lambda _plan, _scope, **_kwargs: [(batch, (projected, unresolved))],
    )
    monkeypatch.setattr(MODULE, "_validate_disposable_acceptance", lambda _path: {"evidence_sha256": "b" * 64})
    monkeypatch.setattr(MODULE, "_connect", lambda: Connection())
    monkeypatch.setattr(MODULE, "_lock_and_validate_plan_inputs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(MODULE, "_restore_session_role", lambda _conn: None)
    monkeypatch.setattr(MODULE, "write_reconciliation_attempts", lambda _conn, attempts, proposals: receipts)
    monkeypatch.setattr(
        MODULE,
        "_projection_requests",
        lambda **kwargs: calls.setdefault("projection_ids", kwargs["observation_ids"]) or (),
    )
    monkeypatch.setattr(
        MODULE,
        "rebuild_reconciled_radius_projections",
        lambda _conn, **kwargs: calls.setdefault("rebuilt", kwargs["projections"]) or 1,
    )
    monkeypatch.setattr(
        MODULE,
        "_postcondition",
        lambda _conn, **_kwargs: {
            "attempt_count": 83,
            "projected_attempt_count": 1,
            "still_unresolved_attempt_count": 82,
            "overlay_count": 1,
            "projection_row_count": 1,
            "original_unresolved_observation_count": 83,
            "original_unresolved_receipt_count": 83,
        },
    )

    result = MODULE.apply(plan)

    assert calls["projection_ids"] == [projected.observation_id]
    assert result["reconciliation"]["attempt_count"] == 2
    assert result["reconciliation"]["overlay_count"] == 1
    assert result["reconciliation"]["still_unresolved_count"] == 82


def test_apply_requires_and_reserves_durable_output(tmp_path: Path) -> None:
    plan = {"plan_schema_version": 1}
    output = ROOT / "artifacts/g11a3/test-apply-evidence.json"

    with pytest.raises(MODULE.RadiusReconciliationProductionControlError):
        MODULE.main(
            [
                "--action",
                "apply",
                "--plan",
                str(tmp_path / "plan.json"),
                "--confirmation",
                MODULE.CONFIRMATION,
            ]
        )

    prepared, reservation_id = MODULE._prepare_apply_output(output, plan)
    try:
        assert prepared == output.resolve()
        recorded = prepared.read_text(encoding="utf-8")
        assert '"status": "apply_started"' in recorded
        assert '"plan_sha256"' in recorded
        assert '"reservation_id"' in recorded
        assert '"production_database_changed": "unknown"' in recorded
        with pytest.raises(MODULE.RadiusReconciliationProductionControlError):
            MODULE._write_output(output, plan)
        with pytest.raises(MODULE.RadiusReconciliationProductionControlError):
            MODULE._prepare_apply_output(output, plan)
        MODULE._finalize_apply_output(
            output,
            {"status": "passed", "production_database_changed": True},
            reservation_id=reservation_id,
        )
        finalized = output.read_text(encoding="utf-8")
        assert '"status": "passed"' in finalized
        assert '"plan_sha256"' in finalized
        assert f'"reservation_id": "{reservation_id}"' in finalized
        with pytest.raises(MODULE.RadiusReconciliationProductionControlError):
            MODULE._finalize_apply_output(
                output,
                plan,
                reservation_id=reservation_id,
            )
    finally:
        prepared.unlink(missing_ok=True)

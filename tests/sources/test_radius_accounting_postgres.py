from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import inspect
import json
from pathlib import Path
from uuid import UUID

import pytest

from server.source_packs.radius.accounting import (
    DATABASE_COMPATIBLE_COLUMNS,
)
from server.source_packs.radius.accounting_postgres import (
    RadiusEvidenceObject,
    RadiusPostgresContractError,
    _validate_batch,
    load_postgres_contract,
)
from server.source_packs.radius.accounting_registration import (
    RadiusRegistrationError,
    load_registration_contract,
    validate_registration_contract,
)
from server.source_packs.radius.collection_routes import load_radius_collection_routes
from server.source_packs.radius.accounting_runtime_contract import (
    RadiusBatchPlan,
    initial_cursor,
    plan_batch,
)
from scripts.maintenance import stage9_radius_postgres_migrate as production_migrate, stage9_radius_postgres_production_preflight as production_preflight


MIGRATION = Path(
    "config/postgres_migrations/"
    "058_radius_accounting_transaction_foundation.sql"
)
ROLLBACK = Path(
    "config/postgres_migrations/"
    "058_radius_accounting_transaction_foundation.rollback.sql"
)
PRODUCTION_PREFLIGHT = Path(
    "scripts/maintenance/"
    "stage9_radius_postgres_production_preflight.py"
)
PRODUCTION_MIGRATE = Path(
    "scripts/maintenance/stage9_radius_postgres_migrate.py"
)


def _line(*, packet_type: str, status: str = "") -> str:
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    index = {
        name: position
        for position, name in enumerate(DATABASE_COMPATIBLE_COLUMNS)
    }
    values = {
        "ComputerName": "NPS01",
        "ServiceName": "IAS",
        "Record-Date": "07/30/2026",
        "Record-Time": "15:00:00",
        "Packet-Type": packet_type,
        "Fully-Qualified-Distinguished-Name": (
            "example.test/Users/sample.user"
        ),
        "Class": "opaque-class",
        "NAS-Identifier": "VPN-GW-01",
        "Acct-Status-Type": status,
        "Acct-Session-Id": "opaque-session",
    }
    for name, value in values.items():
        row[index[name]] = value
    return ",".join(row)


def _plan():
    cursor = initial_cursor(
        source_instance_id="radius-fixture-1",
        transport_binding="fixture-log",
        file_generation="in-20260730",
    )
    return plan_batch(
        cursor=cursor,
        class_cache={},
        file_generation=cursor.file_generation,
        start_offset=0,
        end_offset=200,
        lines=[
            _line(packet_type="2"),
            _line(packet_type="4", status="1"),
        ],
        identity_resolver=lambda _: (
            "sid:S-1-5-21-100000003-200000003-300000003-1101"
        ),
        batch_observed_at_utc=datetime(
            2026, 7, 30, 8, 0, tzinfo=timezone.utc
        ),
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )


def _evidence(plan):
    return tuple(
        RadiusEvidenceObject(
            evidence_uid=UUID(
                f"00000000-0000-0000-0000-{ordinal:012d}"
            ),
            canonical_record_sha256=digest,
            object_reference=f"evidence:radius.fixture.{ordinal}",
            object_sha256=sha256(
                f"fixture-object-{ordinal}".encode()
            ).hexdigest(),
            object_size_bytes=128,
            verified_at_utc=datetime(
                2026, 7, 30, 8, 1, tzinfo=timezone.utc
            ),
        )
        for ordinal, digest in enumerate(plan.evidence_sha256, start=1)
    )


def test_postgres_contract_stays_disposable_and_bounded() -> None:
    contract = load_postgres_contract()
    assert contract["status"] == "accepted_for_disposable_only"
    assert contract["runtime_enabled"] is False
    assert contract["production_migration_applied"] is False
    assert contract["source_contact_allowed"] is False
    assert contract["maximum_records_per_commit"] == 1000


def test_registration_contract_is_exact_disabled_and_bootstrap_gated() -> None:
    contract = load_registration_contract()
    routes = load_radius_collection_routes()
    assert contract["status"] == "prepared_disabled_only"
    assert contract["desired_activation"] == "disabled"
    assert contract["source"]["source_instance_id"] == routes["source_instance_id"]
    assert contract["source"]["endpoint_identity"] == (
        f"fqdn:{routes['source_name']}|ipv4:{routes['owner_confirmed_ip']}"
    )
    assert contract["subscription"]["subscription_id"] == (
        "vpn-radius-session-observations-radius01-v1"
    )
    assert contract["source"]["credential_handle"] is None
    assert contract["stream"]["initial_cursor_policy"] == (
        "requires_bounded_live_bootstrap"
    )
    assert "worker_activation" in contract["prohibited_actions"]


def test_migration_058_current_state_attestation_contract_is_read_only() -> None:
    source = PRODUCTION_MIGRATE.read_text(encoding="utf-8").casefold()
    assert '"finalize-applied"' in source
    assert "radius-accounting-postgres58-production-attestation.json" in source
    assert '"action": "finalize_applied_readback"' in source
    assert '"evidence_kind": "production_current_state_attestation"' in source
    assert "begin read only" in source
    assert "production_database_changed\": false" in source


def test_registration_contract_rejects_endpoint_drift() -> None:
    contract = load_registration_contract()
    contract["source"]["endpoint_identity"] = "fqdn:radius01.example.invalid|ipv4:192.0.2.7"
    with pytest.raises(
        RadiusRegistrationError,
        match="registration_source_identity_mismatch",
    ):
        validate_registration_contract(contract)


def test_evidence_manifest_must_match_plan_exactly() -> None:
    contract = load_postgres_contract()
    plan = _plan()
    evidence = list(_evidence(plan))
    _validate_batch(plan, tuple(evidence), contract)
    evidence[0] = RadiusEvidenceObject(
        evidence_uid=evidence[0].evidence_uid,
        canonical_record_sha256="0" * 64,
        object_reference=evidence[0].object_reference,
        object_sha256=evidence[0].object_sha256,
        object_size_bytes=evidence[0].object_size_bytes,
        verified_at_utc=evidence[0].verified_at_utc,
    )
    with pytest.raises(
        RadiusPostgresContractError,
        match="evidence_hash_mismatch",
    ):
        _validate_batch(plan, tuple(evidence), contract)


def test_batch_cannot_forge_rotation_or_change_cursor_owner() -> None:
    contract = load_postgres_contract()
    plan = _plan()
    evidence = _evidence(plan)
    forged = RadiusBatchPlan(
        contract_id=plan.contract_id,
        current_cursor=plan.current_cursor,
        next_cursor=plan.next_cursor,
        rotation_from_eof=True,
        evidence_sha256=plan.evidence_sha256,
        session_observations=plan.session_observations,
        proposed_class_cache=plan.proposed_class_cache,
        counters=plan.counters,
    )
    with pytest.raises(
        RadiusPostgresContractError,
        match="rotation_claim_mismatch",
    ):
        _validate_batch(forged, evidence, contract)


def test_migration_058_is_atomic_least_privilege_foundation() -> None:
    sql = MIGRATION.read_text(encoding="utf-8").lower()
    assert "requires schema migration 055" in sql
    assert "create role adlog_radius_accounting_worker" in sql
    assert "nologin nosuperuser nocreatedb nocreaterole" in sql
    assert "acquisition_source_instances" in sql
    assert "acquisition_consumer_subscriptions" in sql
    assert "core_evidence_manifests" in sql
    assert "radius_accounting_session_observations" in sql
    assert "acquisition_delivery_outbox" in sql
    assert "radius_accounting_class_cache" in sql
    assert "cursor_start_byte_offset" in sql
    assert "batch_record_ordinal" in sql
    assert "raw_record" not in sql
    assert "account_session_id" not in sql
    assert "nas_identity" not in sql
    assert "values (58,'radius_accounting_transaction_foundation')" in sql


def test_migration_058_rollback_refuses_any_persisted_state() -> None:
    sql = ROLLBACK.read_text(encoding="utf-8").lower()
    guard = sql.index(
        "migration 058 rollback refuses persisted acquisition evidence/state"
    )
    first_drop = sql.index("drop table")
    assert guard < first_drop
    assert "drop role adlog_radius_accounting_worker" in sql
    assert "delete from schema_migrations" in sql






def test_production_preflight_is_read_only_and_single_migration_scoped() -> None:
    source = PRODUCTION_PREFLIGHT.read_text(encoding="utf-8").lower()
    inspect_source = inspect.getsource(production_preflight.inspect).lower()
    assert "set transaction read only" in inspect_source
    assert "conn.rollback()" in inspect_source
    for mutation in (
        "insert into",
        "update ",
        "delete from",
        "create table",
        "create role",
        "drop table",
        "drop role",
        "alter table",
    ):
        assert mutation not in inspect_source
    assert '"execution_contract": "single_file_058_only"' in source
    assert '"excluded_from_automatic_sequence": [56, 57]' in source
    assert "preflight evidence already exists" in source


def test_production_migrate_is_exact_and_confirmation_gated() -> None:
    source = PRODUCTION_MIGRATE.read_text(encoding="utf-8").lower()
    assert "apply-stage9-radius-postgres-58" in source
    assert "rollback-stage9-radius-postgres-58" in source
    assert "single_file_058_only" in source
    assert "excluded_from_automatic_sequence" in source
    assert "migration files changed after preflight" in source
    assert "rollback refuses persisted acquisition state" in source
    assert "migration evidence already exists" in source
    assert "source_instance_created" in source
    assert "source_instance_created\": true" not in source


def test_preflight_evidence_validation_rejects_hash_drift() -> None:
    evidence = {
        "status": "ready",
        "blockers": [],
        "identity": {"database": "fixture"},
        "schema": {"maximum_marker": 55},
        "privileges": {"storage_owner_member": True},
        "migration": {
            "version": 58,
            "execution_contract": "single_file_058_only",
            "excluded_from_automatic_sequence": [56, 57],
            **production_migrate._hashes(),
        },
    }
    live = {
        "status": "ready",
        "blockers": [],
        "identity": dict(evidence["identity"]),
        "schema": dict(evidence["schema"]),
        "privileges": dict(evidence["privileges"]),
    }
    production_migrate._validate_preflight(evidence, live)
    evidence["migration"]["forward_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="changed after preflight"):
        production_migrate._validate_preflight(evidence, live)


def _producer_shaped_disposable_058_result() -> dict:
    """The exact nested shape returned by disposable_acceptance.run()."""
    registration_contract = load_registration_contract()
    return {
        "status": "passed",
        "generated_at_utc": "2026-08-11T00:00:00+00:00",
        "database": {
            "database": "sli_disposable_radius58_fixture",
            "user": "fixture_user",
            "server_version_num": 160000,
            "encoding": "UTF8",
        },
        "evidence": {
            "migration": {
                "marker": True,
                "worker_role": True,
                "evidence_insert": True,
                "evidence_delete": False,
                "cursor_update": True,
            },
            "registration": {
                "source_instance_id": registration_contract["source"][
                    "source_instance_id"
                ],
                "subscription_id": registration_contract["subscription"][
                    "subscription_id"
                ],
                "stream_id": registration_contract["stream"]["stream_id"],
                "transport_binding": registration_contract["stream"][
                    "transport_binding"
                ],
                "registered_disabled_first": True,
                "disposable_manual_enable_only": True,
            },
            "evidence_first": {
                "published_objects": 2,
                "database_manifest_rows_before_commit": 0,
                "orphan_retry_is_idempotent": True,
                "payload_in_result": False,
            },
            "injected_failures": [
                {"phase": "evidence", "rolled_back": True},
                {"phase": "outbox", "rolled_back": True},
                {"phase": "cache", "rolled_back": True},
            ],
            "commit": {
                "evidence_rows": 2,
                "observation_rows": 1,
                "outbox_rows": 1,
                "class_cache_rows": 1,
                "cursor_revision": 1,
                "cursor_byte_offset": 200,
            },
            "stale_replay_rejected": True,
            "persisted_state_rollback_guarded": True,
            "clean_rollback": {
                "marker": False,
                "foundation_table": False,
                "worker_role": False,
            },
        },
        "production_database_changed": False,
        "radius_source_contacted": False,
        "runtime_enabled": False,
        "disposable_schema_cleaned": True,
    }


def test_accepted_disposable_058_uses_actual_producer_result_shape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    evidence = tmp_path / "radius-accounting-postgres58-disposable.json"
    evidence.write_text(
        json.dumps(_producer_shaped_disposable_058_result()), encoding="utf-8"
    )
    monkeypatch.setattr(production_migrate, "DISPOSABLE_EVIDENCE", evidence)

    assert production_migrate._accepted_disposable()["status"] == "passed"


@pytest.mark.parametrize(
    "identifier",
    (
        "source_instance_id",
        "subscription_id",
        "stream_id",
        "transport_binding",
    ),
)
def test_accepted_disposable_058_requires_every_registration_identifier(
    identifier: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = _producer_shaped_disposable_058_result()
    result["evidence"]["registration"].pop(identifier)
    evidence = tmp_path / "radius-accounting-postgres58-disposable.json"
    evidence.write_text(json.dumps(result), encoding="utf-8")
    monkeypatch.setattr(production_migrate, "DISPOSABLE_EVIDENCE", evidence)

    with pytest.raises(RuntimeError, match="disposable_058_evidence_invalid"):
        production_migrate._accepted_disposable()


def test_accepted_disposable_058_rejects_missing_injected_rollback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    result = _producer_shaped_disposable_058_result()
    result["evidence"]["injected_failures"][1]["rolled_back"] = False
    evidence = tmp_path / "radius-accounting-postgres58-disposable.json"
    evidence.write_text(json.dumps(result), encoding="utf-8")
    monkeypatch.setattr(production_migrate, "DISPOSABLE_EVIDENCE", evidence)

    with pytest.raises(RuntimeError, match="disposable_058_evidence_invalid"):
        production_migrate._accepted_disposable()

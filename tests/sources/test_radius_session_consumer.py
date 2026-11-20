from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.source_packs.radius.accounting_manual_control import (
    load_manual_control_contract,
)
from server.source_packs.radius.accounting_registration import (
    load_registration_contract,
)
from server.source_packs.radius.session_consumer import (
    CONTRACT_ID,
    RadiusSessionConsumerError,
    _rebuild_session_projection,
    fail_radius_delivery,
    load_consumer_contract,
)


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "server" / "source_packs" / "radius" / (
    "session_consumer.py"
)


def test_contract_is_disabled_bounded_and_source_free() -> None:
    value = load_consumer_contract()
    assert value["contract_id"] == CONTRACT_ID
    assert value["runtime_enabled"] is False
    assert value["autostart_enabled"] is False
    assert value["source_contact_allowed"] is False
    assert value["maximum_deliveries_per_claim"] == 50
    assert value["maximum_observations_per_session_key"] == 10000
    assert value["maximum_attempts"] == 5


def test_consumer_subscription_matches_registered_manual_route() -> None:
    consumer = load_consumer_contract()
    manual = load_manual_control_contract()
    registration = load_registration_contract()
    assert consumer["subscription_id"] == manual["subscription_id"]
    assert consumer["subscription_id"] == registration["subscription"][
        "subscription_id"
    ]


def test_consumer_uses_leases_skip_locked_and_atomic_receipts() -> None:
    source = MODULE.read_text(encoding="utf-8").lower()
    assert "for update skip locked" in source
    assert "delivery_state='leased'" in source
    assert "lease_until>now()" in source
    assert "maximum_attempts_exhausted" in source
    assert "pg_advisory_xact_lock" in source
    assert "radius_session_projection_receipts" in source
    assert "radius_vpn_session_projection" in source
    assert "delivery_state='delivered'" in source


def test_projection_reads_typed_observations_with_manifest_hash_not_raw_files() -> None:
    source = MODULE.read_text(encoding="utf-8").lower()
    assert "radius_accounting_session_observations" in source
    assert source.count("join core_evidence_manifests manifest") == 2
    assert source.count("manifest.canonical_record_sha256") == 2
    assert "provenance_json->>'canonical_record_sha256'" not in source
    assert "acquisition_evidence_store" not in source
    assert "open(" not in source


def test_projection_rebuild_honors_append_only_reconciliation_overlays() -> None:
    source = " ".join(MODULE.read_text(encoding="utf-8").lower().split())
    assert "left join radius_session_identity_overlays overlay" in source
    assert "coalesce( overlay.session_identity_key" in source
    assert "coalesce( overlay.exact_principal_key" in source
    assert "overlay.observation_id is not null" in source


def test_projection_uses_base_identity_without_optional_overlay_migration() -> None:
    session_key = "radius-session:" + "a" * 64
    principal_key = "entity:11111111-1111-1111-1111-111111111111"

    class CursorWithoutOverlay:
        def __init__(self) -> None:
            self.statements: list[str] = []
            self._one: tuple[bool] | None = None
            self._many: tuple[tuple[object, ...], ...] = ()

        def execute(self, sql: str, _params: object = None) -> None:
            normalized = " ".join(sql.lower().split())
            self.statements.append(normalized)
            if "has_table_privilege" in normalized:
                self._one = (False,)
                return
            if "from acquisition_delivery_outbox" in normalized:
                if "radius_session_identity_overlays" in normalized:
                    raise AssertionError("optional overlay table must not be queried")
                self._many = (
                    (
                        "observation-1",
                        "start",
                        "exact",
                        "ready",
                        session_key,
                        principal_key,
                        datetime(2026, 8, 15, 0, 0, tzinfo=timezone.utc),
                        "f" * 64,
                    ),
                )

        def fetchone(self) -> tuple[bool] | None:
            return self._one

        def fetchall(self) -> tuple[tuple[object, ...], ...]:
            return self._many

    cursor = CursorWithoutOverlay()
    projected = _rebuild_session_projection(
        cursor,
        session_key=session_key,
        current_delivery_id=1,
        subscription_id="vpn-radius-session-observations-radius01-v1",
        maximum_observations=10,
    )

    assert projected == 1
    assert any("canonical_record_sha256" in statement for statement in cursor.statements)
    assert any(
        "insert into radius_vpn_session_projection" in statement
        for statement in cursor.statements
    )


def test_failure_inputs_are_bounded_before_database_use() -> None:
    class NeverConnection:
        def transaction(self):
            raise AssertionError("database must not be reached")

    with pytest.raises(
        RadiusSessionConsumerError,
        match="error_code_invalid",
    ):
        fail_radius_delivery(
            NeverConnection(),
            delivery_id=1,
            lease_token=__import__("uuid").uuid4(),
            error_code="Bad Error",
        )

    with pytest.raises(
        RadiusSessionConsumerError,
        match="retry_delay_invalid",
    ):
        fail_radius_delivery(
            NeverConnection(),
            delivery_id=1,
            lease_token=__import__("uuid").uuid4(),
            error_code="bounded_error",
            retry_delay_seconds=3601,
        )


def test_core_claim_pins_ids_without_role_switch(monkeypatch):
    from contextlib import nullcontext
    from server.source_packs.radius import session_consumer as consumer

    monkeypatch.setattr(consumer, "_validate_contract", lambda *_args, **_kwargs: None)
    contract = {"maximum_deliveries_per_claim": 50, "maximum_attempts": 5,
                "lease_seconds": 120, "subscription_id": "synthetic-subscription"}
    calls = []
    class Cursor:
        def execute(self, sql, params=None):
            calls.append((sql, params))
        def fetchall(self):
            return []
    cursor = Cursor()
    class Connection:
        def transaction(self):
            return nullcontext()
        def cursor(self):
            return nullcontext(cursor)
    consumer.claim_radius_deliveries(Connection(), limit=2, contract=contract,
                                    delivery_ids=(1, 2), activate_role=False)
    assert not any("set local role" in sql for sql, _ in calls)
    assert "delivery_id=any(%s)" in calls[-1][0]
    assert calls[-1][1][2] == [1, 2]
    calls.clear()
    consumer.claim_radius_deliveries(Connection(), contract=contract)
    assert calls[0][0] == "set local role adlog_radius_session_consumer"
    assert calls[-1][1][2] == 50
    assert "delivery_id=any(%s)" not in calls[-1][0]


def test_core_consumer_contract_uses_server_binding_without_windows_routes(monkeypatch):
    from server.source_packs.radius import accounting_registration, session_consumer
    monkeypatch.setattr(accounting_registration, "load_registration_contract",
                        lambda: pytest.fail("Windows collection configuration consulted"))
    contract = session_consumer.load_consumer_contract(subscription_id="synthetic-subscription")
    assert contract["subscription_id"] == "synthetic-subscription"
    session_consumer._validate_contract(contract, subscription_id="synthetic-subscription")


def test_projection_shared_record_budget_bounds_query_before_effects(monkeypatch):
    from server.source_packs.radius import session_consumer as consumer
    calls = []
    class Cursor:
        def execute(self, sql, params=None):
            calls.append((sql, params))
        def fetchone(self):
            return (False,)
        def fetchall(self):
            return [None] * 3
    with pytest.raises(RadiusSessionConsumerError, match="session_observation_limit_exceeded"):
        consumer._rebuild_session_projection(Cursor(), session_key="synthetic-key", current_delivery_id=1,
            subscription_id="synthetic-subscription", maximum_observations=10000, record_budget=[2])
    assert calls[-1][1][-1] == 3
    assert not any("delete from" in sql for sql, _ in calls)

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FORWARD = (
    ROOT
    / "config/postgres_migrations/"
    "060_radius_identity_resolver_owner.sql"
).read_text(encoding="utf-8")
ROLLBACK = (
    ROOT
    / "config/postgres_migrations/"
    "060_radius_identity_resolver_owner.rollback.sql"
).read_text(encoding="utf-8")


def test_forward_creates_dedicated_nologin_definer_owner() -> None:
    lowered = FORWARD.casefold()
    assert "create role adlog_radius_identity_resolver" in lowered
    assert "noinherit nologin nosuperuser" in lowered
    assert (
        "alter function sli_radius_resolve_principal_key(text,text)"
        in lowered
    )
    assert "owner to adlog_radius_identity_resolver" in lowered
    assert (
        "grant usage,create on schema public "
        "to adlog_radius_identity_resolver"
        in lowered
    )
    assert (
        "revoke create on schema public "
        "from adlog_radius_identity_resolver"
        in lowered
    )
    assert "grant select(id,fqdn) on table domains" in lowered
    assert (
        "grant select(entity_id,domain_id,alias_type,normalized_value)"
        in lowered
    )
    assert "to adlog_radius_accounting_worker" in lowered
    assert "from public" in lowered


def test_forward_does_not_grant_identity_tables_to_worker() -> None:
    lowered = FORWARD.casefold()
    assert (
        "on table domains\nto adlog_radius_accounting_worker"
        not in lowered
    )
    assert (
        "on table ad_context_entity_aliases\n"
        "to adlog_radius_accounting_worker"
        not in lowered
    )


def test_rollback_preserves_runtime_state_and_restores_function() -> None:
    lowered = ROLLBACK.casefold()
    assert "rollback refuses persisted radius runtime state" in lowered
    assert "owner to adlog_storage_owner" in lowered
    assert "drop role adlog_radius_identity_resolver" in lowered
    assert "drop function" not in lowered

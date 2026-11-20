from __future__ import annotations

from server.source_packs.radius.accounting_identity import (
    derive_slash_dn_candidates,
    resolve_radius_principal,
)


def test_slash_dn_candidates_cover_cn_and_ou_without_values_in_result() -> None:
    derived = derive_slash_dn_candidates(
        "example.invalid/Users/Example User"
    )
    assert derived is not None
    domain, candidates = derived
    assert domain == "example.invalid"
    assert set(candidates) == {
        "cn=example user,cn=users,dc=example,dc=invalid",
        "cn=example user,ou=users,dc=example,dc=invalid",
    }


def test_resolver_returns_only_one_unique_structural_entity() -> None:
    aliases = {
        (
            "example.invalid",
            "cn=example user,cn=users,dc=example,dc=invalid",
        ): "entity:101",
    }
    result = resolve_radius_principal(
        "example.invalid/Users/Example User",
        expected_organization_fqdn="example.invalid",
        exact_lookup=lambda domain, dn: aliases.get((domain, dn.casefold())),
    )
    assert result == "entity:101"


def test_resolver_fails_closed_on_ambiguity_or_foreign_domain() -> None:
    aliases = {
        (
            "example.invalid",
            "cn=example user,cn=users,dc=example,dc=invalid",
        ): "entity:101",
        (
            "example.invalid",
            "cn=example user,ou=users,dc=example,dc=invalid",
        ): "entity:202",
    }
    lookup = lambda domain, dn: aliases.get((domain, dn.casefold()))
    assert (
        resolve_radius_principal(
            "example.invalid/Users/Example User",
            expected_organization_fqdn="example.invalid",
            exact_lookup=lookup,
        )
        is None
    )
    assert (
        resolve_radius_principal(
            "other.test/Users/Example User",
            expected_organization_fqdn="example.invalid",
            exact_lookup=lookup,
        )
        is None
    )


def test_resolver_preserves_existing_exact_dn_lookup() -> None:
    result = resolve_radius_principal(
        "cn=example user,cn=users,dc=example,dc=invalid",
        expected_organization_fqdn="example.invalid",
        exact_lookup=lambda _domain, dn: (
            "entity:101" if dn.startswith("cn=") else None
        ),
    )
    assert result == "entity:101"

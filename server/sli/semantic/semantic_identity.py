"""Exact identity primitives shared by semantic correlation boundaries."""
from __future__ import annotations

import re


_DOMAIN_SID = re.compile(r"^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$")
_DOMAIN_ID = re.compile(r"^[1-9][0-9]*$")
_PARTITION_KEY_SETS = frozenset(
    {
        frozenset({"domain", "account_sid"}),
        frozenset({"domain", "member_sid", "group_sid"}),
        frozenset({"domain", "account_member_sid"}),
    }
)


def is_exact_domain_sid(value: object) -> bool:
    """Return whether a value is the canonical numeric domain-SID form."""
    return (
        isinstance(value, str)
        and len(value) <= 184
        and _DOMAIN_SID.fullmatch(value) is not None
    )


def parse_exact_domain_sid_partition(partition_key: object) -> dict[str, str] | None:
    """Parse one closed-form domain-SID correlation partition."""
    if not isinstance(partition_key, str):
        return None
    pieces: dict[str, str] = {}
    for component in partition_key.split("|"):
        key, separator, value = component.partition(":")
        if not separator or not key or not value or key in pieces:
            return None
        pieces[key] = value
    if frozenset(pieces) not in _PARTITION_KEY_SETS:
        return None
    if _DOMAIN_ID.fullmatch(pieces["domain"]) is None:
        return None
    return pieces if all(
        is_exact_domain_sid(value) for key, value in pieces.items() if key.endswith("_sid")
    ) else None

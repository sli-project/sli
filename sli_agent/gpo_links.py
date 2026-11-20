# SPDX-License-Identifier: Apache-2.0
"""Lossless gPLink edits for the future credential-bound GPO executor.

This module does not connect to AD. The supplied connection must implement an
atomic, pinned-DC LDAP assertion (including absence of gPLink), under the chosen
account. A read followed by an unconditional replace is not this contract.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID


class LinkConflict(ValueError):
    def __init__(self):
        super().__init__("gpo_link_conflict")


@dataclass(frozen=True)
class LinkSnapshot:
    # The assertion is over both the attribute value and the object's revision.
    # None means absent, which is distinct from an empty attribute value.
    value: str | None
    revision: str


def _entries(value):
    if value is None:
        return []
    if not isinstance(value, str) or len(value) > 1_048_576:
        raise LinkConflict()
    result, offset = [], 0
    # DN is left byte-for-byte intact. In particular, do not split on ';': an
    # escaped semicolon is legal in a DN. The final semicolon separates options.
    for match in re.finditer(r"\[LDAP://([^\[\]\x00\r\n]+);([0-3])\]", value, re.IGNORECASE):
        if match.start() != offset:
            raise LinkConflict()
        result.append((match.group(0), match.group(1), int(match.group(2))))
        offset = match.end()
    if offset != len(value):
        raise LinkConflict()
    return result


def _target(gpo_guid, domain_dn):
    try:
        guid = str(UUID(gpo_guid))
        if UUID(guid).int == 0:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise LinkConflict() from None
    # This comes from the pinned domain's naming context, never a browser path.
    if (not isinstance(domain_dn, str) or len(domain_dn) > 4096
            or not re.fullmatch(r"DC=[A-Za-z0-9-]+(?:,DC=[A-Za-z0-9-]+)*", domain_dn, re.IGNORECASE)):
        raise LinkConflict()
    return f"CN={{{guid}}},CN=Policies,CN=System,{domain_dn}"


def edit_link(value, gpo_guid, domain_dn, *, remove=False):
    """Append one enabled/non-enforced link, or remove only that exact GPO DN.

    Foreign entries and their ordering/options/case survive unchanged. Existing
    disabled, enforced or duplicate own links indicate drift, not permission to
    silently repair them. Noncanonical own DNs fail closed as ambiguous.
    """
    target = _target(gpo_guid, domain_dn)
    entries = _entries(value)
    own = []
    for index, (_, dn, options) in enumerate(entries):
        if dn.casefold() == target.casefold():
            own.append((index, options))
        elif str(UUID(gpo_guid)).casefold() in dn.casefold():
            # A differently escaped/spaced own DN needs native canonicalization
            # and a new preview. It must not result in a second link.
            raise LinkConflict()
    if len(own) > 1 or own and own[0][1] != 0:
        raise LinkConflict()
    if remove:
        return "".join(raw for index, (raw, _, _) in enumerate(entries) if not own or index != own[0][0])
    if own:
        return value
    return (value or "") + f"[LDAP://{target};0]"


def compare_exchange_link(connection, ou_guid, expected, gpo_guid, domain_dn, *, remove=False):
    """One assertion attempt; never retry against a newly read foreign value.

    The connection's read_link and assert_link return LinkSnapshot and bool,
    respectively. An uncertain write response is deliberately propagated: the
    deployment journal must mark it partial and require readback/new preview.
    """
    if (not isinstance(expected, LinkSnapshot) or not isinstance(expected.revision, str)
            or not expected.revision):
        raise LinkConflict()
    current = connection.read_link(ou_guid)
    if current != expected:
        raise LinkConflict()
    desired = edit_link(expected.value, gpo_guid, domain_dn, remove=remove)
    if desired == (expected.value or ""):
        return current
    if connection.assert_link(ou_guid, expected, desired) is not True:
        raise LinkConflict()
    observed = connection.read_link(ou_guid)
    if not isinstance(observed, LinkSnapshot) or observed.value != desired:
        raise LinkConflict()
    return observed

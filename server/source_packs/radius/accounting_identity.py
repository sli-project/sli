from __future__ import annotations

"""Fail-closed identity normalization for Microsoft NPS FQDN observations."""

import itertools
import re
from typing import Callable


ExactLookup = Callable[[str, str], str | None]
MAXIMUM_PATH_DEPTH = 8


class RadiusIdentityResolutionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def derive_slash_dn_candidates(
    value: str,
) -> tuple[str, tuple[str, ...]] | None:
    parts = [item.strip() for item in str(value or "").split("/")]
    if len(parts) < 2 or any(not item for item in parts):
        return None
    domain = parts[0].casefold()
    if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", domain) is None:
        return None
    path = parts[1:]
    if len(path) > MAXIMUM_PATH_DEPTH:
        raise RadiusIdentityResolutionError(
            "radius_identity_path_depth_exceeded"
        )
    leaf = f"cn={_escape_rdn(path[-1])}"
    domain_dn = ",".join(
        f"dc={_escape_rdn(item)}" for item in domain.split(".")
    )
    candidates = []
    for kinds in itertools.product(("cn", "ou"), repeat=len(path) - 1):
        parents = [
            f"{kind}={_escape_rdn(item)}"
            for kind, item in zip(
                reversed(kinds),
                reversed(path[:-1]),
                strict=True,
            )
        ]
        candidates.append(
            ",".join([leaf, *parents, domain_dn]).casefold()
        )
    return domain, tuple(candidates)


def resolve_radius_principal(
    observation: str,
    *,
    expected_organization_fqdn: str,
    exact_lookup: ExactLookup,
) -> str | None:
    raw = str(observation or "").strip()
    organization = str(expected_organization_fqdn or "").strip().casefold()
    if not raw or not organization:
        return None
    exact = exact_lookup(organization, raw)
    if exact is not None:
        return str(exact)
    derived = derive_slash_dn_candidates(raw)
    if derived is None:
        return None
    domain, candidates = derived
    if domain != organization:
        return None
    matches = {
        str(value)
        for candidate in candidates
        if (value := exact_lookup(organization, candidate)) is not None
    }
    return next(iter(matches)) if len(matches) == 1 else None


def _escape_rdn(value: str) -> str:
    text = str(value)
    escaped = (
        text.replace("\\", "\\\\")
        .replace(",", "\\,")
        .replace("+", "\\+")
        .replace('"', '\\"')
        .replace("<", "\\<")
        .replace(">", "\\>")
        .replace(";", "\\;")
        .replace("=", "\\=")
    )
    if escaped.startswith(" ") or escaped.startswith("#"):
        escaped = "\\" + escaped
    if escaped.endswith(" "):
        escaped = escaped[:-1] + "\\ "
    return escaped

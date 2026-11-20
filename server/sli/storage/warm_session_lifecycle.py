from __future__ import annotations

"""Pure append-only lifecycle contract for incremental warm auth sessions.

The module performs no I/O. It makes late close boundaries and out-of-order
open/close handling deterministic before a ClickHouse schema is accepted.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from server.sli.sources.source_capture_continuity import (
    AUTHENTICATION_EVENT_KEYS,
    BOOT_EVENT_KEY,
    CLOSE_EVENT_KEY,
    OPEN_EVENT_KEY,
    PRIVILEGE_EVENT_KEY,
)
from server.sli.semantic.semantic_processing import NormalizedEvent
from server.source_packs.windows_ad_dc import (
    WINDOWS_AUTH_SESSION_EXPLICIT_CREDENTIALS_EVENT_ID,
    WINDOWS_AUTH_SESSION_SUPPLEMENTAL_LOGOUT_EVENT_ID,
)


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "config/stage7_warm_session_lifecycle_v1.json"
CONTRACT_ID = "sli.warm-authentication-session-lifecycle.v1"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
AUTHENTICATION_BOUNDARY_KEYS = frozenset({OPEN_EVENT_KEY, CLOSE_EVENT_KEY})
SUPPLEMENTAL_LOGOUT_EVENT_KEY = WINDOWS_AUTH_SESSION_SUPPLEMENTAL_LOGOUT_EVENT_ID
EXPLICIT_CREDENTIALS_EVENT_KEY = WINDOWS_AUTH_SESSION_EXPLICIT_CREDENTIALS_EVENT_ID
WINDOWS_FOLD_EVENT_KEYS = AUTHENTICATION_EVENT_KEYS | frozenset({
    SUPPLEMENTAL_LOGOUT_EVENT_KEY,
    EXPLICIT_CREDENTIALS_EVENT_KEY,
})
SECURITY_CHANNEL = "Security"
SECURITY_AUDITING_PROVIDER = "Microsoft-Windows-Security-Auditing"


class WarmSessionLifecycleError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SessionBoundary:
    source_event_id: int
    role: str
    server_id: int
    channel_id: int
    logon_id: str
    observed_at_utc: datetime
    normalized_hash: str
    domain_id: int = 0


@dataclass(frozen=True)
class SessionRevision:
    session_uid: str
    revision: int
    state: str
    server_id: int
    channel_id: int
    logon_id: str
    logon_source_event_id: int | None
    logoff_source_event_id: int | None
    logon_time_utc: datetime | None
    logoff_time_utc: datetime | None
    previous_revision_sha256: str | None
    revision_sha256: str
    domain_id: int = 0


@dataclass(frozen=True)
class AuthenticationEvidence:
    """One normalized source-native authentication fact.

    This deliberately does not accept a catalog correlation or a derived
    relation.  ``source_record_id`` is the source-native EventRecordID used to
    establish the Security boot scope; ``source_event_id`` and
    ``normalized_hash`` preserve the immutable stored source evidence.
    """

    source_event_id: int
    source_record_id: int
    event_key: int
    descriptor_source: str
    descriptor_stream: str
    server_id: int
    channel_id: int
    provider_name: str
    logon_id: str | None
    observed_at_utc: datetime
    normalized_hash: str
    principal: str | None = None
    host: str | None = None
    logon_type: str | None = None
    privilege_marker: str | None = None


def authentication_evidence_from_normalized(
    event: NormalizedEvent,
    *,
    source_record_id: int,
    descriptor_source: str = "sli.windows.ad-dc",
    descriptor_stream: str = SECURITY_CHANNEL,
    channel_id: int = 1,
    provider_name: str = SECURITY_AUDITING_PROVIDER,
) -> AuthenticationEvidence:
    """Carry one normalized source fact into the bounded Windows fold."""

    source_host = str(event.roles.get("source_host") or "").strip()
    try:
        server_id = int(source_host)
        event_key = int(event.facts["windows_event_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WarmSessionLifecycleError(
            "warm_session_normalized_source_identity_invalid"
        ) from exc
    session_principal = str(event.roles.get("session_principal") or "").strip()
    prefix = f"{source_host}:"
    logon_id = session_principal[len(prefix):] if session_principal.startswith(prefix) else None
    return AuthenticationEvidence(
        source_event_id=event.source_event_id,
        source_record_id=int(source_record_id),
        event_key=event_key,
        descriptor_source=descriptor_source,
        descriptor_stream=descriptor_stream,
        server_id=server_id,
        channel_id=int(channel_id),
        provider_name=provider_name,
        logon_id=logon_id,
        observed_at_utc=event.occurred_at_utc,
        normalized_hash=event.semantic_sha256,
        principal=event.roles.get("affected_entity") or event.roles.get("actor"),
        host=source_host,
        logon_type=event.facts.get("logon_type"),
        privilege_marker=event.facts.get("privileges"),
    )


@dataclass(frozen=True)
class ContinuityDeclaration:
    """Immutable raw-file/collection provenance for one descriptor scope."""

    scope_identity: str
    descriptor_source: str
    descriptor_stream: str
    server_id: int
    channel_id: int
    provider_name: str
    channel_generation_identity: str
    source_event_ids: tuple[int, ...]
    source_hashes: tuple[str, ...]
    first_event_record_id: int
    last_event_record_id: int
    completeness: str


@dataclass(frozen=True)
class AuthenticationSessionObservation:
    """Immutable closed or incomplete authentication-session evidence."""

    session_uid: str
    state: str
    completeness: str
    quality_reason: str
    coverage_state: str
    promotion_eligible: bool
    boot_source_event_id: int | None
    boot_normalized_hash: str | None
    logon_source_event_id: int | None
    logon_normalized_hash: str | None
    logoff_source_event_id: int | None
    logoff_normalized_hash: str | None
    source_event_ids: tuple[int, ...]
    source_hashes: tuple[str, ...]
    logon_time_utc: datetime | None
    logoff_time_utc: datetime | None
    duration_seconds: int | None
    principal: str | None
    host: str | None
    logon_type: str | None
    privilege_marker: str | None
    privilege_source_event_id: int | None
    privilege_normalized_hash: str | None
    privilege_attachment_state: str
    privilege_evidence_source_event_ids: tuple[int, ...]
    privilege_evidence_normalized_hashes: tuple[str, ...]
    supplemental_logout_source_event_ids: tuple[int, ...] = ()
    supplemental_logout_normalized_hashes: tuple[str, ...] = ()
    explicit_credentials_source_event_ids: tuple[int, ...] = ()
    explicit_credentials_normalized_hashes: tuple[str, ...] = ()


def assemble_authentication_sessions(
    evidence: Sequence[AuthenticationEvidence],
    continuity_declarations: Sequence[ContinuityDeclaration],
) -> tuple[AuthenticationSessionObservation, ...]:
    """Assemble only boot-scoped, continuity-proven open→close sessions.

    Any uncertainty stays an explicit incomplete observation.  In particular,
    this function never pairs by account name, timestamp proximity, an
    unscoped LogonId, or the catalog's deliberately-null correlation field.
    """

    facts = tuple(_validate_authentication_evidence(item) for item in evidence)
    proofs = tuple(_validate_continuity_declaration(item) for item in continuity_declarations)
    boundaries = tuple(item for item in facts if item.event_key in AUTHENTICATION_BOUNDARY_KEYS)
    boots = tuple(item for item in facts if item.event_key == BOOT_EVENT_KEY)
    privileges = tuple(
        item for item in facts if item.event_key == PRIVILEGE_EVENT_KEY
    )
    supplements = tuple(item for item in facts if item.event_key in {
        SUPPLEMENTAL_LOGOUT_EVENT_KEY, EXPLICIT_CREDENTIALS_EVENT_KEY,
    })
    scoped: dict[tuple[object, ...], list[AuthenticationEvidence]] = {}
    by_logon: dict[tuple[object, ...], list[AuthenticationEvidence]] = {}
    boot_by_boundary: dict[int, AuthenticationEvidence | None] = {}
    for boundary in boundaries:
        boot = _preceding_boot(boundary, boots)
        boot_by_boundary[boundary.source_event_id] = boot
        by_logon.setdefault((_source_scope_key(boundary), boundary.logon_id), []).append(boundary)
        scope_key: tuple[object, ...] = (
            _source_scope_key(boundary),
            boot.source_event_id if boot is not None else None,
            boundary.logon_id,
        )
        scoped.setdefault(scope_key, []).append(boundary)

    observations: list[AuthenticationSessionObservation] = []
    rebooted_boundary_ids: set[int] = set()
    for _, group in sorted(
        by_logon.items(),
        key=lambda item: min((fact.source_record_id, fact.source_event_id) for fact in item[1]),
    ):
        opens = [item for item in group if item.event_key == OPEN_EVENT_KEY]
        closes = [item for item in group if item.event_key == CLOSE_EVENT_KEY]
        scopes = {boot_by_boundary[item.source_event_id] for item in group}
        if len(group) == 2 and len(opens) == len(closes) == 1 and len(scopes) == 2:
            selected_boots = tuple(sorted(
                (item for item in scopes if item is not None),
                key=lambda item: (item.source_record_id, item.source_event_id),
            ))
            observations.append(_incomplete_observation(
                group, None, "incomplete_reboot_boundary", extra_source=selected_boots,
            ))
            rebooted_boundary_ids.update(item.source_event_id for item in group)

    observations.extend(
        _assemble_scoped_observation(
            group,
            boot_by_boundary,
            proofs,
            privileges,
            supplements,
            boots,
        )
        for _, group in sorted(
            (
                (key, group) for key, group in scoped.items()
                if not any(item.source_event_id in rebooted_boundary_ids for item in group)
            ),
            key=lambda item: min(
                (fact.source_record_id, fact.source_event_id) for fact in item[1]
            ),
        )
    )
    return tuple(sorted(
        observations,
        key=lambda item: (item.source_event_ids[0], item.session_uid),
    ))


def _assemble_scoped_observation(
    group: Sequence[AuthenticationEvidence],
    boot_by_boundary: Mapping[int, AuthenticationEvidence | None],
    proofs: Sequence[ContinuityDeclaration],
    privileges: Sequence[AuthenticationEvidence],
    supplements: Sequence[AuthenticationEvidence],
    boots: Sequence[AuthenticationEvidence],
) -> AuthenticationSessionObservation:
    ordered = tuple(sorted(group, key=lambda item: (item.source_record_id, item.source_event_id)))
    opens = tuple(item for item in ordered if item.event_key == OPEN_EVENT_KEY)
    closes = tuple(item for item in ordered if item.event_key == CLOSE_EVENT_KEY)
    boot = boot_by_boundary[ordered[0].source_event_id]
    if boot is None:
        return _incomplete_observation(ordered, None, "incomplete_boot_scope_missing")
    proof_chain, proof_reason = _accepted_continuity_proof(boot, ordered, proofs)
    attached = _exact_session_supplements(
        boot, ordered, proof_chain, supplements, boots,
    )
    privilege_attachment = _privilege_attachment(
        boot, ordered, proof_chain, privileges, boots,
    )
    if len(opens) != 1 or len(closes) != 1:
        reason = "incomplete_duplicate_boundary" if len(opens) > 1 or len(closes) > 1 else (
            "incomplete_missing_close" if opens else "incomplete_missing_open"
        )
        return _incomplete_observation(
            ordered, boot, reason, attached=attached,
            proof_chain=proof_chain, privilege_attachment=privilege_attachment,
        )

    opened, closed = opens[0], closes[0]
    if (
        opened.source_record_id >= closed.source_record_id
        or opened.observed_at_utc > closed.observed_at_utc
    ):
        return _incomplete_observation(
            ordered, boot, "incomplete_out_of_order", proof_chain=proof_chain,
            privilege_attachment=privilege_attachment,
        )
    if proof_reason is not None:
        return _incomplete_observation(
            ordered, boot, proof_reason, proof_chain=proof_chain,
            privilege_attachment=privilege_attachment,
        )
    return _closed_observation(
        boot, opened, closed, privilege_attachment, attached,
    )


def _source_scope_key(value: AuthenticationEvidence) -> tuple[int, int, str, str, str]:
    return (
        value.server_id,
        value.channel_id,
        value.provider_name,
        value.descriptor_source,
        value.descriptor_stream,
    )


def _preceding_boot(
    boundary: AuthenticationEvidence,
    boots: Iterable[AuthenticationEvidence],
) -> AuthenticationEvidence | None:
    candidates = [
        item for item in boots
        if _source_scope_key(item) == _source_scope_key(boundary)
        and item.source_record_id < boundary.source_record_id
    ]
    if not candidates:
        return None
    latest_record_id = max(item.source_record_id for item in candidates)
    latest = [item for item in candidates if item.source_record_id == latest_record_id]
    return latest[0] if len(latest) == 1 else None


def _accepted_continuity_proof(
    boot: AuthenticationEvidence,
    boundaries: Sequence[AuthenticationEvidence],
    proofs: Sequence[ContinuityDeclaration],
) -> tuple[tuple[ContinuityDeclaration, ...] | None, str | None]:
    relevant = [
        proof for proof in proofs
        if (
            proof.descriptor_source == boot.descriptor_source
            and proof.descriptor_stream == boot.descriptor_stream
            and proof.server_id == boot.server_id
            and proof.channel_id == boot.channel_id
            and proof.provider_name == boot.provider_name
        )
    ]
    if not relevant:
        return None, "incomplete_coverage_unproven"
    expected_facts = (boot,) + tuple(boundaries)
    expected = tuple(
        (item.source_event_id, item.normalized_hash) for item in expected_facts
    )
    last_record_id = max(item.source_record_id for item in expected_facts)
    complete = sorted(
        (proof for proof in relevant if proof.completeness == "complete"),
        key=lambda item: (
            item.first_event_record_id,
            item.last_event_record_id,
            item.scope_identity,
        ),
    )
    starts = [
        index for index, proof in enumerate(complete)
        if proof.first_event_record_id <= boot.source_record_id
        <= proof.last_event_record_id
        and expected[0] in zip(proof.source_event_ids, proof.source_hashes)
    ]
    accepted: list[tuple[ContinuityDeclaration, ...]] = []
    for start in starts:
        chain = [complete[start]]
        for proof in complete[start + 1:]:
            if chain[-1].last_event_record_id >= last_record_id:
                break
            if proof.first_event_record_id != chain[-1].last_event_record_id + 1:
                break
            if (
                proof.channel_generation_identity
                != chain[-1].channel_generation_identity
            ):
                break
            chain.append(proof)
        covered_pairs = {
            pair
            for proof in chain
            for pair in zip(proof.source_event_ids, proof.source_hashes)
        }
        if (
            chain[-1].last_event_record_id >= last_record_id
            and all(pair in covered_pairs for pair in expected)
        ):
            accepted.append(tuple(chain))
    if len(accepted) != 1:
        return None, "incomplete_coverage_gap"
    return accepted[0], None


def _privilege_attachment(
    boot: AuthenticationEvidence,
    boundaries: Sequence[AuthenticationEvidence],
    proofs: Sequence[ContinuityDeclaration] | None,
    privileges: Sequence[AuthenticationEvidence],
    boots: Sequence[AuthenticationEvidence],
) -> tuple[str, AuthenticationEvidence | None, tuple[AuthenticationEvidence, ...]]:
    opened = next((item for item in boundaries if item.event_key == OPEN_EVENT_KEY), None)
    if not boundaries:
        return "missing", None, ()
    anchor = opened or boundaries[0]
    closes = tuple(item for item in boundaries if item.event_key == CLOSE_EVENT_KEY)
    last_close_record_id = max(
        (item.source_record_id for item in closes), default=None,
    )
    matches = tuple(sorted(
        (
            item for item in privileges
            if _source_scope_key(item) == _source_scope_key(anchor)
            and item.logon_id == anchor.logon_id
            and (opened.source_record_id if opened else boot.source_record_id)
            < item.source_record_id
            and (
                last_close_record_id is None
                or item.source_record_id < last_close_record_id
            )
            and (opened.observed_at_utc if opened else boot.observed_at_utc)
            <= item.observed_at_utc
            and _preceding_boot(item, boots) == boot
        ),
        key=lambda item: (item.source_record_id, item.source_event_id),
    ))
    if not matches:
        return "missing", None, ()
    if len(matches) != 1:
        return "ambiguous", None, matches
    covered_pairs = {
        pair
        for proof in (proofs or ())
        for pair in zip(proof.source_event_ids, proof.source_hashes)
    }
    match = matches[0]
    if (match.source_event_id, match.normalized_hash) not in covered_pairs:
        return "provenance_unverified", None, matches
    return "exact", match, matches


def _exact_session_supplements(
    boot: AuthenticationEvidence,
    boundaries: Sequence[AuthenticationEvidence],
    proofs: Sequence[ContinuityDeclaration] | None,
    supplements: Sequence[AuthenticationEvidence],
    boots: Sequence[AuthenticationEvidence],
) -> tuple[AuthenticationEvidence, ...]:
    opened = next((item for item in boundaries if item.event_key == OPEN_EVENT_KEY), None)
    closed = next((item for item in boundaries if item.event_key == CLOSE_EVENT_KEY), None)
    if opened is None:
        return ()
    covered_pairs = {
        pair
        for proof in (proofs or ())
        for pair in zip(proof.source_event_ids, proof.source_hashes)
    }
    return tuple(sorted(
        (
            item for item in supplements
            if _source_scope_key(item) == _source_scope_key(opened)
            and item.logon_id == opened.logon_id
            and boot.source_record_id < opened.source_record_id < item.source_record_id
            and (closed is None or item.source_record_id < closed.source_record_id)
            and _preceding_boot(item, boots) == boot
            and (item.source_event_id, item.normalized_hash) in covered_pairs
        ),
        key=lambda item: (item.source_record_id, item.source_event_id),
    ))


def _closed_observation(
    boot: AuthenticationEvidence,
    opened: AuthenticationEvidence,
    closed: AuthenticationEvidence,
    privilege_attachment: tuple[
        str, AuthenticationEvidence | None, tuple[AuthenticationEvidence, ...]
    ],
    attached: Sequence[AuthenticationEvidence],
) -> AuthenticationSessionObservation:
    source = (boot, opened, closed)
    privilege_state, privilege, privilege_evidence = privilege_attachment
    return AuthenticationSessionObservation(
        session_uid=_observation_uid("closed", source),
        state="closed",
        completeness="complete",
        quality_reason="complete",
        coverage_state="accepted",
        promotion_eligible=True,
        boot_source_event_id=boot.source_event_id,
        boot_normalized_hash=boot.normalized_hash,
        logon_source_event_id=opened.source_event_id,
        logon_normalized_hash=opened.normalized_hash,
        logoff_source_event_id=closed.source_event_id,
        logoff_normalized_hash=closed.normalized_hash,
        source_event_ids=tuple(item.source_event_id for item in source),
        source_hashes=tuple(item.normalized_hash for item in source),
        logon_time_utc=opened.observed_at_utc,
        logoff_time_utc=closed.observed_at_utc,
        duration_seconds=int((closed.observed_at_utc - opened.observed_at_utc).total_seconds()),
        principal=opened.principal,
        host=opened.host,
        logon_type=opened.logon_type,
        privilege_marker=privilege.privilege_marker if privilege else None,
        privilege_source_event_id=privilege.source_event_id if privilege else None,
        privilege_normalized_hash=privilege.normalized_hash if privilege else None,
        privilege_attachment_state=privilege_state,
        privilege_evidence_source_event_ids=tuple(
            item.source_event_id for item in privilege_evidence
        ),
        privilege_evidence_normalized_hashes=tuple(
            item.normalized_hash for item in privilege_evidence
        ),
        supplemental_logout_source_event_ids=tuple(
            item.source_event_id for item in attached
            if item.event_key == SUPPLEMENTAL_LOGOUT_EVENT_KEY
        ),
        supplemental_logout_normalized_hashes=tuple(
            item.normalized_hash for item in attached
            if item.event_key == SUPPLEMENTAL_LOGOUT_EVENT_KEY
        ),
        explicit_credentials_source_event_ids=tuple(
            item.source_event_id for item in attached
            if item.event_key == EXPLICIT_CREDENTIALS_EVENT_KEY
        ),
        explicit_credentials_normalized_hashes=tuple(
            item.normalized_hash for item in attached
            if item.event_key == EXPLICIT_CREDENTIALS_EVENT_KEY
        ),
    )


def _incomplete_observation(
    boundaries: Sequence[AuthenticationEvidence],
    boot: AuthenticationEvidence | None,
    reason: str,
    *,
    extra_source: Sequence[AuthenticationEvidence] = (),
    attached: Sequence[AuthenticationEvidence] = (),
    proof_chain: Sequence[ContinuityDeclaration] | None = None,
    privilege_attachment: tuple[
        str, AuthenticationEvidence | None, tuple[AuthenticationEvidence, ...]
    ] = ("missing", None, ()),
) -> AuthenticationSessionObservation:
    opened = next(
        (item for item in boundaries if item.event_key == OPEN_EVENT_KEY), None,
    )
    source = tuple(extra_source) + tuple([boot] if boot is not None else []) + tuple(boundaries)
    unique = tuple(sorted(
        dict.fromkeys(source),
        key=lambda item: (item.source_record_id, item.source_event_id),
    ))
    privilege_state, privilege, privilege_evidence = privilege_attachment
    return AuthenticationSessionObservation(
        session_uid=_observation_uid(reason, unique),
        state="incomplete",
        completeness={
            "incomplete_missing_open": "missing_start",
            "incomplete_missing_close": "missing_stop",
        }.get(reason, "conflict"),
        quality_reason=reason,
        coverage_state="accepted" if proof_chain else "unavailable",
        promotion_eligible=bool(proof_chain),
        boot_source_event_id=boot.source_event_id if boot else None,
        boot_normalized_hash=boot.normalized_hash if boot else None,
        logon_source_event_id=opened.source_event_id if opened else None,
        logon_normalized_hash=opened.normalized_hash if opened else None,
        logoff_source_event_id=None,
        logoff_normalized_hash=None,
        source_event_ids=tuple(item.source_event_id for item in unique),
        source_hashes=tuple(item.normalized_hash for item in unique),
        logon_time_utc=opened.observed_at_utc if opened else None,
        logoff_time_utc=None,
        duration_seconds=None,
        principal=opened.principal if opened else None,
        host=opened.host if opened else None,
        logon_type=opened.logon_type if opened else None,
        privilege_marker=privilege.privilege_marker if privilege else None,
        privilege_source_event_id=privilege.source_event_id if privilege else None,
        privilege_normalized_hash=privilege.normalized_hash if privilege else None,
        privilege_attachment_state=privilege_state,
        privilege_evidence_source_event_ids=tuple(
            item.source_event_id for item in privilege_evidence
        ),
        privilege_evidence_normalized_hashes=tuple(
            item.normalized_hash for item in privilege_evidence
        ),
        supplemental_logout_source_event_ids=tuple(
            item.source_event_id for item in attached
            if item.event_key == SUPPLEMENTAL_LOGOUT_EVENT_KEY
        ),
        supplemental_logout_normalized_hashes=tuple(
            item.normalized_hash for item in attached
            if item.event_key == SUPPLEMENTAL_LOGOUT_EVENT_KEY
        ),
        explicit_credentials_source_event_ids=tuple(
            item.source_event_id for item in attached
            if item.event_key == EXPLICIT_CREDENTIALS_EVENT_KEY
        ),
        explicit_credentials_normalized_hashes=tuple(
            item.normalized_hash for item in attached
            if item.event_key == EXPLICIT_CREDENTIALS_EVENT_KEY
        ),
    )


def _observation_uid(kind: str, source: Sequence[AuthenticationEvidence]) -> str:
    payload = "\0".join(
        [CONTRACT_ID, kind]
        + [f"{item.source_event_id}:{item.normalized_hash}" for item in source]
    )
    return sha256(payload.encode("ascii")).hexdigest()[:32]


def _validate_authentication_evidence(value: AuthenticationEvidence) -> AuthenticationEvidence:
    if value.event_key not in WINDOWS_FOLD_EVENT_KEYS:
        raise WarmSessionLifecycleError("warm_session_authentication_event_key_invalid")
    if value.source_event_id <= 0 or value.source_record_id <= 0 or value.server_id <= 0 or value.channel_id <= 0:
        raise WarmSessionLifecycleError("warm_session_authentication_identity_invalid")
    if value.observed_at_utc.tzinfo is None:
        raise WarmSessionLifecycleError("warm_session_authentication_timezone_required")
    digest = str(value.normalized_hash or "").lower()
    if HEX64.fullmatch(digest) is None:
        raise WarmSessionLifecycleError("warm_session_authentication_hash_invalid")
    descriptor_source = str(value.descriptor_source or "").strip()
    descriptor_stream = str(value.descriptor_stream or "").strip()
    provider_name = str(value.provider_name or "").strip()
    logon_id = str(value.logon_id or "").strip() or None
    if not descriptor_source or not descriptor_stream or not provider_name:
        raise WarmSessionLifecycleError("warm_session_authentication_descriptor_invalid")
    if (
        descriptor_stream != SECURITY_CHANNEL
        or provider_name != SECURITY_AUDITING_PROVIDER
    ):
        raise WarmSessionLifecycleError("warm_session_authentication_source_scope_invalid")
    if value.event_key != BOOT_EVENT_KEY and logon_id is None:
        raise WarmSessionLifecycleError("warm_session_authentication_logon_id_required")
    return AuthenticationEvidence(
        source_event_id=int(value.source_event_id), source_record_id=int(value.source_record_id),
        event_key=int(value.event_key), descriptor_source=descriptor_source,
        descriptor_stream=descriptor_stream, server_id=int(value.server_id),
        channel_id=int(value.channel_id), provider_name=provider_name, logon_id=logon_id,
        observed_at_utc=value.observed_at_utc.astimezone(timezone.utc), normalized_hash=digest,
        principal=value.principal, host=value.host, logon_type=value.logon_type,
        privilege_marker=value.privilege_marker,
    )


def _validate_continuity_declaration(value: ContinuityDeclaration) -> ContinuityDeclaration:
    if (
        not str(value.scope_identity or "").strip()
        or not str(value.descriptor_source or "").strip()
        or not str(value.descriptor_stream or "").strip()
        or not str(value.provider_name or "").strip()
        or not str(value.channel_generation_identity or "").strip()
        or value.server_id <= 0 or value.channel_id <= 0
        or value.first_event_record_id <= 0
        or value.last_event_record_id < value.first_event_record_id
        or value.completeness not in {"complete", "gap", "partial", "failed", "truncated"}
        or len(value.source_event_ids) != len(value.source_hashes)
        or len(set(value.source_event_ids)) != len(value.source_event_ids)
        or any(item <= 0 for item in value.source_event_ids)
        or any(HEX64.fullmatch(str(item).lower()) is None for item in value.source_hashes)
    ):
        raise WarmSessionLifecycleError("warm_session_continuity_declaration_invalid")
    return ContinuityDeclaration(
        scope_identity=str(value.scope_identity).strip(),
        descriptor_source=str(value.descriptor_source).strip(),
        descriptor_stream=str(value.descriptor_stream).strip(),
        server_id=int(value.server_id), channel_id=int(value.channel_id),
        provider_name=str(value.provider_name).strip(),
        channel_generation_identity=str(
            value.channel_generation_identity
        ).strip(),
        source_event_ids=tuple(int(item) for item in value.source_event_ids),
        source_hashes=tuple(str(item).lower() for item in value.source_hashes),
        first_event_record_id=int(value.first_event_record_id),
        last_event_record_id=int(value.last_event_record_id),
        completeness=value.completeness,
    )


def legacy_base_revision(
    *,
    session_uid: str,
    state: str,
    server_id: int,
    domain_id: int,
    channel_id: int,
    logon_id: str,
    logon_source_event_id: int | None,
    logoff_source_event_id: int | None,
    logon_time_utc: datetime | None,
    logoff_time_utc: datetime | None,
) -> SessionRevision:
    """Represent one immutable row from the initial warm snapshot.

    The initial snapshot predates the revision overlay and is revision zero.
    Its deterministic zero digest is a sentinel, not a forged hash-chain link;
    the first appended revision therefore stores ``previous=NULL``.
    """

    value = SessionRevision(
        session_uid=str(session_uid).lower(),
        revision=0,
        state=str(state),
        server_id=int(server_id),
        channel_id=int(channel_id),
        logon_id=str(logon_id),
        logon_source_event_id=(
            int(logon_source_event_id)
            if logon_source_event_id is not None
            else None
        ),
        logoff_source_event_id=(
            int(logoff_source_event_id)
            if logoff_source_event_id is not None
            else None
        ),
        logon_time_utc=logon_time_utc,
        logoff_time_utc=logoff_time_utc,
        previous_revision_sha256=None,
        revision_sha256="0" * 64,
        domain_id=int(domain_id),
    )
    _validate_prior(value)
    if value.state == "closed":
        raise WarmSessionLifecycleError("warm_session_legacy_base_closed")
    return value


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WarmSessionLifecycleError("warm_session_contract_invalid") from exc
    expected = {
        "schema_version": 1,
        "contract_id": CONTRACT_ID,
        "status": "prepared_source_only",
        "component_owner": "core_hosted_compatibility",
        "session_identity": "first_observed_boundary_source_event_id",
        "storage_model": "append_only_hash_chained_revisions",
        "reader_model": "latest_revision_per_session_uid",
        "maximum_boundary_events_per_batch": 10_000,
        "production_clickhouse_schema_applied": False,
        "production_routing_changed": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
    }
    if not isinstance(value, dict):
        raise WarmSessionLifecycleError("warm_session_contract_object_required")
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise WarmSessionLifecycleError(f"warm_session_contract_{key}_invalid")
    if value.get("exact_pair_fields") != ["server_id", "channel_id", "logon_id"]:
        raise WarmSessionLifecycleError("warm_session_pair_fields_invalid")
    if int(value.get("close_timeout_seconds") or 0) != 86_400:
        raise WarmSessionLifecycleError("warm_session_timeout_invalid")
    return value


def plan_revision(
    prior: SessionRevision | None,
    boundary: SessionBoundary,
    *,
    contract: Mapping[str, Any] | None = None,
) -> SessionRevision:
    """Return one new immutable revision or fail closed."""

    validated = dict(contract or load_contract())
    clean = _validate_boundary(boundary)
    timeout = int(validated["close_timeout_seconds"])
    if prior is None:
        session_uid = sha256(
            f"{CONTRACT_ID}\0{clean.source_event_id}".encode("ascii")
        ).hexdigest()[:32]
        if clean.role == "open":
            values = {
                "state": "open",
                "logon_source_event_id": clean.source_event_id,
                "logoff_source_event_id": None,
                "logon_time_utc": clean.observed_at_utc,
                "logoff_time_utc": None,
            }
        else:
            values = {
                "state": "orphan_logoff",
                "logon_source_event_id": None,
                "logoff_source_event_id": clean.source_event_id,
                "logon_time_utc": None,
                "logoff_time_utc": clean.observed_at_utc,
            }
        return _revision(
            session_uid=session_uid,
            revision=1,
            boundary=clean,
            previous_revision_sha256=None,
            **values,
        )

    _validate_prior(prior)
    if (
        prior.server_id != clean.server_id
        or prior.channel_id != clean.channel_id
        or prior.logon_id != clean.logon_id
    ):
        raise WarmSessionLifecycleError("warm_session_pair_mismatch")
    if prior.state == "closed":
        raise WarmSessionLifecycleError("warm_session_already_closed")
    if prior.state == "open" and clean.role != "close":
        raise WarmSessionLifecycleError("warm_session_duplicate_open")
    if prior.state == "orphan_logoff" and clean.role != "open":
        raise WarmSessionLifecycleError("warm_session_duplicate_close")

    logon_id = (
        prior.logon_source_event_id
        if prior.logon_source_event_id is not None
        else clean.source_event_id
    )
    logoff_id = (
        prior.logoff_source_event_id
        if prior.logoff_source_event_id is not None
        else clean.source_event_id
    )
    logon_time = prior.logon_time_utc or clean.observed_at_utc
    logoff_time = prior.logoff_time_utc or clean.observed_at_utc
    seconds = (logoff_time - logon_time).total_seconds()
    if seconds < 0 or seconds > timeout:
        raise WarmSessionLifecycleError("warm_session_close_window_invalid")
    return _revision(
        session_uid=prior.session_uid,
        revision=prior.revision + 1,
        state="closed",
        boundary=clean,
        logon_source_event_id=logon_id,
        logoff_source_event_id=logoff_id,
        logon_time_utc=logon_time,
        logoff_time_utc=logoff_time,
        previous_revision_sha256=(
            None if prior.revision == 0 else prior.revision_sha256
        ),
        domain_id=prior.domain_id or clean.domain_id,
    )


def _validate_boundary(value: SessionBoundary) -> SessionBoundary:
    if value.role not in {"open", "close"}:
        raise WarmSessionLifecycleError("warm_session_boundary_role_invalid")
    if value.source_event_id <= 0 or value.server_id <= 0 or value.channel_id <= 0:
        raise WarmSessionLifecycleError("warm_session_boundary_identity_invalid")
    logon_id = str(value.logon_id or "").strip()
    digest = str(value.normalized_hash or "").lower()
    if not logon_id or len(logon_id) > 256 or HEX64.fullmatch(digest) is None:
        raise WarmSessionLifecycleError("warm_session_boundary_value_invalid")
    observed = value.observed_at_utc
    if observed.tzinfo is None:
        raise WarmSessionLifecycleError("warm_session_boundary_timezone_required")
    return SessionBoundary(
        source_event_id=int(value.source_event_id),
        role=value.role,
        server_id=int(value.server_id),
        channel_id=int(value.channel_id),
        logon_id=logon_id,
        observed_at_utc=observed.astimezone(timezone.utc),
        normalized_hash=digest,
        domain_id=int(value.domain_id),
    )


def _validate_prior(value: SessionRevision) -> None:
    if (
        HEX32.fullmatch(value.session_uid) is None
        or value.revision < 0
        or value.state not in {"open", "closed", "orphan_logoff"}
        or HEX64.fullmatch(value.revision_sha256) is None
    ):
        raise WarmSessionLifecycleError("warm_session_prior_invalid")
    if value.revision == 0 and (
        value.revision_sha256 != "0" * 64
        or value.previous_revision_sha256 is not None
    ):
        raise WarmSessionLifecycleError("warm_session_legacy_base_invalid")


def _revision(
    *,
    session_uid: str,
    revision: int,
    state: str,
    boundary: SessionBoundary,
    logon_source_event_id: int | None,
    logoff_source_event_id: int | None,
    logon_time_utc: datetime | None,
    logoff_time_utc: datetime | None,
    previous_revision_sha256: str | None,
    domain_id: int | None = None,
) -> SessionRevision:
    payload = {
        "contract_id": CONTRACT_ID,
        "session_uid": session_uid,
        "revision": revision,
        "state": state,
        "server_id": boundary.server_id,
        "channel_id": boundary.channel_id,
        "domain_id": boundary.domain_id if domain_id is None else domain_id,
        "logon_id": boundary.logon_id,
        "logon_source_event_id": logon_source_event_id,
        "logoff_source_event_id": logoff_source_event_id,
        "logon_time_utc": logon_time_utc.isoformat() if logon_time_utc else None,
        "logoff_time_utc": logoff_time_utc.isoformat() if logoff_time_utc else None,
        "boundary_normalized_hash": boundary.normalized_hash,
        "previous_revision_sha256": previous_revision_sha256,
    }
    digest = sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return SessionRevision(
        session_uid=session_uid,
        revision=revision,
        state=state,
        server_id=boundary.server_id,
        channel_id=boundary.channel_id,
        logon_id=boundary.logon_id,
        logon_source_event_id=logon_source_event_id,
        logoff_source_event_id=logoff_source_event_id,
        logon_time_utc=logon_time_utc,
        logoff_time_utc=logoff_time_utc,
        previous_revision_sha256=previous_revision_sha256,
        revision_sha256=digest,
        domain_id=boundary.domain_id if domain_id is None else domain_id,
    )

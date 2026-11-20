"""Bounded, non-persistent launcher for the separately authorized G11A3 probe.

This module deliberately has no command-line entry point and never opens a
database or source connection itself.  A separately authorized caller supplies
one already-open database connection and three bounded source readers.  Raw
source values stay in process memory and the only returned value is the
redacted result from ``run_probe``.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import re
from time import monotonic
from typing import Any, Iterable, Protocol, Sequence

from scripts.maintenance.stage9_g11a3_probe_orchestrator import (
    AccountingObservation,
    AdVpnRecord,
    MAX_ACCOUNTING_BYTES,
    MAX_ACCOUNTING_CANDIDATES,
    MAX_ACCOUNTING_FILES,
    MAX_ACCOUNTING_RECORDS,
    MAX_NPS_EVENTS,
    MAX_RUNTIME_SECONDS,
    NpsObservation,
    ProbePostflightAttestation,
    ProbePreflight,
    ProbeRequest,
    ProbeStopError,
    SOURCE_UTC_OFFSET_MINUTES,
    WINDOW_END_UTC,
    WINDOW_START_UTC,
    run_probe,
)
from scripts.maintenance.stage9_g11a3_probe_selection import (
    select_accounting_lifecycle,
    select_nps_match,
)
from server.sli.sources.windows_runtime_identity import verify_collection_identity


@dataclass(frozen=True)
class ProbeCollectionLimits:
    window_start_utc: datetime = WINDOW_START_UTC
    window_end_utc: datetime = WINDOW_END_UTC
    nps_events: int = MAX_NPS_EVENTS
    accounting_files: int = MAX_ACCOUNTING_FILES
    accounting_records: int = MAX_ACCOUNTING_RECORDS
    accounting_bytes: int = MAX_ACCOUNTING_BYTES
    accounting_candidates: int = MAX_ACCOUNTING_CANDIDATES
    runtime_seconds: int = MAX_RUNTIME_SECONDS


@dataclass(frozen=True)
class ProbePreflightDiagnosis:
    """Safe stage-level detail for operators; never contains credentials."""

    identity_check: str
    identity_failure_reasons: tuple[str, ...]
    database_check: str
    database_error_type: str | None
    preflight: ProbePreflight | None
    database_failure_stage: str | None = None
    cursor_revision: int | None = None
    cursor_check: str = "not_run"


@dataclass(frozen=True)
class NpsBatch:
    observations: Iterable[NpsObservation]
    cap_reached: bool = False


@dataclass(frozen=True)
class AccountingBatch:
    observations: Iterable[AccountingObservation]
    files_read: int
    bytes_read: int
    candidates_seen: int
    candidate_cap_reached: bool = False
    record_cap_reached: bool = False
    byte_cap_reached: bool = False


class ProbeSources(Protocol):
    """Source adapter contract; each collector must enforce supplied caps."""

    def collect_nps(self, limits: ProbeCollectionLimits) -> NpsBatch: ...

    def collect_accounting(
        self, limits: ProbeCollectionLimits,
    ) -> AccountingBatch: ...

    def lookup_ad(
        self, principal_observation: str,
    ) -> Sequence[AdVpnRecord]: ...


_PREFLIGHT_STATE_QUERY = """
select source_subscription_disabled,no_temporary_login,
       no_worker_started,cursor_revision
from public.sli_g11a3_preflight_state_v1()
"""
class PreflightStateError(RuntimeError):
    """The execute-only preflight function broke its fixed row contract."""


def launch_probe(
    connection: Any, sources: ProbeSources, *, approved_identity: str,
    approved_sid: str,
) -> dict[str, Any]:
    """Prove local safety first, then collect bounded in-memory observations."""

    limits = ProbeCollectionLimits()
    started = monotonic()
    diagnosis = inspect_probe_preflight(
        connection,
        approved_identity=approved_identity,
        approved_sid=approved_sid,
    )
    preflight = diagnosis.preflight or ProbePreflight(
        "", False, False, False, False
    )
    request = _request(
        approved_identity=approved_identity,
        preflight=preflight,
        elapsed_seconds=monotonic() - started,
    )
    if not _safe(preflight):
        return run_probe(request)
    baseline_cursor_revision = diagnosis.cursor_revision

    try:
        accounting = _collect_accounting(sources, limits)
    except Exception:  # noqa: BLE001 -- source detail never leaves memory.
        return _finish_probe(
            connection,
            request,
            baseline_cursor_revision,
            approved_sid,
            force_stopped=True,
        )
    request = replace(
        request,
        accounting_observations=accounting[0],
        accounting_files=accounting[1],
        accounting_bytes=accounting[2],
        accounting_candidates=accounting[3],
        elapsed_seconds=monotonic() - started,
        accounting_candidate_cap_reached=accounting[4],
        accounting_record_cap_reached=accounting[5],
        accounting_byte_cap_reached=accounting[6],
    )
    if any(accounting[4:]) or _timed_out(request):
        return _finish_probe(
            connection, request, baseline_cursor_revision, approved_sid
        )

    try:
        lifecycle = select_accounting_lifecycle(accounting[0])
    except ProbeStopError as exc:
        return _finish_probe(
            connection,
            replace(request, stop_reason=exc.code),
            baseline_cursor_revision,
            approved_sid,
            force_stopped=True,
        )
    nps_limits = replace(
        limits,
        window_start_utc=lifecycle.nps_window_start_utc,
        window_end_utc=lifecycle.nps_window_end_utc,
    )
    try:
        nps = _collect_nps(sources, nps_limits)
    except Exception:  # noqa: BLE001 -- source detail never leaves memory.
        return _finish_probe(
            connection,
            replace(request, stop_reason="nps_collect_exception"),
            baseline_cursor_revision,
            approved_sid,
            force_stopped=True,
        )
    request = replace(
        request,
        nps_events=nps[0],
        elapsed_seconds=monotonic() - started,
        nps_event_cap_reached=nps[1],
    )
    if nps[1] or _timed_out(request):
        return _finish_probe(
            connection, request, baseline_cursor_revision, approved_sid
        )
    if not nps[0]:
        return _finish_probe(
            connection,
            replace(request, stop_reason="nps_empty_result"),
            baseline_cursor_revision,
            approved_sid,
            force_stopped=True,
        )

    try:
        ad_records = tuple(
            sources.lookup_ad(lifecycle.access_accept.principal_observation)
        )
    except Exception:  # noqa: BLE001 -- source detail never leaves memory.
        return _finish_probe(
            connection,
            request,
            baseline_cursor_revision,
            approved_sid,
            force_stopped=True,
        )
    if len(ad_records) != 1:
        return _finish_probe(
            connection,
            replace(request, ad_records=ad_records),
            baseline_cursor_revision,
            approved_sid,
            force_stopped=True,
        )
    try:
        selected_event = select_nps_match(
            lifecycle,
            nps[0],
            subject_sid=ad_records[0].subject_sid,
        )
    except ProbeStopError:
        return _finish_probe(
            connection,
            replace(request, ad_records=ad_records),
            baseline_cursor_revision,
            approved_sid,
            force_stopped=True,
        )
    request = replace(
        request,
        ad_records=ad_records,
        selected_nps_record_id=selected_event.record_id,
        selected_accounting_record_sha256s=(
            lifecycle.access_accept.canonical_record_sha256,
            lifecycle.start.canonical_record_sha256,
            lifecycle.stop.canonical_record_sha256,
        ),
    )
    return _finish_probe(
        connection,
        replace(
            request,
            elapsed_seconds=monotonic() - started,
        ),
        baseline_cursor_revision,
        approved_sid,
    )


def inspect_probe_identity(
    approved_identity: str | None = None,
    approved_sid: str | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Return the approved identity verdict with bounded safe reason codes."""

    try:
        identity = (
            verify_collection_identity()
            if approved_identity is None and approved_sid is None
            else verify_collection_identity(
                expected_principal=approved_identity,
                expected_sid=approved_sid,
            )
        )
    except Exception:  # noqa: BLE001 -- identity details stay out of diagnostics
        return False, ("identity_check_failed",)
    required_identity = (
        str(identity.get("expected_principal") or "").strip()
        if approved_identity is None
        else str(approved_identity).strip()
    )
    identity_ok = bool(
        required_identity
        and identity.get("status") == "ok"
        and str(identity.get("current_principal") or "").casefold()
        == required_identity.casefold()
        and str(identity.get("expected_principal") or "").casefold()
        == required_identity.casefold()
        and identity.get("interactive") is True
        and identity.get("elevated") is False
    )
    reasons = tuple(
        value
        for item in identity.get("reasons") or ()
        if re.fullmatch(r"[a-z][a-z0-9_:]{0,80}", value := str(item))
    )
    if not identity_ok and not reasons:
        reasons = ("identity_check_failed",)
    return identity_ok, reasons


def inspect_probe_preflight(
    connection: Any,
    *,
    approved_identity: str | None = None,
    approved_sid: str | None = None,
    expected_cursor_revision: int | None = None,
) -> ProbePreflightDiagnosis:
    """Distinguish identity, database and unsafe-state failures safely."""

    identity_ok, reasons = inspect_probe_identity(approved_identity, approved_sid)
    if not identity_ok:
        return ProbePreflightDiagnosis(
            identity_check="failed",
            identity_failure_reasons=reasons,
            database_check="not_run",
            database_error_type=None,
            preflight=None,
        )
    try:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute("set transaction read only")
                cursor.execute(_PREFLIGHT_STATE_QUERY)
                rows = cursor.fetchmany(2)
        (
            source_subscription_disabled,
            no_temporary_login,
            no_worker_started,
            cursor_revision,
        ) = _validated_preflight_row(rows)
    except Exception as exc:
        return ProbePreflightDiagnosis(
            identity_check="passed",
            identity_failure_reasons=(),
            database_check="failed",
            database_error_type=_safe_error_type(exc),
            database_failure_stage="preflight_function",
            preflight=None,
        )
    cursor_unchanged = (
        expected_cursor_revision is None
        or cursor_revision == expected_cursor_revision
    )
    return ProbePreflightDiagnosis(
        identity_check="passed",
        identity_failure_reasons=(),
        database_check="passed",
        database_error_type=None,
        cursor_revision=cursor_revision,
        cursor_check=(
            "baseline_recorded"
            if expected_cursor_revision is None
            else "passed" if cursor_unchanged else "failed"
        ),
        preflight=ProbePreflight(
            str(approved_identity or "configured_identity"),
            source_subscription_disabled=source_subscription_disabled,
            no_temporary_login=no_temporary_login,
            no_worker_started=no_worker_started,
            no_cursor_movement=cursor_unchanged,
        ),
    )


def _validated_preflight_row(
    rows: Sequence[Sequence[object]],
) -> tuple[bool, bool, bool, int]:
    if len(rows) != 1 or len(rows[0]) != 4:
        raise PreflightStateError("preflight_state_invalid")
    source_disabled, no_login, no_worker, revision = rows[0]
    if not all(
        type(value) is bool
        for value in (source_disabled, no_login, no_worker)
    ):
        raise PreflightStateError("preflight_state_invalid")
    if type(revision) is not int or revision < 0:
        raise PreflightStateError("preflight_state_invalid")
    return source_disabled, no_login, no_worker, revision


def _preflight(
    connection: Any, approved_identity: str, approved_sid: str | None = None,
) -> ProbePreflight:
    """Preserve the fail-closed production contract used by the probe."""

    diagnosis = inspect_probe_preflight(
        connection,
        approved_identity=approved_identity,
        approved_sid=approved_sid,
    )
    return diagnosis.preflight or ProbePreflight("", False, False, False, False)


def _safe_error_type(exc: Exception) -> str:
    candidate = type(exc).__name__
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", candidate):
        return candidate
    return "UnknownError"


def _finish_probe(
    connection: Any,
    request: ProbeRequest,
    baseline_cursor_revision: int | None,
    approved_sid: str,
    *,
    force_stopped: bool = False,
) -> dict[str, Any]:
    if baseline_cursor_revision is None:
        return run_probe(
            replace(
                request,
                preflight=ProbePreflight("", False, False, False, False),
                postflight_attestation=ProbePostflightAttestation(),
            )
        )
    diagnosis = inspect_probe_preflight(
        connection,
        approved_identity=request.approved_identity,
        approved_sid=approved_sid,
        expected_cursor_revision=baseline_cursor_revision,
    )
    final_preflight = diagnosis.preflight or ProbePreflight(
        "", False, False, False, False
    )
    attestation = ProbePostflightAttestation(
        performed=True,
        identity_reverified=diagnosis.identity_check == "passed",
        database_rechecked=diagnosis.database_check == "passed",
        cursor_unchanged=diagnosis.cursor_check == "passed",
    )
    result = run_probe(
        replace(
            request,
            preflight=final_preflight,
            postflight_attestation=attestation,
        )
    )
    if force_stopped:
        return {
            **result,
            "terminal_quality_state": "stopped",
            "provenance_digests": {},
            "exact_link_bools": {
                "ad_sid_to_vpn_membership": False,
                "nps_subject_sid_to_ad_sid": False,
                "access_accept_class_to_start_stop": False,
            },
        }
    return result


def _collect_nps(
    sources: ProbeSources, limits: ProbeCollectionLimits,
) -> tuple[tuple[NpsObservation, ...], bool]:
    batch = sources.collect_nps(limits)
    observations, exceeded = _bounded_items(batch.observations, limits.nps_events)
    return observations, bool(batch.cap_reached or exceeded)


def _collect_accounting(
    sources: ProbeSources, limits: ProbeCollectionLimits,
) -> tuple[tuple[AccountingObservation, ...], int, int, int, bool, bool, bool]:
    batch = sources.collect_accounting(limits)
    observations, observed_too_many = _bounded_items(
        batch.observations, limits.accounting_records,
    )
    files_read = int(batch.files_read)
    bytes_read = int(batch.bytes_read)
    candidates_seen = int(batch.candidates_seen)
    return (
        observations,
        files_read,
        bytes_read,
        candidates_seen,
        bool(batch.candidate_cap_reached or candidates_seen > limits.accounting_candidates),
        bool(batch.record_cap_reached or observed_too_many),
        bool(batch.byte_cap_reached or bytes_read > limits.accounting_bytes),
    )


def _bounded_items(values: Iterable[Any], maximum: int) -> tuple[tuple[Any, ...], bool]:
    bounded: list[Any] = []
    for value in values:
        if len(bounded) >= maximum:
            return tuple(bounded), True
        bounded.append(value)
    return tuple(bounded), False


def _request(
    *,
    approved_identity: str,
    preflight: ProbePreflight,
    ad_records: Sequence[AdVpnRecord] = (),
    nps_events: Sequence[NpsObservation] = (),
    accounting_observations: Sequence[AccountingObservation] = (),
    accounting_files: int = 0,
    accounting_bytes: int = 0,
    accounting_candidates: int = 0,
    elapsed_seconds: float = 0,
    nps_event_cap_reached: bool = False,
    accounting_candidate_cap_reached: bool = False,
    accounting_record_cap_reached: bool = False,
    accounting_byte_cap_reached: bool = False,
    selected_nps_record_id: str = "",
    selected_accounting_record_sha256s: tuple[str, str, str] = (),
) -> ProbeRequest:
    return ProbeRequest(
        approved_identity=approved_identity,
        preflight=preflight,
        ad_records=ad_records,
        nps_events=nps_events,
        accounting_observations=accounting_observations,
        accounting_files=accounting_files,
        accounting_bytes=accounting_bytes,
        accounting_candidates=accounting_candidates,
        elapsed_seconds=elapsed_seconds,
        source_timezone_offset_minutes=SOURCE_UTC_OFFSET_MINUTES,
        nps_event_cap_reached=nps_event_cap_reached,
        accounting_candidate_cap_reached=accounting_candidate_cap_reached,
        accounting_record_cap_reached=accounting_record_cap_reached,
        accounting_byte_cap_reached=accounting_byte_cap_reached,
        selected_nps_record_id=selected_nps_record_id,
        selected_accounting_record_sha256s=(
            selected_accounting_record_sha256s
        ),
    )


def _safe(preflight: ProbePreflight) -> bool:
    return bool(
        preflight.identity
        and preflight.source_subscription_disabled
        and preflight.no_temporary_login
        and preflight.no_worker_started
        and preflight.no_cursor_movement
    )


def _timed_out(request: ProbeRequest) -> bool:
    return float(request.elapsed_seconds) > MAX_RUNTIME_SECONDS

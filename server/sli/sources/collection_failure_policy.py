"""Fail-closed policy for collection failures that require operator recovery."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


@dataclass(frozen=True)
class CollectionFailureDecision:
    blocked: bool
    code: str | None = None
    phase: str | None = None
    operator_action: str | None = None


_INVALID_SECURITY_CONTEXT_MARKERS = (
    "windows_security_context_invalid",
    "winerror 1749",
    "(1749, 'evtopensession'",
    '(1749, "evtopensession"',
    "неправильный контекст безопасности",
    "контекст безопасности устарел",
    "the security context is invalid",
    "the security context has expired",
)


# Account restrictions, bad password, expired/disabled/locked account, or a
# required password change must not generate repeated authentication attempts.
TERMINAL_AUTH_WINERRORS = frozenset({1317, 1326, 1327, 1328, 1329, 1330, 1331, 1385, 1793, 1907, 1909})
AD_SOURCE_OPERATOR_FAILURE_CODES = frozenset({
    "windows_event_log_authentication_failed", "windows_event_log_access_denied",
    "ad_source_credential_mode_invalid", "ad_source_backend_unsupported",
    "ad_source_credential_profile_invalid",
    "ad_source_endpoint_invalid", "ad_source_credentials_unavailable",
})


def classify_collection_failure(errors: Iterable[object]) -> CollectionFailureDecision:
    """Classify permanent runtime failures without parsing collector payloads."""
    values = [item for item in errors if item is not None]
    numeric_codes: set[int] = set()
    for value in values:
        for candidate in (
            getattr(value, "winerror", None),
            getattr(value, "hresult", None),
            (getattr(value, "args", ()) or (None,))[0],
        ):
            if isinstance(candidate, int):
                numeric_codes.add(candidate & 0xFFFF)
    normalized = "\n".join(str(item) for item in values).casefold()
    wire_codes = {int(code) for code in re.findall(
        r"(?:winerror\s+|\(\s*)(\d+)(?=\b)", normalized,
    )}
    credential_code = next((code for code in sorted(AD_SOURCE_OPERATOR_FAILURE_CODES) if code in normalized), None)
    if credential_code or TERMINAL_AUTH_WINERRORS.intersection(numeric_codes | wire_codes):
        return CollectionFailureDecision(
            blocked=True,
            code=credential_code or "windows_event_log_authentication_failed",
            phase="source_authentication",
            operator_action=(
                "Исправьте локальный AD credential/режим и доступ к настроенному DC; "
                "выполните явную контрольную проверку collection_block_control. Автоматический повтор отключён."
            ),
        )
    if 1749 in numeric_codes or any(marker in normalized for marker in _INVALID_SECURITY_CONTEXT_MARKERS):
        return CollectionFailureDecision(
            blocked=True,
            code="windows_security_context_invalid",
            phase="security_context_invalid",
            operator_action=(
                "Перезапустите процесс сбора в подтверждённой интерактивной Windows-сессии "
                "и проверьте учётные данные/доступ EvtOpenSession. Автоматический повтор отключён."
            ),
        )
    return CollectionFailureDecision(blocked=False)


"""Ordered stage markers used to attribute a non-terminal collection failure.

Matched against the exception text/type.  These do not block the runtime: they
exist so `partial_failed` carries a machine-readable stage instead of being
flattened into `partial_timeout`.
"""
_STAGE_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("open_session", ("evtopensession", "open_remote_session", "rpc server", "logon fail")),
    ("query", ("evtquery", "invalid query", "xpath", "malformed")),
    ("next", ("evtnext", "no more items", "handle is invalid")),
    ("render", ("evtrender", "render")),
    ("parse", ("parse_bounded_xml", "xml", "expat", "not well-formed", "syntaxerror")),
    ("write", ("oserror", "ioerror", "no space", "permission denied", "being used by another process")),
)

_STAGE_BY_EXCEPTION: tuple[tuple[str, str], ...] = (
    ("PermissionError", "write"),
    ("FileNotFoundError", "write"),
    ("OSError", "write"),
    ("UnicodeDecodeError", "parse"),
    ("UnicodeEncodeError", "write"),
    ("MemoryError", "render"),
)


def classify_partial_failure(error: object, *, events_written: int) -> dict[str, object]:
    """Attribute a non-terminal collector exception to a pipeline stage.

    Returns stable machine-readable fields.  `blocked`-class failures (currently
    only `windows_security_context_invalid`) are handled by
    `classify_collection_failure` and keep their own contract; this helper only
    describes WHERE a partial run broke so operators and adaptive logic stop
    reading every mid-stream exception as a timeout.
    """
    if error is None:
        return {}

    normalized = str(error).casefold()
    stage: str | None = None
    for candidate, markers in _STAGE_MARKERS:
        if any(marker in normalized for marker in markers):
            stage = candidate
            break

    if stage is None:
        exception_name = type(error).__name__ if isinstance(error, BaseException) else ""
        for candidate_name, candidate_stage in _STAGE_BY_EXCEPTION:
            if exception_name == candidate_name:
                stage = candidate_stage
                break

    return {
        # `partial_kind` discriminates a broken read from a benign timeout while
        # the wire status stays `partial_timeout`, so existing consumers
        # (archive_state, collector_adaptive, collector_health aggregates, i18n
        # labels) keep working unchanged.
        "partial_kind": "failure",
        "failure_stage": stage or "unknown",
        "partial_failure_code": f"partial_failure_{stage or 'unknown'}",
        "partial_events_written": int(events_written),
        # A partial failure is retryable, but it must NOT advance the cursor:
        # the tail of the channel was never read.
        "cursor_commit_allowed": False,
    }


def collection_failure_fields(decision: CollectionFailureDecision) -> dict[str, object]:
    """Return the stable machine-readable fields shared by all collectors."""
    if not decision.blocked:
        return {}
    return {
        "failure_code": decision.code,
        "failure_scope": "worker_identity",
        "retryable": False,
        "retry_policy": "operator_recovery_required",
        "pipeline_disposition": "blocked_pre_import",
        "operator_action": decision.operator_action,
    }

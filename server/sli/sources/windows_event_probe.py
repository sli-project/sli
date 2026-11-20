"""Проверка доступа к журналу событий Windows в токене вызывающего процесса.

Перенесено из scripts/maintenance/collection_block_control.py: collection_worker
(runtime) не импортирует scripts.maintenance; CLI разблокировки остаётся тонкой
обёрткой и реэкспортирует эти имена.
"""

from __future__ import annotations


def _close_evt_handle(handle: object) -> None:
    """Close pywin32 PyEVT_HANDLE when supported.

    win32evtlog intentionally has no module-level EvtClose function.  Current
    pywin32 handles expose Close(); older wrappers are still released when the
    short-lived probe process exits.
    """

    close = getattr(handle, "Close", None)
    if callable(close):
        close()


def probe_windows_event_context(
    server: str,
    *,
    channel: str = "Security",
    timeout_ms: int = 5000,
    ad_source_credential_mode: str = "process",
    configured_dc: bool = False,
) -> dict[str, object]:
    """Prove bounded remote Event Log query access in the caller's token.

    ``EvtOpenSession`` alone is insufficient: Windows may open the RPC session
    for a filtered UAC token and reject the first ``EvtQuery`` with error 5.
    The preflight therefore opens the session and performs one reverse,
    one-record read before any collection job can be created.
    """
    session = None
    try:
        from scripts.collect.collect_windows_events import (
            open_remote_session,
            probe_latest_record_id,
        )
        from server.sli.sources.ad_source_auth import validate_ad_source_credential_mode

        mode = validate_ad_source_credential_mode(ad_source_credential_mode)
        if mode != "process":
            session = open_remote_session(server, ad_source_credential_mode=mode)
        else:
            target = server
            if configured_dc:
                from server.sli.sources.dc_discovery import (
                    resolve_domain_controller_connect_address,
                )

                target = resolve_domain_controller_connect_address(server)
            session = open_remote_session(target)
        latest_record_id = probe_latest_record_id(
            session,
            str(channel),
            timeout_ms=max(1, min(int(timeout_ms), 15_000)),
        )
        return {
            "status": "ok",
            "server": server,
            "channel": str(channel),
            "query_access": "verified",
            "event_observed": latest_record_id is not None,
        }
    except Exception as exc:
        from scripts.collect.collect_windows_events import winerror_from_exception
        from server.sli.sources.collection_failure_policy import classify_collection_failure
        from server.sli.sources.collection_runtime_block import (
            REASON_WINDOWS_EVENT_LOG_ACCESS_DENIED,
        )

        decision = classify_collection_failure([exc])
        winerror = winerror_from_exception(exc)
        failure_code = (
            REASON_WINDOWS_EVENT_LOG_ACCESS_DENIED
            if winerror == 5
            else decision.code
        )
        return {
            "status": "failed",
            "server": server,
            "channel": str(channel),
            "error_type": type(exc).__name__,
            "winerror": winerror,
            "failure_code": failure_code,
        }
    finally:
        if session is not None:
            _close_evt_handle(session)

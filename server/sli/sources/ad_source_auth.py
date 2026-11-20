"""Explicit Python AD/DC auth selection; never an implicit shared-helper default.

Only the nonsecret mode crosses process boundaries. The source process keeps
its local DPAPI owner token and loads the existing CurrentUser store locally.
"""
from __future__ import annotations

AD_SOURCE_CREDENTIAL_MODE_ENV = "ADLOG_AD_SOURCE_CREDENTIAL_MODE"
AD_EVENTLOG_CREDENTIAL_PROFILE_ENV = "ADLOG_AD_EVENTLOG_CREDENTIAL_PROFILE"
PROCESS = "process"
DPAPI_CURRENT_USER = "dpapi_current_user"


def sanitized_ad_source_error(exc: BaseException) -> RuntimeError:
    """Never propagate native error text/account/password into logs or IPC."""
    from server.sli.sources.collection_failure_policy import classify_collection_failure

    code = getattr(exc, "winerror", None)
    if not isinstance(code, int):
        code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else None
    decision = classify_collection_failure([exc])
    message = (
        "windows_event_log_access_denied"
        if code is not None and (code & 0xFFFF) == 5
        else decision.code or "ad_source_rpc_failed"
    )
    if code is not None:
        message += f" winerror {code & 0xFFFF}"
    error = RuntimeError(message)
    error.winerror = code
    return error


def validate_ad_source_credential_mode(mode: str, *, backend: str = "python") -> str:
    if mode not in (PROCESS, DPAPI_CURRENT_USER):
        raise RuntimeError("ad_source_credential_mode_invalid")
    if mode == DPAPI_CURRENT_USER and backend not in ("python", "auto"):
        raise RuntimeError("ad_source_backend_unsupported")
    return mode


def resolve_ad_source_endpoint(server: str, *, connect_address: str | None = None) -> str:
    """Require an exact configured logical name/FQDN, then reuse DNS readback.

    dc_discovery's legacy no-config fallback and short-name extraction alone
    are insufficient authority to send a separately saved credential.
    """
    from server.sli.sources.dc_discovery import (
        get_configured_domain_controller_targets,
        resolve_domain_controller_connect_address,
    )

    try:
        matches = [target for target in get_configured_domain_controller_targets()
                   if server.casefold() in (target["hostname"].casefold(), target["connect_address"].casefold())]
        if len(matches) != 1:
            raise ValueError
        target = matches[0]
        if connect_address is not None and connect_address.casefold() != target["connect_address"].casefold():
            raise ValueError
        resolved = resolve_domain_controller_connect_address(target["hostname"])
        if resolved != target["connect_address"]:
            raise ValueError
        return resolved
    except Exception:
        raise RuntimeError("ad_source_endpoint_invalid") from None


def load_ad_source_login(target: str, auth_flags: int, *, credential_profile: str = "ad") -> tuple[str, str, str | None, str, int]:
    """Load only after endpoint admission; preserve the stored account exactly."""
    from server.sli.sources.ad_source_credentials import load_credentials, validate_username

    profile = credential_profile
    if profile not in ("ad", "vpn"):
        raise RuntimeError("ad_source_credential_profile_invalid")
    try:
        credentials = load_credentials() if profile == "ad" else load_credentials(profile="vpn")
        username = validate_username(credentials.username)
        if "\\" in username:
            domain, user = username.split("\\", 1)
        else:
            user, domain = username, None  # Native UPN login requires a null domain.
        return target, user, domain, credentials.password, auth_flags
    except Exception:
        raise RuntimeError("ad_source_credentials_unavailable") from None

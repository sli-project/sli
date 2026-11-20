"""VPN accounting credentials scoped to the bounded SMB read in a Job child."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
from typing import Iterator

from server.sli.sources.ad_source_credentials import load_credentials, validate_username
from server.source_packs.radius.collection_routes import require_accounting_source

VPN_SOURCE_CREDENTIAL_MODE_ENV = "ADLOG_VPN_SOURCE_CREDENTIAL_MODE"


class VpnSourceAuthError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def validate_vpn_source_credential_mode(mode: str) -> str:
    if mode not in ("process", "dpapi_current_user"):
        raise VpnSourceAuthError("vpn_source_credential_mode_invalid")
    return mode


def _windows():
    if os.name != "nt":
        raise VpnSourceAuthError("vpn_source_windows_required")
    import win32api
    import win32security
    return win32security, win32api


@contextmanager
def accounting_source_identity(directory: Path, *, mode: str) -> Iterator[None]:
    """Admit the configured share before decrypting under the original owner.

    No persistent SMB mapping or process-token fallback. Callers must limit
    the body to bounded source reads and in-memory anchor derivation;
    local database/evidence work follows revert.
    """
    if validate_vpn_source_credential_mode(mode) == "process":
        yield
        return
    try:
        approved, _timezone, _offset = require_accounting_source()
        if directory != approved:
            raise VpnSourceAuthError("vpn_source_endpoint_invalid")
    except Exception:
        raise VpnSourceAuthError("vpn_source_endpoint_invalid") from None
    try:
        security, api = _windows()
        try:
            existing = security.OpenThreadToken(api.GetCurrentThread(), 8, True)
        except Exception as exc:
            if getattr(exc, "winerror", None) != 1008:  # ERROR_NO_TOKEN only
                raise VpnSourceAuthError("vpn_source_thread_identity_unavailable") from None
        else:
            existing.Close()
            raise VpnSourceAuthError("vpn_source_thread_impersonation_forbidden")
        credentials = load_credentials(profile="vpn")
        username = validate_username(credentials.username)
        if "\\" in username:
            domain, user = username.split("\\", 1)
        else:
            user, domain = username, None
        token = security.LogonUser(user, domain, credentials.password, 9, 3)
        try:
            # Always revert even if the native impersonation call raises.
            try:
                security.ImpersonateLoggedOnUser(token)
                yield
            finally:
                try:
                    security.RevertToSelf()
                except BaseException:
                    # No stack unwinding into local DB/evidence with an unknown
                    # thread identity. The parent Job owns this bounded child.
                    os._exit(74)
        finally:
            token.Close()
    except VpnSourceAuthError:
        raise
    except Exception:
        raise VpnSourceAuthError("vpn_source_access_failed") from None

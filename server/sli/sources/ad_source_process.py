"""Server compatibility wrapper for configured AD acquisition identity."""
from __future__ import annotations

import subprocess
from pathlib import Path

from server.sli.sources.ad_source_auth import (
    load_ad_source_login,
    resolve_ad_source_endpoint,
)

# Re-export the native boundary for existing maintenance callers and fakes.
from sli_collect.powershell import (  # noqa: F401
    _ProcessInfo,
    _run_netonly,
    _source_environment,
    _StartupInfo,
    ctypes,
    os,
)


def run_ad_source_process(command: list[str], *, server: str, cwd: Path,
                          timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    target = resolve_ad_source_endpoint(server)
    login = load_ad_source_login(target, 0)
    try:
        return _run_netonly(command, login=login, cwd=cwd, timeout_seconds=timeout_seconds)
    except Exception as exc:
        code = getattr(exc, "winerror", None)
        known = str(exc) if str(exc) in {
            "ad_source_process_timeout", "ad_source_process_output_limit",
            "ad_source_process_command_invalid", "ad_source_process_command_too_long",
        } else "ad_source_process_failed"
        raise RuntimeError(known + (f" winerror {code}" if isinstance(code, int) else "")) from None
    finally:
        login = None

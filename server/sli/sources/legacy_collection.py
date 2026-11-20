"""One opt-in cutover gate for server-side legacy entry points only.

Agent collectors and core projection routines must remain usable. This module
does not stop running processes, change ownership or remove stored history.
"""
import os

FLAG = "SLI_LEGACY_COLLECTION_DISABLED"
REASON = "legacy_collection_disabled"
MESSAGE = "legacy collection disabled by SLI_LEGACY_COLLECTION_DISABLED; use agent modules and core job handlers"


class LegacyCollectionDisabled(RuntimeError):
    pass


def legacy_collection_disabled() -> bool:
    # Only the documented default permits legacy admission. A typo must not
    # silently reopen old collection paths during the owner's cutover.
    return os.environ.get(FLAG, "0").strip() != "0"


def require_legacy_collection() -> None:
    if legacy_collection_disabled():
        raise LegacyCollectionDisabled(MESSAGE)

"""Security facts from a daily AD snapshot, without account-name heuristics."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

UAC_FLAGS = {
    "passwordNotRequired": 0x20,
    "allowReversiblePasswordEncryption": 0x80,
    "passwordNeverExpires": 0x10000,
    "smartcardLogonRequired": 0x40000,
    "accountNotDelegated": 0x100000,
    "doesNotRequirePreAuth": 0x400000,
}
RISK_KEYS = frozenset({"password_not_required", "kerberos_no_preauth", "spn_privileged",
                       "spn_old_password", "privileged_password_never_expires"})
HYGIENE_EXCEPTION_KEYS = frozenset({"password_age", "inactive_threshold", "spn_old_password"})


def facts(user: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(user)
    raw = user.get("userAccountControl")
    try:
        uac = int(raw) if not isinstance(raw, bool) and str(raw).isascii() and str(raw).isdecimal() else None
    except (ValueError, TypeError, OverflowError):
        uac = None
    for name, bit in UAC_FLAGS.items():
        value = user.get(name)
        result[name] = bool(uac & bit) if uac is not None else value if isinstance(value, bool) else None
    classes = user.get("objectClasses") or []
    classes = {str(value).casefold() for value in (classes if isinstance(classes, list) else [classes])}
    spns = user.get("servicePrincipalNames")
    spns = [value for value in (spns if isinstance(spns, list) else [spns]) if isinstance(value, str) and value.strip()]
    result["servicePrincipalNames"] = spns
    result["serviceAccountType"] = ("gmsa" if "msds-groupmanagedserviceaccount" in classes else
                                    "msa" if "msds-managedserviceaccount" in classes else "spn" if spns else None)
    return result


def privileged(user: Mapping[str, Any]) -> bool:
    """adminCount can survive privilege removal and is not current membership."""
    return any(group.get("watchGroup") is True for group in (user.get("memberships") or {}).get("effective") or []
               if isinstance(group, Mapping)) or any(
        entry.get("relation") == "direct" for entry in user.get("privilegedMemberships") or [] if isinstance(entry, Mapping))


def exception(user: Mapping[str, Any], configured: Mapping[str, Any]) -> dict[str, Any] | None:
    return configured.get(str(user.get("sid") or "").upper()) if user.get("serviceAccountType") else None

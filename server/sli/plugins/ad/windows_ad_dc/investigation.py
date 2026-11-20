from __future__ import annotations

"""Windows AD/DC investigation event IDs, categories and checks."""

from typing import Any

_INVESTIGATION_IMPORTANT_EVENT_IDS = tuple(
    sorted(
        {
            106,
            140,
            141,
            4624,
            4625,
            4648,
            4672,
            4720,
            4722,
            4723,
            4724,
            4725,
            4726,
            4728,
            4729,
            4732,
            4733,
            4738,
            4740,
            4756,
            4757,
            4768,
            4769,
            4771,
            4776,
            7045,
        }
    )
)


_INVESTIGATION_NOISE_EVENT_IDS = frozenset({4634, 4670, 4688, 4768, 4769})


_INVESTIGATION_CATEGORY_BY_EVENT_ID = {
    4625: "failed_logons",
    4624: "logons",
    4648: "logons",
    4634: "logons",
    4723: "passwords",
    4724: "passwords",
    4740: "lockouts",
    4767: "lockouts",
    4728: "groups",
    4729: "groups",
    4732: "groups",
    4733: "groups",
    4756: "groups",
    4757: "groups",
    4672: "privileges",
    4720: "accounts",
    4722: "accounts",
    4725: "accounts",
    4726: "accounts",
    4738: "accounts",
    4768: "kerberos_ntlm",
    4769: "kerberos_ntlm",
    4771: "kerberos_ntlm",
    4776: "kerberos_ntlm",
    7045: "system",
    106: "system",
    140: "system",
    141: "system",
}


_INVESTIGATION_CHECKS = {
    "privileges": "Проверить 4672 рядом с 4624: тип входа, источник и учетная запись.",
}


def investigation_event_ids(scope: str) -> tuple[int, ...]:
    normalized_scope = str(scope or "important").strip().casefold()
    if normalized_scope == "noise":
        return tuple(sorted(_INVESTIGATION_NOISE_EVENT_IDS))
    if normalized_scope == "hide_noise":
        return tuple(
            event_id
            for event_id in _INVESTIGATION_IMPORTANT_EVENT_IDS
            if event_id not in _INVESTIGATION_NOISE_EVENT_IDS
        )
    return _INVESTIGATION_IMPORTANT_EVENT_IDS


def investigation_category(event_id: Any) -> str:
    try:
        return _INVESTIGATION_CATEGORY_BY_EVENT_ID.get(int(event_id), "other")
    except (TypeError, ValueError):
        return "other"


def investigation_check(category: str) -> str | None:
    return _INVESTIGATION_CHECKS.get(str(category or "").strip())

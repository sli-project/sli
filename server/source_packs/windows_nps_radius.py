from __future__ import annotations

"""Fail-closed normalization for the bundled Windows NPS source pack.

The module describes NPS Security events only.  RADIUS Accounting remains a
separate source contract and is never inferred from Event IDs 6272/6273.
"""

from collections.abc import Mapping
from typing import Any

from server.sli.entities.identity_resolution import разрешить_субъект
from server.source_packs.contracts import (
    AccountEventSemantics,
    EventEntitySemantics,
    EventStateSemantics,
    FindingRule,
    SecurityMonitorGroup,
    SemanticCoreRoleFilter,
    SemanticEventIdentity,
)


PACK_ID = "sli.windows.vpn-radius"
STREAM = "Security"
PROVIDER = "Microsoft-Windows-Security-Auditing"
ALLOWED_EVENT_ID = 6272
DENIED_EVENT_ID = 6273
EVENT_IDS = (ALLOWED_EVENT_ID, DENIED_EVENT_ID)


def _text(data: Mapping[str, Any], *names: str, limit: int = 512) -> str | None:
    for name in names:
        value = data.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()[:limit]
    return None


def _event_id(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def correlation_id_for_event(
    *,
    channel: str | None,
    event_id: Any,
    event_data: Mapping[str, Any],
) -> str | None:
    if (
        str(channel or "").strip().casefold() != STREAM.casefold()
        or _event_id(event_id) not in EVENT_IDS
    ):
        return None
    return _text(event_data, "AccountSessionIdentifier", limit=256)


def event_facts_for_event(
    *,
    row: Mapping[str, Any],
    event_data: Mapping[str, Any],
) -> dict[str, Any]:
    event_id = _event_id(row.get("event_id"))
    if event_id not in EVENT_IDS:
        return {}
    return {
        "process_name": None,
        "process_id": None,
        "target_server_name": _text(event_data, "AuthenticationServer"),
        "service_name": None,
        "task_name": None,
        "task_action": None,
        "task_author": None,
        "run_as": None,
        "logon_type": _text(event_data, "AuthenticationType", limit=128),
        "result_code": _text(
            event_data,
            "ReasonCode" if event_id == DENIED_EVENT_ID else "LoggingResult",
            limit=128,
        ),
        "object_name": _text(
            event_data,
            "NetworkPolicyName",
            "NASIdentifier",
        ),
        "share_name": None,
        "message_sample": None,
    }


def entity_semantics_for_event(
    *,
    channel: str | None,
    event_id: Any,
) -> EventEntitySemantics:
    return EventEntitySemantics()


def state_semantics_for_event(
    *,
    channel: str | None,
    event_id: Any,
) -> EventStateSemantics | None:
    return None


def classify_contextual_event(row: Mapping[str, Any]) -> dict[str, Any]:
    event_id = _event_id(row.get("event_id"))
    provider = str(row.get("provider_name") or "").strip().casefold()
    channel = str(row.get("channel") or "").strip().casefold()
    if channel != STREAM.casefold() or provider != PROVIDER.casefold():
        return {
            "severity": "info",
            "title": f"Event ID {event_id}",
            "reason": "NPS descriptor identity does not match.",
        }
    if event_id == ALLOWED_EVENT_ID:
        return {
            "severity": "low",
            "title": "NPS разрешил запрос доступа",
            "reason": "Наблюдается решение NPS; VPN-сессия требует Accounting.",
        }
    if event_id == DENIED_EVENT_ID:
        return {
            "severity": "medium",
            "title": "NPS отклонил запрос доступа",
            "reason": "Отказ требует контекста и не является атакой сам по себе.",
        }
    return {
        "severity": "info",
        "title": f"Event ID {event_id}",
        "reason": "NPS source pack does not declare this event key.",
    }


def account_event_semantics(event_id: Any) -> AccountEventSemantics | None:
    return {
        ALLOWED_EVENT_ID: AccountEventSemantics(
            "NPS разрешил доступ",
            "remote_access_allowed",
            "ok",
        ),
        DENIED_EVENT_ID: AccountEventSemantics(
            "NPS отклонил доступ",
            "remote_access_denied",
            "warn",
        ),
    }.get(_event_id(event_id))


def event_ids_for_search_family(family: str) -> tuple[int, ...]:
    return EVENT_IDS if str(family or "").strip() in {
        "authentication",
        "remote_access",
    } else ()


def event_ids_for_analysis_family(family: str) -> tuple[int, ...]:
    return {
        "remote_access": EVENT_IDS,
        "remote_access_allowed": (ALLOWED_EVENT_ID,),
        "remote_access_denied": (DENIED_EVENT_ID,),
    }.get(str(family or "").strip(), ())


def important_account_event_ids() -> tuple[int, ...]:
    return EVENT_IDS


def event_label(event_id: Any, lang: str) -> str | None:
    labels = {
        ALLOWED_EVENT_ID: {
            "ru": "NPS разрешил запрос доступа",
            "en": "NPS granted access request",
        },
        DENIED_EVENT_ID: {
            "ru": "NPS отклонил запрос доступа",
            "en": "NPS denied access request",
        },
    }.get(_event_id(event_id))
    if labels is None:
        return None
    return labels.get(str(lang or "ru").casefold()) or labels["ru"]


def finding_rules() -> Mapping[int, FindingRule]:
    return {}


def investigation_event_ids(scope: str) -> tuple[int, ...]:
    return () if str(scope or "").strip().casefold() == "noise" else EVENT_IDS


def investigation_category(event_id: Any) -> str:
    return "authentication" if _event_id(event_id) in EVENT_IDS else "other"


def investigation_check(category: str) -> str | None:
    return (
        "Сопоставить решение NPS с политикой и отдельным RADIUS Accounting."
        if str(category or "").strip() == "authentication"
        else None
    )


def security_monitor_groups() -> tuple[SecurityMonitorGroup, ...]:
    return (
        SecurityMonitorGroup(
            key="remote_access",
            label="Удалённый доступ NPS",
            event_ids=EVENT_IDS,
            severity="medium",
            hint="Решения NPS; не являются VPN-сессиями без Accounting.",
        ),
    )


def monitor_privileged_event_ids() -> tuple[int, ...]:
    return ()


def semantic_projection_for_event(
    *,
    event_id: Any,
    channel: str | None,
    provider: str | None,
    event_data: Mapping[str, Any],
    correlation_id: str | None,
    source_host: str,
    identity_host: str | None = None,
    keywords: Any = None,
) -> dict[str, Any]:
    numeric_event_id = _event_id(event_id)
    if not _descriptor_matches(numeric_event_id, channel, provider):
        return _unknown_projection(
            numeric_event_id,
            channel,
            provider,
            correlation_id,
            source_host,
        )

    identity = разрешить_субъект(
        sid=_text(event_data, "SubjectUserSid"),
        sam=_text(
            event_data,
            "SubjectUserName",
            "FullyQualifiedSubjectUserName",
        ),
        домен=_text(event_data, "SubjectDomainName"),
        узел=identity_host or source_host,
    )
    roles: dict[str, str] = {"source_host": source_host}
    identity_roles: dict[str, dict[str, Any]] = {}
    if identity.ключ:
        roles["affected_entity"] = identity.ключ
        identity_roles["affected_entity"] = {
            "key": identity.ключ,
            "state": identity.состояние,
            "step": identity.ступень,
            "provisional": identity.временный,
            "confidence": identity.уверенность,
            "reason": identity.причина,
            "aliases": list(identity.псевдонимы),
            "rule": "identity-ladder/v1",
        }
    session_identifier = _text(
        event_data,
        "AccountSessionIdentifier",
        limit=256,
    )
    if session_identifier:
        roles["session_principal"] = (
            f"{source_host}:nps:{session_identifier.casefold()}"
        )
    source_ip = _text(event_data, "CallingStationID", limit=128)
    if source_ip:
        roles["source_ip"] = source_ip

    semantic_type = (
        "remote_access.authentication.allowed"
        if numeric_event_id == ALLOWED_EVENT_ID
        else "remote_access.authentication.denied"
    )
    facts = {
        "windows_event_id": numeric_event_id,
        "channel": channel,
        "provider": provider,
        "correlation_id": correlation_id or session_identifier,
        "decision": (
            "allowed"
            if numeric_event_id == ALLOWED_EVENT_ID
            else "denied"
        ),
        "authentication_type": _text(event_data, "AuthenticationType"),
        "authentication_provider": _text(
            event_data,
            "AuthenticationProvider",
        ),
        "network_policy": _text(event_data, "NetworkPolicyName"),
        "nas_identifier": _text(event_data, "NASIdentifier"),
        "reason_code": _text(event_data, "ReasonCode", limit=128),
        "session_evidence": "nps_decision_only_accounting_required",
    }
    return {
        "semantic_type": semantic_type,
        "roles": roles,
        "facts": {
            key: value for key, value in facts.items() if value is not None
        },
        "quality": {
            "event_data_encoding": "named",
            "catalog_independent": False,
            "raw_event_mutated": False,
            "missing_actor_sid": _text(event_data, "SubjectUserSid") is None,
            "unresolved_actor": False,
            "unresolved_target": bool(
                identity.ключ and identity.состояние == "unresolved"
            ),
            "missing_source_ip": "source_ip" not in roles,
            "unknown_event_mapping": False,
            "identity_roles": identity_roles,
            "provisional_identity_roles": sorted(
                role
                for role, value in identity_roles.items()
                if value["provisional"]
            ),
            "unresolved_identity_roles": sorted(
                role
                for role, value in identity_roles.items()
                if value["state"] == "unresolved"
            ),
            "semantic_mapping_status": "mapped_nps_decision",
            "vpn_session_confirmed": False,
        },
    }


def semantic_event_identities(
    semantic_types: tuple[str, ...],
) -> tuple[SemanticEventIdentity, ...]:
    wanted = {str(value).strip() for value in semantic_types}
    result: list[SemanticEventIdentity] = []
    for event_id, semantic_type, noise_class in (
        (
            ALLOWED_EVENT_ID,
            "remote_access.authentication.allowed",
            "context",
        ),
        (
            DENIED_EVENT_ID,
            "remote_access.authentication.denied",
            "signal",
        ),
    ):
        if semantic_type in wanted:
            result.append(
                SemanticEventIdentity(
                    source=PACK_ID,
                    stream=STREAM,
                    event_key=str(event_id),
                    provider_name=PROVIDER,
                    semantic_type=semantic_type,
                    noise_class=noise_class,
                    noise_catalog_version="2026-07-30-radius-descriptor-v1",
                )
            )
    return tuple(result)


def semantic_core_role_filters(
    semantic_type: str,
    join_roles: tuple[str, ...],
    trigger_roles: Mapping[str, str],
) -> tuple[SemanticCoreRoleFilter, ...] | None:
    if semantic_type not in {
        "remote_access.authentication.allowed",
        "remote_access.authentication.denied",
    }:
        return None
    field_by_role = {
        "affected_entity": ("subject_user_sid", "subject_user_name"),
        "session_principal": ("correlation_id", None),
    }
    filters: list[SemanticCoreRoleFilter] = []
    for role in join_roles:
        fields = field_by_role.get(role)
        value = str(trigger_roles.get(role) or "").strip()
        if fields is None or not value:
            return None
        filters.append(
            SemanticCoreRoleFilter(
                role=role,
                primary_field=fields[0],
                fallback_field=fields[1],
                value=value.rpartition(":")[2],
            )
        )
    return tuple(filters)


def _descriptor_matches(
    event_id: int,
    channel: str | None,
    provider: str | None,
) -> bool:
    from server.sli.events.event_catalog import lookup_semantic_event_descriptor

    return lookup_semantic_event_descriptor(
        PACK_ID,
        str(channel or ""),
        str(event_id),
        provider,
    ) is not None


def _unknown_projection(
    event_id: int,
    channel: str | None,
    provider: str | None,
    correlation_id: str | None,
    source_host: str,
) -> dict[str, Any]:
    return {
        "semantic_type": "event.unknown",
        "roles": {"source_host": source_host},
        "facts": {
            "windows_event_id": event_id,
            "channel": channel,
            "provider": provider,
            "correlation_id": correlation_id,
        },
        "quality": {
            "event_data_encoding": "named",
            "catalog_independent": False,
            "raw_event_mutated": False,
            "missing_actor_sid": True,
            "unresolved_actor": False,
            "unresolved_target": False,
            "missing_source_ip": True,
            "unknown_event_mapping": True,
            "identity_roles": {},
            "provisional_identity_roles": [],
            "unresolved_identity_roles": [],
            "semantic_mapping_status": (
                "descriptor_identity_missing_or_mismatched"
            ),
            "vpn_session_confirmed": False,
        },
    }

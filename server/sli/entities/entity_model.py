from __future__ import annotations

from typing import Any

from server.sli.semantic.event_card_semantics import catalog_role_values
from server.sli.entities.identity_resolution import разрешить_субъект
from server.source_packs.contracts import EventEntitySemantics
from server.source_packs.registry import resolve_source_normalizer

LINK_ROLES = {"recorder", "actor", "target", "affected", "source", "context"}
PRIVILEGED_GROUP_NAMES = {"domain admins", "enterprise admins", "schema admins", "administrators", "account operators", "server operators", "backup operators", "dnsadmins", "администраторы домена", "администраторы предприятия", "администраторы схемы", "администраторы"}


def extract_event_entities(event_row: dict[str, Any], event_data: dict[str, Any]) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    event_id = int(event_row.get("event_id") or 0)
    server_name = _clean(event_row.get("computer_name") or event_row.get("machine_name") or event_row.get("computer"))
    channel = _clean(event_row.get("channel"))
    provider = _clean(event_row.get("provider_name"))
    source_normalizer = resolve_source_normalizer(
        channel,
        provider,
        str(event_id),
    )
    source_semantics = (
        source_normalizer.entity_semantics(channel=channel, event_id=event_id)
        if source_normalizer
        else EventEntitySemantics()
    )

    if server_name:
        _append_entity(
            links,
            "asset",
            f"server:{server_name.lower()}",
            server_name,
            "recorder",
            server_scoped=True,
            attributes={"role_hint": "event_recorder"},
        )
    if channel:
        _append_entity(
            links,
            "log_source",
            f"log:{channel.lower()}",
            channel,
            "context",
            domain_scoped=False,
            attributes={"provider_name": provider},
        )
    if provider:
        _append_entity(
            links,
            "event_provider",
            f"provider:{provider.lower()}",
            provider,
            "context",
            domain_scoped=False,
        )

    catalog_roles = catalog_role_values({**event_row, "event_data": event_data})
    subject_user = _clean(_pick(event_data, "SubjectUserName") or catalog_roles.get("initiator"))
    subject_domain = _clean(_pick(event_data, "SubjectDomainName"))
    if subject_user and subject_user not in {"-", "ANONYMOUS LOGON"}:
        _append_principal(
            links, subject_user, subject_domain, "actor",
            sid=_pick(event_data, "SubjectUserSid"),
            upn=_pick(event_data, "SubjectUserPrincipalName", "SubjectUPN"),
            email=_pick(event_data, "SubjectEmail", "SubjectMail"),
            node=server_name,
        )

    target_user = _clean(_pick(event_data, "TargetUserName", "TargetAccount"))
    target_domain = _clean(_pick(event_data, "TargetDomainName"))
    if target_user and target_user != "-":
        role = "affected" if source_semantics.target_is_group else "target"
        entity_type = _principal_type(
            target_user,
            force_group=source_semantics.target_is_group,
        )
        _append_principal(
            links,
            target_user,
            target_domain,
            role,
            sid=_pick(event_data, "TargetUserSid", "TargetSid"),
            upn=_pick(event_data, "TargetUserPrincipalName", "TargetUPN"),
            email=_pick(event_data, "TargetEmail", "TargetMail"),
            entity_type=entity_type,
            node=server_name,
        )

    member_name = _clean(_pick(event_data, "MemberName", "MemberSid"))
    if member_name and member_name != "-":
        _append_principal(
            links, member_name, target_domain or subject_domain, "affected",
            sid=_pick(event_data, "MemberSid"), node=server_name,
        )

    workstation = _clean(_pick(event_data, "WorkstationName", "Workstation"))
    if workstation and workstation != "-":
        _append_entity(links, "workstation", f"workstation:{workstation.lower()}", workstation, "source")

    ip_address = _clean(_pick(event_data, "IpAddress", "ClientAddress", "SourceAddress"))
    if ip_address and ip_address not in {"-", "::1", "127.0.0.1"}:
        _append_entity(links, "ip_address", f"ip:{ip_address}", ip_address, "source", domain_scoped=False)

    process_name = _clean(_pick(event_data, "ProcessName", "NewProcessName", "Application"))
    if process_name and process_name != "-":
        _append_entity(links, "process", f"process:{process_name.lower()}", process_name, "source", domain_scoped=False)

    service_name = _clean(_pick(event_data, "ServiceName", "param1"))
    if service_name and source_semantics.service_name_is_entity:
        _append_entity(links, "service", f"service:{service_name.lower()}", service_name, "target")

    task_name = _clean(_pick(event_data, "TaskName", "TaskNamePath"))
    if task_name:
        _append_entity(links, "scheduled_task", f"task:{task_name.lower()}", task_name, "target")

    target_server = _clean(_pick(event_data, "TargetServerName", "ServiceName"))
    if (
        target_server
        and target_server not in {"-", "localhost"}
        and source_semantics.target_server_is_entity
    ):
        _append_entity(links, "asset", f"server:{target_server.lower()}", target_server, "target")

    logon_id = _clean(_pick(event_data, "LogonId", "TargetLogonId", "SubjectLogonId"))
    if logon_id and logon_id not in {"-", "0x0"}:
        scope = f"{server_name.lower()}:" if server_name else ""
        _append_entity(links, "auth_session", f"logon:{scope}{logon_id.lower()}", logon_id, "context", server_scoped=True)

    return _deduplicate_links(links)


def _append_principal(
    links: list[dict[str, Any]],
    name: str,
    domain: str | None,
    role: str,
    *,
    sid: str | None = None,
    upn: str | None = None,
    email: str | None = None,
    entity_type: str | None = None,
    node: str | None = None,
) -> None:
    if not domain and "\\" in name:
        domain = name.rsplit("\\", 1)[0].strip() or None
    normalized_name = _normalize_principal_name(name)
    entity_type = entity_type or _principal_type(normalized_name)
    domain_part = domain.lower() if domain else "unknown"
    legacy_key = f"{entity_type}:{domain_part}:{normalized_name.lower()}"
    identity = разрешить_субъект(
        sid=sid,
        upn=upn,
        почта=email,
        sam=normalized_name,
        домен=domain,
        узел=node,
    )
    key = identity.ключ or legacy_key
    display = f"{domain}\\{normalized_name}" if domain else normalized_name
    aliases = list(dict.fromkeys([*identity.псевдонимы, legacy_key]))
    _append_entity(
        links,
        entity_type,
        key,
        display,
        role,
        confidence=identity.уверенность,
        attributes={
            "sid": sid,
            "domain": domain,
            "identity_state": identity.состояние,
            "identity_step": identity.ступень,
            "identity_aliases": aliases,
            "identity_reason": identity.причина,
        },
    )


def _append_entity(
    links: list[dict[str, Any]],
    entity_type: str,
    natural_key: str,
    display_name: str,
    link_role: str,
    *,
    confidence: float = 1.0,
    domain_scoped: bool = True,
    server_scoped: bool = False,
    attributes: dict[str, Any] | None = None,
) -> None:
    if link_role not in LINK_ROLES:
        raise ValueError(f"Unsupported event/entity role: {link_role}")
    attributes = attributes or {}
    risk_tier = _infer_risk_tier(entity_type, display_name, attributes)
    attributes = {**attributes, "risk_tier": risk_tier}
    links.append(
        {
            "entity_type": entity_type,
            "natural_key": natural_key,
            "display_name": display_name,
            "link_role": link_role,
            "confidence": confidence,
            "domain_scoped": domain_scoped,
            "server_scoped": server_scoped,
            "attributes": attributes,
            "evidence": {"source": "event_data", "role": link_role},
            "extracted_from": "event_data",
        }
    )


def _principal_type(name: str, *, force_group: bool = False) -> str:
    if force_group:
        return "ad_group"
    clean_name = _normalize_principal_name(name)
    if clean_name.endswith("$"):
        return "ad_computer"
    if clean_name.startswith("S-1-"):
        return "security_principal"
    return "ad_user"


def _normalize_principal_name(value: str) -> str:
    value = value.strip()
    if "," in value and "=" in value:
        first_part = value.split(",", 1)[0]
        if "=" in first_part:
            return first_part.split("=", 1)[1].strip()
    if "\\" in value:
        return value.rsplit("\\", 1)[1].strip()
    return value


def _deduplicate_links(links: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    result = []
    for link in links:
        key = (link["entity_type"], link["natural_key"], link["link_role"])
        if key not in seen:
            result.append(link)
            seen.add(key)
    return result


def _infer_risk_tier(entity_type: str, display_name: str, attributes: dict[str, Any]) -> str:
    name = display_name.lower()
    if entity_type == "asset" and (name.startswith("dc") or "domain controller" in name):
        return "critical"
    if entity_type == "ad_group" and any(group in name for group in PRIVILEGED_GROUP_NAMES):
        return "critical"
    if entity_type in {"service", "scheduled_task", "process"}:
        return "contextual"
    if entity_type in {"ad_user", "ad_computer", "security_principal"}:
        normalized = display_name.lower()
        account = normalized.rsplit("\\", 1)[-1]
        if account.startswith("svc") or account.startswith("service") or "service" in account or account.endswith("$"):
            return "important"
        if "admin" in account or "админ" in account:
            return "important"
    if entity_type == "scheduled_task" and ("\\windows\\" not in name and "googleupdate" not in name):
        return "important"
    return str(attributes.get("risk_tier") or "normal")


def _pick(data: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = data.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

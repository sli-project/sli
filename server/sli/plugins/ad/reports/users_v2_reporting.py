"""Production adapter for the AD Users V1.1 reference report.

The existing ``ad.users`` report remains untouched.  This module projects the
authorized SLI directory read model into the snapshot contract consumed by the
approved standalone reference.  Unsupported source sections remain explicit
``not_collected`` or ``partial`` states; no demo or inferred data is emitted.
"""
from __future__ import annotations

import hashlib
import json
import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping

from server.sli.core.database import query_rows_bounded
from server.sli.plugins.ad.reports.users_reporting import USERS_INPUT_LIMIT, get_users_report
from server.sli.plugins.ad.directory_projection import build_directory_projection

_LOGGER = logging.getLogger(__name__)


CONTRACT_ID = "sli.users-report.v2"
REPORT_KEY = "ad.users.v2"
SNAPSHOT_SCHEMA = "sli.ad-users.snapshot/1.0"


def project_users_v2_exact(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Pure shadow projector for one exact immutable Users V2 payload."""
    return deepcopy(dict(snapshot))


def _iso(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        stamp = value
    else:
        try:
            stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return str(value)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return dict(parsed) if isinstance(parsed, Mapping) else {}
    return {}


def _attributes(value: Any) -> dict[str, Any]:
    raw = _mapping(value)
    nested = raw.get("attributes")
    return dict(nested) if isinstance(nested, Mapping) else raw


def _directory_user_population(*, domain_ids: list[int] | None) -> list[dict[str, Any]]:
    """Return every authorized ``Get-ADUser`` object for the sibling report.

    The protected ``ad.users`` read model excludes sAMAccountName values ending
    in ``$``.  The executable Users V1.1 reference does not, so V2 reads the
    canonical directory section directly without changing the baseline filter.
    Agent snapshots already attest the canonical ad_user type but do not repeat
    the legacy object_class attribute. The caller's authorized domains own scope.
    """
    return _population_from_directory_rows(_directory_user_rows(domain_ids=domain_ids))


def _population_from_directory_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows[:USERS_INPUT_LIMIT]:
        attrs = _attributes(row.get("attributes"))
        result.append(
            {
                "entity_id": int(row["entity_id"]),
                "domain_id": int(row["domain_id"]),
                "display_name": row.get("display_name") or attrs.get("display_name"),
                "natural_key": row.get("natural_key"),
                "observed_at_utc": row.get("observed_at_utc"),
                "ou_path": attrs.get("organizational_unit"),
                "enabled": attrs.get("enabled"),
                "locked_out": attrs.get("locked_out"),
                "account_expiration_utc": attrs.get("account_expires_utc"),
                "created_utc": attrs.get("created_utc") or attrs.get("when_created_utc"),
                "department": attrs.get("department"),
                "title": attrs.get("title"),
                "email": attrs.get("mail") or attrs.get("email"),
                "password_last_set_utc": attrs.get("password_last_set_utc"),
                "password_never_expires": attrs.get("password_never_expires"),
                "last_logon_utc": attrs.get("last_logon_utc"),
                "direct_privileges": [],
            }
        )
    return result


def _directory_user_rows(*, domain_ids: list[int] | None, legacy_assembly: bool = False) -> list[dict[str, Any]]:
    """Read the current canonical population in the caller's authorized scope."""
    clean_domains = sorted({int(value) for value in domain_ids or [] if int(value) > 0})
    if domain_ids is not None and not clean_domains:
        return []
    scope_sql = " and entity.domain_id=any(?)" if clean_domains else ""
    account_sql = " and coalesce(version.attributes_json->'attributes'->>'sam_account_name','') not like '%$'" if legacy_assembly else ""
    params: list[Any] = [clean_domains] if clean_domains else []
    params.append(USERS_INPUT_LIMIT + 1)
    rows = query_rows_bounded(
        f"""/* users_v2_complete_get_aduser_population */
            select entity.id as entity_id,entity.domain_id,entity.display_name,
                   entity.natural_key,version.last_observed_at_utc as observed_at_utc,
                   version.attributes_json as attributes
            from entities_v2_active entity
            join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            join domains report_domain on report_domain.id=entity.domain_id
            join ad_context_entity_versions version
              on version.entity_id=entity.id and version.valid_to_utc is null
             and version.source_section='directory_accounts'
            where entity_type.value='ad_user'{scope_sql}
              and lower(coalesce(version.attributes_json->'attributes'->>'object_class','user'))='user'{account_sql}
            order by entity.domain_id,entity.id limit ?""",
        tuple(params),
        statement_timeout_ms=20_000,
    )
    return rows


def _source_state(status: str, source: str, observed_at: Any, detail: str | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "source": source,
        "value": None,
        "observed_at": _iso(observed_at),
        "detail": detail,
        "error": None,
        "coverage": None,
    }


def _extra_attributes(entity_ids: list[int]) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, str]]]:
    if not entity_ids:
        return {}, {}
    versions = query_rows_bounded(
        """/* users_v2_current_attributes */
           select entity_id,attributes_json
           from ad_context_entity_versions
           where valid_to_utc is null and source_section='directory_accounts'
             and entity_id=any(?)
           order by entity_id""",
        (entity_ids,), statement_timeout_ms=10_000,
    )
    aliases = query_rows_bounded(
        """/* users_v2_stable_aliases */
           select entity_id,alias_type,alias_value
           from ad_context_entity_aliases
           where entity_id=any(?) and alias_type in ('object_guid','object_sid')
           order by entity_id,alias_type""",
        (entity_ids,), statement_timeout_ms=5_000,
    )
    attrs = {int(row["entity_id"]): _attributes(row.get("attributes_json")) for row in versions}
    by_alias: dict[int, dict[str, str]] = {}
    for row in aliases:
        by_alias.setdefault(int(row["entity_id"]), {})[str(row["alias_type"])] = str(row["alias_value"])
    return attrs, by_alias


def _group_reference(raw: Mapping[str, Any]) -> dict[str, Any]:
    entity_id = int(raw.get("group_entity_id") or 0)
    name = str(raw.get("group_name") or entity_id)
    return {
        "id": f"group:{entity_id}",
        "objectGuid": f"entity:{entity_id}",
        "sid": None,
        "name": name,
        "samAccountName": name,
        "distinguishedName": None,
        "canonicalName": None,
        "category": "Security",
        "scope": "not_collected",
        "watchGroup": True,
    }


def _group_reference_from_dn(dn: str) -> dict[str, Any]:
    normalized = str(dn).strip()
    name = normalized.split(",", 1)[0]
    if name.upper().startswith("CN="):
        name = name[3:]
    digest = hashlib.sha256(normalized.casefold().encode("utf-8")).hexdigest()[:20]
    return {
        "id": f"group-dn:{digest}",
        "objectGuid": None,
        "sid": None,
        "name": name or normalized,
        "samAccountName": None,
        "distinguishedName": normalized,
        "canonicalName": None,
        "category": "not_collected",
        "scope": "not_collected",
        "watchGroup": False,
    }


def _values(raw: Any) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, tuple):
        return list(raw)
    return [raw]


def _user(item: Mapping[str, Any], attrs: Mapping[str, Any], aliases: Mapping[str, str], *, group_state: str) -> dict[str, Any]:
    observed = item.get("observed_at_utc")
    groups = [_group_reference(value) for value in item.get("direct_privileges") or []]
    groups.extend(_group_reference_from_dn(str(value)) for value in _values(attrs.get("member_of")) if str(value).strip())
    groups = list({value["id"]: value for value in groups}.values())
    group_detail = "Прямые memberOf и разрешённые privileged_membership связи доступны; nested-граф и primaryGroup пока не разрешаются."
    manager_dn = attrs.get("manager_distinguished_name") or attrs.get("manager")
    manager_name = attrs.get("manager_name")
    manager = {"name": manager_name or manager_dn, "distinguishedName": manager_dn} if manager_dn or manager_name else None
    source_states = {
        "directory": _source_state("observed", "directory_accounts", observed),
        "group_graph": _source_state("partial", "directory_accounts.member_of + privileged_membership", observed, group_detail),
        "exact_last_logon": _source_state("not_collected", "domain controllers", observed, "Точный максимум lastLogon по всем DC не входит в текущий production source pack."),
        "password_expiry": _source_state("not_collected", "msDS-UserPasswordExpiryTimeComputed", observed, "Вычисляемая дата истечения пароля не собирается текущим source pack."),
        "manager_resolution": _source_state("not_collected" if manager_dn else "not_applicable", "manager", observed, "Разрешение DN руководителя не входит в текущий source pack." if manager_dn else None),
    }
    natural_key = str(item.get("natural_key") or "")
    sam = str(attrs.get("sam_account_name") or natural_key.rsplit("\\", 1)[-1] or "")
    entity_id = int(item["entity_id"])
    direct = [{**value, "relation": "direct"} for value in groups]
    return {
        "id": f"user:{entity_id}",
        "entityId": entity_id,
        "objectGuid": aliases.get("object_guid") or f"entity:{entity_id}",
        "sid": aliases.get("object_sid"),
        "displayName": str(item.get("display_name") or sam or entity_id),
        "name": str(item.get("display_name") or sam or entity_id),
        "givenName": attrs.get("given_name"),
        "surname": attrs.get("surname"),
        "samAccountName": sam,
        "userPrincipalName": attrs.get("user_principal_name"),
        "distinguishedName": attrs.get("distinguished_name"),
        "canonicalName": attrs.get("canonical_name"),
        "ou": str(item.get("ou_path") or "Расположение не получено"),
        "enabled": item.get("enabled"),
        "lockedOut": item.get("locked_out"),
        "accountExpirationDate": _iso(item.get("account_expiration_utc")),
        "whenCreated": _iso(item.get("created_utc")),
        "whenChanged": _iso(attrs.get("when_changed_utc") or attrs.get("modified_utc")),
        "department": item.get("department"),
        "title": item.get("title"),
        "company": attrs.get("company"),
        "office": attrs.get("office"),
        "description": attrs.get("description"),
        "employeeID": attrs.get("employee_id"),
        "employeeNumber": attrs.get("employee_number"),
        "manager": manager,
        "mail": item.get("email") or attrs.get("email"),
        "proxyAddresses": list(attrs.get("proxy_addresses") or []),
        "telephoneNumber": attrs.get("telephone_number"),
        "otherTelephones": list(attrs.get("other_telephones") or []),
        "mobile": attrs.get("mobile"),
        "ipPhone": attrs.get("ip_phone"),
        "fax": attrs.get("fax"),
        "streetAddress": attrs.get("street_address"),
        "city": attrs.get("city"),
        "state": attrs.get("state"),
        "postalCode": attrs.get("postal_code"),
        "country": attrs.get("country"),
        "passwordLastSet": _iso(item.get("password_last_set_utc")),
        "passwordExpiry": _iso(attrs.get("password_expiry_utc")),
        "passwordExpired": attrs.get("password_expired"),
        "passwordNeverExpires": item.get("password_never_expires"),
        "passwordNotRequired": attrs.get("password_not_required"),
        "cannotChangePassword": attrs.get("cannot_change_password"),
        "lastLogonTimestamp": _iso(item.get("last_logon_utc")),
        "exactLastLogon": None,
        "lastBadPasswordAttempt": _iso(attrs.get("last_bad_password_attempt_utc")),
        "badPasswordCountAtQueryDc": attrs.get("bad_password_count_at_query_dc") or attrs.get("bad_password_count"),
        "smartcardLogonRequired": attrs.get("smartcard_logon_required"),
        "accountNotDelegated": attrs.get("account_not_delegated"),
        "allowReversiblePasswordEncryption": attrs.get("allow_reversible_password_encryption"),
        "trustedForDelegation": attrs.get("trusted_for_delegation"),
        "trustedToAuthForDelegation": attrs.get("trusted_to_auth_for_delegation"),
        "doesNotRequirePreAuth": attrs.get("does_not_require_preauth"),
        "useDesKeyOnly": attrs.get("use_des_key_only"),
        "adminCount": attrs.get("admin_count"),
        "objectClasses": list(attrs.get("object_classes") or []),
        "servicePrincipalNames": list(attrs.get("service_principal_names") or []),
        "userAccountControl": attrs.get("user_account_control"),
        "msDSSupportedEncryptionTypes": attrs.get("supported_encryption_types"),
        "memberships": {
            "status": "partial",
            "primary": None,
            "direct": direct,
            "effective": direct,
            "paths": [
                {"groupId": value["id"], "relation": "direct", "nodes": [{"id": f"user:{entity_id}", "name": str(item.get("display_name") or sam)}, {"id": value["id"], "name": value["name"]}]}
                for value in direct
            ],
            "unresolved": [],
        },
        "sourceStates": source_states,
        "collectionErrors": [],
    }


def build_users_v2_snapshot(*, domain_ids: list[int] | None) -> dict[str, Any]:
    """Build the current authorized snapshot without changing ``ad.users``."""
    common = {"domain_ids": domain_ids, "limit": USERS_INPUT_LIMIT, "max_page_limit": USERS_INPUT_LIMIT}
    rows = _directory_user_rows(domain_ids=domain_ids)
    # A complete population can serve both assemblies. If capped, the legacy
    # non-$ population may extend past this page; retain its independent read.
    reusable = rows if len(rows) <= USERS_INPUT_LIMIT else None
    active = get_users_report(view="active", _directory_only=True, _directory_rows=reusable, **common)
    merged = {int(item["entity_id"]): dict(item) for item in active.get("items") or []}
    for item in _population_from_directory_rows(rows):
        merged.setdefault(int(item["entity_id"]), item)
    coverage = dict(active.get("coverage") or {})
    projection = build_directory_projection(
        items=[merged[key] for key in sorted(merged)],
        coverage=coverage,
        requested_domain_ids=domain_ids,
    )
    return snapshot_from_directory_projection(projection, coverage=coverage, active=active)


def snapshot_from_directory_projection(
    projection: Mapping[str, Any], *, coverage: Mapping[str, Any], active: Mapping[str, Any]
) -> dict[str, Any]:
    """Shared pure assembly for legacy and exact imported directory inputs."""
    names = {int(row["domain_id"]): row.get("domain_name") for row in coverage.get("domains") or [] if row.get("domain_id")}
    users = [{**user, "domainName": names.get(user.get("domainId"))} for user in projection["users"]]
    groups = list(projection["groups"])
    observed = projection.get("observed_at") or coverage.get("latest_observed_at_utc")
    state = str(active.get("state") or "not_collected")
    collection_status = "failed" if state == "unavailable" else str(projection["collection_status"])
    domain_names = [str(row.get("domain_name")) for row in coverage.get("domains") or [] if row.get("domain_name")]
    return {
        "metadata": {
            "schema_version": SNAPSHOT_SCHEMA,
            "collector_version": "sli/users-v2-production-adapter/2",
            "snapshot_id": f"live:{observed or 'not-collected'}",
            "label": "Текущий серверный снимок SLI",
            "started_at": _iso(observed),
            "completed_at": _iso(observed),
            "observed_at": _iso(observed),
            "query_dc": None,
            "domain_dns": domain_names[0] if len(domain_names) == 1 else ", ".join(domain_names),
            "domain_dn": None,
            "forest_dns": None,
            "search_base": "разрешённая область домена SLI",
            "collection_status": collection_status,
            "user_count": len(users),
            "group_count": len(groups),
            "watch_groups": [group for group in groups if group.get("watchGroup")],
            "sources": list(projection["sources"]),
            "contract_id": CONTRACT_ID,
            "report_key": REPORT_KEY,
            "coverage": coverage,
            "limitations": list(active.get("limitations") or []),
        },
        "groups": groups,
        "users": users,
        "collectionErrors": [],
    }


def load_users_v2_snapshots(*, domain_ids: list[int] | None, include_previous: bool = True) -> dict[str, Any]:
    """Build the current snapshot; load the saved comparison snapshot only on demand.

    Saved ``payload_json`` rows are very large; fetching them for every list
    request exhausted PostgreSQL result memory and broke the whole report. The
    comparison is needed only for the "changes" tab, and its failure must not
    take the current snapshot down with it.
    """
    current = build_users_v2_snapshot(domain_ids=domain_ids)
    current.setdefault("metadata", {})["comparison_role"] = "current_context"
    if not include_previous:
        return {
            "contract_id": CONTRACT_ID, "report_key": REPORT_KEY,
            "state": "available" if current.get("users") else "empty",
            "current": current, "previous": None, "saved_snapshot_count": None,
            "previous_state": "not_requested",
        }
    clean_domains = sorted({int(value) for value in domain_ids or [] if int(value) > 0})
    if domain_ids is not None and not clean_domains:
        # An explicit empty authorized scope must never become an unrestricted read.
        return {
            "contract_id": CONTRACT_ID, "report_key": REPORT_KEY,
            "state": "empty", "current": current, "previous": None,
            "saved_snapshot_count": 0, "previous_state": "none",
        }
    scope_sql = " and domain_id=any(?)" if clean_domains else ""
    try:
        rows = query_rows_bounded(
            f"""/* users_v2_saved_snapshots */
                select snapshot_id,captured_at_utc,payload_json
                from users_report_v2_snapshots
                where contract_id=?{scope_sql}
                order by captured_at_utc desc,snapshot_id desc limit 2""",
            tuple([CONTRACT_ID, *([clean_domains] if clean_domains else [])]),
            statement_timeout_ms=5_000,
        )
    except Exception:
        _LOGGER.warning("users_v2 saved snapshots comparison is unavailable", exc_info=True)
        return {
            "contract_id": CONTRACT_ID, "report_key": REPORT_KEY,
            "state": "available" if current.get("users") else "empty",
            "current": current, "previous": None, "saved_snapshot_count": None,
            "previous_state": "unavailable",
        }
    saved: list[dict[str, Any]] = []
    for row in rows:
        payload = _mapping(row.get("payload_json"))
        if payload:
            payload.setdefault("metadata", {})["saved_snapshot_id"] = int(row["snapshot_id"])
            payload["metadata"]["captured_at"] = _iso(row.get("captured_at_utc"))
            payload["metadata"]["comparison_role"] = "previous_saved_snapshot"
            saved.append(payload)
    current_observed = str((current.get("metadata") or {}).get("observed_at") or "")
    previous = next((item for item in saved if str((item.get("metadata") or {}).get("observed_at") or "") != current_observed), None)
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "state": "available" if current.get("users") else "empty",
        "current": current,
        "previous": previous,
        "saved_snapshot_count": len(saved),
        "previous_state": "loaded" if previous else "none",
    }

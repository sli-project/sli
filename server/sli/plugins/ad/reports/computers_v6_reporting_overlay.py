"""Split out of ``server.sli.plugins.ad.reports.computers_v6_reporting`` (plan 7.2b).

Module-level names of ``computers_v6_reporting`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.plugins.ad.reports.computers_v6_reporting as _src
from server.sli.plugins.ad.reports.computer_security import computer_posture


def _apply_computers_v6_source_overlay(item: dict[str, _src.Any], overlay: _src.Mapping[str, _src.Any]) -> None:
    if "by_domain" in overlay:
        overlay = (overlay.get("by_domain") or {}).get(item.get("domain_id")) or {}
    source_snapshot = dict(overlay.get("source_snapshot") or {})
    item["source_snapshot"] = source_snapshot
    item["snapshot_state"] = source_snapshot.get("state")
    guid = str(item.get("object_guid") or "").strip().lower()
    source = dict((overlay.get("by_guid") or {}).get(guid) or {})
    if not source:
        return
    source_time = _src._utc(source_snapshot.get("completed_at_utc") or source.get("collectedAt"))
    directory_time = _src._utc(item.get("observed_at_utc"))
    if source_time and directory_time and source_time < directory_time:
        item["source_snapshot_older_than_directory"] = True
        return
    source_states = {
        str(name): dict(state) for name, state in dict(source.get("sources") or {}).items()
        if isinstance(state, _src.Mapping)
    }
    addresses = list(dict.fromkeys(str(value) for value in [*(source.get("ipv4s") or []), *(source.get("ipv6s") or [])] if str(value)))
    site = {"state": str(dict(source_states.get("site") or {}).get("status") or "not_collected"), "value": source.get("adSite")}
    item.update({
        "display_name": source.get("name") or item.get("display_name"),
        "dns_host_name": source.get("dnsHostName"), "distinguished_name": source.get("distinguishedName"),
        "canonical_name": source.get("canonicalName"), "location": source.get("location"),
        "managed_by": source.get("managedBy"), "description": source.get("description"),
        "operating_system": source.get("osName"), "operating_system_version": source.get("osVersion"),
        "operating_system_build": source.get("osBuild"), "operating_system_family": source.get("osFamily"),
        "operating_system_service_pack": source.get("servicePack"),
        "ou_path": source.get("ou") or _src.normalize_ou_path(source.get("distinguishedName")),
        "ip_addresses": addresses, "ad_site": site,
        "password_last_set_utc": source.get("passwordLastSet"), "created_utc": source.get("whenCreated"),
        "when_changed_utc": source.get("whenChanged"), "user_account_control": source.get("userAccountControl"),
        "service_principal_names": list(source.get("spns") or []),
        "trusted_for_delegation": source.get("trustedForDelegation"),
        "trusted_to_auth_for_delegation": source.get("trustedToAuthForDelegation"),
        "observed_at_utc": source.get("collectedAt") or source_snapshot.get("completed_at_utc"),
    })
    if isinstance(source.get("enabled"), bool):
        item["enabled"] = source["enabled"]
    item["account_state"] = "enabled" if item.get("enabled") is True else "disabled" if item.get("enabled") is False else "unknown"
    item["network"] = {"addresses": addresses, "address_state": str(dict(source_states.get("dns") or {}).get("status") or "not_collected"), "ad_site": site}
    item.setdefault("activity", {})["last_logon_timestamp"] = dict(source_states.get("last_logon_timestamp") or {})
    item["activity"]["exact_last_logon"] = dict(source_states.get("exact_last_logon") or {})
    item["activity"]["dc_event"] = dict(source_states.get("dc_events") or {})
    item["last_logon_utc"] = source.get("eventLastSeen") or source.get("exactLastLogon") or source.get("lastLogonTimestamp")
    base_type = str(item.get("computer_type") or "unknown")
    source_classification = dict(classification) if isinstance((classification := source.get("classification")), _src.Mapping) else {
        "result": source.get("deviceType") or "unknown",
        "state": "unknown",
    }
    source_result = str(source_classification.get("result") or source_classification.get("deviceType") or source.get("deviceType") or "unknown")
    classified_type = source_result if source_result in {"server", "domain_controller", "workstation"} else "unknown"
    if classified_type == "unknown" and base_type in {"server", "workstation"}:
        item["classification"] = {
            "result": base_type,
            "state": "observed",
            "rule_id": "base_inventory_os_family",
            "evidence": [f"OperatingSystem={item.get('operating_system') or 'не передано'}"],
            "source_observation": source_classification,
        }
        item["computer_type"] = base_type
    else:
        item["classification"] = source_classification
        item["computer_type"] = classified_type
    item["classification"]["role_hint"] = source.get("roleHint")
    role_evidence = source.get("roleEvidence")
    if isinstance(role_evidence, list):
        item["classification"]["role_evidence"] = [str(value) for value in role_evidence if value not in (None, "")]
    elif role_evidence not in (None, ""):
        item["classification"]["role_evidence"] = [str(role_evidence)]
    else:
        item["classification"]["role_evidence"] = []
    item["collection"] = {
        "collected_at": source.get("collectedAt"), "query_dc": source.get("queryDc") or source_snapshot.get("query_dc"),
        "collector_version": source.get("collectorVersion") or source_snapshot.get("collector_version"),
    }
    item.setdefault("evidence", {})["source_states"] = source_states
    item["evidence"]["collection_errors"] = list(source.get("collectionErrors") or [])
    item["evidence"]["activity_sources"] = {
        "replicated_last_logon": dict(source_states.get("last_logon_timestamp") or {}),
        "exact_last_logon": dict(source_states.get("exact_last_logon") or {}),
        "dc_logon_events": dict(source_states.get("dc_events") or {}),
    }
    item["evidence"]["network_sources"] = {"dns_addresses": dict(source_states.get("dns") or {}), "ad_site": dict(source_states.get("site") or {})}
    item["quality_issues"] = _src._source_quality_issues(source, dict(overlay.get("requested") or {}))
    computer_posture(item, {
        "user_account_control": source.get("userAccountControl"),
        "trusted_for_delegation": source.get("trustedForDelegation"),
        "allowed_to_delegate_to": source.get("allowedToDelegateTo"),
        "resource_based_delegation_present": source.get("resourceBasedDelegationPresent"),
        "resource_based_delegation_sids": source.get("resourceBasedDelegationSids"),
        "resource_based_delegation_status": source.get("resourceBasedDelegationStatus"),
        "resource_based_delegation_descriptor_sha256": source.get("resourceBasedDelegationDescriptorSha256"),
        "laps_password_expiration_utc": source.get("lapsPasswordExpiration"),
        "legacy_laps_password_expiration_utc": source.get("legacyLapsPasswordExpiration"),
        "laps_password_expiration_status": source.get("lapsPasswordExpirationStatus"),
        "legacy_laps_password_expiration_status": source.get("legacyLapsPasswordExpirationStatus"),
        "password_last_set_status": source.get("passwordLastSetStatus"),
    }, source_time or directory_time, _src._utc)


def _load_computers_v6_source_overlay(domain_ids: list[int] | None) -> dict[str, _src.Any]:
    domains = [] if domain_ids == [] else _src.query_rows_bounded(
        """/* computers_v6_source_domains */ select id,fqdn from domains
           where (?::bigint[] is null or id=any(?::bigint[])) order by id""",
        (domain_ids, domain_ids),
    )
    if not domains:
        return {"by_domain": {}, "source_snapshot": {"state": "not_collected", "object_count": 0}}
    try:
        connection = _src.connect()
    except Exception as exc:
        return {
            "by_guid": {}, "requested": {},
            "source_snapshot": {"state": "unavailable", "errors": [f"source_store_unavailable:{type(exc).__name__}"], "object_count": 0},
        }
    try:
        try:
            by_domain = {}
            for domain in domains:
                try:
                    value = _source_overlay(_src.load_latest_computers_v6_source_snapshot(
                        connection, domain_fqdn=domain["fqdn"],
                    ))
                except Exception as exc:
                    # A failed domain must not replace another domain's evidence.
                    connection.rollback()
                    value = {"by_guid": {}, "requested": {}, "source_snapshot": {
                        "state": "unavailable", "errors": [f"source_snapshot_unavailable:{type(exc).__name__}"], "object_count": 0,
                    }}
                by_domain[int(domain["id"])] = value
        except Exception as exc:
            return {
                "by_guid": {}, "requested": {},
                "source_snapshot": {"state": "unavailable", "errors": [f"source_snapshot_unavailable:{type(exc).__name__}"], "object_count": 0},
            }
    finally:
        connection.close()
    if len(by_domain) == 1:
        public = next(iter(by_domain.values()))["source_snapshot"]
    else:
        snapshots = [value["source_snapshot"] for value in by_domain.values()]
        public = {"state": "stale" if any(value.get("state") == "stale" for value in snapshots) else
                  "complete" if all(value.get("state") == "complete" for value in snapshots) else "partial",
                  "completed_at_utc": min((value["completed_at_utc"] for value in snapshots if value.get("completed_at_utc")), default=None),
                  "object_count": sum(value.get("object_count", 0) for value in snapshots)}
    return {"by_domain": by_domain, "source_snapshot": public}


def _source_overlay(latest):
    public = _src._source_snapshot_public_state(latest)
    if not latest:
        return {"by_guid": {}, "requested": {}, "source_snapshot": public}
    snapshot = latest.get("snapshot") if isinstance(latest.get("snapshot"), _src.Mapping) else {}
    metadata = snapshot.get("metadata") if isinstance(snapshot.get("metadata"), _src.Mapping) else {}
    requested = {
        str(stage.get("name")): bool(stage.get("requested"))
        for stage in metadata.get("sources") or []
        if isinstance(stage, _src.Mapping) and stage.get("name")
    }
    if str(latest.get("base_inventory_status") or "") != "observed":
        return {"by_guid": {}, "requested": requested, "source_snapshot": public}
    by_guid = {
        str(raw.get("objectGuid")).strip().lower(): dict(raw)
        for raw in snapshot.get("objects") or []
        if isinstance(raw, _src.Mapping) and raw.get("objectGuid")
    }
    return {"by_guid": by_guid, "requested": requested, "source_snapshot": public}


def _source_quality_issues(source: _src.Mapping[str, _src.Any], requested: _src.Mapping[str, bool]) -> list[dict[str, _src.Any]]:
    labels = {
        "source_error": "Ошибка источника", "not_collected": "Не собиралось",
        "not_evaluated": "Не оценивалось", "no_record_or_missing_source": "Запись или значение не найдено",
        "partial": "Частичный результат", "missing_field": "Поле отсутствует",
    }
    categories: dict[str, dict[str, _src.Any]] = {}
    for name, raw_state in dict(source.get("sources") or {}).items():
        if not isinstance(raw_state, _src.Mapping):
            continue
        category = _src.quality_category_for_source_state(str(raw_state.get("status") or ""), requested=bool(requested.get(str(name))))
        if category:
            categories.setdefault(category, {"code": category, "label": labels[category]})
    missing = _src.missing_required_object_fields(source)
    if missing:
        categories["missing_field"] = {"code": "missing_field", "label": labels["missing_field"], "fields": missing}
    return [categories[key] for key in labels if key in categories]


def _source_snapshot_public_state(raw: _src.Mapping[str, _src.Any] | None) -> dict[str, _src.Any]:
    if not raw:
        return {"state": "not_collected", "errors": [], "object_count": 0}
    snapshot = raw.get("snapshot") if isinstance(raw.get("snapshot"), _src.Mapping) else {}
    metadata = snapshot.get("metadata") if isinstance(snapshot.get("metadata"), _src.Mapping) else {}
    base_status = str(raw.get("base_inventory_status") or "failed")
    state = str(raw.get("collection_status") or "failed") if base_status == "observed" else base_status
    completed = metadata.get("completed_at") or raw.get("source_completed_at_utc")
    completed_value = _src._utc(completed)
    stale = bool(completed_value and completed_value < _src.datetime.now(_src.timezone.utc) - _src.timedelta(hours=24))
    return {
        "state": "stale" if stale and base_status == "observed" else state,
        "collection_status": state,
        "stale": stale,
        "source_snapshot_id": raw.get("source_snapshot_id"),
        "completed_at_utc": completed,
        "query_dc": metadata.get("query_dc"),
        "collector_version": metadata.get("collector_version"),
        "object_count": int(raw.get("object_count") or 0),
        "errors": list(metadata.get("errors") or []),
    }

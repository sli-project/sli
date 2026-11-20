"""Split out of ``server.sli.plugins.ad.reports.computers_v6_reporting`` (plan 7.2b).

Module-level names of ``computers_v6_reporting`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import re

import server.sli.plugins.ad.reports.computers_v6_reporting as _src
from server.sli.core.messages import catalog, message
from server.sli.plugins.ad.reports.computer_security import (
    OS_SUPPORT_POLICY_VERSION, computer_posture, unsupported_os,
)


def _item(source: _src.Mapping[str, _src.Any], threshold_days: int) -> dict[str, _src.Any]:
    attrs = _src._attributes(source)
    observed = source.get("observed_at_utc")
    activity = _src.evaluate_computer_activity(attrs, observed)
    observed_value = _src._utc(observed)
    last_logon_value = _src._utc(attrs.get("last_logon_utc"))
    age_days = max(0, (observed_value - last_logon_value).days) if observed_value and last_logon_value else None
    activity = {
        **activity,
        "age_days": age_days,
        "time_semantics": "replicated_lastLogonTimestamp_approximation",
        "source_attribute": "LastLogonDate",
    }
    field_states = _src._field_states(attrs)
    enabled = attrs.get("enabled") if isinstance(attrs.get("enabled"), bool) else None
    identity = source.get("identity") if isinstance(source.get("identity"), _src.Mapping) else {}
    addresses = attrs.get("ip_addresses") if isinstance(attrs.get("ip_addresses"), list) else []
    exact_last_logon = attrs.get("exact_last_logon_utc")
    site = attrs.get("ad_site")
    ad_site_state = {
        "state": "observed" if site else "not_collected",
        "value": site,
    }
    object_guid = identity.get("object_guid") or attrs.get("object_guid")
    object_sid = identity.get("object_sid") or attrs.get("sid")
    result = {
        "entity_id": int(source["entity_id"]),
        "domain_id": int(source["domain_id"]),
        "domain_name": source.get("domain_name"),
        "display_name": str(source.get("display_name") or source.get("natural_key") or source["entity_id"]),
        "natural_key": str(source.get("natural_key") or ""),
        "object_guid": object_guid,
        "object_sid": object_sid,
        "identity": {
            "object_guid": object_guid,
            "object_sid": object_sid,
        },
        "dns_host_name": attrs.get("dns_host_name"),
        "distinguished_name": attrs.get("distinguished_name"),
        "canonical_name": attrs.get("canonical_name"),
        "location": attrs.get("location"),
        "managed_by": attrs.get("managed_by"),
        "description": attrs.get("description"),
        "enabled": enabled,
        "account_state": "enabled" if enabled is True else "disabled" if enabled is False else "unknown",
        "computer_type": _src.classify_computer_type(attrs.get("operating_system")),
        "activity_state": activity["state"],
        "activity": activity,
        "last_logon_utc": attrs.get("last_logon_utc"),
        "operating_system": attrs.get("operating_system"),
        "operating_system_version": attrs.get("operating_system_version"),
        "operating_system_family": _src._operating_system_family(attrs.get("operating_system")),
        "operating_system_service_pack": attrs.get("operating_system_service_pack"),
        "ou_path": _src.normalize_ou_path(attrs.get("distinguished_name")),
        "ip_addresses": addresses,
        "ad_site": ad_site_state,
        "network": {
            "addresses": addresses,
            "address_state": "observed" if addresses else "not_collected",
            "ad_site": ad_site_state,
        },
        "password_last_set_utc": attrs.get("password_last_set_utc"),
        "created_utc": attrs.get("created_utc"),
        "when_changed_utc": attrs.get("when_changed_utc"),
        "user_account_control": attrs.get("user_account_control"),
        "service_principal_names": attrs.get("service_principal_names") if isinstance(attrs.get("service_principal_names"), list) else [],
        "trusted_for_delegation": attrs.get("trusted_for_delegation"),
        "trusted_to_auth_for_delegation": attrs.get("trusted_to_auth_for_delegation"),
        "observed_at_utc": _src._iso(observed),
        "evidence": {"attribute_states": field_states},
        "quality_issues": _src._quality_issues(attrs, field_states),
        "semantic_findings": [],
    }
    result["activity"] = {
        **result["activity"],
        "last_logon_timestamp": {
            "state": "observed" if attrs.get("last_logon_utc") else "missing_in_source",
            "value": attrs.get("last_logon_utc"),
            "semantics": "replicated_lastLogonTimestamp_approximation",
        },
        "exact_last_logon": {
            "state": "observed" if exact_last_logon else "not_collected",
            "value": exact_last_logon,
        },
        "dc_event": {"state": "not_collected", "value": None},
    }
    result["evidence"]["activity_sources"] = {
        "replicated_last_logon": result["activity"]["last_logon_timestamp"],
        "exact_last_logon": result["activity"]["exact_last_logon"],
        "dc_logon_events": result["activity"]["dc_event"],
    }
    result["evidence"]["network_sources"] = {
        "dns_addresses": {
            "state": "observed" if addresses else "not_collected",
            "values": addresses,
        },
        "ad_site": ad_site_state,
    }
    computer_posture(result, attrs, observed_value, _src._utc)
    result["reasons"] = _src._attention_reasons(result, threshold_days)
    return result


def _attention_reasons(
    item: _src.Mapping[str, _src.Any],
    threshold_days: int,
) -> list[dict[str, _src.Any]]:
    reasons: list[dict[str, _src.Any]] = []
    evaluated = _src._utc(item.get("qualification_observed_at_utc") or item.get("observed_at_utc"))
    support_end = unsupported_os(item.get("operating_system"), item.get("operating_system_version"), evaluated)
    if support_end:
        reason = _src._reason(
            "unsupported_os", "ОС без поддержки",
            f"{item.get('operating_system')}; окончание расширенной поддержки Microsoft: {support_end}.",
            "Дата оценки позже даты окончания обычной расширенной поддержки Microsoft.",
            "ОС без поддержки Microsoft требует проверки и плана обновления.",
            "Строка ОС в AD не подтверждает патчи, редакцию или право на ESU; специальные редакции требуют отдельной оценки.",
            "Проверить редакцию и ESU; запланировать обновление или согласованное исключение.",
            presentation_params={"operating_system": item.get("operating_system"), "support_end_date": support_end},
        )
        reason.update(support_end_date=support_end, operating_system=item.get("operating_system"),
                      policy_version=OS_SUPPORT_POLICY_VERSION)
        reasons.append(reason)
    if (item.get("delegation") or {}).get("unconstrained") is True:
        reasons.append(_src._reason(
            "unconstrained_delegation", "Неограниченное делегирование",
            "В userAccountControl установлен TRUSTED_FOR_DELEGATION.",
            "Установлен бит 524288.", "Компьютеру разрешено неограниченное делегирование.",
            "Флаг не доказывает использование делегирования; для контроллеров домена может быть штатным.",
            "Проверить назначение и необходимость делегирования.",
        ))
    if (item.get("laps") or {}).get("state") == "expired":
        reason = _src._reason(
            "laps_expired", "Срок метаданных LAPS истёк",
            f"Плановый срок: {(item.get('laps') or {}).get('expiration_utc')}.",
            "Срок LAPS раньше времени снимка.", "Требуется проверить обработку политики LAPS.",
            "Метаданные не доказывают наличие пароля или успешную ротацию; пароль не читается.",
            "Проверить применение LAPS на компьютере и права чтения метаданных.",
            presentation_params={"expiration_utc": str((item.get("laps") or {}).get("expiration_utc"))},
        )
        reason["expiration_utc"] = (item.get("laps") or {}).get("expiration_utc")
        reasons.append(reason)
    quality_codes = {issue["code"] for issue in item.get("quality_issues") or []}
    if quality_codes.intersection({"source_failed", "source_error"}):
        reasons.append(_src._reason(
            "source_error", "Ошибка источника", "Один или несколько обязательных атрибутов имеют состояние ошибки.",
            "Хотя бы один фактически запрошенный источник имеет состояние failed, access_denied или parse_error.",
            "Данные объекта получены с явной ошибкой источника.",
            "Ошибка источника не доказывает неисправность или небезопасность устройства.",
            "Проверить указанный источник и повторить соответствующий этап сбора.",
        ))
    if item.get("computer_type") == "unknown":
        reasons.append(_src._reason(
            "unknown_type", "Тип объекта не определён", "Наблюдаемая ОС не позволяет определить тип.",
            "Ни одно заданное правило не позволило однозначно отнести объект к ПК или серверу.",
            "Тип объекта определить нельзя.",
            "Это не означает, что объект не является реальным компьютером или сервером.",
            "Проверить ОС и классификационные evidence.",
        ))
    activity = dict(item.get("activity") or {})
    if item.get("enabled") is True and activity.get("age_days") is not None and int(activity["age_days"]) > threshold_days:
        age = activity.get("age_days")
        reasons.append(_src._reason(
            "stale_activity", f"Активность старше {threshold_days} дней",
            f"Последнее приблизительное AD-наблюдение: {item.get('last_logon_utc') or 'нет'}; возраст: {age if age is not None else '?'} дней.",
            f"Разница строго больше выбранного порога {threshold_days} дней, а учётная запись включена в AD.",
            f"Последнее доступное AD-наблюдение старше {threshold_days} дней.",
            "lastLogonTimestamp является приблизительным реплицируемым атрибутом и не подтверждает физическое состояние устройства.",
            "Сопоставить с назначением объекта; решение об отключении или удалении принимает человек.",
            threshold_days=threshold_days,
            presentation_params={"age_days": age, "last_logon_utc": item.get("last_logon_utc") or ""},
        ))
    elif item.get("enabled") is True and activity.get("age_days") is None:
        reasons.append(_src._reason(
            "unavailable_activity", "Нет доступной даты активности", "Доступная дата AD-наблюдения отсутствует.",
            "Источник не дал дату наблюдения для включённой в AD учётной записи.", "Дату последней активности определить нельзя.",
            "Отсутствие даты не доказывает отсутствие активности устройства.",
            "Проверить полноту directory_accounts и источник LastLogonDate.",
        ))
    evidence = item.get("evidence") or {}
    source_states = evidence.get("source_states") or {}
    os_source_state = source_states.get("os")
    os_state = (
        str((os_source_state or {}).get("status") or "unknown").strip().lower()
        if os_source_state is not None
        else _src._state_name((evidence.get("attribute_states") or {}).get("operating_system"))
    )
    if not item.get("operating_system") or os_state not in {"observed", "present"}:
        reasons.append(_src._reason(
            "unknown_os", "Операционная система не определена", "OperatingSystem отсутствует в текущем evidence.",
            "Название ОС отсутствует либо источник поля не имеет наблюдаемого значения.",
            "Операционную систему по текущему снимку определить нельзя.",
            "Это не доказывает отсутствие ОС на устройстве.",
            "Проверить атрибут OperatingSystem и полноту directory_accounts.",
        ))
    return reasons


def _reason(
    code: str,
    label: str,
    observed: str,
    condition: str,
    qualification: str,
    limitation: str,
    next_action: str,
    *,
    source_sections: list[str] | None = None,
    threshold_days: int | None = None,
    presentation_params: _src.Mapping[str, str | int | float] | None = None,
) -> dict[str, _src.Any]:
    reason = {
        "code": code,
        "family": code,
        "label": label,
        "rule_version": 1,
        "observed": observed,
        "condition": condition,
        "qualification": qualification,
        "limitation": limitation,
        "next_action": next_action,
        "source_sections": source_sections or ["directory_accounts"],
        "threshold_days": threshold_days,
        "requires_human_review": True,
    }
    # Only vocabulary produced here is presentation. Evidence, source sections,
    # identifiers and unknown reasons are not translated by string matching.
    if code in _src.REASON_CATALOG:
        params = {**(presentation_params or {}), "threshold_days": threshold_days}
        envelopes = {}
        for field in ("label", "observed", "condition", "qualification", "limitation", "next_action"):
            key = f"reports.v2.ad.computers.v6.{('reasons.' + code) if field == 'label' else ('security.' + code + '.' + field)}"
            if code == "stale_activity" and field == "observed" and not params.get("last_logon_utc"):
                key += "_missing_date"
            if key not in catalog("ru"):
                continue
            names = set(re.findall(r"\{(\w+)\}", catalog("ru")[key]))
            if any(not isinstance(params.get(name), (str, int, float)) for name in names):
                continue
            envelopes[field] = message(key, {name: params[name] for name in sorted(names)})
        if envelopes:
            reason["presentation_messages"] = envelopes
    return reason


def _quality_issues(attrs: _src.Mapping[str, _src.Any], field_states: _src.Mapping[str, _src.Mapping[str, _src.Any]]) -> list[dict[str, _src.Any]]:
    issues: list[dict[str, _src.Any]] = []
    states = {_src._state_name(value) for value in field_states.values()}
    if states.intersection(_src.FAILURE_STATES):
        issues.append({"code": "source_failed", "label": "Ошибка источника"})
    if "not_collected" in states:
        issues.append({"code": "not_collected", "label": "Не собиралось"})
    if "not_evaluated" in states:
        issues.append({"code": "not_evaluated", "label": "Не оценивалось"})
    required = ("enabled", "operating_system", "last_logon_utc")
    required_states = {_src._state_name(field_states.get(name)) for name in required}
    if required_states.intersection(_src.MISSING_STATES):
        issues.append({"code": "no_record", "label": "Запись или значение не найдено"})
    if "partial" in states:
        issues.append({"code": "partial", "label": "Частичный результат"})
    missing = [name for name in required if attrs.get(name) in (None, "")]
    if missing:
        issues.append({"code": "missing_field", "label": "Поле отсутствует", "fields": missing})
    return issues


def _coverage(domain_ids: list[int] | None) -> dict[str, _src.Any]:
    scope_sql = " and domain.id=any(?)" if domain_ids else ""
    rows = [] if domain_ids == [] else _src.query_rows_bounded(
        f"""/* computers_v6_coverage */
            with expected_domains as (
                select domain.id as domain_id,domain.fqdn as domain_name
                from domains domain
                where true{scope_sql}
            ), latest_section as (
                select distinct on (run.domain_id) run.domain_id,run.run_id,
                       run.status as run_status,section.status as section_status,
                       section.record_count,run.observed_at_utc
                from ad_context_runs run
                join expected_domains expected on expected.domain_id=run.domain_id
                join ad_context_sections section on section.run_id=run.run_id
                where section.section_name='directory_accounts'
                order by run.domain_id,run.observed_at_utc desc,run.created_at desc,run.run_id desc
            )
            select expected.domain_id,expected.domain_name,latest.run_id,latest.run_status,
                   latest.section_status,latest.record_count,latest.observed_at_utc
            from expected_domains expected
            left join latest_section latest on latest.domain_id=expected.domain_id
            order by expected.domain_id""",
        tuple([domain_ids] if domain_ids else []),
        statement_timeout_ms=3000,
    )
    count = len(rows)
    complete = sum(row.get("run_status") == "completed" and row.get("section_status") == "complete" for row in rows)
    failed = sum(row.get("run_status") in {"failed", "cancelled"} or row.get("section_status") == "failed" for row in rows)
    partial = sum(row.get("run_status") == "partial" or row.get("section_status") == "partial" for row in rows)
    skipped = count - complete - failed - partial
    observed = [_src._utc(row.get("observed_at_utc")) for row in rows]
    observed = [value for value in observed if value is not None]
    stale = sum(
        _src._utc(row.get("observed_at_utc")) is None
        or _src._utc(row.get("observed_at_utc")) < _src.datetime.now(_src.timezone.utc) - _src.timedelta(hours=24)
        for row in rows
    )
    if not count or skipped == count:
        state = "not_collected"
    elif failed == count:
        state = "failed"
    elif complete == count:
        state = "stale" if stale else "complete"
    else:
        state = "partial"
    return {
        "state": state,
        "domain_count": count,
        "complete_domain_count": complete,
        "partial_domain_count": partial,
        "failed_domain_count": failed,
        "skipped_domain_count": skipped,
        "stale_domain_count": stale,
        "directory_record_count": sum(int(row.get("record_count") or 0) for row in rows),
        "latest_observed_at_utc": max(observed).isoformat() if observed else None,
        "domains": [{key: _src._iso(value) for key, value in dict(row).items()} for row in rows],
    }


def _requalify_computers_v6_item(item: dict[str, _src.Any], threshold_days: int) -> None:
    source_snapshot = item.get("source_snapshot") or {}
    qualification_observed = (
        (source_snapshot.get("completed_at_utc") if not item.get("source_snapshot_older_than_directory") else None)
        or item.get("observed_at_utc")
    )
    observed_value = _src._utc(qualification_observed)
    last_observed = _src._utc(item.get("last_logon_utc"))
    item["qualification_observed_at_utc"] = _src._iso(qualification_observed)
    item.setdefault("activity", {})["age_days"] = (
        max(0, (observed_value - last_observed).days)
        if observed_value and last_observed
        else None
    )
    age = item["activity"]["age_days"]
    item["activity_state"] = ("not_applicable" if item.get("enabled") is not True else
                              "missing" if age is None else "stale" if age > threshold_days else "recent")
    item["activity"]["state"] = item["activity_state"]
    item["activity"].setdefault("evidence", {})["threshold_days"] = threshold_days
    item["reasons"] = _src._attention_reasons(item, threshold_days)

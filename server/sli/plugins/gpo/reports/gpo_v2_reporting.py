from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from typing import Any, Iterable, Mapping

from server.sli.sources.gpo_v2_source import canonical_snapshot, validate_snapshot


HARD_FAILURE_STATES = frozenset({"failed", "access_denied", "parse_error"})
REASON_ORDER = (
    "source_failed",
    "source_unverified",
    "version_mismatch",
    "gpt_unavailable",
    "unresolved_link",
    "unresolved_wmi",
    "all_settings_disabled",
    "unlinked",
    "empty_enabled_side",
    "stale_modified",
)
REASON_RANK = {code: index + 1 for index, code in enumerate(REASON_ORDER)}
REASON_CATEGORIES = {code: "deviation" if code == "version_mismatch" else "assignment" if code in {
    "all_settings_disabled", "unlinked", "empty_enabled_side", "stale_modified"} else "unverified" for code in REASON_ORDER}
PRIORITIES = {"deviation": "high", "unverified": "medium", "assignment": "low"}
SOURCE_LABELS = {"sysvol_gpt": "SYSVOL / GPT.INI"}
REASON_TITLES = {
    "source_failed": "Ошибка обязательного источника",
    "source_unverified": "Обязательный источник не подтверждён",
    "version_mismatch": "Версии AD/SYSVOL различаются",
    "gpt_unavailable": "GPT недоступен",
    "unresolved_link": "Ссылка не разрешена",
    "unresolved_wmi": "WMI-фильтр не разрешён",
    "all_settings_disabled": "Обе части GPO отключены",
    "unlinked": "Связи не наблюдались",
    "empty_enabled_side": "Включённая часть без настроек",
    "stale_modified": "Изменена ранее выбранного срока",
}
REPORT_BOUNDARIES = {
    "not_rsop": True,
    "deletion_claim_allowed": False,
}


def project_gpo_v2_exact(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Pure exact-source boundary projector; active pair loading is unchanged."""
    return deepcopy(dict(snapshot))


def _reason(
    code: str,
    fact: str,
    condition: str,
    qualification: str,
    limitation: str,
    next_action: str,
) -> dict[str, Any]:
    return {
        "code": code,
        "rank": REASON_RANK[code],
        "category": REASON_CATEGORIES[code],
        "priority": PRIORITIES[REASON_CATEGORIES[code]],
        "title": REASON_TITLES[code],
        "fact": fact,
        "condition": condition,
        "qualification": qualification,
        "limitation": limitation,
        "next": next_action,
        "next_action": next_action,
    }


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _days_between(later: Any, earlier: Any) -> int | None:
    if not later or not earlier:
        return None
    try:
        later_dt = datetime.fromisoformat(str(later).replace("Z", "+00:00"))
        earlier_dt = datetime.fromisoformat(str(earlier).replace("Z", "+00:00"))
    except ValueError:
        return None
    if later_dt.tzinfo is None:
        later_dt = later_dt.replace(tzinfo=timezone.utc)
    if earlier_dt.tzinfo is None:
        earlier_dt = earlier_dt.replace(tzinfo=timezone.utc)
    return int((later_dt - earlier_dt).total_seconds() // 86_400)


def attention_reasons(gpo: Mapping[str, Any], *, snapshot: Mapping[str, Any], stale_days: int = 0) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    source_states = gpo.get("source_states") or {}
    failures = [
        (name, state)
        for name, state in source_states.items()
        if isinstance(state, Mapping) and state.get("status") in HARD_FAILURE_STATES
    ]
    if failures:
        out.append(
            _reason(
                "source_failed",
                "; ".join(f"{SOURCE_LABELS.get(name, name)}: {state.get('status')}" for name, state in failures),
                "Хотя бы один обязательный источник завершился failed/access_denied/parse_error",
                "Часть сведений по GPO не подтверждена источником",
                "Это не доказывает неисправность или неприменимость самой политики",
                "Проверить ошибку конкретного источника и повторить только чтение",
            )
        )
    unverified = [name for name, state in source_states.items()
                  if name in {"directory", "links", "report", "permissions", "sysvol_gpt"}
                  and isinstance(state, Mapping) and state.get("status") not in {"observed", *HARD_FAILURE_STATES}]
    if unverified:
        out.append(_reason(
            "source_unverified", "; ".join(SOURCE_LABELS.get(name, name) for name in unverified),
            "Обязательный источник не дал полного наблюдения",
            "Часть сведений по GPO не подтверждена источником",
            "Это не доказывает отклонение в самой политике",
            "Проверить полноту и область сбора указанных источников",
        ))
    mismatch_facts: list[str] = []
    for side in ("computer", "user"):
        side_state = gpo.get(side) or {}
        directory_version = _number(side_state.get("directory_version"))
        sysvol_version = _number(side_state.get("sysvol_version"))
        if directory_version is not None and sysvol_version is not None and directory_version != sysvol_version:
            mismatch_facts.append(f"{side}: AD {side_state.get('directory_version')}, SYSVOL {side_state.get('sysvol_version')}")
    if mismatch_facts:
        out.append(
            _reason(
                "version_mismatch",
                "; ".join(mismatch_facts),
                "Наблюдаемые версии одной стороны различаются",
                "На опрошенном DC/UNC есть расхождение версии GPC и GPT",
                "Без опроса всех DC нельзя локализовать репликацию и определить глобальное состояние",
                "Сверить ту же GPO на других DC и состояние AD/DFSR репликации",
            )
        )
    gpt = gpo.get("gpt") or {}
    if gpt.get("status") in {"failed", "access_denied", "no_record", "missing_in_source"}:
        out.append(
            _reason(
                "gpt_unavailable",
                f"{gpt.get('status')}: {gpt.get('detail') or 'GPT.INI не прочитан'}",
                "Каталог GPT или GPT.INI не удалось прочитать",
                "SYSVOL-часть GPO не подтверждена текущим снимком",
                "Это не доказывает отсутствие GPT на других DC",
                "Проверить gPCFileSysPath и доступность пути на выбранном DC",
            )
        )
    unresolved_links = gpo.get("unresolved_link_references") or []
    if unresolved_links:
        out.append(
            _reason(
                "unresolved_link",
                "; ".join(str(item.get("raw_gpc_dn", "")) for item in unresolved_links),
                "gPLink содержит ссылку, которую не удалось связать с собранным GPO",
                "Топология ссылок содержит неразрешённую запись",
                "Причина может быть в неполном сборе, репликации или устаревшей ссылке",
                "Проверить raw gPLink и наличие GPC DN",
            )
        )
    wmi_state = source_states.get("wmi_filter") or {}
    if gpo.get("wmi_filter_id") and wmi_state.get("status") in {"no_record", "failed", "partial"}:
        out.append(
            _reason(
                "unresolved_wmi",
                str(wmi_state.get("detail") or gpo.get("wmi_filter_id")),
                "gPCWQLFilter задан, но объект фильтра не разрешён",
                "Условие WMI для этой GPO не подтверждено",
                "Нельзя вычислить применимость политики к клиенту",
                "Проверить объект msWMI-Som и значение gPCWQLFilter",
            )
        )
    if gpo.get("gpo_status") == "AllSettingsDisabled":
        out.append(
            _reason(
                "all_settings_disabled",
                "GpoStatus = AllSettingsDisabled",
                "Компьютерная и пользовательская части отключены",
                "Содержимое GPO не обрабатывается как обычная включённая политика",
                "Ссылки и ACL при этом могут сохраняться",
                "Подтвердить, что отключение обеих частей является ожидаемым решением владельца",
            )
        )
    root_links_observed = (snapshot.get("source_states") or {}).get("links", {}).get("status") == "observed"
    if not (gpo.get("link_ids") or []) and root_links_observed and source_states.get("links", {}).get("status") == "observed":
        out.append(
            _reason(
                "unlinked",
                "0 наблюдаемых ссылок при source links = observed",
                "Ни одна поддерживаемая site/domain/OU ссылка не связана с GPO",
                "GPO не имеет наблюдаемых доменных ссылок в снимке",
                "Это не проверяет локальные GPO, Starter GPO и внешние домены",
                "Подтвердить назначение GPO и необходимость хранения",
            )
        )
    empty_sides: list[str] = []
    if source_states.get("report", {}).get("status") == "observed":
        if (gpo.get("computer") or {}).get("enabled") and _number((gpo.get("computer") or {}).get("settings_count")) == 0:
            empty_sides.append("Computer")
        if (gpo.get("user") or {}).get("enabled") and _number((gpo.get("user") or {}).get("settings_count")) == 0:
            empty_sides.append("User")
    if empty_sides:
        out.append(
            _reason(
                "empty_enabled_side",
                f"{' и '.join(empty_sides)}: 0 нормализованных настроек",
                "Включённая часть не содержит записей после успешной нормализации XML",
                "Включённая часть выглядит пустой в поддерживаемом каталоге настроек",
                "Некоторые расширения могут не нормализоваться универсальным парсером",
                "Открыть исходный XML Get-GPOReport и проверить расширения",
            )
        )
    age = _days_between(snapshot.get("observed_at"), gpo.get("modification_time"))
    if stale_days > 0 and age is not None and age >= stale_days:
        out.append(
            _reason(
                "stale_modified",
                f"{gpo.get('modification_time')}; {age} дней",
                f"Дата изменения старше выбранного пользователем периода {stale_days} дней",
                "GPO попала в пользовательский временной срез",
                "Возраст изменения не является нормативом, риском или доказательством неиспользования",
                "Проверить назначение, ссылки и фактические процессы изменения",
            )
        )
    for item in out:
        if item["code"] == "version_mismatch" and any(
            source_states.get(source, {}).get("status") != "observed" for source in ("report", "sysvol_gpt")
        ):
            item.update(category="unverified", priority="medium")
    return sorted(out, key=lambda item: (tuple(PRIORITIES).index(item["category"]), item["rank"], item["code"]))


def _signatures(snapshot: Mapping[str, Any], gpo_id: str) -> dict[str, str]:
    links = sorted(
        [item.get("scope_id"), item.get("enabled"), item.get("enforced"), item.get("order")]
        for item in snapshot.get("links", [])
        if item.get("gpo_id") == gpo_id
    )
    settings = sorted(
        item.get("fingerprint")
        or "|".join(str(item.get(key, "")) for key in ("side", "extension", "path", "setting_name", "value_display"))
        for item in snapshot.get("settings", [])
        if item.get("gpo_id") == gpo_id
    )
    permissions = sorted(
        [item.get("trustee_sid"), item.get("permission")]
        for item in snapshot.get("permissions", [])
        if item.get("gpo_id") == gpo_id
    )
    return {
        "links": json.dumps(links, ensure_ascii=False, separators=(",", ":")),
        "settings": json.dumps(settings, ensure_ascii=False, separators=(",", ":")),
        "permissions": json.dumps(permissions, ensure_ascii=False, separators=(",", ":")),
    }


def _source_status_signature(gpo: Mapping[str, Any]) -> str:
    statuses = {name: state.get("status") for name, state in (gpo.get("source_states") or {}).items()}
    return json.dumps(statuses, ensure_ascii=False, separators=(",", ":"))


def compare_snapshots(current: Mapping[str, Any], previous: Mapping[str, Any] | None) -> dict[str, Any]:
    if previous is None:
        return {"state": "not_collected", "items": [], "change_count": 0, "deletion_claim_allowed": False}
    current_map = {item["id"]: item for item in current.get("gpos", [])}
    previous_map = {item["id"]: item for item in previous.get("gpos", [])}
    rows: list[dict[str, Any]] = []
    for gpo_id in dict.fromkeys([*current_map, *previous_map]):
        now = current_map.get(gpo_id)
        before = previous_map.get(gpo_id)
        kinds: list[str] = []
        details: list[str] = []
        if before is None:
            kinds.append("new_gpo")
            details.append("Объект присутствует только в текущем снимке")
        elif now is None:
            kinds.append("absent_current")
            details.append("Объект присутствовал ранее и отсутствует сейчас; причина не установлена")
        else:
            if now.get("display_name") != before.get("display_name"):
                kinds.append("name_changed")
                details.append(f"Имя: {before.get('display_name')} → {now.get('display_name')}")
            if now.get("gpo_status") != before.get("gpo_status"):
                kinds.append("status_changed")
                details.append(f"Status: {before.get('gpo_status')} → {now.get('gpo_status')}")
            if (now.get("owner") or {}).get("name", "") != (before.get("owner") or {}).get("name", ""):
                kinds.append("owner_changed")
                details.append(f"Owner: {(before.get('owner') or {}).get('name') or '—'} → {(now.get('owner') or {}).get('name') or '—'}")
            if now.get("modification_time") != before.get("modification_time"):
                kinds.append("modified_time_changed")
                details.append("Изменилось наблюдаемое время изменения")
            now_versions = [
                (now.get(side) or {}).get(key)
                for side in ("computer", "user")
                for key in ("directory_version", "sysvol_version")
            ]
            old_versions = [
                (before.get(side) or {}).get(key)
                for side in ("computer", "user")
                for key in ("directory_version", "sysvol_version")
            ]
            if now_versions != old_versions:
                kinds.append("versions_changed")
                details.append("Изменились наблюдаемые версии Computer/User")
            now_signatures = _signatures(current, gpo_id)
            old_signatures = _signatures(previous, gpo_id)
            for field, kind, detail in (
                ("links", "links_changed", "Изменился набор, порядок или состояние ссылок"),
                ("settings", "settings_changed", "Изменился нормализованный набор настроек"),
                ("permissions", "permissions_changed", "Изменились наблюдаемые уровни разрешений"),
            ):
                if now_signatures[field] != old_signatures[field]:
                    kinds.append(kind)
                    details.append(detail)
            if (now.get("wmi_filter_id") or None) != (before.get("wmi_filter_id") or None):
                kinds.append("wmi_changed")
                details.append("Изменилась ссылка на WMI-фильтр")
            if _source_status_signature(now) != _source_status_signature(before):
                kinds.append("quality_changed")
                details.append("Изменилось состояние одного или нескольких источников")
        if kinds:
            base = now or before or {}
            rows.append(
                {
                    "_kind": "change",
                    "row_id": f"change:{gpo_id}",
                    "gpo_id": gpo_id,
                    "display_name": base.get("display_name"),
                    "guid": base.get("guid"),
                    "change_kinds": kinds,
                    "change_summary": "; ".join(details),
                    "details": details,
                    "current": now,
                    "previous": before,
                    "current_time": current.get("observed_at"),
                    "previous_time": previous.get("observed_at"),
                    "deletion_claim_allowed": False,
                }
            )
    state = "partial" if current.get("collection_status") == "partial" or previous.get("collection_status") == "partial" else "available"
    return {"state": state, "items": rows, "change_count": len(rows), "deletion_claim_allowed": False}


def _source_error_text(error: Any) -> str:
    if not error:
        return ""
    if isinstance(error, str):
        return error
    if isinstance(error, Mapping):
        return str(error.get("message") or json.dumps(error, ensure_ascii=False))
    return str(error)


def quality_rows(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def append(entity_type: str, entity_id: str, entity_name: str, source: str, state: Any) -> None:
        if not isinstance(state, Mapping) or state.get("status") in {"observed", "not_applicable"}:
            return
        rows.append(
            {
                "_kind": "quality",
                "row_id": f"quality:{len(rows)}",
                "entity_type": entity_type,
                "entity_id": entity_id,
                "entity_name": entity_name,
                "source": source,
                "status": state.get("status"),
                "detail": state.get("detail") or _source_error_text(state.get("error")) or "Источник не дал полного наблюдения",
                "observed_at": state.get("observed_at"),
                "raw": state,
            }
        )

    for name, state in (snapshot.get("source_states") or {}).items():
        append("snapshot", "snapshot", "Снимок", name, state)
    for gpo in snapshot.get("gpos", []):
        for name, state in (gpo.get("source_states") or {}).items():
            append("gpo", gpo["id"], gpo.get("display_name", ""), name, state)
    for scope in snapshot.get("scopes", []):
        for name, state in (scope.get("source_states") or {}).items():
            append("scope", scope["id"], scope.get("name", ""), name, state)
    for link in snapshot.get("links", []):
        append("link", link["id"], f"{link.get('gpo_name')} → {link.get('scope_name')}", "link", link.get("source_state"))
    for setting in snapshot.get("settings", []):
        append("setting", setting["id"], f"{setting.get('gpo_name')}: {setting.get('setting_name')}", "setting_xml", setting.get("source_state"))
    for permission in snapshot.get("permissions", []):
        append("permission", permission["id"], f"{permission.get('gpo_name')}: {permission.get('trustee_name')}", "permission", permission.get("source_state"))
    for wmi in snapshot.get("wmi_filters", []):
        append("wmi", wmi["id"], wmi.get("name", ""), "wmi_filter", wmi.get("source_state"))
    return rows


def _search(rows: Iterable[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    normalized = query.strip().casefold()
    if not normalized:
        return list(rows)
    return [row for row in rows if normalized in json.dumps(row, ensure_ascii=False, default=str).casefold()]


def filter_snapshot_view(
    snapshot: Mapping[str, Any],
    view: str,
    *,
    query: str = "",
    stale_days: int = 0,
    limit: int = 10_000,
) -> dict[str, Any]:
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > 10_000:
        raise ValueError("invalid_gpo_v2_limit")
    if view in {"attention", "unverified", "assignment", "all", "linked", "unlinked"}:
        rows = []
        links_observed = (snapshot.get("source_states") or {}).get("links", {}).get("status") == "observed"
        if view == "unlinked" and not links_observed:
            return {"state": "not_evaluated", "items": [], "has_more": False, "total": 0}
        for gpo in snapshot.get("gpos", []):
            row = dict(gpo)
            row["reasons"] = attention_reasons(gpo, snapshot=snapshot, stale_days=stale_days)
            category = "deviation" if view == "attention" else view
            if view in {"attention", "unverified", "assignment"} and not any(reason["category"] == category for reason in row["reasons"]):
                continue
            if view == "linked" and not (gpo.get("link_ids") or []):
                continue
            if view == "unlinked" and ((gpo.get("link_ids") or []) or not links_observed or (gpo.get("source_states") or {}).get("links", {}).get("status") != "observed"):
                continue
            rows.append(row)
        rows = _search(rows, query)
        rows.sort(key=lambda row: min((tuple(PRIORITIES).index(reason["category"]) * 100 + reason["rank"] for reason in row["reasons"]), default=1000))
        return {
            "state": "partial" if len(rows) > limit else "available",
            "items": rows[:limit],
            "has_more": len(rows) > limit,
            "total": len(rows),
        }
    source = {
        "scopes": snapshot.get("scopes", []),
        "settings": snapshot.get("settings", []),
        "permissions": snapshot.get("permissions", []),
        "wmi": snapshot.get("wmi_filters", []),
        "quality": quality_rows(snapshot),
    }.get(view)
    if source is None:
        raise ValueError("invalid_gpo_v2_view")
    rows = _search([dict(row) for row in source], query)
    return {
        "state": "partial" if len(rows) > limit else "available",
        "items": rows[:limit],
        "has_more": len(rows) > limit,
        "total": len(rows),
    }


def load_authorized_snapshot_pair(connection: Any | None = None, *, domain_ids: list[int] | None) -> dict[str, Any]:
    clean_domain_ids = None if domain_ids is None else sorted(
        {value for value in domain_ids if isinstance(value, int) and not isinstance(value, bool) and value > 0}
    )
    if connection is None:
        from server.sli.core.postgres_runtime_pipeline import connect

        with connect() as owned_connection:
            return load_authorized_snapshot_pair(owned_connection, domain_ids=clean_domain_ids)
    with connection.cursor() as cursor:
        domain_clause = "where" if clean_domain_ids is None else "where domain_id = any(%s) and"
        cursor.execute(
            f"""
            select payload_json, payload_sha256, collection_status, source_completed_at_utc
              from gpo_report_v2_source_snapshots
             {domain_clause} import_status = 'completed'
               and schema_version = 'sli.ad-gpo.snapshot/1.0'
             order by source_completed_at_utc desc
             limit 2
            """,
            () if clean_domain_ids is None else (clean_domain_ids,),
        )
        rows = cursor.fetchall()
    if not rows:
        return {"state": "not_collected", "current": None, "previous": None}
    payloads = []
    for row in rows:
        payload = row[0] if not isinstance(row, Mapping) else row["payload_json"]
        expected_hash = row[1] if not isinstance(row, Mapping) else row["payload_sha256"]
        snapshot = validate_snapshot(payload)
        _payload_text, actual_hash = canonical_snapshot(snapshot)
        if expected_hash is not None:
            expected_hex = bytes(expected_hash).hex() if not isinstance(expected_hash, str) else expected_hash
            if expected_hex.casefold() != actual_hash:
                raise ValueError("stored_gpo_v2_snapshot_hash_mismatch")
        payloads.append(snapshot)
    return {
        "state": "available" if len(payloads) > 1 else "partial",
        "current": payloads[0],
        "previous": payloads[1] if len(payloads) > 1 else None,
    }


def build_gpo_v2_payload(pair: Mapping[str, Any], *, stale_days: int = 0) -> dict[str, Any]:
    current = deepcopy(pair.get("current"))
    previous = deepcopy(pair.get("previous"))
    if current is not None:
        for gpo in current.get("gpos", []):
            gpo["reasons"] = attention_reasons(gpo, snapshot=current, stale_days=stale_days)
    comparison = compare_snapshots(current=current, previous=previous) if current is not None else {
        "state": "not_collected",
        "items": [],
        "change_count": 0,
        "deletion_claim_allowed": False,
    }
    return {
        **dict(pair),
        "current": current,
        "previous": previous,
        "comparison": comparison,
        "boundaries": REPORT_BOUNDARIES,
    }

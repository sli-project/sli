"""L10: pairs first observed in a period relative to retained logon history."""

from __future__ import annotations

from datetime import timedelta

from server.sli.core.database import QueryTimeoutError
from server.sli.core.keyset_cursor import decode_cursor, encode_cursor
from server.sli.reporting.v2.definition import AccessRule, Column, Param, QueryContext, ReportDefinition, ReportIntent, result
from server.sli.plugins.ad.reports.definitions.computer_logons import FIELD_CATEGORY, logon_domain_scope
from server.sli.plugins.ad.reports import new_logon_pairs_reporting as engine
from server.sli.plugins.ad.reports.what_where_when_reporting import InventoryUnavailableError, MAX_DAYS, REPORT_KEY


_FAILURE_TEXT = {
    'context_read_timeout': 'Чтение сохранённого AD-контекста не завершилось в отведённое время. Проверьте нагрузку и состояние хранилища; сравнение входов не выполнено.',
    'context_read_cancelled': 'Чтение сохранённого AD-контекста прервано хранилищем или отменой запроса. Повторите запрос; сравнение входов не выполнено.',
    'computer_inventory_unavailable': 'Реестр рабочих станций AD не собран или недоступен. Проверьте сбор компьютеров выбранного домена; сравнение входов не выполнено.',

    'report_domain_not_configured': 'Домен отчёта не задан. Укажите его в настройках платформы и повторите запрос.',
    'domain_context_unavailable': 'Не удалось определить домен отчёта. Проверьте настройки домена и повторите запрос.',
    'domain_controllers_missing': 'Для выбранного домена нет контроллеров — источников входов. Проверьте настройку сбора с контроллеров домена.',
    'users_context_missing': 'Нет сохранённого снимка пользователей для сравнения. Проверьте сбор AD-контекста пользователей выбранного домена.',
    'computers_context_missing': 'Нет сохранённого снимка компьютеров для сравнения. Проверьте сбор AD-контекста компьютеров выбранного домена.',
    'context_verification_failed': 'Снимок AD-контекста не прошёл проверку целостности. Сравнение остановлено; проверьте состояние сбора и хранилища.',
    'context_read_failed': 'Не удалось прочитать AD-контекст. Повторите запрос; если ошибка сохраняется, проверьте состояние сбора и хранилища.',
    'history_not_enabled': 'Чтение постоянной истории входов не включено. Проверьте настройку истории в разделе «Сбор и хранилище». Новизна пар не определена.',
    'history_not_configured': 'Подключение к постоянной истории входов не настроено полностью. Проверьте настройки хранилища истории.',
    'history_verification_failed': 'История входов не прошла проверку целостности. Сравнение остановлено; проверьте состояние хранилища.',
    'history_read_failed': 'Не удалось прочитать историю входов. Повторите запрос; если ошибка сохраняется, проверьте доступность хранилища истории.',
    'read_cancelled': 'Чтение данных прервано: истекло время ожидания или запрос был отменён. Повторите запрос. Новизна пар не определена.',
    'read_timeout': 'Время ожидания данных истекло. Сузьте период и базовое окно, затем повторите запрос. Новизна пар не определена.',
    'comparison_failed': 'Не удалось построить сравнение входов. Повторите запрос; если ошибка сохраняется, передайте её администратору платформы.',
    'history_empty': 'В постоянной истории нет сохранённых входов от контроллеров выбранного домена. Проверьте сбор и публикацию истории; это не означает, что входов не было.',
}

_REASON_CODES = {
    'report_domain_not_configured': 'report_domain_not_configured',
    'logon_domain_controllers_missing': 'domain_controllers_missing',
    'what_where_when_users_snapshot_unavailable': 'users_context_missing',
    'logon_computers_snapshot_missing': 'computers_context_missing',
    'logon_inventory_unavailable': 'computer_inventory_unavailable',
    'stored_snapshot_hash_mismatch': 'context_verification_failed',
    'stored_snapshot_object_count_mismatch': 'context_verification_failed',
    'stored_snapshot_identity_mismatch': 'context_verification_failed',
    'stored_snapshot_status_mismatch': 'context_verification_failed',
    'stored_base_inventory_status_mismatch': 'context_verification_failed',

    'what_where_when_users_snapshot_hash_mismatch': 'context_verification_failed',
    'logon_history_unavailable': 'history_not_enabled',
    'history_read_mode_invalid': 'history_not_configured',
    'history_clickhouse_port_missing': 'history_not_configured',
    'history_clickhouse_port_invalid': 'history_not_configured',
    'history_clickhouse_credentials_missing': 'history_not_configured',
    'published_history_event_mismatch': 'history_verification_failed',
    'published_history_event_duplicate': 'history_verification_failed',
    'published_history_event_batch_incomplete': 'history_verification_failed',
}


def _failure(error: Exception, fallback: str, *, window=None):
    # Only allowlisted reasons leave the source boundary, never exception text.
    if isinstance(error, QueryTimeoutError):
        code = "context_read_timeout" if fallback == "context_read_failed" else "read_timeout"
    elif getattr(error, "sqlstate", None) == "57014":
        # PostgreSQL uses this state for timeout and other cancellations alike.
        code = "context_read_cancelled" if fallback == "context_read_failed" else "read_cancelled"
    else:
        code = _REASON_CODES.get(str(error), fallback)
    return result(REPORT, state="error", window=window,
                  limitations=[{"code": code, "text": _FAILURE_TEXT[code]}])


def _query(context: QueryContext):
    try:
        domain_id = logon_domain_scope(context.access, context.action)[0]
    except InventoryUnavailableError as exc:
        return _failure(exc, "domain_context_unavailable")
    start, end = (engine.utc(context.params["period"][key]) for key in ("from_utc", "to_utc"))
    days = context.params["baseline_days"]
    if not 1 <= days <= MAX_DAYS:
        raise ValueError("report_parameter_invalid:baseline_days")
    q = str(context.params.get("q") or "").casefold()
    user = str(context.params.get("user") or "").casefold()
    period = context.params["period"]
    binding = {"domain": domain_id, "period": period["preset"], "baseline_days": days, "q": q, "user": user}
    if period["preset"] == "custom":
        binding.update(start=start.isoformat(), end=end.isoformat())
    after = decode_cursor(context.cursor, binding) if context.cursor else None
    if after:
        try:
            start, end = engine.utc(after["start"]), engine.utc(after["end"])
            if not start < end or end - start > timedelta(days=MAX_DAYS):
                raise ValueError("invalid_cursor")
            if not isinstance(after["first_seen"], str) or not isinstance(after["id"], str):
                raise ValueError("invalid_cursor")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid_cursor") from exc
    baseline_start = start - timedelta(days=days)
    window = {"from_utc": start.isoformat(), "to_utc_exclusive": end.isoformat()}
    try:
        inventory = engine.load_context(domain_id)
    except PermissionError:
        raise
    except Exception as exc:
        return _failure(exc, "context_read_failed", window=window)
    try:
        raw = engine.load_history(domain_id, inventory["server_ids"], baseline_start, start, end)
    except PermissionError:
        raise
    except Exception as exc:
        return _failure(exc, "history_read_failed", window=window)
    try:
        compared = engine.compute_pairs(raw["baseline"], raw["period"], baseline_start=baseline_start,
            start=start, end=end, index=inventory["index"], accounts=inventory["accounts"],
            baseline_covered=raw["baseline_covered"] and not raw["truncated"]
            and not raw.get("facts_incomplete") and not inventory["partial"])
        rows = compared["items"]
        rows = [row for row in rows if q in row["computer"].casefold() and user in row["user"].casefold()]
        if after:
            rows = [row for row in rows if (row["first_seen"], row["id"]) > (after["first_seen"], after["id"])]
        page, more = rows[:context.limit], len(rows) > context.limit
        entities = engine.user_entities(domain_id, [row["user_sid"] for row in page if row["user_sid"]])
        for row in page:
            row["computer_entity_id"] = inventory["computers"].get(row["computer_guid"], {}).get("entity_id")
            row["user_entity_id"] = entities.get(str(row["user_sid"] or "").casefold())
        next_cursor = encode_cursor(binding, {"first_seen": page[-1]["first_seen"], "id": page[-1]["id"],
            "start": start.isoformat(), "end": end.isoformat()}) if more else None
    except PermissionError:
        raise
    except Exception as exc:
        return _failure(exc, "comparison_failed", window=window)
    limitations = []
    history_empty = (raw["history_from_utc"] is None and not raw["baseline"] and not raw["period"]
                     and not raw["truncated"] and not raw.get("facts_incomplete"))
    if history_empty:
        limitations.append({"code": "history_empty", "text": _FAILURE_TEXT["history_empty"]})
    if not raw["baseline_covered"]:
        limitations.append({"code": "no_baseline", "text": "Базовое окно не покрыто полностью: нет базы сравнения. Отсутствие предыдущих входов не установлено."})
    if raw["truncated"]:
        limitations.append({"code": "truncated", "text": "Достигнут предел чтения истории. Даты и счётчики частичные; сузьте период. Новизна не определена."})
    if not raw.get("period_bounds_covered", raw.get("period_covered", True)):
        limitations.append({"code": "period_missing", "text": "Текущее окно не покрыто границами сохранённых наблюдений всех разрешённых источников. Выберите день последних наблюдений; полнота сбора этим не подтверждается."})
    if raw.get("facts_incomplete"):
        limitations.append({"code": "facts_incomplete", "text": "Часть записей не прошла проверку опубликованных фактов. Результат частичный, новизна не определена."})
    if compared["incomplete"]:
        limitations.append({"code": "identity_incomplete", "text": "Часть пользователей или компьютеров не сопоставлена с текущим AD-контекстом либо отсутствует SID. Новизна не определена."})
    if inventory["partial"]:
        limitations.append({"code": "inventory_partial", "text": "Снимок AD-контекста неполон. Классификация и новизна пар не подтверждены."})
    if not compared["baseline_covered"] and raw["baseline_covered"]:
        limitations.append({"code": "novelty_unverified", "text": "Новизна не определена: ограничения текущего окна или AD-контекста не позволяют подтвердить сравнение. Это не означает отсутствие базовой истории."})
    limitations.append({"code": "observations", "text": "Сравнение относится к сохранённым наблюдениям, а не ко всем входам. Полнота сбора не доказана. Сопоставление ПК и классификация пользователей используют текущий AD-контекст."})
    # Coverage describes the retained comparison window; collection limits remain in limitations.
    return result(REPORT, state="empty" if history_empty else "partial" if not compared["baseline_covered"] or not raw.get("period_covered", True) else "ok" if page else "empty",
        items=page, has_more=more, next_cursor=next_cursor, window=window, limitations=limitations,
        coverage={"baseline_covered": compared["baseline_covered"],
                  "baseline_from_utc": baseline_start.isoformat(), "baseline_to_utc_exclusive": start.isoformat(),
                  "history_from_utc": raw["history_from_utc"], "history_to_utc": raw.get("history_to_utc"),
                  "baseline_history_covered": raw.get("baseline_bounds_covered", raw["baseline_covered"]),
                  "period_history_covered": raw.get("period_bounds_covered", raw.get("period_covered", True)),
                  "period_covered": raw.get("period_covered", True),
                  "baseline_truncated": raw.get("baseline_truncated", raw["truncated"]),
                  "period_truncated": raw.get("period_truncated", raw["truncated"]), "truncated": raw["truncated"]})


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="Security investigator",
        question="Какие пары пользователь — компьютер впервые наблюдались за период относительно базового окна?",
        action="Inspect newly observed pairs and their exact logon evidence against the preceding baseline.",
        scope="One server-resolved granted domain, selected users and computers, bounded period and preceding baseline window.",
        exclusions="Observed novelty is not first-ever use or a risk verdict; missing baseline or identity context leaves novelty undetermined.",
        sources=(
            "Canonical: published permanent Security 4624 history for domain controllers in the granted domain and both windows.",
            "Supplemental: current AD computer inventory, domain controller membership and service-account classification.",
        ),
        freshness_expectation="Свежесть истории входов, базового окна и текущего AD-контекста проверяется раздельно.",
        rights="ad.computer-logons view grant with computer_logon_observation; server resolves the domain scope before reading history; export is unavailable.",
        field_classes=(FIELD_CATEGORY,),
        coverage="History bounds, baseline availability, truncation and current AD identity context are separate dimensions; baseline_covered does not prove collection continuity.",
        completeness="Source-confirmed collection intervals divided by expected source-window duration across both windows; history bounds and pair counts do not prove continuity. Currently not_proven.",
        denominator="Ожидаемые источники входов выбранного домена × выбранный период и базовое окно; границы истории не доказывают непрерывность сбора.",
        retention="Published derived history follows the storage policy; exact source events may expire independently.",
        provenance="User SID, computer GUID, domain, DC source, first observed time and source event ID.",
        primary_archetype="list",
        product_archetype="investigation-evidence",
        deterministic_policy="Compare first observed user/computer pairs with the retained baseline; novelty requires covered baseline and complete identity context.",
        result_limits="Baseline days and current period are bounded by MAX_DAYS; history read caps and fact validation may invalidate novelty.",
        fallback="Uncovered baseline, truncated history, incomplete facts or AD identity suppress confirmed novelty and expose limitations.",
        acceptance_lanes={
            "product_user": "First-observed pairs answer the baseline comparison question.",
            "authorization": "Logon field grant and server-resolved domain also constrain baseline and entity pivots.",
            "deterministic_interpretation": "Covered baseline and identity matching are necessary for confirmed novelty.",
            "api_view_model": "Sealed cursor preserves baseline, current window and first_seen/id order.",
            "ui_honest_states": "No baseline, truncated history and incomplete identities do not claim a new pair.",
            "evidence_audit": "Pair identity and first observed event retain current AD matching provenance.",
        },
    ),
    key="ad.new-logon-pairs", section="reports/computers", title="Новые пары пользователь — компьютер",
    description="Пары входов, впервые наблюдавшиеся в выбранном периоде относительно базового окна перед ним.",
    archetype="investigation-evidence", access=AccessRule(REPORT_KEY, frozenset({FIELD_CATEGORY}), scope="delegated"),
    params=(Param.period(default="24h", max_days=MAX_DAYS, presets=("24h", "7d", "custom")),
            Param("baseline_days", "Базовое окно, дней", "int", default=30, required=True),
            Param.text("q", "Компьютер"), Param.text("user", "Пользователь")),
    columns=(Column("user", "Пользователь", link="/app/entities/{user_entity_id}"),
             Column("computer", "Компьютер", link="/app/entities/{computer_entity_id}"),
             Column("first_seen", "Первое наблюдение за период", "datetime"),
             Column("logon_types", "Тип входа", "list"), Column("sources", "Источник DC/агент", "list"),
             Column("count", "Входов за период", "number"),
             Column("prior_user_logon", "Любой вход пользователя в базовом окне", "state",
                    labels={"yes": "Да", "no": "Нет", "unknown": "Неизвестно"}),
             Column("novelty", "Сравнение", "state", labels={"new_pair": "Новая пара", "new_user": "Новый пользователь", "no_baseline": "Новизна не определена"})),
    query=_query, row_key="id", row_links=(("Исходное событие / расследование", "/app/events/{source_event_id}"),),
    default_limit=50, max_limit=200,
)

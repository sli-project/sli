"""Exact T002 source deltas on the independent frozen relocation capture.

Keep the original fixture immutable. Only these reviewed replacements are
allowed; the caller still compares the complete resulting AST with production.
"""
from __future__ import annotations


_REPLACEMENTS = {
    'server.sli.reports.new_logon_pairs_reporting': (
        (
            '    with connect() as connection:\n        with connection.cursor() as cursor:\n            membership = _load_domain_controller_membership(cursor, domain_id=domain_id)\n        _, accounts = _load_service_accounts(connection, domain_id)\n        snapshot = load_latest_computers_v6_source_snapshot(connection, domain_fqdn=report_domain_fqdn())\n    population = _load_workstation_population([domain_id])\n    if not snapshot or population["state"] == "unavailable" or not membership.server_ids:\n        raise RuntimeError("logon_inventory_unavailable")\n    return {\n        "index": load_computer_match_index(snapshot), "accounts": accounts,\n',
            '    with connect() as connection:\n        with connection.cursor() as cursor:\n            membership = _load_domain_controller_membership(cursor, domain_id=domain_id)\n        if not membership.server_ids:\n            raise RuntimeError("logon_domain_controllers_missing")\n        _, accounts = _load_service_accounts(connection, domain_id)\n        snapshot = load_latest_computers_v6_source_snapshot(connection, domain_fqdn=report_domain_fqdn())\n    if not snapshot:\n        raise RuntimeError("logon_computers_snapshot_missing")\n    population = _load_workstation_population([domain_id])\n    if population["state"] == "unavailable":\n        raise RuntimeError("logon_inventory_unavailable")\n    return {\n        "index": load_computer_match_index(snapshot), "accounts": accounts,\n',
        ),
    ),
    'server.sli.reporting.v2.reports.new_logon_pairs': (
        (
            '\nfrom datetime import timedelta\n\nfrom server.sli.core.keyset_cursor import decode_cursor, encode_cursor\nfrom server.sli.reporting.v2.definition import AccessRule, Column, Param, QueryContext, ReportDefinition, ReportIntent, result\nfrom server.sli.reporting.v2.reports.computer_logons import FIELD_CATEGORY, logon_domain_scope\n',
            '\nfrom datetime import timedelta\n\nfrom server.sli.core.database import QueryTimeoutError\nfrom server.sli.core.keyset_cursor import decode_cursor, encode_cursor\nfrom server.sli.reporting.v2.definition import AccessRule, Column, Param, QueryContext, ReportDefinition, ReportIntent, result\nfrom server.sli.reporting.v2.reports.computer_logons import FIELD_CATEGORY, logon_domain_scope\n',
        ),
        (
            'from server.sli.reports.what_where_when_reporting import InventoryUnavailableError, MAX_DAYS, REPORT_KEY\n\n\ndef _query(context: QueryContext):\n    try:\n        domain_id = logon_domain_scope(context.access, context.action)[0]\n    except InventoryUnavailableError:\n        return result(REPORT, state="error", limitations=[{"code": "history_unavailable",\n            "text": "История входов или текущий AD-контекст недоступны. Новизна пар не определена."}])\n    start, end = (engine.utc(context.params["period"][key]) for key in ("from_utc", "to_utc"))\n    days = context.params["baseline_days"]\n    if not 1 <= days <= MAX_DAYS:\n',
            'from server.sli.reports.what_where_when_reporting import InventoryUnavailableError, MAX_DAYS, REPORT_KEY\n\n\n_FAILURE_TEXT = {\n    \'report_domain_not_configured\': \'Домен отчёта не задан. Укажите его в настройках платформы и повторите запрос.\',\n    \'domain_context_unavailable\': \'Не удалось определить домен отчёта. Проверьте настройки домена и повторите запрос.\',\n    \'domain_controllers_missing\': \'Для выбранного домена нет контроллеров — источников входов. Проверьте настройку сбора с контроллеров домена.\',\n    \'users_context_missing\': \'Нет сохранённого снимка пользователей для сравнения. Проверьте сбор AD-контекста пользователей выбранного домена.\',\n    \'computers_context_missing\': \'Нет сохранённого снимка компьютеров для сравнения. Проверьте сбор AD-контекста компьютеров выбранного домена.\',\n    \'context_verification_failed\': \'Снимок AD-контекста не прошёл проверку целостности. Сравнение остановлено; проверьте состояние сбора и хранилища.\',\n    \'context_read_failed\': \'Не удалось прочитать AD-контекст. Повторите запрос; если ошибка сохраняется, проверьте состояние сбора и хранилища.\',\n    \'history_not_enabled\': \'Чтение постоянной истории входов не включено. Проверьте настройку истории в разделе «Сбор и хранилище». Новизна пар не определена.\',\n    \'history_not_configured\': \'Подключение к постоянной истории входов не настроено полностью. Проверьте настройки хранилища истории.\',\n    \'history_verification_failed\': \'История входов не прошла проверку целостности. Сравнение остановлено; проверьте состояние хранилища.\',\n    \'history_read_failed\': \'Не удалось прочитать историю входов. Повторите запрос; если ошибка сохраняется, проверьте доступность хранилища истории.\',\n    \'read_cancelled\': \'Чтение данных прервано: истекло время ожидания или запрос был отменён. Повторите запрос. Новизна пар не определена.\',\n    \'read_timeout\': \'Время ожидания данных истекло. Сузьте период и базовое окно, затем повторите запрос. Новизна пар не определена.\',\n    \'comparison_failed\': \'Не удалось построить сравнение входов. Повторите запрос; если ошибка сохраняется, передайте её администратору платформы.\',\n    \'history_empty\': \'В постоянной истории нет сохранённых входов от контроллеров выбранного домена. Проверьте сбор и публикацию истории; это не означает, что входов не было.\',\n}\n\n_REASON_CODES = {\n    \'report_domain_not_configured\': \'report_domain_not_configured\',\n    \'logon_domain_controllers_missing\': \'domain_controllers_missing\',\n    \'what_where_when_users_snapshot_unavailable\': \'users_context_missing\',\n    \'logon_computers_snapshot_missing\': \'computers_context_missing\',\n    \'what_where_when_users_snapshot_hash_mismatch\': \'context_verification_failed\',\n    \'logon_history_unavailable\': \'history_not_enabled\',\n    \'history_read_mode_invalid\': \'history_not_configured\',\n    \'history_clickhouse_port_missing\': \'history_not_configured\',\n    \'history_clickhouse_port_invalid\': \'history_not_configured\',\n    \'history_clickhouse_credentials_missing\': \'history_not_configured\',\n    \'published_history_event_mismatch\': \'history_verification_failed\',\n    \'published_history_event_duplicate\': \'history_verification_failed\',\n    \'published_history_event_batch_incomplete\': \'history_verification_failed\',\n}\n\n\ndef _failure(error: Exception, fallback: str, *, window=None):\n    # Only allowlisted reasons leave the source boundary, never exception text.\n    if isinstance(error, QueryTimeoutError):\n        code = "read_timeout"\n    elif getattr(error, "sqlstate", None) == "57014":\n        # PostgreSQL uses this state for timeout and other cancellations alike.\n        code = "read_cancelled"\n    else:\n        code = _REASON_CODES.get(str(error), fallback)\n    return result(REPORT, state="error", window=window,\n                  limitations=[{"code": code, "text": _FAILURE_TEXT[code]}])\n\n\ndef _query(context: QueryContext):\n    try:\n        domain_id = logon_domain_scope(context.access, context.action)[0]\n    except InventoryUnavailableError as exc:\n        return _failure(exc, "domain_context_unavailable")\n    start, end = (engine.utc(context.params["period"][key]) for key in ("from_utc", "to_utc"))\n    days = context.params["baseline_days"]\n    if not 1 <= days <= MAX_DAYS:\n',
        ),
        (
            '    window = {"from_utc": start.isoformat(), "to_utc_exclusive": end.isoformat()}\n    try:\n        inventory = engine.load_context(domain_id)\n        raw = engine.load_history(domain_id, inventory["server_ids"], baseline_start, start, end)\n        compared = engine.compute_pairs(raw["baseline"], raw["period"], baseline_start=baseline_start,\n            start=start, end=end, index=inventory["index"], accounts=inventory["accounts"],\n            baseline_covered=raw["baseline_covered"] and not raw["truncated"]\n',
            '    window = {"from_utc": start.isoformat(), "to_utc_exclusive": end.isoformat()}\n    try:\n        inventory = engine.load_context(domain_id)\n    except PermissionError:\n        raise\n    except Exception as exc:\n        return _failure(exc, "context_read_failed", window=window)\n    try:\n        raw = engine.load_history(domain_id, inventory["server_ids"], baseline_start, start, end)\n    except PermissionError:\n        raise\n    except Exception as exc:\n        return _failure(exc, "history_read_failed", window=window)\n    try:\n        compared = engine.compute_pairs(raw["baseline"], raw["period"], baseline_start=baseline_start,\n            start=start, end=end, index=inventory["index"], accounts=inventory["accounts"],\n            baseline_covered=raw["baseline_covered"] and not raw["truncated"]\n',
        ),
        (
            '            row["user_entity_id"] = entities.get(str(row["user_sid"] or "").casefold())\n        next_cursor = encode_cursor(binding, {"first_seen": page[-1]["first_seen"], "id": page[-1]["id"],\n            "start": start.isoformat(), "end": end.isoformat()}) if more else None\n    except Exception:\n        return result(REPORT, state="error", window=window,\n            limitations=[{"code": "history_unavailable", "text": "История входов или текущий AD-контекст недоступны. Новизна пар не определена."}])\n    limitations = []\n    if not raw["baseline_covered"]:\n        limitations.append({"code": "no_baseline", "text": "Базовое окно не покрыто полностью: нет базы сравнения. Отсутствие предыдущих входов не установлено."})\n    if raw["truncated"]:\n',
            '            row["user_entity_id"] = entities.get(str(row["user_sid"] or "").casefold())\n        next_cursor = encode_cursor(binding, {"first_seen": page[-1]["first_seen"], "id": page[-1]["id"],\n            "start": start.isoformat(), "end": end.isoformat()}) if more else None\n    except PermissionError:\n        raise\n    except Exception as exc:\n        return _failure(exc, "comparison_failed", window=window)\n    limitations = []\n    history_empty = (raw["history_from_utc"] is None and not raw["baseline"] and not raw["period"]\n                     and not raw["truncated"] and not raw.get("facts_incomplete"))\n    if history_empty:\n        limitations.append({"code": "history_empty", "text": _FAILURE_TEXT["history_empty"]})\n    if not raw["baseline_covered"]:\n        limitations.append({"code": "no_baseline", "text": "Базовое окно не покрыто полностью: нет базы сравнения. Отсутствие предыдущих входов не установлено."})\n    if raw["truncated"]:\n',
        ),
        (
            '        limitations.append({"code": "novelty_unverified", "text": "Новизна не определена: ограничения текущего окна или AD-контекста не позволяют подтвердить сравнение. Это не означает отсутствие базовой истории."})\n    limitations.append({"code": "observations", "text": "Сравнение относится к сохранённым наблюдениям, а не ко всем входам. Полнота сбора не доказана. Сопоставление ПК и классификация пользователей используют текущий AD-контекст."})\n    # Coverage describes the retained comparison window; collection limits remain in limitations.\n    return result(REPORT, state="partial" if not compared["baseline_covered"] or not raw.get("period_covered", True) else "ok" if page else "empty",\n        items=page, has_more=more, next_cursor=next_cursor, window=window, limitations=limitations,\n        coverage={"baseline_covered": compared["baseline_covered"],\n                  "baseline_from_utc": baseline_start.isoformat(), "baseline_to_utc_exclusive": start.isoformat(),\n',
            '        limitations.append({"code": "novelty_unverified", "text": "Новизна не определена: ограничения текущего окна или AD-контекста не позволяют подтвердить сравнение. Это не означает отсутствие базовой истории."})\n    limitations.append({"code": "observations", "text": "Сравнение относится к сохранённым наблюдениям, а не ко всем входам. Полнота сбора не доказана. Сопоставление ПК и классификация пользователей используют текущий AD-контекст."})\n    # Coverage describes the retained comparison window; collection limits remain in limitations.\n    return result(REPORT, state="empty" if history_empty else "partial" if not compared["baseline_covered"] or not raw.get("period_covered", True) else "ok" if page else "empty",\n        items=page, has_more=more, next_cursor=next_cursor, window=window, limitations=limitations,\n        coverage={"baseline_covered": compared["baseline_covered"],\n                  "baseline_from_utc": baseline_start.isoformat(), "baseline_to_utc_exclusive": start.isoformat(),\n',
        ),
    ),
}


# T051: exact reviewed context-diagnosis deltas; no unrelated drift permitted.
_T051_REPLACEMENTS = {'server.sli.reports.what_where_when_reporting': (('\n'
                                                   '\n'
                                                   'def _load_workstation_population(domain_ids: list[int]) -> '
                                                   'dict[str, Any]:\n'
                                                   '    try:\n'
                                                   '        payload = get_computers_v6_report(\n',
                                                   '\n'
                                                   '\n'
                                                   'def _load_workstation_population(domain_ids: list[int], *, '
                                                   'raise_on_error: bool = False) -> dict[str, Any]:\n'
                                                   '    try:\n'
                                                   '        payload = get_computers_v6_report(\n'),
                                                  ('        )\n'
                                                   '    except Exception:\n'
                                                   '        return {"state": "unavailable", "partial": True, "items": '
                                                   '[]}\n'
                                                   '    state = str(payload.get("state") or "unavailable")\n',
                                                   '        )\n'
                                                   '    except Exception:\n'
                                                   '        if raise_on_error:\n'
                                                   '            raise\n'
                                                   '        return {"state": "unavailable", "partial": True, "items": '
                                                   '[]}\n'
                                                   '    state = str(payload.get("state") or "unavailable")\n')),
 'server.sli.reports.new_logon_pairs_reporting': (('    if not snapshot:\n'
                                                   '        raise RuntimeError("logon_computers_snapshot_missing")\n'
                                                   '    population = _load_workstation_population([domain_id])\n'
                                                   '    if population["state"] == "unavailable":\n'
                                                   '        raise RuntimeError("logon_inventory_unavailable")\n',
                                                   '    if not snapshot:\n'
                                                   '        raise RuntimeError("logon_computers_snapshot_missing")\n'
                                                   '    population = _load_workstation_population([domain_id], '
                                                   'raise_on_error=True)\n'
                                                   '    if population["state"] == "unavailable":\n'
                                                   '        raise RuntimeError("logon_inventory_unavailable")\n'),),
 'server.sli.reporting.v2.reports.new_logon_pairs': (('\n'
                                                      '_FAILURE_TEXT = {\n'
                                                      "    'report_domain_not_configured': 'Домен отчёта не задан. "
                                                      "Укажите его в настройках платформы и повторите запрос.',\n"
                                                      "    'domain_context_unavailable': 'Не удалось определить домен "
                                                      "отчёта. Проверьте настройки домена и повторите запрос.',\n",
                                                      '\n'
                                                      '_FAILURE_TEXT = {\n'
                                                      "    'context_read_timeout': 'Чтение сохранённого AD-контекста "
                                                      'не завершилось в отведённое время. Проверьте нагрузку и '
                                                      "состояние хранилища; сравнение входов не выполнено.',\n"
                                                      "    'context_read_cancelled': 'Чтение сохранённого AD-контекста "
                                                      'прервано хранилищем или отменой запроса. Повторите запрос; '
                                                      "сравнение входов не выполнено.',\n"
                                                      "    'computer_inventory_unavailable': 'Реестр рабочих станций "
                                                      'AD не собран или недоступен. Проверьте сбор компьютеров '
                                                      "выбранного домена; сравнение входов не выполнено.',\n"
                                                      '\n'
                                                      "    'report_domain_not_configured': 'Домен отчёта не задан. "
                                                      "Укажите его в настройках платформы и повторите запрос.',\n"
                                                      "    'domain_context_unavailable': 'Не удалось определить домен "
                                                      "отчёта. Проверьте настройки домена и повторите запрос.',\n"),
                                                     ("    'what_where_when_users_snapshot_unavailable': "
                                                      "'users_context_missing',\n"
                                                      "    'logon_computers_snapshot_missing': "
                                                      "'computers_context_missing',\n"
                                                      "    'what_where_when_users_snapshot_hash_mismatch': "
                                                      "'context_verification_failed',\n"
                                                      "    'logon_history_unavailable': 'history_not_enabled',\n",
                                                      "    'what_where_when_users_snapshot_unavailable': "
                                                      "'users_context_missing',\n"
                                                      "    'logon_computers_snapshot_missing': "
                                                      "'computers_context_missing',\n"
                                                      "    'logon_inventory_unavailable': "
                                                      "'computer_inventory_unavailable',\n"
                                                      "    'stored_snapshot_hash_mismatch': "
                                                      "'context_verification_failed',\n"
                                                      "    'stored_snapshot_object_count_mismatch': "
                                                      "'context_verification_failed',\n"
                                                      "    'stored_snapshot_identity_mismatch': "
                                                      "'context_verification_failed',\n"
                                                      "    'stored_snapshot_status_mismatch': "
                                                      "'context_verification_failed',\n"
                                                      "    'stored_base_inventory_status_mismatch': "
                                                      "'context_verification_failed',\n"
                                                      '\n'
                                                      "    'what_where_when_users_snapshot_hash_mismatch': "
                                                      "'context_verification_failed',\n"
                                                      "    'logon_history_unavailable': 'history_not_enabled',\n"),
                                                     ('    # Only allowlisted reasons leave the source boundary, never '
                                                      'exception text.\n'
                                                      '    if isinstance(error, QueryTimeoutError):\n'
                                                      '        code = "read_timeout"\n'
                                                      '    elif getattr(error, "sqlstate", None) == "57014":\n'
                                                      '        # PostgreSQL uses this state for timeout and other '
                                                      'cancellations alike.\n'
                                                      '        code = "read_cancelled"\n'
                                                      '    else:\n'
                                                      '        code = _REASON_CODES.get(str(error), fallback)\n',
                                                      '    # Only allowlisted reasons leave the source boundary, never '
                                                      'exception text.\n'
                                                      '    if isinstance(error, QueryTimeoutError):\n'
                                                      '        code = "context_read_timeout" if fallback == '
                                                      '"context_read_failed" else "read_timeout"\n'
                                                      '    elif getattr(error, "sqlstate", None) == "57014":\n'
                                                      '        # PostgreSQL uses this state for timeout and other '
                                                      'cancellations alike.\n'
                                                      '        code = "context_read_cancelled" if fallback == '
                                                      '"context_read_failed" else "read_cancelled"\n'
                                                      '    else:\n'
                                                      '        code = _REASON_CODES.get(str(error), fallback)\n'))}

def new_logon_pairs_source(source: str, module: str) -> str:
    for before, after in _REPLACEMENTS.get(module, ()) + _T051_REPLACEMENTS.get(module, ()):
        assert source.count(before) == 1, (module, "T002/T051 baseline anchor changed")
        source = source.replace(before, after, 1)
    return source

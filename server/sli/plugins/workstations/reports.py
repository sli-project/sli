"""Bounded PG/history reports and evidence detail; identity scope fails closed."""

from __future__ import annotations

from datetime import datetime, timedelta
from xml.etree.ElementTree import ParseError

from psycopg import OperationalError
from psycopg.errors import InsufficientPrivilege, QueryCanceled, UndefinedTable

from server.sli.agents.agent_names import read_agent_name_details, reported_hostname
from server.sli.core.messages import message
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.reporting.v2.access import report_grant
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    Param,
    ReportDefinition,
    ReportIntent,
    result,
)
from server.sli.storage import workstation_history as history
from server.sli.storage.xml_safety import parse_bounded_xml

FIELDS = frozenset({"identity_basic", "technical", "security", "privilege"})
REPORTS = {
    "logons": ("workstations.logons", "Входы на станциях"),
    "processes": ("workstations.processes", "Процессы и службы"),
    "usb": ("workstations.usb", "Съёмные носители"),
    "protection": ("workstations.protection", "Локальные администраторы и защита"),
}
QUESTIONS = {
    "logons": "Какие входы наблюдались на выбранных рабочих станциях за период?",
    "processes": "Какие процессы, службы и задания наблюдались на выбранных станциях за период?",
    "usb": "Какие съёмные носители наблюдались на выбранных станциях за период?",
    "protection": "Каково последнее наблюдаемое состояние защиты станций и какие изменения локальных прав произошли за период?",
}
FACT_COLUMNS = {
    "logons": (("logon_type", "Тип входа"),),
    "processes": (("process_image", "Процесс"), ("process_command_line", "Командная строка"),
                  ("service_name", "Служба"), ("service_file", "Файл службы"),
                  ("task_name", "Задание"), ("task_change", "Изменение задания")),
    "usb": (("device_id", "Устройство"), ("device_description", "Описание устройства"),
            ("device_class", "Класс устройства")),
    "protection": (("group", "Группа"), ("member", "Участник"), ("change", "Изменение"),
                   ("protection_component", "Компонент защиты"), ("audit_policy_changes", "Изменение политики аудита"),
                   ("antivirus_enabled", "Антивирус включён"),
                   ("real_time_protection_enabled", "Защита в реальном времени"),
                   ("behavior_monitor_enabled", "Контроль поведения"),
                   ("ioav_protection_enabled", "Проверка скачанных файлов"),
                   ("nis_enabled", "Защита сети"), ("tamper_protected", "Защита от изменений")),
}
MAX_STATIONS = 500
MAX_DAYS = 90
MAX_LIMIT = 500

# Older registrations predate registration_host_name. Read at most four events
# per authorized agent using workstation_report_window(agent_key,family,observed_at,id).
# Never search the whole observation history or use an event name as identity.
_EVENT_NAMES_SQL = """
select wanted.agent_key, recent.source_xml
from unnest(%s::text[]) wanted(agent_key)
cross join (values ('logons'),('processes'),('usb'),('protection')) families(family)
cross join lateral (
    select o.source_xml from sli_plugin_workstations.observations o
    where o.agent_key=wanted.agent_key and o.family=families.family
    order by o.observed_at desc,o.id desc limit 1
) recent
"""


def _report_names(cur, keys):
    names = read_agent_name_details(cur, keys)
    missing = [key for key in keys if not names.get(key, {}).get("name")]
    if missing:
        cur.execute(_EVENT_NAMES_SQL, (missing,))
        candidates = {key: {} for key in missing}
        for row in cur.fetchall():
            key, xml = row.get("agent_key"), row.get("source_xml")
            if key not in candidates or not isinstance(xml, str):
                continue
            try:
                root = parse_bounded_xml(xml, max_bytes=1048576)
                name = reported_hostname(root.findtext(
                    "{http://schemas.microsoft.com/win/2004/08/events/event}System/"
                    "{http://schemas.microsoft.com/win/2004/08/events/event}Computer"))
            except (ValueError, ParseError, UnicodeError):
                continue
            if name:
                candidates[key].setdefault(name.casefold(), name)
        for key, values in candidates.items():
            # Conflicting journal names do not identify a single station.
            if len(values) == 1:
                names[key] = {"name": next(iter(values.values())), "source": "event_reported"}
    return names


def _source_error(definition, error):
    # Never expose driver messages: they can contain source identities or SQL.
    reason = "source_unavailable"
    if isinstance(error, QueryCanceled):
        reason = "source_timeout"
    elif isinstance(error, UndefinedTable):
        reason = "source_not_initialized"
    elif isinstance(error, InsufficientPrivilege):
        reason = "source_access_denied"
    return result(definition, state="error", coverage={"state": "error", "reason": reason},
                  limitations=[{"code": reason, "text": message(f"reports.workstations.{reason}")["text"]}])


def _window(period, max_days=MAX_DAYS):
    start = datetime.fromisoformat(str(period["from_utc"]).replace("Z", "+00:00"))
    end = datetime.fromisoformat(str(period["to_utc"]).replace("Z", "+00:00"))
    if (start.utcoffset() is None or end.utcoffset() is None or start >= end
            or end - start > timedelta(days=max_days)):
        raise ValueError("workstation_report_period_invalid")
    return start, end


def read_report(context, family, definition, observation_id=None):
    grant = report_grant(context.access, definition.access.report_key)
    if not grant or context.action not in set(grant.get("allowed_actions") or []):
        raise PermissionError("report_access_denied")
    eligible = [item for item in grant.get("grants") or []
                if context.action in set(item.get("allowed_actions") or [])
                and FIELDS.issubset(set(item.get("field_categories") or []))]
    if not eligible:
        raise PermissionError("report_field_categories_not_allowed")
    scope = context.runtime.get("workstation_scope_adapter")
    if scope is None:
        return result(definition, state="error", coverage={"state": "blocked", "reason": "identity_adapter_unavailable"})
    # Exclude partial grants so an adapter cannot combine disjoint category
    # grants into access to the complete row.
    access = {**context.access, "reports": [{**grant, "grants": eligible}]}
    try:
        keys = tuple(scope.agent_keys(access, definition.key, context.action, FIELDS))
    except (UndefinedTable, InsufficientPrivilege, OperationalError) as exc:
        return _source_error(definition, exc)
    limitations = list(getattr(scope, "limitations", ()))
    if (len(keys) > MAX_STATIONS
            or any(not isinstance(key, str) or not key.strip() or key.strip() != key or len(key) > 256 for key in keys)
            or len(set(keys)) != len(keys)):
        raise ValueError("workstation_scope_invalid")
    selected = context.params.get("agent_key")
    if selected:
        if selected not in keys:
            raise PermissionError("workstation_scope_denied")
        keys = (selected,)
    if type(context.limit) is not int or not 1 <= context.limit <= MAX_LIMIT:
        raise ValueError("workstation_report_limit_invalid")
    if context.cursor and (len(context.cursor) != 64 or any(ch not in "0123456789abcdef" for ch in context.cursor)):
        raise ValueError("workstation_report_cursor_invalid")
    if observation_id is not None and (len(observation_id) != 64 or any(ch not in "0123456789abcdef" for ch in observation_id)):
        raise ValueError("workstation_report_id_invalid")
    start, end = _window(context.params["period"], history.MAX_DAYS if family in history.FAMILIES else MAX_DAYS)
    if not keys:
        return result(definition, state="partial", coverage={"state": "not_proven", "reason": "workstation_scope_empty"},
                      limitations=limitations or [{"code": "workstation_scope_empty", "text":
                          "В разрешённой области нет сопоставленных агентов рабочих станций."}],
                      window={"from_utc": start.isoformat(), "to_utc": end.isoformat()})
    # Keyset order by immutable ID bounds pages without an unbounded COUNT or OFFSET.
    # Coverage is deliberately not inferred from the presence/absence of rows.
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("set local statement_timeout = '5000ms'")
            names = _report_names(cur, keys)
            states = []
            event_cursor = context.cursor or ""
            if family == "protection":
                # Current state is independent of the event period and precedes
                # event pages. Its stable ID lets the same cursor continue into
                # events without skipping events whose hashes sort before it.
                cur.execute("""select id,agent_key,entity_id,ad_computer_id,null::integer as event_id,
                    observed_at,'security.protection.state'::text as semantic_type,
                    state->'components' as facts,
                    jsonb_build_object('snapshot',true,'state',state->>'state') as quality,
                    state_sha256 as observation_sha256
                    from sli_plugin_workstations.protection_state
                    where agent_key=any(%s) order by id limit %s""", (list(keys), MAX_STATIONS))
                states = [dict(row) for row in cur.fetchall()]
                if context.cursor:
                    if any(row["id"] == context.cursor for row in states):
                        event_cursor = ""
                        states = [row for row in states if row["id"] > context.cursor]
                    else:
                        states = []
            evidence_columns = ",source_xml,observation->>'source_sha256' as source_sha256" if observation_id is not None else ""
            exact = " and id=%s" if observation_id is not None else ""
            params = (list(keys), family, start, end, "" if observation_id is not None else event_cursor)
            if observation_id is not None:
                params += (observation_id,)
            params += (context.limit + 1,)
            # Dense process windows can contain millions of IDs. Allow LIMIT
            # pushdown there so the planner can choose an ordered PK scan or a
            # window index for sparse periods. Keep the page materialized so
            # observation JSON is loaded only for the bounded result.
            materialization = "not materialized" if family == "processes" else "materialized"
            storage = " and observation->'facts'->>'storage_evidence'='true'" if family == "usb" else ""
            cur.execute(f"""
                with candidates as {materialization} (
                    select id from sli_plugin_workstations.observations
                    where agent_key=any(%s) and family=%s
                      and observed_at>=%s and observed_at<%s and id>%s
                      {storage}{exact}
                ), page as materialized (
                    select id from candidates order by id limit %s
                )
                select id,agent_key,entity_id,ad_computer_id,event_id,observed_at,
                       observation->>'semantic_type' as semantic_type,
                       observation->'facts' as facts,observation->'quality' as quality,
                       observation_sha256{evidence_columns}
                from sli_plugin_workstations.observations
                join page using(id)
                order by id
            """, params)
            rows = (states + [dict(row) for row in cur.fetchall()])[:context.limit + 1]
    except (UndefinedTable, InsufficientPrivilege, OperationalError) as exc:
        return _source_error(definition, exc)
    history_state = "not_applicable"
    if family in history.FAMILIES:
        history_state = "unavailable"
        try:
            adapter = (context.runtime["workstation_history_adapter"] if "workstation_history_adapter" in context.runtime
                       else history.configured_history())
            if adapter is not None:
                old_rows = adapter.read(keys=keys, family=family, start=start, end=end,
                                        cursor="" if observation_id is not None else context.cursor or "",
                                        limit=context.limit + 1, observation_id=observation_id)
                merged = {row["id"]: row for row in rows}
                for row in old_rows:
                    previous = merged.get(row["id"])
                    # Ignore timestamp formatting, but refuse conflicting identity,
                    # facts or XML when a PG rollback leaves both copies visible.
                    if previous is not None and (previous.keys() != row.keys() or any(
                        previous[key] != row[key] for key in row if key != "observed_at")
                            or history._stamp(previous["observed_at"]) != history._stamp(row["observed_at"])):
                        raise ValueError("workstation_history_receipt_mismatch")
                    merged[row["id"]] = row
                rows = [merged[key] for key in sorted(merged)][:context.limit + 1]
                history_state = "loaded"
        except ValueError:
            return result(definition, state="error", coverage={"state": "blocked", "reason": "workstation_history_receipt_mismatch"})
        except (RuntimeError, OSError):
            history_state = "unavailable"
        if history_state == "unavailable":
            limitations.append({"code": "history_unavailable", "text":
                "Постоянная история недоступна; показаны только доступные данные PostgreSQL."})
    if observation_id is not None and not rows:
        raise LookupError("report_row_not_found")
    more = observation_id is None and len(rows) > context.limit
    items = rows[:context.limit]
    for item in items:
        if "agent_key" in item:
            name = names.get(item["agent_key"], {})
            item["host_name"] = name.get("name")
            item["host_name_source"] = name.get("source", "unknown")
    return result(definition, state="partial", items=items, has_more=more,
                  next_cursor=items[-1]["id"] if more else None,
                  coverage={"state": "not_proven", "completeness": "not_proven", "reason": "agent_import_state_unknown",
                            "continuity_reason": "collection_continuity_not_proven",
                            "history": history_state, "ad_enrichment": "per_observation"},
                  limitations=limitations + [{"code": "coverage_unverified", "text":
                      "Покрытие сбора не подтверждено. USB-события не доказывают чтение или копирование файлов."}],
                  window={"from_utc": start.isoformat(), "to_utc": end.isoformat()})


def make_report(family):
    key, title = REPORTS[family]
    max_days = history.MAX_DAYS if family in history.FAMILIES else MAX_DAYS
    def query(context):
        return read_report(context, family, definition)
    definition = ReportDefinition(
        key=key, section="reports/workstations", title=title,
        description=("Последний снимок Defender независимо от периода и события изменений за период. "
                     "Время снимка показывает его свежесть; неизвестные флаги не подтверждают защиту."
                     if family == "protection" else
                     "Наблюдаемые события; отсутствие строк не подтверждает отсутствие активности."),
        archetype="journal", access=AccessRule(key, FIELDS, scope="delegated", accepts_generic_scope=True),
        intent=ReportIntent(
            version=1,
            user_role="Workstation security reviewer",
            question=QUESTIONS[family],
            action="Inspect source observations before deciding on a workstation investigation.",
            scope=f"Server-resolved authorized agent identities, selected family and a period of at most {max_days} days.",
            exclusions="No inferred work duration, file copying or security compliance; missing identity binding is unavailable.",
            sources=(f"Canonical: workstations {family} observations in the granted station/channel/window scope.",
                     "Supplemental: canonical AD identity enrichment retained per observation."),
            freshness_expectation="Подтверждение источников станций в выбранном окне; непрерывность сбора пока не доказана.",
            rights=f"{key} view grant with atomic workstation field classes; the server identity adapter bounds agent keys.",
            field_classes=tuple(sorted(FIELDS)),
            coverage="Authorized stations and expected family channels in the window; PG and permanent history share the same scope.",
            completeness="Confirmed station/channel collection intervals divided by expected station/channel/window duration; currently not_proven without continuity evidence. Rows and pagination are not the numerator.",
            denominator="Разрешённые станции × ожидаемые каналы выбранного семейства × период; число строк не доказывает полноту.",
            retention="Process/USB evidence moves from PG after the configured period only on exact permanent-history readback; held observations remain hot.",
            provenance="Immutable observation ID, agent identity, native event ID, family and source observation time.",
            primary_archetype="timeline",
            product_archetype="investigation-evidence",
            deterministic_policy=f"Present only native {family} observations for server-bound agents; immutable ID orders PG/history pages without inferring activity.",
            result_limits=f"At most {MAX_STATIONS} authorized stations, {max_days} days and {MAX_LIMIT} rows per page; continuity is not_proven.",
            fallback="Missing identity adapter fails closed; unavailable permanent history exposes PG-only partial data; conflicting receipts fail visibly.",
            acceptance_lanes={
                "product_user": f"Observed {family} events answer the workstation question without inferring work duration or file copying.",
                "authorization": f"{key} grant, atomic fields and server identity binding constrain PG, history and detail.",
                "deterministic_interpretation": f"Native {family} facts retain immutable identity and do not imply compliance or collection continuity.",
                "api_view_model": f"{family} pages preserve station, window and row bounds across PG/history deduplication.",
                "ui_honest_states": f"{family} adapter failure, history loss and continuity not_proven remain explicit.",
                "evidence_audit": f"{family} observation retains agent, native event identity, source time and applicable source hashes.",
            },
        ),
        params=(Param.period(max_days=max_days), Param.text("agent_key", "Ключ агента")),
        columns=(Column("observed_at", "Время", "datetime"), Column("host_name", "Компьютер"),
                 Column("agent_key", "Ключ агента", optional=True),
                 Column("event_id", "Событие", "number"), Column("semantic_type", "Тип"),
                 *((Column("protection_state", "Снимок защиты", "state", path="quality.state",
                            labels={"available": "Получен", "unavailable": "Недоступен"}),)
                   if family == "protection" else ()),
                 *(Column(field, label, "boolean" if field.endswith("_enabled") or field == "tamper_protected" else "text",
                          path=f"facts.{field}") for field, label in FACT_COLUMNS[family])),
        query=query, row_key="id",
        detail=Detail(title="Исходное наблюдение", key="id",
                      columns=(Column("observed_at", "Время", "datetime"), Column("agent_key", "Ключ агента"),
                               Column("event_id", "Событие", "number"),
                               Column("source_xml", "Исходный XML"), Column("source_sha256", "SHA-256 XML"),
                               Column("observation_sha256", "SHA-256 наблюдения")),
                      query=lambda context, row_id: read_report(context, family, definition, row_id)) if family in history.FAMILIES else "fields",
        # Bound cold heap/TOAST reads as well as the ID lookup on the first page.
        default_limit=25 if family == "processes" else 100, max_limit=MAX_LIMIT,
    )
    return definition

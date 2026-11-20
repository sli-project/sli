"""Read-only v2 products over retained, server-scoped file-audit evidence."""
import csv
import io
import json
from dataclasses import replace
from datetime import datetime

from psycopg import OperationalError, errors

from server.sli.core.messages import message
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.plugins.file_audit.access import require_access
from server.sli.plugins.file_audit.acl import access_mask, parse_dacl
from server.sli.plugins.file_audit.contracts import CAPABILITIES, PLUGIN_ID, REPORT_KEYS
from server.sli.plugins.file_audit.report_intents import make_intent
from server.sli.reporting.v2.access import ReportAccess, resolve_access_scope
from server.sli.reporting.v2.definition import (
    AccessRequirement,
    AccessRule,
    Column,
    Detail,
    Param,
    ReportDefinition,
    View,
    result,
)

FIELDS = frozenset({"identity_basic", "technical", "security", "privilege"})
TITLES = ("Обзор", "Действия с файлами", "Массовые операции", "Изменения доступа",
          "Отказы доступа", "Вне рабочего времени", "Права доступа", "Состояние аудита")
OPERATIONS = (("read", "Чтение"), ("write", "Запись"), ("delete", "Удаление"),
              ("rename", "Переименование"),
              ("delete_right", "Операция с правом удаления"), ("permissions", "Права"),
              ("share_change", "Настройки шары"), ("audit_change", "Аудит"),
              ("access_check", "Проверка доступа"), ("unknown", "Неизвестно"))
UNREADABLE = (OperationalError, errors.UndefinedFunction, errors.UndefinedTable, errors.InsufficientPrivilege)


def share_key(root):
    # Share names and collection IDs are not unique across servers.
    return json.dumps([root[key] for key in ("agent_id", "source_instance_id", "collection_scope_id")], separators=(",", ":"))


def admitted_roots(cur, context):
    cur.execute("select sli_plugin_file_audit.report_roots() as roots")
    roots = cur.fetchone()["roots"]
    if len(roots) > 1000:
        raise ValueError("file_audit_root_limit")
    admitted = []
    for root in roots:
        resource = {"agent_id": root["agent_id"], "source_instance_id": root["source_instance_id"],
                    "collection_scope_id": root["collection_scope_id"]}
        if not context.scope.allows(plugin_id=PLUGIN_ID, device_id=root["agent_id"],
                source_instance_id=root["source_instance_id"], collection_scope_id=root["collection_scope_id"]):
            continue
        try:
            require_access(context.access, action=context.action, **resource)
        except PermissionError:
            continue
        admitted.append(root)
    return admitted


def share_options(roots):
    return [{"value": share_key(root), "label": f"{root['source_name']} · {root['share_name'] or root['path']}",
             "important": root.get("important", False)} for root in roots]


def group_assignments(inventory, employee=None):
    rows = []
    for root in inventory:
        smb, smb_known = parse_dacl(root.get("share_dacl"))
        ntfs, ntfs_known = parse_dacl(root.get("root_dacl"))
        known = set(root.get("group_sids") or []) | {"S-1-1-0", "S-1-5-11", "S-1-5-32-544", "S-1-5-32-545"}
        sids = sorted({ace.sid for ace in (*smb, *ntfs) if ace.kind == "A" and not ace.inherit_only
                       and (ace.sid in known or ace.sid.startswith("S-1-5-21-") and ace.sid.endswith("-513"))})
        for sid in sids:
            if employee and employee != sid:
                continue
            rows.append({"share_label": root["share_label"], "subject_sid": sid,
                "smb_mask": access_mask(smb, {sid}) if smb_known and root.get("share_complete") else None,
                "ntfs_mask": access_mask(ntfs, {sid}) if ntfs_known else None, "observed_at": root["observed_at"]})
    return rows[:1000]


def _read(cur, tab, context, roots):
    selected = context.params.get("share", [])
    if selected:
        roots = [root for root in roots if share_key(root) in selected]
    period = context.params["period"]
    after = None
    if context.cursor:
        try:
            after = json.loads(context.cursor)
            if not isinstance(after, dict) or set(after) != {"at", "id"} or not all(isinstance(v, str) for v in after.values()):
                raise ValueError
            if datetime.fromisoformat(after["at"]).utcoffset() is None:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError("report_cursor_invalid") from None
    if not roots:
        return {"items": [], "filtered_count": 0, "has_more": False, "after": None}
    # Keep the SQL function's identity and ACL: its cursor JSON also carries
    # the display option. The external cursor remains only {at, id}.
    options = {**(after or {}), "show_service": context.params.get("show_service", "false") == "true"}
    cur.execute("""select sli_plugin_file_audit.report_rows(%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s) as data""",
        (json.dumps(roots), tab, period["from_utc"], period["to_utc"], context.params.get("path"),
         context.params.get("include_nested", "true") == "true", context.params.get("employee"),
         context.params.get("operation"), json.dumps(options), context.limit))
    data = cur.fetchone()["data"]
    if data.get("service_filter_version") != 1:
        raise errors.UndefinedFunction("file audit service filter migration required")
    return data


def ransom_details(cur, context, roots, items):
    """QW episode metadata needs queue authority as well as native file scope."""
    try:
        queue_scope = resolve_access_scope(context.access, AccessRule("security.queue", frozenset({"security"})), context.action)
        allowed = [root for root in roots if queue_scope.allows(plugin_id=PLUGIN_ID, device_id=root["agent_id"],
            source_instance_id=root["source_instance_id"], collection_scope_id=root["collection_scope_id"])]
    except PermissionError:
        allowed = []
    decisions = {}
    if allowed and items:
        cur.execute("select public.read_file_ransom_details(%s::jsonb,%s::jsonb) as decisions", (
            json.dumps(allowed), json.dumps([row["id"] for row in items])))
        decisions = cur.fetchone()["decisions"]
    admitted = {(root["agent_id"], root["source_instance_id"], root["collection_scope_id"]) for root in allowed}
    for row in items:
        if row["rule_code"] not in {"file-audit.mass-write", "file-audit.mass-delete"}:
            row["ransom"] = {"state": "not_applicable"}
        elif tuple(row.get(key) for key in ("agent_id", "source_instance_id", "collection_scope_id")) not in admitted:
            row["ransom"] = {"state": "denied"}
        else:
            row["ransom"] = decisions.get(row["id"], {"state": "not_evaluated"})


def query(tab, context):
    definition = REPORTS[REPORT_KEYS.index(tab)]
    try:
        with connect() as conn, conn.cursor() as cur:
            # One snapshot for metadata, admission and page/count reads.
            cur.execute("set transaction isolation level repeatable read, read only")
            roots = admitted_roots(cur, context)
            source_kind = context.params.get("source_kind")
            if source_kind:
                roots = [root for root in roots if root.get("source_kind", "server") == source_kind]
            data = _read(cur, tab, context, roots)
            if tab == "mass-operations":
                ransom_details(cur, context, roots, data["items"])
    except errors.QueryCanceled:
        return result(definition, state="error", coverage={"state": "unavailable", "reason": "source_timeout"},
            limitations=[{"code": "source_timeout", "text": message("reports.file-audit.source_timeout")["text"]}])
    except UNREADABLE:
        return result(definition, state="error", coverage={"state": "unavailable", "reason": "source_unreadable"})
    except ValueError as exc:
        if str(exc) != "file_audit_root_limit":
            raise
        return result(definition, state="partial", coverage={"state": "unknown", "reason": "result_truncated"},
            limitations=[{"code": "root_limit", "text": "Область превышает 1000 шар. Уточните назначенную область доступа."}])
    items = data["items"]
    by_root = {(r["agent_id"], r["source_instance_id"], r["collection_scope_id"]): r for r in roots}
    for row in items:
        root = by_root.get(tuple(row.get(key) for key in ("agent_id", "source_instance_id", "collection_scope_id")), {})
        row["share_label"] = f"{root.get('source_name', '—')} · {root.get('share_name') or root.get('path', '—')}"
        row["operation"] = row.get("operation") or row.get("details", {}).get("operation")
        if tab == "mass-operations":
            row["operation"] = row["rule_code"].removeprefix("file-audit.mass-")
            details = row["details"]
            row["files_per_minute"] = round(details["distinct_files"] * 60 / details["window_seconds"], 1)
        if tab in ("overview", "audit-state") and not row.get("snapshot_id"):
            row["folders_with_read_audit"] = None
        if tab == "audit-state":
            row["delivery_state"] = ("unknown" if "delivery_received_at" not in row else
                "not_received" if row["delivery_received_at"] is None else
                "imported" if row.get("delivery_imported_at") else "pending_import")
        # Native IDs stay available when identity enrichment is absent.
        row["employee"] = row.get("subject_sid")
        if tab == "out-of-hours":
            row["path"] = next((e.get("path") for e in row.get("evidence", []) if e.get("path")), None)
    coverage = {"state": "unknown", "reason": "coverage_incomplete", "completeness": "not_proven"}
    if tab in ("overview", "audit-state", "permissions") and items:
        times = [row["observed_at"] for row in items if row.get("observed_at")]
        if times:
            coverage.update(observed_at_utc=max(times), freshness_threshold_seconds=86400)
    summary = data.get("summary", {})
    response = result(definition, state="partial" if roots else "not_collected", items=items,
        filtered_count=data["filtered_count"] if roots else None, has_more=data["has_more"],
        next_cursor=json.dumps(data["after"], separators=(",", ":")) if data["has_more"] else None,
        filter_options={"share": share_options(roots)}, coverage=coverage,
        metrics=[{"key": key, "label": label, "value": summary.get(key),
                  "quality": "observed" if summary.get(key) is not None else "unknown",
                  "filter": {} if key == "denials" else {"operation": key}}
                 for key, label in (("read", "Чтения"), ("write", "Записи"), ("delete", "Удаления"), ("denials", "Отказы"))],
        collections={"timeline": data.get("timeline", [])} if tab == "overview" else
            {"groups": group_assignments(data.get("inventory", []), context.params.get("employee"))} if tab == "permissions" else {},
        limitations=[{"code": "coverage_unverified", "text": "Полнота сбора за выбранный период не подтверждена."}],
        window={"timezone": context.timezone, **context.params["period"]})
    if not roots or tab != "overview":
        response["metrics"] = []
    return response


def export(tab, context):
    if CAPABILITIES["export"] not in set(context.access.get("capabilities", [])):
        raise PermissionError("report_access_denied")
    definition = REPORTS[REPORT_KEYS.index(tab)]
    projection = ReportAccess(definition, context.access, "export")
    rows, cursor, truncated = [], None, False
    # A bounded export uses the same scope, predicates, cursor and time window.
    while len(rows) < 10000:
        data = projection.result(query(tab, replace(context, cursor=cursor, limit=100, action="export")))
        if data["state"] in ("error", "denied", "not_collected"):
            raise ValueError("report_export_unavailable")
        rows.extend(data["items"])
        truncated = data["has_more"]
        if not data["has_more"]:
            break
        cursor = data["next_cursor"]
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([column.label for column in definition.columns])
    for row in rows:
        values = []
        for column in definition.columns:
            value = row
            for key in (column.path or column.key).split("."):
                value = value.get(key) if isinstance(value, dict) else None
            text = column.labels.get(str(value), str(value)) if value is not None else ""
            # Formula injection protection applies to native paths and SIDs too.
            values.append("'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text)
        writer.writerow(values)
    return output.getvalue(), {"rows": len(rows), "truncated": truncated}


def _columns(tab):
    time = Column("observed_at", "Время", "datetime")
    employee = Column("employee", "Сотрудник")
    path = Column("path", "Объект")
    operation = Column("operation", "Действие", labels=dict(OPERATIONS))
    share = Column("share_label", "Шара")
    if tab == "overview":
        return (share, path, Column("actions", "Действий", "number"), Column("completeness", "Снимок", "state",
            labels={"complete": "Полный", "partial": "Неполный", "failed": "Ошибка"}), time)
    if tab == "audit-state":
        return (share, Column("folders_with_read_audit", "Папки с аудитом чтения", "number"),
                Column("delivery_state", "Последний пакет", "state", labels={"unknown": "Неизвестно",
                    "not_received": "Не принят", "pending_import": "Ожидает импорта", "imported": "Импортирован"}),
                Column("delivery_received_at", "Последний приём пакета", "datetime"),
                Column("delivery_imported_at", "Импорт принятого пакета", "datetime"),
                Column("delivery_record_id", "Принятый RecordID", "number"),
                Column("unread_objects", "Не прочитано", "number"), Column("audit_state", "Аудит", "state",
                    labels={"pending": "Ожидается", "verified": "Подтверждено", "partial": "Неполный",
                            "blocked": "Заблокировано", "failed": "Ошибка"}), time)
    if tab == "permissions":
        return (path, employee, Column("rule_code", "Причина проверки", labels={
            "file-audit.broad-write": "Широкая группа", "file-audit.direct-user-rights": "Прямое назначение",
            "file-audit.disabled-account-rights": "Учётка отключена", "file-audit.acl-review": "Требуется проверка"}),
            Column("share_mask", "SMB", "code", path="details.share_mask"),
            Column("ntfs_mask", "NTFS", "code", path="details.ntfs_mask"))
    if tab == "mass-operations":
        return (employee, share, operation, Column("window_start", "Начало окна", "datetime", path="details.window_start"),
                Column("window_end", "Конец окна", "datetime", path="details.window_end"),
                Column("distinct_files", "Разных файлов", "number", path="details.distinct_files"),
                Column("files_per_minute", "Файлов/мин", "number"))
    if tab == "out-of-hours":
        return (Column("local_time", "Местное время", path="details.local_time"), time, employee, path, operation)
    if tab == "access-denials":
        return (time, employee, Column("client_ip", "Клиент"), path, Column("denial_layer", "Уровень",
            labels={"smb": "SMB", "ntfs": "NTFS", "unknown": "Неизвестно"}), Column("access_mask", "Право", "code"))
    if tab == "permission-changes":
        return (time, employee, path, operation, Column("correlation_state", "Сопоставление", "state",
            labels={"not_attempted": "Не выполнено", "complete": "Установлено", "partial": "Неполное",
                    "ambiguous": "Неоднозначно"}))
    return (time, employee, Column("client_ip", "Клиент"), path, operation)


def _make_report(tab, title):
    return ReportDefinition(key=f"file-audit.{tab}", section="reports/file-audit", title=title,
        description="Аудит файловых серверов MS", archetype="list",
        access=AccessRequirement(f"file-audit.{tab}", FIELDS, frozenset({CAPABILITIES['view']})),
        params=(Param.period(default="24h", max_days=31, presets=("24h", "7d", "30d", "custom")),
                Param.choice("source_kind", "Источник", (("server", "Серверы"), ("workstation", "Рабочие станции"))),
                Param.text("path", "Объект", max_length=4096), Param.choice("include_nested", "Включая вложенные", (("true", "Да"), ("false", "Нет")), default="true"),
                Param.text("employee", "Сотрудник"), Param("share", "Шара", "multichoice", options_from="share"),
                Param.choice("operation", "Действие", OPERATIONS),
                Param.choice("show_service", "Показать служебные", (("false", "Нет"), ("true", "Да")), default="false")),
        columns=_columns(tab), row_key="id", query=lambda context: query(tab, context),
        export_csv=lambda context: export(tab, context), default_limit=50, max_limit=100,
        views=(View("table"),) + ((View("chart", key="timeline", title="Действия за период", source="timeline",
            chart="timeseries", x="at", series=(("Действия", "actions"),)),) if tab == "overview" else
            (View("table", key="groups", title="Групповой доступ к шарам", source="groups", columns=(
                Column("share_label", "Шара"), Column("subject_sid", "Группа"), Column("smb_mask", "SMB", "code"),
                Column("ntfs_mask", "NTFS", "code"), Column("observed_at", "Снимок", "datetime"))),) if tab == "permissions" else ()), intent=make_intent(tab),
        detail=Detail("Сохранённые свидетельства", "id", (
            Column("reference", "Ссылка", "code"), Column("event_id", "Событие", "number"),
            Column("record_id", "Запись", "number"), Column("generation", "Поколение", "code"),
            Column("path", "Объект"), Column("operation", "Действие", labels=dict(OPERATIONS)),
            Column("payload_sha256", "SHA-256", "code")), inline="evidence"))


REPORTS = tuple(_make_report(tab, title) for tab, title in zip(REPORT_KEYS, TITLES, strict=True))


def reports():
    return REPORTS

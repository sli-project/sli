type ActorId = "alex" | "marina" | "dmitry" | "admin";

const actor = (): ActorId => {
  const value = localStorage.getItem("sli-v4-user") ?? new URLSearchParams(location.search).get("fixtureActor");
  return value === "marina" || value === "dmitry" || value === "admin" ? value : "alex";
};

const actors = {
  alex: { short: "Алексей К.", full: "Алексей Кузнецов", role: "Специалист ИБ / участник AD-аудита", packages: [["sec-operators", "ИБ · операторы"], ["ad-auditors", "AD · аудит и сопровождение"]], direct: true },
  marina: { short: "Марина О.", full: "Марина Орлова", role: "Оператор ИБ", packages: [["sec-operators", "ИБ · операторы"]], direct: false },
  dmitry: { short: "Дмитрий С.", full: "Дмитрий Соколов", role: "Аналитик ИБ / участник AD-аудита", packages: [["sec-analysts", "ИБ · аналитики"], ["ad-auditors", "AD · аудит и сопровождение"]], direct: true },
  admin: { short: "Елена В.", full: "Елена Волкова", role: "Эксплуатация проекта / администрирование доступа", packages: [["project-ops", "Проект · эксплуатация"], ["access-admins", "Администрирование доступа"]], direct: false },
} as const;

const reportDefinitions = [
  ["security.queue", "Очередь проблем ИБ", "Короткая очередь: что произошло, вероятная причина и безопасное следующее действие.", "security.problems", "Отдел ИБ", "/app/problems", 3.2, "Служебные данные"],
  ["event.evidence", "События и доказательства", "Точные события, Event ID, источник, UTC, исходные поля и переходы к объектам.", "evidence.events_v2", "Отдел ИБ", "/app/events", 2.6, "Технические данные"],
  ["cases.workspace", "Расследования", "Дела, временные линии, подтверждённые и исключённые доказательства, решения аналитика.", "cases.workspace", "Отдел ИБ", "/app/cases", 2.1, "Служебные данные"],
  ["ad.state", "Состояние и риски Active Directory", "Сводка домена, DC, Kerberos, LDAP, учётных записей, компьютеров и качества AD.", "ad.audit.snapshot", "ИТ-служба", "/app/ad-report", 4.0, "Персональные и технические данные"],
  ["ad.gpo.review", "GPO — очередь ручной проверки", "Приоритеты P1–P4, владельцы, возраст, скрипты, резервная копия и план отката.", "ad.gpo.governance", "ИТ-служба", "/app/gpo-report", 3.4, "Технические данные"],
  ["ad.privileged", "Привилегированные учётные записи", "Прямые и вложенные привилегии, активность, парольные исключения и подтверждение владельца.", "ad.accounts.privileged", "ИБ + ИТ", "/app/privileged-report", 2.8, "Персональные данные"],
  ["vpn.audit", "VPN-доступ и актуальность владельцев", "Активные, неактивные и привилегированные VPN-пользователи с контекстом учётной записи.", "ad.access.vpn", "ИТ-служба", "/app/vpn-report", 1.9, "Персональные данные"],
  ["platform.readiness", "Готовность и устойчивость проекта", "Источники, службы, очереди, PostgreSQL, резервные копии, PITR и технические ограничения.", "platform.readiness", "Администратор проекта", "/app/project-readiness", 3.1, "Внутренние технические данные"],
  ["platform.events", "Технические события проекта", "Журнал сбора, обработки, хранения и диагностических проверок платформы.", "platform.events", "Администратор проекта", "/app/project-readiness", 1.7, "Внутренние технические данные"],
] as const;

const allowedReportKeys = (id: ActorId) => id === "admin"
  ? new Set(["platform.readiness", "platform.events"])
  : id === "marina"
    ? new Set(["security.queue"])
    : id === "dmitry"
      ? new Set(["ad.state", "ad.gpo.review", "ad.privileged", "event.evidence", "cases.workspace"])
      : new Set(["security.queue", "ad.state", "ad.gpo.review", "ad.privileged"]);

const pinnedReportKeys = (id: ActorId) => id === "admin"
  ? new Set(["platform.readiness", "platform.events"])
  : id === "marina"
    ? new Set(["security.queue"])
    : id === "dmitry"
      ? new Set(["event.evidence", "cases.workspace", "ad.state", "ad.privileged"])
      : new Set(["security.queue", "ad.state", "ad.privileged", "ad.gpo.review"]);

const capabilities = (id: ActorId) => id === "admin"
  ? ["access.manage", "report.publish", "report.design", "project.readiness"]
  : id === "marina"
    ? ["entity.view", "entity.basic", "entity.states", "finding.summary", "problem.view", "problem.act"]
    : id === "dmitry"
      ? ["entity.view", "entity.basic", "entity.groups", "entity.privileges", "entity.activity", "entity.states", "entity.findings", "entity.evidence", "entity.technical", "event.view", "case.view", "case.create", "report.export"]
      : ["entity.view", "entity.basic", "entity.groups", "entity.privileges", "entity.states", "entity.findings", "problem.view", "problem.act", "case.create", "task.create", "report.export"];

function reports(id: ActorId) {
  const allowed = allowedReportKeys(id);
  const pinned = pinnedReportKeys(id);
  return reportDefinitions.map(([report_key, name, purpose, dataset_key, owner, target_path, version, sensitivity]) => {
    const isAllowed = allowed.has(report_key);
    const isRequestable = !isAllowed && !report_key.startsWith("platform.");
    return ({
    report_key, version, name, owner, purpose, dataset_key, dataset_version: 1,
    sensitivity, discoverable: true, requestable: isRequestable,
    access_state: isAllowed ? "available" : isRequestable ? "requestable" : "request_unavailable",
    request_profile: isRequestable ? { scope_kinds: ["domain", "server"], max_days: 30 } : undefined,
    status: "published", target_path, allowed: isAllowed,
    explanation: isAllowed ? (report_key === "ad.privileged" && (id === "alex" || id === "dmitry") ? `Назначен напрямую до ${id === "dmitry" ? "30.09.2026" : "31.12.2026"}` : `Доступ через ${report_key.startsWith("ad.") ? "группа AD · аудит" : report_key.startsWith("platform.") ? "группа Проект · эксплуатация" : id === "dmitry" ? "группа ИБ · аналитики" : "группа ИБ · операторы"}`) : "Доступ не назначен",
    missing_capabilities: isAllowed ? [] : ["report.view"], field_categories: /^(ad\.|vpn\.)/.test(report_key) ? ["identity.basic", "pii.contact", "pii.hr", "ad.attributes"] : report_key.startsWith("platform.") ? ["platform.technical"] : ["identity.basic"], allowed_actions: isAllowed ? ["view", "export"] : [], scopes: [{ kind: "domain", values: /^(ad\.|vpn\.)/.test(report_key) ? ["host5.example.invalid", "OU=Users_KHV"] : report_key.startsWith("platform.") ? ["platform"] : ["host5.example.invalid"] }],
    sources: isAllowed ? [{ source_type: report_key === "ad.privileged" && (id === "alex" || id === "dmitry") ? "direct" : "group", source: report_key === "ad.privileged" ? "Распоряжение ИБ-128" : actors[id].packages[0][1], valid_until: report_key === "ad.privileged" ? "2026-12-31" : null }] : [],
    pinned: pinned.has(report_key),
  })});
}

function access(id: ActorId) {
  const currentReports = reports(id);
  return { api_version: "v4", evaluated_at_utc: "2026-07-17T11:05:00Z", preview: false,
    subject: { type: "fixture", id: id === "alex" ? 1 : id === "marina" ? 2 : id === "dmitry" ? 3 : 4, username: actors[id].short, coarse_role: id === "admin" ? "admin" : "operator" },
    groups: actors[id].packages.map(([key, name], index) => ({ id: index + 1, key, name, source: "fixture" })),
    packages: actors[id].packages.map(([key, name]) => ({ key, name })), package_explain: [], capabilities: capabilities(id), capability_explain: {}, reports: currentReports,
    allowed_report_count: currentReports.filter((item) => item.allowed).length,
    navigation: [], explicit_denies: { packages: [], capabilities: [], reports: [] },
  };
}

const recentObjects = [
  { object_type: "ad_user", object_id: "ivanov", display_name: "Иванов Иван Петрович", natural_key: "CORP\\ivanov", source: "Пользователь AD", freshness: "Включён", last_seen_utc: "2026-07-17T11:02:00Z" },
  { object_type: "service_account", object_id: "svc-backup", display_name: "svc-backup", natural_key: "CORP\\svc-backup", source: "Сервисная учётная запись", freshness: "Заблокирована", last_seen_utc: "2026-07-17T10:50:00Z" },
  { object_type: "computer", object_id: "app-srv-03", display_name: "APP-SRV-03", natural_key: "Windows Server 2019", source: "Компьютер", freshness: "Активен", last_seen_utc: "2026-07-17T10:53:00Z" },
  { object_type: "ad_group", object_id: "backup-operators", display_name: "Backup Operators", natural_key: "CORP\\Backup Operators", source: "Группа AD", freshness: "Привилегированная", last_seen_utc: "2026-07-17T11:01:00Z" },
];

const allObjects = [...recentObjects,
  { object_type: "gpo", object_id: "workstation-baseline", display_name: "Workstation Security Baseline", natural_key: "{4A91…E331}", source: "GPO", freshness: "Нужна проверка", last_seen_utc: "2026-07-17T10:40:00Z" },
  { object_type: "domain_controller", object_id: "dc2", display_name: "DC2", natural_key: "dc2.host5.example.invalid", source: "Контроллер домена", freshness: "Работает", last_seen_utc: "2026-07-17T11:04:00Z" },
  { object_type: "ad_user", object_id: "adm-kuznetsov", display_name: "Кузнецов Алексей Сергеевич", natural_key: "CORP\\adm.kuznetsov", source: "Пользователь AD", freshness: "Привилегированный", last_seen_utc: "2026-07-17T10:59:00Z" },
  { object_type: "ad_group", object_id: "vpnl2tp", display_name: "VPNl2tp", natural_key: "430 участников", source: "Группа AD", freshness: "Доступ VPN", last_seen_utc: "2026-07-17T10:51:00Z" },
];

function workspace(id: ActorId) {
  const a = access(id); const allowed = a.reports.filter((item) => item.allowed);
  return { api_version: "v4", state: "ready", subject: { ...a.subject, username: actors[id].full, coarse_role: actors[id].role }, packages: a.packages, groups: a.groups, capabilities: a.capabilities, reports: allowed, recent_objects: id === "admin" ? [] : recentObjects,
    composition: { package_count: a.packages.length, group_count: a.groups.length, direct_report_count: actors[id].direct ? 1 : 0, allowed_report_count: allowed.length, explicit_deny_count: 0 }, limits: {} };
}

const eventRows = [
  { event_db_id: 12854801, event_id: 4728, time_created_utc: "2026-07-19T06:37:06Z", server: "DC2", channel: "Security", provider_name: "Microsoft-Windows-Security-Auditing", label: "Участник добавлен в привилегированную группу", subject: "CORP\\adm.kuznetsov", target: "CORP\\ivanov", final_risk: "high", display_labels: { risk: "Высокий" } },
  { event_db_id: 12853680, event_id: 4624, time_created_utc: "2026-07-19T05:48:10Z", server: "DC2", channel: "Security", provider_name: "Microsoft-Windows-Security-Auditing", label: "Успешный сетевой вход в систему", subject: "CORP\\ivanov", target: "APP-SRV-03", final_risk: "low", display_labels: { risk: "Низкий" } },
  { event_db_id: 12853127, event_id: 4769, time_created_utc: "2026-07-19T05:21:44Z", server: "DC1", channel: "Security", provider_name: "Microsoft-Windows-Security-Auditing", label: "Запрошен сервисный билет Kerberos", subject: "CORP\\ivanov", target: "cifs/files01.host5.example.invalid", final_risk: "low", display_labels: { risk: "Низкий" } },
  { event_db_id: 12849770, event_id: 4723, time_created_utc: "2026-07-18T10:26:31Z", server: "DC2", channel: "Security", provider_name: "Microsoft-Windows-Security-Auditing", label: "Выполнена попытка смены пароля", subject: "CORP\\ivanov", target: "CORP\\ivanov", final_risk: "medium", display_labels: { risk: "Средний" } },
];

function objectDetail(id: ActorId) {
  const full = id === "dmitry";
  const tabs = ["overview", "groups", "privileges", "activity", "states", "findings", "evidence", "technical"].map((tab) => ({ id: tab, label: ({ overview: "Обзор", groups: "Членство в группах", privileges: "Доступ и привилегии", activity: "Активность", states: "Состояние и изменения", findings: "Находки", evidence: "Доказательства", technical: "Технические данные" } as Record<string,string>)[tab], available: id === "marina" ? ["overview", "findings"].includes(tab) : id === "alex" ? !["activity", "evidence", "technical"].includes(tab) : full }));
  return { api_version: "v4", state: "ready", object: { ...recentObjects[0], first_seen_utc: "2024-02-12T08:14:00Z", latest_state: { status: "требует внимания" } }, identity_contract: "unified_object_v4", tabs,
    provenance: [{ source: "AD snapshot", observed_at_utc: "2026-07-17T11:02:00Z", freshness: "актуально" }, { source: "Windows logs", observed_at_utc: "2026-07-17T10:48:00Z", freshness: "12 минут" }, { source: "AD Context", observed_at_utc: "2026-07-17T10:58:00Z", freshness: "актуально" }],
    current_states: [{ id: 1, state_type: "Учётная запись", status: "включена", summary: "enabled", observed_at_utc: "2026-07-17T11:02:00Z" }, { id: 2, state_type: "Привилегия", status: "требует аттестации", summary: "Backup Operators", observed_at_utc: "2026-07-17T10:58:00Z" }],
    findings: [{ id: 1, title: "Вложенное членство в Backup Operators без подтверждённого владельца", severity: "высокий", status: "открыта", summary: "Доступ требует аттестации.", evidence_event_id: 12854801 }],
    events: eventRows, events_state: "available", identity_links: [{ relation_type: "nested_membership", source_name: "IT-Helpdesk", target_object_id: "Backup Operators", confidence: "высокая", observed_at: "2026-07-17T10:58:00Z" }],
    directory_context: { items: [{ context_evidence_id: 501, context_kind: "entity", source_section: "AD user", source_pack_id: "ad-20260717", observed_at_utc: "2026-07-17T11:02:00Z", current: true, attributes: { display_name: "Иванов Иван Петрович", sam_account_name: "ivanov", user_principal_name: "ivanov@host5.example.invalid", mail: "ivanov@host5.example.invalid", department: "ИТ", distinguished_name: "CN=Иванов Иван,OU=Users_KHV,DC=corp,DC=local", object_sid: "S-1-5-21-1000-1104" } }] },
    actions: id === "marina" ? ["copy_link", "start_case"] : ["copy_link", "create_task", "start_case"], limitations: ["Покрытие DC1 частичное: backlog 18 минут."],
  };
}

function reportData(key: string, id: ActorId) {
  const fixtureKey = key === "events.explorer" ? "event.evidence" : key;
  const sourceReport = reports(id).find((item) => item.report_key === fixtureKey);
  if (!sourceReport?.allowed) return null;
  const report = key === "events.explorer"
    ? { ...sourceReport, report_key: key, dataset_key: "events.v2" }
    : sourceReport;
  const base = key === "security.queue" ? [
    { id: "privilege-path", priority: "P1", severity: "critical", metric_group: "critical", status: "in_progress", title: "CORP\\ivanov получил вложенную привилегию Backup Operators", probable_cause: "пользователь входит в IT-Helpdesk, которую добавили в привилегированную группу. Подтверждённый владелец доступа не найден.", limitation: "покрытие DC1 частичное", age_label: "22 минуты назад", object_type: "ad_user", object_id: "ivanov", open_label: "Открыть карточку", action_label: "В расследование", action_primary: false },
    { id: "svc-backup-lockout", priority: "P1", severity: "high", metric_group: "high", status: "in_progress", title: "Сервисная учётная запись svc-backup регулярно блокируется", probable_cause: "служба на APP-SRV-03 может использовать старый пароль. Причина требует проверки ИТ.", limitation: "14 ошибок входа", age_label: "17 минут назад", action_label: "Передать ИТ", action_primary: true },
    { id: "inventory-sync", priority: "P2", severity: "medium", metric_group: "medium", status: "open", title: "На DC1 создана новая запланированная задача", cause_label: "Причина не установлена:", probable_cause: "событие подтверждает создание InventorySync учётной записью deploy.bot; назначение требует владельца.", limitation: "вывод предварительный", age_label: "53 минуты назад", action_label: "Создать проверку", action_primary: false },
  ] : key === "events.explorer" ? eventRows.map((row) => ({
    id: row.event_db_id,
    time_created_utc: row.time_created_utc,
    event_id: row.event_id,
    channel: row.channel,
    subject_user_name: row.subject,
    target_user_name: row.target,
  })) : key === "ad.privileged" ? [{ display_name: "Иванов Иван Петрович", account: "CORP\\ivanov", privilege: "Backup Operators", path: "IT-Helpdesk → Backup Operators", changed_at: "Сегодня 12:48", age_days: 153, owner: "Не подтверждён", priority: "P1" }]
    : key === "ad.gpo.review" ? [{ gpo: "Workstations Security Baseline", change: "Изменена привязка", owner: "Не подтверждён", backup: "2026-07-10", rollback: "Требуется", priority: "P1" }]
    : [{ domain: "host5.example.invalid", users: 1428, computers: 816, privileged_paths: 3, stale_objects: 27, status: "требует внимания" }];
  const fields = Object.keys(base[0]).map((field) => ({ key: field, label: ({ id: "ID в БД", time_created_utc: "Время UTC", event_id: "Event ID", channel: "Канал", subject_user_name: "Инициатор", target_user_name: "Цель", priority: "Приоритет", category: "Категория", title: "Проблема", probable_cause: "Вероятная причина", limitation: "Ограничение данных", allowed_action: "Разрешённое действие", object: "Объект", display_name: "Пользователь", account: "Учётная запись", privilege: "Привилегия", path: "Путь", changed_at: "Изменено", age_days: "Возраст", owner: "Владелец", gpo: "GPO", change: "Изменение", backup: "Backup", rollback: "Откат", domain: "Домен", users: "Пользователи", computers: "Компьютеры", privileged_paths: "Пути привилегий", stale_objects: "Неактуальные объекты", status: "Статус" } as Record<string,string>)[field] ?? field, category: "identity.basic" }));
  return { api_version: "v4", report, dataset_key: report.dataset_key, state: key === "events.explorer" ? "available" : "ready", items: base, fields, has_more: false, next_cursor: null, limits: {} };
}

function datasets() {
  return { api_version: "v4", arbitrary_sql_allowed: false, items: [{ dataset_key: "ad.privileged", version: 1, name: "Аттестация привилегий", purpose: "Безопасный dataset привилегированных путей", fields_json: ["display_name", "account", "privilege", "path", "owner", "priority"].map((key) => ({ key, label: key === "display_name" ? "Пользователь" : key, category: "identity.basic" })), filters_json: [{ key: "priority", ops: ["eq", "in"] }, { key: "owner", ops: ["eq", "contains"] }], sort_json: ["display_name", "priority"], actions_json: ["view", "export", "create_task"] }] };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

export function installFixtureApi() {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw, location.origin); const path = url.pathname; const id = actor();
    if (!path.startsWith("/api/")) return nativeFetch(input, init);
    if (path === "/api/v1/ui/bootstrap") return json({ api_version: "v1", principal: { username: actors[id].short, role: id === "admin" ? "admin" : "operator" }, effective_role: id === "admin" ? "admin" : "operator", navigation: [], api_time_contract: "UTC", access_model: "composite_v4", capabilities: capabilities(id), packages: access(id).packages, allowed_report_count: access(id).allowed_report_count });
    if (path === "/api/v1/workspace") return json(workspace(id));
    if (path === "/api/v1/reports/catalog") { const items = reports(id); return json({ api_version: "v4", state: "ready", items, allowed_count: items.filter((item) => item.allowed).length, total_count: items.length, explain_contract: "composite_v4" }); }
    if (/^\/api\/v1\/reports\/[^/]+\/data$/.test(path)) { const result = reportData(decodeURIComponent(path.split("/")[4]), id); return result ? json(result) : json({ detail: "report_access_denied" }, 403); }
    if (path === "/api/v1/access/effective") return json(access(id));
    if (path === "/api/v1/access/subjects") return json({ users: Object.entries(actors).map(([key, value], index) => ({ id: index + 1, username: value.full, role: key === "admin" ? "admin" : "operator", is_active: true })), groups: [], packages: [], assignments: [], package_assignments: [] });
    if (path === "/api/v1/access/audit") return json({ items: [], limit: 100 });
    if (path === "/api/v1/objects") return json({ api_version: "v4", query: url.searchParams.get("q") ?? "", state: "ready", items: id === "admin" ? [] : allObjects, has_more: false, limits: {} });
    if (/^\/api\/v1\/objects\/[^/]+\/[^/]+$/.test(path)) return id === "admin" ? json({ detail: "forbidden" }, 403) : json(objectDetail(id));
    if (path === "/api/v1/reports/datasets") return id === "admin" ? json(datasets()) : json({ detail: "forbidden" }, 403);
    if (path === "/api/v1/reports/builder/preview") return json({ state: "allowed", required_capabilities: ["report.publish"], field_categories: ["identity.basic"], policy_gate: "passed" });
    if (path === "/api/v1/reports/definitions" || path === "/api/v1/access/assignments") return json({ item: { status: "saved" } });
    if (path === "/api/v1/events") return id === "marina" || id === "admin" ? json({ detail: "forbidden" }, 403) : json({ api_version: "v1", items: eventRows, has_more: false, query_status: "ok" });
    if (path === "/api/v1/investigation-cases") return json({ items: [{ id: 41, public_id: "CASE-2026-0041", title: "Изменение привилегий CORP\\ivanov", status: "На проверке", owner: "А. Кузнецов", evidence_count: 12, updated_at: "сегодня", created_by: "fixture", created_at: "2026-07-19" }, { id: 38, public_id: "CASE-2026-0038", title: "Блокировки svc-backup", status: "Открыто", owner: "Н. Орлова", evidence_count: 8, updated_at: "сегодня", created_by: "fixture", created_at: "2026-07-19" }, { id: 33, public_id: "CASE-2026-0033", title: "Неожиданная задача InventorySync", status: "Подтверждено", owner: "Д. Соколов", evidence_count: 17, updated_at: "сегодня", created_by: "fixture", created_at: "2026-07-19" }], limit: 50 });
    if (path === "/api/v1/operations/overview") return json({ generated_at_utc: "2026-07-17T11:05:00Z", collector_health: { operations_slo: { status: "ok", label: "В норме", freshness_current: 6 } }, workers: { items: [{ worker_name: "collector-1", label: "Сбор событий", state: "active", phase: "idle", heartbeat_age_seconds: 4 }, { worker_name: "projection-1", label: "Проекция объектов", state: "active", phase: "processing", heartbeat_age_seconds: 7 }] }, postgres: { status: "ok", database: { database_human: "18.4 ГБ" }, long_running_queries: [] }, storage: { status: "ok", project_overview: { total_human: "42.8 ГБ" } } });
    if (path === "/api/auth/logout") return json({ status: "ok" });
    return json({ detail: `fixture_not_implemented:${path}` }, 404);
  };
}

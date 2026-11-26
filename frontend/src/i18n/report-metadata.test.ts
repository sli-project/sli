// @vitest-environment jsdom
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReportDefinitionDto, ReportResultDto } from "../api/report-v2-types";
import { en } from "./en";
import { localeRuntime, setLocale, t } from "./index";
import { localizeReportCatalog, localizeReportDefinition, localizeReportResult, localizeReportRow, reportMetadataText, reportPresetKey } from "./report-metadata";
import { setDisplayTimeZone } from "../design-system/format";
import { columnValue } from "../app/report-v2/state";
import { ru } from "./ru";
import { gpoReportDefinition } from "../plugins/ad/gpo-report";
import gpoDeclaration from "../../../server-dotnet/src/Sli.Server/Gpo/declaration.json";
import { testPython } from "../test-support/python";

it.each(["logons", "processes", "usb", "protection"])("localizes workstation %s scope limitations without changing access state", (family) => {
  const limitations = ["workstation_scope_unresolved", "workstation_scope_empty"].map((code) => ({
    code, text: ru[`reports.v2.workstations.${family}.limitations.${code}` as keyof typeof ru],
  }));
  const raw: ReportResultDto = { contract_id: "sli.report-result.v2", report_key: `workstations.${family}`, state: "partial",
    items: [], metrics: [], series: {}, coverage: { state: "not_proven", reason: "workstation_scope_empty" },
    filter_options: {}, window: {}, filtered_count: null, has_more: false, next_cursor: null, limitations };
  try {
    for (const locale of ["ru", "en"] as const) {
      setLocale(locale);
      const localized = localizeReportResult(raw);
      expect(localized.state).toBe("partial");
      expect(localized.items).toEqual([]);
      expect(localized.coverage).toEqual(raw.coverage);
      expect(localized.limitations.map((item) => item.text)).toEqual(limitations.map((item) =>
        (locale === "ru" ? ru : en)[`reports.v2.workstations.${family}.limitations.${item.code}` as keyof typeof ru]));
    }
  } finally { setLocale("ru"); }
});

it("translates AD values and local dates in both locales without changing evidence", () => {
  const row = { control_id: "trust.direction", actual_value: "BiDirectional", actual_text: "BiDirectional",
    object_context: { trust_partner: "unknown", last_replication_attempt_utc: "2026-10-08T04:05:00Z" },
    context: [{ code: "trust_partner", label: "Партнёр", value: "unknown" },
      { code: "last_replication_attempt_utc", label: "Последняя попытка", value: "2026-10-08T04:05:00Z" }] };
  setDisplayTimeZone("Asia/Bangkok");
  try {
    for (const locale of ["ru", "en"] as const) {
      setLocale(locale);
      const localized = localizeReportRow("ad.infrastructure", row);
      expect(localized.actual_text).toBe(locale === "ru" ? "Двустороннее" : "Bidirectional");
      expect(localized.actual_value).toBe("BiDirectional");
      expect(localized.object_context).toBe(row.object_context);
      const context = localized.context as Array<{ value: string }>;
      expect(context[0].value).toBe("unknown");
      expect(context[1].value).toContain(locale === "ru" ? "08.10.2026" : "Oct 8, 2026");
      expect(context[1].value).toContain("11:05");
    }
    expect(row.actual_text).toBe("BiDirectional");
  } finally { setDisplayTimeZone(undefined); setLocale("ru"); }
});

it("localizes the five user tabs, privilege basis and policy limitations", () => {
  setLocale("en");
  expect(["active", "disabled", "privileged", "risk", "semantic"].map((tab) => reportMetadataText("ad.users.v2", `views.${tab}.title`, "fallback")))
    .toEqual(["Active", "Disabled", "Privileged", "Risk", "Semantics"]);
  expect(reportMetadataText("ad.users.v2", "columns.privilege_basis.label", "fallback")).toBe("Privilege basis");
  const localized = localizeReportResult({ contract_id: "sli.report-result.v2", report_key: "ad.users.v2", state: "partial", items: [], metrics: [], series: {},
    coverage: { unknown_accounts: 2, hygiene_policy: { password_age: 120, inactivity: 30 } }, filter_options: {}, window: {},
    filtered_count: 0, has_more: false, next_cursor: null,
    branches: { users: { state: "partial", reason: "fixture_coverage", limitations: [{ code: "threshold", text: "fallback" }] } },
    limitations: [{ code: "unknown_accounts", text: "fallback" }, { code: "hygiene_policy", text: "fallback" }, { code: "threshold", text: "fallback" }] });
  expect(localized.limitations[0].text).toBe("Insufficient classification data: 2.");
  expect(localized.limitations[1].text).toContain("password age > 120 days; inactivity > 30 days");
  expect(localized.limitations[2].text).toContain("password age > 120 days; inactivity > 30 days");
  expect(localized.branches?.users.limitations[0].text).toContain("password age > 120 days; inactivity > 30 days");
});

// Read the actual registry without invoking queries or connecting to a database.
// Metrics are declared inside query functions, so inspect their metadata AST only.
const registryScript = String.raw`
import ast
import importlib
import inspect
import json
from server.sli.reporting.v2.registry import registered_reports, SECTION_TITLES

definitions = []
metrics = {}
filter_options = {}
for report in registered_reports():
    definitions.append({**report.to_json(), "filter_options": {}})
    module = importlib.import_module(report.query.__module__)
    tree = ast.parse(inspect.getsource(module))
    entries = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.keyword) or node.arg != "metrics":
            continue
        value = node.value
        if isinstance(value, ast.ListComp):
            fields = {ast.literal_eval(k): v for k, v in zip(value.elt.keys, value.elt.values) if k is not None}
            names = [name for name in ("key", "label", "caption") if name in fields]
            value.elt = ast.Dict(keys=[ast.Constant(name) for name in names], values=[fields[name] for name in names])
            if any(isinstance(child, ast.Call) for child in ast.walk(value)):
                raise AssertionError("Metric metadata must not execute calls")
            expression = ast.fix_missing_locations(ast.Expression(value))
            entries.extend(eval(compile(expression, "<metric metadata>", "eval"), vars(module)))
        elif isinstance(value, ast.List):
            for item in value.elts:
                if isinstance(item, ast.Dict):
                    fields = {ast.literal_eval(k): v for k, v in zip(item.keys, item.values) if k is not None}
                    def metadata_value(node):
                        if report.key == "security.problems" and isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "message":
                            return module.message(ast.literal_eval(node.value.args[0]))["text"]
                        return ast.literal_eval(node)
                    entries.append({name: metadata_value(fields[name]) for name in ("key", "label", "caption") if name in fields})
                elif isinstance(item, ast.Call):
                    entries.append(dict(zip(("key", "label"), map(ast.literal_eval, item.args[:2]))))
                else:
                    raise AssertionError("Unsupported metric metadata declaration")
        else:
            raise AssertionError("Unsupported metrics declaration")
    metrics[report.key] = entries
    if hasattr(module, "REASON_LABELS"):
        filter_options[report.key] = {"reason": [{"value": key, "label": label} for key, label in module.REASON_LABELS.items()]}
print(json.dumps({"definitions": definitions, "sections": SECTION_TITLES, "metrics": metrics, "filterOptions": filter_options}, ensure_ascii=True))
`;

function readRegistry() {
  const root = resolve(import.meta.dirname, "../../..");
  return JSON.parse(execFileSync(testPython(root), ["-B", "-c", registryScript], { cwd: root, encoding: "utf8", timeout: 30_000 })) as {
    definitions: ReportDefinitionDto[];
    sections: Record<string, string>;
    metrics: Record<string, Array<{ key: string; label: string; caption?: string }>>;
    filterOptions: Record<string, ReportDefinitionDto["filter_options"]>;
  };
}

// Share the real registry snapshot without spawning Python inside each test case.
const registry = readRegistry();

// The product is server-dotnet: for reports already cleaned on the .NET side the shipped declaration
// replaces the frozen Python one.
const shippedDefinitions = JSON.parse(readFileSync(
  resolve(import.meta.dirname, "../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json"), "utf8")) as ReportDefinitionDto[];
for (const key of ["security.events.chains", "ad.infrastructure"]) {
  const shipped = shippedDefinitions.find((item) => item.key === key)!;
  registry.definitions = registry.definitions.map((item) => item.key === key ? { ...shipped, filter_options: {} } : item);
}
const adDefinitions = JSON.parse(readFileSync(
  resolve(import.meta.dirname, "../../../server-dotnet/src/Sli.Server/Ad/report-definitions.json"), "utf8"
)) as Record<string, { declaration: ReportDefinitionDto }>;
const computerLogons = adDefinitions["ad.computer-logons"].declaration;
registry.definitions = registry.definitions.map((item) => item.key === computerLogons.key
  ? { ...computerLogons, filter_options: {} } : item);
registry.metrics[computerLogons.key] = [];
delete registry.filterOptions[computerLogons.key];

it.each(["ru", "en"] as const)("displays security action outcomes without replacing source evidence (%s)", (locale) => {
  setLocale(locale);
  const definition = localizeReportDefinition(registry.definitions.find((item) => item.key === "security.events.chains")!);
  const column = definition.columns.find((item) => item.key === "outcome")!;
  expect(column.path).toBe("outcome_code");
  const dictionary = locale === "ru" ? ru : en;
  for (const code of ["success", "failure", "unknown"] as const) {
    const outcome = code === "unknown" ? { state: "unknown", reason: "not_proven" }
      : { state: "observed", value: code, basis: "audit_keywords" };
    const raw = { outcome, outcome_code: code, event_db_id: 7 };
    const localized = localizeReportRow(definition.key, raw);
    expect(columnValue(column, localized)).toBe(dictionary[`reports.v2.security.events.chains.columns.outcome.labels.${code}`]);
    expect(localized.outcome).toBe(outcome);
    expect(raw.outcome).toBe(outcome);
    expect(localized.outcome_code).toBe(code);
  }
});

it.each([
  ["ru", "Основание привилегий", "Полнота привилегированного членства не подтверждена; показаны известные прямые, основные и вложенные связи."],
  ["en", "Privilege basis", "Privileged membership coverage is unconfirmed; known direct, primary and nested memberships are shown."],
] as const)("localizes direct, primary and nested privilege coverage in %s", (locale, label, limitation) => {
  setLocale(locale);
  expect(t("reports.v2.ad.users.v2.limitations.privilege_incomplete")).toBe(limitation);
  const definition = localizeReportDefinition(registry.definitions.find((item) => item.key === "ad.users.v2")!);
  expect(definition.columns.find((column) => column.key === "privilege_basis")?.label).toBe(label);
  const sourceText = "Полнота привилегированного членства не подтверждена; показаны известные прямые, основные и вложенные связи.";
  const raw: ReportResultDto = { contract_id: "sli.report-result.v2", report_key: "ad.users.v2", state: "partial",
    items: [], metrics: [], series: {}, coverage: {}, filter_options: {}, window: {}, filtered_count: 0,
    has_more: false, next_cursor: null, limitations: [{ code: "privilege_incomplete", text: sourceText }] };
  const localized = localizeReportResult(raw);
  expect(localized.limitations[0].text).toBe(limitation);
  expect(localized.state).toBe("partial");
  expect(raw.limitations[0].text).toBe(sourceText);
});

it("localizes user information independently of confirmed reasons and keeps unknown status", () => {
  setLocale("en");
  const information = { key: "password_age_unknown", label: "Возраст пароля: неизвестно", category: "information",
    policy: { status: "unknown", reason: "fact_missing_or_invalid", threshold_days: 90, value: null, observed_at: "2026-10-07T00:00:00Z" } };
  const confirmed = { key: "locked_out", label: "Учётная запись заблокирована", category: "confirmed" };
  const raw = { reasons: [confirmed], information_limitations: [information], review_details: [confirmed, information],
    reason_text: confirmed.label, information_text: information.label, password_age_policy: "unknown", sid: "synthetic-sid" };
  const localized = localizeReportRow("ad.users.v2", raw);
  expect(localized.reason_text).toBe("Account locked");
  expect(localized.information_text).toBe("Password age: unknown");
  expect(localized.password_age_policy).toBe("unknown");
  expect(localized.reasons).toHaveLength(1);
  expect(localized.information_limitations).toHaveLength(1);
  expect(localized.review_details).toHaveLength(2);
  expect(localized.sid).toBe(raw.sid);
  expect(raw.reason_text).toBe(confirmed.label);
  const definition = localizeReportDefinition(registry.definitions.find((item) => item.key === "ad.users.v2")!);
  expect(definition.columns.find((column) => column.key === "information")?.label).toBe("Information limitations");
  expect(definition.params.find((param) => param.key === "information")?.options?.map((option) => option.label)).toContain("Password age: unknown");
});

it("localizes GPO categories, priorities and next steps without adding a deviation", () => {
  setLocale("en");
  const reason = { code: "empty_enabled_side", title: "Включённая часть без настроек", category: "assignment", priority: "low", next: "Открыть исходный XML Get-GPOReport и проверить расширения", fact: "synthetic-fact" };
  const raw = { reasons: [reason], reason_titles: null, assignment_titles: reason.title, next_step: reason.next };
  const localized = localizeReportRow("ad.gpo.v2", raw);
  expect(localized.reason_titles).toBeNull();
  expect(localized.assignment_titles).toBe("Enabled side without settings");
  expect(localized.next_step).toBe("Open the source Get-GPOReport XML and inspect extensions");
  expect((localized.reasons as Array<typeof reason>)[0].fact).toBe("synthetic-fact");
  expect((localized.reasons as Array<typeof reason>)[0].priority).toBe("low");
  const definition = localizeReportDefinition(({ ...gpoDeclaration.declaration, filter_options: {} } as unknown as ReportDefinitionDto));
  expect(definition.columns.find((column) => column.key === "priority")?.labels?.low).toBe("Clarify assignment");
  expect(definition.params.find((param) => param.key === "view")?.options?.find((option) => option.value === "unverified")?.label).toBe("Unverified information");
});

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it("localizes visible GPO tabs without changing source records or access state", () => {
  setLocale("en");
  const raw = ({ ...gpoDeclaration.declaration, filter_options: {} } as unknown as ReportDefinitionDto);
  const localized = gpoReportDefinition(localizeReportDefinition(raw));
  const links = localized.views.find((view) => view.key === "linked_scopes")!;
  const changes = localized.views.find((view) => view.key === "changes")!;
  expect(localized.views.map((view) => view.title)).toEqual(["Policies", "Changes", "Linked scopes"]);
  expect(changes.note).toBeUndefined();
  expect(changes.columns?.find((column) => column.key === "before_sha256")?.label).toBe("Previous fingerprint");
  expect(changes.columns?.find((column) => column.key === "kind")?.labels?.object_removed).toBe("Object removed");
  expect(links.columns?.find((column) => column.key === "outcome")?.labels?.blocked).toBe("Blocked");
  const evidence = { path: "user-a → group-a → policy-a [ACE 0]", ace_id: "ace-0", outcome: "unknown" };
  const result: ReportResultDto = { contract_id: "sli.report-result.v2", report_key: raw.key, state: "partial",
    items: [], metrics: [], filtered_count: 0, has_more: false, next_cursor: null,
    collections: { filtering: [evidence] }, series: {}, filter_options: {}, coverage: { graph_state: "partial" }, window: {},
    limitations: [{ code: "effective_boundary", text: "Сведения GPC" }, { code: "filtering_truncated", text: "Предел обхода" }] };
  const translated = localizeReportResult(result);
  expect(translated.limitations[0].text).toContain("not the policy actually applied");
  expect(translated.limitations[1].text).toContain("traversal budget");
  expect(translated.collections).toBe(result.collections);
  expect(translated.coverage).toBe(result.coverage);
  expect(translated.state).toBe("partial");
  for (const view of [links, changes]) {
    for (const column of view.columns ?? []) {
      const key = `reports.v2.ad.gpo.v2.views.${view.key}.columns.${column.key}.label` as keyof typeof ru;
      expect(ru[key]).toBeDefined();
      expect(en[key]).toBeDefined();
    }
  }
});

it.each(["ru", "en"] as const)("resolves queue catalog envelopes in %s regardless of server text", (locale) => {
  setLocale(locale);
  const envelope = (code: string) => ({ code, params: {}, text: "other language" });
  const definition = registry.definitions.find((item) => item.key === "security.problems")!;
  const coded = { ...definition, title: "other language", presentation_messages: { title: envelope("reports.v2.security.problems.title") },
    columns: definition.columns.map((column) => column.key === "status" ? { ...column, labels: { new: "other language" }, labels_messages: { new: envelope("security.problems.status.new") } } : column) };
  const localized = localizeReportDefinition(coded);
  const merged = localizeReportDefinition(definition);
  const dictionary = locale === "en" ? en : ru;
  const params = Object.fromEntries(merged.params.map((param) => [param.key, param]));
  for (const key of ["entity_id", "rule_code", "created_from", "created_to"] as const) {
    expect(params[key].hidden).toBe(true);
    expect(params[key].label).toBe(dictionary[`reports.v2.security.problems.params.${key}.label`]);
  }
  expect(params.entity_id.kind).toBe("int");
  expect(params.risk.options).toEqual([
    { value: "accepted", label: dictionary["reports.v2.security.problems.params.risk.options.accepted"] },
    { value: "all", label: dictionary["reports.v2.security.problems.params.risk.options.all"] },
  ]);
  expect(merged.columns.find((column) => column.key === "risk_acceptance")).toMatchObject({
    label: dictionary["reports.v2.security.problems.columns.risk_acceptance.label"], component: "problems.risk-badge",
  });
  expect(merged.presets.find((preset) => preset.params.risk === "accepted")).toMatchObject({
    label: dictionary['reports.v2.security.problems.presets.{"risk":"accepted"}'], params: { risk: "accepted" },
  });
  expect(localized.title).toBe(locale === "en" ? en["reports.v2.security.problems.title"] : ru["reports.v2.security.problems.title"]);
  expect(localized.columns.find((column) => column.key === "status")?.labels?.new).toBe(locale === "en" ? en["security.problems.status.new"] : ru["security.problems.status.new"]);
  const raw: ReportResultDto = { contract_id: "sli.report-result.v2", report_key: "security.problems", state: "ok", has_more: false,
    next_cursor: null, filtered_count: 1, metrics: [], collections: {}, series: {}, coverage: {}, filter_options: {}, limitations: [], window: {},
    items: [{ id: 7, title: "Source title", title_text: "other language", summary: "Source summary", what_happened: "Source summary",
      review_hint_text: "other language", review_hint: { bucket: "machine_account", verdict: false },
      presentation_messages: { title_text: envelope("security.problems.presentation.audit_title"), review_hint_text: envelope("reports.v2.security.problems.presentation.machine_account") } }],
  };
  const row = localizeReportResult(raw).items[0];
  expect(row.title_text).toBe(locale === "en" ? en["security.problems.presentation.audit_title"] : ru["security.problems.presentation.audit_title"]);
  expect(row.review_hint_text).toBe(locale === "en" ? en["reports.v2.security.problems.presentation.machine_account"] : ru["reports.v2.security.problems.presentation.machine_account"]);
  expect(row.title).toBe("Source title");
  expect(row.what_happened).toBe("Source summary");
  expect(row.review_hint).toEqual(raw.items[0].review_hint);
  expect(raw.items[0].title_text).toBe("other language");
});

it.each(["ad.users.v2", "ad.computers.v6", "ad.infrastructure"])("localizes %s without optional coverage metadata", (reportKey) => {
  setLocale("en");
  const row = { display_name: "Synthetic account", description: "Synthetic source description" };
  const result = { report_key: reportKey, items: [row], metrics: [], filter_options: {}, limitations: [] } as unknown as ReportResultDto;
  const localized = localizeReportResult(result);
  expect(localized.items).toBe(result.items);
  expect(localized.items[0]).toBe(row);
  expect(localized.coverage).toBeUndefined();
});

it.each([
  [undefined, false],
  [undefined, true],
  ["audit_policy_changed", false],
  ["audit_policy_changed", true],
] as const)("localizes 4719 hints while preserving the classification and suppression evidence (presentation=%s, suppressed=%s)", (presentationCode, suppressed) => {
  setLocale("en");
  const hint = { bucket: "machine_account", kind: "hint", verdict: false, sample_count: 20, truncated: true };
  const result: ReportResultDto = {
    contract_id: "sli.report-result.v2", report_key: "security.problems", state: "ok", has_more: false,
    next_cursor: null, filtered_count: 1, metrics: [], items: [{
      ...(presentationCode ? { presentation_code: presentationCode, actor: "S-1-5-18", entities: [] } : {}),
      review_hint: hint, review_hint_text: "Учётная запись компьютера", suppressed,
    }],
    collections: {}, series: {}, coverage: {}, filter_options: {}, limitations: [], window: {},
  };
  const localized = localizeReportResult(result);
  expect(localized.items[0].review_hint_text).toBe("Machine account");
  expect(localized.items[0].review_hint).toBe(hint);
  expect(localized.items[0].suppressed).toBe(suppressed);
  if (presentationCode === "audit_policy_changed") {
    expect(localized.items[0].title_text).toBe(en["security.problems.presentation.audit_title"]);
    expect(localized.items[0].what_happened).toBe(en["security.problems.presentation.audit_what"]);
    expect(localized.items[0].why_text).toBe(en["security.problems.presentation.audit_why"]);
    expect(localized.items[0].next_text).toBe(en["security.problems.presentation.audit_next"]);
  }
  const relocalized = localizeReportResult(localized);
  expect(relocalized.items[0].review_hint_text).toBe("Machine account");
  expect(relocalized.items[0].review_hint).toBe(hint);
  expect(relocalized.items[0].suppressed).toBe(suppressed);
  expect(result.items[0].review_hint_text).toBe("Учётная запись компьютера");
  const definition = registry.definitions.find((item) => item.key === "security.problems")!;
  const translated = localizeReportDefinition(definition);
  expect(translated.params.find((param) => param.key === "show_suppressed")?.label).toBe("Show suppressed");
  expect(translated.columns.find((column) => column.key === "review_hint")?.label).toBe("Audit change context (needs review)");
});

describe("v2 registry metadata", () => {
  it.each([
    "overview", "actions", "mass-operations", "permission-changes",
    "access-denials", "out-of-hours", "permissions", "audit-state",
  ])("localizes the file-audit.%s source filter without changing its contract", (tab) => {
    const definition = registry.definitions.find((item) => item.key === `file-audit.${tab}`)!;
    const parameter = definition.params.find((param) => param.key === "source_kind")!;
    for (const locale of ["ru", "en"] as const) {
      setLocale(locale);
      const localized = localizeReportDefinition(definition);
      expect(localized.params.find((param) => param.key === "source_kind")).toEqual({
        ...parameter,
        label: locale === "en" ? "Source" : "Источник",
        options: [
          { value: "server", label: locale === "en" ? "Servers" : "Серверы" },
          { value: "workstation", label: locale === "en" ? "Workstations" : "Рабочие станции" },
        ],
      });
      expect(definition.params.find((param) => param.key === "source_kind")).toBe(parameter);
      expect(parameter.label).toBe("Источник");
      expect(parameter.options?.map((option) => option.label)).toEqual(["Серверы", "Рабочие станции"]);
    }
  });

  it("keeps AD history periods alongside hidden deep-link parameters", () => {
    setLocale("en");
    const raw = registry.definitions.find((item) => item.key === "ad.infrastructure")!;
    const localized = localizeReportDefinition(raw);
    const period = raw.params.find((param) => param.key === "period")!;
    expect(period.max_days).toBe(3650);
    expect(localized.params.find((param) => param.key === "period")).toMatchObject({ ...period, label: "Period" });
    expect(period.presets).toContain("24h");
    expect(localized.views.find((view) => view.key === "parameter_changes")?.source).toBe("parameter_changes");
    expect(localized.views.find((view) => view.key === "changes")?.source).toBe("changes");
    expect(localized.views.find((view) => view.key === "privileged_changes")?.source).toBe("privileged_changes");
    for (const key of ["domain_id", "domain", "row_id", "include_previous"]) {
      expect(localized.params.find((param) => param.key === key)?.hidden).toBe(true);
    }
  });

  it.each([
    ["ad.users.v2", "domain_id", "Domain"],
    ["ad.users.v2", "domain", "Domain"],
    ["ad.infrastructure", "domain_id", "Domain"],
    ["ad.infrastructure", "domain", "Domain"],
    ["ad.infrastructure", "row_id", "Parameter"],
    ["ad.computers.v6", "domain_id", "Domain"],
    ["ad.computers.v6", "domain", "Domain"],
    ["security.problems", "id", "No."],
    ["security.problems", "domain", "Domain"],
    ["security.problems", "time_from", "Period start"],
    ["security.problems", "time_to", "Period end"],
  ] as const)("localizes the hidden %s %s parameter without changing its contract", (report, key, label) => {
    setLocale("en");
    const definition = registry.definitions.find((item) => item.key === report)!;
    const parameter = definition.params.find((param) => param.key === key)!;
    expect(parameter.hidden).toBe(true);
    const localized = localizeReportDefinition(definition);
    expect(localized.params.find((param) => param.key === key)).toEqual({ ...parameter, label });
    expect(definition.params.find((param) => param.key === key)).toBe(parameter);
    setLocale("ru");
    if (report !== "ad.infrastructure") expect(localizeReportDefinition(definition)).toBe(definition);
  });

  it("localizes rule quality and preserves unknown metrics, cohort links and coverage", () => {
    setLocale("en");
    const raw = registry.definitions.find((item) => item.key === "security.rule-quality")!;
    const definition = localizeReportDefinition(raw);
    expect(definition.title).toBe("Rule quality");
    expect(definition.params[0].label).toBe("Period");
    expect(definition.columns.find((column) => column.key === "false_positive_rate")?.label).toBe("False positives, %");
    expect(definition.columns[0].link).toBe(raw.columns[0].link);
    expect(definition.intent?.question).toBe(en["reports.v2.security.rule-quality.intent.question"]);
    expect(definition.intent?.denominator).toBe(en["reports.v2.security.rule-quality.intent.denominator"]);
    expect(definition.intent?.freshness_expectation).toBe(en["reports.v2.security.rule-quality.intent.freshness_expectation"]);
    expect(definition.intent?.completeness).toBe(raw.intent?.completeness);
    expect(definition.intent?.rights).toBe(raw.intent?.rights);
    const result: ReportResultDto = {
      contract_id: "sli.report-result.v2", report_key: raw.key, state: "partial", items: [{
        rule_code: "semantic.synthetic", findings_produced: 2, false_positive_rate: null, accepted_risk: null,
        cohort_from: "2026-10-01T00:00:00Z", cohort_to: "2026-10-07T00:00:00Z",
      }], has_more: false, next_cursor: null, filtered_count: 1, metrics: [], series: {}, filter_options: {},
      coverage: { completeness: "not_proven", accepted_risk_supported: false }, window: {},
      limitations: [{ code: "accepted_risk_unavailable", text: "Статус принятого риска не поддерживается текущим lifecycle; метрика недоступна." }],
    };
    const localized = localizeReportResult(result);
    expect(localized.limitations[0].text).toContain("metric is unavailable");
    expect(localized.items).toBe(result.items);
    expect(localized.coverage).toBe(result.coverage);
    expect(localized.items[0].false_positive_rate).toBeNull();
    expect(localized.items[0].accepted_risk).toBeNull();
  });

  it("localizes the new-pair passport while preserving source and baseline measurement boundaries", () => {
    setLocale("en");
    const report = registry.definitions.find((item) => item.key === "ad.new-logon-pairs")!;
    const localized = localizeReportDefinition(report);
    expect(localized.intent?.question).toBe(en["reports.v2.ad.new-logon-pairs.intent.question"]);
    expect(localized.intent?.denominator).toContain("baseline window");
    expect(localized.intent?.freshness_expectation).toContain("checked separately");
    expect(localized.intent?.completeness).toBe(report.intent?.completeness);
    expect(localized.intent?.coverage).toBe(report.intent?.coverage);
    expect(localized.intent?.rights).toBe(report.intent?.rights);
    expect(report.intent?.question).toBe(ru["reports.v2.ad.new-logon-pairs.intent.question"]);
  });
  it("localizes service and task results without changing observations or evidence", () => {
    setLocale("en");
    const definition = registry.definitions.find((item) => item.key === "security.events.chains")!;
    const observations = [{ event_db_id: 10, initiator_sid: null, href: "/app/events/10" }];
    const rows = [{ object: "synthetic-service", action: "synthetic-path", previous_value: ["synthetic-previous"],
      event_ids: [10], evidence: ["4697: /app/events/10"], observations, quality: "unknown_object" }];
    const result: ReportResultDto = {
      contract_id: "sli.report-result.v2", report_key: definition.key, state: "partial", has_more: false, next_cursor: null,
      filtered_count: 1, metrics: [{ key: "persistence_services", label: "Службы с наблюдаемой установкой", value: 1 }],
      items: [], collections: { persistence_changes: rows }, coverage: { completeness: "not_proven" },
      series: {}, filter_options: {}, window: {},
      limitations: [{ code: "persistence_linking", text: "Связь не доказывает установку." },
        { code: "persistence_truncated", text: "Частичный срез." }],
    };
    const translated = localizeReportResult(result);
    expect(translated.metrics[0].label).toBe("Services with observed installation");
    expect(translated.limitations[0].text).toContain("does not prove");
    expect(translated.limitations[1].text).not.toMatch(/[А-Яа-яЁё]/);
    expect(translated.collections).toEqual(result.collections);
    expect(translated.coverage).toEqual(result.coverage);
  });
  it.each(["ru", "en"] as const)("localizes registered notification channel intent in %s", (locale) => {
    setLocale(locale);
    const definition = registry.definitions.find((item) => item.key === "notifications.channels")!;
    const localized = localizeReportDefinition(definition);
    for (const field of ["question", "denominator", "freshness_expectation"] as const) {
      const key = `reports.v2.notifications.channels.intent.${field}` as const;
      expect(definition.intent![field]).toBe(ru[key]);
      expect(localized.intent![field]).toBe((locale === "en" ? en : ru)[key]);
    }
  });

  it("has an English translation for every registered presentation key", () => {
    setLocale("en");
    expect(registry.definitions.length).toBeGreaterThan(0);
    const check = (report: string, field: string, label: string) => {
      if (!label) return;
      const key = `reports.v2.${report}.${field}`;
      expect(en[key as keyof typeof en], key).toBeTypeOf("string");
      expect(en[key as keyof typeof en], key).not.toBe("");
      expect(ru[key as keyof typeof ru], key).toBeTypeOf("string");
      expect(reportMetadataText(report, field, label), key).toBe(en[key as keyof typeof en]);
      expect(reportMetadataText(report, field, label), key).not.toMatch(/[А-Яа-яЁё]/);
    };
    const columns = (report: string, prefix: string, values: ReportDefinitionDto["columns"]) => {
      for (const column of values) {
        check(report, `${prefix}.${column.key}.label`, column.label);
        for (const [code, label] of Object.entries(column.labels ?? {})) check(report, `${prefix}.${column.key}.labels.${code}`, label);
      }
    };
    for (const [section, title] of Object.entries(registry.sections)) check("sections", `${section}.title`, title);
    for (const report of registry.definitions.filter((item) => item.key !== "ad.gpo.v2")) {
      const localized = localizeReportDefinition(report);
      // Journal descriptions and passports have no screen or dictionary entries.
      const { description: _description, intent: _intent, ...listPresentation } = localized;
      expect(JSON.stringify(report.key === "events.journal" ? listPresentation : localized), report.key).not.toMatch(/[А-Яа-яЁё]/);
      check(report.key, "title", report.title);
      if (report.key !== "events.journal") {
        check(report.key, "description", report.description);
        expect(report.intent, report.key).toBeTruthy();
        for (const field of ["question", "denominator", "freshness_expectation"] as const) {
          check(report.key, `intent.${field}`, report.intent![field]);
          expect(ru[`reports.v2.${report.key}.intent.${field}` as keyof typeof ru]).toBe(report.intent![field]);
        }
        const localizedIntent = localizeReportDefinition(report).intent!;
        expect({ ...localizedIntent, question: report.intent!.question, denominator: report.intent!.denominator,
          freshness_expectation: report.intent!.freshness_expectation }).toEqual(report.intent);
      }
      columns(report.key, "columns", report.columns);
      for (const param of report.params) {
        if (report.key === computerLogons.key && param.hidden) continue;
        check(report.key, `params.${param.key}.label`, param.label);
        if (report.key === computerLogons.key && param.key === "service_logons") continue;
        for (const option of param.options ?? []) check(report.key, `params.${param.key}.options.${option.value}`, option.label);
      }
      for (const view of report.views) {
        check(report.key, `views.${view.key}.title`, view.title ?? "");
        check(report.key, `views.${view.key}.note`, view.note ?? "");
        columns(report.key, `views.${view.key}.columns`, view.columns ?? []);
        for (const series of view.series ?? []) check(report.key, `views.${view.key}.series.${series.path}`, series.label);
      }
      if (typeof report.detail === "object") {
        check(report.key, "detail.title", report.detail.title);
        columns(report.key, "detail.columns", report.detail.columns);
        for (const link of report.detail.row_links) check(report.key, `detail.row_links.${link.href}`, link.label);
      }
      for (const preset of report.presets) check(report.key, `presets.${reportPresetKey(preset.params)}`, preset.label);
      for (const link of report.row_links) check(report.key, `row_links.${link.href}`, link.label);
      for (const metric of registry.metrics[report.key]) {
        check(report.key, `metrics.${metric.key}.label`, metric.label);
        check(report.key, `metrics.${metric.key}.caption`, metric.caption ?? "");
      }
      for (const [param, options] of Object.entries(registry.filterOptions[report.key] ?? {})) {
        for (const option of options) check(report.key, `params.${param}.options.${option.value}`, option.label);
      }
    }
  });
  it("uses stable keys despite server wording changes and falls back for unknown metadata", () => {
    setLocale("en");
    const report = registry.definitions.find((item) => item.key === "ad.computers.v6")!;
    const changed = { ...report, title: "Updated server title", description: "Updated server description",
      columns: report.columns.map((column) => ({ ...column, label: "Updated column label" })) };
    const localized = localizeReportDefinition(changed);
    expect(localized.title).toBe("Computers");
    expect(localized.description).toBe(localizeReportDefinition(report).description);
    expect(localized.columns[0].label).toBe("Computer");
    expect(reportMetadataText(report.key, "columns.future.label", "Unknown server label")).toBe("Unknown server label");
    expect(reportMetadataText("future.report", "title", report.title)).toBe(report.title);
    const catalog = localizeReportCatalog({ contract_id: "sli.report-catalog.v2", items: [{
      key: "vpn.connections", title: "Updated title", description: "Updated description", section: "reports/remote-access",
      section_title: "Updated section", home_view: { kind: "chart", key: "daily", title: "Updated view" },
    }] });
    expect(catalog.items[0].title).toBe("VPN connections");
    expect(catalog.items[0].section_title).toBe("Remote access");
    expect(catalog.items[0].home_view?.title).not.toBe("Updated view");
    setLocale("ru");
    expect(localizeReportDefinition(changed)).toBe(changed);
    expect(reportMetadataText(report.key, "title", changed.title)).toBe(changed.title);
  });

  it("localizes the four approved Users tabs and the temporary membership reason without changing evidence", () => {
    setLocale("en");
    const report = registry.definitions.find((item) => item.key === "ad.users.v2")!;
    const localized = localizeReportDefinition(report);
    expect(localized.views.map((view) => [view.key, view.title])).toEqual([
      ["checks", "Require review"], ["privileged", "Privileged"],
      ["changes", "Changes"], ["all", "All accounts"],
    ]);
    expect(localized.views.map((view) => view.access)).toEqual(report.views.map((view) => view.access));
    const reason = { key: "temporary_membership", label: "Краткое членство в контрольной группе", summary: "Synthetic control group",
      observed: "2", condition: "Условие", qualification: "Наблюдение", limitation: "Ограничение", next: "Следующий шаг", evidence: [[1, 2]] };
    const unchanged = { display_name: "Synthetic unchanged account", reasons: [{ key: "future", label: "Synthetic reason" }], reason_text: "Synthetic reason" };
    const result: ReportResultDto = {
      contract_id: "sli.report-result.v2", report_key: report.key, state: "partial", has_more: false, next_cursor: null,
      filtered_count: 1, metrics: [{ key: "activity_unknown", label: "События без точной идентичности", value: 3 }],
      items: [{ display_name: "Synthetic account", reasons: [reason], reason_text: reason.label }, unchanged],
      collections: { temporary_memberships: [{ candidate_id: "fixture", quality: "ambiguous", evidence: [1, 2] }] },
      series: {}, coverage: { completeness: "not_proven" }, filter_options: { reason: [{ value: reason.key, label: reason.label }] },
      limitations: [{ code: "activity_coverage", text: "Полнота источников не подтверждена." }], window: {},
    };
    const translated = localizeReportResult(result);
    expect(translated.items[0].reason_text).toBe("Brief membership in a monitored group");
    const detail = (translated.items[0].reasons as Array<typeof reason>)[0];
    expect(detail.limitation).toContain("do not prove use");
    expect(detail.summary).toBe(reason.summary);
    expect(detail.evidence).toEqual(reason.evidence);
    expect(translated.collections).toBe(result.collections);
    expect(translated.coverage).toBe(result.coverage);
    expect(translated.limitations[0].text).toContain("not confirmed");
    expect(translated.metrics[0].label).toBe("Events without exact identity");
    expect(translated.filter_options.reason[0].label).toBe("Brief membership in a monitored group");
    expect(result.items[0].reason_text).toBe(reason.label);
    expect(translated.items[1]).toBe(unchanged);
    const untouched = { ...result, items: [unchanged] };
    expect(localizeReportResult(untouched).items).toBe(untouched.items);
    setLocale("ru");
    expect(localizeReportDefinition(report).views.map((view) => [view.key, view.title])).toEqual([
      ["checks", "Требуют проверки"], ["privileged", "Привилегированные"],
      ["changes", "Изменения"], ["all", "Все учётки"],
    ]);
    expect(localizeReportResult(result)).toBe(result);
  });

  it("translates keyed metrics and service filter options while preserving row and database values", () => {
    setLocale("en");
    const result: ReportResultDto = {
      contract_id: "sli.report-result.v2", report_key: "ad.users.v2", state: "ok", has_more: false, next_cursor: null,
      filtered_count: 1, metrics: [{ key: "attention", label: "Updated metric", value: 7, filter: { view: "attention" } }],
      items: [{ display_name: "Описание", department: "Политика", value: "Изменения" }],
      collections: { changes: [{ description: "Описание" }] }, series: { label: "Описание" }, coverage: { state: "ok" },
      filter_options: { reason: [{ value: "locked_out", label: "Updated reason", count: 3 }],
        department: [{ value: "Политика", label: "Политика" }], domain: [{ value: "1", label: "Политика" }] },
      limitations: [], window: {},
    };
    const localized = localizeReportResult(result);
    expect(localized.metrics[0].label).toBe("Confirmed review reasons");
    expect(localized.metrics[0].value).toBe(7);
    expect(localized.metrics[0].filter).toBe(result.metrics[0].filter);
    expect(localized.filter_options.reason[0]).toEqual({ value: "locked_out", label: "Account locked", count: 3 });
    expect(localized.filter_options.department).toBe(result.filter_options.department);
    expect(localized.filter_options.domain).toBe(result.filter_options.domain);
    expect(localized.items).toBe(result.items);
    expect(localized.collections).toBe(result.collections);
    expect(localized.series).toBe(result.series);
    expect(result.metrics[0].label).toBe("Updated metric");
    const computers = localizeReportResult({ ...result, report_key: "ad.computers.v6", filter_options: {
      os: [{ value: "__missing__", label: "Updated sentinel" }, { value: "Политика", label: "Политика" }],
    } });
    expect(computers.filter_options.os[0]).toEqual({ value: "__missing__", label: "No data" });
    expect(computers.filter_options.os[1].label).toBe("Политика");
    setLocale("ru");
    expect(localizeReportResult(result)).toBe(result);
  });

  it("keys presets by their parameters instead of labels or parameter order", () => {
    expect(reportPresetKey({ view: "all", enabled: "disabled" })).toBe(reportPresetKey({ enabled: "disabled", view: "all" }));
    setLocale("en");
    const report = registry.definitions.find((item) => item.key === "ad.computers.v6")!;
    const changed = { ...report, presets: [...report.presets].reverse().map((preset) => ({ ...preset, label: "Updated preset" })) };
    const localized = localizeReportDefinition(changed);
    expect(localized.presets.map((preset) => preset.label)).toEqual(localizeReportDefinition(report).presets.map((preset) => preset.label).reverse());
    expect(localized.presets[0].params).toBe(changed.presets[0].params);
  });
  it("renders English VPN presentation values and preserves legacy, unknown and object data", () => {
    setLocale("en");
    const result: ReportResultDto = {
      contract_id: "sli.report-result.v2", report_key: "vpn.accounts", state: "ok", has_more: false,
      next_cursor: null, filtered_count: 4, metrics: [{ key: "active_users", label: "Активные", value: 2 }],
      items: [
        { activity: "active", department_text: "Поле недоступно", department_text_code: "unavailable", password_text: "Без ограничения срока", password_text_code: "never_expires", privilege_text: "Не обнаружено в неполном срезе", privilege_text_code: "not_detected_partial", display_name: "Название объекта" },
        { activity: "inactive", department_text: "Не указано", department_text_code: "unspecified", password_text: "С ограничением срока", password_text_code: "expires", privilege_text: "Есть пересечение", privilege_text_code: "overlap" },
        { activity: "disabled", department_text: "Подразделение из источника", department_text_code: null, privilege_text: "Не обнаружено", privilege_text_code: "not_detected" },
        { activity: "unknown", privilege_text: "Срез не собран", privilege_text_code: "not_collected", password_text: "Поле недоступно", password_text_code: "unavailable" },
        { department_text: "Не указано", password_text: "Текст будущего сервера", password_text_code: "future-code" },
      ], filter_options: {}, series: {}, coverage: {}, limitations: [], window: {},
    };
    const localized = localizeReportResult(result);
    expect(localized.metrics[0].label).toBe("Active");
    expect(localized.items[0]).toMatchObject({ department_text: "Field unavailable", password_text: "Never expires", privilege_text: "Not detected in partial coverage", display_name: "Название объекта" });
    expect(localized.items[1]).toMatchObject({ department_text: "Not specified", password_text: "Expires", privilege_text: "Overlap detected" });
    expect(localized.items[2]).toMatchObject({ department_text: "Подразделение из источника", privilege_text: "Not detected" });
    expect(localized.items[3]).toMatchObject({ privilege_text: "Snapshot not collected", password_text: "Field unavailable" });
    expect(localized.items[4]).toEqual(result.items[4]);
    expect(result.items[0].department_text).toBe("Поле недоступно");
    const definition = localizeReportDefinition(registry.definitions.find((item) => item.key === "vpn.accounts")!);
    const state = definition.columns.find((column) => column.key === "activity")!;
    expect(localized.items.slice(0, 4).map((row) => columnValue(state, row))).toEqual(["Active", "Inactive", "Disabled", "Unknown"]);
    const vpn = localizeReportDefinition(registry.definitions.find((item) => item.key === "vpn.connections")!);
    if (typeof vpn.detail !== "object") throw new Error("missing VPN detail");
    const lifecycle = vpn.detail.columns.find((column) => column.key === "state")!;
    expect(columnValue(lifecycle, { lifecycle_state: "closed" })).toBe("Completed");
    setLocale("ru");
    expect(localizeReportResult(result)).toBe(result);
  });

  it("translates home metrics and fixed VPN/chain explanations using stable keys", () => {
    setLocale("en");
    const result: ReportResultDto = { contract_id: "sli.report-result.v2", report_key: "security.problems", state: "ok",
      items: [], has_more: false, next_cursor: null, filtered_count: 0, metrics: [{ key: "closed", label: "Закрытые", value: 3 }],
      series: {}, coverage: {}, filter_options: {}, limitations: [], window: {} };
    expect(localizeReportResult(result).metrics[0].label).toBe("Closed");
    const vpn = localizeReportResult({ ...result, report_key: "vpn.connections", limitations: [
      { code: "authorizations_meaning", text: "Changed server wording" },
      { code: "vpn_note", text: "NPS 6273 отражает отказ авторизации и не определяет длительность VPN-сессии." },
      { code: "vpn_note", text: "Ссылки на raw Accounting evidence не публикуются текущей безопасной session view." },
    ], branches: {
      accounting: { state: "error", reason: "source_unreadable", limitations: [{ code: "vpn_source_unreadable", text: "Changed wording" }] },
      nps: { state: "error", reason: "window_or_input_limit", limitations: [{ code: "authorizations_unavailable", text: "Changed wording" }] },
      windows: { state: "partial", reason: "coverage_unverified", limitations: [{ code: "windows_unavailable", text: "Changed wording" }] },
      windows_heatmap: { state: "error", reason: "source_unreadable", limitations: [{ code: "windows_heatmap_unavailable", text: "Changed wording" }] },
    } });
    expect(vpn.limitations[0].text).toContain("independent NPS facts");
    expect(vpn.limitations[1].text).toContain("does not determine VPN session duration");
    expect(vpn.limitations[2].text).not.toMatch(/[А-Яа-яЁё]/);
    expect(vpn.branches?.accounting.limitations[0].text).toContain("session source");
    expect(vpn.branches?.nps.limitations[0].text).toContain("NPS decisions are unavailable");
    expect(vpn.branches?.windows_heatmap.limitations[0].text).toContain("heatmap is unavailable");
    expect(vpn.branches).toMatchObject({
      accounting: { state: "error", reason: "source_unreadable" },
      nps: { state: "error", reason: "window_or_input_limit" },
      windows: { state: "partial", reason: "coverage_unverified" },
      windows_heatmap: { state: "error", reason: "source_unreadable" },
    });
    expect(vpn.branches?.windows.state).toBe("partial");
    expect(vpn.branches?.windows.limitations[0].text).toContain("90 days");
    const chains = localizeReportResult({ ...result, report_key: "security.events.chains", limitations: [
      { code: "observations_only", text: "Changed wording" }, { code: "future-code", text: "Описание из источника" },
    ] });
    expect(chains.limitations[0].text).toContain("source event observations");
    expect(chains.limitations[1].text).toBe("Описание из источника");
  });

  it("localizes revocation candidates and preserves their evidence and coverage", () => {
    setLocale("en");
    const raw = registry.definitions.find((item) => item.key === "security.events.chains")!;
    const definition = localizeReportDefinition(raw);
    expect(definition.params.find((param) => param.key === "identity_scope")?.options?.map((option) => option.label))
      .toEqual(["All observations", "Exact identity only"]);
    const result: ReportResultDto = { contract_id: "sli.report-result.v2", report_key: raw.key, state: "partial",
      items: [], has_more: false, next_cursor: null, filtered_count: 1,
      metrics: [{ key: "revocation_logons", label: "Аккаунты с последующей 4624 (кандидаты)", value: 1 }],
      collections: { account_revocation: [{ account: "account-a", evidence: [10, "session-a"], qualification: "candidate" }] },
      series: {}, filter_options: {}, coverage: { completeness: "not_proven", accounting_state: "unavailable" }, window: {},
      limitations: [{ code: "revocation_candidate", text: "Это кандидаты." },
        { code: "revocation_accounting", text: "Accounting недоступен." }] };
    const localized = localizeReportResult(result);
    expect(localized.metrics[0].label).toBe("Accounts with subsequent 4624 (candidates)");
    expect(localized.limitations[0].text).toContain("not proof");
    expect(localized.limitations[1].text).toContain("has not been established");
    expect(localized.collections).toBe(result.collections);
    expect(localized.coverage).toBe(result.coverage);
  });

  it("localizes recurring lockout results and keeps observed values intact", () => {
    setLocale("en");
    const raw = registry.definitions.find((item) => item.key === "security.events.chains")!;
    const definition = localizeReportDefinition(raw);
    expect(definition.params.find((param) => param.key === "failure_window")?.options?.map((option) => option.label))
      .toEqual(["5 minutes", "15 minutes", "1 hour", "24 hours"]);
    const result: ReportResultDto = { contract_id: "sli.report-result.v2", report_key: raw.key, state: "partial",
      items: [], has_more: false, next_cursor: null, filtered_count: 1,
      metrics: [{ key: "recurring_accounts", label: "Аккаунты с повторными блокировками", value: 1 }],
      collections: { lockout_recurring: [{ account: "account-a", failure_codes: ["0x18"], first_event: 10 }] },
      series: {}, filter_options: {}, coverage: { completeness: "not_proven" }, window: {},
      limitations: [{ code: "recurring_truncated", text: "Достигнут лимит событий или аккаунтов." }] };
    const localized = localizeReportResult(result);
    expect(localized.metrics[0].label).toBe("Accounts with recurring lockouts");
    expect(localized.limitations[0].text).toContain("lower bounds");
    expect(localized.collections).toBe(result.collections);
    expect(localized.coverage).toBe(result.coverage);
  });

  it("localizes NPS policy tabs and preserves their source and coverage codes", () => {
    setLocale("en");
    const raw = registry.definitions.find((item) => item.key === "vpn.connections")!;
    const definition = localizeReportDefinition(raw);
    const policies = definition.views.find((view) => view.key === "policy_denials")!;
    expect(policies.title).toBe("Policies and reasons");
    expect(policies.source).toBe("policy_denials");
    expect(policies.note).toBe("NPS decisions are shown. Collection completeness is unverified.");
    expect(policies.note).not.toContain("6272");
    expect(policies.columns?.find((column) => column.key === "current_coverage")?.labels?.truncated).toBe("Truncated sample");
    expect(definition.views.find((view) => view.key === "policy_denials_growth")?.title).toBe("NPS denial trend");
    const events = definition.views.find((view) => view.key === "policy_denials_events")!;
    expect(events.columns?.find((column) => column.key === "decision")?.labels?.allowed).toBe("NPS allow");
    expect(events.columns?.find((column) => column.key === "event_db_id")?.link).toBe("/app/events/{event_db_id}");
    expect(definition.params.find((param) => param.key === "min_growth")?.label).toBe("Minimum denial growth (decisions)");
    expect(reportMetadataText("vpn.connections", "limitations.nps_policy_previous_sample", "")).toContain("previous window");
    expect(reportMetadataText("vpn.connections", "metrics.nps_allowed.label", "")).toBe("NPS allows");
  });

  it("translates chain state transitions by observation codes without interpreting object descriptions", () => {
    setLocale("en");
    const result: ReportResultDto = { contract_id: "sli.report-result.v2", report_key: "security.events.chains", state: "ok",
      items: [
        { change_text: "отключена → включена", account_change: { observed_transition: { before: { state: "observed", value: "disabled" }, after: { state: "observed", value: "enabled" } } }, description: "Описание объекта" },
        { change_text: "не подтверждено → заблокирована", account_change: { observed_transition: { after: { state: "observed", value: "locked" } } } },
        { change_text: "добавление в группу", change: { state: "observed", kind: "member_added" } },
        { change_text: "Описание новой операции", change: { state: "observed", kind: "future-kind" } },
        { change_text: "Неподдерживаемый текст" },
      ], has_more: false, next_cursor: null, filtered_count: 5, metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {} };
    const localized = localizeReportResult(result);
    expect(localized.items.map((row) => row.change_text)).toEqual([
      "disabled → enabled", "not confirmed → locked", "group member addition", "Описание новой операции", "Неподдерживаемый текст",
    ]);
    expect(localized.items[0].description).toBe("Описание объекта");
    expect(localized.items[0].account_change).toBe(result.items[0].account_change);
    expect(result.items[0].change_text).toBe("отключена → включена");
  });

});

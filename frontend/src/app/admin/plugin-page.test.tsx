// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import userEvent from "@testing-library/user-event";
import ad from "../../../../config/plugin_settings_schema/sli.ad.settings.json";
import fileAudit from "../../../../config/plugin_settings_schema/sli.file-audit.settings.json";
import gpo from "../../../../config/plugin_settings_schema/sli.gpo.settings.json";
import remoteAccess from "../../../../config/plugin_settings_schema/sli.remote-access.settings.json";
import sigma from "../../../../config/plugin_settings_schema/sli.sigma.settings.json";
import workstations from "../../../../config/plugin_settings_schema/sli.workstations.settings.json";
import workspaceDeclarations from "../../../../server-dotnet/src/Sli.Server/Workspace/declarations.json";
import type { PluginState } from "../../api/client";
import type { PluginSettings, SettingsSchema } from "../../api/plugin-settings-types";
import { localeRuntime, setLocale, t } from "../../i18n";
import { PluginPage } from "./plugin-page";
import { validSetting } from "./plugin-settings-model";

const access = vi.hoisted(() => ({ subject: { coarse_role: "admin" }, platform_owner: true, capabilities: ["access.manage"] }));
vi.mock("../App", () => ({ useEffectiveAccess: () => access, useTimeZone: () => ({ timeZone: "UTC" }) }));

const original = () => ({ plugin_id: ad.plugin_id, schema: ad.settings, rules: ad.rules, sources: {},
  values: Object.fromEntries(Object.entries(ad.settings.properties).map(([key, node]) => [key, node.default])) }) as PluginSettings;
let settings: PluginSettings;
let requests: Array<{ path: string; method: string; body?: { key: string; value: unknown } }>;
let rejectKey = "";
let denySettings = false;
let sigmaEnabled = true;
let sigmaRulesAvailable = true;
let sigmaReadFailed = false;
let sigmaMatches = 4;
let radiusSources: Array<{ source_instance_id: string; source_state: string }>;
let client: QueryClient;
let pluginStates: Record<string, Partial<PluginState>>;
let setupSources: Array<{ pack_id: string; enabled: boolean; data_state: string;
  instances?: Array<{ source_instance_id: string; last_data_utc: string | null; data_state: string }> }>;
const plugin = (plugin_id: string) => ({ plugin_id, installed: true, configured: true, enabled: plugin_id !== "sli.remote-access",
  component_runtime: "running", revision: 7, last_data_at_utc: null,
  status: { state: plugin_id === "sli.remote-access" ? "disabled" : plugin_id === "sli.sigma" ? "no_sources" : "waiting",
    reason: plugin_id === "sli.sigma" ? "no_sources" : undefined,
    next_action: plugin_id === "sli.sigma" ? "connect_sigma_events" : undefined,
    last_data_at: null, error_at: null, error_object: null }, ...pluginStates[plugin_id] });

beforeEach(() => {
  settings = original(); requests = []; rejectKey = ""; denySettings = false; radiusSources = []; sigmaEnabled = true;
  pluginStates = {}; setupSources = [];
  sigmaRulesAvailable = true; sigmaReadFailed = false; sigmaMatches = 4;
  access.subject.coarse_role = "admin"; access.platform_owner = true;
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  vi.spyOn(window, "confirm").mockReturnValue(true);
  vi.stubGlobal("fetch", vi.fn(async (path: string, options?: RequestInit) => {
    const method = options?.method ?? "GET";
    const body = options?.body ? JSON.parse(String(options.body)) : undefined;
    requests.push({ path, method, body });
    const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
    if (path.endsWith("/settings")) {
      if (denySettings) return json({ error: "forbidden" }, 403);
      if (method === "PUT") {
        if (body.key === rejectKey) return json({ error: "invalid_plugin_setting_value", detail: "private-error-marker" }, 400);
        settings.values[body.key] = body.value;
        return json({ plugin_id: settings.plugin_id, key: body.key, value: body.value });
      }
      if (path === `/api/plugins/${settings.plugin_id}/settings`) return json(settings);
      const declaration = [gpo, workstations, fileAudit, remoteAccess, sigma].find((item) => path === `/api/plugins/${item.plugin_id}/settings`);
      return declaration ? json({ plugin_id: declaration.plugin_id, schema: declaration.settings, rules: declaration.rules, values: {}, sources: {} })
        : json({ error: "plugin_not_found" }, 404);
    }
    if (path === "/api/v1/plugins") return json({ items: ["sli.ad", "sli.gpo", "sli.workstations", "sli.file-audit", "sli.remote-access", "sli.sigma"].map(plugin), can_manage: true });
    if (path === "/api/v1/plugins/sli.ad") return json({ item: { ...plugin("sli.ad"), enabled: false } });
    if (path === "/api/v1/operations/plugins/sli.remote-access") return json({ item: { observed: { status: "ok", sources: radiusSources } } });
    if (path === "/api/v1/setup/status") return json({ sources: setupSources, domains: [
      { fqdn: "one.example.invalid", observed_at_utc: "2026-10-29T01:00:00Z" }, { fqdn: "two.example.invalid", observed_at_utc: null },
    ], domain_controllers: [{ hostname: "DC-01", domain: "one.example.invalid", enabled: true }, { hostname: "DC-02", domain: "two.example.invalid", enabled: true }] });
    if (path === "/api/v1/admin/agents") return json({ items: [] });
    if (path.startsWith("/api/v2/reports/file-audit.overview/data?")) return json({
      coverage: { audit_resources: { servers: 1, audited: 1, shares: 6 } }, items: [], metrics: [], limitations: [], series: {}, filter_options: {},
    });
    if (path === "/api/v1/admin/agents/file-audit/accounts") return json({
      items: [{ sid: "S-1-5-21-100000001-200000002-300000003-1201", name: "EXAMPLE\\Backup Operators" }],
    });
    if (path === "/api/v2/reports") return json({ contract_id: "sli.report-catalog.v2", items: [
      { key: "ad.infrastructure", title: "Состояние домена", description: "Каталог", section: "active-directory", section_title: "AD", owner_id: "sli.ad" },
      { key: "ad.gpo.v2", title: "Политики", description: "GPO", section: "active-directory", section_title: "AD", owner_id: "sli.gpo" },
      ...workspaceDeclarations.reports.filter(({ key }) => ["workstations.logons", "workstations.processes", "workstations.usb"].includes(key)),
      { key: "workstations.protection", title: "Защита", description: "Последний снимок Defender независимо от периода и события изменений за период.", section: "workstations", section_title: "Workstations", owner_id: "sli.workstations" },
    ] });
    if (path === "/api/v1/semantic/sigma-live-rules") {
      if (sigmaReadFailed) return json({ error: "unexpected_error" }, 503);
      if (!sigmaRulesAvailable) return json({ rules: [] });
      if (method === "POST") sigmaEnabled = body.enabled;
      return json({ rules: [{ rule_id: "7b449a5e-1db5-4dd0-a2dc-4e3a67282538",
        title: "Hidden Local User Creation", level: "high", author: "SigmaHQ", license: "DRL-1.1",
        source_uri: "https://example.test/rule", enabled: sigmaEnabled, matches_24h: sigmaMatches }] });
    }
    throw new Error(`Unexpected request ${method} ${path}`);
  }));
});
afterEach(() => { cleanup(); client?.clear(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
function mount(pluginId = "sli.ad") {
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><PluginPage pluginId={pluginId} title={pluginId === "sli.ad" ? "Active Directory" : pluginId}/></QueryClientProvider>);
}
async function openSettings() {
  fireEvent.click(await screen.findByRole("tab", { name: t("pluginPage.tab.settings") }));
  return screen.findByRole("spinbutton", { name: t("plugins.sli.ad.settings.ad.inactivity_days.label") });
}
const writes = () => requests.filter((request) => request.method === "PUT");

it("opens Sigma on the rules table and applies the authoritative switch response", async () => {
  mount("sli.sigma");
  const row = await screen.findByRole("row", { name: /Создание скрытого локального пользователя/ });
  expect(screen.queryByRole("tab", { name: "Обзор" })).toBeNull();
  expect(within(row).getByText("4")).toBeTruthy();
  expect(within(row).queryByText(/SigmaHQ|DRL-1.1/)).toBeNull();
  const toggle = within(within(row).getAllByRole("cell")[0]).getByRole("switch", { checked: true });
  fireEvent.click(toggle);
  await waitFor(() => expect(within(row).getByRole("switch", { checked: false })).toHaveProperty("disabled", false));
  expect(requests.filter((request) => request.method === "POST")).toEqual([{
    path: "/api/v1/semantic/sigma-live-rules", method: "POST",
    body: { rule_id: "7b449a5e-1db5-4dd0-a2dc-4e3a67282538", enabled: false },
  }]);
  fireEvent.click(within(row).getByRole("button", { name: "Создание скрытого локального пользователя" }));
  const card = screen.getByRole("dialog");
  expect(within(card).getByText("Hidden Local User Creation")).toBeTruthy();
  expect(within(card).getByText("SigmaHQ")).toBeTruthy();
  expect(within(card).getByText("DRL-1.1")).toBeTruthy();
});

it("hides the Sigma matches column while all counts are zero", async () => {
  sigmaMatches = 0;
  mount("sli.sigma");
  expect(await screen.findByRole("row", { name: /Создание скрытого локального пользователя/ })).toBeTruthy();
  expect(screen.queryByRole("columnheader", { name: t("security.sigma.live.matches") })).toBeNull();
});

it("uses one Sigma source table and omits the workstation installation namespace", async () => {
  setupSources = [
    { pack_id: "sli.windows.ad-dc", enabled: true, data_state: "fresh", instances: [
      { source_instance_id: "DC-01", data_state: "fresh", last_data_utc: "2026-11-28T09:30:00Z" },
    ] },
    { pack_id: "sli.windows.ad-context", enabled: true, data_state: "fresh", instances: [
      { source_instance_id: "example.test", data_state: "never", last_data_utc: null },
      { source_instance_id: "workstations.invalid", data_state: "never", last_data_utc: null },
    ] },
  ];
  mount("sli.sigma");
  fireEvent.click(await screen.findByRole("tab", { name: "Подключение" }));
  const table = await screen.findByRole("table");
  expect(within(table).getAllByRole("columnheader").map(cell => cell.textContent)).toEqual(["Источник", "Что поступает", "Последние данные"]);
  expect(within(table).getByRole("row", { name: /DC-01.+09:30/ })).toBeTruthy();
  expect(within(table).getByRole("row", { name: /example.test.+Не собрано/ })).toBeTruthy();
  expect(screen.queryByText("workstations.invalid")).toBeNull();
});

it.each(["sli.ad", "sli.gpo"])("retains domain setup in Connection for %s", async (id) => {
  mount(id);
  expect(await screen.findByRole("switch", { name: t("plugins.toggle"), checked: true })).toHaveProperty("disabled", false);
  fireEvent.click(screen.getByRole("tab", { name: "Подключение" }));
  expect(await screen.findByRole("link", { name: /Домены и контроллеры/ })).toBeTruthy();
  if (id === "sli.gpo") {
    await waitFor(() => expect(client.getQueryState(["plugin-settings", id])?.status).toBe("success"));
    expect(screen.queryByRole("tab", { name: "Настройки" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Правила" })).toBeNull();
    expect(await screen.findByRole("tab", { name: "Отчёты" })).toBeTruthy();
  }
});

it("uses Resources counts in the file audit header and has no Connection tab", async () => {
  mount("sli.file-audit");
  expect(await screen.findByText(t("file-audit.resources.summary", { status: t("plugins.enabled"), servers: 1, audited: 1, shares: 6 }), { exact: false })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "Ресурсы", selected: true })).toBeTruthy();
  expect(within(screen.getByRole("tabpanel")).getByRole("link", { name: "Файловые серверы → Аудит" }).getAttribute("href"))
    .toBe("/app/report/file-audit.overview?tab=audit-state");
  expect(screen.queryByRole("tab", { name: t("pluginPage.tab.connection") })).toBeNull();
  expect(requests.some((request) => request.path === "/api/v1/admin/agents")).toBe(false);
});

it("searches for AD accounts by name and saves only the selected SID", async () => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("CSS", { ...globalThis.CSS, escape: (value: string) =>
    Array.from(value, character => "\\" + character.codePointAt(0)!.toString(16) + " ").join("") });
  mount("sli.file-audit");
  fireEvent.click(await screen.findByRole("tab", { name: "Настройки" }));
  const picker = await screen.findByRole("combobox", { name: t("plugins.sli.file-audit.settings.excluded_accounts.label") });
  const user = userEvent.setup();
  await user.type(picker, "Backup");
  await user.click(await screen.findByRole("option", { name: "EXAMPLE\\Backup Operators" }));
  expect(await screen.findByRole("button", { name: t("filters.remove", { label: "EXAMPLE\\Backup Operators" }) })).toBeTruthy();
  await user.click(screen.getByRole("button", { name: t("platformSettings.save") }));
  await waitFor(() => expect(writes()).toEqual([{
    path: "/api/plugins/sli.file-audit/settings", method: "PUT",
    body: { key: "file_audit.excluded_accounts", value: ["S-1-5-21-100000001-200000002-300000003-1201"] },
  }]));
});

it("shows the workstation state consistently even when the legacy source pack is disabled", async () => {
  setupSources = [{ pack_id: "sli.windows.workstations", enabled: false, data_state: "unavailable" }];
  pluginStates["sli.workstations"] = { source_count: 0, source_names: [], status: {
    state: "no_sources", reason: "no_sources", next_action: "install_workstation_agent",
    last_data_at: null, error_at: null, error_object: null,
  } };
  mount("sli.workstations");
  const expected = "Включён · Нет подключённых источников · Установите агент SLI на рабочую станцию";
  const header = await screen.findByText(expected, { selector: "header p a" });
  expect(screen.queryByRole("tab", { name: "Подключение" })).toBeNull();
  expect(header).toBeTruthy();
  expect(screen.queryByRole("tab", { name: "Обзор" })).toBeNull();
  expect(screen.getByRole("link", { name: expected }).getAttribute("href")).toBe("/app/agents");
});

it("counts a workstation with an agent before it has collection", async () => {
  pluginStates["sli.workstations"] = { source_count: 1, source_names: ["fixture-workstation"], status: {
    state: "no_sources", reason: "no_collection", next_action: null,
    last_data_at: null, error_at: null, error_object: null,
  } };
  mount("sli.workstations");
  expect(await screen.findByText("Включён · 1 компьютер подключён", { selector: "header p" })).toBeTruthy();
  expect(screen.queryByRole("tab", { name: "Обзор" })).toBeNull();
  expect(screen.queryByRole("tab", { name: "Подключение" })).toBeNull();
});

it("shows one VPN connection guide and a visibly labeled switch while disabled", async () => {
  mount("sli.remote-access");
  expect(await screen.findByRole("switch", { name: "Включить VPN / NPS", checked: false })).toBeTruthy();
  expect(screen.getByText("Включить VPN / NPS")).toBeTruthy();
  expect(screen.getByRole("heading", { name: "VPN / NPS не подключён" })).toBeTruthy();
  expect(within(screen.getByRole("list")).getAllByRole("listitem")).toHaveLength(3);
  expect(screen.queryByRole("tablist")).toBeNull();
  expect(requests.some(request => request.path === "/api/v1/operations/plugins/sli.remote-access")).toBe(false);
});

it("keeps the workstation protection report link without a description paragraph", async () => {
  mount("sli.workstations");
  fireEvent.click(await screen.findByRole("tab", { name: t("pluginPage.tab.reports") }));
  const panel = screen.getByRole("tabpanel");
  expect(within(panel).getByRole("link", { name: "Защита" }).getAttribute("href")).toBe("/app/report/workstations.protection");
  expect(within(panel).queryByText(/Последний снимок Defender/)).toBeNull();
  expect(panel.textContent).not.toMatch(/Время снимка|неизвестные флаги/);
});

it.each(["ru", "en"] as const)("lists the workstation reports without methodology copy in %s", async (locale) => {
  setLocale(locale);
  mount("sli.workstations");
  fireEvent.click(await screen.findByRole("tab", { name: t("pluginPage.tab.reports") }));
  const panel = screen.getByRole("tabpanel");
  for (const key of ["workstations.logons", "workstations.processes", "workstations.usb"]) {
    const link = panel.querySelector(`a[href="/app/report/${key}"]`);
    expect(link).not.toBeNull();
    expect(link?.closest("li")?.querySelector("p")).toBeNull();
  }
});

it("keeps the file audit working-hours link without an empty-settings message", async () => {
  mount("sli.file-audit");
  fireEvent.click(await screen.findByRole("tab", { name: t("pluginPage.tab.settings") }));
  const panel = screen.getByRole("tabpanel");
  expect(within(panel).getByRole("link", { name: t("pluginPage.coreSettings") }).getAttribute("href")).toBe("/app/platform-settings");
  expect(panel.textContent).not.toMatch(/На этой вкладке нет настроек|Откройте «Подключение»/);
});

it("shows the connection action once when Sigma rules and sources are absent", async () => {
  sigmaRulesAvailable = false;
  mount("sli.sigma");
  const panel = await screen.findByRole("tabpanel");
  expect(await within(panel).findByText(t("security.sigma.live.catalog_empty"))).toBeTruthy();
  expect(screen.getAllByText(t("plugins.next.connect_sigma_events"), { exact: false })).toHaveLength(1);
  expect(within(panel).queryByText(t("state.unavailable.title"))).toBeNull();
});

it("names a Sigma rules load failure and can retry", async () => {
  sigmaReadFailed = true;
  mount("sli.sigma");
  expect((await screen.findByRole("alert")).textContent).toContain(t("security.sigma.live.read_failed"));
  sigmaReadFailed = false;
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  expect(await screen.findByRole("row", { name: /Создание скрытого локального пользователя/ })).toBeTruthy();
});

it("shows each registered Accounting source once with its distinct subscription states", async () => {
  pluginStates["sli.remote-access"] = { enabled: true };
  radiusSources = [
    { source_instance_id: "lab-nps", source_state: "manual_enabled" },
    { source_instance_id: "lab-nps", source_state: "subscription_disabled" },
    { source_instance_id: "lab-nps", source_state: "subscription_disabled" },
  ];
  mount("sli.remote-access");
  fireEvent.click(await screen.findByRole("tab", { name: "Подключение" }));
  const row = await screen.findByRole("row", { name: /lab-nps/ });
  expect(within(row).getByText("Сбор разрешён · Подписка отключена")).toBeTruthy();
  expect(screen.queryByText(t("pluginPage.radius.missing"))).toBeNull();
});

it("renders actual AD schema labels, help, defaults and collapsed advanced settings", async () => {
  mount();
  const input = await openSettings();
  expect((input as HTMLInputElement).value).toBe("90");
  expect(screen.getByText("По умолчанию: 90")).toBeTruthy();
  expect(screen.getByText(t("plugins.sli.ad.settings.ad.inactivity_days.help"))).toBeTruthy();
  expect(screen.getByText("Расширенные").closest("details")?.open).toBe(false);
  expect(screen.getAllByRole("button", { name: "Вернуть по умолчанию" }).length).toBeGreaterThan(3);
  expect(writes()).toEqual([]);
});

it("writes only the changed key with a typed value through the existing PUT API", async () => {
  mount(); fireEvent.change(await openSettings(), { target: { value: "120" } });
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await screen.findByText("Настройки сохранены.");
  expect(writes()).toEqual([{ method: "PUT", path: "/api/plugins/sli.ad/settings", body: { key: "ad.inactivity_days", value: 120 } }]);
});

it.each(["0", "3651", "1.5", ""])("blocks invalid AD value %s before writing", async (value) => {
  mount(); fireEvent.change(await openSettings(), { target: { value } });
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Порог неактивности");
  expect(writes()).toEqual([]);
});

it("resets a value to the declared default", async () => {
  settings.values["ad.inactivity_days"] = 150;
  mount(); const input = await openSettings();
  fireEvent.click(within(input.closest(".sli-ds-field") as HTMLElement).getByRole("button", { name: "Вернуть по умолчанию" }));
  expect((input as HTMLInputElement).value).toBe("90");
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await screen.findByText("Настройки сохранены.");
  expect(writes()[0].body?.value).toBe(90);
});

it("retains a settings draft while reading another tab", async () => {
  mount(); fireEvent.change(await openSettings(), { target: { value: "151" } });
  fireEvent.click(screen.getByRole("tab", { name: "Обзор" }));
  fireEvent.click(screen.getByRole("tab", { name: "Настройки" }));
  expect((screen.getByRole("spinbutton", { name: "Порог неактивности, дней" }) as HTMLInputElement).value).toBe("151");
  expect(writes()).toEqual([]);
});

it("renders nested workstation policy controls without a JSON editor", async () => {
  settings = { plugin_id: "sli.workstations", schema: workstations.settings as unknown as SettingsSchema,
    rules: workstations.rules, sources: {}, values: { "workstations.evidence_retention_days": 90, "workstations.logon_policy": null } };
  mount("sli.workstations"); fireEvent.click(await screen.findByRole("tab", { name: "Настройки" }));
  const retention = await screen.findByRole("spinbutton", { name: "Хранение процессов и USB, дней" });
  expect((retention as HTMLInputElement).value).toBe("90");
  expect(screen.queryByText(/Хранить доказательства/)).toBeNull();
  fireEvent.click(await screen.findByRole("button", { name: "Настроить" }));
  fireEvent.click(screen.getByRole("button", { name: "Добавить запись" }));
  expect(screen.getByRole("textbox", { name: "Идентификатор станции" })).toBeTruthy();
  await chooseOption(screen.getByLabelText("Область действия", { selector: "button" }), "1");
  expect(screen.getByRole("textbox", { name: "Путь подразделения" })).toBeTruthy();
  expect(screen.queryByRole("textbox", { name: "Идентификатор станции" })).toBeNull();
});

it("disables and re-enables the workstation rule without removing its configured hours", async () => {
  const schedule = { scope: { kind: "station", station_id: "fixture" }, timezone: "UTC", weekdays: [0],
    start: "09:00", end: "18:00", include_cached_interactive: false };
  settings = { plugin_id: "sli.workstations", schema: workstations.settings as unknown as SettingsSchema,
    rules: workstations.rules, sources: {}, values: { "workstations.logon_policy": { version: 4, policies: [schedule] } } };
  mount("sli.workstations");
  const row = await screen.findByRole("row", { name: /Вход вне разрешённого времени/ });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  fireEvent.click(within(row).getByRole("switch", { checked: true }));
  expect(writes()).toHaveLength(0);
  fireEvent.click(within(row).getByRole("switch", { checked: true }));
  const off = await within(row).findByRole("switch", { checked: false });
  expect(within(row).getByText("Выключен")).toBeTruthy();
  fireEvent.click(off);
  await within(row).findByRole("switch", { checked: true });
  expect(writes().map(request => request.body)).toEqual([
    { key: "workstations.logon_policy", value: { version: 5, enabled: false, policies: [schedule] } },
    { key: "workstations.logon_policy", value: { version: 6, enabled: true, policies: [schedule] } },
  ]);
  fireEvent.click(screen.getByRole("tab", { name: "Настройки" }));
  fireEvent.change(await screen.findByRole("textbox", { name: t("pluginPage.field.end") }), { target: { value: "19:00" } });
  fireEvent.click(screen.getByRole("button", { name: t("platformSettings.save") }));
  await screen.findByText(t("pluginPage.saved"));
  expect(writes().at(-1)?.body).toEqual({ key: "workstations.logon_policy",
    value: { version: 7, enabled: true, policies: [{ ...schedule, end: "19:00" }] } });
});

it("shows a safe validation refusal and preserves the unsaved edit", async () => {
  rejectKey = "ad.inactivity_days";
  mount(); const input = await openSettings(); fireEvent.change(input, { target: { value: "123" } });
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Проверьте параметр");
  expect(document.body.textContent).not.toContain("private-error-marker");
  expect((input as HTMLInputElement).value).toBe("123");
});

it("retains confirmed writes on partial failure and retries only the remaining key", async () => {
  rejectKey = "ad.inactivity_days";
  mount(); fireEvent.change(await openSettings(), { target: { value: "123" } });
  fireEvent.change(screen.getByRole("spinbutton", { name: "Максимальный возраст пароля, дней" }), { target: { value: "180" } });
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await screen.findByText(/Уже сохранено параметров: 1/);
  rejectKey = "";
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await screen.findByText("Настройки сохранены.");
  expect(writes().map((request) => request.body?.key)).toEqual(["ad.password_max_age_days", "ad.inactivity_days", "ad.inactivity_days"]);
});

it("never renders current secret/default, sends only replacements, then clears the field", async () => {
  settings.schema = { type: "object", properties: { credential: { type: "string", minLength: 3, "x-label": "pluginPage.secretReplacement", "x-secret": true, default: "private-default-marker" } } };
  settings.values = { credential: "private-current-marker" };
  mount(); fireEvent.click(await screen.findByRole("tab", { name: "Настройки" }));
  const secret = await screen.findByLabelText(t("pluginPage.secretReplacement"), { selector: "input" }) as HTMLInputElement;
  expect(secret.type).toBe("password"); expect(secret.value).toBe("");
  expect(document.body.innerHTML).not.toContain("private-default-marker");
  expect(document.body.innerHTML).not.toContain("private-current-marker");
  expect(screen.queryByRole("button", { name: "Вернуть по умолчанию" })).toBeNull();
  expect(writes()).toEqual([]);
  fireEvent.change(secret, { target: { value: "fixture-replacement" } });
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await screen.findByText("Настройки сохранены.");
  expect(writes()[0].body).toEqual({ key: "credential", value: "fixture-replacement" });
  expect(secret.value).toBe("");
  expect(client.getQueryData<PluginSettings>(["plugin-settings", "sli.ad"])?.values.credential).toBeNull();
});

it("keeps an observer with read capability from saving or toggling", async () => {
  access.subject.coarse_role = "viewer"; access.platform_owner = false;
  mount(); const input = await openSettings();
  expect(input.closest("fieldset")?.disabled).toBe(true);
  expect(screen.queryByRole("switch")).toBeNull();
  fireEvent.submit(input.closest("form")!);
  expect(writes()).toEqual([]);
});

it("shows denied settings distinctly", async () => {
  denySettings = true; mount(); fireEvent.click(await screen.findByRole("tab", { name: "Настройки" }));
  expect(await screen.findByText(t("state.denied.title"))).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Сохранить" })).toBeNull();
});

it("lists and filters multiple domains without discarding their controllers", async () => {
  mount(); await screen.findByLabelText("Домен", { selector: "button" });
  expect(screen.getByText(/DC-01/)).toBeTruthy(); expect(screen.getByText(/DC-02/)).toBeTruthy();
  await chooseOption(screen.getByLabelText("Домен", { selector: "button" }), "two.example.invalid");
  expect(screen.queryByText(/DC-01/)).toBeNull(); expect(screen.getByText(/DC-02/)).toBeTruthy();
});

it("reads rule declarations and uses registry ownership for reports in the same section", async () => {
  mount(); fireEvent.click(await screen.findByRole("tab", { name: "Правила" }));
  expect(await screen.findByText("Возраст пароля")).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: "Отчёты" }));
  expect((await screen.findByRole("link", { name: "Состояние домена" })).getAttribute("href")).toBe("/app/report/ad.infrastructure");
  expect(screen.queryByRole("link", { name: "Политики" })).toBeNull();
});

it("renders translated schema and tabs in English", async () => {
  setLocale("en"); mount();
  expect(await openSettings()).toBeTruthy();
  expect(screen.getByRole("tab", { name: "Connection" })).toBeTruthy();
  expect(screen.getByText("Advanced")).toBeTruthy();
  expect(document.body.textContent).not.toMatch(/plugins\.sli\./);
});

it("validates nested workstation policy shape, oneOf, bounds and unexpected fields", () => {
  const node = workstations.settings.properties["workstations.logon_policy"] as unknown as SettingsSchema;
  const policy = { version: 1, policies: [{ scope: { kind: "station", station_id: "fixture" }, timezone: "UTC", weekdays: [0, 1], start: "09:00", end: "18:00", include_cached_interactive: false }] };
  expect(validSetting(policy, node)).toBe(true);
  expect(validSetting({ ...policy, unknown: true }, node)).toBe(false);
  expect(validSetting({ ...policy, policies: [{ ...policy.policies[0], weekdays: [0, 0] }] }, node)).toBe(false);
  expect(validSetting({ ...policy, policies: [{ ...policy.policies[0], scope: { kind: "station" } }] }, node)).toBe(false);
  expect(validSetting({ ...policy, policies: [{ ...policy.policies[0], start: "25:00" }] }, node)).toBe(false);
});

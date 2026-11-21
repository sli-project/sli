// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, type AgentCollectionHealth, type OperationsOverview, type SetupStatus } from "../../api/client";
import type { NotificationWorkspace } from "../../api/notification-types";
import { localeRuntime, setLocale, t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import * as actions from "../operations-actions";
import { SystemStatusPage } from "./status";

const access = vi.hoisted(() => ({ platform_owner: true, subject: { coarse_role: "admin" }, capabilities: ["operations.view"] }));
vi.mock("../App", () => ({ useTimeZone: () => ({ timeZone: "UTC" }), useEffectiveAccess: () => access }));

const agent: AgentCollectionHealth["items"][number] = {
  id: "00000000-0000-4000-8000-000000000001", host_id: "00000000-0000-4000-8000-000000000002",
  name: "LAB-DC01", domains: ["example.test"], state: "current", connection: "online", last_seen: "2026-11-14T01:16:00Z",
  last_packet_at: "2026-11-14T01:15:00Z", href: "/app/agents", policy_revision: 1, applied_policy_revision: 1,
  modules: [{ module_id: "sli.windows.ad-dc", channels: [{ channel: "Security", state: "current",
    last_packet_at: "2026-11-14T01:15:00Z", last_import_at: "2026-11-14T01:15:10Z", import_lag_seconds: 0, budget_seconds: 900 }] }],
};
const health = (items: typeof agent[]): AgentCollectionHealth => ({ state: items.length ? "current" : "unknown", checked_at_utc: "2026-11-14T01:16:00Z", active_agents: items.length, current_agents: items.length, items });
const setup = (items: typeof agent[] = []): SetupStatus => ({ api_version: "v1", generated_at_utc: "2026-11-14T01:16:00Z", read_only: true,
  steps: [], sources: [], domains: [], domain_controllers: [], domain_controller_source: null, report_domain: null, collection: null, agent_collection: health(items) });
const operations = {
  api_version: "v1", read_only: true, generated_at_utc: "2026-11-14T01:16:00Z", collection: {}, collector_health: {}, postgres: {},
  workers: { status: "ok", items: [{ worker_name: "notification_delivery", label: "Internal label", state: "active", status: "running", started_at: "2026-11-13T12:00:00Z" }] },
  storage: { disk_pressure: { disk: { used_bytes: 2 * 1024 ** 3, free_bytes: 3 * 1024 ** 3 } } },
} satisfies OperationsOverview;
const notifications = (enabled = false): NotificationWorkspace => ({ channels: [{ kind: "telegram", enabled, state: "not_configured", secret_ref: "fixture-reference",
  tls_mode: "tls", revision: 1, updated_at: "2026-11-14T01:16:00Z", last_accepted_at: null, last_attempt_at: null, last_result_code: null, secret_status: null }],
  can_configure: true, subscriptions: [], counts: { total: 0, new_count: 0, accepted: 0, errors: 0, waiting: 0, other: 0 }, items: [], has_more: false, next_cursor: null, previous_login_at: null });
const clients: QueryClient[] = [];
const postgresVolume = { mount_point: "/srv/sli-db", used_bytes: 2 * 1024 ** 3, free_bytes: 3 * 1024 ** 3 };

it("shows the PostgreSQL mount and omits the backup line until a copy exists", async () => {
  vi.mocked(api.storageOverview).mockResolvedValue({ storage: {
    postgres_volume: { ...postgresVolume, free_bytes: 98 * 1024 ** 3 },
    disk_pressure: { disk: { free_human: "16 GB" } },
    footprint: { components: [], backups: { last_backup_at_utc: null } },
  } });
  renderPage();
  const table = await screen.findByRole("table", { name: "Диск" });
  const row = within(table).getByText("/srv/sli-db").closest("tr")!;
  expect(within(row).getByText("98 ГБ")).toBeTruthy();
  expect(within(row).getByText("2 ГБ")).toBeTruthy();
  expect(screen.queryByText(/^Последняя копия:/)).toBeNull();
});

it.each([true, false, null])("shows the latest backup and reports a shared disk only when confirmed (%s)", async (sameDisk) => {
  setLocale("ru");
  const time = "2026-11-14T01:16:00Z";
  vi.mocked(api.storageOverview).mockResolvedValue({ storage: { footprint: {
    components: [], backups: { last_backup_at_utc: time, same_disk_as_postgres: sameDisk },
  } } });
  renderPage();
  const line = await screen.findByText(/^Последняя копия:/);
  expect(line.textContent).toBe(t(sameDisk ? "systemStatus.lastBackupSameDisk" : "systemStatus.lastBackup", {
    time: formatDateTime(time, "UTC"),
  }));
});

it.each(["ru", "en"] as const)("shows disk admission refusal with an action and clears it after recovery (%s)", async (locale) => {
  setLocale(locale);
  vi.mocked(api.storageOverview).mockResolvedValue({ storage: { agent_inbox_capacity: "full" } });
  renderPage();
  const line = await screen.findByText(t("systemStatus.inboxDiskFull"));
  expect(line.tagName).toBe("P");
  expect(line.closest(".sli-ds-state--banner, details")).toBeNull();
  expect(line.textContent).toContain(locale === "ru" ? "Увеличьте диск сервера" : "Expand the server disk");
  vi.mocked(api.storageOverview).mockResolvedValue({ storage: { agent_inbox_capacity: "ok" } });
  await clients[clients.length - 1].invalidateQueries({ queryKey: ["operations-storage"] });
  await waitFor(() => expect(screen.queryByText(t("systemStatus.inboxDiskFull"))).toBeNull());
});

it.each(["ru", "en"] as const)("names the failed disk measurement and action (%s)", async (locale) => {
  setLocale(locale);
  vi.mocked(api.storageOverview).mockResolvedValue({ storage: { agent_inbox_capacity: "unavailable" } });
  renderPage();
  expect(await screen.findByText(t("systemStatus.inboxDiskUnavailable"))).toBeTruthy();
});

it.each(["ru", "en"] as const)("shows the retained packet refusal in the source row in %s", async (locale) => {
  setLocale(locale);
  const data = setup([{ ...agent, modules: [{ module_id: "sli.windows.ad-dc", channels: [{ ...agent.modules[0].channels[0],
    import_failure_reason: "short_event_attestation_failed", import_failure_at: "2026-11-14T01:16:00Z" }] }] }]);
  vi.mocked(api.setupStatus).mockResolvedValue(data);
  renderPage();
  const fact = await screen.findByText(locale === "ru" ? /^Пакет событий LAB-DC01 отклонён: происхождение не подтверждено/ : /^Event packet from LAB-DC01 rejected: origin could not be verified/);
  expect(fact.closest("tr")).toBeTruthy();
  expect(fact.textContent).toContain(formatDateTime("2026-11-14T01:16:00Z", "UTC", { withYear: false }));
  expect(fact.closest(".sli-ds-state--banner, details")).toBeNull();
  expect(document.body.textContent).not.toContain("short_event_attestation_failed");
});

it.each(["ru", "en"] as const)("shows a declared data gap as one plain line in %s", async (locale) => {
  setLocale(locale);
  const data = setup([{ ...agent }]);
  data.agent_collection!.items[0].data_gaps = [
    { from_utc: "2026-11-01T01:16:00Z", to_utc: "2026-11-15T01:16:00Z" },
    { from_utc: "2026-11-01T01:16:00Z", to_utc: "2026-11-15T01:16:00Z" },
  ];
  vi.mocked(api.setupStatus).mockResolvedValue(data);
  renderPage();
  const line = await screen.findByText(locale === "ru" ? /^нет данных с LAB-DC01 за / : /^No data from LAB-DC01 for /);
  expect(line.tagName).toBe("P");
  expect(line.textContent).toContain(locale === "ru" ? "01.11.2026" : "Nov 1, 2026");
  expect(line.textContent).toContain(locale === "ru" ? "15.11.2026" : "Nov 15, 2026");
  expect(line.closest(".sli-ds-state--banner, details")).toBeNull();
  expect(screen.queryAllByText(locale === "ru" ? /^нет данных с / : /^No data from /)).toHaveLength(1);
});
function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  clients.push(client);
  return render(<QueryClientProvider client={client}><SystemStatusPage/></QueryClientProvider>);
}

it.each([["ru", "Консоль сервера"], ["en", "Server console"]] as const)("opens the administrator's Cockpit terminal in a new tab (%s)", async (locale, label) => {
  setLocale(locale);
  const url = "https://sli.example.test:9090/system/terminal";
  vi.mocked(api.diagnostics).mockResolvedValue({ status: "ok", web_console: { available: true, url } });
  renderPage();
  const link = await screen.findByRole("link", { name: label });
  expect(link.getAttribute("href")).toBe(url);
  expect(link.getAttribute("target")).toBe("_blank");
  expect(link.getAttribute("rel")).toContain("noopener");
});

it.each([["admin", false], ["operator", true], ["viewer", true]] as const)("hides the Cockpit terminal for %s when availability is %s", async (role, available) => {
  access.subject.coarse_role = role;
  access.platform_owner = role === "admin";
  vi.mocked(api.diagnostics).mockResolvedValue({ status: "ok", release_metadata: { project_version: "1.0.0" },
    web_console: { available, url: available ? "https://sli.example.test:9090/system/terminal" : null } });
  renderPage();
  await screen.findByText(/1\.0\.0/);
  expect(screen.queryByRole("link", { name: t("systemStatus.serverConsole") })).toBeNull();
});

it.each(["ru", "en"] as const)("shows one Security log full line with the exact record ID and action in %s", async (locale) => {
  setLocale(locale);
  const event = { server: "dc.example.test", time_created_utc: "2026-11-14T01:16:42Z", record_id: "9007199254740993" };
  vi.mocked(api.securityLogFull).mockResolvedValue({ items: [event] });
  renderPage();
  const message = locale === "ru" ? /журнал Security заполнился/ : /the Security log filled up/;
  const line = await screen.findByText(message);
  expect(line.tagName).toBe("P");
  expect(line.closest(".sli-ds-state--banner, details")).toBeNull();
  expect(line.textContent).toContain(event.server);
  expect(line.textContent).toContain(formatDateTime(event.time_created_utc, "UTC", { seconds: true }));
  expect(line.textContent).toContain(event.record_id);
  expect(line.textContent).toContain(locale === "ru" ? "Часть событий аудита могла не записаться" : "Some audit events may not have been recorded");
  expect(line.textContent).toContain(locale === "ru" ? "включите перезапись" : "enable overwriting");
  expect(screen.getAllByText(message)).toHaveLength(1);
  vi.mocked(api.securityLogFull).mockResolvedValue({ items: [] });
  await clients[clients.length - 1].invalidateQueries({ queryKey: ["operations-security-log-full"] });
  await waitFor(() => expect(screen.queryByText(message)).toBeNull());
});

it.each(["ru", "en"] as const)("shows an unresolved password detection domain with the agent and action in %s", async (locale) => {
  setLocale(locale);
  vi.mocked(api.setupStatus).mockResolvedValue(setup([{ ...agent, password_domain_required: true }]));
  renderPage();
  const line = await screen.findByText(t("systemStatus.passwordDomainRequired", { name: agent.name }));
  expect(line.closest("tr")).toBeTruthy();
  expect(line.textContent).toContain("LAB-DC01");
  expect(line.textContent).toContain(locale === "ru" ? "проверьте домен контроллера" : "check the controller’s domain");
  expect(line.closest(".sli-ds-state--banner, details")).toBeNull();
});

beforeEach(() => {
  access.subject.coarse_role = "admin";
  access.platform_owner = true;
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  vi.spyOn(api, "setupStatus").mockResolvedValue(setup());
  vi.spyOn(api, "operations").mockResolvedValue(operations);
  vi.spyOn(api, "operationsWorkers").mockResolvedValue({ workers: operations.workers });
  vi.spyOn(api, "storageOverview").mockResolvedValue({ storage: { ...operations.storage, postgres_volume: postgresVolume } });
  vi.spyOn(api, "diagnostics").mockResolvedValue({ status: "ok", release_metadata: { project_version: "1.0.0", generated_at_utc: "2026-11-01T01:00:00Z" } });
  vi.spyOn(api, "securityLogFull").mockResolvedValue({ items: [] });
  vi.spyOn(api, "notificationWorkspace").mockResolvedValue(notifications());
  vi.spyOn(api, "telegramSetup").mockResolvedValue({ secret_set: true, chat_bound: true });
  vi.spyOn(api, "smtpSetupStatus").mockRejectedValue(new Error("not requested"));
});
afterEach(() => { cleanup(); clients.splice(0).forEach((client) => client.clear()); vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("keeps one source and shows duplicate, identity conflict and old-version actions as table rows (%s)", async (locale) => {
  setLocale(locale);
  const data = setup([{ ...agent, duplicate_agents: 2, identity_conflict: true }]);
  data.agent_collection!.replaced_agents = [{ ...agent, id: "old-agent", agent_version: "1.0.0", replacement_version: "1.1.0" }];
  vi.mocked(api.setupStatus).mockResolvedValue(data);
  renderPage();
  expect(await screen.findByText(locale === "ru" ? "Заменён версией 1.1.0" : "Replaced by version 1.1.0")).toBeTruthy();
  expect(screen.getByText(t("agents.twoAgents", { name: "LAB-DC01" }))).toBeTruthy();
  expect(screen.getByText(t("agents.removeExtra"))).toBeTruthy();
  expect(screen.getByText(t("agents.identityConflict"))).toBeTruthy();
  const sources = screen.getByRole("table", { name: t("systemStatus.sources") });
  expect(within(sources).getAllByRole("row")).toHaveLength(2);
});

it.each(["ru", "en"] as const)("shows erroneously revoked agents with the registration action (%s)", async (locale) => {
  setLocale(locale);
  const data = setup([agent]);
  data.agent_collection!.replaced_agents = [{ id: "revoked-agent", name: "dc.example.test", certificate_reissue_required: true }];
  vi.mocked(api.setupStatus).mockResolvedValue(data);
  renderPage();
  expect(await screen.findByText(t("agents.certificateReissueRequired", { name: "dc.example.test" }))).toBeTruthy();
  expect(screen.getByRole("link", { name: t("agents.registerAgain") }).getAttribute("href")).toBe("/app/agents?register=1");
  expect(screen.queryByRole("button", { name: t("agents.removeOld") })).toBeNull();
});

it.each(["ru", "en"] as const)("names checks blocked by missing DC auditing in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  vi.mocked(api.setupStatus).mockResolvedValue(setup([{ ...agent, windows_audit: {
    policy_revision: 1, reported_at: "2026-11-15T01:19:00Z", management_state: "disabled", command_line_enabled: null,
    families: { domain_controller: { state: "missing", non_security_channels: [], required: [{
      subcategory: "logon", guid: "0cce9215-69ae-11d9-bed3-505054503030", success: true, failure: true,
      actual_success: true, actual_failure: false, detections: [1, 2, 3], domain_changes: false,
    }] } },
  } }]));
  renderPage();
  const checks = await screen.findByRole("table", { name: locale === "ru" ? "Неработающие проверки" : "Checks not running" });
  expect(checks.textContent).toContain("LAB-DC01");
  expect(within(checks).getAllByRole("link", { name: locale === "ru" ? "Включите аудит на LAB-DC01" : "Enable auditing on LAB-DC01" }).length).toBeGreaterThan(0);
  expect(screen.getByRole("table", { name: t("systemStatus.sources") }).textContent).toContain(locale === "ru" ? "Аудит Windows выключен" : "Windows auditing is off");
});

it("links one source row with the reported audit cause, time and corrective action to its agent", async () => {
  const source = structuredClone(agent);
  source.windows_audit = { policy_revision: 1, checked_at: "2026-11-14T01:16:00Z", reported_at: "2026-11-14T01:17:00Z",
    management_state: "blocked", command_line_enabled: null, families: { domain_controller: {
      state: "managed_by_gpo", non_security_channels: [], required: [{ guid: "fixture", subcategory: "logon", success: false,
        failure: true, actual_success: true, actual_failure: false, state: "managed_by_gpo" }],
    } } };
  vi.mocked(api.setupStatus).mockResolvedValue(setup([source]));
  renderPage();
  const fact = await screen.findByText("Аудит выключен политикой домена · 14.11, 01:16");
  const table = screen.getByRole("table", { name: "Источники" });
  const row = within(table).getAllByRole("row")[1];
  expect(within(row).getByText(fact.textContent!)).toBe(fact);
  expect(within(row).getByText("Включите аудит в политике домена")).toBeTruthy();
  expect(within(row).getByRole("link", { name: source.name }).getAttribute("href")).toBe(`/app/agents?agent_id=${source.id}`);
});

it("does not show a failure while a successful response is still pending", async () => {
  let resolve!: (value: OperationsOverview) => void;
  vi.mocked(api.operationsWorkers).mockReturnValue(new Promise((done) => { resolve = done; }));
  renderPage();
  await screen.findByRole("table", { name: "Источники" });
  expect(screen.queryByText("Не загрузились Службы сервера")).toBeNull();
  expect(screen.queryByText("Не загрузились Диск")).toBeNull();
  resolve(operations);
  expect(await screen.findByRole("table", { name: "Службы сервера" })).toBeTruthy();
});

it("shows three first-run steps without agents and links to the next actions", async () => {
  renderPage();
  const steps = await screen.findByRole("list", { name: "Первый запуск" });
  expect(within(steps).getAllByRole("listitem")).toHaveLength(3);
  expect(steps.textContent).toContain("Первые данные: ждём");
  expect(within(steps).getByRole("link", { name: "Подключить" }).getAttribute("href")).toBe("/app/agents");
  expect(within(steps).getByRole("link", { name: "Настроить" }).getAttribute("href")).toBe("/app/notifications");
  expect(screen.queryByText(/Неизвестно|Не определено|Нет данных|не подтвержд/)).toBeNull();
});

it("keeps table skeletons visible until slow sources and services finish", async () => {
  let resolveSetup!: (value: SetupStatus) => void;
  let resolveWorkers!: (value: Pick<OperationsOverview, "workers">) => void;
  vi.mocked(api.setupStatus).mockImplementation(() => new Promise((resolve) => { resolveSetup = resolve; }));
  vi.mocked(api.operationsWorkers).mockImplementation(() => new Promise((resolve) => { resolveWorkers = resolve; }));
  renderPage();
  await screen.findByRole("table", { name: "Диск" });
  expect(screen.getAllByRole("status").filter((element) => element.getAttribute("aria-busy") === "true")).toHaveLength(2);
  expect(screen.queryByText(/Не загрузились/)).toBeNull();
  resolveSetup(setup([agent])); resolveWorkers({ workers: operations.workers });
  expect(await screen.findByRole("table", { name: "Источники" })).toBeTruthy();
  expect(await screen.findByRole("table", { name: "Службы сервера" })).toBeTruthy();
  expect(screen.queryAllByRole("status").filter((element) => element.getAttribute("aria-busy") === "true")).toHaveLength(0);
});

it("shows actual launch times for running and disabled services", async () => {
  vi.mocked(api.operationsWorkers).mockResolvedValue({ workers: { items: [
    ...operations.workers.items,
    { worker_name: "semantic", label: "", state: "disabled", status: "stopped", started_at: "2026-11-12T09:30:00Z" },
  ] } });
  renderPage();
  const table = await screen.findByRole("table", { name: "Службы сервера" });
  expect(table.textContent).toContain("13.11, 12:00");
  expect(table.textContent).toContain("12.11, 09:30");
  expect(table.textContent).toContain(t("systemStatus.service.disabled"));
  expect(table.textContent).not.toContain(t("systemStatus.service.failed"));
});

it("hides onboarding when an agent has sent data and a channel is configured", async () => {
  vi.mocked(api.setupStatus).mockResolvedValue(setup([agent]));
  vi.mocked(api.notificationWorkspace).mockResolvedValue(notifications(true));
  renderPage();
  await waitFor(() => expect(api.telegramSetup).toHaveBeenCalledWith("status"));
  await waitFor(() => expect(screen.queryByRole("list", { name: "Первый запуск" })).toBeNull());
  expect(await screen.findByText("LAB-DC01 присылает данные")).toBeTruthy();
  expect(screen.getByRole("table", { name: "Диск" }).textContent).toContain("3 ГБ");
});

it("does not call an enabled channel configured without a saved token and chat", async () => {
  vi.mocked(api.setupStatus).mockResolvedValue(setup([agent]));
  vi.mocked(api.notificationWorkspace).mockResolvedValue(notifications(true));
  vi.mocked(api.telegramSetup).mockResolvedValue({ secret_set: false, chat_bound: false });
  renderPage();
  expect(await screen.findByRole("list", { name: "Первый запуск" })).toBeTruthy();
  expect(await screen.findByText(/Первые данные: получены в/)).toBeTruthy();
});

it("shows a silent source with its name, last packet time and action", async () => {
  const silent = structuredClone(agent);
  silent.state = "error";
  silent.modules[0].channels[0] = { ...silent.modules[0].channels[0], state: "error", failure_reason: "packet_stale", last_packet_at: "2026-11-08T01:16:00Z" };
  vi.mocked(api.setupStatus).mockResolvedValue(setup([silent]));
  renderPage();
  const fact = await screen.findByText("LAB-DC01 не присылает данные с 08.11, 01:16");
  expect(within(fact.closest("tr")!).getByText("Проверьте службу SLIAgentNet")).toBeTruthy();
});

it("keeps services and disk visible when the sources request fails", async () => {
  vi.mocked(api.setupStatus).mockRejectedValue(new Error("fixture failure"));
  renderPage();
  expect(await screen.findByRole("table", { name: "Службы сервера" })).toBeTruthy();
  expect(screen.getByRole("table", { name: "Диск" })).toBeTruthy();
  expect(screen.getByText("Не загрузились Источники")).toBeTruthy();
  expect(screen.queryByRole("table", { name: "Источники" })).toBeNull();
});

it("shows source data while the server request is still pending, then handles its failure", async () => {
  let reject: (error: Error) => void = () => undefined;
  vi.mocked(api.operationsWorkers).mockImplementation(() => new Promise((_resolve, fail) => { reject = fail; }));
  vi.mocked(api.setupStatus).mockResolvedValue(setup([agent]));
  renderPage();
  expect(await screen.findByText("LAB-DC01 присылает данные")).toBeTruthy();
  reject(new Error("fixture failure"));
  expect(await screen.findByText("Не загрузились Службы сервера")).toBeTruthy();
  expect(screen.getByRole("table", { name: "Источники" })).toBeTruthy();
  expect(screen.getByRole("table", { name: "Диск" })).toBeTruthy();
  expect(api.operations).not.toHaveBeenCalled();
});

it("excludes archived domains and hidden modules and services", async () => {
  const data = setup([agent, { ...agent, id: "archived-agent", name: "archived-host", domains: ["archive.example.test"] },
    { ...agent, id: "hidden-agent", name: "hidden-host", modules: [{ module_id: "sli.workstations", channels: [] }] }]);
  data.domains = [{ fqdn: "archive.example.test", netbios_name: null, is_archived: true, server_count: 1 }];
  vi.mocked(api.setupStatus).mockResolvedValue(data);
  vi.mocked(api.operationsWorkers).mockResolvedValue({ workers: { items: [...operations.workers.items,
    { worker_name: "radius_accounting", label: "Hidden service", state: "active" }] } });
  renderPage();
  expect(await screen.findByText("LAB-DC01 присылает данные")).toBeTruthy();
  expect(screen.queryByText(/archived-host|hidden-host|Hidden service/)).toBeNull();
});

it.each(["ru", "en"] as const)("localizes the page and copies the update command in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  const { container } = renderPage();
  await screen.findByRole("table", { name: t("systemStatus.services") });
  fireEvent.click(screen.getByRole("button", { name: t("systemStatus.copy") }));
  await screen.findByRole("button", { name: t("systemStatus.copied") });
  expect(writeText).toHaveBeenCalledWith("sudo apt update && sudo apt upgrade");
  expect(container.textContent).not.toContain("01.11"); // Build time is not installation time.
  if (locale === "en") expect(container.textContent).not.toMatch(/[А-Яа-яЁё]/);
});

it("downloads the existing diagnostics export", async () => {
  const download = vi.spyOn(actions, "downloadOperationsExport").mockReturnValue("2026-11-14T01:16:00Z");
  renderPage();
  await screen.findByRole("table", { name: "Службы сервера" });
  fireEvent.click(screen.getByRole("button", { name: "Скачать диагностику" }));
  await waitFor(() => expect(download).toHaveBeenCalledWith(operations));
});

it("shows lost connection for an agent that connected before and has an enabled channel without a first packet past its deadline", async () => {
  const lost = structuredClone(agent);
  lost.state = "error"; lost.connection = "offline"; lost.last_seen = "2026-11-13T20:00:00Z"; lost.last_packet_at = null;
  lost.modules[0].channels[0] = { channel: "Security", state: "error", failure_reason: "packet_missing", last_packet_at: null, last_import_at: null, import_lag_seconds: null, budget_seconds: 900 };
  vi.mocked(api.setupStatus).mockResolvedValue(setup([lost]));
  renderPage();
  const fact = await screen.findByText("Агент на LAB-DC01 не выходит на связь с 13.11, 20:00");
  expect(within(fact.closest("tr")!).getByText("Проверьте службу SLIAgentNet")).toBeTruthy();
  expect(screen.queryByText("LAB-DC01 ещё не присылал данные")).toBeNull();
});

it("shows lost connection instead of a waiting neighbour channel when another channel has data", async () => {
  const lost = structuredClone(agent);
  lost.connection = "offline"; lost.last_seen = "2026-11-13T20:00:00Z";
  lost.modules[0].channels.push({ channel: "Directory Service", state: "waiting", last_packet_at: null, last_import_at: null, import_lag_seconds: null, budget_seconds: 900 });
  vi.mocked(api.setupStatus).mockResolvedValue(setup([lost]));
  renderPage();
  expect(await screen.findByText("Агент на LAB-DC01 не выходит на связь с 13.11, 20:00")).toBeTruthy();
});

it("explains that a new agent has never connected while it is within its deadline", async () => {
  const fresh = structuredClone(agent);
  fresh.state = "waiting"; fresh.connection = "never_seen"; fresh.last_seen = null; fresh.last_packet_at = null;
  fresh.modules[0].channels[0] = { channel: "Security", state: "waiting", last_packet_at: null, last_import_at: null, import_lag_seconds: null, budget_seconds: 900 };
  vi.mocked(api.setupStatus).mockResolvedValue(setup([fresh]));
  renderPage();
  expect(await screen.findByText("Агент на LAB-DC01 ещё не выходил на связь")).toBeTruthy();
});

const directory = { channel: "Directory Service", state: "error" as const, failure_reason: "packet_missing" as const, last_packet_at: null,
  last_import_at: null, import_lag_seconds: null, budget_seconds: 900, issue_since_utc: "2026-11-14T00:30:00Z" };

it("names a silent expected channel and its own deadline while another channel is fresh", async () => {
  const partial = structuredClone(agent);
  partial.state = "error"; partial.modules[0].channels.push(directory);
  vi.mocked(api.setupStatus).mockResolvedValue(setup([partial]));
  renderPage();
  const fact = await screen.findByText("LAB-DC01 не присылает данные из канала Directory Service с 14.11, 00:30");
  expect(within(fact.closest("tr")!).getByText("Проверьте службу SLIAgentNet")).toBeTruthy();
  expect(fact.textContent).not.toContain("01:15");
});

it("gives no warning for an intentionally disabled channel", async () => {
  vi.mocked(api.setupStatus).mockResolvedValue(setup([agent]));
  renderPage();
  expect(await screen.findByText("LAB-DC01 присылает данные")).toBeTruthy();
  expect(screen.queryByText(/Directory Service/)).toBeNull();
});

it("keeps lost connection above a silent expected channel", async () => {
  const lost = structuredClone(agent);
  lost.state = "error"; lost.connection = "offline"; lost.last_seen = "2026-11-13T20:00:00Z"; lost.modules[0].channels.push(directory);
  vi.mocked(api.setupStatus).mockResolvedValue(setup([lost]));
  renderPage();
  expect(await screen.findByText("Агент на LAB-DC01 не выходит на связь с 13.11, 20:00")).toBeTruthy();
  expect(screen.queryByText(/Directory Service/)).toBeNull();
});

it.each(["ru", "en"] as const)("confirms restoring the previously delivering agent (%s)", async (locale) => {
  setLocale(locale);
  vi.mocked(api.setupStatus).mockResolvedValue(setup([{ ...agent, agent_version: "1.1.0", delivery_fallback: {
    agent_id: "old-agent", last_packet_at: "2026-11-14T00:00:00Z", since: "2026-11-14T00:30:00Z", can_restore: true,
  } }]));
  const action = vi.spyOn(api, "agentAction").mockResolvedValue({});
  renderPage();
  const fact = await screen.findByText(t("agents.deliveryFallback", { name: "LAB-DC01", version: "1.1.0",
    since: formatDateTime("2026-11-14T00:30:00Z", "UTC", { withYear: false }),
    until: formatDateTime("2026-11-14T00:00:00Z", "UTC", { withYear: false }) }));
  const label = t("agents.restoreOld");
  fireEvent.click(within(fact.closest("tr")!).getByRole("button", { name: label }));
  expect(action).not.toHaveBeenCalled();
  const dialog = screen.getByRole("dialog");
  expect(dialog.textContent).toContain("LAB-DC01");
  fireEvent.click(within(dialog).getByRole("button", { name: label }));
  await waitFor(() => expect(action).toHaveBeenCalledWith("restore", { agent_id: "old-agent", current_agent_id: agent.id }));
});

it("does not offer restoration for a revoked old agent", async () => {
  vi.mocked(api.setupStatus).mockResolvedValue(setup([{ ...agent, delivery_fallback: {
    agent_id: "old-agent", last_packet_at: "2026-11-14T00:00:00Z", since: null, can_restore: false,
  } }]));
  renderPage();
  await screen.findByText(/новый агент/);
  expect(screen.queryByRole("button", { name: t("agents.restoreOld") })).toBeNull();
});

it("cancels restoration without changing agents and keeps a failed restoration in the dialog", async () => {
  vi.mocked(api.setupStatus).mockResolvedValue(setup([{ ...agent, delivery_fallback: {
    agent_id: "old-agent", last_packet_at: "2026-11-14T00:00:00Z", since: null, can_restore: true,
  } }]));
  const action = vi.spyOn(api, "agentAction").mockRejectedValue(new Error("agent_restore_conflict"));
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: t("agents.restoreOld") }));
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: t("agents.cancel") }));
  expect(action).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: t("agents.restoreOld") }));
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: t("agents.restoreOld") }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", t("agents.restoreError"));
  expect(screen.getByRole("dialog")).toBeTruthy();
});

it.each(["ru", "en"] as const)("shows running file-backed services and hides retired roles (%s)", async (locale) => {
  setLocale(locale);
  vi.mocked(api.operationsWorkers).mockResolvedValue({ workers: { items: [
    ...["notification_delivery", "core_job_executor_light"].map((worker_name) => ({ worker_name, label: "", state: "active", status: "running",
      observation_source: "native_process_heartbeat", started_at: "2026-11-13T12:00:00Z" })),
    ...["collection", "agent_import", "gpo_snapshot", "password_producer", "password_risk", "smtp_delivery", "telegram_delivery"].map((worker_name) =>
      ({ worker_name, label: "", state: "stale", status: "stopped" })),
  ] } });
  renderPage();
  const table = await screen.findByRole("table", { name: t("systemStatus.services") });
  const rows = within(table).getAllByRole("row").slice(1);
  expect(rows.map((row) => row.textContent)).toEqual([
    expect.stringContaining(t("systemStatus.service.notifications")),
    expect.stringContaining(t("systemStatus.service.light")),
  ]);
  for (const row of rows) expect(row.textContent).toContain(t("systemStatus.service.running"));
  expect(table.textContent).not.toContain(t("systemStatus.service.failed"));
  expect(table.textContent).not.toContain(t("systemStatus.service.disabled"));
  expect(table.textContent).not.toContain(t("systemStatus.service.check"));
});

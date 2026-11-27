// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiResponseError, type PluginState } from "../../api/client";

const mocks = vi.hoisted(() => ({ list: vi.fn(), change: vi.fn(), reportData: vi.fn() }));
vi.mock("../../api/client", async (importOriginal) => {
  const original = await importOriginal<typeof import("../../api/client")>();
  return { ...original, api: { ...original.api, plugins: () => mocks.list(),
    setPluginEnabled: (item: PluginState, enabled: boolean) => mocks.change(item, enabled),
    reportV2Data: (...args: Parameters<typeof original.api.reportV2Data>) => mocks.reportData(...args),
  } };
});
import { localeRuntime, setLocale, t } from "../../i18n";
import { createAdminPlaceholderRoutes } from "./navigation-pages";
import { PluginPage } from "./plugin-page";
import { PluginsPage } from "./plugins";

const item: PluginState = { plugin_id: "sli.ad", package_version: "0.1.0", installed: true,
  configured: true, enabled: true, receiving_data: false, component_runtime: "running", queue_state: "drained", revision: 4, last_data_at_utc: null,
  source_names: ["DC01"], source_count: 1,
  status: { state: "waiting", last_data_at: null, error_at: null, error_object: null } };
vi.mock("../App", async (importOriginal) => ({
  ...await importOriginal<typeof import("../App")>(),
  useEffectiveAccess: () => ({ subject: { coarse_role: "viewer" }, capabilities: ["operations.view"], reports: [] }),
}));

const disabledStatus = { ...item.status!, state: "disabled" as const };

function mount(content = <PluginsPage/>) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}>{content}</QueryClientProvider>);
}
beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => {
  cleanup();
  setLocale("ru");
  vi.resetAllMocks();
  vi.restoreAllMocks();
});

async function openDisableDialog() {
  fireEvent.click(await screen.findByRole("button", { name: "Выключить" }));
  return screen.findByRole("dialog");
}

async function confirmDisable() {
  fireEvent.click(within(await openDisableDialog()).getByRole("button", { name: "Выключить" }));
}

it("uses the page heading to name the All plugins table", async () => {
  mocks.list.mockResolvedValue({ items: [item], can_manage: false });
  mount();
  const table = await screen.findByRole("table", { name: t("plugins.title") });
  const heading = screen.getByRole("heading", { name: t("plugins.title") });
  expect(document.getElementById(table.getAttribute("aria-labelledby") ?? "")).toBe(heading);
  expect(table.querySelector("caption")).toBeNull();
});

it("opens the failing module row on System status", async () => {
  const errorAt = "2026-11-26T08:00:00Z";
  mocks.list.mockResolvedValue({ items: [{ ...item,
    status: { state: "error", last_data_at: null, error_at: errorAt, error_object: "DC01" },
  }], can_manage: false });
  const view = mount();
  const link = await screen.findByRole("link", { name: /^Включён · Сбой сбора · DC01 · 26/ });
  const href = link.getAttribute("href")!;
  view.unmount();

  const root = createRootRoute();
  const router = createRouter({
    routeTree: root.addChildren(createAdminPlaceholderRoutes(root)),
    history: createMemoryHistory({ initialEntries: [href] }),
    basepath: "/app",
  });
  mount(<RouterProvider router={router}/>);
  expect(await screen.findByRole("heading", { name: t("shell.adminNav.status") })).toBeTruthy();
  const table = await screen.findByRole("table", { name: t("plugins.title") });
  const row = within(table).getByRole("row", { name: /Active Directory Включён · Сбой сбора · DC01/ });
  expect(row.contains(document.getElementById(new URL(href, "http://localhost").hash.slice(1)))).toBe(true);
});

it("disables through the current revision and reads the new status from the server", async () => {
  const drained = { ...item, enabled: false, component_runtime: "draining", status: disabledStatus };
  mocks.list.mockResolvedValueOnce({ items: [item], can_manage: true }).mockResolvedValue({ items: [drained], can_manage: true });
  mocks.change.mockResolvedValue({ item: drained });
  mount();
  const dialog = await openDisableDialog();
  expect(dialog.textContent).toContain("Сбор и проверки Active Directory остановятся на всех агентах.");
  expect(mocks.change).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole("button", { name: t("agents.cancel") }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(mocks.change).not.toHaveBeenCalled();
  await confirmDisable();
  await waitFor(() => expect(mocks.change).toHaveBeenCalledWith(item, false));
  expect((await screen.findByRole("button", { name: "Включить" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(t("plugins.status.disabled"))).toBeTruthy();
  expect(screen.queryByText(new RegExp(t("plugins.status.waiting")))).toBeNull();
});

it("keeps delegated readers from mutating", async () => {
  mocks.list.mockResolvedValue({ items: [item], can_manage: false });
  mount();
  await screen.findByText(new RegExp(t("plugins.status.waiting")));
  expect(screen.queryByRole("button", { name: "Выключить" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Включить" })).toBeNull();
  expect(screen.queryByText(/^Работает/)).toBeNull();
});

it("cannot enable an unconfigured plugin", async () => {
  mocks.list.mockResolvedValue({ items: [{ ...item, enabled: false, configured: false, component_runtime: "stopped" }], can_manage: true });
  mount();
  expect((await screen.findByRole("button", { name: "Включить" }) as HTMLButtonElement).disabled).toBe(true);
});

it("shows a rejected mutation without claiming a disabled plugin", async () => {
  mocks.list.mockResolvedValue({ items: [item], can_manage: true });
  mocks.change.mockRejectedValue(new Error("plugin_state_conflict"));
  mount();
  await confirmDisable();
  expect((await screen.findByRole("alert")).textContent).toContain("Состояние не изменено");
  expect(screen.queryByText("Плагин выключен")).toBeNull();
});

it("names workstations and enables then disables from the registered drained state", async () => {
  const stopped = { ...item, plugin_id: "sli.workstations", enabled: false, component_runtime: "stopped", revision: 1, status: disabledStatus };
  const running = { ...stopped, enabled: true, component_runtime: "running", revision: 2, status: item.status };
  const disabled = { ...stopped, revision: 3 };
  let current: PluginState = stopped;
  mocks.list.mockImplementation(async () => ({ items: [current], can_manage: true }));
  mocks.change.mockImplementation(async (_item: PluginState, enabled: boolean) => {
    current = enabled ? running : disabled;
    return { item: current };
  });
  mount();
  expect(await screen.findByRole("row", { name: /Рабочие станции/ })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Включить" }));
  const disable = await screen.findByRole("button", { name: "Выключить" });
  expect(mocks.change).toHaveBeenNthCalledWith(1, stopped, true);
  await waitFor(() => expect((disable as HTMLButtonElement).disabled).toBe(false));
  await confirmDisable();
  await waitFor(() => expect((screen.getByRole("button", { name: "Включить" }) as HTMLButtonElement).disabled).toBe(false));
  expect(mocks.change).toHaveBeenNthCalledWith(2, running, false);
  expect(screen.getByText(t("plugins.status.disabled"))).toBeTruthy();
});

it.each([
  ["plugin_management_owner_or_admin_required", "Изменять состояние может только владелец"],
  ["plugin_not_found", "Плагин не найден"],
  ["plugin_state_request_invalid", "Некорректный запрос"],
  ["plugin_revision_conflict", "Состояние плагина изменилось"],
  ["plugin_not_installed", "Плагин не зарегистрирован"],
  ["plugin_not_configured", "Плагин не настроен"],
  ["plugin_runtime_not_stopped", "Плагин ещё не остановлен"],
  ["plugin_runtime_not_running", "Плагин не находится в рабочем состоянии"],
  ["plugin_queue_not_drained", "Очередь плагина ещё не опустела"],
  ["plugin_active_leases", "У плагина есть активные задания"],
  ["plugin_runtime_transition_unsupported", "Управление этим плагином пока не поддерживается"],
  ["plugin_runtime_precondition_failed", "Компоненты плагина не готовы"],
  ["plugin_state_unavailable", "Состояние плагинов недоступно"],
])("shows the safe translated server refusal %s", async (code, message) => {
  mocks.list.mockResolvedValue({ items: [item], can_manage: true });
  mocks.change.mockRejectedValue(new ApiResponseError(409, code, "private-marker"));
  mount();
  await confirmDisable();
  expect((await screen.findByRole("alert")).textContent).toContain(message);
  expect(screen.getByRole("alert").textContent).not.toContain("private-marker");
  expect(screen.queryByText("Плагин выключен")).toBeNull();
});

it("keeps unknown server details out of the fallback error", async () => {
  mocks.list.mockResolvedValue({ items: [item], can_manage: true });
  mocks.change.mockRejectedValue(new ApiResponseError(500, "unknown_reason", "private-marker"));
  mount();
  await confirmDisable();
  expect((await screen.findByRole("alert")).textContent).toContain("Состояние не изменено");
  expect(screen.getByRole("alert").textContent).not.toContain("private-marker");
});

it.each(["ru", "en"] as const)("keeps only the latest received data visible when a plugin is disabled in %s", async (locale) => {
  setLocale(locale);
  mocks.list.mockResolvedValue({ items: [{ ...item, enabled: false, status: disabledStatus,
    data_receipts: { state: "observed", last_received_at: "2025-01-01T12:00:00Z", last_imported_at: null,
      last_snapshot_completed_at: "2026-01-02T12:00:00Z" } }], can_manage: false });
  mount();
  expect(await screen.findByText(/2026/)).toBeTruthy();
  expect(screen.queryByText(/2025|0\.1\.0/)).toBeNull();
  expect(screen.getByRole("link", { name: t("plugins.status.disabled") })).toBeTruthy();
});

it("keeps an unassigned file-server module enabled and opens its setup without mutating state", async () => {
  const fileServers: PluginState = { ...item, plugin_id: "sli.file-audit", source_names: [], source_count: 0,
    status: { ...item.status!, state: "no_sources", reason: "no_sources", next_action: "connect_file_server" } };
  const gpo = { ...item, plugin_id: "sli.gpo", source_names: ["DC01", "DC02", "DC03", "DC04"], source_count: 4 };
  mocks.list.mockResolvedValue({ items: [gpo, item, fileServers], can_manage: true });
  mount();
  const fileRow = await screen.findByRole("row", { name: /Файловые серверы/ });
  expect(within(fileRow).getByRole("link", { name: /Включён.*Установите агент SLI на файловый сервер/ })).toBeTruthy();
  expect(within(fileRow).getAllByText("—")).toHaveLength(2);
  expect(within(fileRow).getByRole("link", { name: "Открыть" }).getAttribute("href")).toBe("/app/admin/plugins/sli.file-audit");
  expect(within(fileRow).getByRole("button", { name: "Выключить" })).toBeTruthy();
  expect(screen.getByText("DC01, DC02 и ещё 2")).toBeTruthy();
  expect(mocks.change).not.toHaveBeenCalled();
});

it.each([
  ["sli.file-audit", "working", null, 1, "Включён · 1 сервер подключён"],
  ["sli.file-audit", "error", null, 1, "Включён · FS01 подключён, агент устарел · Агент 26.0.136 не может проверить файловый аудит. Обновите его до версии 26.0.154 или новее."],
  ["sli.workstations", "no_sources", "install_workstation_agent", 0, "Включён · Нет подключённых источников · Установите агент SLI на рабочую станцию"],
  ["sli.remote-access", "disabled", null, 0, "Выключен"],
  ["sli.sigma", "no_sources", "connect_sigma_events", 0, "Включён · Нет подключённых источников · Подключите контроллер домена для сбора событий Windows"],
  ["sli.sigma", "error", "check_collection", 0, "Включён"],
] as const)("shows the server state for %s on the administration screens", async (pluginId, state, action, sourceCount, expected) => {
  const status: PluginState["status"] = { ...item.status!, state, next_action: action };
  if (pluginId === "sli.file-audit" && state === "error") {
    status.reason = "outdated_agent";
    status.error_object = "FS01";
    status.check_agent_requirement = { agent_version: "26.0.136", minimum_version: "26.0.154" };
  }
  if (pluginId === "sli.file-audit") {
    mocks.reportData.mockResolvedValue({ coverage: { audit_resources: {
      servers: 1, audited: state === "working" ? 2 : 0, shares: 3,
    } } });
  }
  if (pluginId === "sli.sigma" && state === "error") {
    status.reason = "collection_delayed";
    status.error_at = "2026-11-27T16:46:00Z";
  }
  mocks.list.mockResolvedValue({ can_manage: false, items: [{ ...item, plugin_id: pluginId, enabled: state !== "disabled",
    source_count: sourceCount, source_names: sourceCount ? ["FS01"] : [], status,
  }] });
  const list = mount();
  const href = (await screen.findByRole("link", { name: expected })).getAttribute("href")!;
  list.unmount();

  const page = mount(<PluginPage pluginId={pluginId} title={pluginId}/>);
  if (pluginId === "sli.file-audit") {
    const summary = t("file-audit.resources.summary", {
      status: t("plugins.enabled"), servers: 1, audited: state === "working" ? 2 : 0, shares: 3,
    });
    expect(await screen.findByText(summary, { exact: false, selector: "header p" })).toBeTruthy();
    expect(screen.getByRole("link", { name: t("file-audit.screen.overview") }).getAttribute("href"))
      .toBe("/app/report/file-audit.overview?tab=overview");
  } else {
    expect(await screen.findByText(expected, { selector: "header p" })).toBeTruthy();
  }
  page.unmount();

  const root = createRootRoute();
  const router = createRouter({ routeTree: root.addChildren(createAdminPlaceholderRoutes(root)),
    history: createMemoryHistory({ initialEntries: [href] }), basepath: "/app" });
  mount(<RouterProvider router={router}/>);
  const table = await screen.findByRole("table", { name: t("plugins.title") });
  expect(within(table).getByRole("cell", { name: expected })).toBeTruthy();
});

it("keeps file-server setup and disable hidden for delegated readers", async () => {
  mocks.list.mockResolvedValue({ items: [{ ...item, plugin_id: "sli.file-audit", source_names: [], source_count: 0 }], can_manage: false });
  mount();
  const row = await screen.findByRole("row", { name: /Файловые серверы/ });
  expect(within(row).getByRole("link", { name: "Открыть" }).getAttribute("href")).toBe("/app/admin/plugins/sli.file-audit");
  expect(within(row).queryByRole("link", { name: "Включить" })).toBeNull();
  expect(within(row).queryByRole("button", { name: "Выключить" })).toBeNull();
});

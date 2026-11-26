// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiResponseError, type PluginState } from "../../api/client";

const mocks = vi.hoisted(() => ({ list: vi.fn(), change: vi.fn() }));
vi.mock("../../api/client", async (importOriginal) => {
  const original = await importOriginal<typeof import("../../api/client")>();
  return { ...original, api: { ...original.api, plugins: () => mocks.list(), setPluginEnabled: (item: PluginState, enabled: boolean) => mocks.change(item, enabled) } };
});
import { localeRuntime, setLocale, t } from "../../i18n";
import { PluginsPage } from "./plugins";

const item: PluginState = { plugin_id: "sli.remote-access", package_version: "0.1.0", installed: true,
  configured: true, enabled: true, receiving_data: false, component_runtime: "running", queue_state: "drained", revision: 4, last_data_at_utc: null,
  status: { state: "waiting", last_data_at: null, error_at: null, error_object: null } };
const disabledStatus = { ...item.status!, state: "disabled" as const };

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><PluginsPage/></QueryClientProvider>);
}
beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => {
  cleanup();
  setLocale("ru");
  vi.resetAllMocks();
  vi.restoreAllMocks();
});

it("does not present the worker process as evidence that the plugin is working", async () => {
  mocks.list.mockResolvedValue({ items: [item], can_manage: false });
  mount();
  await screen.findByText("Версия");
  expect(screen.getByText("0.1.0")).toBeTruthy();
  expect(screen.getByText(t("plugins.status.waiting"))).toBeTruthy();
  expect(screen.queryByText(/^Работает/)).toBeNull();
  expect(screen.getByRole("link", { name: "Открыть диагностику" }).getAttribute("href")).toBe("/app/operations#runtime-workers");
  expect(screen.queryByText("Ошибка сбора")).toBeNull();
});

it("disables through the current revision and reads the new status from the server", async () => {
  const drained = { ...item, enabled: false, component_runtime: "draining", status: disabledStatus };
  mocks.list.mockResolvedValueOnce({ items: [item], can_manage: true }).mockResolvedValue({ items: [drained], can_manage: true });
  mocks.change.mockResolvedValue({ item: drained });
  mount();
  fireEvent.click(await screen.findByRole("button", { name: "Выключить" }));
  await waitFor(() => expect(mocks.change).toHaveBeenCalledWith(item, false));
  expect((await screen.findByRole("button", { name: "Включить" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(t("plugins.status.disabled"))).toBeTruthy();
  expect(screen.queryByText(t("plugins.status.waiting"))).toBeNull();
});

it("keeps delegated readers from mutating", async () => {
  mocks.list.mockResolvedValue({ items: [item], can_manage: false });
  mount();
  await screen.findByText(t("plugins.status.waiting"));
  expect(screen.queryByRole("button", { name: "Выключить" })).toBeNull();
  expect(screen.getByRole("note").textContent).toContain("только владелец");
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
  fireEvent.click(await screen.findByRole("button", { name: "Выключить" }));
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
  expect((await screen.findByRole("heading", { level: 2 })).textContent).toContain("Рабочие станции");
  fireEvent.click(screen.getByRole("button", { name: "Включить" }));
  const disable = await screen.findByRole("button", { name: "Выключить" });
  expect(mocks.change).toHaveBeenNthCalledWith(1, stopped, true);
  await waitFor(() => expect((disable as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(disable);
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
  fireEvent.click(await screen.findByRole("button", { name: "Выключить" }));
  expect((await screen.findByRole("alert")).textContent).toContain(message);
  expect(screen.getByRole("alert").textContent).not.toContain("private-marker");
  expect(screen.queryByText("Плагин выключен")).toBeNull();
});

it("keeps unknown server details out of the fallback error", async () => {
  mocks.list.mockResolvedValue({ items: [item], can_manage: true });
  mocks.change.mockRejectedValue(new ApiResponseError(500, "unknown_reason", "private-marker"));
  mount();
  fireEvent.click(await screen.findByRole("button", { name: "Выключить" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Состояние не изменено");
  expect(screen.getByRole("alert").textContent).not.toContain("private-marker");
});



it.each(["ru", "en"] as const)("keeps prior receipt timestamps readable for a disabled plugin in %s", async (locale) => {
  setLocale(locale);
  mocks.list.mockResolvedValue({ items: [{ ...item, enabled: false, status: disabledStatus, receiving_data: true,
    data_receipts: { state: "observed", last_received_at: "2026-01-01T00:00:00Z", last_imported_at: null, last_snapshot_completed_at: null },
  }], can_manage: false });
  mount();
  await screen.findByText(t("plugins.lastReceipt"));
  expect(screen.getByText(t("plugins.status.disabled"))).toBeTruthy();
  expect(screen.getByText(/2026/)).toBeTruthy();
  expect(mocks.change).not.toHaveBeenCalled();
});

it.each(["ru", "en"] as const)("describes the plugins returned by the server in %s", async (locale) => {
  setLocale(locale);
  const ids = ["sli.ad", "sli.gpo", "sli.file-audit", "sli.workstations", "sli.remote-access", "sli.sigma", "sli.future"];
  mocks.list.mockResolvedValue({ items: ids.map((plugin_id) => ({ ...item, plugin_id })), can_manage: false });
  mount();
  await screen.findByText(t("plugins.description.ad"));
  for (const key of ["gpo", "fileAudit", "workstations", "remoteAccess", "sigma", "unknown"]) {
    expect(screen.getByText(t(`plugins.description.${key}` as Parameters<typeof t>[0]))).toBeTruthy();
  }
  expect(screen.getByRole("heading", { name: /sli.future/ })).toBeTruthy();
  if (locale === "en") expect(document.body.textContent).not.toMatch(/[А-Яа-яЁё]/);
  expect(screen.queryByRole("button")).toBeNull();
});

it.each(["ru", "en"] as const)("shows independent receipt, import and completed snapshot facts in %s", async (locale) => {
  setLocale(locale);
  mocks.list.mockResolvedValue({ items: [{ ...item, plugin_id: "sli.ad", enabled: false,
    data_receipts: { state: "observed", last_received_at: "2026-01-01T00:00:00Z", last_imported_at: null,
      last_snapshot_completed_at: "2026-01-02T00:00:00Z" } }], can_manage: false });
  mount();
  await screen.findByText(t("plugins.lastSnapshotCompleted"));
  expect(screen.queryByText(t("plugins.lastImport"))).toBeNull();
  expect(screen.queryByText("Ошибка сбора")).toBeNull();
  expect(mocks.change).not.toHaveBeenCalled();
});

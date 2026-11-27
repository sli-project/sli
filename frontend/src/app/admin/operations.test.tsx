// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ bootstrap: vi.fn(), storage: vi.fn(), growth: vi.fn(), settings: vi.fn(), update: vi.fn(), health: vi.fn(), role: "admin", manage: true }));
vi.mock("../App", () => ({ useTimeZone: () => ({ timeZone: "UTC" }), useEffectiveAccess: () => ({ capabilities: state.manage ? ["access.manage"] : [] }) }));
vi.mock("../../api/client", async (original) => {
  const actual = await original<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, operations: async () => ({ collection: {}, collector_health: {}, postgres: {}, storage: {} }), systemHealth: () => state.health(), bootstrap: () => state.bootstrap(), storageOverview: () => state.storage(),
    storageGrowth: () => state.growth(), platformSettings: () => state.settings(), updatePlatformSetting: (key: string, value: string) => state.update(key, value) } };
});
import { OperationsPage } from "./operations";
import { localeRuntime, setLocale, t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
const history = { key: "ad.snapshot_history_days", value: "365", source: "default", environment: "SLI_AD_SNAPSHOT_HISTORY_DAYS" };
const overview = () => ({ storage: {
  disk_pressure: { disk: { used_human: "20 GB", free_human: "80 GB" } },
  footprint: { components: [{ key: "postgres_database", human: "12.5 GB" }, { key: "clickhouse_volume_history", human: "11 GB" }],
    backups: { last_backup_at_utc: "2026-11-13T10:00:00Z" } },
} });
function mount() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><OperationsPage/></QueryClientProvider>);
}
beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  state.role = "admin"; state.manage = true;
  state.bootstrap.mockImplementation(async () => ({ effective_role: state.role }));
  state.storage.mockResolvedValue(overview());
  state.growth.mockResolvedValue({});
  state.health.mockResolvedValue({});
  state.settings.mockResolvedValue({ items: [history, { ...history, key: "workstations.evidence_retention_days", value: "90" }] });
  state.update.mockResolvedValue({ item: { ...history, value: "730" } });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.resetAllMocks(); });
it.each(["ru", "en"] as const)("keeps empty storage facts out of the error state in %s", async (locale) => {
  setLocale(locale);
  state.storage.mockResolvedValue({ storage: {} });
  state.settings.mockResolvedValue({ items: [] });
  const { container } = mount();
  await waitFor(() => expect(state.storage).toHaveBeenCalled());
  await waitFor(() => expect(container.querySelector('[data-state="loading"]')).toBeNull());
  expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(t("operations.page.title"));
  expect(screen.queryByRole("alert")).toBeNull();
  expect(container.querySelector('[data-state="error"], [data-state="unavailable"]')).toBeNull();
});

it.each(["ru", "en"] as const)("renders available facts without collection diagnostics in %s", async (locale) => {
  setLocale(locale); mount();
  const disk = await screen.findByRole("table", { name: locale === "ru" ? "Диск" : "Disk" });
  const database = within(disk).getByRole("row", { name: /База данных PostgreSQL|PostgreSQL database/ });
  expect(within(database).getByText(locale === "ru" ? "12,5 ГБ" : "12.5 GB")).toBeTruthy();
  expect(within(disk).getByText(locale === "ru" ? "80 ГБ" : "80 GB")).toBeTruthy();
  expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(locale === "ru" ? "Хранение" : "Storage");
  expect(screen.getByRole("table", { name: locale === "ru" ? "Резервная копия" : "Backup" }).textContent).toContain("13");
  expect(screen.queryByText(/Автообновление|не подтвержд|Это не оценка|Диагностика|Долгих запросов/)).toBeNull();
  expect(document.querySelector("details, .sli-ds-state--banner")).toBeNull();
  expect(screen.queryByRole("columnheader", { name: /Прирост|Хватит|Размер|Где лежит|Следующая|Growth|Days left|Size|Location|Next/ })).toBeNull();
  expect(screen.queryByText(/SLI_AD_SNAPSHOT_HISTORY_DAYS/)).toBeNull();
});
it("renders disk within one second without waiting for settings", async () => {
  state.settings.mockReturnValue(new Promise(() => undefined)); state.growth.mockReturnValue(new Promise(() => undefined)); const start = performance.now(); mount();
  await screen.findByRole("table", { name: "Диск" }, { timeout: 1000 }); expect(performance.now() - start).toBeLessThan(1000);
});
it.each(["ru", "en"] as const)("adds measured growth and runway without estimating missing ClickHouse growth in %s", async (locale) => {
  setLocale(locale);
  state.growth.mockResolvedValue({ measured_growth: { components: {
    database_bytes: { bytes_per_day: -1024, per_day_human: "1 КБ" },
    disk_used_bytes: { bytes_per_day: 0, per_day_human: "0 Б" },
  } }, forecast: { estimated_days: 60 } });
  mount(); const disk = await screen.findByRole("table", { name: t("operations.disk.title") });
  await within(disk).findByRole("columnheader", { name: t("operations.disk.growth") });
  expect(within(disk).getByText(locale === "en" ? "−1 KB" : "−1 КБ")).toBeTruthy();
  expect(within(disk).getByText(locale === "en" ? "0 B" : "0 Б")).toBeTruthy();
  expect(within(disk).getByText("60")).toBeTruthy();
  expect(within(disk).queryByText(/ClickHouse/)).toBeNull();
});
it("omits tables without API values and retains a measured zero", async () => {
  state.storage.mockResolvedValue({ storage: { footprint: { components: [], backups: { last_backup_at_utc: null } } } });
  state.settings.mockResolvedValue({ items: [] }); mount();
  await waitFor(() => expect(state.storage).toHaveBeenCalled());
  await waitFor(() => expect(document.querySelector('[aria-busy="true"]')).toBeNull());
  expect(screen.queryByRole("table")).toBeNull(); cleanup();
  state.storage.mockResolvedValue({ storage: { footprint: { components: [{ key: "postgres_database", human: "0 B" }] } } }); mount();
  const disk = await screen.findByRole("table", { name: "Диск" }); expect(within(disk).getByText("0 Б")).toBeTruthy();
  expect(within(disk).queryByRole("columnheader", { name: "Свободно" })).toBeNull();
});
it.each([
  { bytes: 1048576, text: "1 МБ" },
  { bytes: 0, text: "0 Б" },
  { bytes: null, text: "—" },
])("keeps the logical database measurement separate from partition capacity ($text)", async ({ bytes, text }) => {
  state.storage.mockResolvedValue({ storage: {
    footprint: { components: bytes === null ? [] : [{
      key: "postgres_database", bytes, human: text, observed_at_utc: "2026-11-20T02:00:00Z",
    }] },
    disk_pressure: { disk: { used_bytes: 20 * 1024 ** 3, free_bytes: 80 * 1024 ** 3, used_human: "20 GB", free_human: "80 GB" } },
  } });
  mount();
  const disk = await screen.findByRole("table", { name: t("operations.disk.title") });
  const database = within(disk).getByRole("row", { name: /База данных/ });
  const partition = within(disk).getByRole("row", { name: /Раздел диска/ });
  expect(within(database).getAllByRole("cell").map((cell) => cell.textContent)).toEqual(["База данных PostgreSQL", text, "—"]);
  expect(within(partition).getAllByRole("cell").map((cell) => cell.textContent)).toEqual(["Раздел диска", "20 ГБ", "80 ГБ"]);
});
it("shows the measured PostgreSQL filesystem free space on the database row", async () => {
  state.storage.mockResolvedValue({ storage: {
    ...overview().storage,
    postgres_volume: { mount_point: "/srv/sli-db", used_bytes: 23 * 1024 ** 3, free_bytes: 0 },
  } });
  mount();
  const table = await screen.findByRole("table", { name: t("operations.disk.title") });
  const database = within(table).getByRole("row", { name: /База данных/ });
  expect(within(database).getAllByRole("cell").map((cell) => cell.textContent)).toEqual(["База данных PostgreSQL", "12,5 ГБ", "0 Б"]);
});
it("saves retention once and reports the time", async () => {
  mount(); const input = await screen.findByRole("spinbutton", { name: "История изменений AD/GPO" });
  const save = screen.getByRole("button", { name: "Сохранить" }) as HTMLButtonElement; expect(save.disabled).toBe(true);
  expect(save.closest(".sli-ds-header__actions")).not.toBeNull();
  fireEvent.change(input, { target: { value: "730" } }); expect(save.disabled).toBe(false); fireEvent.click(save);
  await waitFor(() => expect(state.update).toHaveBeenCalledWith("ad.snapshot_history_days", "730"));
  expect((await screen.findByRole("status")).textContent).toMatch(/Сохранено в \d{2}:\d{2}/); expect(save.disabled).toBe(true); expect((input as HTMLInputElement).value).toBe("730");
});
it.each(["6", "3651", "7.5", ""])("rejects invalid retention %s", async (value) => {
  mount(); fireEvent.change(await screen.findByRole("spinbutton", { name: "История изменений AD/GPO" }), { target: { value } });
  expect((screen.getByRole("button", { name: "Сохранить" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByRole("alert").textContent).toBe(t("platformSettings.ad_history.validation")); expect(state.update).not.toHaveBeenCalled();
});
it("shows a save error at the field and allows retry", async () => {
  state.update.mockRejectedValueOnce(new Error("unavailable")); mount();
  fireEvent.change(await screen.findByRole("spinbutton"), { target: { value: "730" } }); fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Не удалось сохранить срок хранения."); expect(screen.queryByText(/Сохранено в/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" })); await screen.findByText(/Сохранено в/);
});
it("keeps disk available when settings fail", async () => {
  state.settings.mockRejectedValue(new Error("unavailable")); mount(); await screen.findByRole("table", { name: "Диск" });
  expect(await screen.findByText("Не удалось загрузить сроки хранения.")).toBeTruthy();
});
it("does not request settings without access.manage", async () => {
  state.manage = false; state.role = "operator"; mount(); await screen.findByRole("table", { name: "Диск" }); expect(state.settings).not.toHaveBeenCalled();
});
it("keeps viewers from requesting storage", async () => {
  state.role = "viewer"; mount(); await screen.findByText(t("operations.auth.denied")); expect(state.storage).not.toHaveBeenCalled();
});


it("retries a disk failure while retaining editable settings", async () => {
  state.storage.mockRejectedValueOnce(new Error("unavailable")); mount();
  expect(await screen.findByText(t("operations.page.unavailable"))).toBeTruthy();
  expect(screen.getByRole("spinbutton")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  await screen.findByRole("table", { name: "Диск" });
});
it("shows retention read-only for operators even with settings read access", async () => {
  state.role = "operator"; mount();
  await screen.findByRole("table", { name: "Сроки хранения" });
  expect(screen.queryByRole("spinbutton")).toBeNull();
  expect(screen.queryByRole("button", { name: "Сохранить" })).toBeNull();
});

it("shows the cleanup command only for retained ClickHouse data", async () => {
  state.storage.mockResolvedValue({ storage: { ...overview().storage, retired_clickhouse_data: true } });
  mount();
  expect(await screen.findByText("sudo rm -rf -- /srv/sli-db/clickhouse")).toBeTruthy();
  cleanup(); state.storage.mockResolvedValue(overview()); mount();
  await screen.findByRole("table", { name: "Диск" });
  expect(screen.queryByText("sudo rm -rf -- /srv/sli-db/clickhouse")).toBeNull();
});

it.each(["ru", "en"] as const)("shows one catch-up line with its cursor and removes it on completion in %s", async (locale) => {
  setLocale(locale);
  state.health.mockResolvedValue({ password_catchup: { from: "2026-11-15T06:30:00Z", to: "2026-11-18T06:30:00Z", cursor: "2026-11-16T06:30:00Z", heartbeat: "2026-11-18T06:40:00Z" } });
  state.settings.mockResolvedValue({ items: [] });
  mount();
  const line = await screen.findByText(/Обнаружение паролей дообрабатывает события с|Password detection is processing events from/);
  expect(line.textContent).toContain(locale === "ru" ? "Обнаружение паролей дообрабатывает события с" : "Password detection is processing events from");
  expect(line.textContent).toContain(formatDateTime("2026-11-16T06:30:00Z", "UTC"));
  expect(line.querySelector("[data-state], details")).toBeNull();
  cleanup(); state.health.mockResolvedValue({ password_catchup: null }); mount();
  await waitFor(() => expect(state.health).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.queryByText(t("state.loading"))).toBeNull());
  expect(screen.queryByRole("status")).toBeNull();
});

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ bootstrap: vi.fn(), storage: vi.fn(), settings: vi.fn(), update: vi.fn(), role: "admin", manage: true }));
vi.mock("../App", () => ({ useTimeZone: () => ({ timeZone: "UTC" }), useEffectiveAccess: () => ({ capabilities: state.manage ? ["access.manage"] : [] }) }));
vi.mock("../../api/client", async (original) => {
  const actual = await original<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, bootstrap: () => state.bootstrap(), storageOverview: () => state.storage(),
    platformSettings: () => state.settings(), updatePlatformSetting: (key: string, value: string) => state.update(key, value) } };
});
import { OperationsPage } from "./operations";
import { localeRuntime, setLocale, t } from "../../i18n";
const history = { key: "ad.snapshot_history_days", value: "365", source: "default", environment: "SLI_AD_SNAPSHOT_HISTORY_DAYS" };
const overview = () => ({ storage: {
  postgres_volume: { mount_point: "/fixture-history", used_bytes: 23 * 2 ** 30, free_bytes: 80 * 2 ** 30 },
  postgres_volume_forecast_days: 28,
  footprint: { backups: { last_backup_at_utc: "2026-11-13T10:00:00Z" } },
} });
function mount() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><OperationsPage/></QueryClientProvider>);
}
beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  state.role = "admin"; state.manage = true;
  state.bootstrap.mockImplementation(async () => ({ effective_role: state.role }));
  state.storage.mockResolvedValue(overview());
  state.settings.mockResolvedValue({ items: [history, { ...history, key: "workstations.evidence_retention_days", value: "90" }] });
  state.update.mockResolvedValue({ item: { ...history, value: "730" } });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.resetAllMocks(); });
it.each(["ru", "en"] as const)("shows disk use and the measured forecast in %s", async (locale) => {
  setLocale(locale);
  mount();
  const disk = await screen.findByRole("table", { name: t("operations.disk.title") });
  expect(within(disk).getAllByRole("row")).toHaveLength(2);
  expect(within(disk).getByText(locale === "ru" ? "23 ГБ" : "23 GB")).toBeTruthy();
  expect(within(disk).getByText(locale === "ru" ? "80 ГБ" : "80 GB")).toBeTruthy();
  expect(screen.getByText(t("operations.disk.forecast", { days: locale === "ru" ? "28 дней" : "28 days" }))).toBeTruthy();
  expect(disk.textContent).not.toMatch(/PostgreSQL|fixture-history/);
  expect(screen.getByRole("table", { name: t("operations.backup.title") }).textContent).toContain("13");
});

it("keeps a measured zero without substituting an application disk or making up a forecast", async () => {
  state.storage.mockResolvedValue({ storage: {
    postgres_volume: { mount_point: "/fixture-history", used_bytes: 0, free_bytes: 2 ** 30 },
    disk_pressure: { disk: { used_bytes: 5 * 2 ** 30, free_bytes: 12 * 2 ** 30 } },
  } });
  mount();
  const disk = await screen.findByRole("table", { name: t("operations.disk.title") });
  expect(within(disk).getByText("0 Б")).toBeTruthy();
  expect(within(disk).getByText("1 ГБ")).toBeTruthy();
  expect(screen.queryByText(/Места хватит/)).toBeNull();
});

it("keeps disk usage visible while retention is loading", async () => {
  state.settings.mockReturnValue(new Promise(() => undefined));
  mount();
  await screen.findByRole("table", { name: "Диск" });
  expect(screen.queryByRole("spinbutton")).toBeNull();
});

it("validates retention and shows the new period only after the server confirms", async () => {
  mount();
  await screen.findByText("История хранится 365 дней");
  fireEvent.click(screen.getByRole("button", { name: t("operations.history.edit") }));
  const days = screen.getByRole("spinbutton", { name: t("operations.history.days") });
  const save = screen.getByRole("button", { name: t("operations.settings.save") }) as HTMLButtonElement;
  expect(save.disabled).toBe(true);
  fireEvent.change(days, { target: { value: "6" } });
  expect(save.disabled).toBe(true);
  expect(screen.getByRole("alert").textContent).toBe(t("operations.history.range"));
  expect(state.update).not.toHaveBeenCalled();
  fireEvent.change(days, { target: { value: "730" } });
  state.update.mockRejectedValueOnce(new Error("fixture_error"));
  fireEvent.click(save);
  await screen.findByText(t("operations.history.saveError"));
  expect(screen.getByText("История хранится 365 дней")).toBeTruthy();
  expect(screen.queryByText("История хранится 730 дней")).toBeNull();
  fireEvent.click(save);
  await screen.findByText("История хранится 730 дней");
  expect(state.update).toHaveBeenLastCalledWith(history.key, "730");
  expect(screen.queryByRole("spinbutton")).toBeNull();
});

it("keeps an operator with settings access from editing retention", async () => {
  state.role = "operator";
  mount();
  await screen.findByText("История хранится 365 дней");
  expect(screen.queryByRole("button", { name: t("operations.history.edit") })).toBeNull();
});

it("requests confirmation before shortening history retention", async () => {
  state.update.mockResolvedValue({ item: { ...history, value: "30" } });
  mount();
  fireEvent.click(await screen.findByRole("button", { name: t("operations.history.edit") }));
  fireEvent.change(screen.getByRole("spinbutton"), { target: { value: "30" } });
  const save = screen.getByRole("button", { name: t("operations.settings.save") });
  fireEvent.click(save);
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText(t("operations.history.shortenImpact"))).toBeTruthy();
  expect(state.update).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole("button", { name: t("platformSettings.cancel") }));
  fireEvent.click(save);
  fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: t("operations.history.shorten") }));
  await screen.findByText("История хранится 30 дней");
  expect(state.update).toHaveBeenCalledOnce();
  expect(state.update).toHaveBeenCalledWith(history.key, "30");
});

it("keeps viewers from requesting storage", async () => {
  state.role = "viewer";
  mount();
  await screen.findByText(t("operations.auth.denied"));
  expect(state.storage).not.toHaveBeenCalled();
});

it("retries a disk failure", async () => {
  state.storage.mockRejectedValueOnce(new Error("unavailable"));
  mount();
  await screen.findByText(t("operations.page.unavailable"));
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  await screen.findByRole("table", { name: "Диск" });
});

it("shows the cleanup command only for retained ClickHouse data", async () => {
  state.storage.mockResolvedValue({ storage: { ...overview().storage, retired_clickhouse_data: true } });
  mount();
  await screen.findByText("sudo rm -rf -- /srv/sli-db/clickhouse");
  cleanup();
  state.storage.mockResolvedValue(overview());
  mount();
  await screen.findByRole("table", { name: "Диск" });
  expect(screen.queryByText("sudo rm -rf -- /srv/sli-db/clickhouse")).toBeNull();
});

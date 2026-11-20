// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { PlatformSetting } from "../../api/client";

const state = vi.hoisted(() => ({ list: vi.fn(), update: vi.fn(), domains: vi.fn(), controls: vi.fn(), accounts: vi.fn(), owner: true, registry: false, watch: false }));
vi.mock("../App", () => ({ useEffectiveAccess: () => ({ platform_owner: state.owner,
  reports: [...(state.registry ? [{ report_key: "decoys.registry", allowed: true }] : []),
    ...(state.watch ? [{ report_key: "watch.registry", allowed: true }] : [])] }) }));
vi.mock("./decoys", () => ({ DecoyRegistry: () => <div data-testid="decoy-registry"/> }));
vi.mock("../account-watch", () => ({ AccountWatch: () => <div data-testid="watch-registry"/> }));
vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api,
    platformSettings: () => state.list(),
    updatePlatformSetting: (key: string, value: string) => state.update(key, value),
    setupDomains: () => state.domains(), reportV2Data: (_key: string, params: URLSearchParams) => state.accounts(params), semanticControls: () => state.controls(),
  } };
});
import { PlatformSettingsPage } from "./platform-settings";
import { localeRuntime, setLocale, t } from "../../i18n";

const sid = "S-1-5-21-100000001-200000002-300000003-1001";
const sid2 = "S-1-5-21-100000001-200000002-300000003-1002";
const setting = (key: string, value: string): PlatformSetting => ({ key, value, label: key, description: "", source: "database",
  environment: "SLI_TEST_SETTING", updated_by: "fixture-admin", updated_at: "2026-11-13T00:00:00Z" });
const calendar = { timezone: "UTC", weekdays: [0, 1, 2, 3, 4], start: "09:00", end: "18:00", excluded_dates: ["2026-12-25"],
  exceptions: [{ subject_sid: sid, start_utc: "2026-11-14T00:00:00Z", end_utc: "2026-11-14T01:00:00Z", reason: "fixture" }] };
const items = [
  setting("reports.domain_fqdn", "example.test"), setting("ad.password_max_age_days", "365"), setting("ad.inactivity_days", "90"),
  setting("ad.service_account_exceptions", JSON.stringify([{ sid, excluded_by: "fixture-admin" }])),
  setting("windows_auth.distributed_window_hours", "24"), setting("windows_auth.distributed_min_accounts", "10"),
  setting("windows_auth.distributed_min_sources", "5"), setting("windows_auth.distributed_max_failures_per_account", "3"),
  setting("security.working_time", JSON.stringify(calendar)), setting("ad.snapshot_history_days", "365"),
  setting("workstations.evidence_retention_days", "90"), setting("workstations.logon_policy", ""),
];
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><PlatformSettingsPage/></QueryClientProvider>);
}
const saveButton = () => screen.getByRole("button", { name: t("platformSettings.save") }) as HTMLButtonElement;
const input = (key: Parameters<typeof t>[0]) => screen.getByLabelText(t(key)) as HTMLInputElement;
const change = (key: Parameters<typeof t>[0], value: string) => fireEvent.change(input(key), { target: { value } });
beforeEach(() => {
  vi.resetAllMocks(); state.owner = true; state.watch = false; state.registry = false;
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  state.list.mockResolvedValue({ items });
  state.accounts.mockResolvedValue({ items: [{ sid, sam: "fixture-service" }, { sid: sid2, sam: "fixture-backup" }] });
  state.domains.mockResolvedValue({ items: [{ fqdn: "example.test" }, { fqdn: "second.example.test" }, { fqdn: "old.example.test", is_archived: true }] });
  state.update.mockImplementation(async (key: string, value: string) => ({ item: setting(key, value) }));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("renders one form and saves only the two changed fields (%s)", async (locale) => {
  setLocale(locale);
  state.registry = true; state.watch = true;
  const { container } = mount();
  await screen.findByLabelText(t("platformSettings.ad.password.title"));
  expect(screen.getAllByRole("button", { name: t("platformSettings.save") })).toHaveLength(1);
  expect(saveButton().disabled).toBe(true);
  expect(container.textContent).not.toMatch(/SLI_|Технические сведения о версии|Technical version details|fixture-admin/);
  expect(container.textContent).not.toContain(locale === "ru" ? "Хранение доказательств процессов и USB" : "Process and USB evidence retention");
  expect(container.textContent).not.toContain(locale === "ru" ? "Время входа на рабочие станции" : "Workstation sign-in time");
  expect(screen.queryByText(t("semanticControls.title"))).toBeNull();
  expect(screen.queryByTestId("decoy-registry")).toBeNull();
  expect(screen.queryByTestId("watch-registry")).toBeNull();
  expect(state.controls).not.toHaveBeenCalled();
  if (locale === "en") expect(container.textContent).not.toMatch(/[А-Яа-яЁё]/);
  change("platformSettings.ad.password.title", "120"); change("platformSettings.ad.inactivity.title", "60");
  fireEvent.click(saveButton());
  await waitFor(() => expect(screen.getByRole("status").textContent).toMatch(locale === "ru" ? /^Сохранено в \d{2}:\d{2}$/ : /^Saved at \d{2}:\d{2}$/));
  expect(state.update.mock.calls).toEqual([["ad.password_max_age_days", "120"], ["ad.inactivity_days", "60"]]);
  expect(saveButton().disabled).toBe(true);
});

it("cancels all edits without saving", async () => {
  mount(); await screen.findByLabelText(t("platformSettings.ad.password.title"));
  change("platformSettings.ad.password.title", "120"); change("platformSettings.time.start", "08:00");
  fireEvent.click(screen.getByRole("button", { name: t("platformSettings.cancel") }));
  expect(input("platformSettings.ad.password.title").value).toBe("365");
  expect(input("platformSettings.time.start").value).toBe("09:00");
  expect(saveButton().disabled).toBe(true); expect(state.update).not.toHaveBeenCalled();
});

it("keeps successful writes and retries only the failed field", async () => {
  state.update.mockImplementation(async (key: string, value: string) => {
    if (key === "ad.inactivity_days") throw new Error("fixture_failure");
    return { item: setting(key, value) };
  });
  mount(); await screen.findByLabelText(t("platformSettings.ad.password.title"));
  change("platformSettings.ad.password.title", "120"); change("platformSettings.ad.inactivity.title", "60");
  fireEvent.click(saveButton());
  const error = await screen.findByRole("alert");
  expect(error.textContent).toContain(t("platformSettings.ad.inactivity.title"));
  expect(within(error.parentElement!).getByLabelText(t("platformSettings.ad.inactivity.title"))).toBeTruthy();
  expect(screen.queryByRole("status")).toBeNull();
  state.update.mockImplementation(async (key: string, value: string) => ({ item: setting(key, value) }));
  await waitFor(() => expect(saveButton().disabled).toBe(false));
  fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(state.update.mock.calls).toEqual([["ad.password_max_age_days", "120"], ["ad.inactivity_days", "60"], ["ad.inactivity_days", "60"]]);
});

it("keeps fields disabled during a save and uses the server-normalized value", async () => {
  let resolve!: (value: unknown) => void;
  state.update.mockReturnValue(new Promise((done) => { resolve = done; }));
  mount(); await screen.findByLabelText(t("platformSettings.ad.password.title"));
  change("platformSettings.ad.password.title", "00120"); fireEvent.click(saveButton());
  await waitFor(() => expect(state.update).toHaveBeenCalledOnce());
  expect(input("platformSettings.ad.password.title").closest("fieldset")!.disabled).toBe(true);
  resolve({ item: setting("ad.password_max_age_days", "120") });
  await screen.findByRole("status");
  expect(input("platformSettings.ad.password.title").value).toBe("120"); expect(saveButton().disabled).toBe(true);
});

it.each([
  ["ad.password_max_age_days", "platformSettings.ad.password.title", "0", "3651", "1", "3650"],
  ["ad.inactivity_days", "platformSettings.ad.inactivity.title", "0", "3651", "1", "3650"],
  ["windows_auth.distributed_window_hours", "platformSettings.spray.distributed_window_hours.title", "0", "745", "1", "744"],
  ["windows_auth.distributed_min_accounts", "platformSettings.spray.distributed_min_accounts.title", "0", "745", "1", "744"],
  ["windows_auth.distributed_min_sources", "platformSettings.spray.distributed_min_sources.title", "0", "745", "1", "744"],
  ["windows_auth.distributed_max_failures_per_account", "platformSettings.spray.distributed_max_failures_per_account.title", "0", "745", "1", "744"],
] as const)("enforces existing bounds for %s", async (key, label, low, high, min, max) => {
  mount(); await screen.findByLabelText(t(label));
  expect(input(label).min).toBe(min); expect(input(label).max).toBe(max);
  for (const invalid of [low, high, "1.5", ""]) {
    change(label, invalid); expect(saveButton().disabled).toBe(true); expect(screen.getByRole("alert")).toBeTruthy();
  }
  change(label, min); fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(state.update).toHaveBeenCalledWith(key, min);
});

it("selects service accounts by name without displaying identifiers and confirms removal", async () => {
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  const { container } = mount(); await screen.findByText("fixture-service");
  expect(container.textContent).not.toContain(sid);
  change("platformSettings.service_exceptions.title", "backup");
  const choice = await screen.findByLabelText(t("platformSettings.service_exceptions.choose"));
  fireEvent.change(choice, { target: { value: sid2 } });
  fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(state.update).toHaveBeenLastCalledWith("ad.service_account_exceptions", JSON.stringify([sid, sid2]));
  const remove = screen.getByRole("button", { name: t("platformSettings.service_exceptions.remove", { name: "fixture-service" }) });
  fireEvent.click(remove); expect(saveButton().disabled).toBe(true);
  expect(confirm).toHaveBeenCalledWith(t("platformSettings.service_exceptions.confirm", { name: "fixture-service" }));
  confirm.mockReturnValue(true); fireEvent.click(remove);
  fireEvent.click(screen.getByRole("button", { name: t("platformSettings.service_exceptions.remove", { name: "fixture-backup" }) }));
  fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(state.update).toHaveBeenLastCalledWith("ad.service_account_exceptions", "[]");
});

it("retains existing service exceptions if account names cannot be loaded", async () => {
  state.accounts.mockRejectedValue(new Error("fixture_failure"));
  mount(); await screen.findByText(t("platformSettings.service_exceptions.loadFailed"));
  change("platformSettings.ad.password.title", "120"); fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(state.update.mock.calls).toEqual([["ad.password_max_age_days", "120"]]);
});

it("edits calendar controls while preserving dates and account exceptions", async () => {
  mount(); await screen.findByLabelText(t("platformSettings.time.start"));
  change("platformSettings.time.start", "08:00"); change("platformSettings.time.zone", "Europe/Moscow");
  fireEvent.click(screen.getByLabelText(t("platformSettings.day.sat")));
  fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(JSON.parse(state.update.mock.calls[0][1])).toEqual({ ...calendar, start: "08:00", timezone: "Europe/Moscow", weekdays: [0, 1, 2, 3, 4, 5] });
});

it("rejects equal working hours and accepts an overnight interval", async () => {
  mount(); await screen.findByLabelText(t("platformSettings.time.start"));
  change("platformSettings.time.start", "18:00");
  expect(saveButton().disabled).toBe(true);
  expect(screen.getByRole("alert").textContent).toBe(t("platformSettings.working_time.validation"));
  change("platformSettings.time.start", "22:00"); change("platformSettings.time.end", "06:00");
  fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(JSON.parse(state.update.mock.calls[0][1])).toEqual({ ...calendar, start: "22:00", end: "06:00" });
});

it("does not invent working hours when no calendar is configured", async () => {
  state.list.mockResolvedValue({ items: [setting("security.working_time", "")] });
  mount(); await screen.findByLabelText(t("platformSettings.time.start"));
  expect(input("platformSettings.time.start").value).toBe("");
  expect(screen.getAllByRole("checkbox").every((element) => !(element as HTMLInputElement).checked)).toBe(true);
  change("platformSettings.time.start", "09:00"); expect(saveButton().disabled).toBe(true);
  change("platformSettings.time.end", "18:00"); change("platformSettings.time.zone", "UTC");
  fireEvent.click(screen.getByLabelText(t("platformSettings.day.mon")));
  fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(JSON.parse(state.update.mock.calls[0][1])).toEqual({ timezone: "UTC", weekdays: [0], start: "09:00", end: "18:00", excluded_dates: [], exceptions: [] });
});

it("selects registered active domains and does not silently change an archived preference", async () => {
  state.list.mockResolvedValue({ items: [{ ...setting("reports.domain_fqdn", "old.example.test"), effective_value: "example.test", effective_state: "available" }] });
  mount(); await screen.findByRole("option", { name: "example.test" });
  expect(input("platformSettings.report_domain.title").value).toBe("old.example.test");
  expect(saveButton().disabled).toBe(true); expect(state.update).not.toHaveBeenCalled();
  change("platformSettings.report_domain.title", "example.test"); fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(state.update).toHaveBeenCalledWith("reports.domain_fqdn", "example.test");
});

it("shows a domain load error at its field without blocking other settings", async () => {
  state.domains.mockRejectedValue(new Error("fixture_failure"));
  mount(); await screen.findByText(t("platformSettings.domainsFailed"));
  change("platformSettings.ad.password.title", "120"); fireEvent.click(saveButton()); await screen.findByRole("status");
  expect(state.update).toHaveBeenCalledWith("ad.password_max_age_days", "120");
});

it.each(["watch", "registry"] as const)("preserves scoped %s access without requesting installation settings", async (kind) => {
  state.owner = false; state[kind] = true;
  mount(); expect(screen.getByTestId(kind === "watch" ? "watch-registry" : "decoy-registry")).toBeTruthy();
  expect(state.list).not.toHaveBeenCalled();
});

it("does not offer the AD/GPO change history retention; it is edited on the storage page", async () => {
  mount(); await screen.findByLabelText(t("platformSettings.ad.password.title"));
  expect(screen.queryByLabelText(/AD\/GPO/)).toBeNull();
  expect(screen.queryByRole("heading", { name: /истории изменений/i })).toBeNull();
});

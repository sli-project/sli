// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiResponseError, type PlatformSetting } from "../../api/client";

const state = vi.hoisted(() => ({ list: vi.fn(), update: vi.fn(), domains: vi.fn(), controls: vi.fn(), accounts: vi.fn(),
  backup: vi.fn(), saveBackup: vi.fn(), accessLoaded: true, owner: true, canManage: false, registry: false, watch: false }));
vi.mock("../App", () => ({ useEffectiveAccess: () => state.accessLoaded ? ({ platform_owner: state.owner,
  capabilities: state.canManage ? ["access.manage"] : [],
  reports: [...(state.registry ? [{ report_key: "decoys.registry", allowed: true }] : []),
    ...(state.watch ? [{ report_key: "watch.registry", allowed: true }] : [])] }) : undefined }));
vi.mock("./decoys", () => ({ DecoyRegistry: () => <div data-testid="decoy-registry"/> }));
vi.mock("../account-watch", () => ({ AccountWatch: () => <div data-testid="watch-registry"/> }));
vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api,
    platformSettings: () => state.list(),
    updatePlatformSetting: (key: string, value: string) => state.update(key, value),
    backupSettings: () => state.backup(),
    updateBackupSettings: (body: unknown) => state.saveBackup(body),
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
  state.accessLoaded = true; state.canManage = false;
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  state.list.mockResolvedValue({ items });
  state.accounts.mockResolvedValue({ items: [{ sid, sam: "fixture-service" }, { sid: sid2, sam: "fixture-backup" }] });
  state.domains.mockResolvedValue({ items: [{ fqdn: "example.test" }, { fqdn: "second.example.test" }, { fqdn: "old.example.test", is_archived: true }] });
  state.update.mockImplementation(async (key: string, value: string) => ({ item: setting(key, value) }));
  state.backup.mockResolvedValue({ enabled: false, path: null, revision: "backup-1", storage_status: "unconfigured" });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it.each([false, true])("shows no regular backup controls without confirmed ownership (access loaded: %s)", async (loaded) => {
  state.accessLoaded = loaded; state.owner = false; state.canManage = true;
  mount();
  if (loaded) await screen.findByLabelText(t("platformSettings.ad.password.title"));
  expect(screen.queryByRole("heading", { name: "Резервное копирование" })).toBeNull();
  expect(state.backup).not.toHaveBeenCalled();
});

it("waits for the saved state and never infers disabled from an unavailable coordinator", async () => {
  state.backup.mockImplementation(() => new Promise(() => {}));
  const initial = mount();
  const section = () => within(screen.getByRole("region", { name: "Резервное копирование" }));
  expect(section().getByRole("status")).toBeTruthy();
  expect(section().queryByRole("checkbox")).toBeNull();
  initial.unmount();

  state.backup.mockResolvedValue({ enabled: false, path: null, revision: null, storage_status: "unavailable" });
  mount();
  expect((await section().findByRole("alert")).textContent).toContain("Не удалось загрузить настройки резервного копирования");
  expect(section().queryByRole("checkbox")).toBeNull();
  expect(state.saveBackup).not.toHaveBeenCalled();
  state.backup.mockResolvedValue({ enabled: true, path: "/mnt/backup/live", revision: "backup-2", storage_status: "ready" });
  fireEvent.click(section().getByRole("button", { name: t("state.retry") }));
  expect((await section().findByRole<HTMLInputElement>("checkbox")).checked).toBe(true);
});

it.each([
  ["ru", "Резервное копирование", "Регулярное резервное копирование", "Каталог на сервере", "Сохранить настройки резервного копирования", "Настройки резервного копирования сохранены."],
  ["en", "Backup", "Scheduled backups", "Directory on the server", "Save backup settings", "Backup settings saved."],
] as const)("saves a server directory with optimistic concurrency and shows the confirmed state (%s)", async (locale, title, toggle, directory, saveLabel, saved) => {
  setLocale(locale);
  const confirmed = { enabled: true, path: "/mnt/backups/confirmed", revision: "backup-2", storage_status: "ready" };
  let resolveSave!: (value: typeof confirmed) => void;
  state.saveBackup.mockImplementation(() => new Promise((resolve) => { resolveSave = resolve; }));
  const page = mount();
  const section = within(screen.getByRole("region", { name: title }));
  const enabled = await section.findByRole<HTMLInputElement>("checkbox", { name: toggle });
  const path = section.getByRole<HTMLInputElement>("textbox", { name: directory });
  const save = section.getByRole<HTMLButtonElement>("button", { name: saveLabel });
  expect(enabled.checked).toBe(false);
  expect(path.disabled).toBe(true);
  fireEvent.click(enabled);
  fireEvent.change(path, { target: { value: "C:\\backups" } });
  expect(save.disabled).toBe(true);
  fireEvent.change(path, { target: { value: "/mnt/backups/chosen" } });
  fireEvent.click(save);
  await waitFor(() => expect(state.saveBackup).toHaveBeenCalledWith({
    enabled: true, path: "/mnt/backups/chosen", revision: "backup-1",
  }));
  expect(enabled.disabled).toBe(true);
  expect(path.disabled).toBe(true);
  expect(state.update).not.toHaveBeenCalled();
  resolveSave(confirmed);
  expect((await section.findByRole("status")).textContent).toBe(saved);
  expect(path.value).toBe(confirmed.path);
  expect(save.disabled).toBe(true);
  state.backup.mockResolvedValue(confirmed);
  page.unmount();
  mount();
  const reopened = within(screen.getByRole("region", { name: title }));
  expect((await reopened.findByRole<HTMLInputElement>("checkbox", { name: toggle })).checked).toBe(true);
  expect(reopened.getByRole<HTMLInputElement>("textbox", { name: directory }).value).toBe(confirmed.path);
});

it("disables the schedule on an unavailable volume and keeps the last saved directory", async () => {
  const existing = { enabled: true, path: "/mnt/backup/previous", revision: "backup-3", storage_status: "unavailable" };
  state.backup.mockResolvedValue(existing);
  state.saveBackup.mockResolvedValue({ ...existing, enabled: false, revision: "backup-4" });
  mount();
  const section = within(screen.getByRole("region", { name: "Резервное копирование" }));
  const enabled = await section.findByRole<HTMLInputElement>("checkbox");
  const path = section.getByRole<HTMLInputElement>("textbox");
  expect(section.getByText("Хранилище недоступно.")).toBeTruthy();
  fireEvent.change(path, { target: { value: "/mnt/backup/draft" } });
  fireEvent.click(enabled);
  expect(path.value).toBe(existing.path);
  fireEvent.click(section.getByRole("button", { name: "Сохранить настройки резервного копирования" }));
  await waitFor(() => expect(state.saveBackup).toHaveBeenCalledWith({ enabled: false, path: existing.path, revision: "backup-3" }));
  expect(await section.findByText("Сохранённое расписание выключено.")).toBeTruthy();
});

it("shows a localized storage error at the field without exposing the raw server text", async () => {
  state.saveBackup.mockRejectedValue(new ApiResponseError(400, "native_backup_root_same_device", "private host diagnostic"));
  mount();
  const section = within(screen.getByRole("region", { name: "Резервное копирование" }));
  fireEvent.click(await section.findByRole("checkbox"));
  const path = section.getByRole<HTMLInputElement>("textbox");
  fireEvent.change(path, { target: { value: "/mnt/backups" } });
  expect(path.hasAttribute("aria-describedby")).toBe(false);
  fireEvent.click(section.getByRole("button", { name: "Сохранить настройки резервного копирования" }));
  const error = await section.findByRole("alert");
  expect(error.textContent).toBe("Выберите каталог на другом диске, отдельно от базы данных.");
  expect(path.getAttribute("aria-describedby")).toBe(error.id);
  expect(path.value).toBe("/mnt/backups");
  expect(section.queryByText("private host diagnostic")).toBeNull();
  expect(section.getByText("Сохранённое расписание выключено.")).toBeTruthy();
});

it("requires a new read after a revision conflict and does not resubmit stale settings", async () => {
  state.backup.mockResolvedValueOnce({ enabled: true, path: "/mnt/old", revision: "backup-1", storage_status: "ready" })
    .mockResolvedValueOnce({ enabled: true, path: "/mnt/current", revision: "backup-2", storage_status: "ready" });
  state.saveBackup.mockRejectedValueOnce(new ApiResponseError(409, "backup_settings_revision_conflict"));
  mount();
  const section = within(screen.getByRole("region", { name: "Резервное копирование" }));
  fireEvent.click(await section.findByRole("checkbox"));
  const save = section.getByRole<HTMLButtonElement>("button", { name: "Сохранить настройки резервного копирования" });
  fireEvent.click(save);
  expect((await section.findByRole("alert")).textContent).toContain("Настройки изменились.");
  expect(save.disabled).toBe(true);
  fireEvent.click(section.getByRole("button", { name: "Загрузить настройки заново" }));
  await waitFor(() => expect(section.getByRole<HTMLInputElement>("textbox").value).toBe("/mnt/current"));
  expect(state.backup).toHaveBeenCalledTimes(2);
  expect(state.saveBackup).toHaveBeenCalledTimes(1);
  expect(section.getByRole<HTMLInputElement>("checkbox").checked).toBe(true);
});

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

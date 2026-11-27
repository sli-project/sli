// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DataTable } from "../../design-system";
import { TimeZoneContext } from "../../shared/time-zone";
import { localeRuntime, setLocale, t } from "../../i18n";
import { roleLabel } from "../report-labels";

const state = vi.hoisted(() => ({ bootstrap: vi.fn(), logout: vi.fn(), settings: vi.fn(), saveSetting: vi.fn() }));
vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, bootstrap: () => state.bootstrap(), logout: () => state.logout(),
    platformSettings: () => state.settings(), updatePlatformSetting: (key: string, value: string) => state.saveSetting(key, value) } };
});
import { SettingsPage } from "./settings";

// Saving a preference does not need hundreds of rendered Intl options.
const supportedTimeZones = Intl.supportedValuesOf("timeZone");
beforeEach(() => {
  vi.spyOn(Intl, "supportedValuesOf").mockReturnValue(["Asia/Vladivostok", "Europe/Berlin"]);
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("CSS", { ...globalThis.CSS, escape: (value: string) =>
    Array.from(String(value), (character) => `\\${(character.codePointAt(0) || 0xfffd).toString(16)} `).join("") });
  state.bootstrap.mockResolvedValue({ principal: { username: "fixture-user", role: "operator" } });
});
afterEach(() => { cleanup(); setLocale("ru"); localStorage.clear(); sessionStorage.clear(); vi.restoreAllMocks(); vi.clearAllMocks(); vi.unstubAllGlobals(); });

function Profile({ withTable = false }: { withTable?: boolean }) {
  const [timeZone, setTimeZone] = useState("UTC");
  return <TimeZoneContext.Provider value={{ timeZone, setTimeZone }}>
    <SettingsPage/>
    {withTable ? <DataTable columns={[{ key: "stamp", label: "Time", kind: "datetime" }]}
      rows={[{ stamp: "2026-11-14T00:00:00Z" }]} rowKey={(row) => row.stamp} caption="Times"/> : null}
  </TimeZoneContext.Provider>;
}
function renderProfile(withTable = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><Profile withTable={withTable}/></QueryClientProvider>);
}

it.each(["ru", "en"] as const)("shows a compact profile and saves the language only on Save (%s)", async (locale) => {
  setLocale(locale);
  const { container } = renderProfile();
  await screen.findByText(`fixture-user · ${roleLabel("operator")}`);
  expect(screen.getByRole("heading", { level: 1, name: locale === "ru" ? "Язык и время" : "Language & time" })).toBeTruthy();
  expect(screen.getByRole("button", { name: t("operations.settings.logout") })).toBeTruthy();
  expect(container.textContent).not.toMatch(/не реализована|not implemented|Текущая сессия|Current session|Запомнить меня|Remember me/);
  expect(screen.queryByRole("link")).toBeNull();
  if (locale === "en") expect(container.textContent?.replace("Русский", "")).not.toMatch(/[А-Яа-яЁё]/);
  const save = screen.getByRole("button", { name: t("operations.settings.save") }) as HTMLButtonElement;
  expect(save.disabled).toBe(true);
  const next = locale === "ru" ? "en" : "ru";
  await chooseOption(screen.getByLabelText(t("shell.profile.language.title"), { selector: "button" }), next);
  expect(localStorage.getItem("sli.locale")).toBe(locale);
  expect(save.disabled).toBe(false);
  await userEvent.click(save);
  expect(localStorage.getItem("sli.locale")).toBe(next);
  expect(localeRuntime.reload).toHaveBeenCalled();
  expect(state.logout).not.toHaveBeenCalled();
  cleanup();
  renderProfile();
  await screen.findByText(`fixture-user · ${roleLabel("operator")}`);
  expect(screen.getByRole("status").textContent).toMatch(next === "ru" ? /^Сохранено в \d{2}\.\d{2}\.\d{4}, \d{2}:\d{2}$/ : /^Saved at [A-Z][a-z]{2} \d{1,2}, \d{4}, \d{1,2}:\d{2} [AP]M$/);
});

it("offers the browser first and searches the complete Intl list without applying free text", async () => {
  vi.mocked(Intl.supportedValuesOf).mockReturnValue(supportedTimeZones);
  renderProfile();
  const user = userEvent.setup();
  const input = screen.getByRole("combobox", { name: t("operations.settings.tz_title") });
  await user.click(screen.getByRole("button", { name: /^Часовой пояс/ }));
  const list = within(await screen.findByRole("listbox"));
  const labels = list.getAllByRole("option", { hidden: true }).map(option => option.textContent);
  expect(labels[0]).toBe("Как в браузере");
  const renderedZones = new Set(labels);
  expect(supportedTimeZones.filter(zone => !renderedZones.has(zone))).toEqual([]);
  fireEvent.change(input, { target: { value: "vLaDiVoStOk" } });
  expect(await screen.findByRole("option", { name: "Asia/Vladivostok" })).toBeTruthy();
  expect(screen.queryByRole("option", { name: "Europe/Berlin" })).toBeNull();
  fireEvent.change(input, { target: { value: "Invalid/Zone" } });
  await user.tab();
  expect((input as HTMLInputElement).value).toBe("UTC");
  expect((screen.getByRole("button", { name: t("operations.settings.save") }) as HTMLButtonElement).disabled).toBe(true);
});

it.each([
  ["Asia/Vladivostok", "14.11.2026, 10:00"],
  ["Europe/Berlin", "14.11.2026, 01:00"],
  ["browser", new Date("2026-11-14T00:00:00Z").toLocaleString("ru-RU", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })],
])("applies the selected time zone %s to displayed table times on Save", async (zone, expected) => {
  renderProfile(true);
  const user = userEvent.setup();
  const table = screen.getByRole("table");
  expect(within(table).getByText("14.11.2026, 00:00")).toBeTruthy();
  const input = screen.getByRole("combobox", { name: t("operations.settings.tz_title") });
  await user.click(input);
  fireEvent.change(input, { target: { value: zone === "browser" ? "Как в браузере" : zone } });
  if (zone === "browser") await user.keyboard("{ArrowDown}{Enter}");
  else await user.click(await screen.findByRole("option", { name: zone }));
  expect(within(table).getByText("14.11.2026, 00:00")).toBeTruthy();
  const save = screen.getByRole("button", { name: t("operations.settings.save") }) as HTMLButtonElement;
  expect(save.disabled).toBe(false);
  await user.click(save);
  expect(within(table).getByText(expected)).toBeTruthy();
  expect(screen.getByRole("status").textContent).toMatch(/^Сохранено в \d{2}\.\d{2}\.\d{4}, \d{2}:\d{2}$/);
  expect(save.disabled).toBe(true);
});

it("names a profile load failure and retries without exposing server error text", async () => {
  state.bootstrap.mockRejectedValueOnce(new Error("fixture_internal_failure"));
  renderProfile();
  expect((await screen.findByRole("alert")).textContent).toContain("Не удалось загрузить профиль");
  expect(screen.queryByText("fixture_internal_failure")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  expect(await screen.findByText(`fixture-user · ${roleLabel("operator")}`)).toBeTruthy();
});

it("saves the server schedule time zone through platform settings", async () => {
  state.bootstrap.mockResolvedValue({ principal: { username: "fixture-user", role: "admin" }, capabilities: ["access.manage"] });
  state.settings.mockResolvedValue({ items: [{ key: "server.timezone", value: "host" }] });
  state.saveSetting.mockResolvedValue({ item: { key: "server.timezone", value: "Europe/Berlin" } });
  renderProfile();
  const input = await screen.findByLabelText(t("operations.settings.server_tz_title"), { selector: "button" });
  expect(input.textContent).toBe(t("operations.settings.server_tz_host"));
  await chooseOption(input, "Europe/Berlin");
  expect(state.saveSetting).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: t("operations.settings.save") }));
  expect(state.saveSetting).toHaveBeenCalledWith("server.timezone", "Europe/Berlin");
  await screen.findByRole("status");
  expect(input.textContent).toBe("Europe/Berlin");
  expect((screen.getByRole("combobox", { name: t("operations.settings.tz_title") }) as HTMLInputElement).value).toBe("UTC");
});

it("calls logout, disables it while pending and names a failure", async () => {
  let fail!: (error: Error) => void;
  state.logout.mockImplementation(() => new Promise((_resolve, reject) => { fail = reject; }));
  renderProfile();
  await userEvent.click(screen.getByRole("button", { name: t("operations.settings.logout") }));
  await waitFor(() => expect(state.logout).toHaveBeenCalledOnce());
  expect((screen.getByRole("button", { name: t("operations.settings.logging_out") }) as HTMLButtonElement).disabled).toBe(true);
  fail(new Error("fixture_internal_failure"));
  expect((await screen.findByRole("alert")).textContent).toBe(t("shell.profile.logoutFailed"));
  expect(screen.queryByText("fixture_internal_failure")).toBeNull();
});

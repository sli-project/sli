// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ bootstrap: vi.fn(), access: { capabilities: ["access.manage"] as string[] }, fetch: vi.fn() }));
vi.mock("../App", () => ({ useEffectiveAccess: () => state.access, useTimeZone: () => ({ timeZone: "UTC" }) }));

import { AccessCenterPage } from "./access";
import { api } from "../../api/client";
import { localeRuntime, setLocale, t } from "../../i18n";

const people = [
  { id: 1, username: "synthetic.admin", role: "admin", is_active: true, is_service: false, last_login_at: "2026-11-13T12:00:00Z" },
  { id: 2, username: "synthetic.operator", role: "operator", is_active: true, is_service: false, last_login_at: null },
  { id: 3, username: "synthetic.viewer", role: "viewer", is_active: false, is_service: false, last_login_at: null },
];
const audit = Array.from({ length: 25 }, (_, index) => ({ id: index + 1, actor_type: "user", actor_id: 1, action: index === 24 ? "future_action" : "platform_setting_update", target_key: "ad.state", reason: null, outcome: "ok", created_at: "2026-11-13T12:00:00Z" }));
const response = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
const mutations = () => state.fetch.mock.calls.filter(([, init]) => init?.method === "POST");

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><AccessCenterPage/></QueryClientProvider>);
  return { ...view, client };
}

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  vi.stubGlobal("fetch", state.fetch);
  vi.spyOn(api, "bootstrap").mockImplementation(() => state.bootstrap());
  state.bootstrap.mockResolvedValue({ effective_role: "admin" });
  state.access = { capabilities: ["access.manage"] };
  state.fetch.mockImplementation(async (url: string, init?: RequestInit) => {
    if (init?.method === "POST") return response({ item: {} });
    if (url === "/api/auth/users") return response({ items: [...people, { ...people[0], id: 4, username: "synthetic.service", is_service: true }], roles: [] });
    if (url.startsWith("/api/v1/access/audit?limit=100")) return response({ items: audit, limit: 100 });
    if (url === "/api/v2/reports") return response({ items: [{ key: "ad.infrastructure", title: "AD status" }] });
    throw new Error(`Unexpected test request: ${url}`);
  });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.resetAllMocks(); });

it.each(["ru", "en"] as const)("keeps empty people and audit lists out of the error state in %s", async locale => {
  setLocale(locale);
  state.fetch.mockImplementation(async () => response({ items: [], roles: [] }));
  const { container } = mount();
  expect(await screen.findByText(t("access.people.empty"))).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: t("access.people.audit.title") }));
  expect(await screen.findByText(t("access.people.audit.empty"))).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(container.querySelector('[data-state="error"], [data-state="unavailable"]')).toBeNull();
});

it.each(["ru", "en"] as const)("shows the user endpoint's people and roles without access or assignment blocks in %s", async locale => {
  setLocale(locale);
  const { container } = mount();
  expect(await screen.findByText("synthetic.admin")).toBeTruthy();
  const table = screen.getByRole("table", { name: t("access.people.title") });
  expect(within(table).getByText(t("access.admin.roles.admin.label"))).toBeTruthy();
  expect(within(table).getByText(t("access.people.role.operator"))).toBeTruthy();
  expect(within(table).getByText(t("access.people.role.viewer"))).toBeTruthy();
  expect(within(table).getByText(t("access.admin.status.disabled"))).toBeTruthy();
  expect(screen.queryByText("synthetic.service")).toBeNull();
  expect(within(table).getAllByText("—").length).toBeGreaterThan(0);
  for (const key of ["access.center.recent_assignments", "access.user.reports.title"]) {
    expect(screen.queryByText(t(key as Parameters<typeof t>[0]))).toBeNull();
  }
  expect(container.querySelector("details,.sli-ds-metrics,.sli-ds-state--banner")).toBeNull();
  expect(screen.queryByRole("combobox")).toBeNull();
  expect(mutations()).toHaveLength(0);
  if (locale === "en") expect(container.textContent).not.toMatch(/[А-Яа-яЁё]/);
});

it.each(["viewer", "admin"])("creates a user with the entered name, password and %s role, then copies the accepted password", async role => {
  const user = userEvent.setup();
  const clipboard = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
  mount();
  await user.click(await screen.findByRole("button", { name: "Добавить пользователя" }));
  const dialog = screen.getByRole("dialog");
  const save = within(dialog).getByRole("button", { name: "Сохранить" });
  expect((save as HTMLButtonElement).disabled).toBe(true);
  expect(within(dialog).queryByRole("option", { name: "Оператор" })).toBeNull();
  await user.type(within(dialog).getByLabelText("Имя"), "synthetic.colleague");
  await chooseOption(within(dialog).getByLabelText("Роль", { selector: "button" }), role);
  await user.type(within(dialog).getByLabelText("Пароль"), "Synthetic-only-pass-69");
  await user.click(save);
  await within(dialog).findByRole("button", { name: "Скопировать" });
  expect(mutations()).toHaveLength(1);
  expect(mutations()[0][0]).toBe("/api/auth/users");
  expect(JSON.parse(mutations()[0][1].body)).toEqual({ username: "synthetic.colleague", role, password: "Synthetic-only-pass-69" });
  await user.click(within(dialog).getByRole("button", { name: "Скопировать" }));
  expect(clipboard).toHaveBeenCalledWith("Synthetic-only-pass-69");
  expect(await within(dialog).findByRole("status")).toHaveProperty("textContent", "Скопировано");
  await user.click(within(dialog).getByRole("button", { name: t("drawer.close") }));
  await user.click(screen.getByRole("button", { name: "Добавить пользователя" }));
  expect((screen.getByLabelText("Пароль") as HTMLInputElement).value).toBe("");
  expect(screen.queryByRole("button", { name: "Скопировать" })).toBeNull();
});

it("changes an existing operator to a beta role and can change it back after saving", async () => {
  const user = userEvent.setup();
  mount();
  const row = (await screen.findByText("synthetic.operator")).closest("tr")!;
  await user.click(within(row).getByRole("button", { name: "Сменить роль" }));
  const dialog = screen.getByRole("dialog");
  const select = within(dialog).getByLabelText("Роль", { selector: "button" });
  await user.click(select);
  expect((await screen.findByRole("option", { name: "Оператор" })).getAttribute("aria-disabled")).toBe("true");
  await user.keyboard("{Escape}");
  await chooseOption(select, "viewer");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  expect(await within(dialog).findByRole("status")).toHaveProperty("textContent", expect.stringMatching(/^Сохранено в \d\d\.\d\d\.\d{4}, \d\d:\d\d$/));
  await chooseOption(select, "admin");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(mutations()).toHaveLength(2));
  expect(mutations().map(([url, init]) => [url, JSON.parse(init.body)])).toEqual([
    ["/api/auth/users/2", { role: "viewer" }], ["/api/auth/users/2", { role: "admin" }],
  ]);
});

it("places a rejected password's error at its field and does not offer to copy it", async () => {
  const original = state.fetch.getMockImplementation()!;
  state.fetch.mockImplementation((url: string, init?: RequestInit) => init?.method === "POST"
    ? response({ error: "password_must_be_at_least_12_characters" }, 400) : original(url, init));
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole("button", { name: "Добавить пользователя" }));
  const dialog = screen.getByRole("dialog");
  await user.type(within(dialog).getByLabelText("Имя"), "synthetic.colleague");
  await user.type(within(dialog).getByLabelText("Пароль"), "Synthetic-only-pass-69");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  const error = await within(dialog).findByRole("alert");
  expect(error.textContent).toBe("Пароль должен содержать не менее 12 символов");
  expect(error.parentElement).toBe(within(dialog).getByLabelText("Пароль").parentElement);
  expect(within(dialog).queryByRole("button", { name: "Скопировать" })).toBeNull();
});

it("confirms disabling by name, respects cancellation and enables a disabled user", async () => {
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  const user = userEvent.setup();
  mount();
  const row = (await screen.findByText("synthetic.admin")).closest("tr")!;
  await user.click(within(row).getByRole("button", { name: "Отключить" }));
  expect(confirm).toHaveBeenLastCalledWith(expect.stringContaining("synthetic.admin"));
  expect(mutations()).toHaveLength(0);
  confirm.mockReturnValue(true);
  await user.click(within(row).getByRole("button", { name: "Отключить" }));
  await waitFor(() => expect(mutations()).toHaveLength(1));
  const disabled = screen.getByText("synthetic.viewer").closest("tr")!;
  expect((within(disabled).getByRole("button", { name: "Сбросить пароль" }) as HTMLButtonElement).disabled).toBe(true);
  await user.click(within(disabled).getByRole("button", { name: "Включить" }));
  await waitFor(() => expect(mutations()).toHaveLength(2));
  expect(mutations().map(([url, init]) => [url, JSON.parse(init.body)])).toEqual([
    ["/api/auth/users/1", { is_active: false }], ["/api/auth/users/3", { is_active: true }],
  ]);
});

it("resets the selected user's password through the existing endpoint", async () => {
  vi.spyOn(window, "confirm").mockReturnValue(true);
  const user = userEvent.setup();
  mount();
  const row = (await screen.findByText("synthetic.admin")).closest("tr")!;
  await user.click(within(row).getByRole("button", { name: "Сбросить пароль" }));
  const dialog = screen.getByRole("dialog");
  await user.type(within(dialog).getByLabelText("Новый пароль"), "Synthetic-reset-only-69");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await within(dialog).findByRole("status");
  expect(mutations().map(([url, init]) => [url, JSON.parse(init.body)])).toEqual([["/api/auth/users/1/password", { password: "Synthetic-reset-only-69" }]]);
  expect((within(dialog).getByLabelText("Новый пароль") as HTMLInputElement).value).toBe("");
});

it.each(["ru", "en"] as const)("keeps all returned audit rows, translates known actions and shows an unknown action's code in %s", async locale => {
  setLocale(locale);
  const user = userEvent.setup();
  mount();
  await screen.findByText("synthetic.admin");
  await user.click(screen.getByRole("tab", { name: t("access.people.audit.title") }));
  const unknown = await screen.findByText("future_action");
  const table = screen.getByRole("table", { name: t("access.people.audit.title") });
  expect(within(table).getAllByRole("row")).toHaveLength(audit.length + 1);
  expect(within(table).getAllByText(t("access.audit.actions.platform_setting_update"))).toHaveLength(24);
  expect(within(table).getAllByText("synthetic.admin")).toHaveLength(25);
  await waitFor(() => expect(within(table).getAllByText(locale === "en" ? "Active Directory health" : "AD status")).toHaveLength(25));
  await user.click(unknown);
  const dialog = screen.getByRole("dialog");
  expect(within(dialog).getByText(t("access.center.audit.basis")).nextElementSibling?.textContent).toBe("—");
});

it.each(["viewer", "operator", "failed", "pending"])("does not request the user inventory when the effective role is %s", async role => {
  if (role === "pending") state.bootstrap.mockImplementation(() => new Promise(() => {}));
  else if (role === "failed") state.bootstrap.mockRejectedValue(new Error("synthetic failure"));
  else state.bootstrap.mockResolvedValue({ effective_role: role, principal: { role: "admin" } });
  const { client } = mount();
  await act(async () => {});
  if (role !== "pending") await waitFor(() => expect(client.isFetching()).toBe(0));
  expect(state.fetch.mock.calls.some(([url]) => url === "/api/auth/users")).toBe(false);
  expect(screen.queryByRole("button", { name: "Добавить пользователя" })).toBeNull();
});

it("does not attribute an API key's action to a person with the same numeric identifier", async () => {
  const original = state.fetch.getMockImplementation()!;
  state.fetch.mockImplementation((url: string, init?: RequestInit) => url.startsWith("/api/v1/access/audit?limit=100")
    ? response({ items: [{ ...audit[0], actor_type: "api_key" }], limit: 100 }) : original(url, init));
  const user = userEvent.setup();
  mount();
  await screen.findByText("synthetic.admin");
  await user.click(screen.getByRole("tab", { name: "Журнал" }));
  const table = await screen.findByRole("table", { name: "Журнал" });
  expect(within(table).queryByText("synthetic.admin")).toBeNull();
  expect(within(table).queryByRole("columnheader", { name: t("access.people.audit.actor") })).toBeNull();
});

it("opens the role descriptions from a user row and gives that list a distinct tab label", async () => {
  mount();
  await screen.findByRole("tab", { name: "Учётные записи" });
  const table = await screen.findByRole("table", { name: t("access.people.title") });
  expect(screen.queryByRole("tab", { name: t("access.people.title") })).toBeNull();
  expect(screen.getByRole("link", { name: "Заявки на доступ" }).getAttribute("href")).toBe("/app/access-requests");
  fireEvent.click(within(table).getAllByRole("button", { name: t("access.people.changeRole") })[1]);
  const dialog = screen.getByRole("dialog", { name: t("access.people.changeRole") });
  expect(within(dialog).getByText(t("access.admin.roles.operator.description"))).toBeTruthy();
  expect(within(dialog).getByText(t("access.admin.roles.admin.description"))).toBeTruthy();
});

it("shows a grouped Telegram change with its raw records and attributes local automation to SLI", async () => {
  const original = state.fetch.getMockImplementation()!;
  const first = { ...audit[0], actor_id: null, actor_type: "local", action: "notification_channel_update",
    target_type: "notification_channel", target_key: "telegram", created_at: "2026-11-13T11:59:00Z" };
  const last = { ...first, id: 2, created_at: "2026-11-13T12:00:00Z" };
  state.fetch.mockImplementation((url: string, init?: RequestInit) => url.includes("collapse=1")
    ? response({ items: [{ ...last, occurrences: [last, first] }], limit: 100 }) : original(url, init));
  mount();
  fireEvent.click(await screen.findByRole("tab", { name: "Журнал" }));
  const table = await screen.findByRole("table", { name: "Журнал" });
  const row = within(table).getByText("Изменены настройки Telegram").closest("tr")!;
  expect(within(row).getByRole("cell", { name: "SLI" })).toBeTruthy();
  expect(within(row).getByRole("cell", { name: "2" })).toBeTruthy();
  fireEvent.click(row);
  const dialog = screen.getByRole("dialog", { name: "Изменены настройки Telegram" });
  expect(within(dialog).getByRole("table")).toBeTruthy();
});

it("loads the inventory error independently and retries it", async () => {
  const original = state.fetch.getMockImplementation()!;
  state.fetch.mockImplementation((url: string, init?: RequestInit) => url === "/api/auth/users" ? response({ error: "synthetic_unavailable" }, 503) : original(url, init));
  const user = userEvent.setup();
  mount();
  expect(await screen.findByText("Не удалось загрузить список пользователей")).toBeTruthy();
  state.fetch.mockImplementation(original);
  await user.click(screen.getByRole("button", { name: "Повторить" }));
  expect(await screen.findByText("synthetic.admin")).toBeTruthy();
});

it("opens details with the identifier below the user facts using the row keyboard action", async () => {
  mount();
  const row = (await screen.findByText("synthetic.admin")).closest("tr")!;
  fireEvent.keyDown(row, { key: "Enter" });
  const dialog = screen.getByRole("dialog");
  expect(within(dialog).getByRole("heading", { name: "synthetic.admin" })).toBeTruthy();
  expect(within(dialog).getByText("Идентификатор пользователя").nextElementSibling?.textContent).toBe("1");
});

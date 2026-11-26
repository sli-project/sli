// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  users: vi.fn(), subjects: vi.fn(), effective: vi.fn(), updateUser: vi.fn(), resetPassword: vi.fn(),
}));
vi.mock("../App", () => ({
  useTimeZone: () => ({ timeZone: "UTC" }),
  useEffectiveAccess: () => ({ capabilities: ["access.manage"] }),
}));
vi.mock("../../design-system", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../design-system")>()),
  useOverlays: () => ({ toast: vi.fn(), openDrawer: vi.fn(), openModal: vi.fn(), closeModal: vi.fn() }),
}));
vi.mock("../../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/client")>()),
  api: {
    bootstrap: async () => ({ effective_role: "admin" }),
    adminUsers: () => state.users(), apiKeys: async () => ({ items: [] }),
    updateUser: (...args: unknown[]) => state.updateUser(...args),
    resetUserPassword: (...args: unknown[]) => state.resetPassword(...args),
    v4AccessSubjectsForAccountType: (kind: string) => state.subjects(kind), v4Access: (id?: number) => state.effective(id),
    v4AccessGrantOptions: async () => ({ items: [] }), v4AccessAudit: async () => ({ items: [] }),
    reportsV2Catalog: async () => ({ items: [] }),
  },
}));

import { localeRuntime, setLocale } from "../../i18n";
import { AdminPage } from "./admin";
import { filterAccounts } from "./account-filter";

const users = [
  { id: 1, username: "synthetic-person", role: "viewer", is_active: true, is_service: false },
  { id: 2, username: "report-key-person", role: "viewer", is_active: false, is_service: false },
  { id: 3, username: "renamed-reader", role: "viewer", is_active: true, is_service: true },
  { id: 4, username: "report-key-revoked", role: "viewer", is_active: false, is_service: true },
];
const roles = [{ id: "viewer", label: "Viewer", description: "Synthetic role" }];
function mount(Page: () => React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><Page/></QueryClientProvider>);
}
beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  state.users.mockResolvedValue({ items: users, roles });
  state.subjects.mockImplementation(async (kind: string) => ({ users: users.filter((item) => item.is_service === (kind === "service")), packages: [], groups: [], assignments: [], package_assignments: [] }));
  state.effective.mockResolvedValue({ subject: {}, groups: [], packages: [], reports: [], capabilities: [], explicit_denies: { packages: [], capabilities: [], reports: [] } });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.clearAllMocks(); });

it("keeps legacy unclassified inventory in people without guessing from the login", () => {
  const legacy = [{ username: "report-key-legacy", is_service: undefined as unknown as boolean }];
  expect(filterAccounts(legacy, "people")).toEqual(legacy);
  expect(filterAccounts(legacy, "service")).toEqual([]);
});

it.each([
  ["ru", "Учётные записи", "Люди", "Служебные"],
  ["en", "Accounts", "People", "Service accounts"],
] as const)("separates people from service inventory in %s without changing accounts", async (locale, label, people, service) => {
  setLocale(locale);
  mount(AdminPage);
  await screen.findByText("synthetic-person");
  expect(screen.getByText("report-key-person")).toBeTruthy();
  expect(screen.queryByText("renamed-reader")).toBeNull();
  expect(screen.queryByText("report-key-revoked")).toBeNull();
  const filter = screen.getByLabelText(label, { selector: "button" });
  expect(filter.textContent).toBe(people);
  await chooseOption(filter, "service");
  expect(filter.textContent).toBe(service);
  expect(screen.getByText("renamed-reader")).toBeTruthy();
  expect(screen.getByText("report-key-revoked")).toBeTruthy();
  expect(screen.queryByText("synthetic-person")).toBeNull();
  expect(screen.queryByText("report-key-person")).toBeNull();
  await chooseOption(filter, "people");
  expect(screen.getByText("synthetic-person")).toBeTruthy();
  expect(state.updateUser).not.toHaveBeenCalled();
  expect(state.resetPassword).not.toHaveBeenCalled();
});

it("shows an honest empty service filter and restores people", async () => {
  state.users.mockResolvedValue({ items: users.slice(0, 2), roles });
  mount(AdminPage);
  await screen.findByText("synthetic-person");
  await chooseOption(screen.getByLabelText("Учётные записи", { selector: "button" }), "service");
  expect(screen.getByText("Служебных учётных записей нет")).toBeTruthy();
  await chooseOption(screen.getByLabelText("Учётные записи", { selector: "button" }), "people");
  expect(screen.getByText("report-key-person")).toBeTruthy();
});

it("does not leave a password-reset form for an account hidden by the filter", async () => {
  const user = userEvent.setup();
  mount(AdminPage);
  const row = (await screen.findByText("synthetic-person")).closest("tr")!;
  await user.click(within(row).getByRole("button", { name: "Сбросить пароль" }));
  expect(screen.getByLabelText("Новый пароль")).toBeTruthy();
  await chooseOption(screen.getByLabelText("Учётные записи", { selector: "button" }), "service");
  expect(screen.queryByLabelText("Новый пароль")).toBeNull();
  expect(state.resetPassword).not.toHaveBeenCalled();
});


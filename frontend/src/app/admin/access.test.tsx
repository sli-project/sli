// @vitest-environment jsdom
import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  timeZone: "UTC",
  bootstrap: vi.fn(),
  catalog: vi.fn(),
  access: undefined as unknown,
  toast: vi.fn(),
  subjects: vi.fn(),
  grantOptions: vi.fn(),
  audit: vi.fn(),
  effective: vi.fn(),
  requests: vi.fn(),
  decide: vi.fn(),
  createAssignment: vi.fn(),
  createPackage: vi.fn(),
}));

vi.mock("../App", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../App")>()),
  useEffectiveAccess: () => state.access,
  useTimeZone: () => ({ timeZone: state.timeZone }),
}));
vi.mock("../../design-system", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../design-system")>()), useOverlays: () => ({ toast: state.toast, openDrawer: vi.fn(), openModal: vi.fn(), closeModal: vi.fn() }) }));
vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      bootstrap: () => state.bootstrap(),
      reportsV2Catalog: () => state.catalog(),
      v4AccessSubjects: () => state.subjects(),
      v4AccessSubjectsForAccountType: () => state.subjects(),
      v4AccessGrantOptions: () => state.grantOptions(),
      v4AccessAudit: () => state.audit(),
      v4Access: (userId?: number) => state.effective(userId),
      v4ReportAccessRequests: () => state.requests(),
      v4DecideReportAccessRequest: (id: number, body: unknown) => state.decide(id, body),
    },
  };
});
vi.mock("../v4-mutation-workflows", () => ({
  createAssignmentWithVerification: (body: unknown) => state.createAssignment(body),
  createPackageAssignmentWithVerification: (body: unknown) => state.createPackage(body),
}));

import { AccessCenterPage, AccessRequestsPage, AccessUserPage } from "./access";
import { localeRuntime, setLocale, t } from "../../i18n";

const manage = { capabilities: ["access.manage"], reports: [] };

const effectiveAccess = (overrides: Record<string, unknown> = {}) => ({
  evaluated_at_utc: "2026-09-29T10:00:00Z",
  subject: { username: "operator1", coarse_role: "operator", id: 7 },
  groups: [{ key: "ib", name: "ИБ · операторы" }],
  packages: [{ key: "sec", name: "Пакет ИБ" }],
  capabilities: ["reports.view", "access.manage"],
  allowed_report_count: 1,
  explicit_denies: { packages: [], capabilities: [], reports: ["ad.state"] },
  reports: [
    { report_key: "security.queue", name: "Очередь проблем", allowed: true, explanation: "Access allowed by assignment and capability policy", dataset_key: "findings", allowed_actions: ["view", "export"], sources: [{ source_type: "package", source: "sec" }], missing_capabilities: [] },
    { report_key: "ad.state", name: "Состояние AD", allowed: false, explanation: "Явный запрет", dataset_key: "ad", allowed_actions: [], sources: [], missing_capabilities: [] },
  ],
  ...overrides,
});

const subjects = {
  users: [{ id: 7, username: "operator1", role: "operator", is_active: true }, { id: 8, username: "gone", role: "viewer", is_active: false }],
  groups: [],
  packages: [{ package_key: "sec", name: "Пакет ИБ", description: "Работа с очередью", capabilities: ["reports.view"], reports: ["security.queue"] }],
  assignments: [{ id: 1, subject_type: "user", subject_id: 7, report_key: "vpn.audit", effect: "allow", source_type: "direct", scope_json: { kind: "all" }, field_categories: [], allowed_actions: ["view"], valid_until: null, business_reason: "аудит VPN", created_at: "2026-09-01T00:00:00Z" }],
  package_assignments: [{ id: 2, subject_type: "user", subject_id: 7, package_key: "sec", package_name: "Пакет ИБ", effect: "allow", source_type: "temporary", valid_until: null, business_reason: "замена коллеги", created_at: "2026-09-01T00:00:00Z" }],
};

async function mount(Page: () => ReactNode, client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  const root = createRootRoute();
  const routes = ["/access", "/access-user"].map((path) => createRoute({ getParentRoute: () => root, path, component: Page }));
  const router = createRouter({ routeTree: root.addChildren(routes), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/access"] }) });
  await router.load();
  return render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
}

beforeEach(() => {
  vi.stubGlobal("scrollTo", vi.fn());
  state.catalog.mockResolvedValue({ items: [] });
  state.timeZone = "UTC";
  state.bootstrap.mockResolvedValue({ effective_role: "operator" });
  state.access = manage;
  state.subjects.mockResolvedValue(subjects);
  state.grantOptions.mockResolvedValue({ api_version: "v4", items: [], limits: { reports: 100 } });
  state.audit.mockResolvedValue({ items: [{ id: 1, actor_type: "user", action: "package_assignment_created", target_key: "sec", reason: "замена коллеги", outcome: "ok", created_at: "2026-09-29T09:00:00Z" }], limit: 100 });
  state.effective.mockResolvedValue(effectiveAccess());
});
afterEach(() => { cleanup(); vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.clearAllMocks(); });

it.each(["ru", "en"] as const)("localizes own access after module import in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  state.effective.mockResolvedValue(effectiveAccess({ groups: [], packages: [], reports: [] }));
  const own = await mount(AccessUserPage);
  await screen.findByText("operator1");
  expect(screen.getByText(t("access.user.note.title"))).toBeTruthy();
  if (locale === "en") expect(own.container.textContent).not.toMatch(/[А-Яа-яЁё]/);
});

it.each(["ru", "en"] as const)("localizes request states and decision drawer without granting access in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  state.requests.mockResolvedValue({ items: [{
    id: 51, username: "fixture-user", report_key: "fixture", report_name: "Fixture report", report_version: 2, dataset_version: 3,
    requested_scope_json: { kind: "all" }, requested_valid_until: "2026-12-01T12:00:37.123Z", business_reason: "Fixture request",
    requested_field_categories: [], requested_actions: ["view"], status: "submitted",
  }] });
  const { container } = await mount(AccessRequestsPage);
  expect(await screen.findByText(t("access.center.status.submitted"))).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: t("access.requests.button.review") }));
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByLabelText(t("access.requests.drawer.decisionReason"))).toBeTruthy();
  if (locale === "en") { expect(container.textContent).not.toMatch(/[А-Яа-яЁё]/); expect(dialog.textContent).not.toMatch(/[А-Яа-яЁё]/); }
  await userEvent.click(within(dialog).getByRole("button", { name: t("access.assign.drawer.cancel") }));
  expect(state.decide).not.toHaveBeenCalled();
  cleanup();
  state.access = { capabilities: [], reports: [] };
  const denied = await mount(AccessRequestsPage);
  expect(await screen.findByRole("link", { name: t("access.center.gate.openMine") })).toBeTruthy();
  if (locale === "en") expect(denied.container.textContent).not.toMatch(/[А-Яа-яЁё]/);
});

it("denies the access centre and the request queue without access.manage", async () => {
  state.access = { capabilities: ["reports.view"], reports: [] };
  await mount(AccessCenterPage);
  expect((await screen.findByRole("alert")).textContent).toContain("Нет доступа");
  expect(state.subjects).not.toHaveBeenCalled();
  cleanup();
  await mount(AccessRequestsPage);
  expect((await screen.findByRole("alert")).textContent).toContain("рассмотрения заявок");
  expect(state.requests).not.toHaveBeenCalled();
});

it("shows the own effective access with a trace button per report", async () => {
  await mount(AccessUserPage);
  expect(await screen.findByText("operator1")).toBeTruthy();
  expect(screen.getByText("оператор")).toBeTruthy();
  expect(screen.getByText("Пакет ИБ")).toBeTruthy();
  expect(document.querySelectorAll("[data-access-trace]").length).toBe(2);
  expect(screen.getByText("просмотр, экспорт")).toBeTruthy();
});

it("records a rejection of a report access request", async () => {
  state.requests.mockResolvedValue({ api_version: "v4", limit: 100, review_allowed: true, items: [{
    id: 5, requester_user_id: 7, username: "operator1", report_key: "vpn.audit", report_name: "VPN-аудит", report_version: 2, dataset_version: 3,
    requested_scope_json: { kind: "all" }, requested_valid_until: "2026-12-01T00:00:00Z", business_reason: "нужен для расследования",
    requested_field_categories: ["security"], requested_actions: ["view"], status: "submitted", created_at: "2026-09-28T00:00:00Z", updated_at: "2026-09-28T00:00:00Z",
  }] });
  state.decide.mockResolvedValue({ item: {} });
  const user = userEvent.setup();
  await mount(AccessRequestsPage);
  expect(await screen.findByText("VPN-аудит")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Отклонить" }));
  const dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText("Причина отказа"), "Не хватает основания");
  await user.click(within(dialog).getByRole("button", { name: "Отклонить" }));
  await waitFor(() => expect(state.decide).toHaveBeenCalledTimes(1));
  expect(state.decide).toHaveBeenCalledWith(5, { decision: "reject", decision_reason: "Не хватает основания" });
});

it.each([["Asia/Novosibirsk", false, false], ["America/New_York", false, false], ["Asia/Novosibirsk", true, false], ["America/New_York", true, false], ["America/New_York", true, true]] as const)("approval instant in %s (edited=%s, zoneChanged=%s)", async (timeZone, edited, zoneChanged) => {
  state.timeZone = timeZone;
  const original = "2026-12-01T12:00:37.123Z";
  state.requests.mockResolvedValue({ api_version: "v4", limit: 100, review_allowed: true, items: [{
    id: 5, requester_user_id: 7, username: "operator1", report_key: "vpn.audit", report_name: "VPN-аудит", report_version: 2, dataset_version: 3,
    requested_scope_json: { kind: "all" }, requested_valid_until: original, business_reason: "нужен для расследования",
    requested_field_categories: ["security"], requested_actions: ["view"], status: "submitted", created_at: "2026-09-28T00:00:00Z", updated_at: "2026-09-28T00:00:00Z",
  }] });
  // Keep the drawer open after the intercepted submission; no real access is changed.
  state.decide.mockImplementation(() => new Promise(() => undefined));
  const user = userEvent.setup();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await mount(AccessRequestsPage, client);
  await user.click(await screen.findByRole("button", { name: t("access.requests.button.review") }));
  const dialog = await screen.findByRole("dialog");
  const input = within(dialog).getByLabelText(t("access.requests.drawer.validUntilLimit")) as HTMLInputElement;
  expect(input.value).toBe(timeZone === "Asia/Novosibirsk" ? "2026-12-01 19:00" : "2026-12-01 07:00");
  if (edited) fireEvent.change(input, { target: { value: timeZone === "Asia/Novosibirsk" ? "2026-12-01T18:00" : "2026-12-01T06:00" } });
  if (zoneChanged) {
    state.timeZone = "UTC";
    await act(async () => { client.setQueryData(["v4", "report-access-requests", "all"], { items: [], review_allowed: true }); });
    expect(within(dialog).getByText(`Зона времени этой формы: ${timeZone}.`)).toBeTruthy();
  }
  await user.type(within(dialog).getByLabelText(t("access.requests.drawer.decisionReason")), "Подтверждено оператором");
  await user.click(within(dialog).getByRole("button", { name: t("access.requests.drawer.approve") }));
  await waitFor(() => expect(state.decide).toHaveBeenCalledWith(5, expect.objectContaining({ valid_until: edited ? "2026-12-01T11:00:00.000Z" : original })));
});


it.each((["ru", "en"] as const).flatMap((locale) => ["2026-03-08T02:30", "2026-11-01T01:30"].map((wall) => ({ locale, wall }))))("rejects ambiguous or nonexistent edited approval time ($locale $wall)", async ({ locale, wall }) => {
  const { setLocale, localeRuntime } = await import("../../i18n");
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  state.timeZone = "America/New_York";
  state.requests.mockResolvedValue({ api_version: "v4", limit: 100, review_allowed: true, items: [{
    id: 5, requester_user_id: 7, username: "operator1", report_key: "vpn.audit", report_name: "VPN", report_version: 2, dataset_version: 3,
    requested_scope_json: { kind: "all" }, requested_valid_until: "2026-12-01T12:00:37.123Z", business_reason: "test request",
    requested_field_categories: ["security"], requested_actions: ["view"], status: "submitted", created_at: "2026-09-28T00:00:00Z", updated_at: "2026-09-28T00:00:00Z",
  }] });
  state.decide.mockImplementation(() => new Promise(() => undefined));
  try {
    await mount(AccessRequestsPage);
    fireEvent.click(await screen.findByRole("button", { name: t("access.requests.button.review") }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText(t("access.requests.drawer.validUntilLimit")), { target: { value: wall } });
    fireEvent.change(within(dialog).getByLabelText(t("access.requests.drawer.decisionReason")), { target: { value: "Valid reason" } });
    fireEvent.click(within(dialog).getByRole("button", { name: t("access.requests.drawer.approve") }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", locale === "ru"
      ? "Время не существует или неоднозначно в выбранной зоне. Выберите другое время либо откройте форму заново в UTC."
      : "This time is nonexistent or ambiguous in the selected zone. Choose another time or reopen the form in UTC.");
    expect(state.decide).not.toHaveBeenCalled();
  } finally { setLocale("ru"); vi.restoreAllMocks(); }
});


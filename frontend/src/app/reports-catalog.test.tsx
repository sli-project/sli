// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  v2: vi.fn(), v4: vi.fn(), request: vi.fn(), pin: vi.fn(), toast: vi.fn(), data: vi.fn(),
}));

vi.mock("../design-system", async (importOriginal) => ({ ...(await importOriginal<typeof import("../design-system")>()), useOverlays: () => ({ toast: state.toast, openDrawer: vi.fn(), openModal: vi.fn(), closeModal: vi.fn() }) }));
vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      reportsV2Catalog: () => state.v2(), v4Reports: () => state.v4(),
      v4CreateReportAccessRequest: (body: unknown) => state.request(body), v4UpdateReportPreference: (...args: unknown[]) => state.pin(...args),
      v4ReportData: (...args: unknown[]) => state.data(...args), v4ReportExportUrl: (key: string) => `/api/export/${key}`,
    },
  };
});

import { buildCatalogRows, ReportsCatalogPage } from "./reports-catalog";
import { ReportViewerPage, viewerState } from "./report-viewer";
import { localeRuntime, setLocale, t } from "../i18n";

const v4 = (overrides: Record<string, unknown> = {}) => ({
  report_key: "x.report", version: 1, name: "Отчёт X", owner: "ИБ", purpose: "Назначение X", dataset_key: "d", dataset_version: 1,
  sensitivity: "restricted", status: "published", target_path: "/reports/x.report", allowed: true, explanation: "", missing_capabilities: [],
  field_categories: [], allowed_actions: ["view"], scopes: [], sources: [], pinned: false, ...overrides,
});

async function mount(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const root = createRootRoute();
  const routes = [
    createRoute({ getParentRoute: () => root, path: "/reports", component: ReportsCatalogPage }),
    createRoute({ getParentRoute: () => root, path: "/reports/$reportKey", component: ReportViewerPage }),
    createRoute({ getParentRoute: () => root, path: "/report/$reportKey", component: () => null }),
  ];
  const router = createRouter({ routeTree: root.addChildren(routes), basepath: "/app", history: createMemoryHistory({ initialEntries: [`/app${path}`] }) });
  await router.load();
  return render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
}

beforeEach(() => {
  vi.stubGlobal("scrollTo", vi.fn());
  state.v2.mockResolvedValue({ items: [{ key: "ad.users.v2", title: "Учётные записи AD", description: "Пользователи", section: "ad", section_title: "Active Directory" }] });
  state.v4.mockResolvedValue({ items: [], allowed_count: 0, total_count: 0 });
  state.request.mockResolvedValue({ item: {} });
  state.pin.mockResolvedValue({ item: {} });
});
afterEach(() => { cleanup(); vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.clearAllMocks(); });

it.each(["ru", "en"] as const)("keeps localized builtin metadata and custom report text separate in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const builtinTitle = locale === "en" ? "AD accounts" : "Учётные записи AD";
  state.v2.mockResolvedValue({ items: [{ key: "ad.users.v2", title: builtinTitle, description: "Fixture metadata", section: "ad", section_title: "Active Directory" }] });
  state.v4.mockResolvedValue({ items: [v4()], allowed_count: 1, total_count: 1 });
  await mount("/reports");
  expect(await screen.findByRole("link", { name: builtinTitle })).toBeTruthy();
  expect(screen.getByRole("link", { name: "Отчёт X" })).toBeTruthy();
  expect(state.pin).not.toHaveBeenCalled();
  expect(state.request).not.toHaveBeenCalled();
  cleanup();
  state.data.mockResolvedValue(data({ items: [{ enabled: true, display_name: "Исходное имя" }], fields: [{ key: "enabled", label: "Custom enabled", category: "identity_basic" }, { key: "display_name", label: "Custom name", category: "identity_basic" }] }));
  await mount("/reports/x.report");
  expect(await screen.findByText("Исходное имя")).toBeTruthy();
  expect(screen.getByText(t("reports.viewer.value.yes"))).toBeTruthy();
  expect(screen.queryByText(t("reports.viewer.action.export"))).toBeNull();
});

it("shows a v2 report once even when a v4 report targets it", () => {
  const rows = buildCatalogRows(
    [{ key: "ad.users.v2", title: "Учётные записи AD", description: "", section_title: "Active Directory" }],
    [v4({ report_key: "ad.users", name: "Пользователи AD (v4)" }), v4({ report_key: "ops.readiness", name: "Готовность", target_path: "/project-readiness" })],
  );
  expect(rows.map((row) => row.title)).toEqual(["Учётные записи AD", "Готовность"]);
  expect(rows[0].report?.report_key).toBe("ad.users");
  expect(rows[1].path).toBe("/project-readiness");
});

it("renders one catalog with sections and the pin preference for an allowed report", async () => {
  state.v4.mockResolvedValue({ items: [v4({ report_key: "ad.users", target_path: "/reports/ad.users" })], allowed_count: 1, total_count: 1 });
  await mount("/reports");
  expect(await screen.findByRole("heading", { name: "Active Directory" })).toBeTruthy();
  expect(screen.getAllByRole("link", { name: "Учётные записи AD" })).toHaveLength(1);
  fireEvent.click(await screen.findByRole("button", { name: /Закрепить отчёт/ }));
  await waitFor(() => expect(state.pin).toHaveBeenCalledWith("ad.users", true));
  await waitFor(() => expect(state.toast).toHaveBeenCalledWith("Отчёт закреплён", expect.any(String)));
});

it("offers the access request for a not-allowed report and sends it to the api", async () => {
  state.v4.mockResolvedValue({ items: [v4({ report_key: "sec.hidden", name: "Закрытый отчёт", allowed: false, requestable: true, target_path: "/reports/sec.hidden" })], allowed_count: 0, total_count: 1 });
  await mount("/reports");
  expect(screen.queryByRole("link", { name: "Закрытый отчёт" })).toBeNull();
  fireEvent.click(await screen.findByRole("button", { name: /Запросить доступ к отчёту/ }));
  fireEvent.change(await screen.findByLabelText("Рабочее обоснование"), { target: { value: "Нужно для проверки инцидента" } });
  fireEvent.click(screen.getByRole("button", { name: "Отправить заявку" }));
  await waitFor(() => expect(state.request).toHaveBeenCalledTimes(1));
  expect(state.request.mock.calls[0][0]).toMatchObject({ report_key: "sec.hidden", scope: { kind: "all" }, business_reason: "Нужно для проверки инцидента" });
  await waitFor(() => expect(state.toast).toHaveBeenCalledWith("Заявка отправлена", expect.stringContaining("Закрытый отчёт")));
});

it("reports a failed request and an unavailable catalog honestly", async () => {
  state.v2.mockRejectedValue(new Error("v2 down"));
  state.v4.mockRejectedValue(new Error("v4 down"));
  await mount("/reports");
  expect((await screen.findByRole("alert")).textContent).toContain("v2 down");
});

const data = (overrides: Record<string, unknown> = {}) => ({
  api_version: "v4", report: v4({ allowed_actions: ["view"] }), dataset_key: "d", state: "ok",
  items: [{ name: "alpha" }], fields: [{ key: "name", label: "Имя", category: "identity_basic" }], has_more: false, limits: {}, ...overrides,
});

it("hides export without permission and shows it with permission", async () => {
  state.data.mockResolvedValue(data());
  await mount("/reports/x.report");
  expect(await screen.findByText("alpha")).toBeTruthy();
  expect(screen.queryByText("Экспорт")).toBeNull();
  cleanup();
  state.data.mockResolvedValue(data({ report: v4({ allowed_actions: ["view", "export"] }) }));
  await mount("/reports/x.report");
  expect((await screen.findByText("Экспорт")).getAttribute("href")).toBe("/api/export/x.report");
});

it("loads the next page by cursor", async () => {
  state.data.mockResolvedValueOnce(data({ has_more: true, next_cursor: "c1" })).mockResolvedValueOnce(data({ items: [{ name: "beta" }] }));
  await mount("/reports/x.report");
  fireEvent.click(await screen.findByRole("button", { name: /Показать ещё|Загрузить/ }));
  expect(await screen.findByText("beta")).toBeTruthy();
  expect(state.data.mock.calls[1][2].get("cursor")).toBe("c1");
});

it("shows denied for a forbidden report and not an empty table", async () => {
  state.data.mockRejectedValue(new Error("403 report_access_denied"));
  await mount("/reports/x.report");
  expect((await screen.findByRole("alert")).getAttribute("data-state")).toBe("denied");
});

it("does not present an unavailable source as an empty result", () => {
  expect(viewerState(data({ state: "gated", items: [] }) as never, 0)).toBe("unavailable");
  expect(viewerState(data({ items: [] }) as never, 0)).toBe("empty");
  expect(viewerState(data() as never, 1)).toBe("ok");
});

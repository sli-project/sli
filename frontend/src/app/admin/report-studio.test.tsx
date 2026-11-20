// @vitest-environment jsdom
import { existsSync, readFileSync } from "node:fs";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  v2Catalog: vi.fn(),
  access: undefined as unknown,
  definitions: vi.fn(), detail: vi.fn(), datasets: vi.fn(), preview: vi.fn(), publish: vi.fn(),
  promote: vi.fn(), retire: vi.fn(), visibility: vi.fn(), summary: vi.fn(), catalog: vi.fn(),
}));

vi.mock("../App", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../App")>()),
  useEffectiveAccess: () => state.access,
  useTimeZone: () => ({ timeZone: "UTC" }),
}));
vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      reportsV2Catalog: () => state.v2Catalog(),
      v4ReportDefinitions: () => state.definitions(), v4ReportDefinitionDetail: (key: string) => state.detail(key), v4Datasets: () => state.datasets(),
      v4BuilderPreview: (body: unknown) => state.preview(body), v4PublishReport: (body: unknown) => state.publish(body),
      v4PromoteReportVersion: (key: string, version: number) => state.promote(key, version), v4RetireReport: (key: string) => state.retire(key),
      v4SetReportVisibility: (key: string, body: unknown) => state.visibility(key, body), v4ReportAccessSummary: (key: string) => state.summary(key),
      v4Reports: () => state.catalog(),
    },
  };
});

import { ApiResponseError } from "../../api/client";
import { OverlayProvider } from "../../design-system";
import { ReportStudioPage } from "./report-studio";
import { localeRuntime, setLocale, t, type Locale } from "../../i18n";

async function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const root = createRootRoute();
  const routes = ["/report-studio", "/reports/$reportKey", "/report/$reportKey", "/access-user"].map((path) => createRoute({ getParentRoute: () => root, path, component: ReportStudioPage }));
  const router = createRouter({ routeTree: root.addChildren(routes), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/report-studio"] }) });
  await router.load();
  return render(<QueryClientProvider client={client}><OverlayProvider><RouterProvider router={router}/></OverlayProvider></QueryClientProvider>);
}

const def = (overrides: Record<string, unknown> = {}) => ({
  report_key: "qa.vpn", version: 1, name: "VPN-доступ", owner_name: "ИБ", purpose: "Кто в VPN", sensitivity: "restricted", status: "published",
  dataset_key: "ad.accounts.vpn", dataset_version: 1, published_at: "2026-10-01T09:00:00Z", created_at: "2026-10-01T09:00:00Z",
  discoverable: false, requestable: false, assignment_count: 2, package_count: 1, code_defined: false, ...overrides,
});
const version = (overrides: Record<string, unknown> = {}) => ({
  report_key: "qa.vpn", version: 1, name: "VPN-доступ", owner_name: "ИБ", purpose: "Кто в VPN", sensitivity: "restricted", status: "published",
  definition_json: { columns: ["account"], filters: [], sort: [], actions: ["view"] }, discoverable: false, requestable: false,
  published_at: "2026-10-01T09:00:00Z", created_by: 1, dataset_key: "ad.accounts.vpn", ...overrides,
});
const dataset = {
  dataset_key: "ad.accounts.vpn", version: 1, name: "VPN-учётки", fields_json: [
    { key: "account", label: "Учётная запись", category: "identity_basic" }, { key: "state", label: "Состояние", category: "security" },
  ],
  filters_json: [{ key: "state", ops: ["eq", "in"] }, { key: "unsupported", ops: ["eq"] }], actions_json: ["view", "export"], status: "published",
  executable: true, executable_filter_keys: ["state"], executable_sort_keys: ["account"],
};
const FULL = ["reports.design", "reports.publish", "reports.assign"];
const as = (capabilities: string[]) => { state.access = { capabilities, reports: [], subject: { id: 7, username: "ivanov", type: "user", coarse_role: "admin" } }; };

beforeEach(() => {
  vi.stubGlobal("scrollTo", vi.fn());
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale("ru");
  state.v2Catalog.mockResolvedValue({ items: [] });
  as(FULL);
  state.definitions.mockResolvedValue({ items: [
    def(), def({ version: 2, status: "draft", published_at: null }),
    def({ report_key: "qa.draft", name: "Черновик", status: "draft", assignment_count: 0, package_count: 0 }),
    def({ report_key: "ad.users.v2", name: "Пользователи AD", code_defined: true, assignment_count: 3, package_count: 0 }),
    def({ report_key: "qa.empty", name: "Без назначений", assignment_count: 0, package_count: 0 }),
  ] });
  state.detail.mockImplementation(async (key: string) => ({
    api_version: "v4", report_key: key, code_defined: key === "ad.users.v2", assignment_count: 2, package_count: 1,
    versions: key === "qa.vpn" ? [version({ version: 2, status: "draft", published_at: null }), version()] : [version({ report_key: key, status: "draft", published_at: null })],
  }));
  state.datasets.mockResolvedValue({ items: [dataset, { ...dataset, dataset_key: "never.runs", name: "Не выполняется", executable: false }] });
  state.preview.mockResolvedValue({ status: "accepted", required_capabilities: ["field.identity_basic", "field.security"], missing_capabilities: ["field.security"], required_field_categories: [], sample_state: "not_requested_no_data_disclosure", sample_rows: [] });
  state.summary.mockRejectedValue(new ApiResponseError(404, "not_found"));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.clearAllMocks(); });

it("groups versions into one registry row and counts only published reports without any grants", async () => {
  await mount();
  const table = await screen.findByRole("table", { name: "Реестр отчётов" });
  const rows = within(table).getAllByRole("row").slice(1);
  expect(rows).toHaveLength(4);
  const vpn = rows.find((row) => within(row).queryByText("VPN-доступ"))!;
  expect(within(vpn).queryByText("qa.vpn")).toBeNull();
  expect(within(vpn).getByText("черновик v2")).toBeTruthy();
  for (const label of ["Источник", "Назначений", "Видимость", "Версия"]) {
    expect(within(table).queryByRole("columnheader", { name: label })).toBeNull();
  }
  const details = within(vpn).getByText("Подробнее").closest("details")!;
  expect(details.open).toBe(false);
  await userEvent.click(within(vpn).getByText("Подробнее"));
  expect(details.open).toBe(true);
  expect(screen.queryByRole("complementary")).toBeNull();
  expect(within(vpn).getByText("Скрыт")).toBeTruthy();
  expect(within(vpn).getByText("конструктор")).toBeTruthy();
  expect(vpn.textContent).toContain("3");
  expect(within(rows.find((row) => within(row).queryByText("Пользователи AD"))!).getByText("код")).toBeTruthy();
  const unassigned = screen.getByText("Отчёты конструктора без назначений").closest(".sli-ds-metric")!;
  expect(unassigned.textContent).toContain("1");
  expect(unassigned.textContent).toContain("Владелец платформы имеет доступ и без них.");
  await userEvent.click(screen.getByRole("button", { name: /^черновик · 1/ }));
  expect(within(screen.getByRole("table", { name: "Реестр отчётов" })).getAllByRole("row")).toHaveLength(2);
});

it("opens a code-defined report as read-only information with a link to the report", async () => {
  await mount();
  await userEvent.click(await screen.findByText("Пользователи AD"));
  expect(await screen.findByText("Отчёт определён в коде")).toBeTruthy();
  expect(screen.queryByRole("tab", { name: "Предпросмотр" })).toBeNull();
  expect(screen.queryByRole("tab", { name: "Публикация" })).toBeNull();
  expect(screen.getByRole("link", { name: "Открыть отчёт" }).getAttribute("href")).toContain("/report/ad.users.v2");
  expect(screen.queryByRole("button", { name: "Сохранить черновик" })).toBeNull();
});

it("excludes code-defined workstation reports and package grants from the unassigned builder KPI", async () => {
  state.definitions.mockResolvedValue({ items: [
    ...["logons", "processes", "usb", "protection"].map((family) => def({
      report_key: `workstations.${family}`, name: `Fixture ${family}`, code_defined: true, assignment_count: 0, package_count: 0,
    })),
    def({ report_key: "fixture.unassigned", assignment_count: 0, package_count: 0 }),
    def({ report_key: "fixture.packaged", name: "Packaged report", assignment_count: 0, package_count: 1 }),
    def({ report_key: "fixture.draft", name: "Draft report", status: "draft", assignment_count: 0, package_count: 0 }),
  ] });
  await mount();
  const metric = (await screen.findByText("Отчёты конструктора без назначений")).closest(".sli-ds-metric")!;
  expect(metric.querySelector(".sli-ds-metric__value")?.textContent).toBe("1");
});

it.each(["ru", "en"] as Locale[])("keeps one report per displayed title and reveals retired and duplicate reports with one toggle (%s)", async (locale) => {
  setLocale(locale);
  const title = locale === "ru" ? "Компьютеры" : "Computers";
  state.v2Catalog.mockResolvedValue({ items: [{ key: "ad.computers.v2", title }] });
  state.definitions.mockResolvedValue({ items: [
    def({ report_key: "ad.computers.v2", name: "Legacy computers", version: 2, published_at: "2026-09-01T09:00:00Z" }),
    def({ report_key: "computers.current", name: title, version: 4, published_at: "2026-10-01T09:00:00Z" }),
    // Более новый черновик не вытесняет опубликованный отчёт с тем же названием.
    def({ report_key: "computers.draft", name: title, version: 9, status: "draft", published_at: null, created_at: "2026-10-20T09:00:00Z" }),
    def({ report_key: "computers.retired", name: title, version: 10, status: "retired", published_at: "2026-10-21T09:00:00Z" }),
    def({ report_key: "retired.only", name: "Retired only", status: "retired" }),
    def({ report_key: "computers.current", name: title, version: 5, status: "draft", published_at: null }),
    def({ report_key: "computers.current", name: title, version: 3, status: "retired" }),
  ] });
  const user = userEvent.setup();
  await mount();
  const table = await screen.findByRole("table", { name: t("studio.registry.caption") });
  await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(2));
  expect(within(table).getAllByText(title)).toHaveLength(1);
  expect(within(table).getByText(t("studio.row.pendingDraft", { version: 5 }))).toBeTruthy();
  expect(screen.queryByText("Retired only")).toBeNull();
  expect(screen.queryByRole("table", { name: t("studio.archive.caption") })).toBeNull();
  const total = screen.getByText(t("studio.metrics.total")).closest(".sli-ds-metric")!;
  expect(total.querySelector(".sli-ds-metric__value")?.textContent).toBe("1");
  await user.click(screen.getByRole("button", { name: t("studio.archive.show"), expanded: false }));
  const archive = screen.getByRole("table", { name: t("studio.archive.caption") });
  expect(within(archive).getAllByRole("row")).toHaveLength(5);
  expect(within(archive).getAllByText(title)).toHaveLength(3);
  expect(within(archive).getByText("Retired only")).toBeTruthy();
  expect(within(table).getAllByText(title)).toHaveLength(1);
  // Свёрнутый отчёт по-прежнему можно открыть и закрыть без потери реестра.
  await user.click(within(archive).getByText("Retired only"));
  expect(await screen.findByRole("complementary", { name: "Retired only" })).toBeTruthy();
  await user.click(screen.getByRole("button", { name: t("studio.close") }));
  await user.click(screen.getByRole("button", { name: t("studio.archive.hide"), expanded: true }));
  expect(screen.queryByRole("table", { name: t("studio.archive.caption") })).toBeNull();
});

it("uses the newest version when duplicate titles have no published report", async () => {
  state.definitions.mockResolvedValue({ items: [
    def({ report_key: "draft.old", name: "Draft title", version: 4, status: "draft", published_at: null, created_at: "2026-09-01T09:00:00Z" }),
    def({ report_key: "draft.new", name: "Draft title", version: 2, status: "draft", published_at: null, created_at: "2026-10-01T09:00:00Z" }),
  ] });
  await mount();
  const table = await screen.findByRole("table", { name: t("studio.registry.caption") });
  expect(within(table).getAllByRole("row")).toHaveLength(2);
  await userEvent.click(within(table).getByText("Подробнее", { selector: "summary" }));
  expect(within(table).getByText("v2")).toBeTruthy();
  expect(within(table).queryByText("v4")).toBeNull();
});

it.each(["ru", "en"] as Locale[])("shows actual menu membership independently of catalogue visibility (%s)", async (locale) => {
  setLocale(locale);
  state.v2Catalog.mockResolvedValue({ items: [], navigation: {
    enabled_plugins: ["sli.ad"], sections: [{ id: "reports", title: "studio.title", groups: [{ id: "reports", entries: [
      { id: "users-report", label: "shell.nav.users-report", path: "/report/ad.users.v2", icon: "users", plugin_id: "sli.ad", reports: ["ad.users.v2"] },
      { id: "vpn", label: "studio.col.name", path: "/reports/qa.vpn", icon: "report", always: true },
    ] }] }],
  } });
  state.access = { capabilities: FULL, reports: [{ report_key: "ad.users.v2", allowed: true }] };
  state.definitions.mockResolvedValue({ items: [
    def({ discoverable: true }),
    def({ report_key: "ad.users.v2", name: "Users in menu", discoverable: false }),
    def({ report_key: "catalog.only", name: "Catalogue only", discoverable: true }),
  ] });
  await mount();
  const table = await screen.findByRole("table", { name: t("studio.registry.caption") });
  const vpn = within(table).getByText("VPN-доступ").closest("tr")!;
  const users = within(table).getByText("Users in menu").closest("tr")!;
  const catalogOnly = within(table).getByText("Catalogue only").closest("tr")!;
  expect(within(users).getByText(t("studio.menu.yes"))).toBeTruthy();
  expect(within(vpn).getByText(t("studio.menu.no"))).toBeTruthy();
  expect(within(catalogOnly).getByText(t("studio.menu.no"))).toBeTruthy();
});

it.each(["ru", "en"] as Locale[])("omits zero metric tiles while retaining a positive count (%s)", async (locale) => {
  setLocale(locale);
  state.definitions.mockResolvedValue({ items: [def()] });
  await mount();
  await screen.findByRole("table");
  const metrics = screen.getByRole("region", { name: t("studio.metrics.aria") });
  expect(within(metrics).getByText(t("studio.metrics.total"))).toBeTruthy();
  expect(within(metrics).getByText(t("studio.metrics.published"))).toBeTruthy();
  expect(within(metrics).queryByText(t("studio.metrics.drafts"))).toBeNull();
  expect(within(metrics).queryByText(t("studio.metrics.unassigned"))).toBeNull();
  expect(screen.queryByRole("button", { name: t("studio.archive.show") })).toBeNull();
});

// Полный сценарий с вводом и повторными рендерами требует запаса под нагрузкой.
it("creates a report: executable datasets only, preview with rows, save a draft, then publish after confirmation", async () => {
  state.preview.mockImplementation(async (body: Record<string, unknown>) => ({
    status: "gated", required_capabilities: ["field.identity_basic"], missing_capabilities: [], required_field_categories: [],
    ...(body.with_rows ? { sample_state: "rows", sample_columns: [{ key: "account", label: "Учётная запись" }], sample_rows: [{ account: "ivanov" }] } : {}),
  }));
  const saved: Array<Record<string, unknown>> = [];
  const baseDefinitions = (await state.definitions()).items as Array<Record<string, unknown>>;
  state.definitions.mockImplementation(async () => ({ items: [...baseDefinitions, ...saved] }));
  state.publish.mockImplementation(async (body: Record<string, unknown>) => {
    saved.push(def({ report_key: body.report_key, name: body.name, status: body.status, assignment_count: 0, package_count: 0 }));
    return { item: { report_key: body.report_key, version: 1, status: body.status } };
  });
  state.detail.mockImplementation(async (key: string) => ({ api_version: "v4", report_key: key, code_defined: false, assignment_count: 0, package_count: 0, versions: [version({ report_key: key, status: "draft", published_at: null })] }));
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByRole("button", { name: "Создать отчёт" }));
  const dataset = await screen.findByLabelText("Набор данных");
  expect(within(dataset).queryByText(/Не выполняется/)).toBeNull();
  await user.selectOptions(dataset, "ad.accounts.vpn");
  await user.type(screen.getByLabelText("Ключ отчёта"), "qa.studio.one");
  await user.type(screen.getByLabelText("Название"), "Студия 1");
  await user.type(screen.getByLabelText("Владелец"), "ИБ");
  await user.type(screen.getByLabelText("Назначение отчёта"), "Проверка студии");
  // фильтры предлагают только выполняемые ключи, сортировка — только выполняемые поля
  await user.click(screen.getByRole("button", { name: "Добавить фильтр" }));
  const filterField = screen.getByLabelText("Поле фильтра");
  expect(within(filterField).queryByText("unsupported")).toBeNull();
  await user.selectOptions(filterField, "state");
  await user.type(screen.getByLabelText("Значение"), "enabled");
  await user.click(screen.getByRole("button", { name: "Добавить сортировку" }));
  expect(within(screen.getByLabelText("Поле сортировки")).queryByText("Состояние")).toBeNull();

  // без проверки сохранить нельзя
  await user.click(screen.getByRole("tab", { name: "Публикация" }));
  expect((screen.getByRole("button", { name: "Сохранить черновик" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByRole("note").textContent).toContain("Сначала проверьте");

  await user.click(screen.getByRole("tab", { name: "Предпросмотр" }));
  expect(await screen.findByText("ivanov")).toBeTruthy();
  expect(state.preview).toHaveBeenCalledWith(expect.objectContaining({ with_rows: true, filters: [{ field: "state", op: "eq", value: "enabled" }] }));

  await user.click(screen.getByRole("tab", { name: "Публикация" }));
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(state.publish).toHaveBeenCalledWith(expect.objectContaining({ report_key: "qa.studio.one", status: "draft", dataset_key: "ad.accounts.vpn" })));
  expect(await screen.findByRole("tab", { name: "Доступ" })).toBeTruthy();

  // публикация идёт через диалог, который объясняет приватность по умолчанию
  await user.click(screen.getByRole("button", { name: "Опубликовать" }));
  expect(await screen.findByText(/остаётся приватным/)).toBeTruthy();
  expect(state.publish).toHaveBeenCalledTimes(1);
  await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: t("studio.confirm.cancel") }));
  expect(state.promote).not.toHaveBeenCalled();
  expect(state.visibility).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Опубликовать" }));
  // нетронутый сохранённый черновик выпускается, а не копируется новой версией
  state.promote.mockResolvedValue({ item: {} });
  await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Опубликовать" }));
  await waitFor(() => expect(state.promote).toHaveBeenCalledWith("qa.studio.one", 1));
  expect(state.publish).toHaveBeenCalledTimes(1);
}, 15_000);

it("explains why saving is blocked without the publish capability and why assignment is blocked without reports.assign", async () => {
  as(["reports.design"]);
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByText("VPN-доступ"));
  await user.click(await screen.findByRole("tab", { name: "Публикация" }));
  expect((screen.getByRole("button", { name: "Опубликовать" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getAllByRole("note")[0].textContent).toContain("Публикация отчётов");
  await user.click(screen.getByRole("tab", { name: "Доступ" }));
  expect((screen.getByRole("button", { name: "Назначить доступ" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(/reports\.assign/)).toBeTruthy();
});

it("shows the catalogue with the access tab only for a user who can only assign", async () => {
  as(["reports.assign"]);
  state.catalog.mockResolvedValue({ items: [{ report_key: "qa.vpn", version: 1, name: "VPN-доступ", owner: "ИБ", purpose: "", dataset_key: "ad.accounts.vpn", dataset_version: 1, sensitivity: "restricted", status: "published", discoverable: true, requestable: false }] });
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByText("VPN-доступ"));
  expect(await screen.findByRole("tab", { name: "Доступ" })).toBeTruthy();
  expect(screen.queryByRole("tab", { name: "Определение" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Создать отчёт" })).toBeNull();
  expect(state.definitions).not.toHaveBeenCalled();
  expect((screen.getByRole("button", { name: "Назначить мне" }) as HTMLButtonElement).disabled).toBe(false);
});

it("denies the page without any report capability and makes no request", async () => {
  as(["reports.view"]);
  await mount();
  expect((await screen.findByRole("alert")).textContent).toContain("студией отчётов");
  expect(state.definitions).not.toHaveBeenCalled();
});

it("explains the security re-approval refusal in plain words and maps backend codes", async () => {
  state.preview.mockResolvedValue({ status: "accepted", required_capabilities: [], missing_capabilities: [], required_field_categories: [] });
  state.publish.mockRejectedValue(new ApiResponseError(400, "report_security_reapproval_required"));
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByText("VPN-доступ"));
  await user.click(await screen.findByRole("tab", { name: "Определение" }));
  await user.click(await screen.findByRole("button", { name: "Проверить определение" }));
  expect(await screen.findByText("Определение принято")).toBeTruthy();
  await user.click(screen.getByRole("tab", { name: "Публикация" }));
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  expect((await screen.findByRole("alert")).textContent).toContain("повторное согласование");
});

it("releases a draft after confirmation and changes visibility of the published version", async () => {
  state.promote.mockResolvedValue({ item: {} });
  state.visibility.mockResolvedValue({ item: {} });
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByText("VPN-доступ"));
  await user.click(await screen.findByRole("tab", { name: "Публикация" }));
  await user.click(await screen.findByRole("button", { name: "Выпустить черновик" }));
  expect(state.promote).not.toHaveBeenCalled();
  const dialog = await screen.findByRole("dialog");
  await user.click(within(dialog).getByRole("button", { name: "Выпустить черновик" }));
  await waitFor(() => expect(state.promote).toHaveBeenCalledWith("qa.vpn", 2));
  expect((screen.getByLabelText("Можно запросить") as HTMLInputElement).disabled).toBe(true);
  await user.click(screen.getByLabelText("В каталоге"));
  expect((screen.getByLabelText("Можно запросить") as HTMLInputElement).disabled).toBe(false);
  await user.click(screen.getByRole("button", { name: "Применить видимость" }));
  await waitFor(() => expect(state.visibility).toHaveBeenCalledWith("qa.vpn", { discoverable: true, requestable: false }));
});

it("shows what the server rejected in human words", async () => {
  state.preview.mockRejectedValue(new ApiResponseError(400, "report_filter_not_executable"));
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByText("VPN-доступ"));
  await user.click(await screen.findByRole("tab", { name: "Определение" }));
  await user.click(await screen.findByRole("button", { name: "Проверить определение" }));
  expect((await screen.findByRole("alert")).textContent).toContain("пока не умеет фильтровать");
});

it("lists who has access and offers the shortcut for the current user once the server provides the summary", async () => {
  state.summary.mockResolvedValue({ assignments: [{ id: 1, username: "petrov", allowed_actions: ["view"] }], packages: [{ package_key: "sec", name: "Пакет ИБ" }], pending_requests: 2 });
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByText("VPN-доступ"));
  await user.click(await screen.findByRole("tab", { name: "Доступ" }));
  expect(await screen.findByText(/petrov/)).toBeTruthy();
  expect(screen.getByText("Пакет ИБ")).toBeTruthy();
  expect(screen.getByText("Заявок на рассмотрении: 2")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Открыть отчёт" }).getAttribute("href")).toContain("/reports/qa.vpn");
  expect((screen.getByRole("button", { name: "Назначить мне" }) as HTMLButtonElement).disabled).toBe(false);
});

it("keeps the retired admin routes as redirects to the studio", () => {
  const source = readFileSync(existsSync("src/product-main.tsx") ? "src/product-main.tsx" : "frontend/src/product-main.tsx", "utf8");
  for (const path of ["/report-management", "/report-editor", "/report-builder"]) {
    expect(source).toContain(`retiredRedirect("${path}", "/report-studio")`);
  }
  expect(source).toContain('path: "/report-studio", component: ReportStudioPage');
});

it("uses v2 catalog titles for code reports in both the registry and detail", async () => {
  state.v2Catalog.mockResolvedValue({ items: [{ key: "vpn.accounts", title: "VPN catalog title" }] });
  state.definitions.mockResolvedValue({ items: [def({ report_key: "vpn.audit", name: "Legacy VPN", code_defined: true })] });
  state.detail.mockResolvedValue({ report_key: "vpn.audit", code_defined: true, versions: [version({ report_key: "vpn.audit" })] });
  await mount();
  await userEvent.click(await screen.findByText("VPN catalog title"));
  expect(await screen.findByRole("heading", { name: "VPN catalog title" })).toBeTruthy();
  expect(screen.getAllByText("vpn.audit").length).toBeGreaterThan(0);
  expect(screen.queryByText("Legacy VPN")).toBeNull();
});


it.each(["loading", "error"])("opens creation while the registry is %s", async (registryState) => {
  if (registryState === "loading") state.definitions.mockImplementation(() => new Promise(() => {}));
  else state.definitions.mockRejectedValue(new Error("Registry unavailable"));
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByRole("button", { name: t("studio.create") }));
  const detail = await screen.findByRole("complementary", { name: t("studio.new.title") });
  expect(await within(detail).findByLabelText(t("studio.def.dataset"))).toBeTruthy();
  expect(within(detail).getByRole("tab", { name: t("studio.tab.definition") }).getAttribute("aria-selected")).toBe("true");
  expect(screen.queryByText(t("studio.registry.empty.title"))).toBeNull();
  expect(state.publish).not.toHaveBeenCalled();
  expect(state.promote).not.toHaveBeenCalled();
  await user.click(within(detail).getByRole("button", { name: t("studio.close") }));
  expect(screen.queryByRole("complementary")).toBeNull();
});

it("opens creation from an empty registry and resets only after close and reopen", async () => {
  state.definitions.mockResolvedValue({ items: [] });
  const user = userEvent.setup();
  await mount();
  await screen.findByText(t("studio.registry.empty.title"));
  await user.click(screen.getAllByRole("button", { name: t("studio.create") })[1]);
  const name = await screen.findByLabelText(t("studio.def.name"));
  await user.type(name, "Unsaved report");
  await user.click(screen.getAllByRole("button", { name: t("studio.create") })[0]);
  expect((screen.getByLabelText(t("studio.def.name")) as HTMLInputElement).value).toBe("Unsaved report");
  await user.click(screen.getByRole("button", { name: t("studio.close") }));
  expect(screen.queryByRole("complementary")).toBeNull();
  await user.click(screen.getAllByRole("button", { name: t("studio.create") })[0]);
  expect((await screen.findByLabelText(t("studio.def.name")) as HTMLInputElement).value).toBe("");
  expect(state.publish).not.toHaveBeenCalled();
});

it("keeps the creation card closable while datasets load or fail", async () => {
  state.datasets.mockImplementation(() => new Promise(() => {}));
  const user = userEvent.setup();
  await mount();
  await screen.findByRole("table");
  await user.click(screen.getByRole("button", { name: t("studio.create") }));
  const loading = await screen.findByRole("complementary", { name: t("studio.new.title") });
  expect(within(loading).queryByLabelText(t("studio.def.dataset"))).toBeNull();
  await user.click(within(loading).getByRole("button", { name: t("studio.close") }));
  expect(screen.queryByRole("complementary")).toBeNull();
  cleanup();
  state.datasets.mockRejectedValue(new Error("Datasets unavailable"));
  await mount();
  await screen.findByRole("table");
  await user.click(screen.getByRole("button", { name: t("studio.create") }));
  const failed = await screen.findByRole("complementary", { name: t("studio.new.title") });
  expect(await within(failed).findByText("Datasets unavailable")).toBeTruthy();
  await user.click(within(failed).getByRole("button", { name: t("studio.close") }));
  expect(screen.queryByRole("complementary")).toBeNull();
});

it("explains an empty executable dataset list without enabling save or publish", async () => {
  state.datasets.mockResolvedValue({ items: [{ ...dataset, executable: false }] });
  const user = userEvent.setup();
  await mount();
  await screen.findByRole("table");
  await user.click(screen.getByRole("button", { name: t("studio.create") }));
  expect(await screen.findByText(t("studio.def.dataset.none.title"))).toBeTruthy();
  await user.click(screen.getByRole("tab", { name: t("studio.tab.publication") }));
  expect((screen.getByRole("button", { name: "Сохранить черновик" }) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole("button", { name: "Опубликовать" }) as HTMLButtonElement).disabled).toBe(true);
  expect(state.publish).not.toHaveBeenCalled();
});

it.each(["ru", "en"] as Locale[])("shows catalog titles and custom names without keys in either registry layout (%s)", async (locale) => {
  setLocale(locale);
  const title = locale === "ru" ? "Учётные записи VPN" : "VPN accounts";
  state.v2Catalog.mockResolvedValue({ items: [{ key: "vpn.accounts", title }] });
  state.definitions.mockResolvedValue({ items: [
    def({ report_key: "vpn.audit", name: "Legacy VPN", code_defined: true }),
    def({ report_key: "custom.report", name: "Custom report" }),
  ] });
  const user = userEvent.setup();
  await mount();
  await screen.findByText(title);
  const table = screen.getByRole("table", { name: t("studio.registry.caption") });
  expect(within(table).getByText("Custom report")).toBeTruthy();
  for (const key of ["vpn.audit", "custom.report"]) expect(within(table).queryByText(key)).toBeNull();
  await user.click(within(table).getByText("Custom report"));
  const detail = await screen.findByRole("complementary", { name: "Custom report" });
  expect(within(detail).getByText("custom.report")).toBeTruthy();
  const compact = screen.getByRole("table", { name: t("studio.registry.caption") });
  expect(within(compact).getByText(title)).toBeTruthy();
  expect(within(compact).getByText("Custom report")).toBeTruthy();
  for (const key of ["vpn.audit", "custom.report"]) expect(within(compact).queryByText(key)).toBeNull();
});

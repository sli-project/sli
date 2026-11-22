// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import type { SetupDomain, SetupDomainController } from "../../api/client";
import type { NavigationRegistryDto, ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import registry from "../../../../config/navigation_v3.json";
import { buildNavigation, globalSearchTarget, navigationRedirect, preserveNavigationView } from "../../app/navigation";
import { legacyLogonsHref, withReturnTo } from "../../app/report-v2/legacy";
import { localeRuntime, setLocale } from "../../i18n";
import { PluginReportPage } from "../routes";
import { DomainControllersStep } from "./DomainControllersStep";

const state = vi.hoisted(() => ({ capabilities: ["access.manage"], addDc: vi.fn(), toggleDc: vi.fn() }));
vi.mock("../../app/App", async (original) => ({
  ...await original<typeof import("../../app/App")>(),
  useEffectiveAccess: () => ({ capabilities: state.capabilities, reports: [] }),
}));
vi.mock("../../api/client", async (original) => {
  const actual = await original<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api,
    addSetupDomainController: (body: unknown) => state.addDc(body),
    setSetupDomainControllerEnabled: (host: string, enabled: boolean) => state.toggleDc(host, enabled),
  } };
});

// Literal expectations taken from the pre-transfer navigation and setup source.
// Do not derive them from the new page registry or compare two re-exports.
const captions = [
  ["ad.infrastructure", "Состояние Active Directory"],
  ["ad.users.v2", "Пользователи"],
  ["ad.computers.v6", "Компьютеры"],
  ["ad.computer-logons", "Входы на компьютеры"],
  ["ad.new-logon-pairs", "Новые пары пользователь — компьютер"],
] as const;

function reportDefinition(key: string, title: string): ReportDefinitionDto {
  const computerInventory = key === "ad.computers.v6";
  return { key, title, section: "reports/identity", description: title, archetype: "list",
    params: [{ key: "domain", label: "Домен", kind: "domain", required: true }],
    columns: computerInventory
      ? [{ key: "display_name", label: "Компьютер", kind: "text", path: "display_name" }]
      : [{ key: "name", label: "Объект", kind: "text", path: "name", link: "/app/objects/ad_user/{id}" }],
    views: computerInventory
      ? [{ kind: "table", key: "checks", source: "checks" }, { kind: "table", key: "computers", title: "Все компьютеры" }]
      : [{ kind: "table", key: "table" }],
    row_key: "id", detail: "fields", export: true,
    limits: { default: 100, max: 500 }, presets: [], row_links: [],
    filter_options: { domain: [{ value: "1", label: "synthetic.test" }] },
  };
}

function reportResult(key: string): ReportResultDto {
  return { contract_id: "sli.report-result.v2", report_key: key, state: "ok",
    items: [{ id: 7, name: "synthetic-object", display_name: "synthetic-object" }], filtered_count: 1, has_more: false, next_cursor: null,
    metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {},
  };
}

function mount(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}>{node}</QueryClientProvider>) };
}

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  state.capabilities = ["access.manage"];
});
afterEach(() => { cleanup(); setLocale("ru"); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.clearAllMocks(); });

it("preserves the AD section, exact captions, URLs and independent GPO ownership", () => {
  const reports = new Set(["ad.state", "ad.users.v2", "ad.computers.v6", "ad.computer-logons", "ad.gpo.v2"]);
  const nav = buildNavigation({ reports, capabilities: new Set(["objects.view", "access.manage"]) }, registry as NavigationRegistryDto);
  const ad = nav.find((section) => section.id === "active-directory")!;
  expect(ad.title).toBe("Active Directory");
  expect(ad.groups.flatMap((group) => group.items.map(({ label, path }) => [label, path]))).toEqual([
    ["Состояние AD", "/report/ad.infrastructure"], ["Пользователи", "/report/ad.users.v2"],
    ["Компьютеры", "/report/ad.computers.v6"],
  ]);
  expect(nav.find((section) => section.id === "group-policies")?.title).toBe("Групповые политики");
  expect(nav.find((section) => section.id === "group-policies")?.groups.flatMap((group) => group.items.map(({ label, path }) => [label, path])))
    .toEqual([["Групповые политики", "/report/ad.gpo.v2"]]);
  const core = buildNavigation({ reports, capabilities: new Set(["objects.view", "access.manage"]) },
    { ...registry, enabled_plugins: ["sli.gpo"] } as NavigationRegistryDto);
  expect(core.some((section) => section.id === "active-directory")).toBe(false);
  const corePaths = core.flatMap((section) => section.groups.flatMap((group) => group.items.map((item) => item.path)));
  // The status page is its own menu item, independent of AD plugin ownership.
  expect(corePaths).toEqual(expect.arrayContaining(["/admin/status", "/agents", "/access", "/report/ad.gpo.v2"]));
  expect(corePaths).not.toContain("/platform-settings");
  expect(globalSearchTarget("synthetic-object")).toEqual({ to: "/report/events.journal", search: { q: "synthetic-object" } });
});

it("keeps the logon alias, workspace query and back link", () => {
  expect(navigationRedirect("/report/ad.computer-logons", { domain: "1", user: "synthetic-user", tab: "table" }))
    .toEqual({ to: "/report/ad.computers.v6", search: { domain: "1", user: "synthetic-user", tab: "table", nav_view: "logons" }, replace: true });
  expect(legacyLogonsHref("?q=synthetic-host&user_q=synthetic-user&with_logons=true"))
    .toBe("/app/report/ad.computer-logons?q=synthetic-host&user=synthetic-user&with_logons=yes");
  expect(preserveNavigationView(new URLSearchParams("domain=1&tab=changes"), "?nav_view=logons").toString())
    .toBe("domain=1&tab=changes&nav_view=logons");
  expect(withReturnTo("/app/objects/ad_user/7", "/app/report/ad.infrastructure?domain=1&tab=changes"))
    .toBe("/app/objects/ad_user/7?return_to=%2Fapp%2Freport%2Fad.infrastructure%3Fdomain%3D1%26tab%3Dchanges");
});

it.each(captions)("renders bundled %s with the same caption, rows, export and query for either pilot flag", async (key, title) => {
  const requests: string[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input); requests.push(url);
    return new Response(JSON.stringify(url.includes("/data?") ? reportResult(key) : reportDefinition(key, title)));
  }));
  window.history.replaceState(null, "", `/app/report/${key}?domain=1&nav_view=logons`);
  const { rerender, client } = mount(<PluginReportPage reportKey={key} pilotEnabled={false}/>);
  const computerInventory = key === "ad.computers.v6";
  const caption = computerInventory ? "Все компьютеры" : title;
  const table = await screen.findByRole("table", { name: caption });
  expect(within(table).getByRole("columnheader", { name: computerInventory ? "Компьютер" : key === "ad.users.v2" ? "Учётная запись / ФИО" : "Объект" })).toBeTruthy();
  if (computerInventory) {
    expect(screen.getByRole("heading", { level: 1, name: title })).toBeTruthy();
    expect(screen.getByRole("tab", { name: caption, selected: true })).toBeTruthy();
    expect(within(table).getByRole("button", { name: "synthetic-object" })).toBeTruthy();
    expect(requests.some((url) => new URL(url, "http://example.test").searchParams.get("tab") === "computers")).toBe(true);
  } else if (key === "ad.users.v2") {
    fireEvent.click(within(table).getByRole("button", { name: "synthetic-object" }));
    expect(await screen.findByRole("dialog")).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
  } else {
    const link = within(table).getByRole("link", { name: "synthetic-object" });
    const back = new URL(link.getAttribute("href")!, "http://synthetic.test").searchParams.get("return_to");
    expect(back).toContain(`/app/report/${key}?`);
    expect(back).toContain("domain=1");
    expect(back).toContain("nav_view=logons");
  }
  expect(screen.getByRole("link", { name: "Экспорт CSV" }).getAttribute("href"))
    .toContain(`/api/v2/reports/${key}/export.csv?`);
  const before = table.outerHTML;
  rerender(<QueryClientProvider client={client}><PluginReportPage reportKey={key} pilotEnabled/></QueryClientProvider>);
  expect(screen.getByRole("table", { name: caption }).outerHTML).toBe(before);
  expect(requests.every((url) => url === `/api/v2/reports/${key}` || url.startsWith(`/api/v2/reports/${key}/`))).toBe(true);
});

it("keeps server denial on the bundled AD route without loading external JS", async () => {
  const requests: string[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input); requests.push(url);
    return url.includes("/api/v2/reports/")
      ? new Response(JSON.stringify({ error: "forbidden" }), { status: 403 })
      : new Response(JSON.stringify({ items: [] }));
  }));
  mount(<PluginReportPage reportKey="ad.users.v2" pilotEnabled/>);
  expect(await screen.findByRole("link", { name: "Мой доступ" })).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByRole("link", { name: "Экспорт CSV" })).toBeNull();
  expect(requests.some((url) => url.includes("/plugins/"))).toBe(false);
});

it("preserves the AD history detail and export permission", async () => {
  const key = "ad.infrastructure";
  const definition = { ...reportDefinition(key, "Состояние Active Directory"), export: false,
    views: [{ kind: "table" as const, key: "table", title: "Состояние AD" },
      { kind: "table" as const, key: "changes", title: "Изменения AD" }],
  };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify(
    String(input).includes("/data?") ? reportResult(key) : definition,
  ))));
  window.history.replaceState(null, "", `/app/report/${key}?domain=1&tab=changes`);
  mount(<PluginReportPage reportKey={key} pilotEnabled/>);
  const table = await screen.findByRole("table", { name: "Изменения AD" });
  expect(screen.queryByRole("link", { name: "Экспорт CSV" })).toBeNull();
  fireEvent.click(within(table).getByText("synthetic-object").closest("tr")!);
  expect(await screen.findByRole("dialog")).toBeTruthy();
  expect(new URLSearchParams(window.location.search).get("tab")).toBe("changes");
});

const domains: SetupDomain[] = [{ fqdn: "synthetic.test", netbios_name: "SYNTHETIC", server_count: 1 }];
const controller: SetupDomainController = { hostname: "SYNTHETIC-DC", connect_address: "dc.synthetic.test", domain: "synthetic.test", enabled: true, source: "db", dns_readback: false };

it("keeps DC captions and read-only rows for readers without access.manage", () => {
  state.capabilities = ["reports.view"];
  mount(<DomainControllersStep controllers={[controller]} domains={domains}/>);
  const table = screen.getByRole("table", { name: "Контроллеры домена" });
  expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent))
    .toEqual(["Контроллер", "Домен", "Источник", "Проверка DNS", "Состояние"]);
  expect(within(table).getAllByRole("cell").map((cell) => cell.textContent))
    .toEqual(["dc.synthetic.test", "synthetic.test", "база", "нет", "включён"]);
  expect(screen.queryByRole("button")).toBeNull();
  expect(screen.queryByLabelText("DNS-имя контроллера (FQDN)")).toBeNull();
});

it("adds and toggles stored DCs, refreshes setup and leaves file DCs read-only", async () => {
  state.addDc.mockResolvedValue({ item: controller });
  state.toggleDc.mockResolvedValue({ item: controller });
  const { client } = mount(<DomainControllersStep controllers={[controller, { ...controller, hostname: "SYNTHETIC-FILE", source: "file" },
    { ...controller, hostname: "SYNTHETIC-OFF", enabled: false }]} domains={domains}/>);
  const refresh = vi.spyOn(client, "invalidateQueries");
  fireEvent.change(screen.getByLabelText("DNS-имя контроллера (FQDN)"), { target: { value: " new.synthetic.test " } });
  fireEvent.change(screen.getByLabelText("Домен"), { target: { value: "synthetic.test" } });
  fireEvent.click(screen.getByRole("button", { name: "Добавить контроллер" }));
  expect(await screen.findByText("Контроллер добавлен.")).toBeTruthy();
  expect(state.addDc).toHaveBeenCalledWith({ hostname: "new.synthetic.test", domain: "synthetic.test" });
  expect((screen.getByLabelText("DNS-имя контроллера (FQDN)") as HTMLInputElement).value).toBe("");
  fireEvent.click(screen.getByRole("button", { name: "Отключить" }));
  await waitFor(() => expect(state.toggleDc).toHaveBeenCalledWith("SYNTHETIC-DC", false));
  await waitFor(() => expect((screen.getByRole("button", { name: "Включить" }) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(screen.getByRole("button", { name: "Включить" }));
  await waitFor(() => expect(state.toggleDc).toHaveBeenCalledWith("SYNTHETIC-OFF", true));
  await waitFor(() => expect(refresh).toHaveBeenCalledTimes(3));
  expect(refresh).toHaveBeenLastCalledWith({ queryKey: ["setup-status"] });
  expect(screen.getAllByRole("button", { name: /Отключить|Включить/ })).toHaveLength(2);
});

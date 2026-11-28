// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider, useLocation } from "@tanstack/react-router";
import fixture from "../../../config/navigation_v3.json";
import workstationSettings from "../../../config/plugin_settings_schema/sli.workstations.settings.json";
import workspaceDeclarations from "../../../server-dotnet/src/Sli.Server/Workspace/declarations.json";
import type { AgentCollectionHealth } from "../api/client";
import type { SettingsSchema } from "../api/plugin-settings-types";
import type { NavigationEntryDto } from "../api/report-v2-types";

const registryState = vi.hoisted(() => ({ disabled: [] as string[], preview: false }));

const state = vi.hoisted(() => ({
  access: {
    subject: { username: "test.operator" },
    capabilities: ["problem.view"],
    reports: [{ report_key: "ad.users.v2", allowed: true }, { report_key: "vpn.audit", allowed: false }],
  },
}));

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      bootstrap: vi.fn().mockResolvedValue({ capabilities: [], principal: { username: "test.operator" } }),
      v4Access: vi.fn().mockImplementation(async () => state.access),
      reportsV2Catalog: vi.fn().mockImplementation(async () => ({
        contract_id: "sli.report-catalog.v2",
        items: workspaceDeclarations.reports.filter(({ key }) => key === "workstations.overview"),
        navigation: { ...fixture, modules_preview: registryState.preview,
          enabled_plugins: fixture.enabled_plugins.filter((id) => !registryState.disabled.includes(id)) },
      })),
      agentCollection: vi.fn(),
      plugins: vi.fn().mockResolvedValue({ items: [], can_manage: false }),
      pluginSettings: vi.fn(),
      setupStatus: vi.fn().mockResolvedValue({ sources: [], domains: [], domain_controllers: [] }),
      agents: vi.fn().mockResolvedValue({ items: [] }),
      logout: vi.fn().mockResolvedValue({}),
      v4Objects: vi.fn(),
    },
  };
});

import { api } from "../api/client";
import { AppShell, useTimeZone } from "./App";
import { useDateFormatters } from "../design-system/useDateFormatters";
import { navigationBeforeLoad, parseShellSearch, stringifyShellSearch } from "./navigation";
import { createAdminPlaceholderRoutes } from "./admin/navigation-pages";
import { PluginsRoute } from "./admin/plugins";
import { localeRuntime, setLocale } from "../i18n";

function TimeZoneProbe() {
  const { timeZone } = useTimeZone();
  const { formatDateTime } = useDateFormatters();
  return <output aria-label="Display time zone">{timeZone} · {formatDateTime("2026-11-14T00:00:00Z")}</output>;
}

async function renderShell(initialPath = "/", showTimeZone = false, waitForHeading = true) {
  const root = createRootRoute({ component: AppShell, beforeLoad: ({ location }) => navigationBeforeLoad(location) });
  const page = (path: string) => createRoute({ getParentRoute: () => root, path, component: () => <><h1 data-page-heading tabIndex={-1}>Главная страница</h1>{showTimeZone ? <TimeZoneProbe/> : null}</> });
  const search = createRoute({ getParentRoute: () => root, path: "/report/events.journal", component: () => {
    const { searchStr } = useLocation();
    return <><h1 data-page-heading>Журнал событий</h1><output aria-label="Journal query">{new URLSearchParams(searchStr).get("q")}</output></>;
  } });
  const plugins = createRoute({ getParentRoute: () => root, path: "/plugins", component: PluginsRoute });
  const entity = createRoute({ getParentRoute: () => root, path: "/entities/$entityId", component: () => {
    const { entityId } = entity.useParams();
    return <h1 data-page-heading>Object {entityId}</h1>;
  } });
  const routes = [page("/"), plugins, page("/access"), page("/access/$id"), page("/access-requests"), page("/admin"), page("/agents"), page("/settings"), page("/setup"), page("/project-readiness"), page("/platform-settings"), page("/report-studio"), page("/notifications"), page("/operations"), page("/reports"), page("/report/$reportKey"), page("/objects"), page("/search"), ...createAdminPlaceholderRoutes(root), search, entity];
  const router = createRouter({ routeTree: root.addChildren(routes), history: createMemoryHistory({ initialEntries: [initialPath] }), parseSearch: parseShellSearch, stringifySearch: stringifyShellSearch });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
  if (waitForHeading) await waitFor(() => expect(document.querySelector("[data-page-heading]")).not.toBeNull());
  return client;
}

window.scrollTo = () => undefined;
const adminAccess = {
  subject: { username: "admin.user" },
  capabilities: ["access.manage", "operations.view"],
  reports: [{ report_key: "ad.users.v2", allowed: true }],
};
const userAccess = state.access;
const fixtureAgent: AgentCollectionHealth["items"][number] = {
  id: "00000000-0000-4000-8000-000000000001", host_id: "00000000-0000-4000-8000-000000000002", name: "fixture-host", domains: ["example.test"],
  state: "error", connection: "never_seen", last_seen: null, last_packet_at: null,
  policy_revision: 1, applied_policy_revision: 1, modules: [],
  href: "/app/agents?agent_id=00000000-0000-4000-8000-000000000001#agent-00000000-0000-4000-8000-000000000001",
};
function setLocaleQuiet(locale: "ru" | "en") {
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  reload.mockRestore();
}
afterEach(() => {
  cleanup();
  state.access = userAccess;
  registryState.disabled = [];
  registryState.preview = false;
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  setLocaleQuiet("ru");
  vi.useRealTimers();
});

describe("AppShell", () => {
  it.each(["browser", "Asia/Vladivostok", "Europe/Berlin"])("restores the saved %s time zone after reload", async (zone) => {
    localStorage.setItem("sli.timeZone", zone);
    await renderShell("/settings", true);
    const expected = new Date("2026-11-14T00:00:00Z").toLocaleString("ru-RU", {
      year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", timeZone: zone === "browser" ? undefined : zone,
    });
    expect(screen.getByLabelText("Display time zone").textContent).toBe(`${zone} · ${expected}`);
  });

  it.each(["ru", "en"] as const)("shows the beta work destinations in order in %s", async (locale) => {
    setLocaleQuiet(locale);
    const entries = fixture.sections.flatMap((section) => section.groups.flatMap<NavigationEntryDto>((group) => group.entries));
    state.access = { ...adminAccess,
      reports: entries.flatMap((entry) => entry.reports ?? []).map((report_key) => ({ report_key, allowed: true })),
      capabilities: entries.flatMap((entry) => entry.capabilities ?? []),
    };
    await renderShell();
    const nav = screen.getByRole("navigation", { name: locale === "ru" ? "Разделы" : "Sections" });
    await within(nav).findByRole("link", { name: locale === "ru" ? "Администрирование" : "Administration" });
    const regions = within(nav).getAllByRole("region");
    expect(regions.flatMap((region) => within(region).getAllByRole("link").map((link) => link.getAttribute("href")))).toEqual([
      "/", "/report/security.problems", "/report/security.events.chains", "/report/events.journal",
      "/report/ad.infrastructure", "/report/ad.users.v2", "/report/ad.computers.v6", "/report/ad.gpo.v2", "/report/file-audit.overview", "/report/workstations.overview",
    ]);
    expect(within(nav).getByRole("link", { name: locale === "ru" ? "Изменения в домене" : "Domain changes" })).toBeTruthy();
    expect(within(nav).queryByRole("link", { name: locale === "ru" ? "Оповещения" : "Notifications" })).toBeNull();
  });

  it.each([
    "/admin/update", "/admin/activity", "/report-studio",
  ])("opens home for hidden %s for both scoped users and administrators", async (path) => {
    for (const grants of [userAccess, adminAccess]) {
      state.access = grants;
      const client = await renderShell(path);
      const nav = screen.getByRole("navigation", { name: "Разделы" });
      await waitFor(() => expect(within(nav).getByRole("link", { name: "Главная" }).getAttribute("aria-current")).toBe("page"));
      expect(screen.queryByRole("tab")).toBeNull();
      expect(within(screen.getByRole("main")).getByRole("heading", { name: "Главная страница" })).toBeTruthy();
      cleanup();
      client.clear();
    }
  });

  it.each(["/report/vpn.connections"])(
    "keeps the unavailable page at %s and mounts the route after server opt-in", async (path) => {
      state.access = adminAccess;
      const client = await renderShell(path, false, false);
      const main = await screen.findByRole("main");
      expect(await within(main).findByText("Модуль недоступен.")).toBeTruthy();
      expect(within(main).queryByRole("heading")).toBeNull();
      registryState.preview = true;
      await client.invalidateQueries({ queryKey: ["report-v2", "catalog"] });
      expect(await within(main).findByRole("heading")).toBeTruthy();
      expect(within(main).queryByText("Модуль недоступен.")).toBeNull();
    },
  );

  const placeholderPages = [
    ["/admin/language-time", "Язык и время", "Language & time"],
  ];
  it.each((["ru", "en"] as const).flatMap((locale) => placeholderPages.map(([path, ru, en]) => [locale, path, locale === "ru" ? ru : en] as const)))("shows an honest development placeholder in %s on %s", async (locale, path, title) => {
    setLocaleQuiet(locale);
    state.access = adminAccess;
    await renderShell(path);
    const main = screen.getByRole("main");
    expect(await within(main).findByText(locale === "ru" ? "В разработке" : "In development")).toBeTruthy();
    expect(within(main).getByRole("heading", { name: title })).toBeTruthy();
    expect(within(main).queryByRole("table")).toBeNull();
    expect(within(main).queryByRole("alert")).toBeNull();
    expect(within(main).queryByRole("button")).toBeNull();
    const nav = screen.getByRole("navigation", { name: locale === "ru" ? "Разделы" : "Sections" });
    expect(within(nav).getAllByRole("link").filter((link) => link.getAttribute("aria-current") === "page").map((link) => link.getAttribute("href"))).toEqual([path.startsWith("/admin/plugins/") ? path : "/settings"]);
  });

  it.each([...placeholderPages, ["/admin/status"], ["/plugins"]])("keeps a direct visit to %s denied without admin grants", async (path) => {
    await renderShell(path);
    const main = screen.getByRole("main");
    await waitFor(() => expect(main.querySelector('[data-state="denied"]')).not.toBeNull());
    expect(within(main).queryByText("В разработке")).toBeNull();
  });

  it.each([
    ["sli.ad", "Active Directory"],
    ["sli.gpo", "Групповые политики"],
    ["sli.file-audit", "Файловый аудит"],
    ["sli.remote-access", "VPN / NPS"],
    ["sli.workstations", "Рабочие станции"],
  ])("routes %s to its plugin screen and retains the administration gate", async (id, title) => {
    registryState.preview = id === "sli.remote-access";
    const path = `/admin/plugins/${id}`;
    await renderShell(path);
    await waitFor(() => expect(screen.getByRole("main").querySelector('[data-state="denied"]')).not.toBeNull());
    expect(screen.queryByRole("tab")).toBeNull();
    cleanup();
    state.access = adminAccess;
    if (id === "sli.workstations") {
      vi.mocked(api.plugins).mockResolvedValueOnce({ items: [{
        plugin_id: id, package_version: "1.0.0", installed: true, configured: true, enabled: true,
        receiving_data: false, component_runtime: "running", queue_state: "idle", revision: 1,
        last_data_at_utc: null,
      }], can_manage: false });
      vi.mocked(api.pluginSettings).mockResolvedValueOnce({
        plugin_id: id, schema: workstationSettings.settings as unknown as SettingsSchema,
        rules: workstationSettings.rules, values: {}, sources: {},
      });
    }
    await renderShell(path);
    const main = within(screen.getByRole("main"));
    expect(await main.findByRole("heading", { name: title })).toBeTruthy();
    if (id === "sli.workstations") {
      expect(main.getByRole("tab", { name: "Обзор", selected: true })).toBeTruthy();
      for (const name of ["Настройки", "Правила", "Отчёты"]) {
        expect(await main.findByRole("tab", { name })).toBeTruthy();
      }
    }
    if (id === "sli.workstations" || id === "sli.file-audit") {
      expect(main.queryByRole("tab", { name: "Подключение" })).toBeNull();
    } else {
      await userEvent.click(main.getByRole("tab", { name: "Подключение" }));
      expect(main.getByRole("tab", { name: "Подключение", selected: true })).toBeTruthy();
    }
    expect(main.queryByText("В разработке")).toBeNull();
  });

  it("opens both plugin pages from the administration menu even when their collection is off", async () => {
    state.access = adminAccess;
    registryState.preview = true;
    registryState.disabled = ["sli.file-audit", "sli.remote-access"];
    await renderShell("/admin/status");
    const nav = screen.getByRole("navigation", { name: "Разделы" });
    await userEvent.click(await within(nav).findByRole("link", { name: "Все плагины" }));
    expect(await screen.findByRole("heading", { name: "Плагины" })).toBeTruthy();
    for (const name of ["Файловый аудит", "VPN / NPS"]) {
      await userEvent.click(within(nav).getByRole("link", { name }));
      expect(await screen.findByRole("heading", { name })).toBeTruthy();
      expect(within(nav).getByRole("link", { name }).getAttribute("aria-current")).toBe("page");
    }
  });

  it("keeps the old setup, readiness and platform settings reachable from Status", async () => {
    state.access = { ...adminAccess, reports: [{ report_key: "operations.readiness", allowed: true }] };
    await renderShell("/admin/status");
    const main = screen.getByRole("main");
    fireEvent.click(await within(main).findByText("Связанные разделы"));
    expect(within(main).getByRole("link", { name: "Первичная настройка" }).getAttribute("href")).toBe("/setup");
    expect(within(main).getByRole("link", { name: "Готовность платформы" }).getAttribute("href")).toBe("/project-readiness");
    expect(within(main).getByRole("link", { name: "Настройки платформы" }).getAttribute("href")).toBe("/platform-settings");
    fireEvent.click(within(main).getByRole("link", { name: "Первичная настройка" }));
    await screen.findByRole("heading", { name: "Главная страница" });
    const nav = screen.getByRole("navigation", { name: "Разделы" });
    expect(within(nav).getByRole("link", { name: "Состояние системы" }).getAttribute("aria-current")).toBe("page");
  });

  it("preserves scoped platform settings access without exposing other admin destinations", async () => {
    state.access = { ...userAccess, capabilities: [], reports: [{ report_key: "decoys.registry", allowed: true }] };
    await renderShell("/admin/status");
    const main = screen.getByRole("main");
    expect(await within(main).findByRole("heading", { name: "Состояние системы" })).toBeTruthy();
    fireEvent.click(within(main).getByText("Связанные разделы"));
    expect(within(main).getByRole("link", { name: "Настройки платформы" }).getAttribute("href")).toBe("/platform-settings");
  });

  it.each([
    ["/access", ["/access-requests", "/admin"]],
    ["/admin/language-time", ["/settings"]],
  ] as const)("keeps related old pages reachable from %s", async (path, destinations) => {
    state.access = adminAccess;
    await renderShell(path);
    const main = screen.getByRole("main");
    fireEvent.click(await within(main).findByText("Связанные разделы"));
    expect(within(main).getAllByRole("link").map((link) => link.getAttribute("href"))).toEqual(destinations);
  });

  it.each(["error", "lagging"] as const)("keeps %s collection diagnostics out of the header", async (agentState) => {
    state.access = adminAccess;
    const readCollection = vi.mocked(api.agentCollection).mockClear().mockResolvedValue({
      agent_collection: { state: agentState === "error" ? "error" : "partial", checked_at_utc: "2026-10-13T00:00:00Z",
        items: [{ ...fixtureAgent, state: agentState }], active_agents: 1, current_agents: 0 },
    });
    await renderShell();
    const header = within(screen.getByRole("banner"));
    expect(header.queryByRole("status")).toBeNull();
    expect(header.queryByRole("button", { name: /fixture-host/ })).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(readCollection).not.toHaveBeenCalled();
  });

  it("exposes the search icon as a visible keyboard submit action", async () => {
    await renderShell();
    const search = screen.getByRole("search");
    const submit = within(search).getByRole("button", { name: "Выполнить поиск" });
    expect(submit.getAttribute("type")).toBe("submit");
    expect(submit.classList.contains("sli-ds-sr-only")).toBe(false);
    expect(submit.classList.contains("sli-ds-shell__search-submit")).toBe(true);
    submit.focus();
    expect(document.activeElement).toBe(submit);
  });

  it("opens a permitted object directly and preserves a custom period in the event journal link", async () => {
    state.access = { ...userAccess, capabilities: ["objects.view", "events.view"] };
    const objects = { computer: ["41", "Example computer"], user: ["42", "Example user"], ad_group: ["43", "Example group"] };
    const read = vi.mocked(api.v4Objects).mockImplementation(async (params) => {
      const type = params?.get("type") as keyof typeof objects;
      const [id, label] = objects[type];
      return { api_version: "v4", query: params?.get("q") ?? "", items: [{
        object_id: id, object_type: type, display_name: label, source: "fixture",
      }], state: "available", has_more: false, limits: {} };
    });
    await renderShell("/report/events.journal?period=custom&from=2026-11-26&to=2026-11-28&tz=UTC");
    const header = within(screen.getByRole("search"));
    const input = header.getByRole("searchbox");
    fireEvent.change(input, { target: { value: "Example" } });
    const computers = await header.findByRole("group", { name: "Компьютеры" });
    expect(within(computers).getByRole("link").getAttribute("href")).toBe("/entities/41");
    expect(within(await header.findByRole("group", { name: "Пользователи" })).getByRole("link").getAttribute("href")).toBe("/entities/42");
    const group = within(await header.findByRole("group", { name: "Группы" })).getByRole("link");
    const journal = new URL(header.getByRole("link", { name: "Искать в журнале событий" }).getAttribute("href")!, "https://example.test");
    expect(Object.fromEntries(journal.searchParams)).toEqual({ period: "custom", from: "2026-11-26", to: "2026-11-28", tz: "UTC", q: "Example" });
    expect(read.mock.calls.map(([params]) => params?.get("limit"))).toEqual(["5", "5", "5"]);
    group.focus();
    await userEvent.keyboard("{Enter}");
    expect(await screen.findByRole("heading", { name: "Object 43" })).toBeTruthy();
    read.mockReset();
  });

  it("renders the GPO section separately and removes it when GPO is disabled", async () => {
    state.access = { ...userAccess, reports: [...userAccess.reports, { report_key: "ad.gpo.v2", allowed: true }] };
    const client = await renderShell();
    const nav = screen.getByRole("navigation", { name: "Разделы" });
    const gpo = await within(nav).findByRole("region", { name: "Групповые политики" });
    expect(within(gpo).getByRole("link", { name: "Групповые политики" }).getAttribute("href")).toBe("/report/ad.gpo.v2");
    const ad = within(nav).getByRole("region", { name: "Active Directory" });
    expect(within(ad).queryByRole("link", { name: "Групповые политики" })).toBeNull();
    registryState.disabled = ["sli.gpo"];
    await client.invalidateQueries({ queryKey: ["report-v2"] });
    await waitFor(() => expect(within(nav).queryByRole("region", { name: "Групповые политики" })).toBeNull());
    expect(within(nav).getByRole("link", { name: "Пользователи" })).toBeTruthy();
  });
  it("updates menu visibility when the shared report catalog is invalidated", async () => {
    const client = await renderShell();
    const nav = screen.getByRole("navigation", { name: "Разделы" });
    await waitFor(() => expect(within(nav).getByRole("link", { name: "Пользователи" })).toBeTruthy());
    registryState.disabled = ["sli.ad"];
    await client.invalidateQueries({ queryKey: ["report-v2"] });
    await waitFor(() => expect(within(nav).queryByRole("link", { name: "Пользователи" })).toBeNull());
    expect(within(nav).getByRole("link", { name: "Проблемы" })).toBeTruthy();
  });
  it("hides the disabled AD section while keeping permitted core navigation", async () => {
    registryState.disabled = ["sli.ad"];
    await renderShell();
    const nav = screen.getByRole("navigation", { name: "Разделы" });
    await waitFor(() => expect(within(nav).getByRole("link", { name: "Проблемы" })).toBeTruthy());
    expect(within(nav).queryByRole("link", { name: "Пользователи" })).toBeNull();
    expect(within(nav).queryByText("Active Directory")).toBeNull();
  });

  it("builds navigation only from sections the access allows and marks the active item", async () => {
    await renderShell();
    const nav = screen.getByRole("navigation", { name: "Разделы" });
    await waitFor(() => expect(within(nav).getByRole("link", { name: "Пользователи" })).toBeTruthy());
    expect(within(nav).getByRole("link", { name: "Главная" }).getAttribute("aria-current")).toBe("page");
    expect(within(nav).getByRole("link", { name: "Проблемы" })).toBeTruthy();
    expect(within(nav).queryByRole("link", { name: "VPN-подключения" })).toBeNull();
    expect(within(nav).queryByRole("link", { name: "Доступ" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Администрирование/ })).toBeNull();
  });

  it("keeps landmarks, skip link and global search", async () => {
    await renderShell();
    expect(screen.getByRole("link", { name: "К основному содержимому" }).getAttribute("href")).toBe("#main");
    expect(screen.getByRole("main")).toBeTruthy();
    expect(screen.getByRole("search")).toBeTruthy();
    expect(screen.getByRole("searchbox", { name: "Глобальный поиск" })).toBeTruthy();
  });

  it.each(["Enter", "submit"])("filters the event journal from the top search using %s", async (method) => {
    state.access = { ...userAccess, capabilities: ["problem.view", "events.view"] };
    await renderShell();
    const submit = async (value: string) => {
      const input = screen.getByRole("searchbox", { name: "Глобальный поиск" });
      await userEvent.clear(input);
      await userEvent.type(input, value);
      if (method === "Enter") await userEvent.keyboard("{Enter}");
      else await userEvent.click(screen.getByRole("button", { name: "Выполнить поиск" }));
    };
    await submit("  4728  ");
    expect(await screen.findByRole("heading", { name: "Журнал событий" })).toBeTruthy();
    expect(screen.getByLabelText("Journal query").textContent).toBe("4728");
    await submit('"example.test"');
    await waitFor(() => expect(screen.getByLabelText("Journal query").textContent).toBe('"example.test"'));
    expect(within(screen.getByRole("navigation", { name: "Разделы" })).queryByRole("link", { name: "Объекты и сущности" })).toBeNull();
  });

  it("opens the navigation from the mobile toggle and closes it on Escape", async () => {
    await renderShell();
    const shell = document.querySelector("[data-sli-shell]") as HTMLElement;
    const toggle = screen.getByRole("button", { name: "Открыть меню" });
    expect(shell.dataset.menuOpen).toBe("false");
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(toggle);
    expect(shell.dataset.menuOpen).toBe("true");
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(shell.dataset.menuOpen).toBe("false");
  });

  it("shows the profile menu with logout", async () => {
    await renderShell();
    const profile = await screen.findByRole("button", { name: /test\.operator/ });
    fireEvent.click(profile);
    expect(screen.getByRole("menuitem", { name: "Выйти из системы" })).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("sets the theme from the profile menu and remembers it", async () => {
    await renderShell();
    fireEvent.click(await screen.findByRole("button", { name: /test\.operator/ }));
    expect(screen.getByRole("menuitemradio", { name: "Тёмная" }).getAttribute("aria-checked")).toBe("true");
    fireEvent.click(screen.getByRole("menuitemradio", { name: "Тёмная" }));
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(localStorage.getItem("sli.theme")).toBe("dark");
    expect(screen.getByRole("menuitemradio", { name: "Тёмная" }).getAttribute("aria-checked")).toBe("true");
    fireEvent.click(screen.getByRole("menuitemradio", { name: "Светлая" }));
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(localStorage.getItem("sli.theme")).toBe("light");
    fireEvent.click(screen.getByRole("menuitemradio", { name: "Как в системе" }));
    expect(document.documentElement.getAttribute("data-theme")).toBe("system");
    expect(localStorage.getItem("sli.theme")).toBe("system");
  });

  it("renders the shell in English when the locale is en", async () => {
    setLocaleQuiet("en");
    state.access = { ...userAccess, reports: [...userAccess.reports, { report_key: "ad.gpo.v2", allowed: true }] };
    await renderShell();
    const nav = screen.getByRole("navigation", { name: "Sections" });
    await waitFor(() => expect(within(nav).getByRole("link", { name: "Users" })).toBeTruthy());
    expect(within(nav).getByText("Active Directory")).toBeTruthy();
    const gpo = within(nav).getByRole("region", { name: "Group policies" });
    expect(within(gpo).getByRole("link", { name: "Group policies" }).getAttribute("href")).toBe("/report/ad.gpo.v2");
    expect(within(nav).getByRole("link", { name: "Home" })).toBeTruthy();
    expect(screen.getByRole("searchbox", { name: "Global search" })).toBeTruthy();
    fireEvent.click(await screen.findByRole("button", { name: /test\.operator/ }));
    expect(screen.getByRole("menuitem", { name: "Sign out" })).toBeTruthy();
  });

  it.each(["ru", "en"] as const)("opens all permitted admin groups from the work sidebar and returns on mobile in %s", async (locale) => {
    setLocaleQuiet(locale);
    state.access = { ...adminAccess, capabilities: [...adminAccess.capabilities, "reports.design"],
      reports: [...adminAccess.reports, { report_key: "operations.readiness", allowed: true }] };
    await renderShell();
    const nav = screen.getByRole("navigation", { name: locale === "ru" ? "Разделы" : "Sections" });
    const entry = await within(nav).findByRole("link", { name: locale === "ru" ? "Администрирование" : "Administration" });
    expect(entry.getAttribute("href")).toBe("/admin/status");
    fireEvent.click(screen.getByRole("button", { name: locale === "ru" ? "Открыть меню" : "Open menu" }));
    fireEvent.click(entry);
    const titles = locale === "ru" ? ["Система", "Плагины"] : ["System", "Plugins"];
    for (const title of titles) expect(await within(nav).findByRole("group", { name: title })).toBeTruthy();
    expect(within(nav).getAllByRole("link").map((link) => link.getAttribute("href"))).toEqual([
      "/", "/admin/status", "/agents", "/access", "/notifications", "/operations", "/settings",
      "/admin/plugins/sli.sigma", "/plugins",
    ]);
    expect(within(nav).getAllByRole("link").slice(1).map((link) => link.textContent)).toEqual(locale === "ru" ? [
      "Состояние системы", "Агенты", "Пользователи и роли", "Оповещения", "Хранение", "Язык и время",
      "Sigma", "Все плагины",
    ] : [
      "System status", "Agents", "Users & roles", "Notifications", "Storage", "Language & time",
      "Sigma", "All plugins",
    ]);
    expect(within(nav).getAllByRole("link").filter((link) => link.getAttribute("aria-current") === "page").map((link) => link.getAttribute("href"))).toEqual(["/admin/status"]);
    expect(document.querySelector<HTMLElement>("[data-sli-shell]")?.dataset.menuOpen).toBe("false");
    fireEvent.click(screen.getByRole("button", { name: locale === "ru" ? "Открыть меню" : "Open menu" }));
    fireEvent.click(within(nav).getByRole("link", { name: locale === "ru" ? /К работе/ : /Back to work/ }));
    await within(nav).findByRole("link", { name: locale === "ru" ? "Администрирование" : "Administration" });
    expect(document.querySelector<HTMLElement>("[data-sli-shell]")?.dataset.menuOpen).toBe("false");
  });

  it("links scoped notification readers only to their permitted admin destination", async () => {
    state.access = { ...userAccess, capabilities: [], reports: [{ report_key: "notifications.deliveries", allowed: true }] };
    await renderShell();
    const nav = screen.getByRole("navigation", { name: "Разделы" });
    const entry = await within(nav).findByRole("link", { name: "Администрирование" });
    expect(entry.getAttribute("href")).toBe("/notifications");
    fireEvent.click(entry);
    await within(nav).findByRole("link", { name: /К работе/ });
    expect(within(nav).getAllByRole("group").map((group) => group.getAttribute("aria-label"))).toEqual(["Система"]);
    expect(within(nav).queryByRole("link", { name: "Доступ" })).toBeNull();
    expect(within(nav).queryByRole("link", { name: "Агенты" })).toBeNull();
  });

  it.each(["ru", "en"] as const)("opens Language & time from the user menu in %s", async (locale) => {
    setLocaleQuiet(locale);
    state.access = adminAccess;
    await renderShell();
    const profile = await screen.findByRole("button", { name: "admin.user" });
    fireEvent.click(profile);
    const menu = within(screen.getByRole("menu"));
    const link = menu.getByRole("menuitem", { name: locale === "ru" ? "Язык и время" : "Language & time" });
    expect(link.getAttribute("href")).toBe("/settings");
    expect(menu.queryByRole("menuitem", { name: locale === "ru" ? "Оповещения" : "Notifications" })).toBeNull();
    expect(menu.queryByRole("menuitemradio", { name: /Русский|English/ })).toBeNull();
    expect(menu.getByRole("menuitem", { name: /Выйти|Sign out/ })).toBeTruthy();
    fireEvent.click(link);
    await waitFor(() => expect(profile.getAttribute("aria-expanded")).toBe("false"));
    const nav = within(screen.getByRole("navigation", { name: locale === "ru" ? "Разделы" : "Sections" }));
    const settings = nav.getByRole("link", { name: locale === "ru" ? "Язык и время" : "Language & time" });
    expect(settings.getAttribute("aria-current")).toBe("page");
    const icon = (label: string) => nav.getByRole("link", { name: label }).querySelector("use")?.getAttribute("href");
    expect(icon(locale === "ru" ? "Оповещения" : "Notifications")).not.toBe(icon(locale === "ru" ? "Агенты" : "Agents"));
    expect(icon(locale === "ru" ? "Хранение" : "Storage")).toBe("#i-database");
  });

  it("closes the user menu with Escape or an outside click", async () => {
    state.access = adminAccess;
    await renderShell();
    const profile = await screen.findByRole("button", { name: "admin.user" });
    fireEvent.click(profile);
    expect(profile.getAttribute("aria-expanded")).toBe("true");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    fireEvent.click(profile);
    fireEvent.mouseDown(screen.getByRole("main"));
    expect(screen.queryByRole("menu")).toBeNull();
  });

  for (const path of ["/access", "/access/42", "/access-requests", "/admin", "/platform-settings", "/settings", "/setup", "/project-readiness", "/notifications"]) {
    it(`renders the admin sidebar with the way back on ${path}`, async () => {
      state.access = { ...adminAccess, reports: [...adminAccess.reports, { report_key: "operations.readiness", allowed: true }] };
      await renderShell(path);
      const nav = screen.getByRole("navigation", { name: "Разделы" });
      await waitFor(() => expect(within(nav).getByRole("link", { name: "Состояние системы" })).toBeTruthy());
      expect(within(nav).getByRole("link", { name: /К работе/ }).getAttribute("href")).toBe("/");
      expect(within(nav).getByRole("link", { name: "Пользователи и роли" })).toBeTruthy();
      const activeHref = ["/access", "/access/42", "/admin", "/access-requests"].includes(path) ? "/access" : path === "/settings" ? "/settings" : ["/setup", "/platform-settings", "/project-readiness"].includes(path) ? "/admin/status" : path;
      expect(within(nav).getAllByRole("link").filter((link) => link.getAttribute("aria-current") === "page").map((link) => link.getAttribute("href"))).toEqual([activeHref]);
      expect(within(nav).queryByRole("link", { name: "Главная" })).toBeNull();
      expect(within(nav).queryByRole("link", { name: "Пользователи" })).toBeNull();
    });
  }

  it("keeps pages outside the navigation in the work zone", async () => {
    state.access = adminAccess;
    await renderShell("/objects");
    const nav = screen.getByRole("navigation", { name: "Разделы" });
    await waitFor(() => expect(within(nav).getByRole("link", { name: "Главная" })).toBeTruthy());
    expect(within(nav).queryByRole("link", { name: /К работе/ })).toBeNull();
    expect(within(nav).getByRole("link", { name: "Администрирование" })).toBeTruthy();
  });

  it("hides administration from users without administration entries", async () => {
    await renderShell();
    await screen.findByRole("button", { name: /test\.operator/ });
    expect(screen.queryByRole("button", { name: "Администрирование" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Администрирование" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Оповещения" })).toBeNull();
  });

  it("shows the zone sidebar in the mobile menu", async () => {
    state.access = adminAccess;
    await renderShell("/access");
    fireEvent.click(screen.getByRole("button", { name: "Открыть меню" }));
    const nav = screen.getByRole("navigation", { name: "Разделы" });
    await waitFor(() => expect(within(nav).getByRole("link", { name: /К работе/ })).toBeTruthy());
  });
});

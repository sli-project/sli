// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ status: vi.fn(), archive: vi.fn(), saveSetting: vi.fn(), addDomain: vi.fn(), addDc: vi.fn(), toggleDc: vi.fn(), timeZone: "UTC", access: undefined as unknown }));

vi.mock("../App", async (importOriginal) => ({ ...(await importOriginal<typeof import("../App")>()), useEffectiveAccess: () => state.access, useTimeZone: () => ({ timeZone: state.timeZone, setTimeZone: () => undefined }) }));

vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, setupStatus: () => state.status(), setSetupDomainArchived: (fqdn: string, archived: boolean) => state.archive(fqdn, archived), updatePlatformSetting: (key: string, value: string) => state.saveSetting(key, value), addSetupDomain: (body: unknown) => state.addDomain(body), addSetupDomainController: (body: unknown) => state.addDc(body), setSetupDomainControllerEnabled: (host: string, enabled: boolean) => state.toggleDc(host, enabled) } };
});

import { ApiResponseError } from "../../api/client";
import { SetupPage } from "./setup";
import { OverlayProvider } from "../../design-system";
import { getLocale, localeRuntime, setLocale, t } from "../../i18n";

const status = {
  api_version: "v1", generated_at_utc: "2026-10-02T00:00:00Z", read_only: true,
  steps: [
    { id: "report-domain", title: "Домен отчётов", state: "done", summary: "Домен отчётов: corp.example.test.", link: "/platform-settings" },
    { id: "domains", title: "Домены Active Directory", state: "todo", summary: "Домены ещё не загружены.", manual: "Домены появляются при первой загрузке.", doc: "docs/ADMIN_GUIDE.md" },
    { id: "domain-controllers", title: "Контроллеры домена", state: "done", summary: "Настроено контроллеров: 1." },
    { id: "sources", title: "Источники", state: "done", summary: "Доступно пакетов источников: 1." },
    { id: "first-collection", title: "Первый сбор", state: "unavailable", summary: "Состояние сбора недоступно.", link: "/operations" },
  ],
  report_domain: { key: "reports.domain_fqdn", value: "corp.example.test", source: "database" },
  domains: [],
  domain_controllers: [{ hostname: "DC1", connect_address: "dc1.example.test", domain: null, enabled: true, source: "file", dns_readback: true }],
  domain_controller_source: "file",
  sources: [{ pack_id: "sli.windows.ad-dc", display_name: t("setup.source.name.domainController"), version: "1.0.0", source_kind: "event", enabled: true }],
  collection: null,
};

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return { ...render(<QueryClientProvider client={client}><OverlayProvider><SetupPage/></OverlayProvider></QueryClientProvider>), client };
}

afterEach(() => { cleanup(); vi.clearAllMocks(); state.access = undefined; });

it("shows every step with its live state, details and manual hints", async () => {
  state.status.mockResolvedValue(status);
  mount();

  expect(await screen.findByText(/1\. Домен отчётов/)).toBeTruthy();
  expect(screen.getAllByText("Готово")).toHaveLength(2);
  expect(screen.getByText("Требует действия")).toBeTruthy();
  expect(screen.getAllByText("Нет данных")).toHaveLength(2);
  expect(screen.getByRole("table", { name: "Контроллеры домена" })).toBeTruthy();
  expect(screen.getByText("dc1.example.test")).toBeTruthy();
  expect(screen.getByText("файл")).toBeTruthy();
  expect(screen.getByText(/sli.windows.ad-dc 1.0.0/)).toBeTruthy();
  expect(screen.getByText("docs/ADMIN_GUIDE.md")).toBeTruthy();
  expect(screen.getByText("docs/ADMIN_GUIDE.md").closest("details")?.open).toBe(false);
  expect(screen.getByRole("heading", { name: /Источники со свежими данными/ })).toBeTruthy();
  expect((screen.getByRole("link", { name: t("platformSettings.page.title") }) as HTMLAnchorElement).getAttribute("href")).toBe("/app/platform-settings");
});

it("never offers to start collection or to change data", async () => {
  state.status.mockResolvedValue(status);
  mount();
  await screen.findByText(/1\. Домен отчётов/);
  expect(screen.queryAllByRole("button")).toHaveLength(0);
});

it("reports an unavailable backend instead of an empty checklist", async () => {
  state.status.mockRejectedValue(new Error("setup_unavailable"));
  mount();
  expect(await screen.findByText(/setup_unavailable/)).toBeTruthy();
  expect(screen.queryByText(/1\. Домен отчётов/)).toBeNull();
});

const withDomain = { ...status, domains: [{ fqdn: "corp.example.test", netbios_name: "CORP", forest: "corp.example.test", server_count: 2 }] };

it.each(["ru", "en"] as const)("collapses the completed domain form without losing explicit edits (%s)", async (locale) => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  state.status.mockResolvedValue({ ...withDomain, steps: status.steps.map((step) => step.id === "domains" ? { ...step, state: "done" } : step) });
  state.access = { capabilities: ["access.manage"] };
  try {
    mount();
    await screen.findByRole("table", { name: t("setup.domain.tableCaption") });
    const section = document.getElementById("setup-domains")!;
    const summary = within(section).getByText(t("setup.domain.add"), { selector: "summary" });
    const disclosure = summary.closest("details")!;
    expect(disclosure.open).toBe(false);
    expect(within(section).getByLabelText(t("setup.domain.labelFqdn")).closest("details")).toBe(disclosure);
    expect(within(section).getByRole("switch")).toBeTruthy();
    fireEvent.click(summary);
    expect(disclosure.open).toBe(true);
    const fqdn = within(section).getByRole("textbox", { name: t("setup.domain.labelFqdn") }) as HTMLInputElement;
    const submit = within(section).getByRole("button", { name: t("setup.domain.add") }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.change(fqdn, { target: { value: " new.example.test " } });
    fireEvent.click(summary);
    expect(disclosure.open).toBe(false);
    fireEvent.click(summary);
    expect(fqdn.value).toBe(" new.example.test ");
    expect(state.addDomain).not.toHaveBeenCalled();
    expect(state.archive).not.toHaveBeenCalled();
    fireEvent.change(within(section).getByRole("textbox", { name: t("setup.domain.labelNetbios") }), { target: { value: " NEW " } });
    state.addDomain.mockResolvedValue({ item: { fqdn: "new.example.test" } });
    fireEvent.click(submit);
    await waitFor(() => expect(state.addDomain).toHaveBeenCalledWith({ fqdn: "new.example.test", netbios_name: "NEW" }));
    expect(state.addDomain).toHaveBeenCalledTimes(1);
    expect(await within(section).findByRole("status")).toHaveProperty("textContent", t("setup.domain.added"));
  } finally { cleanup(); setLocale(previous); reload.mockRestore(); }
});

it.each(["ru", "en"] as const)("keeps unfinished domain forms directly available (%s)", async (locale) => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  state.access = { capabilities: ["access.manage"] };
  try {
    for (const stepState of ["todo", "unavailable"] as const) {
      state.status.mockResolvedValue({ ...withDomain, steps: status.steps.map((step) => step.id === "domains" ? { ...step, state: stepState } : step) });
      mount();
      await screen.findByRole("table", { name: t("setup.domain.tableCaption") });
      const section = document.getElementById("setup-domains")!;
      expect(within(section).getByRole("textbox", { name: t("setup.domain.labelFqdn") })).toBeTruthy();
      expect(within(section).queryByText(t("setup.domain.add"), { selector: "summary" })).toBeNull();
      expect(state.addDomain).not.toHaveBeenCalled();
      cleanup();
    }
  } finally { cleanup(); setLocale(previous); reload.mockRestore(); }
});

it.each(["ru", "en"] as const)("does not offer a domain form disclosure without management access (%s)", async (locale) => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  state.access = { capabilities: ["reports.view"] };
  try {
    for (const stepState of ["done", "todo"] as const) {
      state.status.mockResolvedValue({ ...withDomain, steps: status.steps.map((step) => step.id === "domains" ? { ...step, state: stepState } : step) });
      mount();
      await screen.findByRole("table", { name: t("setup.domain.tableCaption") });
      const section = document.getElementById("setup-domains")!;
      expect(within(section).queryByText(t("setup.domain.add"), { selector: "summary" })).toBeNull();
      expect(within(section).queryByLabelText(t("setup.domain.labelFqdn"))).toBeNull();
      expect(within(section).queryByRole("switch")).toBeNull();
      expect(state.addDomain).not.toHaveBeenCalled();
      cleanup();
    }
  } finally { cleanup(); setLocale(previous); reload.mockRestore(); }
});

it("lists domains in a table without a form for users who cannot manage", async () => {
  state.status.mockResolvedValue(withDomain);
  state.access = { capabilities: ["reports.view"] };
  mount();
  expect(await screen.findByRole("table", { name: "Домены Active Directory" })).toBeTruthy();
  expect(screen.getByText("CORP")).toBeTruthy();
  expect(screen.queryByLabelText("DNS-имя домена")).toBeNull();
});

it("adds a domain for an administrator and refreshes the checklist", async () => {
  state.status.mockResolvedValue(status);
  state.access = { capabilities: ["access.manage"] };
  state.addDomain.mockResolvedValue({ item: withDomain.domains[0] });
  mount();
  fireEvent.change(await screen.findByLabelText("DNS-имя домена"), { target: { value: " corp.example.test " } });
  fireEvent.change(screen.getByLabelText(/NetBIOS-имя/), { target: { value: "CORP" } });
  fireEvent.click(screen.getByRole("button", { name: "Добавить домен" }));
  await waitFor(() => expect(state.addDomain).toHaveBeenCalledWith({ fqdn: "corp.example.test", netbios_name: "CORP" }));
  expect(await screen.findByText("Домен добавлен.")).toBeTruthy();
  await waitFor(() => expect(state.status).toHaveBeenCalledTimes(2));
});

it("shows a readable message when the domain already exists", async () => {
  state.status.mockResolvedValue(status);
  state.access = { capabilities: ["access.manage"] };
  state.addDomain.mockRejectedValue(new ApiResponseError(409, "domain_already_exists"));
  mount();
  fireEvent.change(await screen.findByLabelText("DNS-имя домена"), { target: { value: "corp.example.test" } });
  fireEvent.click(screen.getByRole("button", { name: "Добавить домен" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Такой домен уже добавлен.");
});

const dbController = { hostname: "DC2", connect_address: "dc2.corp.example.test", domain: "corp.example.test", enabled: true, source: "db" as const, dns_readback: false };
const withDbControllers = { ...withDomain, domain_controllers: [dbController, { ...dbController, hostname: "DC3", connect_address: "dc3.corp.example.test", enabled: false }], domain_controller_source: "db" };

it("shows controllers without actions for users who cannot manage", async () => {
  state.status.mockResolvedValue(withDbControllers);
  state.access = { capabilities: ["reports.view"] };
  mount();
  expect(await screen.findByRole("table", { name: "Контроллеры домена" })).toBeTruthy();
  expect(screen.getByText("отключён")).toBeTruthy();
  expect(screen.queryByLabelText("DNS-имя контроллера (FQDN)")).toBeNull();
  expect(screen.queryByRole("button", { name: "Отключить" })).toBeNull();
});

it("uses the sole registered domain without a selector and refreshes the checklist", async () => {
  state.status.mockResolvedValue(withDbControllers);
  state.access = { capabilities: ["access.manage"] };
  state.addDc.mockResolvedValue({ item: dbController });
  mount();
  fireEvent.change(await screen.findByLabelText("DNS-имя контроллера (FQDN)"), { target: { value: " dc4.corp.example.test " } });
  const domain = screen.getByLabelText("Домен") as HTMLInputElement;
  expect(domain.readOnly).toBe(true);
  expect(domain.value).toBe("corp.example.test");
  expect(screen.queryByRole("combobox")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Добавить контроллер" }));
  await waitFor(() => expect(state.addDc).toHaveBeenCalledWith({ hostname: "dc4.corp.example.test", domain: "corp.example.test" }));
  expect(await screen.findByText("Контроллер добавлен.")).toBeTruthy();
  await waitFor(() => expect(state.status).toHaveBeenCalledTimes(2));
});

it("requires an explicit registered domain when adding a controller with multiple domains", async () => {
  state.status.mockResolvedValue({ ...withDbControllers, domains: [...withDomain.domains,
    { ...withDomain.domains[0], fqdn: "second.example.test" }] });
  state.access = { capabilities: ["access.manage"] };
  state.addDc.mockResolvedValue({ item: dbController });
  mount();
  fireEvent.change(await screen.findByLabelText(t("setup.dc.labelHostname")), { target: { value: "dc1.second.example.test" } });
  const add = screen.getByRole("button", { name: t("setup.dc.add") }) as HTMLButtonElement;
  expect(add.disabled).toBe(true);
  await chooseOption(screen.getByLabelText(t("setup.dc.labelDomain"), { selector: "button" }), "second.example.test");
  fireEvent.click(add);
  await waitFor(() => expect(state.addDc).toHaveBeenCalledWith({ hostname: "dc1.second.example.test", domain: "second.example.test" }));
});

it("cannot add a controller before a domain is registered", async () => {
  state.status.mockResolvedValue(status);
  state.access = { capabilities: ["access.manage"] };
  mount();
  fireEvent.change(await screen.findByLabelText(t("setup.dc.labelHostname")), { target: { value: "dc1.corp.example.test" } });
  expect((screen.getByLabelText(t("setup.dc.labelDomain"), { selector: "button" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.submit(screen.getByRole("button", { name: t("setup.dc.add") }).closest("form")!);
  expect(state.addDc).not.toHaveBeenCalled();
});

it.each(["ru", "en"] as const)("uses localized hints with empty setup inputs in %s", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  const previous = getLocale();
  setLocale(locale);
  try {
    state.status.mockResolvedValue(status);
    state.access = { capabilities: ["access.manage"] };
    mount();
    for (const key of ["setup.domain.fqdnPlaceholder", "setup.domain.netbiosPlaceholder", "setup.dc.hostnamePlaceholder"] as const) {
      expect((await screen.findByPlaceholderText(t(key)) as HTMLInputElement).value).toBe("");
    }
  } finally {
    cleanup();
    setLocale(previous);
    vi.restoreAllMocks();
  }
});

it("disables and enables stored controllers but offers no toggle for file rows", async () => {
  state.status.mockResolvedValue({ ...withDbControllers, domain_controllers: [...withDbControllers.domain_controllers, { ...dbController, hostname: "DC9", source: "file" as const }] });
  state.access = { capabilities: ["access.manage"] };
  state.toggleDc.mockResolvedValue({ item: { hostname: "DC2", enabled: false, previous_enabled: true } });
  mount();
  fireEvent.click(await screen.findByRole("button", { name: "Отключить" }));
  await waitFor(() => expect(state.toggleDc).toHaveBeenCalledWith("DC2", false));
  expect(screen.getAllByRole("button", { name: /Отключить|Включить/ })).toHaveLength(2);
});

it("shows a readable message when the controller already exists", async () => {
  state.status.mockResolvedValue(withDbControllers);
  state.access = { capabilities: ["access.manage"] };
  state.addDc.mockRejectedValue(new ApiResponseError(409, "domain_controller_already_exists"));
  mount();
  fireEvent.change(await screen.findByLabelText("DNS-имя контроллера (FQDN)"), { target: { value: "dc2.corp.example.test" } });
  fireEvent.change(screen.getByLabelText("Домен"), { target: { value: "corp.example.test" } });
  fireEvent.click(screen.getByRole("button", { name: "Добавить контроллер" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Такой контроллер уже добавлен.");
});

it.each(["ru", "en"] as const)("shows independent source states and a specific next step in %s", async (locale) => {
  const previous = getLocale();
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  try {
    state.status.mockResolvedValue({ ...status, steps: status.steps.map((step) => step.id === "sources" ? { ...step, state: "todo" } : step), sources: [{ ...status.sources[0], installed: true, configured: true, enabled: false,
      activation_state: "disabled", data_state: "stale", data_received: false, instances: [
        { source_instance_id: "source:1", configured: true, enabled: false, data_received: false, data_state: "stale", last_data_utc: "2026-10-01T00:00:00Z", next_action: "enable" },
        { source_instance_id: "source-2", configured: null, enabled: null, data_received: null, data_state: "unavailable", last_data_utc: null, next_action: "check_configuration" },
      ] }], next_step: { pack_id: status.sources[0].pack_id, source_instance_id: "source:1", action: "enable" } });
    mount();
    const source = await screen.findByRole("group", { name: `${t("setup.source.name.domainController")}: source:1` });
    expect(within(source).getByText(t("setup.source.installed"))).toBeTruthy();
    expect(within(source).getByText(t("setup.source.configured"))).toBeTruthy();
    expect(within(source).getByText(t("setup.source.disabled"))).toBeTruthy();
    expect(within(source).getByText(t("setup.source.data.stale"))).toBeTruthy();
    expect(within(source).getByText(t("setup.source.next.ad_enable"))).toBeTruthy();
    expect(within(source).getByRole("link", { name: t("setup.steps.controllers.title") }).getAttribute("href")).toBe("#setup-domain-controllers");
    const unknown = screen.getByRole("group", { name: `${t("setup.source.name.domainController")}: source-2` });
    expect(within(unknown).getAllByText(t("setup.source.unknown"))).toHaveLength(2);
    expect(within(unknown).getByText(t("setup.source.data.unavailable"))).toBeTruthy();
    expect(within(unknown).getByText(t("setup.source.next.ad_configure"))).toBeTruthy();
    expect(within(unknown).getByRole("link", { name: t("setup.steps.controllers.title") }).getAttribute("href")).toBe("#setup-domain-controllers");
    expect(screen.getByRole("heading", { level: 2, name: `4. ${t("setup.steps.sources.title")} ${t("setup.state.todo")}` })).toBeTruthy();
    const href = screen.getByRole("link", { name: /source:1/ }).getAttribute("href")!;
    expect(document.getElementById(decodeURIComponent(href.slice(1)))).toBe(source);
  } finally {
    cleanup();
    setLocale(previous);
    vi.restoreAllMocks();
  }
});

it("does not infer configuration or data from a legacy enabled package", async () => {
  state.status.mockResolvedValue(status);
  mount();
  const source = await screen.findByRole("group", { name: t("setup.source.name.domainController") });
  expect(within(source).getAllByText(t("setup.source.unknown"))).toHaveLength(2);
  expect(within(source).getByText(t("setup.source.data.unavailable"))).toBeTruthy();
  expect(screen.getByText(t("setup.steps.sources.unavailable"))).toBeTruthy();
});

it("links the next step to an installed package that has no configured instances", async () => {
  state.status.mockResolvedValue({ ...status, sources: [{ ...status.sources[0], installed: true, configured: false, enabled: false,
    activation_state: "disabled", data_state: "never", data_received: false, instances: [] }],
    steps: status.steps.map((step) => ["sources", "first-collection"].includes(step.id) ? { ...step, state: "todo" } : step),
    next_step: { pack_id: status.sources[0].pack_id, source_instance_id: null, action: "configure" } });
  mount();
  const source = await screen.findByRole("group", { name: t("setup.source.name.domainController") });
  expect(within(source).getByText(t("setup.source.installed"))).toBeTruthy();
  expect(within(source).getByText(t("setup.source.notConfigured"))).toBeTruthy();
  expect(within(source).getByText(t("setup.source.disabled"))).toBeTruthy();
  expect(within(source).getByText(t("setup.source.data.never"))).toBeTruthy();
  const href = screen.getByRole("link", { name: new RegExp(`${t("setup.source.name.domainController")} —`) }).getAttribute("href")!;
  expect(document.getElementById(decodeURIComponent(href.slice(1)))).toBe(source);
  expect(within(source).getByRole("link", { name: t("setup.steps.controllers.title") }).getAttribute("href")).toBe("#setup-domain-controllers");
});

it.each([
  { enabled: true, dataState: "never", received: false, firstCollection: "todo", action: "collect" },
  { enabled: true, dataState: "fresh", received: true, firstCollection: "done", action: null },
  { enabled: true, dataState: "stale", received: true, firstCollection: "todo", action: "check_data" },
  { enabled: false, dataState: "fresh", received: true, firstCollection: "todo", action: "enable" },
])("shows $dataState data independently of activation ($enabled)", async ({ enabled, dataState, received, firstCollection, action }) => {
  state.status.mockResolvedValue({ ...status, collection: { collection_enabled: true, block_reason: null, channels: 1, last_success_utc: status.generated_at_utc },
    sources: [{ ...status.sources[0], installed: true, configured: true, enabled,
      activation_state: enabled ? "enabled" : "disabled", data_state: dataState, data_received: received,
      instances: [{ source_instance_id: "source-1", configured: true, enabled, data_received: received, data_state: dataState,
        last_data_utc: received ? status.generated_at_utc : null, next_action: action }] }],
    steps: status.steps.map((step) => step.id === "sources" ? { ...step, state: enabled ? "done" : "todo" }
      : step.id === "first-collection" ? { ...step, state: firstCollection } : step),
    next_step: action ? { pack_id: status.sources[0].pack_id, source_instance_id: "source-1", action } : null });
  mount();
  const source = await screen.findByRole("group", { name: `${t("setup.source.name.domainController")}: source-1` });
  expect(within(source).getByText(t(enabled ? "setup.source.enabled" : "setup.source.disabled"))).toBeTruthy();
  expect(within(source).getByText(t(`setup.source.data.${dataState as "fresh" | "stale" | "never"}`))).toBeTruthy();
  expect(screen.getByText(t("setup.sources.collectionSummary", { count: enabled && dataState === "fresh" ? 1 : 0 }))).toBeTruthy();
  expect(screen.queryByText(t("setup.source.nextStep")) !== null).toBe(Boolean(action));
});

it("keeps an archive labelled with unknown date and offers restore only to managers", async () => {
  state.status.mockResolvedValue({ ...status, domains: [{ fqdn: "old.example.test", netbios_name: null, server_count: 2, is_archived: true }] });
  state.access = { capabilities: [] };
  mount();
  expect(await screen.findByText(/old.example.test/)).toBeTruthy();
  expect(screen.getByText(/дата наблюдения неизвестна/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: /Вернуть в текущие домены/ })).toBeNull();
});

for (const locale of ["ru", "en"] as const) it(`keeps archive observation instant in the selected zone (${locale})`, async () => {
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  const previous = getLocale();
  setLocale(locale);
  state.timeZone = "Asia/Novosibirsk";
  state.status.mockResolvedValue({ ...status, domains: [{ fqdn: "old.example.test", netbios_name: null, server_count: 2, is_archived: true, observed_at_utc: "2026-10-08T23:05:00Z" }] });
  try {
    const view = mount();
    expect(await screen.findByText(locale === "ru" ? /09\.10\.2026, 06:05/ : /Oct 9, 2026, 6:05 AM/)).toBeTruthy();
    state.timeZone = "UTC";
    view.rerender(<QueryClientProvider client={view.client}><OverlayProvider><SetupPage/></OverlayProvider></QueryClientProvider>);
    expect(await screen.findByText(locale === "ru" ? /08\.10\.2026, 23:05/ : /Oct 8, 2026, 11:05 PM/)).toBeTruthy();
  } finally { setLocale(previous); state.timeZone = "UTC"; reload.mockRestore(); }
});

it.each(["ru", "en"] as const)("confirms archive and restore, while cancel and Escape never write (%s)", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  const previous = getLocale(); setLocale(locale);
  state.access = { capabilities: ["access.manage"] };
  state.status.mockResolvedValue(withDomain);
  state.archive.mockResolvedValue({ item: { is_archived: true } });
  try {
    mount();
    const toggle = await screen.findByRole("switch");
    expect(toggle.getAttribute("aria-checked")).toBe("false");
    fireEvent.click(toggle);
    expect(state.archive).not.toHaveBeenCalled();
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: t("domain.archive.cancel") }));
    expect(state.archive).not.toHaveBeenCalled();
    fireEvent.click(toggle); fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(state.archive).not.toHaveBeenCalled();
    fireEvent.click(toggle);
    state.status.mockResolvedValue({ ...withDomain, domains: [{ ...withDomain.domains[0], is_archived: true }] });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: t("domain.archive.confirm") }));
    await waitFor(() => expect(screen.getByRole("switch").getAttribute("aria-checked")).toBe("true"));
    expect(state.archive).toHaveBeenCalledTimes(1);
    expect(state.archive).toHaveBeenCalledWith("corp.example.test", true);
    fireEvent.click(screen.getByRole("switch"));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: t("domain.archive.confirm") }));
    await waitFor(() => expect(state.archive).toHaveBeenCalledWith("corp.example.test", false));
  } finally { cleanup(); setLocale(previous); vi.restoreAllMocks(); }
});

it("keeps archive unchanged on error and suppresses repeated pending clicks", async () => {
  state.access = { capabilities: ["access.manage"] };
  state.status.mockResolvedValue(withDomain);
  let reject!: (error: Error) => void;
  state.archive.mockImplementation(() => new Promise((_resolve, rejectPromise) => { reject = rejectPromise; }));
  mount();
  fireEvent.click(await screen.findByRole("switch"));
  const confirm = within(screen.getByRole("dialog")).getByRole("button", { name: t("domain.archive.confirm") });
  fireEvent.click(confirm); fireEvent.click(confirm);
  await waitFor(() => expect(state.archive).toHaveBeenCalledTimes(1));
  expect((screen.getByRole("switch") as HTMLButtonElement).disabled).toBe(true);
  reject(new Error("unavailable"));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", t("domain.archive.error"));
  expect(screen.getByRole("switch").getAttribute("aria-checked")).toBe("false");
});

const suggestedStatus = { ...status, report_domain: { ...status.report_domain, configured_value: "old.example.test", suggested_value: "corp.example.test" } };

it("offers an explicit domain save and refreshes report defaults without automatic mutation", async () => {
  state.access = { capabilities: ["access.manage"] };
  state.status.mockResolvedValue(suggestedStatus);
  state.saveSetting.mockResolvedValue({});
  const view = mount();
  const invalidate = vi.spyOn(view.client, "invalidateQueries");
  const save = await screen.findByRole("button", { name: t("domain.archive.useSuggested", { domain: "corp.example.test" }) });
  expect(screen.getByText("old.example.test")).toBeTruthy();
  expect(state.saveSetting).not.toHaveBeenCalled();
  fireEvent.click(save); fireEvent.click(save);
  await waitFor(() => expect(state.saveSetting).toHaveBeenCalledTimes(1));
  expect(state.saveSetting).toHaveBeenCalledWith("reports.domain_fqdn", "corp.example.test");
  await waitFor(() => expect(invalidate).toHaveBeenCalledWith({ queryKey: ["report-v2"] }));
});

it.each([null, undefined, ""])("does not invent a recommended domain from missing metadata (%s)", async (suggested_value) => {
  state.access = { capabilities: ["access.manage"] };
  state.status.mockResolvedValue({ ...suggestedStatus, report_domain: { ...suggestedStatus.report_domain, suggested_value } });
  mount(); await screen.findByText("old.example.test");
  expect(screen.queryByRole("button", { name: /Сделать доменом отчётов/ })).toBeNull();
  expect(state.saveSetting).not.toHaveBeenCalled();
});

it("keeps metadata visible without offering writes to a non-manager", async () => {
  state.access = { capabilities: [] };
  state.status.mockResolvedValue({ ...suggestedStatus, domains: withDomain.domains });
  mount(); await screen.findByText("old.example.test");
  expect(screen.queryByRole("switch")).toBeNull();
  expect(screen.queryByRole("button", { name: /Сделать доменом отчётов/ })).toBeNull();
});

it("keeps the saved domain on a failed explicit change and allows retry", async () => {
  state.access = { capabilities: ["access.manage"] };
  state.status.mockResolvedValue(suggestedStatus);
  state.saveSetting.mockRejectedValueOnce(new Error("unavailable")).mockResolvedValueOnce({});
  mount();
  const save = await screen.findByRole("button", { name: t("domain.archive.useSuggested", { domain: "corp.example.test" }) });
  fireEvent.click(save);
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", t("domain.archive.saveError"));
  expect(screen.getByText("old.example.test")).toBeTruthy();
  fireEvent.click(save);
  await waitFor(() => expect(state.saveSetting).toHaveBeenCalledTimes(2));
});


it.each(["ru", "en"] as const)("uses registered DC collection for the active domain without changing legacy settings in %s", async (locale) => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  try {
    state.status.mockResolvedValue({ ...status,
      domains: [{ fqdn: "corp.example.test", forest: "corp.example.test", server_count: 1, is_archived: false }],
      domain_controllers: [{ hostname: "dc1.example.test", connect_address: "dc1.example.test", domain: "corp.example.test", enabled: false, source: "db", dns_readback: true }],
      sources: [{ ...status.sources[0], collection_basis: "agents", configured: true, activation_state: "enabled", instances: [
        { source_instance_id: "DC1.EXAMPLE.TEST", configured: true, enabled: true, collection_state: "current", data_received: true, data_state: "fresh", next_action: null, last_data_utc: null },
        { source_instance_id: "agent-only.example.test", configured: true, enabled: true, collection_state: "current", data_received: true, data_state: "fresh", next_action: null, last_data_utc: null },
      ] }],
      agent_collection: { state: "current", active_agents: 2, current_agents: 2, items: [] },
    });
    mount();
    const table = await screen.findByRole("table", { name: t("setup.dc.tableCaption") });
    expect(within(table).getAllByText(t("operations.agent_collection.state.current"))).toHaveLength(2);
    expect(within(table).queryByText(t("setup.dc.disabled"))).toBeNull();
    expect(within(table).getByText("agent-only.example.test")).toBeTruthy();
    expect(within(table).queryAllByRole("button")).toHaveLength(0);
    const domainTable = screen.getByRole("table", { name: t("setup.domain.tableCaption") });
    expect(within(domainTable).queryByText(t("domain.archive.label"), { exact: false })).toBeNull();
    expect(screen.getByText(t("setup.controllers.currentCount", { count: 2 }))).toBeTruthy();
    expect(state.toggleDc).not.toHaveBeenCalled();
    expect(state.archive).not.toHaveBeenCalled();
  } finally { setLocale(previous); reload.mockRestore(); }
});

it.each(["ru", "en"] as const)("keeps unbound controller unknown and legacy controls explicit in %s", async (locale) => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  try {
    state.access = { capabilities: ["access.manage"] };
    state.status.mockResolvedValue({ ...status,
      domain_controllers: [{ hostname: "dc1.example.test", connect_address: "dc1.example.test", domain: null, enabled: true, source: "db", dns_readback: false }],
      sources: [{ ...status.sources[0], collection_basis: "agents", configured: null, activation_state: "unavailable", instances: [] }],
      agent_collection: { state: "unknown", active_agents: 0, current_agents: 0, items: [] },
    });
    mount();
    const table = await screen.findByRole("table", { name: t("setup.dc.tableCaption") });
    expect(within(table).getByText(t("setup.source.unknown"))).toBeTruthy();
    expect(within(table).getByText(`${t("setup.controllers.targetConfiguration")}: ${t("setup.dc.enabled")}`)).toBeTruthy();
    expect(within(table).getByRole("button", { name: t("setup.dc.actionDisable") })).toBeTruthy();
    expect(within(table).queryByText(t("operations.agent_collection.state.current"))).toBeNull();
    expect(state.toggleDc).not.toHaveBeenCalled();
  } finally { setLocale(previous); reload.mockRestore(); }
});

it.each(["ru", "en"] as const)("keeps incomplete controller observations unavailable in %s", async (locale) => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  try {
    for (const instances of [undefined, [{ source_instance_id: "dc1.example.test", configured: true, enabled: true, data_received: null, data_state: "unavailable", last_data_utc: null, next_action: null }]]) {
      state.status.mockResolvedValue({ ...status,
        sources: [{ ...status.sources[0], collection_basis: "agents", configured: true, activation_state: "enabled", instances }],
        agent_collection: { state: "current", active_agents: 1, current_agents: 1, items: [] },
      });
      const view = mount();
      await screen.findByRole("table", { name: t("setup.dc.tableCaption") });
      const step = document.getElementById("setup-domain-controllers")!;
      expect(within(step).getByText(t("setup.steps.controllers.unavailable"))).toBeTruthy();
      expect(within(step).queryByText(t("setup.controllers.currentCount", { count: 0 }))).toBeNull();
      view.unmount();
    }
  } finally { setLocale(previous); reload.mockRestore(); }
});

it.each(["ru", "en"] as const)("names setup navigation destinations while preserving their URLs in %s", async (locale) => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  try {
    state.status.mockResolvedValue({ ...status,
      sources: [{ ...status.sources[0], collection_basis: "agents", configured: false, activation_state: "disabled", instances: [] }],
      agent_collection: { state: "unknown", active_agents: 0, current_agents: 0, items: [] },
    });
    mount();
    expect((await screen.findByRole("link", { name: t("platformSettings.page.title") })).getAttribute("href")).toBe("/app/platform-settings");
    expect(screen.getByRole("link", { name: t("shell.nav.operations") }).getAttribute("href")).toBe("/app/operations");
    expect(screen.getAllByRole("link", { name: t("agents.title") }).map((link) => link.getAttribute("href"))).toEqual(["/app/agents", "/app/agents"]);
    expect(screen.queryByRole("link", { name: t("setup.step.openPage") })).toBeNull();
    expect(state.addDc).not.toHaveBeenCalled();
    expect(state.toggleDc).not.toHaveBeenCalled();
  } finally { setLocale(previous); reload.mockRestore(); }
});

it.each(["ru", "en"] as const)("names the archive action instead of marking a current domain archived for managers (%s)", async (locale) => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  setLocale(locale);
  state.access = { capabilities: ["access.manage"] };
  try {
    for (const archived of [false, true]) {
      state.status.mockResolvedValue({ ...withDomain, domains: [{ ...withDomain.domains[0], is_archived: archived }] });
      const view = mount();
      const toggle = await screen.findByRole("switch");
      expect(toggle.getAttribute("aria-checked")).toBe(String(archived));
      expect(toggle.textContent).toBe(t(archived ? "domain.archive.restore" : "domain.archive.archive"));
      expect(toggle.textContent).not.toBe(t("domain.archive.toggle"));
      expect(state.archive).not.toHaveBeenCalled();
      view.unmount();
    }
  } finally { setLocale(previous); reload.mockRestore(); }
});

it.each(["ru", "en"] as const)("translates controller sources and known validation errors after selecting %s", async (locale) => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  state.status.mockResolvedValue(withDbControllers);
  state.access = { capabilities: ["access.manage"] };
  state.addDomain.mockRejectedValue(new ApiResponseError(409, "domain_already_exists"));
  state.addDc.mockRejectedValue(new ApiResponseError(409, "domain_controller_already_exists"));
  try {
    mount();
    const table = await screen.findByRole("table", { name: t("setup.dc.tableCaption") });
    expect(within(table).getAllByText(t("setup.dc.source.db"))).toHaveLength(2);
    fireEvent.change(screen.getByLabelText(t("setup.domain.labelFqdn")), { target: { value: "corp.example.test" } });
    fireEvent.click(screen.getByRole("button", { name: t("setup.domain.add") }));
    expect(await screen.findByText(t("setup.domain.error.domain_already_exists"))).toBeTruthy();
    fireEvent.change(screen.getByLabelText(t("setup.dc.labelHostname")), { target: { value: "dc2.corp.example.test" } });
    fireEvent.click(screen.getByRole("button", { name: t("setup.dc.add") }));
    expect(await screen.findByText(t("setup.dc.error.domain_controller_already_exists"))).toBeTruthy();
  } finally { cleanup(); setLocale(previous); reload.mockRestore(); }
});

it("renders the complete English checklist without Russian system text", async () => {
  const previous = getLocale();
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  state.status.mockResolvedValue(withDbControllers);
  state.access = { capabilities: ["access.manage"] };
  try {
    const { container } = mount();
    await screen.findByRole("table", { name: t("setup.dc.tableCaption") });
    expect(container.textContent).not.toMatch(/[А-Яа-яЁё]/);
    expect(state.addDomain).not.toHaveBeenCalled();
    expect(state.addDc).not.toHaveBeenCalled();
    expect(state.toggleDc).not.toHaveBeenCalled();
  } finally { cleanup(); setLocale(previous); reload.mockRestore(); }
});

it.each(["toString", "__proto__", "future_validation"])("preserves unknown validation code %s without treating it as a message key", async (code) => {
  state.status.mockResolvedValue(withDbControllers);
  state.access = { capabilities: ["access.manage"] };
  state.addDomain.mockRejectedValue(new ApiResponseError(409, code));
  state.addDc.mockRejectedValue(new ApiResponseError(409, code));
  mount();
  fireEvent.change(await screen.findByLabelText(t("setup.domain.labelFqdn")), { target: { value: "corp.example.test" } });
  fireEvent.click(screen.getByRole("button", { name: t("setup.domain.add") }));
  expect(await screen.findByText(code)).toBeTruthy();
  fireEvent.change(screen.getByLabelText(t("setup.dc.labelHostname")), { target: { value: "dc2.corp.example.test" } });
  fireEvent.click(screen.getByRole("button", { name: t("setup.dc.add") }));
  await waitFor(() => expect(screen.getAllByText(code)).toHaveLength(2));
});

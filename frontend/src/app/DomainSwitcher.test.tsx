// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Link, Outlet, RouterProvider } from "@tanstack/react-router";
import { api, type HomeSummaryV2, type WorkspaceDomain } from "../api/client";
import { DomainSwitcher } from "./DomainSwitcher";
import { domainSearchMiddleware, selectedDomain, withDomain } from "./domain-navigation";

const access = { capabilities: ["workspace.view"] } as Awaited<ReturnType<typeof api.v4Access>>;
const domain = (id: number, partial = false): WorkspaceDomain => ({ id, display_name: `domain-${id}.example.test`,
  freshness: { snapshot_state: partial ? "partial" : "complete", observed_at_utc: "2026-10-17T00:00:00Z" } });
const summary = (items: WorkspaceDomain[]): HomeSummaryV2 => ({
  problems_found: { count: 12 }, domains: items.map((item) => ({ ...item, summary: {
    problems_found: { count: item.id === 1 ? 12 : item.id === 2 ? 0 : null }, observation_health: { state: "ok" },
  } })),
} as HomeSummaryV2);

async function show(items = [domain(1), domain(2, true)], initial = "/") {
  vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
  vi.spyOn(api, "domains").mockResolvedValue({ items });
  vi.spyOn(api, "homeSummaryV2").mockResolvedValue(summary(items));
  const root = createRootRoute({ search: { middlewares: [domainSearchMiddleware] }, component: () => <>
    <DomainSwitcher access={access}/><Link to="/report/$reportKey" params={{ reportKey: "ad.users.v2" }}>Users</Link>
    <Link to="/report/$reportKey" params={{ reportKey: "ad.computers.v6" }}>Computers</Link><Link to="/">Home</Link><Outlet/>
  </> });
  const home = createRoute({ getParentRoute: () => root, path: "/", component: () => <h1>Home page</h1> });
  const report = createRoute({ getParentRoute: () => root, path: "/report/$reportKey", component: () => <h1>Report</h1> });
  const router = createRouter({ routeTree: root.addChildren([home, report]), history: createMemoryHistory({ initialEntries: [initial] }) });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
  await router.load();
  await waitFor(() => expect(api.domains).toHaveBeenCalled());
  return { router, client };
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("does not request the home summary on a report until the domain menu is opened", async () => {
  await show(undefined, "/report/ad.users.v2");
  const trigger = await screen.findByLabelText("Домен: Все домены");
  expect(api.homeSummaryV2).not.toHaveBeenCalled();
  fireEvent.click(trigger);
  await waitFor(() => expect(api.homeSummaryV2).toHaveBeenCalledTimes(1));
  fireEvent.click(trigger);
  fireEvent.click(screen.getByRole("link", { name: "Computers" }));
  await screen.findByText("Report");
  expect(api.homeSummaryV2).toHaveBeenCalledTimes(1);
});

it("hides the switcher when no domains are accessible", async () => {
  const { client } = await show([]);
  await waitFor(() => expect(client.getQueryState(["domains", access])?.status).toBe("success"));
  expect(screen.queryByLabelText(/^Домен:/)).toBeNull();
  expect(api.homeSummaryV2).not.toHaveBeenCalled();
});

it("shows the switcher for a single accessible domain without requesting counts", async () => {
  await show([domain(1)]);
  fireEvent.click(await screen.findByLabelText("Домен: Все домены"));
  expect(screen.getByRole("button", { name: /domain-1\.example\.test/ })).toBeTruthy();
  expect(api.homeSummaryV2).not.toHaveBeenCalled();
});

it("shows authorized counts without warnings, incomplete domains first and hides zero", async () => {
  await show();
  fireEvent.click(await screen.findByLabelText("Домен: Все домены"));
  const menu = screen.getByLabelText("Домен");
  await waitFor(() => expect(within(menu).getAllByText("12")).toHaveLength(2));
  const options = within(menu).getAllByRole("button");
  expect(within(menu).queryByRole("img")).toBeNull();
  expect(menu.querySelector(".sli-ds-state--banner")).toBeNull();
  expect(options.map((item) => item.textContent)).toEqual(["Все домены12", "domain-2.example.test", "domain-1.example.test12"]);
  expect(screen.queryByRole("searchbox")).toBeNull();
});

it("searches seven or more domains and keeps all domains available", async () => {
  await show(Array.from({ length: 7 }, (_, index) => domain(index + 1)));
  fireEvent.click(await screen.findByLabelText("Домен: Все домены"));
  fireEvent.change(screen.getByRole("searchbox"), { target: { value: "DOMAIN-3" } });
  const menu = screen.getByLabelText("Домен");
  expect(within(menu).getAllByRole("button")).toHaveLength(2);
  expect(within(menu).getByRole("button", { name: /domain-3.*—/ })).toBeTruthy();
  fireEvent.change(screen.getByRole("searchbox"), { target: { value: "missing" } });
  expect(within(menu).getByText("Домены не найдены")).toBeTruthy();
});

it("preserves selection through home, both AD reports and history, then clears it", async () => {
  const { router } = await show();
  fireEvent.click(await screen.findByLabelText("Домен: Все домены"));
  fireEvent.click(screen.getByRole("button", { name: /domain-2/ }));
  await waitFor(() => expect(selectedDomain(router.state.location.searchStr)).toBe("2"));
  for (const label of ["Users", "Computers", "Home"]) {
    fireEvent.click(screen.getByRole("link", { name: label }));
    await waitFor(() => expect(router.state.location.pathname).toBe(label === "Home" ? "/" : `/report/${label === "Users" ? "ad.users.v2" : "ad.computers.v6"}`));
    expect(selectedDomain(router.state.location.searchStr)).toBe("2");
    expect(within(screen.getByLabelText("Домен: domain-2.example.test")).getByText("domain-2.example.test")).toBeTruthy();
  }
  await act(async () => { router.history.back(); });
  await waitFor(() => expect(router.state.location.pathname).toBe("/report/ad.computers.v6"));
  fireEvent.click(screen.getByLabelText("Домен: domain-2.example.test"));
  expect(screen.getByRole("button", { name: /domain-2/, current: true })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /Все домены/ }));
  await waitFor(() => expect(selectedDomain(router.state.location.searchStr)).toBeNull());
  expect(await screen.findByLabelText("Домен: Все домены")).toBeTruthy();
  fireEvent.click(screen.getByRole("link", { name: "Users" }));
  await waitFor(() => expect(router.state.location.pathname).toBe("/report/ad.users.v2"));
  expect(selectedDomain(router.state.location.searchStr)).toBeNull();
});

it("restores a domain_id deep link and never labels unavailable counts zero", async () => {
  const { client } = await show(undefined, "/?domain_id=2");
  const trigger = await screen.findByLabelText("Домен: domain-2.example.test");
  fireEvent.click(trigger);
  await waitFor(() => expect(client.getQueryData(["domains", "summary", access])).toBeDefined());
  vi.mocked(api.homeSummaryV2).mockRejectedValue(new Error("synthetic-unavailable"));
  await act(async () => { await client.invalidateQueries({ queryKey: ["domains", "summary"] }); });
  const menu = screen.getByLabelText("Домен");
  await waitFor(() => expect(within(menu).getAllByText("—")).toHaveLength(3));
  expect(menu.textContent).not.toContain("12");
  fireEvent.keyDown(menu, { key: "Escape" });
  expect(menu.closest("details")?.open).toBe(false);
  expect(document.activeElement).toBe(trigger);
});

it("preserves scope on plain report links without overriding explicit scope", () => {
  expect(withDomain("/app/report/ad.users.v2?tab=active", "?domain_id=2")).toBe("/app/report/ad.users.v2?tab=active&domain=2");
  expect(withDomain("/app/report/ad.users.v2?domain=1", "?domain=2")).toBe("/app/report/ad.users.v2?domain=1");
});

it("keeps archive selectable and labels its observation date without treating age as lifecycle", async () => {
  await show([domain(1), { ...domain(2), is_archived: true }]);
  fireEvent.click(await screen.findByLabelText("Домен: Все домены"));
  expect(screen.getByRole("button", { name: /domain-2.*Архив.*17\.10\.2026/ })).toBeTruthy();
});

it("carries explicit All through router middleware and new-tab links", () => {
  expect(withDomain("/app/report/ad.computers.v6", "?scope=all")).toBe("/app/report/ad.computers.v6?scope=all");
  expect(domainSearchMiddleware({ search: { scope: "all" }, next: () => ({}) } as never)).toEqual({ scope: "all" });
});

it("allows explicitly opening the only authorized domain when it is archived", async () => {
  const { router } = await show([{ ...domain(1), is_archived: true }]);
  fireEvent.click(await screen.findByLabelText("Домен: Все домены"));
  fireEvent.click(screen.getByRole("button", { name: /domain-1.*Архив/ }));
  await waitFor(() => expect(selectedDomain(router.state.location.searchStr)).toBe("1"));
});

it("formats the archive timestamp in English without leaking the ISO value", async () => {
  const { localeRuntime, setLocale } = await import("../i18n");
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  try {
    await show([{ ...domain(1), is_archived: true }]);
    fireEvent.click(await screen.findByLabelText("Domain: All domains"));
    const item = screen.getByRole("button", { name: /domain-1.*Archive/ });
    expect(item.textContent).toContain("Oct 17, 2026");
    expect(item.textContent).not.toMatch(/2026-10-17T|17\.10\.2026/);
  } finally { setLocale("ru"); }
});

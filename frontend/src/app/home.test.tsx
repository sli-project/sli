/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { HomePeriod } from "../api/home-period";
import { localeRuntime, setLocale, t } from "../i18n";
import { HomePage } from "./home";

vi.mock("./App", () => ({
  useTimeZone: () => ({ timeZone: "UTC" }),
  useEffectiveAccess: () => undefined,
  useAccessStatus: () => "получены",
}));
const route = vi.hoisted(() => ({ searchStr: "?domain=7", navigate: vi.fn() }));
vi.mock("@tanstack/react-router", () => ({ useLocation: () => route, useNavigate: () => route.navigate }));
const example = {
  domains: [{ id: 7, name: "example.test" }, { id: 8, name: "second.example.test" }],
  domain_id: 7, from: "2026-11-21T02:00:00Z", to: "2026-11-22T02:00:00Z", updated_at: "2026-11-22T02:00:05Z",
  problems: {
    open_count: 131, unassigned_count: 85, in_work_count: 46, page: null, href: "/app/report/security.problems?domain=7",
    items: [{
      id: 12, name: "DC01", fact: "Security log cleared on DC01", severity: "high", at: "2026-11-22T01:15:00Z",
      status: "active", assignee: "analyst-example", assignee_state: "assigned", occurrence_count: 3,
      source: null, href: "/app/report/security.problems?domain=7&id=12", object_href: "/app/entities/3",
      observations: [{ at: "2026-11-22T01:15:00Z", event_id: 1102, source: "DC01.example.test", href: "/app/events/37" }],
    }],
  },
  controllers: {
    href: "/app/report/ad.infrastructure?domain=7",
    items: [
      { id: 3, name: "DC01", at: "2026-11-22T01:22:00Z", passed: 4, failures: [{ key: "dns", actual: "failed" }], href: "/app/entities/3" },
      { id: 4, name: "DC02", at: "2026-11-22T01:22:00Z", passed: 5, failures: [], href: "/app/entities/4" },
    ],
  },
  changes: {
    href: "/app/report/security.events.chains?domain=7",
    items: [{ at: "2026-11-22T01:25:00Z", name: "service-example", event_id: 4720, initiator: "admin-example", value: null, href: "/app/events/38" }],
  },
} satisfies HomePeriod;

beforeEach(() => {
  sessionStorage.clear();
  route.searchStr = "?domain=7";
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

function show(respond: (url: string) => HomePeriod | Response = () => example) {
  const request = vi.fn(async (url: string) => {
    const result = respond(url);
    return result instanceof Response ? result : Response.json(result);
  });
  vi.stubGlobal("fetch", request);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><HomePage/></QueryClientProvider>);
  return request;
}

it("shows the open queue, repeats, review links and only failed checks", async () => {
  const request = show();
  const problems = await screen.findByRole("table", { name: t("home.problems") });
  expect(screen.getByRole("tab", { name: /131/, selected: true })).toBeTruthy();
  expect(screen.getByRole("tab", { name: /85/ })).toBeTruthy();
  expect(screen.getByRole("tab", { name: /46/ })).toBeTruthy();
  expect(within(problems).getByText("High").textContent).toContain("◆");
  expect(within(problems).getByText("×3")).toBeTruthy();
  expect(within(problems).getByText("analyst-example")).toBeTruthy();
  expect(within(problems).getByRole("link", { name: t("home.status.active") }).getAttribute("href")).toContain("id=12");
  fireEvent.keyDown(within(problems).getByText(example.problems.items[0].fact).closest("tr")!, { key: "Enter" });
  const observations = within(problems).getByRole("table", { name: t("home.observations") });
  expect(within(observations).getByRole("link").getAttribute("href")).toBe("/app/events/37");
  const controllers = screen.getByRole("table", { name: t("home.controllers") });
  expect(within(controllers).getByText("DNS · Failed")).toBeTruthy();
  expect(within(controllers).queryByText("DC02")).toBeNull();
  expect(within(controllers).queryByRole("combobox")).toBeNull();
  const changes = screen.getByRole("table", { name: t("home.changes") });
  expect(within(changes).getByText(/Account created/)).toBeTruthy();
  expect(within(changes).getByText("admin-example")).toBeTruthy();
  expect(screen.getByRole("link", { name: t("home.domainChanges") }).getAttribute("href"))
    .toContain("security.events.chains");
  expect(screen.queryByRole("figure")).toBeNull();
  expect(request).toHaveBeenCalledTimes(1);
});

it("requests server pages and keeps whole-population totals on filtered pages", async () => {
  const request = show((url) => url.includes("queue=unassigned") ? {
    ...example, problems: { ...example.problems, items: [{ ...example.problems.items[0], name: "unassigned-example",
      assignee: null, assignee_state: "unassigned" }] },
  } : example);
  await screen.findByRole("table", { name: t("home.problems") });
  fireEvent.click(screen.getByRole("tab", { name: /85/ }));
  await screen.findByText("unassigned-example");
  const query = (index: number) => new URL(request.mock.calls[index][0], "http://localhost").searchParams;
  expect(query(1).get("queue")).toBe("unassigned");
  expect(screen.getByRole("tab", { name: /131/ })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("table.next") }));
  await waitFor(() => expect(query(2).get("page")).toBe("2"));
  fireEvent.click(screen.getByRole("radio", { name: "100" }));
  await waitFor(() => expect(query(3).get("limit")).toBe("100"));
  expect(query(3).get("page")).toBe("1");
});

it("updates the previous window without losing the current open queue", async () => {
  const request = show((url) => url.includes("period=custom") ? {
    ...example, from: "2026-11-20T02:00:00Z", to: example.from, changes: { ...example.changes, items: [] },
  } : example);
  await screen.findByText("admin-example");
  fireEvent.click(screen.getByRole("button", { name: t("home.period.previous") }));
  await screen.findByText(t("home.changes.empty"));
  expect(screen.getByRole("table", { name: t("home.problems") })).toBeTruthy();
  const query = new URL(request.mock.calls[1][0], "http://localhost").searchParams;
  expect(query.get("from")).toBe("2026-11-20T02:00:00.000Z");
  expect(query.get("to")).toBe("2026-11-21T02:00:00.000Z");
});

it("omits infrastructure when every check passed", async () => {
  show(() => ({ ...example, controllers: { ...example.controllers, items: example.controllers.items.slice(1) } }));
  await screen.findByRole("table", { name: t("home.problems") });
  expect(screen.queryByRole("heading", { name: t("home.controllers") })).toBeNull();
});

it.each(["problems", "controllers", "changes"] as const)("retries the failed %s block while leaving the others visible", async (block) => {
  let response: HomePeriod = { ...example, [block]: null };
  const request = show(() => response);
  expect((await screen.findByRole("alert")).textContent).toContain(t(`home.loadFailed.${block}`));
  for (const other of ["problems", "controllers", "changes"] as const) {
    if (other !== block) screen.getByRole("table", { name: t(`home.${other}`) });
  }
  response = example;
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  await screen.findByRole("table", { name: t(`home.${block}`) });
  expect(screen.queryByRole("alert")).toBeNull();
  expect(request).toHaveBeenCalledTimes(2);
});

it("recovers when the summary request fails before any block has loaded", async () => {
  let response: HomePeriod | Response = new Response(null, { status: 503 });
  show(() => response);
  expect((await screen.findByRole("alert")).textContent).toContain(t("home.loadFailed"));
  response = example;
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  await screen.findByRole("table", { name: t("home.problems") });
});

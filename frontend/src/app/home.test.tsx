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
  active_operator_count: 2,
  since_previous_login: { from: "2026-11-19T02:00:00Z", to: "2026-11-22T02:00:05Z",
    new_count: 3, closed_count: 2, new_href: "/app/report/security.problems?domain=7&created_from=2026-11-19T02:00:00Z&created_to=2026-11-22T02:00:05Z" },
  problems: {
    open_count: 131, unassigned_count: 85, in_work_count: 46, page: null, href: "/app/report/security.problems?domain=7",
    items: [{
      id: 12, name: "DC01", fact: "Security log cleared on DC01", severity: "high", at: "2026-11-22T01:15:00Z",
      status: "active", assignee: "analyst-example", assignee_state: "assigned", occurrence_count: 3,
      source: null, href: "/app/report/security.problems?domain=7&id=12", object_href: "/app/entities/3",
      observations: [{ at: "2026-11-22T01:15:00Z", event_id: 1102, source: "DC01.example.test", href: "/app/events/37" }],
    }],
  },
  weak_spots: {
    failed: [],
    items: [
      { id: "ad:dns", label: "DNS", count: 2, report: "ad.infrastructure", href: "/app/report/ad.infrastructure?domain=7&qualification=failed&q=dns" },
      { id: "user:inactive", label: "Inactive accounts", count: 4, report: "ad.users.v2", href: "/app/report/ad.users.v2?domain=7&tab=checks&check=inactive_enabled" },
      { id: "computer:laps", label: "Expired LAPS passwords", count: 1, report: "ad.computers.v6", href: "/app/report/ad.computers.v6?domain=7&tab=checks" },
      { id: "gpo:version", label: "AD and SYSVOL versions differ", count: 1, report: "ad.gpo.v2", href: "/app/report/ad.gpo.v2?domain=7&tab=gpos&view=attention" },
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
  expect(within(problems).getByText(/Nov 22.*1:15 AM/)).toBeTruthy();
  expect(within(problems).getByRole("link", { name: t("home.status.active") }).getAttribute("href")).toContain("id=12");
  fireEvent.keyDown(within(problems).getByText(example.problems.items[0].fact).closest("tr")!, { key: "Enter" });
  const observations = within(problems).getByRole("table", { name: t("home.observations") });
  expect(within(observations).getByRole("link").getAttribute("href")).toBe("/app/events/37");
  const weaknesses = screen.getByRole("table", { name: t("home.weakSpots") });
  for (const check of example.weak_spots.items) {
    const row = within(weaknesses).getByText(check.label).closest("tr")!;
    expect(within(row).getByText(String(check.count))).toBeTruthy();
    expect(within(row).getByRole("link").getAttribute("href")).toBe(check.href);
  }
  const changes = screen.getByRole("table", { name: t("home.changes") });
  expect(within(changes).getByText(/Account created/)).toBeTruthy();
  expect(within(changes).getByText("admin-example")).toBeTruthy();
  expect(screen.getByRole("link", { name: t("home.domainChanges") }).getAttribute("href"))
    .toContain("security.events.chains");
  expect(screen.queryByRole("figure")).toBeNull();
  expect(request).toHaveBeenCalledTimes(1);
});

it("shows the password problem totals alongside the event sample size", async () => {
  const finding = {
    ...example.problems.items[0], name: "Accounts: 18", fact: "Failed attempts: 2,002",
    observations_are_sample: true,
  };
  show(() => ({ ...example, problems: { ...example.problems, items: [finding] } }));

  const accounts = await screen.findByRole("link", { name: "Accounts: 18" });
  const row = accounts.closest("tr")!;
  expect(within(row).getByText("Failed attempts: 2,002")).toBeTruthy();
  fireEvent.keyDown(row, { key: "Enter" });
  expect(screen.getByRole("table", { name: "Event sample (1)" })).toBeTruthy();
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

it("omits Weak spots when every check passed", async () => {
  show(() => ({ ...example, weak_spots: { ...example.weak_spots, items: [] } }));
  await screen.findByRole("table", { name: t("home.problems") });
  expect(screen.queryByRole("heading", { name: t("home.weakSpots") })).toBeNull();
});

it("hides assignment controls for a single operator with a saved unassigned filter", async () => {
  sessionStorage.setItem("sli.home.queue:7", JSON.stringify({ filter: "unassigned", limit: 25, page: 2 }));
  show(() => ({ ...example, active_operator_count: 1 }));
  const problems = await screen.findByRole("table", { name: t("home.problems") });
  expect(screen.getByRole("tab", { name: /131/, selected: true })).toBeTruthy();
  expect(screen.queryByRole("tab", { name: /85/ })).toBeNull();
  expect(within(problems).queryByRole("columnheader", { name: t("home.assignee") })).toBeNull();
  expect(within(problems).queryByText("analyst-example")).toBeNull();
});

it("shows the sign-in delta and links new problems to the server's time bounds", async () => {
  show();
  const link = await screen.findByRole("link", { name: "+3 new" });
  expect(link.getAttribute("href")).toBe(example.since_previous_login.new_href);
  expect(link.closest("header")?.textContent).toContain("Since previous sign-in: +3 new · −2 closed");
});

it("omits the sign-in delta when there is no previous sign-in", async () => {
  show(() => ({ ...example, since_previous_login: null }));
  await screen.findByRole("table", { name: t("home.problems") });
  expect(screen.queryByText(/Since previous sign-in/)).toBeNull();
});

it.each(["problems", "weak_spots", "changes"] as const)("retries the failed %s block while leaving the others visible", async (block) => {
  const name = block === "weak_spots" ? "weakSpots" : block;
  let response: HomePeriod = { ...example, [block]: null };
  const request = show(() => response);
  expect((await screen.findByRole("alert")).textContent).toContain(t(`home.loadFailed.${name}`));
  for (const other of ["problems", "weakSpots", "changes"] as const) {
    if (other !== name) screen.getByRole("table", { name: t(`home.${other}`) });
  }
  response = example;
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  await screen.findByRole("table", { name: t(`home.${name}`) });
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

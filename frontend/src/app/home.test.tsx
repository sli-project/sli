/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { HomePeriod } from "../api/home-period";
import { localeRuntime, setLocale } from "../i18n";
import { HomePage } from "./home";

vi.mock("./App", () => ({
  useTimeZone: () => ({ timeZone: "UTC" }),
  useEffectiveAccess: () => undefined,
  useAccessStatus: () => "получены",
}));
const route = vi.hoisted(() => ({ searchStr: "?domain=7", navigate: vi.fn() }));
vi.mock("@tanstack/react-router", () => ({ useLocation: () => route, useNavigate: () => route.navigate }));
vi.mock("../design-system/Chart", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../design-system/Chart")>();
  return {
    ...actual,
    Chart: ({ title, spec }: Parameters<typeof actual.Chart>[0]) => <figure aria-label={title}>
      {spec.kind === "timeseries" && spec.series.map((series) =>
        <div key={series.name} aria-label={series.name}>{JSON.stringify(series.points.map((point) => point.y))}</div>)}
    </figure>,
  };
});

const example = {
  domains: [{ id: 7, name: "example.test" }, { id: 8, name: "second.example.test" }],
  domain_id: 7, from: "2026-11-21T02:00:00Z", to: "2026-11-22T02:00:00Z", updated_at: "2026-11-22T02:00:05Z",
  problems: {
    new_count: 2, closed_count: 1, open_count: 4, href: "/app/report/security.problems?domain=7",
    items: [{
      id: 12, name: "DC01", fact: "Security log cleared on DC01", severity: "high", at: "2026-11-22T01:15:00Z",
      source: "DC01.example.test", href: "/app/report/security.problems?domain=7&id=12", object_href: "/app/entities/3",
      events_href: "/app/report/events.journal?domain=7&account=DC01",
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
    href: "/app/report/events.journal?domain=7",
    items: [{ at: "2026-11-22T01:25:00Z", name: "service-example", event_id: 4720, initiator: "admin-example", value: null, href: "/app/events/38" }],
  },
  activity: {
    hours: [{ at: "2026-11-22T01:00:00Z", failed: 105, succeeded: 42, typical: 4 }],
    markers: [{ severity: "high", at: "2026-11-22T01:15:00Z" }],
  },
} satisfies HomePeriod;

beforeEach(() => {
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

it("renders all four blocks from the requested domain and opens Problems from the object and observation links", async () => {
  const request = show();
  const problems = await screen.findByRole("table", { name: "New and important in this period" });
  expect(request.mock.calls[0][0]).toBe("/api/v1/home/summary?domain_id=7&tz=UTC&period=24h&contract=v4");
  expect(screen.getByText("New in period 2 · Closed in period 1 · Open total 4")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Problems queue: 4 open →" }).getAttribute("href")).toBe("/app/report/security.problems?domain=7");
  expect(within(problems).getByText("High").textContent).toContain("◆");
  expect(within(problems).getByRole("link", { name: "DC01" }).getAttribute("href")).toBe("/app/report/security.problems?domain=7&id=12");
  fireEvent.keyDown(within(problems).getByText("Security log cleared on DC01").closest("tr")!, { key: "Enter" });
  const observations = within(problems).getByRole("table", { name: "Observations" });
  expect(within(observations).getByRole("link", { name: "Security log cleared" }).getAttribute("href")).toBe("/app/events/37");
  expect(within(problems).getByRole("link", { name: "Problem" }).getAttribute("href")).toBe("/app/report/security.problems?domain=7&id=12");
  expect(within(problems).getByRole("link", { name: "Object card" }).getAttribute("href")).toBe("/app/entities/3");
  expect(within(problems).getByRole("link", { name: "Object events" }).getAttribute("href")).toBe("/app/report/events.journal?domain=7&account=DC01");
  const controllers = screen.getByRole("table", { name: "Domain controller status" });
  expect(within(controllers).getAllByRole("row")[1].textContent).toContain("DNS");
  expect(within(controllers).getByText("All 5 checks passed")).toBeTruthy();
  const changes = screen.getByRole("table", { name: "Permission and configuration changes" });
  expect(within(changes).getByText("Account created")).toBeTruthy();
  expect(within(changes).getByText("admin-example · 4720")).toBeTruthy();
  expect(within(screen.getByLabelText("Activity in this period")).getByLabelText("Failed logons").textContent).toBe("[105]");
});

it("loads the adjacent previous window and returns to the current period", async () => {
  const request = show((url) => url.includes("period=custom") ? {
    ...example, from: "2026-11-20T02:00:00Z", to: example.from, problems: { ...example.problems, new_count: 0, items: [] },
  } : example);
  const previous = screen.getByRole("button", { name: "Previous period" });
  await screen.findByText("New in period 2 · Closed in period 1 · Open total 4");
  fireEvent.click(previous);
  await screen.findByText("New in period 0 · Closed in period 1 · Open total 4");
  const query = new URL(request.mock.calls[1][0], "http://localhost").searchParams;
  expect(query.get("from")).toBe("2026-11-20T02:00:00.000Z");
  expect(query.get("to")).toBe("2026-11-21T02:00:00.000Z");
  fireEvent.click(previous);
  await screen.findByText("New in period 2 · Closed in period 1 · Open total 4");
});

it("refetches after a manual refresh and retains the selected domain", async () => {
  const request = show();
  await screen.findByRole("table", { name: "Domain controller status" });
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
  expect(request.mock.calls[1][0]).toBe(request.mock.calls[0][0]);
});

const blocks = [
  ["problems", "Новое и важное за период", "Не удалось загрузить новые и важные проблемы"],
  ["controllers", "Состояние контроллеров домена", "Не удалось загрузить состояние контроллеров домена"],
  ["changes", "Изменения прав и настроек", "Не удалось загрузить изменения прав и настроек"],
  ["activity", "Активность за период", "Не удалось загрузить активность за период"],
] as const;

it.each(blocks)("recovers the %s block while keeping the other blocks visible", async (block, title, message) => {
  setLocale("ru");
  let response: HomePeriod = { ...example, [block]: null };
  const request = show(() => response);
  const error = await screen.findByRole("alert");
  expect(error.textContent).toContain(message);
  for (const [other, label] of blocks) {
    if (other !== block) screen.getByRole(other === "activity" ? "figure" : "table", { name: label });
  }
  response = example;
  fireEvent.click(screen.getByRole("button", { name: "Повторить" }));
  await screen.findByRole(block === "activity" ? "figure" : "table", { name: title });
  expect(screen.queryByRole("alert")).toBeNull();
  expect(request).toHaveBeenCalledTimes(2);
  expect(request.mock.calls[1][0]).toBe(request.mock.calls[0][0]);
});

it("recovers when the summary request fails before any block has loaded", async () => {
  let response: HomePeriod | Response = new Response(null, { status: 503 });
  show(() => response);
  expect((await screen.findByRole("alert")).textContent).toContain("Could not load Home");
  response = example;
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await screen.findByRole("table", { name: "Domain controller status" });
});

it("shows dashes for missing counts, controller checks and time, and change initiator", async () => {
  show(() => ({
    ...example,
    problems: { ...example.problems, new_count: null, closed_count: 0, open_count: null },
    controllers: { ...example.controllers, items: [{ id: 5, name: "DC03", at: null, passed: 0, failures: [], href: null }] },
    changes: { ...example.changes, items: [{ at: "2026-11-22T01:25:00Z", name: "service-example", event_id: 4720, initiator: null, value: null }] },
  }));
  await screen.findByText("New in period — · Closed in period 0 · Open total —");
  screen.getByRole("link", { name: "Problems queue: — open →" });
  const controller = screen.getByRole("row", { name: /DC03/ });
  expect(within(controller).getAllByRole("cell").slice(1).map((cell) => cell.textContent)).toEqual(["—", "—", "—"]);
  screen.getByRole("cell", { name: "— · 4720" });
});

it("keeps an unobserved activity hour separate from an observed zero", async () => {
  show(() => ({ ...example, activity: { hours: [
    { at: "2026-11-22T00:00:00Z", failed: null, succeeded: null, typical: null },
    { at: "2026-11-22T01:00:00Z", failed: 0, succeeded: 2, typical: 4 },
  ], markers: [] } }));
  const activity = within(await screen.findByRole("figure", { name: "Activity in this period" }));
  expect(activity.getByLabelText("Failed logons").textContent).toBe("[null,0]");
  expect(activity.getByLabelText("Successful logons").textContent).toBe("[null,2]");
  expect(activity.getByLabelText("Typical").textContent).toBe("[null,4]");
});

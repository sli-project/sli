// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale, t } from "../../i18n";
import { TimeZoneContext } from "../../shared/time-zone";
import * as app from "../App";
import { ReportRenderer } from "./ReportRenderer";
import type { Problem } from "./problems-model";

const definition: ReportDefinitionDto = {
  key: "security.problems", title: "Problems", section: "investigation", description: "", archetype: "queue",
  params: [{ key: "q", kind: "text", label: "Search" }], columns: [], views: [{ key: "queue", kind: "custom", component: "problems.workplace" }],
  row_key: "id", detail: "none", limits: { default: 50, max: 200 }, export: false, presets: [], row_links: [], filter_options: {},
};
const time = "2026-11-22T01:34:00Z";
const critical: Problem = {
  id: 7, title: "Successful sign-in", kind: "success", severity: "critical", status: "new", account: "svc-backup",
  object: "svc-backup", source: "203.0.113.11", addresses: ["203.0.113.11"], computer: "<dc01.example.test>",
  attempts: 125, first_attempt: "2026-11-22T01:21:00Z", success_at: time, last_seen_utc: time, has_journal: true,
};
const spray: Problem = {
  id: 8, title: "Password spraying", kind: "spray", severity: "medium", status: "active",
  source: "198.51.100.77", accounts: 12, attempts: 36, last_seen_utc: time,
  breakdown: Array.from({ length: 12 }, (_, index) => ({ object: `target-${index + 1}`, source: "198.51.100.77", accounts: 1, attempts: 3, at: time })),
};
const audit: Problem = {
  id: 9, title: "Logon auditing disabled", kind: "audit", severity: "high", status: "new", object: "dc02.example.test",
  actor: "adm.example", last_seen_utc: time,
};

let population: Problem[];
let requestFailed: boolean;
let calls: URLSearchParams[];

function response(items: Problem[], open: number, closed: number): ReportResultDto {
  return {
    contract_id: "sli.report-result.v2", report_key: definition.key, state: items.length ? "ok" : "empty",
    items, filtered_count: items.length, queue_counts: { open, closed }, has_more: false, next_cursor: null,
    metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {},
  };
}

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  vi.setSystemTime(new Date("2026-11-22T02:00:00Z"));
  population = [critical, audit, spray];
  calls = [];
  requestFailed = false;
  window.history.replaceState(null, "", "/app/report/security.problems");
  vi.spyOn(app, "useEffectiveAccess").mockReturnValue({
    capabilities: ["investigations.manage", "evidence.exact"], reports: [{ report_key: "events.explorer", allowed: true }],
  } as ReturnType<typeof app.useEffectiveAccess>);
  vi.spyOn(api, "reportV2Definition").mockResolvedValue(definition);
  vi.spyOn(api, "reportV2Data").mockImplementation(async (_, params) => {
    calls.push(new URLSearchParams(params));
    if (requestFailed) throw new Error("Synthetic queue load failure");
    if (params.has("id")) return response(population.filter((problem) => String(problem.id) === params.get("id")), 0, 0);
    const severity = params.get("severity"), search = params.get("q")?.toLowerCase() ?? "";
    const filtered = population.filter((problem) => (!severity || problem.severity === "critical" || severity === "high" && problem.severity === "high")
      && [problem.object, problem.source, problem.account, problem.computer, ...problem.breakdown?.map(({ object }) => object) ?? []]
        .some((value) => value?.toLowerCase().includes(search)));
    const closed = filtered.filter((problem) => problem.status === "closed");
    const open = filtered.filter((problem) => problem.status !== "closed");
    return response((params.get("queue_tab") === "closed" ? closed : open).map(({ breakdown: _, ...problem }) => problem), open.length, closed.length);
  });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.unstubAllGlobals(); vi.useRealTimers(); vi.restoreAllMocks(); });

function renderQueue() {
  return render(<TimeZoneContext.Provider value={{ timeZone: "Asia/Bangkok", setTimeZone: () => undefined }}>
    <QueryClientProvider client={new QueryClient()}><ReportRenderer reportKey={definition.key}/></QueryClientProvider>
  </TimeZoneContext.Provider>);
}

it("expands an attack into ten observation rows, then shows the rest without additional selections", async () => {
  renderQueue();
  const table = await screen.findByRole("table");
  const expand = within(table).getByRole("button", { name: /Expand Accounts/ });
  fireEvent.click(expand);
  await within(table).findByText("target-10");
  expect(within(table).queryByText("target-11")).toBeNull();
  expect(within(table).getByRole("row", { name: /target-1 Attempts · 3 198.51.100.77/ })).toBeTruthy();
  fireEvent.click(within(table).getByRole("button", { name: "2 more · Show all" }));
  expect(within(table).getByText("target-12")).toBeTruthy();
  expect(within(table).getAllByRole("checkbox")).toHaveLength(4);
  fireEvent.click(within(table).getByRole("button", { name: /Collapse Accounts/ }));
  expect(within(table).queryByText("target-1")).toBeNull();
});

it("selects all displayed problems, closes them in one request and reopens them in one request", async () => {
  const change = vi.spyOn(api, "updateProblems").mockImplementation(async (ids, status) => {
    population = population.map((problem) => ids.includes(problem.id) ? { ...problem, status, closed_at: status === "closed" ? time : null } : problem);
    return { status: "ok", changed: ids.length };
  });
  renderQueue();
  await screen.findByRole("tab", { name: "Open (3)" });
  fireEvent.click(screen.getByRole("checkbox", { name: t("problems.select_all") }));
  fireEvent.click(screen.getByRole("button", { name: "Close selected (3)" }));
  await screen.findByText(t("problems.empty"));
  expect(change.mock.calls).toEqual([[[7, 9, 8], "closed"]]);
  fireEvent.click(screen.getByRole("tab", { name: "Closed (3)" }));
  expect(await screen.findAllByText("Closed 08:34")).toHaveLength(3);
  fireEvent.click(screen.getByRole("checkbox", { name: t("problems.select_all") }));
  fireEvent.click(screen.getByRole("button", { name: "Reopen selected (3)" }));
  await screen.findByRole("tab", { name: "Open (3)" });
  expect(change.mock.calls).toEqual([[[7, 9, 8], "closed"], [[7, 9, 8], "active"]]);
  fireEvent.click(screen.getByRole("tab", { name: "Open (3)" }));
  expect(await screen.findByText("svc-backup")).toBeTruthy();
});

it("shows scoped tab counts for severity and searches by address, account and computer as the user types", async () => {
  population.push({ ...audit, id: 10, status: "closed" }, { ...spray, id: 11, status: "closed" });
  renderQueue();
  await screen.findByRole("tab", { name: "Closed (2)" });
  fireEvent.change(screen.getByRole("combobox", { name: t("problems.severity") }), { target: { value: "high" } });
  await screen.findByRole("tab", { name: "Open (2)" });
  expect(screen.getByRole("tab", { name: "Closed (1)" })).toBeTruthy();
  fireEvent.change(screen.getByRole("combobox", { name: t("problems.severity") }), { target: { value: "" } });
  const input = screen.getByRole("searchbox");
  for (const [q, value] of [["198.51.100.77", "Accounts · 12"], ["target-7", "Accounts · 12"], ["DC02", "dc02.example.test"]]) {
    fireEvent.change(input, { target: { value: q } });
    await waitFor(() => expect(calls.at(-1)?.get("q")).toBe(q));
    expect(await screen.findByText(value)).toBeTruthy();
  }
  expect(screen.queryByRole("button", { name: t("filters.apply") })).toBeNull();
});

it.each(["#7", "?id=7"])("opens a deep-linked card with six observed facts and local time (%s)", async (suffix) => {
  window.history.replaceState(null, "", `/app/report/security.problems${suffix}`);
  const writeText = vi.fn(async () => undefined);
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
  renderQueue();
  const card = await screen.findByRole("dialog", { name: "svc-backup" });
  await within(card).findByText("What happened");
  expect(within(card).getByText(/08:34.*125 failed attempts/)).toBeTruthy();
  expect(card.querySelectorAll("dt")).toHaveLength(6);
  expect(card.querySelectorAll("li")).toHaveLength(3);
  expect(within(card).getByText("<dc01.example.test>")).toBeTruthy();
  expect(within(card).queryByText("2026-11-22T01:34:00Z")).toBeNull();
  fireEvent.click(within(card).getByRole("button", { name: "Copy addresses (1)" }));
  await within(card).findByText("Addresses copied");
  expect(writeText).toHaveBeenCalledWith("203.0.113.11");
  const journal = new URL((within(card).getByRole("link", { name: "Event journal" }) as HTMLAnchorElement).href);
  expect(journal.searchParams.get("problem_id")).toBe("7");
  expect(journal.searchParams.get("from")).toBe("2026-11-22T01:20:00.000Z");
});

it("uses dashes for failed counts and restores the list after retry", async () => {
  requestFailed = true;
  renderQueue();
  const failure = await screen.findByRole("alert");
  expect(failure.textContent).toContain(t("problems.load_failed"));
  expect(screen.getByRole("tab", { name: "Open (—)" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "Closed (—)" })).toBeTruthy();
  requestFailed = false;
  fireEvent.click(within(failure).getByRole("button", { name: "Retry" }));
  expect(await screen.findByRole("tab", { name: "Open (3)" })).toBeTruthy();
});

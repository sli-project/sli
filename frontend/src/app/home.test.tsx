/** @vitest-environment jsdom */
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiResponseError, type HomeDecisionSummary, type V4Access } from "../api/client";
import { counted, localeRuntime, setLocale, t } from "../i18n";
import { homeAssignee, homeDay, homeObjects, homeOccurrences, homeParams, homeTime } from "./home-view";

let accessStatus = "получены";
let access: V4Access | undefined;
vi.mock("./App", () => ({
  useTimeZone: () => ({ timeZone: "UTC" }),
  useEffectiveAccess: () => access,
  useAccessStatus: () => accessStatus,
}));
import { HomeComposition, HomePage } from "./home";

beforeEach(() => {
  accessStatus = "получены"; access = undefined; window.history.replaceState({}, "", "/app");
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru");
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function summary(): HomeDecisionSummary {
  return { contract_id: "sli.home-summary.v3", state: "ok", time_zone: "UTC", total: 23, new_count: 2,
    previous_login_at: "2026-10-16T18:05:00Z", updated_at_utc: "2026-10-17T08:52:00Z",
    remaining_groups: 2, remaining_problems: 20, href: "/app/report/security.problems?population=attention&domain=7", warnings: [],
    groups: [{ key: "synthetic-rule", title: "Synthetic problem", severity: "high", total: 3, new_count: 2,
      last_seen_utc: "2026-10-17T08:41:00Z", assigned_to: null,
      objects: ["a", "b", "c"].map((name) => ({ name: `synthetic-${name}`, domain: "example.test" })), object_count: 87,
      href: "/app/report/security.problems?population=attention&domain=7&rule_code=synthetic-rule" }],
  };
}
function compose(data = summary()) { return render(<HomeComposition data={data} onRetry={vi.fn()}/>); }
function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}><HomePage/></QueryClientProvider>) };
}

it("offers setup when the server has no agents and removes the actions when an agent appears", async () => {
  access = { platform_owner: true, capabilities: [] } as unknown as V4Access;
  const inventory = vi.spyOn(api, "agents").mockResolvedValue({ items: [] });
  vi.spyOn(api, "homeDecisions").mockResolvedValue({ ...summary(), state: "partial", groups: [], total: null });
  const { client, container } = show();

  expect((await screen.findByRole("link", { name: "Добавить агента" })).getAttribute("href")).toBe("/app/agents?register=1");
  expect(screen.getByRole("link", { name: "Подключить оповещения" }).getAttribute("href")).toBe("/app/notifications?tab=channels");
  expect(container.querySelector("p, table")).toBeNull();

  inventory.mockResolvedValue({ items: [{ id: "00000000-0000-4000-8000-000000000001" }] } as Awaited<ReturnType<typeof api.agents>>);
  await client.invalidateQueries({ queryKey: ["admin-agents"] });
  await waitFor(() => expect(screen.queryByRole("link", { name: "Добавить агента" })).toBeNull());
  expect(screen.queryByRole("link", { name: "Подключить оповещения" })).toBeNull();
});

it("keeps the queue when agent inventory is unavailable", async () => {
  access = { platform_owner: true, capabilities: [] } as unknown as V4Access;
  vi.spyOn(api, "agents").mockRejectedValue(new ApiResponseError(503, "unavailable"));
  vi.spyOn(api, "homeDecisions").mockResolvedValue(summary());
  show();
  expect(await screen.findByRole("table")).toBeTruthy();
  expect(screen.queryByRole("link", { name: "Добавить агента" })).toBeNull();
});

it("renders one grouped queue with counts, domain objects and a scoped group link", () => {
  const { container } = compose();
  expect(screen.getByRole("heading", { name: "Что требует решения" })).toBeTruthy();
  expect(screen.getAllByText("Что требует решения")).toHaveLength(1);
  const table = screen.getByRole("table");
  expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual(["Важность", "Проблема", "Новых", "Последняя", "Всего"]);
  expect(container.querySelector("header p")).toBeNull();
  expect(screen.getByRole("link", { name: "Synthetic problem" }).getAttribute("href")).toBe(summary().groups[0].href);
  expect(screen.getByText(/synthetic-a \(example.test\).*и ещё 84/)).toBeTruthy();
  expect(screen.getByText("17.10.2026, 08:41")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Ещё 20 проблем →" }).getAttribute("href")).toBe(summary().href);
  expect(container.querySelectorAll("table")).toHaveLength(1);
  expect(container.querySelector(".sli-ds-metric")).toBeNull();
  for (const text of ["Контекст сводки", "Время источника", "Ограничения данных", "Отчёты"]) expect(container.textContent).not.toContain(text);
  expect(screen.queryByRole("status")).toBeNull();
});

it("keeps the problem, severity and total in the phone layout", () => {
  compose();
  const row = screen.getAllByRole("row")[1];
  expect([...row.querySelectorAll("td:not([data-home-detail])")].map((cell) => cell.textContent)).toEqual([
    "высокая", expect.stringContaining("Synthetic problem"), "3",
  ]);
  expect(row.querySelectorAll("[data-home-detail]")).toHaveLength(3);
});

it.each(["ru", "en"] as const)("shows assignees only when a group has an assignment in %s", (locale) => {
  setLocale(locale);
  const data = summary();
  data.groups[0].assignee_state = "unassigned";
  data.groups.push({ ...data.groups[0], key: "assigned", assigned_to: "synthetic.operator", assignee_state: "assigned" });
  compose(data);
  expect(screen.getByRole("columnheader", { name: t("home.queue.assignee") })).toBeTruthy();
  const rows = screen.getAllByRole("row").slice(1);
  expect(within(rows[0]).getByText(t("security.problems.assignee.unassigned"))).toBeTruthy();
  expect(within(rows[1]).getByText("synthetic.operator")).toBeTruthy();
});

it("hides an assignee column containing only blank assignments", () => {
  const data = summary(); data.groups[0].assigned_to = "   ";
  compose(data);
  expect(screen.queryByRole("columnheader", { name: t("home.queue.assignee") })).toBeNull();
});

it("keeps source warnings and their details off the home screen", () => {
  const data = summary();
  data.warnings = [{ domain: "warning.example.test", reason_code: "home.queue.warning.source_incomplete", href: "/app/operations?domain=7" }];
  const { container } = compose(data);
  expect(screen.queryByText("warning.example.test", { exact: false })).toBeNull();
  expect(screen.queryByText("Подробнее")).toBeNull();
  expect(container.querySelector("details")).toBeNull();
  expect(screen.getByRole("table")).toBeTruthy();
});

it("renders a confirmed empty queue without a freshness note", () => {
  const data = { ...summary(), state: "empty", groups: [], total: 0, remaining_groups: 0, remaining_problems: 0 } as HomeDecisionSummary;
  compose(data);
  expect(screen.getByText("Сегодня спокойно: проблем, требующих решения, нет")).toBeTruthy();
  expect(screen.queryByText(/Данные обновлены/)).toBeNull();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByRole("link", { name: /Ещё/ })).toBeNull();
});

it("keeps agent connection health off the home screen", () => {
  const data = summary();
  data.agent_link_warning = { reason_code: "home.queue.warning.agent_link_unstable", agent_count: 3,
    window_from_utc: "2026-10-17T08:00:00Z", window_to_utc: "2026-10-17T09:00:00Z",
    observed_at_utc: "2026-10-17T08:52:00Z", href: "/app/operations" };
  compose(data);
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.getByRole("table")).toBeTruthy();
});

it("does not turn missing counts, baseline, objects or times into zero", () => {
  const data = summary(); data.total = null; data.new_count = null; data.previous_login_at = null;
  data.groups[0] = { ...data.groups[0], new_count: null, last_seen_utc: null, objects: [], object_count: null };
  compose(data);
  expect(screen.queryByText(/новых с вашего прошлого входа/)).toBeNull();
  expect(screen.queryByText("Нет данных")).toBeNull();
  expect(screen.getAllByRole("cell", { name: "—" }).length).toBeGreaterThan(0);
});

it.each(["partial", "stale"] as const)("keeps %s empty results free of diagnostic links and alerts", (state) => {
  const data = { ...summary(), state, total: null, groups: [],
    warnings: [{ domain: "example.test", reason_code: "home.queue.warning.source_incomplete", href: "/app/operations?domain=7" }],
  } as HomeDecisionSummary;
  compose(data);
  expect(screen.queryByText("Нет проблем, требующих решения")).toBeNull();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.queryByRole("link")).toBeNull();
  expect(screen.queryByText(t("state.unavailable.title"))).toBeNull();
  expect(screen.queryByRole("button", { name: t("state.retry") })).toBeNull();
  expect(screen.queryByRole("link", { name: "Диагностика" })).toBeNull();
});

it("keeps an actual failed request retryable", () => {
  compose({ ...summary(), state: "error", total: null, groups: [] });
  expect(screen.getByRole("alert")).toBeTruthy();
  expect(screen.getByRole("button", { name: t("state.retry") })).toBeTruthy();
});

it("retains known counts and rows when source coverage is incomplete", () => {
  compose({ ...summary(), state: "partial" });
  expect(screen.getByRole("table")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Synthetic problem" })).toBeTruthy();
});

it("keeps incomplete empty results free of diagnostic links in English", () => {
  setLocale("en");
  compose({ ...summary(), state: "partial", total: null, groups: [] });
  expect(screen.queryByText("The problem list is not yet confirmed to be complete.")).toBeNull();
  expect(screen.queryByRole("link")).toBeNull();
  expect(screen.queryByRole("alert")).toBeNull();
});

it.each([0, null])("shows a dash for an empty new count (%s) but keeps a known total", (newCount) => {
  const data = summary(); data.groups[0].new_count = newCount;
  compose(data);
  const cells = screen.getAllByRole("row")[1].querySelectorAll("td");
  expect(cells[2].textContent).toBe("—"); expect(cells[4].textContent).toBe("3");
});

it("renders the mockup denied state without any queue information", () => {
  const data = { ...summary(), state: "denied" } as HomeDecisionSummary;
  compose(data);
  expect(screen.getByText("Нет доступа ни к одному домену")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Запросить доступ" }).getAttribute("href")).toBe("/app/reports");
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByText(/23 проблем/)).toBeNull();
});

it("loads the new contract once and sends the selected domain and timezone", async () => {
  window.history.replaceState({}, "", "/app?domain=7");
  const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => summary() }); vi.stubGlobal("fetch", fetchMock);
  show();
  await screen.findByRole("table");
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/home/summary?domain=7&scope=domain&tz=UTC&contract=v3");
});

it("waits for access and ignores any previously cached data when access fails", async () => {
  accessStatus = "загружается";
  const request = vi.spyOn(api, "homeDecisions").mockResolvedValue(summary());
  const { client, rerender } = show();
  expect(request).not.toHaveBeenCalled();
  accessStatus = "получены";
  rerender(<QueryClientProvider client={client}><HomePage/></QueryClientProvider>);
  await screen.findByRole("table"); expect(request).toHaveBeenCalledTimes(1);
  accessStatus = "отказ";
  rerender(<QueryClientProvider client={client}><HomePage/></QueryClientProvider>);
  expect(screen.queryByRole("table")).toBeNull();
  const alert = screen.getByRole("alert");
  expect(alert.textContent).toBe("Не удалось проверить доступ к очереди проблем");
  expect(alert.closest(".sli-ds-state--banner, [data-tone]")).toBeNull();
});

it("shows a denied API response without a table", async () => {
  vi.spyOn(api, "homeDecisions").mockRejectedValue(new ApiResponseError(403, "domain_scope_denied"));
  show(); await screen.findByRole("alert"); expect(screen.queryByRole("table")).toBeNull();
  expect(screen.getByText("Нет доступа ни к одному домену")).toBeTruthy();
});

it("formats domain parameters and dates without browser-dependent punctuation", () => {
  expect(homeParams("?domain_id=8", "UTC").get("domain_id")).toBe("8");
  expect(homeParams("?domain=8", "UTC").get("scope")).toBe("domain");
  expect(homeTime("2026-10-17T08:41:00Z", "Asia/Bangkok")).toBe("17.10.2026, 15:41");
  expect(homeTime("invalid", "UTC")).toBe("—");
  expect(homeObjects({ ...summary().groups[0], objects: [{ name: "synthetic", domain: null }], object_count: 1 })).toBe("synthetic");
});

it("switches the home wording to English", () => {
  setLocale("en"); compose();
  expect(screen.getByText("Oct 17, 2026, 8:41 AM")).toBeTruthy();
  expect(screen.getByRole("heading", { name: "What needs a decision" })).toBeTruthy();
  expect(screen.queryByRole("columnheader", { name: "Assignee" })).toBeNull();
});


it.each(["ru", "en"] as const)("shows daily occurrences and resolved names without identity disclosures in %s", (locale) => {
  setLocale(locale);
  const data = summary();
  data.groups[0] = { ...data.groups[0], day: "2026-10-17", assignee_state: "unassigned",
    objects: [{ name: "Synthetic retained name", identifier: "S-1-5-21-100000001-200000002-300000003-1101", domain: "example.test",
      snapshot_name: true, source: { source_run_id: "synthetic-run", observed_at_utc: "2026-08-01T00:00:00Z", event_db_id: 91 } }] };
  const { container } = compose(data);
  expect(screen.getByText(homeOccurrences(3))).toBeTruthy();
  expect(screen.queryByText(t("security.problems.assignee.unassigned"))).toBeNull();
  expect(screen.getByText(t("home.queue.day", { day: locale === "en" ? "Oct 17, 2026" : "17.10.2026" }))).toBeTruthy();
  expect(container.querySelector("details")).toBeNull();
  expect(container.textContent).not.toContain("S-1-5-21-");
  expect(container.textContent).not.toContain("synthetic-run");
  expect(homeAssignee({ ...data.groups[0], assignee_state: "unknown" })).toBe(t("home.queue.no_data"));
});


it.each([
  ["ru", ["1 раз", "2 раза", "5 раз", "21 раз"]],
  ["en", ["1 occurrence", "2 occurrences", "5 occurrences", "21 occurrences"]],
] as const)("uses locale-aware occurrence forms in %s", (locale, expected) => {
  setLocale(locale);
  expect([1, 2, 5, 21].map(homeOccurrences)).toEqual(expected);
});



it.each([
  ["ru", "31.12.2025, 16:30", "01.01.2026, 14:30"],
  ["en", "Dec 31, 2025, 4:30 PM", "Jan 1, 2026, 2:30 PM"],
] as const)("uses the selected timezone and includes the local year in %s", (locale, west, east) => {
  setLocale(locale);
  expect(homeTime("2026-01-01T00:30:00Z", "America/Los_Angeles")).toBe(west);
  expect(homeTime("2026-01-01T00:30:00Z", "Pacific/Kiritimati")).toBe(east);
  expect(homeTime(null, "UTC")).toBe("—");
  expect(homeTime("invalid", "UTC")).toBe("—");
});

it.each(["ru", "en"] as const)("keeps cohort calendar days and scoped links unchanged in %s", (locale) => {
  setLocale(locale);
  const data = summary();
  data.time_zone = "America/Los_Angeles";
  data.groups[0].day = "2024-02-29";
  data.groups[0].href += "&cohort=retained&time_from=2024-02-29&time_to=2024-03-01&tz=America%2FLos_Angeles";
  compose(data);
  expect(screen.getByText(t("home.queue.day", { day: locale === "en" ? "Feb 29, 2024" : "29.02.2024" }))).toBeTruthy();
  expect(screen.getByRole("link", { name: "Synthetic problem" }).getAttribute("href")).toBe(data.groups[0].href);
});

it.each(["2025-02-29", "2026-02-30", "2026-13-01", "2026-1-01", "not-a-date"])("does not normalize an invalid cohort day %s", (day) => {
  const data = summary(); data.groups[0].day = day;
  compose(data);
  expect(screen.getByText(t("home.queue.day", { day: "—" }))).toBeTruthy();
  expect(screen.queryByText(t("home.queue.day", { day }))).toBeNull();
});


it.each([null, undefined, ""])("keeps missing calendar day %s unknown", (day) => {
  expect(homeDay(day)).toBe("—");
});


it.each(["ru", "en"] as const)("replaces unresolved names with dashes and removes raw identity blocks in %s", (locale) => {
  setLocale(locale);
  const data = summary();
  const sid = "S-1-5-21-100000001-200000002-300000003-1101";
  data.groups = (["no_match", "unverified", "unavailable", "ambiguous"] as const).map((state) => ({
    ...data.groups[0], key: state, href: `/app/report/security.problems?cohort=${state}`, identity_state: "unavailable",
    objects: [{ name: sid, name_state: state, identifier: sid, domain: "example.test" }], object_count: 1,
  }));
  const { container } = compose(data);
  const rows = screen.getAllByRole("row").slice(1);
  expect(rows.map((row) => within(row).getByRole("link").getAttribute("href"))).toEqual(data.groups.map((group) => group.href));
  for (const row of rows) {
    expect(row.querySelector(".sli-ds-home-queue__objects")?.textContent).toBe("—");
    expect(row.querySelector("details")).toBeNull();
    expect(row.querySelector("p")).toBeNull();
  }
  expect(container.textContent).not.toMatch(/S-1-5|SID|Исходные идентификаторы|Original identifiers|Имя объекта|Object \d+:|Имена из снимка/);
  expect(container.querySelector(".sli-ds-state--banner, .sli-ds-callout")).toBeNull();
});

it.each(["ru", "en"] as const)("keeps resolved names and hides SID-shaped names and provenance in %s", (locale) => {
  setLocale(locale);
  const data = summary();
  const sid = "S-1-5-21-100000001-200000002-300000003-1101";
  data.groups[0].objects = [
    { name: "Synthetic retained name", name_state: "named", snapshot_name: true, identifier: sid, domain: "example.test",
      source: { source_run_id: "synthetic-run", observed_at_utc: "2026-08-01T00:00:00Z", event_db_id: 91 } },
    { name: sid, name_state: "named", domain: "example.test" },
    { name: `sid:synthetic-dc:${sid}`, name_state: "literal", domain: "example.test" },
  ];
  data.groups[0].object_count = 3;
  const { container } = compose(data);
  expect(container.querySelector(".sli-ds-home-queue__objects")?.textContent).toBe("Synthetic retained name (example.test), —, —");
  expect(container.querySelector("details")).toBeNull();
  expect(container.textContent).not.toContain(sid);
  expect(container.textContent).not.toContain("synthetic-run");
});


it.each(["ru", "en"] as const)("shows every returned group and preserves server remaining counts (%s)", (locale) => {
  setLocale(locale);
  const data = summary();
  data.groups = Array.from({ length: 8 }, (_, i) => ({ ...data.groups[0], key: String(i), title: "Group " + i, total: i + 1 }));
  data.remaining_groups = 2; data.remaining_problems = 10;
  compose(data);
  expect(screen.getAllByRole("row").slice(1).map((row) => within(row).getByRole("link").textContent))
    .toEqual(data.groups.map((group) => group.title));
  expect(screen.getByRole("link", { name: t("home.queue.more", { groups: counted(2, "groups"), count: counted(10, "problems") }) })).toBeTruthy();
});


it.each(["ru", "en"] as const)("keeps the queue link when remaining totals are unknown (%s)", (locale) => {
  setLocale(locale);
  const data = summary();
  data.groups = Array.from({ length: 6 }, (_, i) => ({ ...data.groups[0], key: String(i), title: "Group " + i }));
  data.remaining_groups = null; data.remaining_problems = null;
  compose(data);
  expect(screen.getByRole("link", { name: t("home.queue.more_unknown") }).getAttribute("href")).toBe(data.href);
});

it("renders all rows of a short list without a more-groups link", () => {
  const data = summary();
  data.groups = Array.from({ length: 14 }, (_, index) => ({ ...data.groups[0], key: String(index), title: `Problem ${index + 1}` }));
  data.remaining_groups = 0; data.remaining_problems = 0;
  compose(data);
  expect(screen.getAllByRole("row").slice(1).map((row) => within(row).getByRole("link").textContent))
    .toEqual(data.groups.map((group) => group.title));
  expect(screen.queryByRole("link", { name: /Ещё/ })).toBeNull();
});

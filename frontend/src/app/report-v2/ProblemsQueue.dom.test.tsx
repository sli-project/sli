// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { OverlayProvider } from "../../design-system";
import { localeRuntime, setLocale } from "../../i18n";
import { ReportRenderer } from "./ReportRenderer";

vi.mock("../App", () => ({
  useEffectiveAccess: () => ({ capabilities: ["investigations.manage"] }),
  useTimeZone: () => ({ timeZone: "UTC" }),
}));

const key = "security.problems";
const definition: ReportDefinitionDto = {
  key, title: "Security problems", section: "investigation", description: "", archetype: "queue",
  params: [{ key: "queue_view", kind: "choice", label: "View" }, { key: "queue_assignee", kind: "text", label: "Assignee" }, { key: "q", kind: "text", label: "Search" }],
  filter_options: { domain: [{ label: "example.test", value: "7" }] }, columns: [], views: [], row_key: "id",
  detail: { title: "Evidence", kind: "sub", key: "id", columns: [], row_links: [] }, export: false,
  presets: [], row_links: [], limits: { default: 50, max: 200 },
};
const page = (items: ReportResultDto["items"], total = items.length): ReportResultDto => ({
  contract_id: "sli.report-result.v2", report_key: key, state: "ok", items, filtered_count: total, has_more: false, next_cursor: null,
  filter_options: {}, metrics: [], window: {}, coverage: {}, limitations: [], series: { queue_counts: { all: 3, open: 2, active: 1, deferred: 0, resolved: 0 } },
});

const problem = {
  id: 41, title_text: "Password spray", severity: "high", status: "new", entity_text: "operator.one", actor_text: "192.0.2.28",
  problem_cohort: '["finding",41]', occurrence_count: 2, evidence_total: 64, last_seen_utc: "2026-11-22T11:52:43Z",
  queue_attack: { accounts: ["operator.one", "operator.two"], addresses: ["192.0.2.28"], account_count: 12, event_count: 64 },
};
const second = { ...problem, id: 42, problem_cohort: "", title_text: "Repeated sign-in failures", occurrence_count: 1, queue_attack: null };
const third = { ...second, id: 43, status: "active", title_text: "Audit policy changed" };
const evidence = { event_id: 4625, event_db_id: 712, evidence_id: 712, hostname: "example-dc", time_created_utc: "2026-11-22T11:52:43Z" };

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("en"); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

function renderQueue(data = (params: URLSearchParams) => {
  if (params.has("id")) return page([{ ...(params.get("id") === "43" ? third : problem), rule_code: "AUTH-04", queue_participant: "operator.one" }]);
  if (params.has("cohort") || params.get("fold") === "false") return page([problem, second]);
  return page(params.get("queue_view") === "active" ? [third] : [problem, third]);
}) {
  vi.spyOn(api, "reportV2Definition").mockResolvedValue(definition);
  vi.spyOn(api, "riskResponsibles").mockResolvedValue({ items: [{ id: 8, username: "reviewer" }] });
  vi.spyOn(api, "reportV2Detail").mockResolvedValue(page([evidence]));
  const reads = vi.spyOn(api, "reportV2Data").mockImplementation(async (_, params) => data(params));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  render(<QueryClientProvider client={client}><OverlayProvider><ReportRenderer reportKey={key} initialSearch="domain=7"/></OverlayProvider></QueryClientProvider>);
  return reads;
}

it("expands repeat rows in place and opens exact evidence", async () => {
  const user = userEvent.setup();
  renderQueue();
  const attack = await screen.findByRole("link", { name: "Password spray" });
  expect(screen.getByRole("checkbox", { name: "Collapse repeats" })).toHaveProperty("checked", true);
  await user.click(screen.getByRole("button", { name: "Expand repeats for #41" }));
  await screen.findByRole("link", { name: /Repeated sign-in failures/ });
  await user.click(screen.getByRole("button", { name: "Collapse repeats for #41" }));
  expect(screen.queryByRole("link", { name: /Repeated sign-in failures/ })).toBeNull();
  await user.click(attack);
  const panel = await screen.findByRole("dialog", { name: "Password spray · operator.one, operator.two and 10 more" });
  expect(await within(panel).findByText("4625")).toBeTruthy();
  expect(within(panel).getByRole("link", { name: "Open in event journal" }).getAttribute("href"))
    .toBe("/app/report/events.journal?finding=41&domain=7&hide_open_problem_evidence=off");
  await user.click(within(panel).getByRole("button", { name: "Next problem" }));
  expect(await screen.findByRole("dialog", { name: "Audit policy changed" })).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "Close" }));
});

it("shows the file episode response without an empty journal events section", async () => {
  const user = userEvent.setup();
  const title = "Mass file changes · Files · 110 files in 1 min";
  const next = "Check the account and folder. Stop the process.";
  renderQueue(() => page([{ ...second, rule_code: "semantic.qw.file-ransom", title_text: title, next_text: next }]));
  await user.click(await screen.findByRole("link", { name: title }));
  const panel = await screen.findByRole("dialog", { name: title });
  expect(await within(panel).findByText(next)).toBeTruthy();
  expect(within(panel).queryByRole("heading", { name: "Events" })).toBeNull();
  expect(api.reportV2Detail).not.toHaveBeenCalled();
});

it("shows filter counts and requests the selected severity and domain", async () => {
  const user = userEvent.setup();
  const reads = renderQueue();
  await screen.findByRole("button", { name: "Open 2" });
  expect(screen.queryByRole("link", { name: "Export CSV" })).toBeNull();
  await chooseOption(screen.getByLabelText("Severity", { selector: "button" }), "high");
  await user.click(await screen.findByRole("button", { name: "In progress 1" }));
  expect(reads.mock.calls.some(([, params]) => params.get("queue_view") === "active" && params.get("severity") === "high")).toBe(true);
  await chooseOption(screen.getByLabelText("Domain", { selector: "button" }), "");
  await waitFor(() => {
    const params = reads.mock.lastCall?.[1];
    expect(params?.has("domain")).toBe(false);
    expect(params?.has("scope")).toBe(false);
  });
});

it("shows short attack titles, two values per cell and the full attempt totals", async () => {
  setLocale("ru");
  const user = userEvent.setup();
  const accounts = Array.from({ length: 18 }, (_, index) => `test-user${String(index + 1).padStart(2, "0")}`);
  const addresses = Array.from({ length: 21 }, (_, index) => `198.51.100.${index + 10}`);
  const sprayTitle = "Попытки входа с адреса 192.0.2.28 · 18 учётных записей · 2\u00a0002 попытки";
  const bruteTitle = "Подбор пароля к учётной записи Администратор · 21 адрес · 111\u00a0890 попыток";
  const spray = { ...problem, id: 1694, title_text: sprayTitle, rule_code: "semantic.qw.password-spray", evidence_total: 50,
    occurrence_count: 2002, queue_attack: { accounts, addresses: ["192.0.2.28"], account_count: 18, event_count: 2002 } };
  const brute = { ...problem, id: 1689, title_text: bruteTitle, rule_code: "semantic.qw.password-brute-force", evidence_total: 50,
    occurrence_count: 111890, queue_attack: { accounts: ["Администратор", "АДМИНИСТРАТОР", "администратор", "test-alias"], addresses, address_count: 21, event_count: 111890 } };
  renderQueue((params) => page(params.has("id") ? [params.get("id") === "1694" ? spray : brute] : [spray, brute]));

  const sprayLink = await screen.findByRole("link", { name: sprayTitle });
  const bruteLink = screen.getByRole("link", { name: bruteTitle });
  const sprayRow = within(sprayLink.closest("tr")!);
  const bruteRow = within(bruteLink.closest("tr")!);
  expect(sprayLink.closest("td")?.textContent).toBe(`›${sprayTitle}`);
  expect(bruteLink.closest("td")?.textContent).toBe(`›${bruteTitle}`);
  expect(sprayLink.getAttribute("href")).toBe("/app/report/security.problems?id=1694&domain=7");
  expect(bruteLink.getAttribute("href")).toBe("/app/report/security.problems?id=1689&domain=7");
  const object = sprayRow.getByText("+16").closest("td");
  const initiator = bruteRow.getByText("+19").closest("td");
  expect(object?.textContent).toBe("test-user01, test-user02+16");
  expect(object?.title).toBe(accounts.join(", "));
  expect(initiator?.textContent).toBe("198.51.100.10, 198.51.100.11+19");
  expect(initiator?.title).toBe(addresses.join(", "));
  expect(sprayRow.getByRole("button", { name: "2\u00a0002 события" })).toBeTruthy();
  expect(bruteRow.getByRole("button", { name: "111\u00a0890 событий" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "50 событий" })).toBeNull();
  expect(screen.queryByRole("columnheader", { name: "№" })).toBeNull();

  await user.click(bruteLink);
  const panel = await screen.findByRole("dialog");
  expect(within(panel).queryByText("#1689")).toBeNull();
  expect(within(panel).getByText((content) => content.includes(addresses.join(", ")))).toBeTruthy();
});

it("omits the evidence column if a password finding has only a retained sample count", async () => {
  renderQueue(() => page([{ ...problem, evidence_total: 50, queue_attack: { ...problem.queue_attack, event_count: null } }]));
  await screen.findByRole("link", { name: "Password spray" });
  expect(screen.queryByRole("columnheader", { name: "Evidence" })).toBeNull();
});

it("opens the finding journal directly and links back to the same problem", async () => {
  const journalKey = "events.journal";
  vi.spyOn(api, "reportV2Definition").mockResolvedValue({ ...definition, key: journalKey, title: "Events journal" });
  const readEvidence = vi.spyOn(api, "reportV2Detail").mockResolvedValue(page([evidence]));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  render(<QueryClientProvider client={client}><ReportRenderer reportKey={journalKey} initialSearch="finding=41&domain=7"/></QueryClientProvider>);

  expect((await screen.findByRole("link", { name: "4625" })).getAttribute("href")).toBe("/app/events/712");
  expect(screen.getByRole("link", { name: "Problem #41" }).getAttribute("href")).toBe("/app/report/security.problems?id=41&domain=7");
  expect(readEvidence).toHaveBeenCalledWith(key, "41", new URLSearchParams({ queue_view: "all", tz: "UTC", domain: "7" }));
});

it("submits a classified decision and shows who changed state", async () => {
  const user = userEvent.setup();
  let status = "new";
  const decide = vi.spyOn(api, "decideProblems").mockImplementation(async (input) => {
    if (input.state) status = input.state;
    return { status: "ok", changed: input.ids.length };
  });
  renderQueue((params) => params.has("id") ? page([{ ...problem, status, status_history: status === "closed" ? [{ id: 6,
    changed_at: "2026-11-22T11:55:00Z", changed_by: "reviewer", old_status: "new", new_status: "closed",
    note: 'sli.queue:{"classification":"fixed","comment":"Reset password"}' }] : [] }]) : page([{ ...problem, status }, third]));
  await user.click(await screen.findByRole("link", { name: /Password spray/ }));
  const panel = screen.getByRole("dialog", { name: "Password spray · operator.one, operator.two and 10 more" });
  await chooseOption(within(panel).getByLabelText("State", { selector: "button" }), "closed");
  const dialog = screen.getByRole("dialog", { name: "Change state" });
  await chooseOption(within(dialog).getByLabelText("Resolution reason", { selector: "button" }), "fixed");
  await user.type(within(dialog).getByRole("textbox"), "Reset password");
  await user.click(within(dialog).getByRole("button", { name: "Save decision" }));
  expect(decide).toHaveBeenCalledWith({ ids: [41], state: "closed", classification: "fixed", comment: "Reset password" });
  expect(await within(panel).findByText(/Real problem \(fixed\).*Reset password/)).toBeTruthy();
  expect(within(panel).getByText("reviewer")).toBeTruthy();
});

it("assigns the selected findings to the chosen user", async () => {
  const user = userEvent.setup();
  const decide = vi.spyOn(api, "decideProblems").mockResolvedValue({ status: "ok", changed: 2 });
  renderQueue();
  await user.click(await screen.findByRole("checkbox", { name: "Select problem #41" }));
  await user.click(screen.getByRole("checkbox", { name: "Select problem #43" }));
  await user.click(within(screen.getByRole("group", { name: "Selected problems" })).getByRole("button", { name: "Assign" }));
  const assignment = await screen.findByRole("dialog", { name: "Assign" });
  await user.click(await within(assignment).findByRole("button", { name: /Assignee/ }));
  await user.click(await screen.findByRole("option", { name: "reviewer" }));
  await user.click(within(assignment).getByRole("button", { name: "Save decision" }));
  expect(decide).toHaveBeenLastCalledWith({ ids: [41, 43], assignee_id: 8 });
});

// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import definitions from "../../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ReportRenderer } from "./ReportRenderer";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function journal(state: ReportResultDto["state"] = "ok", empty = false, stateDetails: NonNullable<ReportResultDto["state_details"]> = { reason: "freshness_exceeded", source: "dc01.example.test", stale_since_utc: "2026-11-11T12:00:00Z" }, items?: Record<string, unknown>[], nextPageItems?: Record<string, unknown>[]) {
  const definition = { ...definitions.find((item) => item.key === "events.journal"), filter_options: {} } as unknown as ReportDefinitionDto;
  const result: ReportResultDto = {
    contract_id: "sli.report-result.v2", report_key: "events.journal", state,
    items: empty ? [] : [{ id: 1, time_created_utc: "2026-11-11T12:00:00Z", title_text: "Synthetic event",
      participant: "Не определён по доступным данным", on_behalf: null, channel: "Security",
      presentation_messages: { participant: { code: "events.participant_unknown", params: {}, text: "Не определён по доступным данным" } } },
    { id: 2, time_created_utc: "2026-11-11T11:00:00Z", title_text: "Synthetic account event", participant: "synthetic.user", channel: "Security" }],
    has_more: false, next_cursor: null, filtered_count: empty ? 0 : 2, metrics: [], series: {}, filter_options: {},
    coverage: { completeness: "not_proven", observed_at_utc: "2026-11-11T12:00:00Z" },
    state_details: stateDetails,
    limitations: [{ code: "no_risk_in_slice", text: "Synthetic methodology" }],
    window: { from_utc: "2026-11-06T12:00:00Z", to_utc_exclusive: "2026-11-13T12:00:00Z" },
  };
  if (items) { result.items = items; result.filtered_count = items.length; }
  if (nextPageItems) { result.has_more = true; result.next_cursor = "synthetic-cursor"; result.filtered_count = result.items.length + nextPageItems.length; }
  const requests: URL[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), window.location.origin);
    requests.push(url);
    const page = nextPageItems && url.searchParams.has("cursor") ? { ...result, items: nextPageItems, has_more: false, next_cursor: null } : result;
    return new Response(JSON.stringify(url.pathname.endsWith("/data") ? page : definition), { headers: { "Content-Type": "application/json" } });
  }));
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <ReportRenderer reportKey="events.journal"/>
  </QueryClientProvider>);
  return requests;
}

it.each((["ru", "en"] as const).flatMap((locale) => (["ok", "partial", "stale", "processing"] as const).map((state) => ({ locale, state }))))("shows only journal columns and hides explanatory blocks ($locale, $state)", async ({ locale, state }) => {
  setLocale(locale);
  window.history.replaceState(null, "", "/app/report/events.journal?domain=7");
  const requests = journal(state);
  await screen.findByText("Synthetic event");
  const table = screen.getByRole("table");
  expect(within(table).getAllByRole("columnheader").map((cell) => cell.textContent)).toEqual(locale === "ru"
    ? ["Время", "Событие", "Участник", "Журнал"] : ["Time", "Event", "Participant", "Log"]);
  expect(within(table).getAllByRole("row")[1].querySelectorAll("td")[2].textContent).toBe("—");
  expect(screen.getByText("synthetic.user")).toBeTruthy();
  expect(screen.queryByText("Не определён по доступным данным")).toBeNull();
  expect(screen.queryByText(t("reports.passport.more"))).toBeNull();
  expect(screen.queryByText(t("reports.renderer.limitations_title"))).toBeNull();
  expect(screen.queryByText("Synthetic methodology")).toBeNull();
  expect(document.querySelector(".sli-ds-state--banner")).toBeNull();
  expect(document.querySelector(".sli-ds-report > p")).toBeNull();
  const more = screen.getByText(t("reports.filters.more")).closest("details")!;
  expect(more.open).toBe(false);
  expect(more.contains(screen.getByText(t('reports.v2.events.journal.presets.{"q":"4625","view":"authentication"}')))).toBe(true);
  expect(more.contains(screen.getByLabelText(t("reports.v2.events.journal.params.view.label")))).toBe(true);
  expect(more.contains(screen.getByLabelText(t("reports.v2.events.journal.params.server.label")))).toBe(true);
  const request = requests.find((url) => url.pathname.endsWith("/data"))!;
  expect(request.searchParams.get("domain")).toBe("7");
  expect(request.searchParams.get("period")).toBe("7d");
  expect(new URLSearchParams(window.location.search).get("domain")).toBe("7");
  const csv = screen.getByRole("link", { name: t("reports.renderer.export_csv") });
  expect(new URL(csv.getAttribute("href")!, window.location.origin).searchParams.get("domain")).toBe("7");
  fireEvent.click(screen.getByText(t("reports.filters.more")));
  fireEvent.click(screen.getByText(t('reports.v2.events.journal.presets.{"q":"4625","view":"authentication"}')));
  await waitFor(() => expect(new URLSearchParams(window.location.search).get("q")).toBe("4625"));
  expect(new URLSearchParams(window.location.search).get("domain")).toBe("7");
  expect(new URLSearchParams(window.location.search).get("view")).toBe("authentication");
});

it.each(["ru", "en"] as const)("keeps an explicit period and shows a single empty line (%s)", async (locale) => {
  setLocale(locale);
  window.history.replaceState(null, "", "/app/report/events.journal?domain=7&period=24h");
  const requests = journal("empty", true);
  const text = locale === "ru" ? "Записей нет" : "No records";
  const line = await screen.findByText(text);
  expect(line.textContent).toBe(text);
  expect(document.querySelector(".sli-ds-state")).toBeNull();
  expect(screen.queryByText(t("reports.empty.show_latest"))).toBeNull();
  expect(screen.queryByText(t("reports.empty.source_diagnostics"))).toBeNull();
  expect(screen.queryByText(t("reports.renderer.limitations_title"))).toBeNull();
  expect(requests.find((url) => url.pathname.endsWith("/data"))!.searchParams.get("period")).toBe("24h");
});

it.each(["ru", "en"] as const)("does not claim there were no events when collection is not confirmed (%s)", async (locale) => {
  setLocale(locale);
  window.history.replaceState(null, "", "/app/report/events.journal?domain=7");
  journal("not_collected", true, { reason: "collection_not_confirmed" });
  const line = await screen.findByText(t("reports.v2.events.journal.not_loaded"));
  expect(line.textContent).toBe(locale === "ru" ? "Журнал не загружен" : "Journal not loaded");
  expect(screen.queryByText(t("reports.v2.events.journal.empty"))).toBeNull();
  expect(document.querySelector(".sli-ds-state--banner")).toBeNull();
});

it("shows rows when state is not_collected but rows exist", async () => {
  window.history.replaceState(null, "", "/app/report/events.journal?domain=7");
  journal("not_collected", false, { reason: "collection_not_confirmed" });
  await screen.findByText("Synthetic event");
  expect(screen.queryByText(t("reports.v2.events.journal.not_loaded"))).toBeNull();
  expect(screen.queryByText(t("reports.v2.events.journal.empty"))).toBeNull();
});


it("hides columns empty on the page by default but keeps them in Columns", async () => {
  window.history.replaceState(null, "", "/app/report/events.journal");
  journal("ok", false, { reason: "available" }, [
    { id: 1, title_text: "Synthetic event", participant: null, on_behalf: "—" },
    { id: 2, title_text: "Synthetic account event", participant: " ", on_behalf: null },
  ]);
  await screen.findByText("Synthetic event");
  const table = screen.getByRole("table");
  expect(within(table).queryByRole("columnheader", { name: "Участник" })).toBeNull();
  expect(within(table).queryByRole("columnheader", { name: "От имени" })).toBeNull();
  expect(screen.getByText("1–2 из 2")).toBeTruthy();
  fireEvent.click(screen.getByText(t("table.columns")));
  const participant = screen.getByRole("checkbox", { name: "Участник" }) as HTMLInputElement;
  expect(participant.checked).toBe(false);
  fireEvent.click(participant);
  expect(within(table).getByRole("columnheader", { name: "Участник" })).toBeTruthy();
});

it("keeps populated actor columns visible", async () => {
  journal("ok", false, { reason: "available" }, [{ id: 1, title_text: "Synthetic event", participant: "user.one", on_behalf: "user.two" }]);
  await screen.findByText("Synthetic event");
  expect(screen.getByRole("columnheader", { name: "Участник" })).toBeTruthy();
  expect(screen.getByRole("columnheader", { name: "От имени" })).toBeTruthy();
});

it("pages fifty source records at a time and returns to the previous page", async () => {
  window.history.replaceState(null, "", "/app/report/events.journal");
  const row = (id: number) => ({ id, title_text: `Synthetic event ${id}` });
  const requests = journal("ok", false, { reason: "available" }, Array.from({ length: 50 }, (_, i) => row(i + 1)), [row(51), row(52)]);
  await screen.findByText("1–50 из 52");
  fireEvent.click(screen.getByRole("button", { name: t("table.next") }));
  await screen.findByText("51–52 из 52");
  expect(screen.queryByText("Synthetic event 1")).toBeNull();
  expect(screen.getByText("Synthetic event 51")).toBeTruthy();
  expect(requests.find((url) => url.searchParams.has("cursor"))?.searchParams.get("cursor")).toBe("synthetic-cursor");
  fireEvent.click(screen.getByRole("button", { name: t("table.previous") }));
  await screen.findByText("1–50 из 52");
  expect(screen.getByText("Synthetic event 1")).toBeTruthy();
  expect(screen.queryByText("Synthetic event 51")).toBeNull();
});

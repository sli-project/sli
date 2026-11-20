// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportDetailDto, ReportResultDto } from "../../api/report-v2-types";
import { localeRuntime, setLocale, t } from "../../i18n";
import { DetailSection } from "./DetailSection";
import { localizeReportResult } from "../../i18n/report-metadata";

afterEach(() => { cleanup(); vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); });

const detail: ReportDetailDto = {
  kind: "sub", title: "Evidence", key: "id", columns: [
    { key: "event_id", path: "event_id", label: "Event", kind: "code", link: "/app/events/{event_db_id}" },
  ], row_links: [],
};
const definition = { key: "security.problems", title: "Problems" } as ReportDefinitionDto;
function page(start: number, count: number, more: boolean): ReportResultDto {
  return { contract_id: "sli.report-result.v2", report_key: definition.key, state: "ok",
    items: Array.from({ length: count }, (_, i) => ({ event_db_id: start + i, event_id: 4719 })),
    has_more: more, next_cursor: more ? String(start + count) : null, filtered_count: 70,
    metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {} };
}
function show(row = { id: 7, evidence_total: 70 }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><DetailSection definition={definition} detail={detail} row={row} baseParams="status=new&severity=high&limit=50"/></QueryClientProvider>);
}

it("keeps GPO detail facts without the limitation column or remarks", async () => {
  const gpoDetail: ReportDetailDto = { ...detail, title: "Synthetic policy settings",
    columns: [{ key: "setting", path: "setting", label: "Setting", kind: "text" },
      { key: "limitation", path: "limitation", label: "Limitation", kind: "text" }] };
  vi.spyOn(api, "reportV2Detail").mockResolvedValue({ ...page(1, 1, false), report_key: "ad.gpo.v2",
    items: [{ id: 8, setting: "Synthetic setting", limitation: "Synthetic caveat" }],
    limitations: [{ code: "synthetic", text: "Synthetic remark" }] });
  render(<QueryClientProvider client={new QueryClient()}><DetailSection definition={{ ...definition, key: "ad.gpo.v2" }}
    detail={gpoDetail} row={{ id: 7 }} baseParams=""/></QueryClientProvider>);
  expect(await screen.findByRole("cell", { name: "Synthetic setting" })).toBeTruthy();
  expect(screen.queryByRole("columnheader", { name: "Limitation" })).toBeNull();
  expect(screen.queryByText("Synthetic caveat")).toBeNull();
  expect(screen.queryByText("Synthetic remark")).toBeNull();
});

it.each(["ru", "en"] as const)("loads all 70 evidence rows in pages and retains return_to (%s)", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const request = vi.spyOn(api, "reportV2Detail").mockImplementation(async (_key, _row, params) => {
    const start = Number(params?.get("cursor") ?? 1);
    return page(start, start === 61 ? 10 : 20, start < 61);
  });
  window.history.replaceState(null, "", "/app/report/security.problems?status=new&severity=high");
  show();
  await screen.findByText(t("table.shown", { count: 20 }), { exact: false });
  expect(screen.getByText(/70/, { selector: ".sli-ds-table__footer span" })).toBeTruthy();
  for (const count of [40, 60, 70]) {
    fireEvent.click(screen.getByRole("button", { name: t("table.loadMore") }));
    await screen.findByText(t("table.shown", { count }), { exact: false });
  }
  expect(screen.queryByRole("button", { name: t("table.loadMore") })).toBeNull();
  expect(screen.getAllByRole("link")).toHaveLength(70);
  expect(new URL(screen.getAllByRole("link")[69].getAttribute("href")!, window.location.origin).searchParams.get("return_to")).toBe("/app/report/security.problems?status=new&severity=high");
  expect(request.mock.calls[3][2]?.get("cursor")).toBe("61");
  expect(request.mock.calls[3][2]?.get("status")).toBe("new");
  expect(screen.getAllByRole("link").map((link) => new URL(link.getAttribute("href")!, window.location.origin).pathname)).toEqual(
    Array.from({ length: 70 }, (_, i) => `/app/events/${i + 1}`),
  );
});

it("keeps loaded evidence and offers retry when a later page fails", async () => {
  vi.spyOn(api, "reportV2Detail").mockResolvedValueOnce(page(1, 20, true)).mockRejectedValueOnce(new ApiResponseError(503)).mockResolvedValueOnce(page(21, 20, true));
  show();
  await screen.findByText(t("table.shown", { count: 20 }), { exact: false });
  fireEvent.click(screen.getByRole("button", { name: t("table.loadMore") }));
  await screen.findByRole("button", { name: t("state.retry") });
  expect(screen.getAllByRole("link")).toHaveLength(20);
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  await waitFor(() => expect(screen.getAllByRole("link")).toHaveLength(40));
});

it.each(["ru", "en"] as const)("shows a bounded count without using the finding's stored total (%s)", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const bounded = { ...page(1, 20, true), filtered_count: null, coverage: { evidence_total_lower_bound: 10001 } };
  vi.spyOn(api, "reportV2Detail").mockResolvedValue(bounded);
  show();
  expect(await screen.findByText(t("security.problems.evidence.lower_bound", { count: 10001 }))).toBeTruthy();
  expect(screen.getByRole("button", { name: t("table.loadMore") })).toBeTruthy();
  expect(screen.queryByText(/70/, { selector: ".sli-ds-table__footer span" })).toBeNull();
});

it("uses the latest page's count when evidence is added between requests", async () => {
  vi.spyOn(api, "reportV2Detail").mockResolvedValueOnce(page(1, 20, true)).mockResolvedValueOnce({ ...page(21, 20, true), filtered_count: 71 });
  show();
  await screen.findByRole("button", { name: t("table.loadMore") });
  fireEvent.click(screen.getByRole("button", { name: t("table.loadMore") }));
  await screen.findByText(/71/, { selector: ".sli-ds-table__footer span" });
  expect(screen.getAllByRole("link")).toHaveLength(40);
});

it.each(["ru", "en"] as const)("keeps unavailable source references on a later page with an informative partial state (%s)", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const partial = { ...page(21, 1, false), state: "partial" as const,
    items: [{ evidence_id: 21, event_db_id: null, event_id: null }],
    coverage: { evidence_missing_sources: 1 } };
  vi.spyOn(api, "reportV2Detail").mockResolvedValueOnce(page(1, 20, true)).mockResolvedValueOnce(partial);
  show();
  await screen.findByRole("button", { name: t("table.loadMore") });
  fireEvent.click(screen.getByRole("button", { name: t("table.loadMore") }));
  expect(await screen.findByText(t("security.problems.evidence.partial", { count: 1 }))).toBeTruthy();
  expect(screen.getAllByRole("link")).toHaveLength(20);
  expect(screen.getAllByRole("row")).toHaveLength(22);
  expect(screen.queryByRole("button", { name: t("table.loadMore") })).toBeNull();
});

it.each(["ru", "en"] as const)("explains empty evidence without claiming the problem is absent (%s)", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  vi.spyOn(api, "reportV2Detail").mockResolvedValue({ ...page(1, 0, false), state: "empty", filtered_count: 0 });
  show();
  expect(await screen.findByText(t("security.problems.evidence.empty"))).toBeTruthy();
  expect(screen.queryByRole("link")).toBeNull();
  expect(screen.queryByRole("button", { name: t("table.loadMore") })).toBeNull();
});

it("does not fetch or expose evidence when detail access is denied", async () => {
  const request = vi.spyOn(api, "reportV2Detail");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><DetailSection definition={definition}
    detail={{ ...detail, access: { allowed: false } }} row={{ id: 7 }} baseParams=""/></QueryClientProvider>);
  expect(request).not.toHaveBeenCalled();
  expect(screen.queryByRole("link")).toBeNull();
  expect(screen.queryByRole("button", { name: t("table.loadMore") })).toBeNull();
});

function nativeSnapshot(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { storage_kind: "file_audit_snapshot", evidence_key: "fixture-evidence-a", evidence_role: "semantic_scenario",
    availability: "available", observed_at_utc: "2026-01-02T03:04:05Z", historical: true,
    resource: { agent_id: "fixture-agent", source_instance_id: "fixture-source", collection_scope_id: "fixture-root" },
    coverage: { state: "partial", unread_objects: 2, has_more: true },
    grants: [{ path: "/fixture-folder", layer: "ntfs", principal: "everyone", grant_mask: 6, severity: "medium" }],
    grants_has_more: true, limitations: ["privileges_and_conditional_aces_not_evaluated", "<private-unregistered-reason>"], ...overrides };
}
function showNative() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><DetailSection definition={definition}
    detail={{ ...detail, row_component: "problems.acl-evidence" }} row={{ id: 7 }} baseParams="domain=7&cursor=discard-me"/></QueryClientProvider>);
}

it.each([
  ["en", "Retained ACL snapshot", "Everyone", "Historical grant; current permissions and effective network access are not proven.", "Additional grants exist.", "Some snapshot limitations could not be described."],
  ["ru", "Сохранённый снимок прав", "Все", "Историческое назначение прав; текущие права и эффективный сетевой доступ не доказаны.", "Есть дополнительные назначения прав.", "Некоторые ограничения снимка не удалось описать."],
] as const)("opens historical native grants without an EventLog link (%s)", async (locale, snapshotLabel, everyone, historical, more, fallback) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  vi.spyOn(api, "reportV2Detail").mockResolvedValue({ ...page(1, 0, false), state: "partial", items: [nativeSnapshot()], filtered_count: 1 });
  showNative();
  fireEvent.click(await screen.findByRole("button", { name: snapshotLabel }));
  expect(screen.getByText("/fixture-folder")).toBeTruthy();
  expect(screen.getByText(everyone)).toBeTruthy();
  expect(screen.getByText(t("security.scenarios.filters.risk.medium"))).toBeTruthy();
  expect(screen.getByText(historical)).toBeTruthy();
  expect(screen.getByText(more)).toBeTruthy();
  expect(screen.getByText(fallback)).toBeTruthy();
  expect(screen.queryByText("<private-unregistered-reason>")).toBeNull();
  expect(screen.queryByRole("link")).toBeNull();
  expect(screen.queryByText(t("security.problems.evidence.partial", { count: 1 }))).toBeNull();
  expect(screen.getByText(/NTFS/)).toBeTruthy();
  expect(screen.getByText(locale === "en" ? "Partial inventory" : "Частичная инвентаризация")).toBeTruthy();
  expect(screen.getByText(locale === "en" ? "Unread objects: 2." : "Непрочитанных объектов: 2.")).toBeTruthy();
  expect(document.querySelector("time")?.getAttribute("datetime")).toBe("2026-01-02T03:04:05Z");
});

it.each(["ru", "en"] as const)("counts unavailable snapshots and missing events while retaining a real event link (%s)", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const unavailable = nativeSnapshot({ evidence_key: "fixture-evidence-b", availability: "unavailable", observed_at_utc: null, resource: null,
    coverage: { state: "unknown", unread_objects: null, has_more: null }, grants: [], grants_has_more: false, limitations: ["native_source_unavailable"] });
  vi.spyOn(api, "reportV2Detail").mockResolvedValue({ ...page(1, 0, false), state: "partial", filtered_count: 4,
    items: [{ storage_kind: "core_event", evidence_id: 9, event_db_id: 901, event_id: 4719, evidence_role: "primary" },
      { storage_kind: "core_event", evidence_id: 10, event_db_id: null, evidence_role: "primary" }, nativeSnapshot(), unavailable],
    coverage: { evidence_missing_sources: 2 } });
  showNative();
  expect(await screen.findByText(t("security.problems.evidence.partial", { count: 2 }))).toBeTruthy();
  expect(screen.getAllByRole("link")).toHaveLength(1);
  expect(new URL(screen.getByRole("link").getAttribute("href")!, window.location.origin).pathname).toBe("/app/events/901");
  fireEvent.click(screen.getAllByRole("button", { name: locale === "en" ? "Retained ACL snapshot" : "Сохранённый снимок прав" })[1]);
  expect(screen.getByText(locale === "en" ? "The retained snapshot source is unavailable." : "Источник сохранённого снимка недоступен.")).toBeTruthy();
  expect(screen.queryByText("/fixture-folder")).toBeNull();
  expect(screen.getByText(locale === "en" ? "Historical grant; current permissions and effective network access are not proven." : "Историческое назначение прав; текущие права и эффективный сетевой доступ не доказаны.")).toBeTruthy();
});

it("passes native cursors unchanged and retains selected domain across pages", async () => {
  const cursor = "opaque.native/+?=_fixture";
  const request = vi.spyOn(api, "reportV2Detail").mockResolvedValueOnce({ ...page(1, 0, true), items: [nativeSnapshot()], next_cursor: cursor })
    .mockResolvedValueOnce({ ...page(1, 0, false), items: [nativeSnapshot({ evidence_key: "fixture-evidence-b" })] });
  showNative();
  fireEvent.click(await screen.findByRole("button", { name: t("table.loadMore") }));
  await screen.findByText(t("table.shown", { count: 2 }), { exact: false });
  expect(request.mock.calls[0][2]?.has("cursor")).toBe(false);
  expect(request.mock.calls[1][2]?.get("cursor")).toBe(cursor);
  expect(request.mock.calls[1][2]?.get("domain")).toBe("7");
});

it("does not fetch native evidence or render snapshot metadata after a server access denial", async () => {
  vi.spyOn(api, "reportV2Detail").mockRejectedValue(new ApiResponseError(403));
  showNative();
  await screen.findByText(t("state.denied.title"));
  expect(screen.queryByText("/fixture-folder")).toBeNull();
  expect(screen.queryByRole("button", { name: "Сохранённый снимок прав" })).toBeNull();
  expect(screen.queryByRole("link")).toBeNull();
});

it("keeps native unknown coverage distinct from zero unread objects", async () => {
  vi.spyOn(api, "reportV2Detail").mockResolvedValue({ ...page(1, 0, false), items: [nativeSnapshot({
    coverage: { state: "unknown", unread_objects: null, has_more: null }, grants_has_more: false,
    limitations: ["__proto__"],
  })], filtered_count: 1 });
  showNative();
  fireEvent.click(await screen.findByRole("button", { name: "Сохранённый снимок прав" }));
  expect(screen.getByText("Полнота инвентаризации неизвестна")).toBeTruthy();
  expect(screen.queryByText("Непрочитанных объектов: 0.")).toBeNull();
  expect(screen.queryByText("Есть дополнительные назначения прав.")).toBeNull();
  expect(screen.getByText("Некоторые ограничения снимка не удалось описать.")).toBeTruthy();
});

function nativeSelectionHarness() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const view = (finding = 7, params = "domain=7", allowed = true) => <QueryClientProvider client={client}>
    <DetailSection definition={definition} detail={{ ...detail, row_component: "problems.acl-evidence", access: { allowed } }}
      row={{ id: finding }} baseParams={params}/>
  </QueryClientProvider>;
  return { client, view };
}

it("removes selected snapshot metadata after a successful same-key unavailable refetch", async () => {
  const unavailable = nativeSnapshot({ availability: "unavailable", observed_at_utc: null, resource: null,
    coverage: { state: "unknown", unread_objects: null, has_more: null }, grants: [], grants_has_more: false,
    limitations: ["native_source_unavailable"] });
  vi.spyOn(api, "reportV2Detail").mockResolvedValueOnce({ ...page(1, 0, false), items: [nativeSnapshot()], filtered_count: 1 })
    .mockResolvedValueOnce({ ...page(1, 0, false), state: "partial", items: [unavailable], filtered_count: 1, coverage: { evidence_missing_sources: 1 } });
  const { client, view } = nativeSelectionHarness();
  render(view());
  fireEvent.click(await screen.findByRole("button", { name: "Сохранённый снимок прав" }));
  expect(screen.getByText("/fixture-folder")).toBeTruthy();
  expect(document.querySelector("time")?.getAttribute("datetime")).toBe("2026-01-02T03:04:05Z");
  await act(async () => { await client.refetchQueries({ queryKey: ["report-v2", "detail"] }); });
  await screen.findByText(t("security.problems.evidence.partial", { count: 1 }));
  expect(screen.queryByText("/fixture-folder")).toBeNull();
  expect(document.querySelector("time")).toBeNull();
  expect(screen.queryByText("Все")).toBeNull();
  expect(screen.queryByText(t("security.scenarios.filters.risk.medium"))).toBeNull();
  expect(screen.queryByLabelText(t("reports.detail.selected_row_aria")) === null
    || screen.queryByText("Источник сохранённого снимка недоступен.") !== null).toBe(true);
});

it("clears snapshot selection when the row disappears after refetch", async () => {
  vi.spyOn(api, "reportV2Detail").mockResolvedValueOnce({ ...page(1, 0, false), items: [nativeSnapshot()], filtered_count: 1 })
    .mockResolvedValueOnce({ ...page(1, 0, false), state: "empty", items: [], filtered_count: 0 });
  const { client, view } = nativeSelectionHarness();
  render(view());
  fireEvent.click(await screen.findByRole("button", { name: "Сохранённый снимок прав" }));
  await act(async () => { await client.refetchQueries({ queryKey: ["report-v2", "detail"] }); });
  await screen.findByText(t("security.problems.evidence.empty"));
  expect(screen.queryByLabelText(t("reports.detail.selected_row_aria"))).toBeNull();
  expect(screen.queryByText("/fixture-folder")).toBeNull();
  expect(document.querySelector("time")).toBeNull();
});

it.each([
  ["finding", 8, "domain=7"],
  ["domain", 7, "domain=8"],
  ["query", 7, "domain=7&status=closed"],
] as const)("clears snapshot selection when the %s population changes, even with the same evidence key", async (_change, finding, params) => {
  vi.spyOn(api, "reportV2Detail").mockResolvedValue({ ...page(1, 0, false), items: [nativeSnapshot()], filtered_count: 1 });
  const { view } = nativeSelectionHarness();
  const shown = render(view());
  fireEvent.click(await screen.findByRole("button", { name: "Сохранённый снимок прав" }));
  expect(screen.getByText("/fixture-folder")).toBeTruthy();
  shown.rerender(view(finding, params));
  await screen.findByRole("button", { name: "Сохранённый снимок прав" });
  expect(screen.queryByLabelText(t("reports.detail.selected_row_aria"))).toBeNull();
  expect(screen.queryByText("/fixture-folder")).toBeNull();
  expect(document.querySelector("time")).toBeNull();
});

it("does not restore snapshot selection after detail access is revoked and restored", async () => {
  vi.spyOn(api, "reportV2Detail").mockResolvedValue({ ...page(1, 0, false), items: [nativeSnapshot()], filtered_count: 1 });
  const { view } = nativeSelectionHarness();
  const shown = render(view());
  fireEvent.click(await screen.findByRole("button", { name: "Сохранённый снимок прав" }));
  shown.rerender(view(7, "domain=7", false));
  expect(screen.queryByText("/fixture-folder")).toBeNull();
  shown.rerender(view());
  await screen.findByRole("button", { name: "Сохранённый снимок прав" });
  expect(screen.queryByLabelText(t("reports.detail.selected_row_aria"))).toBeNull();
  expect(screen.queryByText("/fixture-folder")).toBeNull();
});


it.each(["ru", "en"] as const)("renders coded inventory reason details in %s", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const reason = { code: "stale_activity", label: "Активность старше 90 дней", observed: "Русский исходный текст",
    presentation_messages: {
      label: { code: "reports.v2.ad.computers.v6.reasons.stale_activity", params: { threshold_days: 90 } },
      observed: { code: "reports.v2.ad.computers.v6.security.stale_activity.observed",
        params: { last_logon_utc: "2026-01-01T00:00:00Z", age_days: 91 } },
    } };
  const payload = { ...page(1, 1, false), report_key: "ad.computers.v6", items: [{ entity_id: 1, reasons: [reason] }] };
  const [row] = localizeReportResult(payload, "UTC").items;
  const inventory = { key: "ad.computers.v6", title: "Computers" } as ReportDefinitionDto;
  const inline: ReportDetailDto = { kind: "inline", title: "Reason details", key: "entity_id", inline: "reasons",
    columns: [{ key: "label", path: "label", label: "Reason", kind: "text" }, { key: "observed", path: "observed", label: "Observation", kind: "text" }], row_links: [] };
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { container } = render(<QueryClientProvider client={client}><DetailSection definition={inventory} detail={inline} row={row} baseParams=""/></QueryClientProvider>);
  expect(screen.getByText(locale === "en" ? "Activity is older than 90 days" : "Активность старше 90 дней")).toBeTruthy();
  expect(screen.getByText(locale === "en" ? "Last approximate AD observation: Jan 1, 2026, 12:00 AM; age: 91 days."
    : "Последнее приблизительное AD-наблюдение: 01.01.2026, 00:00; возраст: 91 дней.")).toBeTruthy();
  if (locale === "en") expect(container.textContent).not.toMatch(/[А-Яа-яЁё]/);
});

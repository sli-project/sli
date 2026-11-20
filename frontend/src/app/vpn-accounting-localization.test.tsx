// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import type { VpnSessionEvidence, VpnSessionReport } from "../api/client";
import { localeRuntime, setLocale, type Locale } from "../i18n";
import { VpnAccountingSessionsPanel, type SecurityEventsFilterState } from "./security-events-report";

vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
const clients: QueryClient[] = [];
afterEach(() => { cleanup(); clients.splice(0).forEach((client) => client.clear()); setLocale("ru"); });

const sourceId = "синтетический-источник.example.invalid";
const unknownEvent = "vendor_событие";
const filters: SecurityEventsFilterState = {
  domainId: 7, timeFrom: "", timeTo: "", timeZone: "UTC", category: "", eventId: "",
  outcome: "", actor: "", target: "", group: "", source: "", q: "", limit: 200,
};
const session: VpnSessionReport["items"][number] = {
  session_row_id: "session-a", entity_id: 42, domain_id: 7, generation: 1,
  lifecycle_state: "closed", completeness: "complete", started_at_utc: "2026-09-11T10:00:00Z",
  last_observed_at_utc: "2026-09-11T11:00:00Z", stopped_at_utc: "2026-09-11T11:00:00Z",
  duration_seconds: 3600, observation_count: 4, anomalies: [],
};

function renderPanel(locale: Locale, item = session) {
  setLocale(locale);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  clients.push(client);
  client.setQueryData(["investigation-cases"], { items: [] });
  const report: VpnSessionReport = {
    contract_id: "sli.vpn-session-report.v1", report_key: "vpn.audit", source_domain_id: 7,
    state: "available", branches: {}, coverage: null, items: [item],
    page: { limit: 200, offset: 0, has_more: false },
  };
  const evidence: VpnSessionEvidence = {
    contract_id: "sli.vpn-session-evidence.v1", report_key: "vpn.audit", source_domain_id: 7,
    session_row_id: item.session_row_id, state: "available", lifecycle: null,
    branch: { branch: "session_evidence", state: "available", reason: "authorized", dataset_or_resource_group: "vpn" },
    observations: ["start", "stop", "interim_update", unknownEvent].map((event, index) => ({
      observation_id: `observation-${index}`, lifecycle_event: event,
      observed_at_utc: index === 2 ? null : "2026-09-11T10:00:00Z",
      evidence: {
        evidence_uid: `evidence-${index}`, source_instance_id: sourceId, stream_id: "accounting",
        transport_binding: "synthetic", object_reference: `fixture-${index}`,
        canonical_record_sha256: "a".repeat(64), object_sha256: "b".repeat(64), object_size_bytes: 128,
      },
    })),
  };
  client.setQueryData(["security-relations", "vpn-accounting-evidence", 7, item.session_row_id], evidence);
  return render(<QueryClientProvider client={client}><VpnAccountingSessionsPanel
    report={report} items={report.items} loading={false} failed={false} hasMore={false}
    fetchingMore={false} fetchMore={() => {}} filters={filters}/></QueryClientProvider>);
}

it.each(["ru", "en"] as const)("%s: localizes the session row's timestamp labels", (locale) => {
  renderPanel(locale);
  const row = screen.getByText(locale === "en" ? /^AD Object #42 · Start / : /^Объект AD #42 · Начало /);
  expect(row.textContent).toMatch(locale === "en"
    ? / · Start .+ · last observation .+ · Stop .+/
    : / · Начало .+ · последнее наблюдение .+ · Завершение .+/);
});

it.each(["ru", "en"] as const)("%s: renders known evidence events and unconfirmed time", async (locale) => {
  renderPanel(locale);
  await userEvent.click(screen.getByRole("button", { name: locale === "en" ? "Show evidence" : "Показать доказательства" }));
  const observations = within(screen.getByRole("list")).getAllByRole("listitem");
  expect(observations[0].textContent).toMatch(locale === "en" ? /^Start · / : /^Начало · /);
  expect(observations[1].textContent).toMatch(locale === "en" ? /^Stop · / : /^Завершение · /);
  expect(observations[2].textContent).toContain(locale === "en" ? "Interim · time unconfirmed · " : "Промежуточное обновление · время не подтверждено · ");
});

it.each(["ru", "en"] as const)("%s: preserves unknown evidence events and source values", async (locale) => {
  renderPanel(locale);
  await userEvent.click(screen.getByRole("button", { name: locale === "en" ? "Show evidence" : "Показать доказательства" }));
  const observations = within(screen.getByRole("list")).getAllByRole("listitem");
  expect(observations[3].textContent).toContain(`${unknownEvent} · `);
  for (const observation of observations) expect(observation.textContent).toContain(sourceId);
});

it("en: removes system Cyrillic while retaining Cyrillic from source evidence", async () => {
  const { container } = renderPanel("en");
  await userEvent.click(screen.getByRole("button", { name: "Show evidence" }));
  const text = container.textContent ?? "";
  expect(text).toContain(sourceId);
  expect(text).toContain(unknownEvent);
  expect(text.replaceAll(sourceId, "").replaceAll(unknownEvent, "")).not.toMatch(/[А-Яа-яЁё]/);
});

it.each(["ru", "en"] as const)("%s: does not invent a Stop timestamp when it is absent", (locale) => {
  renderPanel(locale, { ...session, lifecycle_state: "open_observed", completeness: "partial",
    stopped_at_utc: null, duration_seconds: null, anomalies: ["missing_stop"] });
  const row = screen.getByText(locale === "en" ? /^AD Object #42 · Start / : /^Объект AD #42 · Начало /);
  expect(row.textContent).toContain(locale === "en" ? " · last observation " : " · последнее наблюдение ");
  expect(row.textContent).not.toContain(locale === "en" ? " · Stop " : " · Завершение ");
  expect(screen.getByText(locale === "en" ? /End and duration not confirmed/ : /Конец и длительность не подтверждены/)).toBeTruthy();
});

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { api, type VpnSessionReport } from "../api/client";
import { VpnAccountingSessionsPanel, type SecurityEventsFilterState } from "./security-events-report";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("binds an in-flight save and its success/cache state to case A after switching to B", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(["investigation-cases"], { items: [{ id: 1, title: "Case A" }, { id: 2, title: "Case B" }] });
  client.setQueryData(["investigation-case", "1"], { title: "Case A" });
  client.setQueryData(["investigation-case", "2"], { title: "Case B" });
  let finish!: (value: Awaited<ReturnType<typeof api.addInvestigationEvidenceRef>>) => void;
  const save = vi.spyOn(api, "addInvestigationEvidenceRef").mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  const report: VpnSessionReport = {
    contract_id: "sli.vpn-session-report.v1", report_key: "vpn.audit", source_domain_id: 7,
    state: "available", branches: { session_evidence: { state: "available", branch: "session_evidence", reason: "authorized", dataset_or_resource_group: "vpn" } }, coverage: null,
    page: { limit: 200, offset: 0, has_more: false },
    items: [{ session_row_id: "session-a", entity_id: 42, domain_id: 7, generation: 1,
      lifecycle_state: "closed", completeness: "complete", started_at_utc: "2026-09-11T10:00:00Z",
      last_observed_at_utc: "2026-09-11T11:00:00Z", stopped_at_utc: "2026-09-11T11:00:00Z",
      duration_seconds: 3600, observation_count: 2, anomalies: [] }],
  };
  const filters: SecurityEventsFilterState = { domainId: 7, timeFrom: "", timeTo: "", timeZone: "UTC", category: "", eventId: "", outcome: "", actor: "", target: "", group: "", source: "", q: "", limit: 200 };
  render(<QueryClientProvider client={client}><VpnAccountingSessionsPanel report={report} items={report.items} loading={false} failed={false} hasMore={false} fetchingMore={false} fetchMore={() => {}} filters={filters}/></QueryClientProvider>);
  await userEvent.click(await screen.findByRole("button", { name: "Сохранить в расследование" }));
  expect(save).toHaveBeenCalledWith(1, { evidence_kind: "vpn_accounting_session", source_domain_id: 7, reference_id: "session-a" });
  await userEvent.selectOptions(screen.getByRole("combobox"), "2");
  expect(screen.queryByRole("button", { name: "Сохраняем…" })).toBeNull();
  await act(async () => { finish({} as Awaited<ReturnType<typeof api.addInvestigationEvidenceRef>>); });
  await waitFor(() => expect(client.getQueryState(["investigation-case", "1"])?.isInvalidated).toBe(true));
  expect(client.getQueryState(["investigation-case", "2"])?.isInvalidated).toBe(false);
  expect(screen.queryByRole("button", { name: "Сохранено" })).toBeNull();
  expect(screen.getByRole("button", { name: "Сохранить в расследование" })).toBeTruthy();
  await userEvent.selectOptions(screen.getByRole("combobox"), "1");
  expect(screen.getByRole("button", { name: "Сохранено" })).toBeTruthy();
});

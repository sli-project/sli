// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import * as app from "../../app/App";
import { api } from "../../api/client";
import { localeRuntime, setLocale, t } from "../../i18n";
import { WorkstationsPage } from "./route";

let lastLogin: unknown = {};
let deviceSummary: unknown = {};
let processFinding: Record<string, unknown> | null = null;
let denied = false;
let listOverrides: Partial<ReportResultDto> = {};
let revision = "synthetic-initial";
const requests: string[] = [];
const station = { station_id: "ws:ad:123", agent_key: "synthetic-agent", ad_computer_id: null,
  station_type: "workstation", metadata: { display_name: "Synthetic workstation", operating_system: "Synthetic OS" }, observed_checks: 1 };
const definition: ReportDefinitionDto = { key: "workstations.overview", section: "reports/workstations", title: "Workstations",
  description: "", archetype: "journal", params: [], columns: [], views: [], row_key: "station_id", detail: "fields",
  export: false, limits: { default: 50, max: 50 }, presets: [], row_links: [], filter_options: {} };
const result = (overrides: Partial<ReportResultDto> = {}): ReportResultDto => ({
  contract_id: "sli.report-result.v2", report_key: definition.key, state: "partial", items: [{ ...station, last_interactive_login: lastLogin, devices: deviceSummary }],
  has_more: false, next_cursor: null, filtered_count: 1, metrics: [], series: {}, coverage: {}, filter_options: {},
  limitations: [], window: {}, collections: { paging: [{ start: 1, has_previous: false, previous_cursor: null }], checks: [] }, ...overrides,
});

beforeEach(() => {
  listOverrides = {};
  processFinding = null; deviceSummary = {}; lastLogin = {}; denied = false; revision = "synthetic-initial"; requests.length = 0;
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  vi.spyOn(app, "useEffectiveAccess").mockImplementation(() => ({ subject: { type: "session", id: 7 },
    evaluated_at_utc: revision, capabilities: ["workstations.read"], reports: [] }) as unknown as ReturnType<typeof app.useEffectiveAccess>);
  vi.spyOn(app, "useTimeZone").mockReturnValue({ timeZone: "UTC", setTimeZone: vi.fn() } as ReturnType<typeof app.useTimeZone>);
  window.history.replaceState(null, "", "/app/workstations?tab=stations&search=synthetic&domain_id=11&domain=22");
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input); requests.push(url);
    if (denied && url.includes("/data?")) return new Response(JSON.stringify({ error: "workstation_access_denied" }), { status: 403 });
    if (url.includes("/detail?") && url.includes("finding_id=")) return new Response(JSON.stringify(result({ state: "ok", items: [{ source_xml: "<Event>synthetic</Event>", source_sha256: "b".repeat(64) }] })));
    if (url.includes("/detail?")) return new Response(JSON.stringify(result({ collections: { findings: [processFinding ?? {
      id: "a".repeat(64), check_id: "C05", reason_code: "service_or_task_changed", reason_params: {},
      evidence_refs: [{ kind: "workstation_observation", observation_id: "c".repeat(64), agent_key: "synthetic-agent" }],
    }] } })));
    return new Response(JSON.stringify(url.includes("/data?") ? result(listOverrides) : definition), { headers: { "Content-Type": "application/json" } });
  }));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><WorkstationsPage/></QueryClientProvider>);
  return { ...view, refresh: () => view.rerender(<QueryClientProvider client={client}><WorkstationsPage/></QueryClientProvider>) };
}

it.each(["ru", "en"] as const)("explains the first inventory build without a false zero (%s)", async (locale) => {
  listOverrides = { items: [], filtered_count: null, coverage: { population_status: "inventory_pending" },
    metrics: [{ key: "stations", label: "workstations.overview.stations", value: null, quality: "unknown" },
      { key: "observed", label: "workstations.overview.observed", value: null, quality: "unknown" }] };
  setLocale(locale); mount();
  expect(await screen.findByText(t("workstations.overview.inventoryPending"))).toBeTruthy();
  const metrics = screen.getByRole("region", { name: t("reports.summaryAria") });
  expect(within(metrics).queryByText("0")).toBeNull();
  expect(within(metrics).queryByText("≥ null")).toBeNull();
  expect(within(metrics).getAllByText(t("workstations.overview.unknown"))).toHaveLength(2);
});

it.each(["ru", "en"] as const)("explains missing agents and keeps observed counts as lower bounds (%s)", async (locale) => {
  listOverrides = { coverage: { population_status: "no_agents" },
    metrics: [{ key: "stations", label: "workstations.overview.stations", value: 3, quality: "observed" }] };
  setLocale(locale); mount();
  expect(await screen.findByText(t("workstations.overview.noAgents"))).toBeTruthy();
  expect(screen.getByText("≥ 3")).toBeTruthy();
});

it.each(["ru", "en"] as const)("explains pending check processing (%s)", async (locale) => {
  listOverrides = { coverage: { population_status: "awaiting_observations" }, collections: { checks: [
    { check_id: "C01", title_key: "workstations.checks.C01.title", counts: { stations: { value: null, relation: "unknown" } } },
  ] } };
  window.history.replaceState(null, "", "/app/workstations?tab=checks&check_id=C01");
  setLocale(locale); mount();
  expect(await screen.findByText(t("workstations.overview.awaitingObservations"))).toBeTruthy();
  expect(screen.getByText(t("workstations.overview.checkPending"))).toBeTruthy();
});

it.each(["ru", "en"] as const)("opens the real registered view, card and exact source, preserving return state (%s)", async (locale) => {
  setLocale(locale); mount();
  fireEvent.click(await screen.findByRole("button", { name: "Synthetic workstation" }));
  const dialog = await screen.findByRole("dialog");
  fireEvent.click(await within(dialog).findByRole("button", { name: `${t("workstations.overview.evidence")} 1` }));
  expect(await screen.findByText("<Event>synthetic</Event>")).toBeTruthy();
  expect(requests.some((url) => url.includes("finding_id=") && url.includes("evidence_index=1"))).toBe(true);
  const dataRequests = requests.filter((url) => url.includes("/data?") || url.includes("/detail?"));
  expect(dataRequests.every((url) => new URL(url, window.location.origin).searchParams.get("domain") === "11")).toBe(true);
  expect(dataRequests.some((url) => url.includes("/rows/ws%3Aad%3A123/detail?"))).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: t("workstations.overview.backToStation") }));
  expect(new URLSearchParams(window.location.search).get("station")).toBe("ws:ad:123");
  expect(new URLSearchParams(window.location.search).get("search")).toBe("synthetic");
  expect(new URLSearchParams(window.location.search).get("domain_id")).toBe("11");
  fireEvent.click(within(dialog).getByRole("button", { name: t("drawer.close") }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(new URLSearchParams(window.location.search).has("station")).toBe(false);
});

it.each(["ws:ad:123", "ws:agent:60f58b59-3811-4940-85db-a3de8ea664bb"])("encodes the actual client detail URL once (%s)", async (id) => {
  await api.reportV2Detail("workstations.overview", id, new URLSearchParams("domain=11"));
  expect(requests).toEqual([`/api/v2/reports/workstations.overview/rows/${encodeURIComponent(id)}/detail?domain=11`]);
});

it("clears a previously opened source and station after access evaluation changes", async () => {
  const view = mount();
  fireEvent.click(await screen.findByRole("button", { name: "Synthetic workstation" }));
  fireEvent.click(await screen.findByRole("button", { name: `${t("workstations.overview.evidence")} 1` }));
  expect(await screen.findByText("<Event>synthetic</Event>")).toBeTruthy();
  denied = true; revision = "synthetic-revoked"; view.refresh();
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(screen.queryByText("<Event>synthetic</Event>")).toBeNull();
  expect(screen.queryByRole("button", { name: "Synthetic workstation" })).toBeNull();
});


it.each(["ru", "en"] as const)("shows the last observed target login in the registered list and card, never an active session (%s)", async (locale) => {
  lastLogin = { observed_at: "2026-10-19T12:30:00+00:00", logon_type: 10,
    account: { name: "Synthetic target", domain: "EXAMPLE", sid: "S-1-5-21-1-2-3-1001" },
    current_state: "unknown", evidence_ref: { observation_id: "c".repeat(64) } };
  setLocale(locale); mount();
  expect(await screen.findByText("EXAMPLE\\Synthetic target")).toBeTruthy();
  expect(screen.queryByText("S-1-5-21-1-2-3-1001")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Synthetic workstation" }));
  const dialog = await screen.findByRole("dialog");
  expect(await within(dialog).findByText("EXAMPLE\\Synthetic target")).toBeTruthy();
  expect(within(dialog).getByText(t("workstations.overview.loginType10"))).toBeTruthy();
  expect(within(dialog).getByText(t("workstations.overview.loginNotCurrent"))).toBeTruthy();
  expect(within(dialog).getByText(/2026/)).toBeTruthy();
});

it.each([{}, { observed_at: "invalid", logon_type: 2, account: { name: "bad" } },
  { observed_at: "2026-10-19T12:30:00Z", logon_type: 3, account: { name: "network" } },
  { observed_at: "2026-10-19T12:30:00Z", logon_type: "unknown", account: { name: "unclassified" } }])(
  "does not invent an interactive login from absent or invalid summaries", async (value) => {
    lastLogin = value; mount();
    fireEvent.click(await screen.findByRole("button", { name: "Synthetic workstation" }));
    const dialog = await screen.findByRole("dialog");
    await within(dialog).findByText(t("workstations.overview.lastLogin"));
    for (const name of ["bad", "network", "unclassified"]) expect(screen.queryByText(name)).toBeNull();
  });


it.each(["ru", "en"] as const)("shows observed device lower bounds in the registered list and card (%s)", async (locale) => {
  deviceSummary = { devices_7d: { value: 2, relation: "at_least" }, baseline_status: "unknown" };
  setLocale(locale); mount();
  expect(await screen.findByText("≥ 2")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Synthetic workstation" }));
  const dialog = await screen.findByRole("dialog");
  expect(await within(dialog).findByText(t("workstations.overview.devices7d"))).toBeTruthy();
  expect(within(dialog).getByText("≥ 2")).toBeTruthy();
});

it("does not turn an unknown device baseline into zero", async () => {
  deviceSummary = { devices_7d: { value: null, relation: "unknown" }, baseline_status: "unknown" };
  mount();
  fireEvent.click(await screen.findByRole("button", { name: "Synthetic workstation" }));
  const dialog = await screen.findByRole("dialog");
  await within(dialog).findByText(t("workstations.overview.devices7d"));
  expect(screen.queryByText("≥ 0")).toBeNull();
});


it.each(["ru", "en"] as const)("shows bounded observed C04 metadata without signature or live-process claims (%s)", async (locale) => {
  processFinding = { id: "a".repeat(64), check_id: "C04", reason_code: "suspicious_process_path", reason_params: {},
    process_details: { path: "C:\\Windows\\Temp\\fixture.exe", process_id: "17", signature_status: "not_received", current_state: "unknown",
      command_line: "PRIVATE-COMMAND", signer: "UNPROVEN-SIGNER" } };
  setLocale(locale); mount();
  fireEvent.click(await screen.findByRole("button", { name: "Synthetic workstation" }));
  const dialog = await screen.findByRole("dialog");
  expect(await within(dialog).findByText("C:\\Windows\\Temp\\fixture.exe")).toBeTruthy();
  expect(within(dialog).getByText("17")).toBeTruthy();
  expect(within(dialog).getByText(t("workstations.process.signature_not_received"))).toBeTruthy();
  expect(within(dialog).getByText(t("workstations.process.current_state_unknown"))).toBeTruthy();
  expect(screen.queryByText("PRIVATE-COMMAND")).toBeNull();
  expect(screen.queryByText("UNPROVEN-SIGNER")).toBeNull();
});

it("does not render process details for another check type", async () => {
  processFinding = { id: "a".repeat(64), check_id: "C05", reason_code: "service_or_task_changed", reason_params: {},
    process_details: { path: "foreign-process", process_id: "17", signature_status: "not_received" } };
  mount(); fireEvent.click(await screen.findByRole("button", { name: "Synthetic workstation" }));
  const dialog = await screen.findByRole("dialog");
  await within(dialog).findByText(t("workstations.checks.C05.title"));
  expect(screen.queryByText("foreign-process")).toBeNull();
});

it.each(["ru", "en"] as const)("labels signature as current file measurement, not executed process trust (%s)", async (locale) => {
  processFinding = { id: "a".repeat(64), check_id: "C04", reason_code: "suspicious_process_path", reason_params: {},
    process_details: { path: "C:\\Windows\\Temp\\fixture.exe", process_id: "17", current_state: "unknown",
      file_measurement: { scope: "file_at_measurement", status: "signed", observed_at_utc: "2026-10-28T12:00:00+00:00",
        sha256_before: "a".repeat(64), sha256_after: "a".repeat(64), identity_before: "b".repeat(64), identity_after: "b".repeat(64),
        signer_sha256: "c".repeat(64), kind: "embedded", reason: null } } };
  setLocale(locale); mount();
  fireEvent.click(await screen.findByRole("button", { name: "Synthetic workstation" }));
  const dialog = await screen.findByRole("dialog");
  expect(await within(dialog).findByText("a".repeat(64))).toBeTruthy();
  expect(within(dialog).getByText(t("workstations.process.measurement_signed"))).toBeTruthy();
  expect(within(dialog).getByText(t("workstations.process.measurement_limit"))).toBeTruthy();
  expect(within(dialog).getByText(t("workstations.process.current_state_unknown"))).toBeTruthy();
  expect(within(dialog).queryByText(t("workstations.process.signature_not_received"))).toBeNull();
});

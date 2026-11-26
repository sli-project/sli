// @vitest-environment jsdom
import { chooseOption } from "../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiResponseError } from "../api/client";
import { OverlayProvider } from "../design-system";
import { localeRuntime, setLocale } from "../i18n";

const state = vi.hoisted(() => ({ manage: true }));
vi.mock("./App", () => ({ useEffectiveAccess: () => ({ capabilities: state.manage ? ["investigations.manage"] : [] }) }));
vi.mock("./problem-case-actions", () => ({ ProblemCaseActions: () => <button type="button">Open investigation</button> }));
import { exportFinding, ProblemRiskAcceptance, RiskBadge } from "./problem-risk-acceptance";

beforeEach(() => {
  state.manage = true;
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => { callback(0); return 0; });
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  vi.spyOn(api, "riskResponsibles").mockResolvedValue({ items: [{ id: 12, username: "fixture-owner" }] });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function mount(row: Record<string, unknown> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><OverlayProvider>
    <ProblemRiskAcceptance row={{ id: 7, ...row }} formatTime={(value) => value || "—"}/>
  </OverlayProvider></QueryClientProvider>);
  return client;
}

const future = () => new Date(Date.now() + 86400000).toISOString();
async function fill() {
  fireEvent.change(screen.getByLabelText("Reason"), { target: { value: " Fixture reason " } });
  await chooseOption(screen.getByLabelText("Responsible platform user", { selector: "button" }), "12");
  fireEvent.change(screen.getByLabelText("Valid until"), { target: { value: future().slice(0, 16) } });
}

it("opens a dialog with mandatory fields, investigation and finding export", async () => {
  const change = vi.spyOn(api, "changeFindingRisk").mockResolvedValue({ status: "ok", acceptance: {
    id: 31, finding_id: 7, state: "active", expires_at: future(), responsible_user_id: 12,
    reason: "Fixture reason", created_by: "fixture-analyst", created_at: future(),
  }, risk_audit: [] });
  const client = mount();
  const invalidate = vi.spyOn(client, "invalidateQueries");
  fireEvent.click(screen.getByRole("button", { name: "Snooze" }));
  const dialog = screen.getByRole("dialog", { name: "Snooze" });
  expect(within(dialog).getByRole("button", { name: "Open investigation" })).toBeTruthy();
  expect(within(dialog).getByRole("button", { name: "Export finding" })).toBeTruthy();
  await waitFor(() => expect(screen.getByLabelText("Responsible platform user", { selector: "button" })).toHaveProperty("disabled", false));
  fireEvent.click(within(dialog).getByRole("button", { name: "Snooze" }));
  expect(change).not.toHaveBeenCalled();
  expect(screen.getByRole("alert").textContent).toContain("reason");
  await fill();
  fireEvent.click(within(dialog).getByRole("button", { name: "Snooze" }));
  await waitFor(() => expect(change).toHaveBeenCalledWith(7, expect.objectContaining({
    action: "create", reason: "Fixture reason", responsible_user_id: 12, expires_at: expect.any(String),
  })));
  expect("created_by" in change.mock.calls[0][1]).toBe(false);
  await waitFor(() => expect(invalidate).toHaveBeenCalledWith({ queryKey: ["report-v2", "data"] }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(screen.getByRole("button", { name: "Cancel snooze" })).toBeTruthy();
});

it("shows acceptance, expiry, responsible, author and audit, and revokes the exact acceptance", async () => {
  const change = vi.spyOn(api, "changeFindingRisk").mockResolvedValue({ status: "ok", acceptance: { id: 31, state: "revoked" } } as never);
  mount({ risk_acceptance: { id: 31, state: "active", expires_at: future(), reason: "Fixture decision", responsible_user_id: 12,
    responsible_username: "fixture-owner", created_by: "fixture-analyst", created_at: "fixture time" },
  risk_audit: [{ id: 1, action: "suppression_create", actor: "fixture-analyst", occurred_at: "fixture time",
    details: { rule: { reason: "Fixture decision", responsible_user_id: 12, expires_at: "fixture expiry" } } }] });
  expect(screen.getByText(/Snoozed ·/)).toBeTruthy();
  expect(screen.getByText(/fixture-owner/)).toBeTruthy();
  expect(screen.getAllByText(/fixture-analyst/).length).toBeGreaterThan(0);
  fireEvent.click(screen.getByRole("button", { name: "Cancel snooze" }));
  await waitFor(() => expect(change).toHaveBeenCalledWith(7, { action: "revoke", id: 31 }));
});

it("renders expired risk distinctly and permits a new decision", () => {
  mount({ status: "repeated", risk_acceptance: { id: 31, state: "active", expires_at: "2000-01-01T00:00:00Z" } });
  expect(screen.getByText(/Snooze expired/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Cancel snooze" })).toBeNull();
  expect(screen.getByRole("button", { name: "Snooze" })).toBeTruthy();
});

it("keeps risk decisions read-only for viewers", () => {
  state.manage = false;
  mount({ risk_acceptance: { id: 31, state: "active", expires_at: future() } });
  expect(screen.getByText(/Snoozed ·/)).toBeTruthy();
  expect(screen.queryByRole("button")).toBeNull();
  expect(api.riskResponsibles).not.toHaveBeenCalled();
});

it("retains the dialog and renders translated contract errors on failure", async () => {
  vi.spyOn(api, "changeFindingRisk").mockRejectedValue(new ApiResponseError(400, "responsible_not_found", "raw server text"));
  mount();
  fireEvent.click(screen.getByRole("button", { name: "Snooze" }));
  await waitFor(() => expect(screen.getByLabelText("Responsible platform user", { selector: "button" })).toHaveProperty("disabled", false));
  await fill();
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Snooze" }));
  await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("active platform user"));
  expect(screen.getByRole("dialog")).toBeTruthy();
  expect(screen.queryByText("raw server text")).toBeNull();
});

it.each(["2000-01-01T00:00", "2100-01-01T00:00"])("rejects an expiry outside the permitted window: %s", async (expiry) => {
  const change = vi.spyOn(api, "changeFindingRisk");
  mount();
  fireEvent.click(screen.getByRole("button", { name: "Snooze" }));
  await waitFor(() => expect(screen.getByLabelText("Responsible platform user", { selector: "button" })).toHaveProperty("disabled", false));
  await fill();
  fireEvent.change(screen.getByLabelText("Valid until"), { target: { value: expiry } });
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Snooze" }));
  expect(change).not.toHaveBeenCalled();
  expect(screen.getByRole("alert")).toBeTruthy();
});

it("exports the visible finding, evidence and risk history as JSON", async () => {
  const createObjectURL = vi.fn().mockReturnValue("blob:fixture");
  const revokeObjectURL = vi.fn();
  vi.stubGlobal("URL", { createObjectURL, revokeObjectURL });
  const captured: { anchor?: HTMLAnchorElement } = {};
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { captured.anchor = this; });
  const row = { id: 7, evidence: [{ event_db_id: 1 }], risk_audit: [{ id: 31 }] };
  exportFinding(row);
  expect(click).toHaveBeenCalledOnce();
  expect(captured.anchor?.download).toBe("finding-7.json");
  const blob = createObjectURL.mock.calls[0][0] as Blob;
  const contents = await new Promise<string>((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.readAsText(blob);
  });
  expect(JSON.parse(contents)).toEqual(row);
  await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith("blob:fixture"));
});

it("can load the full audit in bounded pages without losing the current decision", async () => {
  const entry = (id: number) => ({ id, action: "suppression_create", actor: "fixture-analyst", occurred_at: "fixture time",
    details: { rule: { reason: `Fixture decision ${id}`, responsible_user_id: 12, expires_at: "fixture expiry" } } });
  const load = vi.spyOn(api, "findingRiskAudit").mockResolvedValue({ items: [entry(50)], has_more: false } as never);
  mount({ risk_audit: Array.from({ length: 50 }, (_, index) => entry(100 - index)) });
  fireEvent.click(screen.getByText("Snooze history"));
  fireEvent.click(screen.getByRole("button", { name: "Earlier decisions" }));
  await waitFor(() => expect(load).toHaveBeenCalledWith(7, 51));
  await waitFor(() => expect(screen.getByText(/Fixture decision 50/)).toBeTruthy());
  expect(screen.queryByRole("button", { name: "Earlier decisions" })).toBeNull();
  expect(screen.getByRole("button", { name: "Snooze" })).toBeTruthy();
});

it("refreshes the queue when an acceptance expires without a worker refresh", async () => {
  vi.useFakeTimers();
  try {
    const client = new QueryClient();
    const invalidate = vi.spyOn(client, "invalidateQueries");
    render(<QueryClientProvider client={client}><RiskBadge row={{ risk_acceptance: {
      id: 31, state: "active", expires_at: new Date(Date.now() + 1000).toISOString(),
    } }} formatTime={(value) => value || ""}/></QueryClientProvider>);
    await act(() => vi.advanceTimersByTimeAsync(1001));
    expect(screen.getByText(/Snooze expired/)).toBeTruthy();
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["report-v2", "data"] });
  } finally { vi.useRealTimers(); }
});

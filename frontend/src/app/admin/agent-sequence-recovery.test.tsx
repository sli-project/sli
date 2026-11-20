// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale, t } from "../../i18n";
import { AgentSequenceRecovery } from "./agent-sequence-recovery";
const state = vi.hoisted(() => ({ read: vi.fn(), accept: vi.fn() }));
vi.mock("../../api/client", () => ({ api: { agentSequenceRecovery: (...args: unknown[]) => state.read(...args), acceptAgentSequenceGap: (...args: unknown[]) => state.accept(...args) } }));
const id = "00000000-0000-4000-8000-000000000001";
const gap = { id: "42", agent_id: id, module_id: "sli.workstations", expected_sequence: "9007199254740993", received_sequence: "9007199254741000", missing_packets: "7", observed_at: "2026-10-23T01:00:00Z", previous_observed_at: null, packet_observed_at: "2026-10-23T00:00:00Z", status: "pending", loss_event_count: null, loss_time_bounds_known: false };
const second = { ...gap, id: "43", module_id: "sli.windows.ad-dc", expected_sequence: "9", received_sequence: "11", missing_packets: "2" };
const response = (streams = [gap, second]) => ({ gaps: streams, truncated: false, recovery_preview: { preview_token: "a".repeat(64), agent_id: id, observation_ids: streams.map((item) => item.id), streams } });
function mount(canRecover = true) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}><AgentSequenceRecovery agentId={id} hostName="Fixture host" canRecover={canRecover} active timeZone="UTC"/></QueryClientProvider>);
}
async function open() { await userEvent.click(screen.getByRole("button", { name: t("agents.sequenceRecovery.title") })); }
async function review() { await userEvent.click(await screen.findByRole("button", { name: t("agents.sequenceRecovery.review") })); }
beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); state.read.mockResolvedValue(response()); state.accept.mockResolvedValue({ status: "authorized", preview_token: "a".repeat(64), agent_id: id, observation_ids: ["43", "42"] }); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.resetAllMocks(); });
it("neither loads nor offers recovery without owner scope", () => { mount(false); expect(state.read).not.toHaveBeenCalled(); expect(screen.queryByRole("button")).toBeNull(); });
it.each(["ru", "en"] as const)("submits one explicitly confirmed exact all-stream set (%s)", async (locale) => {
  setLocale(locale); mount(); expect(state.read).not.toHaveBeenCalled(); await open(); await review();
  expect(screen.getByText(t("agents.sequenceRecovery.range", { first: "9007199254740993", last: "9007199254740999", count: "7" }))).toBeTruthy();
  expect(screen.getByText(t("agents.sequenceRecovery.range", { first: "9", last: "10", count: "2" }))).toBeTruthy();
  expect(screen.getAllByRole("checkbox")).toHaveLength(1);
  const submit = screen.getByRole("button", { name: t("agents.sequenceRecovery.accept") }); expect((submit as HTMLButtonElement).disabled).toBe(true);
  await userEvent.click(screen.getByRole("checkbox")); await userEvent.click(submit);
  await waitFor(() => expect(state.accept).toHaveBeenCalledExactlyOnceWith(id, ["42", "43"], "a".repeat(64)));
  expect(await screen.findByText(t("agents.sequenceRecovery.authorized"))).toBeTruthy();
});
it("cancel and close discard consent without mutation", async () => {
  mount(); await open(); await review(); await userEvent.click(screen.getByRole("checkbox")); await userEvent.click(screen.getByRole("button", { name: t("agents.cancel") }));
  await review(); expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false); await open(); await open();
  expect(screen.queryByRole("checkbox")).toBeNull(); expect(state.accept).not.toHaveBeenCalled();
});
it("requires refetch and fresh consent after stale or uncertain response; new streams are not autoaccepted", async () => {
  state.accept.mockRejectedValueOnce(new Error("409 stale")); mount(); await open(); await review(); await userEvent.click(screen.getByRole("checkbox")); await userEvent.click(screen.getByRole("button", { name: t("agents.sequenceRecovery.accept") }));
  expect(await screen.findByRole("alert")).toBeTruthy(); expect((screen.getByRole("checkbox") as HTMLInputElement).disabled).toBe(true);
  const third = { ...gap, id: "44", module_id: "sli.gpo-snapshot" }; state.read.mockResolvedValue(response([gap, second, third]));
  await userEvent.click(screen.getByRole("button", { name: t("agents.sequenceRecovery.reload") })); await review();
  expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false); expect(state.accept).toHaveBeenCalledTimes(1);
  expect((screen.getByRole("button", { name: t("agents.sequenceRecovery.accept") }) as HTMLButtonElement).disabled).toBe(true);
});
it("guards repeated clicks while submission is in flight", async () => {
  let resolve!: (value: unknown) => void; state.accept.mockImplementation(() => new Promise((done) => { resolve = done; }));
  mount(); await open(); await review(); await userEvent.click(screen.getByRole("checkbox")); await userEvent.dblClick(screen.getByRole("button", { name: t("agents.sequenceRecovery.accept") })); expect(state.accept).toHaveBeenCalledTimes(1);
  expect((screen.getByRole("button", { name: t("agents.sequenceRecovery.reload") }) as HTMLButtonElement).disabled).toBe(true);
  await act(async () => { resolve({ status: "authorized", preview_token: "a".repeat(64), agent_id: id, observation_ids: ["42", "43"] }); });
});
it("rejects malformed cross-agent previews instead of offering partial recovery", async () => {
  state.read.mockResolvedValue({ ...response(), recovery_preview: { ...response().recovery_preview, agent_id: "other" } }); mount(); await open(); expect(await screen.findByRole("alert")).toBeTruthy(); expect(screen.queryByRole("button", { name: t("agents.sequenceRecovery.review") })).toBeNull();
});
it("keeps historical accepted loss read-only with no eligible streams", async () => {
  state.read.mockResolvedValue({ ...response([]), gaps: [{ ...gap, status: "accepted" }], truncated: true }); mount(); await open();
  expect(await screen.findByText(t("agents.sequenceRecovery.accepted"))).toBeTruthy(); expect(screen.getByText(t("agents.sequenceRecovery.noEligible"))).toBeTruthy(); expect(screen.getByText(t("agents.sequenceRecovery.truncated"))).toBeTruthy(); expect(screen.queryByRole("button", { name: t("agents.sequenceRecovery.review") })).toBeNull();
});

it("requires fresh confirmation when the same IDs receive a new immutable preview token", async () => {
  mount(); await open(); await review(); await userEvent.click(screen.getByRole("checkbox"));
  state.read.mockResolvedValue({ ...response(), recovery_preview: { ...response().recovery_preview, preview_token: "b".repeat(64) } });
  await userEvent.click(screen.getByRole("button", { name: t("agents.sequenceRecovery.reload") })); await review();
  expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false); expect(state.accept).not.toHaveBeenCalled();
});
it("does not report authorization when the receipt echoes a different preview", async () => {
  state.accept.mockResolvedValue({ status: "authorized", agent_id: id, observation_ids: ["42", "43"], preview_token: "b".repeat(64) });
  mount(); await open(); await review(); await userEvent.click(screen.getByRole("checkbox")); await userEvent.click(screen.getByRole("button", { name: t("agents.sequenceRecovery.accept") }));
  expect(await screen.findByRole("alert")).toBeTruthy(); expect((screen.getByRole("checkbox") as HTMLInputElement).disabled).toBe(true);
});

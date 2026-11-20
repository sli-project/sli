// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiResponseError } from "../api/client";
import { localeRuntime, setLocale, t } from "../i18n";
import { ru } from "../i18n/ru";
import { en } from "../i18n/en";

const state = vi.hoisted(() => ({ read: vi.fn(), save: vi.fn(), accessAvailable: true, actor: { type: "session", id: 1, username: "fixture-owner" } }));
vi.mock("./App", () => ({ useEffectiveAccess: () => state.accessAvailable ? { subject: state.actor } : undefined }));
vi.mock("../api/client", async (importOriginal) => ({
  ...await importOriginal<typeof import("../api/client")>(),
  api: { sigmaRules: (scope: unknown) => state.read(scope), updateSemanticControl: (change: unknown) => state.save(change) },
}));
import { SigmaRulesPanel } from "./sigma-rules";

const scope = { installation_id: "00000000-0000-0000-0000-000000000001", plugin_id: "sli.windows.ad-dc",
  source_instance_id: "fixture-source", source_generation: "fixture-generation", collection_scope_id: "" };
const otherScope = { ...scope, source_generation: "other-generation" };
const execution = { manifest_sha256: "b".repeat(64), plan_sha256: "c".repeat(64), compiler_version: "compiler-v1",
  mapping_version: "mapping-v1", overlay_sha256: null, mode: "test", state: "matched", complete: true,
  counts: { scanned: 10, evaluable: 10, matched: 3, suppressed: 0, unknown: 0, skipped: 0 },
  evaluable_percent: 100, matches_per_1000_evaluable: 300, required_fields: ["CommandLine"],
  evaluation_intervals: [], quality: [] };
function response() {
  return { api_version: "v1", contract: "sli.sigma.rules.v1", read_only: true, state: "available", reason: null,
    metadata_state: "unavailable", window_basis: "latest_retained_test_history", scope, sources: [],
    since: "2026-01-01T00:00:00Z", until: "2026-01-02T00:00:00Z", rules: [{
      rule_id: "00000000-0000-0000-0000-000000000002", raw_sha256: "a".repeat(64), canonical_sha256: "e".repeat(64),
      upstream_commit: "d".repeat(40), status: "test", tags: [], title: null, description: null, metadata_state: "unavailable",
      executions: [execution], runtime: { state: "measured", basis: "eligible_atomic_detection_inputs", enabled: 2, shadow: 7, test: 12 },
      admission: { state: "available", reason: null, policies: [{ policy_id: "fixture-policy", policy_version: 2,
        policy_title: "Synthetic policy title", lifecycle_status: "shadow", admitted: false, effective_mode: "shadow", execution: {} }] },
    }] };
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}><SigmaRulesPanel/></QueryClientProvider>);
}
async function choose(value = scope) {
  fireEvent.change(await screen.findByLabelText(t("security.sigma.list.source")), { target: { value: JSON.stringify(value) } });
}
beforeEach(() => {
  state.accessAvailable = true;
  state.actor = { type: "session", id: 1, username: "fixture-owner" };
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  state.read.mockImplementation(async (selected) => selected ? response() : { ...response(), rules: [], sources: [scope, otherScope] });
  state.save.mockResolvedValue({ status: "ok" });
});

it.each(["success", "error"])("preserves the pending ledger across actual unmount/remount and %s", async (outcome) => {
  let finish!: () => void;
  state.save.mockImplementation(() => new Promise((resolve, reject) => {
    finish = () => outcome === "success" ? resolve({ status: "ok" }) : reject(new Error("uncertain"));
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const node = (show: boolean) => <QueryClientProvider client={client}>{show ? <SigmaRulesPanel/> : <p>Other tab</p>}</QueryClientProvider>;
  const view = render(node(true)); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Reason" } });
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.admit") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledTimes(1));
  view.rerender(node(false)); view.rerender(node(true)); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Duplicate" } });
  const button = screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement;
  expect(button.disabled).toBe(true); fireEvent.click(button); expect(state.save).toHaveBeenCalledTimes(1);
  finish();
  if (outcome === "error") {
    await screen.findByText(t("security.sigma.list.save_failed"));
    view.rerender(node(false)); view.rerender(node(true)); await choose(); await screen.findByRole("table");
    expect(screen.getByText(t("security.sigma.list.save_failed"))).toBeTruthy();
    expect((screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement).disabled).toBe(true);
  } else await waitFor(() => expect(state.read.mock.calls.filter(([value]) => value).length).toBe(3));
});

it.each(["actor", "session"])("isolates a new %s and ignores the old POST completion", async (boundary) => {
  let finish!: (value: unknown) => void;
  state.save.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const node = (show: boolean) => <QueryClientProvider client={client}>{show ? <SigmaRulesPanel/> : null}</QueryClientProvider>;
  const view = render(node(true)); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Reason" } });
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.admit") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledTimes(1));
  view.rerender(node(false));
  if (boundary === "actor") state.actor = { ...state.actor, id: 2, username: "fixture-other-owner" };
  else client.clear();
  view.rerender(node(true)); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "New context" } });
  expect((screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement).disabled).toBe(false);
  const finishOld = finish;
  state.save.mockResolvedValueOnce({ status: "ok" });
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.admit") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(state.read.mock.calls.filter(([value]) => value).length).toBe(3));
  const reads = state.read.mock.calls.length;
  finishOld({ status: "ok" });
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(state.read.mock.calls.length).toBe(reads);
});

it("can actually submit when initially unavailable access becomes authenticated", async () => {
  state.accessAvailable = false;
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  const node = () => <QueryClientProvider client={client}><SigmaRulesPanel/></QueryClientProvider>;
  const view = render(node()); await choose(); await screen.findByRole("table");
  expect((screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement).disabled).toBe(true);
  state.accessAvailable = true; view.rerender(node()); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Authenticated reason" } });
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.admit") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledExactlyOnceWith({ action: "policy_admission",
    policy_id: "fixture-policy", policy_version: 2, enabled: true, reason: "Authenticated reason" }));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.resetAllMocks(); });

it("discovers scopes without entering hashes and keeps titles unknown, TEST and runtime separate", async () => {
  mount(); await choose();
  const table = await screen.findByRole("table", { name: t("security.sigma.list.title") });
  expect(state.read).toHaveBeenCalledWith(scope);
  expect(within(table).getByText(t("security.sigma.list.title_unknown"))).toBeTruthy();
  expect(within(table).getByRole("columnheader", { name: t("security.sigma.list.test") })).toBeTruthy();
  expect(within(table).getByRole("columnheader", { name: t("security.sigma.list.runtime") })).toBeTruthy();
  expect(screen.getByText(/2026-01-01/)).toBeTruthy();
  expect(within(table).getByText(t("security.sigma.list.not_admitted"))).toBeTruthy();
  expect(screen.queryByLabelText(t("security.sigma.scope.catalog"))).toBeNull();
  expect(state.save).not.toHaveBeenCalled();
  const nameCell = within(table).getByText(t("security.sigma.list.title_unknown")).closest("td")!;
  expect(nameCell.textContent).not.toContain("00000000");
  expect(nameCell.textContent).not.toContain("Synthetic policy title");
});

it("renders retained revision labels literally and keeps the bound policy label separate", async () => {
  const data = response();
  Object.assign(data.rules[0], { title: "Retained <Sigma> title", description: "Exact retained purpose", metadata_state: "available" });
  state.read.mockImplementation(async (selected) => selected ? data : { ...data, rules: [], sources: [scope] });
  mount(); await choose(); await screen.findByRole("table");
  const cell = screen.getByText("Retained <Sigma> title").closest("td")!;
  expect(cell.textContent).toContain("Exact retained purpose");
  expect(cell.textContent).not.toContain("Synthetic policy title");
  expect(cell.querySelector("sigma")).toBeNull();
  expect(screen.queryByText(t("security.sigma.list.metadata_unavailable"))).toBeNull();
});

it("requires an explicit reason and sends one exact-version owner admission without optimistic success", async () => {
  let finish!: (value: unknown) => void;
  state.save.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  mount(); await choose(); await screen.findByRole("table");
  const button = screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Reviewed exact revision" } });
  fireEvent.click(button); fireEvent.click(button);
  await waitFor(() => expect(state.save).toHaveBeenCalledTimes(1));
  expect(state.save).toHaveBeenCalledWith({ action: "policy_admission", policy_id: "fixture-policy", policy_version: 2,
    enabled: true, reason: "Reviewed exact revision" });
  expect(screen.queryByText(t("platformSettings.saved"))).toBeNull();
  finish({ status: "ok" });
  await waitFor(() => expect(state.read.mock.calls.filter(([value]) => value).length).toBe(2));
});

it("keeps a failed/uncertain save locked until an explicit fresh read and never retries the write", async () => {
  state.save.mockRejectedValue(new Error("fixture-private-network-error"));
  mount(); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Reason" } });
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.admit") }));
  await screen.findByText(t("security.sigma.list.save_failed"));
  const button = screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement;
  expect(button.disabled).toBe(true); fireEvent.click(button);
  expect(state.save).toHaveBeenCalledTimes(1);
  expect(document.body.textContent).not.toContain("fixture-private-network-error");
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.refresh") }));
  await waitFor(() => expect(screen.queryByText(t("security.sigma.list.save_failed"))).toBeNull());
});

it("hides old rows immediately on scope change and ignores a late result", async () => {
  let finish!: (value: unknown) => void;
  state.read.mockImplementation((selected) => !selected ? Promise.resolve({ ...response(), rules: [], sources: [scope, otherScope] })
    : selected.source_generation === scope.source_generation ? new Promise((resolve) => { finish = resolve; })
      : Promise.resolve({ ...response(), scope: otherScope, rules: [] }));
  mount(); await choose(); await choose(otherScope);
  await screen.findByText(t("security.sigma.no_rules"));
  finish(response());
  await waitFor(() => expect(screen.queryByRole("table")).toBeNull());
});

it("keeps an unresolved admission locked across manual refresh and repeated clicks", async () => {
  let finish!: (value: unknown) => void;
  state.save.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  mount(); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Reason" } });
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.admit") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.refresh") }));
  await waitFor(() => expect(state.read.mock.calls.filter(([value]) => value).length).toBe(2));
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Another reason" } });
  const button = screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement;
  expect(button.disabled).toBe(true); fireEvent.click(button);
  expect(state.save).toHaveBeenCalledTimes(1);
  finish({ status: "ok" });
  await waitFor(() => expect(state.read.mock.calls.filter(([value]) => value).length).toBe(3));
});

it("keeps the exact pending operation across source changes and reconciles its original source", async () => {
  let finish!: (value: unknown) => void;
  state.save.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  state.read.mockImplementation(async (selected) => !selected ? { ...response(), rules: [], sources: [scope, otherScope] }
    : selected.source_generation === scope.source_generation ? response() : { ...response(), scope: otherScope, rules: [] });
  mount(); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Reason" } });
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.admit") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledTimes(1));
  await choose(otherScope); await screen.findByText(t("security.sigma.no_rules"));
  await choose(); await screen.findByRole("table");
  expect((screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement).disabled).toBe(true);
  await choose(otherScope); await screen.findByText(t("security.sigma.no_rules"));
  finish({ status: "ok" });
  await waitFor(() => expect(state.read.mock.calls.filter(([value]) => value?.source_generation === scope.source_generation).length).toBe(3));
  expect(screen.queryByRole("table")).toBeNull();
  expect(state.save).toHaveBeenCalledTimes(1);
});

it("does not reconcile an uncertain write with a read that started before the write settled", async () => {
  let reject!: (value: unknown) => void;
  let oldRead!: (value: unknown) => void;
  let reads = 0;
  state.save.mockImplementation(() => new Promise((_resolve, fail) => { reject = fail; }));
  state.read.mockImplementation((selected) => !selected ? Promise.resolve({ ...response(), rules: [], sources: [scope, otherScope] })
    : ++reads === 2 ? new Promise((resolve) => { oldRead = resolve; }) : Promise.resolve(response()));
  mount(); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Reason" } });
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.admit") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.refresh") }));
  await waitFor(() => expect(reads).toBe(2));
  reject(new Error("fixture uncertain response"));
  await screen.findByText(t("security.sigma.list.save_failed"));
  oldRead(response());
  await waitFor(() => expect((screen.getByRole("button", { name: t("security.sigma.list.refresh") }) as HTMLButtonElement).disabled).toBe(false));
  expect(screen.getByText(t("security.sigma.list.save_failed"))).toBeTruthy();
  expect((screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement).disabled).toBe(true);
  await choose(otherScope); await screen.findByRole("table"); await choose(); await screen.findByRole("table");
  expect((screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: t("security.sigma.list.refresh") }));
  await waitFor(() => expect(screen.queryByText(t("security.sigma.list.save_failed"))).toBeNull());
  expect(state.save).toHaveBeenCalledTimes(1);
});

it.each(["draft", "test", "retired"])("blocks enabling a %s version and retains explicit admission semantics", async (lifecycle) => {
  const data = response(); data.rules[0].admission.policies[0].lifecycle_status = lifecycle;
  state.read.mockImplementation(async (selected) => selected ? data : { ...data, rules: [], sources: [scope] });
  mount(); await choose(); await screen.findByRole("table");
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Reason" } });
  expect((screen.getByRole("button", { name: t("security.sigma.list.admit") }) as HTMLButtonElement).disabled).toBe(true);
});

it("shows nonowner and missing history as unmeasured without controls or zero", async () => {
  const data = response();
  data.rules[0].admission = { state: "unavailable", reason: "owner_required", policies: [] } as unknown as typeof data.rules[0]["admission"];
  data.rules[0].executions = [];
  data.rules[0].runtime = { ...data.rules[0].runtime, state: "unmeasured", enabled: null } as unknown as typeof data.rules[0]["runtime"];
  state.read.mockImplementation(async (selected) => selected ? data : { ...data, rules: [], sources: [scope] });
  mount(); await choose(); const table = await screen.findByRole("table");
  expect(within(table).queryByText("0")).toBeNull();
  expect(screen.queryByRole("button", { name: t("security.sigma.list.admit") })).toBeNull();
  expect(screen.getByText(t("security.sigma.list.owner_required"))).toBeTruthy();
});

it.each([401, 403, 500])("hides stale rows and private diagnostics for read error %s", async (status) => {
  state.read.mockRejectedValue(new ApiResponseError(status));
  mount();
  const alert = await screen.findByRole("alert");
  expect(alert.getAttribute("data-state")).toBe(status === 500 ? "unavailable" : "denied");
  expect(screen.queryByRole("table")).toBeNull();
});

it.each(["ru", "en"] as const)("renders the same localized list contract in %s", async (locale) => {
  expect(Object.keys(ru).filter((key) => key.startsWith("security.sigma.list."))).toEqual(
    Object.keys(en).filter((key) => key.startsWith("security.sigma.list.")));
  setLocale(locale); mount(); await choose(); await screen.findByRole("table");
  expect(document.body.textContent).not.toContain("security.sigma.");
});

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { t } from "../../i18n";
import { AgentDeploymentPanel } from "./agent-deployment";

const id = "00000000-0000-4000-8000-000000000001";
const token = "g".repeat(43);
const blobs: Blob[] = [];
let client: QueryClient;
beforeEach(() => {
  vi.spyOn(api, "agentDeploymentDirectory").mockImplementation(async (body) => body.domain_id ? { computers: [{ id: 7, name: "synthetic-one" }, { id: 8, name: "synthetic-two" }], ous: [], has_more: false } : { domains: [{ id: 1, name: "example.test" }] });
  vi.spyOn(api, "agentTemplates").mockResolvedValue({ items: [{ id, version: 1, assigned_modules: [], collection_policy: { state: "active", interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864 } }] });
  vi.spyOn(api, "agentGroupTokens").mockResolvedValue({ items: [] });
  vi.spyOn(api, "agentUpdateWaves").mockResolvedValue({ items: [] });
  vi.spyOn(api, "createAgentGroupToken").mockImplementation(async () => ({ id, group_id: id, token, expires_at: new Date(Date.now() + 3600000).toISOString() }));
  vi.spyOn(api, "revokeAgentGroupToken").mockResolvedValue({ status: "revoked" });
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: vi.fn((blob: Blob) => { blobs.push(blob); return "blob:synthetic"; }) });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
});
afterEach(() => { cleanup(); client.clear(); blobs.length = 0; vi.restoreAllMocks(); vi.useRealTimers(); });
function view(sessionKey = "owner-one") { return <QueryClientProvider client={client}><AgentDeploymentPanel agents={[]} sessionKey={sessionKey}/></QueryClientProvider>; }
async function prepare() {
  const result = render(view());
  const details = screen.getByText(t("agents.deployment.title")).closest("details")!; details.open = true; fireEvent(details, new Event("toggle"));
  await screen.findByRole("option", { name: "example.test" });
  fireEvent.change(screen.getByLabelText(t("agents.deployment.domain")), { target: { value: "1" } });
  await screen.findByLabelText(t("agents.deployment.allComputers"));
  fireEvent.change(screen.getByLabelText(t("agents.deployment.template")), { target: { value: id } });
  fireEvent.click(screen.getByLabelText(t("agents.deployment.allComputers")));
  fireEvent.click(await screen.findByLabelText("synthetic-one")); fireEvent.click(screen.getByLabelText("synthetic-two"));
  fireEvent.change(screen.getByLabelText(t("agents.deployment.registrationOrigin")), { target: { value: "https://sli.example.test:8443" } });
  fireEvent.change(screen.getByLabelText(t("agents.deployment.registrationPin")), { target: { value: "a".repeat(64) } });
  return result;
}
async function issue() {
  const button = screen.getByRole("button", { name: t("agents.deployment.create") });
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false)); fireEvent.click(button);
  await screen.findByRole("button", { name: t("agents.deployment.registrationDownload", { computer: "synthetic-one" }) });
}
function downloads() { return screen.queryAllByRole("button", { name: /synthetic-(one|two)/ }); }
it("downloads separately only on explicit clicks and keeps secrets out of query/mutation caches", async () => {
  await prepare(); await issue(); expect(URL.createObjectURL).not.toHaveBeenCalled();
  expect(downloads()).toHaveLength(2);
  fireEvent.click(downloads()[0]); fireEvent.click(downloads()[1]);
  expect(blobs).toHaveLength(2); expect(URL.revokeObjectURL).toHaveBeenCalledTimes(2);
  const contents = await Promise.all(blobs.map((blob) => new Promise<string>((resolve, reject) => {
    const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = reject; reader.readAsText(blob);
  })));
  expect(contents.map((value) => JSON.parse(value).enrollment.computer_entity_id)).toEqual([7, 8]);
  expect(contents.map((value) => JSON.parse(value).server_url)).toEqual(["https://sli.example.test:8443/", "https://sli.example.test:8443/"]);
  expect(api.createAgentGroupToken).toHaveBeenCalledOnce();
  expect(api.createAgentGroupToken).toHaveBeenCalledWith(expect.objectContaining({ computer_entity_ids: [7, 8], auto_approve: false, trusted_bindings: [] }));
  expect(JSON.stringify(client.getQueryCache().getAll().map((item) => item.state.data))).not.toContain(token);
  expect(client.getMutationCache().getAll()).toHaveLength(0);
});
it("clears download material when scope changes", async () => {
  await prepare(); await issue(); fireEvent.click(screen.getByLabelText("synthetic-two"));
  await waitFor(() => expect(downloads()).toHaveLength(0)); expect(screen.queryByText(token)).toBeNull();
});
it("does not restore a late token response after a scope change", async () => {
  let resolve!: (value: { id: string; group_id: string; token: string; expires_at: string }) => void;
  vi.mocked(api.createAgentGroupToken).mockImplementation(() => new Promise((done) => { resolve = done; }));
  await prepare(); fireEvent.click(screen.getByRole("button", { name: t("agents.deployment.create") }));
  await waitFor(() => expect(resolve).toBeDefined());
  // A session remount also covers scope changes while controls are disabled by an in-flight request.
  cleanup(); render(view("owner-two"));
  await act(async () => resolve({ id, group_id: id, token, expires_at: new Date(Date.now() + 3600000).toISOString() }));
  expect(downloads()).toHaveLength(0); expect(screen.queryByText(token)).toBeNull();
});
it("clears material on session changes and explicit dismissal", async () => {
  const result = await prepare(); await issue();
  result.rerender(view("owner-two")); await waitFor(() => expect(downloads()).toHaveLength(0));
  expect(screen.queryByText(token)).toBeNull();
});
it("discards a late response when directory scope changes during issuance", async () => {
  let resolve!: (value: { id: string; group_id: string; token: string; expires_at: string }) => void;
  vi.mocked(api.createAgentGroupToken).mockImplementation(() => new Promise((done) => { resolve = done; }));
  await prepare(); fireEvent.click(screen.getByRole("button", { name: t("agents.deployment.create") }));
  await waitFor(() => expect(resolve).toBeDefined());
  act(() => client.setQueryData(["agent-deployment-directory", 1, undefined], { computers: [{ id: 7, name: "synthetic-one" }], ous: [], has_more: false }));
  await act(async () => resolve({ id, group_id: id, token, expires_at: new Date(Date.now() + 3600000).toISOString() }));
  expect(downloads()).toHaveLength(0); expect(screen.queryByText(token)).toBeNull();
});
it("clears material when the issued token is revoked in refreshed metadata", async () => {
  await prepare(); await issue();
  act(() => client.setQueryData(["agent-group-tokens"], { items: [{ id, revoked_at: "synthetic-revocation", expires_at: new Date(Date.now() + 3600000).toISOString() }] }));
  await waitFor(() => expect(downloads()).toHaveLength(0));
});
it("clears expired material without issuing or downloading anything else", async () => {
  vi.mocked(api.createAgentGroupToken).mockImplementation(async () => ({ id, group_id: id, token, expires_at: new Date(Date.now() + 300).toISOString() }));
  await prepare(); await issue();
  await waitFor(() => expect(downloads()).toHaveLength(0));
  expect(URL.createObjectURL).not.toHaveBeenCalled();
});
it("requires explicit endpoint fields and clears a dismissed secret", async () => {
  await prepare();
  expect((screen.getByLabelText(t("agents.deployment.registrationOrigin")) as HTMLInputElement).required).toBe(true);
  expect((screen.getByLabelText(t("agents.deployment.registrationPin")) as HTMLInputElement).required).toBe(true);
  await issue(); fireEvent.click(screen.getByRole("button", { name: t("agents.dismiss") }));
  expect(downloads()).toHaveLength(0); expect(screen.queryByText(token)).toBeNull();
});

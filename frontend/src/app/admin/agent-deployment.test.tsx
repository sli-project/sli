// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, type AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { AgentDeploymentPanel } from "./agent-deployment";

const id = "00000000-0000-4000-8000-000000000001";
const other = "00000000-0000-4000-8000-000000000002";
const binding = { host_id: id, instance_name: null, key_fingerprint: "a".repeat(64), computer_entity_id: 3 };
const agent: AgentItem = { id, host_id: id, status: "active", last_seen: null, assigned_modules: [
  { module_id: "sli.workstations", enabled: true, config: {} }, { module_id: "sli.ad-snapshot", enabled: true, config: {} }],
  policy_revision: 1, applied_policy_revision: 0, certificates: [], rights_probe: {} };

beforeEach(() => {
  vi.spyOn(api, "agentDeploymentDirectory").mockImplementation(async (body) => body.domain_id ? {
    ous: [{ id: 2, name: "fixture-ou" }], computers: [{ id: 3, name: "fixture-computer" }], has_more: false,
  } : { domains: [{ id: 1, name: "example.test" }, { id: 4, name: "other.test" }] });
  vi.spyOn(api, "agentTemplates").mockResolvedValue({ items: [{ id, version: 2, assigned_modules: [], collection_policy: {
    state: "active", interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864 } }] });
  vi.spyOn(api, "agentGroupTokens").mockResolvedValue({ items: [{ id, group_id: other, domain_id: 1, ou_entity_ids: [2],
    computer_entity_ids: [], auto_approve: false, max_uses: 100, uses_count: 1, expires_at: "2099-01-01T00:00:00Z", revoked_at: null }] });
  vi.spyOn(api, "agentUpdateWaves").mockResolvedValue({ items: [{ id: other, version: "1.1.0", status: "running", confirmed: 0, errors: 0 }] });
  vi.spyOn(api, "createAgentGroupToken").mockResolvedValue({ id, group_id: other, token: "synthetic-secret", expires_at: "2099-01-01T00:00:00Z" });
  vi.spyOn(api, "revokeAgentGroupToken").mockResolvedValue({ status: "revoked" });
  vi.spyOn(api, "stopAgentUpdateWave").mockResolvedValue({ id: other, version: "1.1.0", status: "stopped", confirmed: 0, errors: 0 });
  vi.spyOn(api, "saveAgentTemplate").mockResolvedValue({ id, version: 2 });
  vi.spyOn(api, "agentGroupRequests").mockResolvedValue({ items: [{ id: other, ...binding }], has_more: false });
  vi.spyOn(api, "approveAgentGroupRequests").mockResolvedValue({ items: [{ request_id: other, status: "approved", token: "synthetic-personal" }] });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const result = render(<QueryClientProvider client={client}><AgentDeploymentPanel agents={[agent]}/></QueryClientProvider>);
  return { client, ...result };
}
async function open() {
  const details = screen.getByText(t("agents.deployment.title")).closest("details")!;
  details.open = true;
  fireEvent(details, new Event("toggle"));
}
async function choose() {
  await chooseOption(screen.getByLabelText(t("agents.deployment.domain"), { selector: "button" }), "1");
  await chooseOption(screen.getByLabelText(t("agents.deployment.template"), { selector: "button" }), id);
}
async function upload(value: unknown) {
  const file = new File([JSON.stringify(value)], "fixture.json", { type: "application/json" });
  Object.defineProperty(file, "text", { value: async () => JSON.stringify(value) });
  fireEvent.change(screen.getByLabelText(t("agents.deployment.trustedReport")), { target: { files: [file] } });
  await waitFor(() => expect((screen.getByLabelText(t("agents.deployment.trustedReport")) as HTMLInputElement).disabled).toBe(false));
}

it("loads nothing and performs no deployment until the panel is opened", () => {
  mount();
  expect(api.agentDeploymentDirectory).not.toHaveBeenCalled();
  expect(api.createAgentGroupToken).not.toHaveBeenCalled();
});

it("prepares a whole-domain token without enabling automatic approval and keeps secrets out of cache", async () => {
  const copy = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: copy } });
  const { client } = mount(); await open(); await choose();
  const button = screen.getByRole("button", { name: t("agents.deployment.create") });
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(button);
  expect(await screen.findByText("synthetic-secret")).toBeTruthy();
  expect(screen.getByText(/^Действует до|^Expires/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("agents.copy") }));
  await waitFor(() => expect(copy).toHaveBeenCalledWith("synthetic-secret"));
  expect(api.createAgentGroupToken).toHaveBeenCalledWith({ domain_id: 1, ou_entity_ids: [], computer_entity_ids: [],
    max_uses: 100, ttl_seconds: 3600, template_id: id, template_version: 2, auto_approve: false, trusted_bindings: [] });
  expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state.data))).not.toContain("synthetic-secret");
  expect(client.getMutationCache().getAll()).toHaveLength(0);
  fireEvent.click(screen.getByRole("button", { name: t("agents.dismiss") }));
  expect(screen.queryByText("synthetic-secret")).toBeNull();
});

it("selects a computer inside an OU and clears selection when the domain changes", async () => {
  mount(); await open(); await choose();
  await chooseOption(screen.getByLabelText(t("agents.deployment.ou"), { selector: "button" }), "2");
  await waitFor(() => expect(api.agentDeploymentDirectory).toHaveBeenCalledWith({ domain_id: 1, ou_entity_ids: [2] }));
  fireEvent.click(screen.getByLabelText(t("agents.deployment.allComputers")));
  const button = screen.getByRole("button", { name: t("agents.deployment.create") });
  expect((button as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(await screen.findByLabelText("fixture-computer"));
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(button);
  await waitFor(() => expect(api.createAgentGroupToken).toHaveBeenCalledWith(expect.objectContaining({ domain_id: 1, ou_entity_ids: [2], computer_entity_ids: [3] })));
  await chooseOption(screen.getByLabelText(t("agents.deployment.domain"), { selector: "button" }), "4");
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(true));
  expect(screen.getByLabelText(t("agents.deployment.ou"), { selector: "button" }).textContent).toContain(t("agents.deployment.wholeDomain"));
});

it("requires trusted bindings before enabling automatic approval", async () => {
  mount(); await open(); await choose();
  fireEvent.click(screen.getByLabelText(t("agents.deployment.auto")));
  const button = screen.getByRole("button", { name: t("agents.deployment.create") });
  expect((button as HTMLButtonElement).disabled).toBe(true);
  await upload([binding]);
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(button);
  await waitFor(() => expect(api.createAgentGroupToken).toHaveBeenCalledWith(expect.objectContaining({ auto_approve: true, trusted_bindings: [binding] })));
});

it("rejects malformed evidence and leaves automatic enrollment disabled", async () => {
  mount(); await open(); await choose();
  fireEvent.click(screen.getByLabelText(t("agents.deployment.auto")));
  await upload([{ computer_entity_id: 3 }]);
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect((screen.getByRole("button", { name: t("agents.deployment.create") }) as HTMLButtonElement).disabled).toBe(true);
  expect(api.createAgentGroupToken).not.toHaveBeenCalled();
});

it("approves only requests matching the trusted report and returns personal tokens once", async () => {
  mount(); await open(); await upload([binding]);
  fireEvent.click(screen.getByRole("button", { name: t("agents.deployment.approve") }));
  await waitFor(() => expect(api.approveAgentGroupRequests).toHaveBeenCalledWith({ filter: { group_id: other, token_id: id }, evidence: [{ ...binding, request_id: other }] }));
  expect(await screen.findByText(/synthetic-personal/)).toBeTruthy();
});

it("stops enrollment and the existing update wave without starting a wave", async () => {
  mount(); await open();
  fireEvent.click(await screen.findByRole("button", { name: t("agents.deployment.stopBatch") }));
  await waitFor(() => expect(api.revokeAgentGroupToken).toHaveBeenCalledWith(id));
  const stop = screen.getByRole("button", { name: t("agents.deployment.stopWave") });
  await waitFor(() => expect((stop as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(stop);
  await waitFor(() => expect(api.stopAgentUpdateWave).toHaveBeenCalledWith(other));
  expect(api.createAgentGroupToken).not.toHaveBeenCalled();
});

it("copies only portable workstation settings into a group template", async () => {
  mount(); await open();
  await chooseOption(screen.getByLabelText(t("agents.deployment.templateSource"), { selector: "button" }), id);
  fireEvent.click(screen.getByRole("button", { name: t("agents.deployment.saveTemplate") }));
  await waitFor(() => expect(api.saveAgentTemplate).toHaveBeenCalledWith({ expected_version: 0,
    assigned_modules: [agent.assigned_modules[0]], collection_policy: {} }));
});

it("keeps the selected unnamed template source identifiable in technical details", async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><AgentDeploymentPanel agents={[agent, { ...agent, id: other, host_id: other }]}/></QueryClientProvider>);
  await open();
  const select = screen.getByLabelText(t("agents.deployment.templateSource"), { selector: "button" });
  for (const source of [id, other]) {
    await chooseOption(select, source);
    const details = document.getElementById(select.getAttribute("aria-describedby")!) as HTMLDetailsElement;
    expect(details.open).toBe(false);
    expect(details.textContent).toContain(source);
  }
  expect(api.saveAgentTemplate).not.toHaveBeenCalled();
});

it("keeps a personal token when approval starts at the uploaded scope commit", async () => {
  mount(); await open();
  const approve = await screen.findByRole("button", { name: t("agents.deployment.approve") }) as HTMLButtonElement;
  let resolveText!: (text: string) => void;
  const file = new File(["synthetic"], "fixture.json", { type: "application/json" });
  Object.defineProperty(file, "text", { value: () => new Promise<string>((resolve) => { resolveText = resolve; }) });
  fireEvent.change(screen.getByLabelText(t("agents.deployment.trustedReport")), { target: { files: [file] } });
  await waitFor(() => expect(resolveText).toBeDefined());
  await waitFor(() => expect(approve.disabled).toBe(true));
  let clicked = false;
  const clickAtCommit = new Promise<void>((resolve) => {
    const observer = new MutationObserver(() => {
      if (!clicked && !approve.disabled) {
        clicked = true; observer.disconnect();
        // A real click can arrive after the async upload commit, before passive effects.
        approve.click(); resolve();
      }
    });
    observer.observe(approve, { attributes: true, attributeFilter: ["disabled"] });
  });
  resolveText(JSON.stringify([binding]));
  await clickAtCommit;
  await waitFor(() => expect(api.approveAgentGroupRequests).toHaveBeenCalledWith({ filter: { group_id: other, token_id: id }, evidence: [{ ...binding, request_id: other }] }));
  expect(await screen.findByText(/synthetic-personal/)).toBeTruthy();
});

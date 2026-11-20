// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { api } from "./client";
import domainRequest from "../test-fixtures/password_detection_domain_ui_request.json";

afterEach(() => vi.unstubAllGlobals());

it("reads readiness and an exact agent through their read-only API contracts", async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ items: [] }) });
  vi.stubGlobal("fetch", fetch);
  await api.platformReadiness();
  expect(fetch.mock.calls[0][0]).toBe("/api/v1/operations/overview?view=readiness");
  await api.agents("00000000-0000-4000-8000-000000000001");
  expect(fetch.mock.calls[1][0]).toBe("/api/v1/admin/agents?agent_id=00000000-0000-4000-8000-000000000001");
  await api.agentCollection();
  expect(fetch.mock.calls[2][0]).toBe("/api/v1/overview?view=agents");
});

it("reads the agent inventory and preserves revisioned module/probe mutation bodies", async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ items: [] }) });
  vi.stubGlobal("fetch", fetch);
  await api.agents();
  expect(fetch.mock.calls[0][0]).toBe("/api/v1/admin/agents");
  const body = { agent_id: "synthetic", module_id: "sli.workstations", enabled: false, config: {}, expected_revision: 2 };
  await api.agentAction("modules", body);
  expect(fetch.mock.calls[1][0]).toBe("/api/v1/admin/agents/modules");
  expect(fetch.mock.calls[1][1]).toMatchObject({ method: "POST", credentials: "same-origin", body: JSON.stringify(body) });
  await api.agentAction("rights-probe", { agent_id: "synthetic" });
  expect(fetch.mock.calls[2][0]).toBe("/api/v1/admin/agents/rights-probe");
  await api.agentAction("policy", { agent_id: "synthetic", expected_revision: 2, collection_policy: { state: "paused" } });
  expect(fetch.mock.calls[3][0]).toBe("/api/v1/admin/agents/policy");
  expect(fetch.mock.calls[3][1].body).toBe(JSON.stringify({ agent_id: "synthetic", expected_revision: 2, collection_policy: { state: "paused" } }));
});

it("creates an enrollment token with the requested TTL without a token inventory read", async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ token: "synthetic" }) });
  vi.stubGlobal("fetch", fetch);
  const body = { host_id: "00000000-0000-4000-8000-000000000001", key_fingerprint: "a".repeat(64), ttl_seconds: 600 };
  expect(await api.createAgentToken(body)).toEqual({ token: "synthetic" });
  expect(fetch).toHaveBeenCalledOnce();
  expect(fetch.mock.calls[0][0]).toBe("/api/v1/admin/agent-tokens");
  expect(fetch.mock.calls[0][1]).toMatchObject({ method: "POST", body: JSON.stringify(body) });
});

it("preserves domain/OU selection, trusted bindings and explicit stop/removal targets", async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ items: [] }) });
  vi.stubGlobal("fetch", fetch);
  const id = "00000000-0000-4000-8000-000000000001";
  const binding = { host_id: id, instance_name: null, key_fingerprint: "a".repeat(64), computer_entity_id: 3 };
  const body = { domain_id: 1, ou_entity_ids: [2], computer_entity_ids: [3], template_id: id, template_version: 2,
    max_uses: 100, ttl_seconds: 604800, auto_approve: true, trusted_bindings: [binding] };
  await api.agentDeploymentDirectory({ domain_id: 1, ou_entity_ids: [2] });
  await api.createAgentGroupToken(body);
  await api.revokeAgentGroupToken(id);
  await api.stopAgentUpdateWave(id);
  await api.agentAction("remove", { operation_id: id, agent_ids: [id] });
  expect(fetch.mock.calls.map((call) => call[0])).toEqual([
    "/api/v1/admin/agent-deployment-directory", "/api/v1/admin/agent-group-tokens", "/api/v1/admin/agent-group-tokens/revoke",
    "/api/v1/admin/agent-update-waves/stop", "/api/v1/admin/agents/remove",
  ]);
  expect(fetch.mock.calls[1][1]).toMatchObject({ method: "POST", credentials: "same-origin", body: JSON.stringify(body) });
  expect(fetch.mock.calls[2][1].body).toBe(JSON.stringify({ id }));
  expect(fetch.mock.calls[3][1].body).toBe(JSON.stringify({ wave_id: id }));
  expect(fetch.mock.calls[4][1].body).toBe(JSON.stringify({ operation_id: id, agent_ids: [id] }));
});

it("preserves the exact explicit domain metadata fixture on existing modules transport", async () => {
  const result = { password_detection_domain: { status: "configured", domain_id: 8, domain_fqdn: "synthetic.example" } };
  const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => result });
  vi.stubGlobal("fetch", fetch);
  expect(await api.agentAction("modules", domainRequest)).toEqual(result);
  expect(fetch).toHaveBeenCalledExactlyOnceWith("/api/v1/admin/agents/modules", expect.objectContaining({ method: "POST", body: JSON.stringify(domainRequest) }));
});

it("treats HTTP200 unavailable authority as failure only for explicit domain metadata", async () => {
  const response = { password_detection_domain: { status: "unavailable", domain_id: null, domain_fqdn: null } };
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => response }));
  await expect(api.agentAction("modules", domainRequest)).rejects.toThrow("password_detection_domain_unavailable");
  await expect(api.agentAction("modules", { agent_id: "synthetic", module_id: "sli.windows.ad-dc", enabled: true, config: {}, expected_revision: 7 })).resolves.toEqual(response);
});

it.each([{}, { password_detection_domain: null }, { password_detection_domain: { status: "unknown" } }])("rejects missing or unconfirmed metadata mutation outcomes %#", async (response) => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => response }));
  await expect(api.agentAction("modules", domainRequest)).rejects.toThrow("password_detection_domain_unavailable");
});

it("accepts unchanged explicit mappings and retains separate integer readback", async () => {
  const result = { password_detection_domain: { status: "unchanged", domain_id: 2147483648, domain_fqdn: "synthetic.example" } };
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => result }));
  await expect(api.agentAction("modules", domainRequest)).resolves.toEqual(result);
  const item = { id: domainRequest.agent_id, password_detection_domain: { ...result.password_detection_domain, status: "configured" } };
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => ({ items: [item] }) }));
  expect((await api.agents()).items[0].password_detection_domain?.domain_id).toBe(2147483648);
});

it("reads only the selected agent recovery records and sends explicit loss confirmation", async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ gaps: [] }) });
  vi.stubGlobal("fetch", fetch);
  await api.agentSequenceRecovery("00000000-0000-4000-8000-000000000001");
  expect(fetch.mock.calls[0][0]).toBe("/api/v1/admin/agents/sequence-recovery?agent_id=00000000-0000-4000-8000-000000000001");
  await api.acceptAgentSequenceGap("00000000-0000-4000-8000-000000000001", ["42", "43"], "a".repeat(64));
  expect(fetch.mock.calls[1][0]).toBe("/api/v1/admin/agents/sequence-recovery");
  expect(fetch.mock.calls[1][1]).toMatchObject({ method: "POST", credentials: "same-origin", body: JSON.stringify({ agent_id: "00000000-0000-4000-8000-000000000001", observation_ids: ["42", "43"], preview_token: "a".repeat(64), confirm_loss: true }) });
});

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { AgentItem } from "../../api/client";
import { localeRuntime, setLocale, t } from "../../i18n";

const state = vi.hoisted(() => ({ list: vi.fn(), action: vi.fn(), token: vi.fn(), auditStatus: vi.fn(), accessRevision: "first", owner: false, capabilities: [] as string[], deploymentDirectory: vi.fn(), deploymentTemplates: vi.fn(), deploymentTokens: vi.fn(), deploymentIssue: vi.fn(), deploymentWaves: vi.fn() }));
vi.mock("../App", () => ({ useEffectiveAccess: () => ({ platform_owner: state.owner, capabilities: state.capabilities, subject: { type: "session", id: 1, username: "fixture-owner" }, evaluated_at_utc: state.accessRevision }), useTimeZone: () => ({ timeZone: "UTC" }) }));
vi.mock("../../api/client", async (original) => ({ ...await original<typeof import("../../api/client")>(), api: {
  agentFileAuditStatus: (agentId: string) => state.auditStatus(agentId),
  agentDeploymentDirectory: (body: { domain_id?: number }) => state.deploymentDirectory(body),
  agentTemplates: () => state.deploymentTemplates(), agentGroupTokens: () => state.deploymentTokens(),
  createAgentGroupToken: (body: unknown) => state.deploymentIssue(body), agentUpdateWaves: () => state.deploymentWaves(),
  agents: () => state.list(), agentAction: (kind: string, body: unknown) => state.action(kind, body), createAgentToken: (body: unknown) => state.token(body),
} }));
import { AgentsPage } from "./agents";

const agent: AgentItem = {
  id: "00000000-0000-4000-8000-000000000001", host_id: "00000000-0000-4000-8000-000000000002",
  host_name: "fixture-host", status: "active", last_seen: null, policy_revision: 2, applied_policy_revision: 1,
  assigned_modules: [{ module_id: "sli.workstations", enabled: true, config: { policy_revision: "2" } }],
  certificates: [{ serial: "a1", not_after: "2030-01-01T00:00:00Z", revoked_at: null }], rights_probe: {},
};
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return { client, ...render(<QueryClientProvider client={client}><AgentsPage/></QueryClientProvider>) };
}
beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  state.owner = true; state.capabilities = []; state.accessRevision = "first";
  setLocale("ru"); window.history.replaceState(null, "", "/app/agents");
  state.list.mockResolvedValue({ items: [agent] }); state.action.mockResolvedValue({});
  state.deploymentDirectory.mockResolvedValue({ domains: [] }); state.deploymentTemplates.mockResolvedValue({ items: [] });
  state.deploymentTokens.mockResolvedValue({ items: [] }); state.deploymentWaves.mockResolvedValue({ items: [] });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });
async function openCard(name = agent.host_name!) {
  fireEvent.click((await screen.findByText(name)).closest("tr")!);
  return screen.getByRole("dialog", { name });
}
async function manual() {
  fireEvent.click(screen.getAllByRole("button", { name: t("agents.addComputer") })[0]);
  fireEvent.click(screen.getByRole("tab", { name: t("agents.manualEnrollment") }));
  fireEvent.change(screen.getByLabelText(t("agents.host")), { target: { value: agent.host_id } });
  fireEvent.change(screen.getByLabelText(t("agents.fingerprint")), { target: { value: "a".repeat(64) } });
}

it("denies before loading inventory without owner or access.manage", () => {
  state.owner = false; mount(); expect(state.list).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: t("agents.addComputer") })).toBeNull();
});

it.each(["ru", "en"] as const)("shows the replaced version and confirms removal of the named computer (%s)", async (locale) => {
  setLocale(locale);
  const old = { ...agent, id: "00000000-0000-4000-8000-000000000003", status: "replaced", agent_version: "1.0.0", replacement_version: "1.1.0", server_id: 7 };
  state.list.mockResolvedValue({ items: [{ ...agent, server_id: 7, agent_version: "1.1.0" }, old] });
  mount();
  expect(await screen.findByText(locale === "ru" ? "Заменён версией 1.1.0" : "Replaced by version 1.1.0")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("agents.removeOld") }));
  const dialog = screen.getByRole("dialog"); expect(within(dialog).getByRole("heading").textContent).toContain("fixture-host");
  expect(state.action).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole("button", { name: t("agents.removeOld") }));
  await waitFor(() => expect(state.action).toHaveBeenCalledWith("remove", expect.objectContaining({ agent_ids: [old.id] })));
});

it.each(["ru", "en"] as const)("offers registration instead of removal for an erroneously revoked agent (%s)", async (locale) => {
  setLocale(locale);
  state.list.mockResolvedValue({ items: [agent, { ...agent, id: "00000000-0000-4000-8000-000000000003",
    status: "replaced", certificate_reissue_required: true }] });
  mount();
  expect(await screen.findByText(t("agents.certificateReissueRequired", { name: "fixture-host" }))).toBeTruthy();
  expect(screen.getByRole("link", { name: t("agents.registerAgain") }).getAttribute("href")).toBe("/app/agents?register=1");
  expect(screen.queryByRole("button", { name: t("agents.removeOld") })).toBeNull();
  expect(state.action).not.toHaveBeenCalled();
});

it("opens the existing registration panel from the certificate recovery link", async () => {
  window.history.replaceState(null, "", "/app/agents?register=1");
  mount();
  expect(await screen.findByRole("dialog", { name: t("agents.addComputer") })).toBeTruthy();
});

it("shows the reissue fact without an owner action to a reader", async () => {
  state.owner = false; state.capabilities = ["access.manage"];
  state.list.mockResolvedValue({ items: [agent, { ...agent, id: "00000000-0000-4000-8000-000000000003",
    status: "replaced", agent_version: "0.2.2", certificate_reissue_required: true }] });
  mount();
  await screen.findByText(t("agents.certificateReissueRequired", { name: "fixture-host" }));
  const table = screen.getByRole("table", { name: t("agents.oldAgents") });
  expect(within(table).getByText("—")).toBeTruthy();
  expect(within(table).queryByRole("link")).toBeNull();
  expect(within(table).queryByRole("button", { name: t("agents.removeOld") })).toBeNull();
});

it.each(["ru", "en"] as const)("keeps the list compact and opens existing controls in a drawer in %s", async (locale) => {
  setLocale(locale);
  state.list.mockResolvedValue({ items: [{ ...agent, last_seen: new Date().toISOString(),
    collection_policy: { state: "active", interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864 },
    windows_audit: { policy_revision: 2, reported_at: "2026-11-13T00:00:00Z", management_state: "applied", command_line_enabled: true, families: {
      logons: { state: "ok", required: [{ guid: "fixture-logon", subcategory: "logon", success: true, failure: true, actual_success: true, actual_failure: true }], non_security_channels: [] } } },
    policy_audit: [{ id: 1, action: "policy_ack", actor: "fixture-admin", occurred_at: "2026-11-13T00:00:00Z", details: {} }],
  }] });
  mount();
  const table = await screen.findByRole("table");
  expect(table.querySelector("tbody details")).toBeNull();
  expect(within(table).getByText(t("agents.working"))).toBeTruthy();
  expect(within(table).getByText(t("agents.auditConfigured"))).toBeTruthy();
  expect(within(table).queryByText(agent.host_id)).toBeNull();
  expect(screen.queryByRole("dialog")).toBeNull();
  const drawer = await openCard();
  for (const key of ["agents.collection", "agents.windowsAudit", "agents.certificate", "agents.audit", "agents.actions"] as const)
    expect(within(drawer).getByRole("heading", { name: t(key) })).toBeTruthy();
  expect(within(drawer).getByText(agent.host_id)).toBeTruthy();
  expect(within(drawer).getByText(agent.id)).toBeTruthy();
  fireEvent.keyDown(document, { key: "Escape" }); expect(screen.queryByRole("dialog")).toBeNull();
});

it("shows disabled computers only in their quick filter and counts each group", async () => {
  state.list.mockResolvedValue({ items: [agent, { ...agent, id: "disabled-agent", host_id: "disabled-host", host_name: "disabled.example.test", status: "disabled" }] });
  mount(); await screen.findByText(agent.host_name!);
  expect(screen.queryByText("disabled.example.test")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Отключённые · 1" }));
  expect(screen.getByText("disabled.example.test")).toBeTruthy(); expect(screen.queryByText(agent.host_name!)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Все · 1" }));
  expect(screen.queryByText("disabled.example.test")).toBeNull();
});

it("filters silent computers and disabled audit requirements from received observations", async () => {
  state.list.mockResolvedValue({ items: [{ ...agent, last_seen: new Date().toISOString() }, { ...agent,
    id: "silent-agent", host_id: "silent-host", host_name: "silent.example.test", last_seen: "2026-01-01T00:00:00Z",
    windows_audit: { policy_revision: 2, reported_at: "2026-11-13T00:00:00Z", management_state: "applied", command_line_enabled: false, families: {
      logons: { state: "missing", required: [{ guid: "fixture-logon", subcategory: "logon", success: true, failure: true, actual_success: false, actual_failure: true }], non_security_channels: [] } } },
  }] });
  mount(); await screen.findByText("silent.example.test");
  fireEvent.click(screen.getByRole("button", { name: "Молчат · 1" }));
  expect(screen.queryByText(agent.host_name!)).toBeNull();
  expect(screen.getByText(/^Молчит с/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Аудит выключен · 1" }));
  expect(screen.getByText("Выключено настроек: 1")).toBeTruthy();
  expect(window.location.search).toBe("?filter=auditOff");
});

it("does not claim audit configuration for an unreported audit", async () => {
  mount(); const table = await screen.findByRole("table");
  expect(within(table).queryByText(t("agents.auditConfigured"))).toBeNull();
  const drawer = await openCard();
  expect(within(drawer).queryByRole("heading", { name: t("agents.windowsAudit") })).toBeNull();
  expect(within(drawer).queryByRole("heading", { name: t("agents.audit") })).toBeNull();
});

it("renders one row per computer using its active registration", async () => {
  state.list.mockResolvedValue({ items: [agent, { ...agent, id: "old-registration", status: "disabled", host_name: "old.example.test" }] });
  mount(); await screen.findByText(agent.host_name!);
  expect(screen.queryByText("old.example.test")).toBeNull();
  expect(screen.getByRole("button", { name: "Все · 1" })).toBeTruthy();
});

it("opens a deep-linked computer directly in its card", async () => {
  window.history.replaceState(null, "", `/app/agents?agent_id=${agent.id}#agent-${agent.id}`);
  mount(); expect(await screen.findByRole("dialog", { name: agent.host_name! })).toBeTruthy();
});

it("offers registration in the add panel and hides file audit", async () => {
  mount(); await screen.findByText(agent.host_name!);
  expect(state.deploymentDirectory).not.toHaveBeenCalled();
  expect(screen.queryByText(t("agents.fileAudit.title"))).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("agents.addComputer") }));
  const drawer = screen.getByRole("dialog", { name: t("agents.addComputer") });
  expect(within(drawer).getByRole("tab", { name: t("agents.deployment.title") }).getAttribute("aria-selected")).toBe("true");
  expect(within(drawer).getByRole("button", { name: t("agents.deployment.create") })).toBeTruthy();
  fireEvent.click(within(drawer).getByRole("tab", { name: t("agents.manualEnrollment") }));
  expect(within(drawer).getByRole("button", { name: t("agents.createToken") })).toBeTruthy();
});

it("names the next step and opens the add panel from an empty list", async () => {
  state.list.mockResolvedValue({ items: [] }); mount();
  expect(await screen.findByText(t("agents.emptyComputers"))).toBeTruthy();
  fireEvent.click(screen.getAllByRole("button", { name: t("agents.addComputer") })[1]);
  expect(screen.getByRole("dialog", { name: t("agents.addComputer") })).toBeTruthy();
});

it("names an inventory loading failure without exposing server details", async () => {
  state.list.mockRejectedValue(new Error("private-fixture-diagnostic")); mount();
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", t("agents.loadError"));
  expect(screen.queryByText("private-fixture-diagnostic")).toBeNull();
});

it("preserves module changes and their revision from the card", async () => {
  mount(); const drawer = await openCard();
  fireEvent.click(within(drawer).getByRole("checkbox", { name: t("agents.moduleWorkstations") }));
  await waitFor(() => expect(state.action).toHaveBeenCalledWith("modules", { agent_id: agent.id,
    module_id: "sli.workstations", enabled: false, config: { policy_revision: "2" }, expected_revision: 2 }));
});

it("keeps manual registration secrets out of caches and clears them when closing the panel", async () => {
  const secret = "synthetic-one-time-token";
  state.token.mockResolvedValue({ id: "synthetic", host_id: agent.host_id, token: secret, expires_at: "2030-01-01T00:00:00Z" });
  const copy = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: copy } });
  const view = mount(); await manual();
  fireEvent.click(screen.getByRole("button", { name: t("agents.createToken") }));
  expect(await screen.findByText(secret)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("agents.copy") }));
  await waitFor(() => expect(copy).toHaveBeenCalledWith(secret));
  expect(JSON.stringify(view.client.getQueryCache().getAll().map((entry) => entry.state.data))).not.toContain(secret);
  expect(view.client.getMutationCache().getAll()).toHaveLength(0);
  fireEvent.keyDown(document, { key: "Escape" }); expect(screen.queryByText(secret)).toBeNull();
});

it("clears manual registration secrets when effective access changes", async () => {
  state.token.mockResolvedValue({ token: "synthetic-secret", expires_at: "2030-01-01T00:00:00Z" });
  const view = mount(); await manual();
  fireEvent.click(screen.getByRole("button", { name: t("agents.createToken") })); await screen.findByText("synthetic-secret");
  state.accessRevision = "second"; view.rerender(<QueryClientProvider client={view.client}><AgentsPage/></QueryClientProvider>);
  expect(screen.queryByText("synthetic-secret")).toBeNull();
});

it("keeps the code visible when copying fails", async () => {
  state.token.mockResolvedValue({ token: "synthetic-secret", expires_at: "2030-01-01T00:00:00Z" });
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockRejectedValue(new Error("private")) } });
  mount(); await manual(); fireEvent.click(screen.getByRole("button", { name: t("agents.createToken") })); await screen.findByText("synthetic-secret");
  fireEvent.click(screen.getByRole("button", { name: t("agents.copy") }));
  expect(await screen.findByText(t("agents.copyError"))).toBeTruthy(); expect(screen.getByText("synthetic-secret")).toBeTruthy();
});

async function prepareRegistrationSession() {
  state.owner = true;
  state.deploymentDirectory.mockImplementation(async (body) => body.domain_id ? {
    computers: [{ id: 7, name: "fixture-enrollment-computer" }], ous: [], has_more: false,
  } : { domains: [{ id: 1, name: "fixture-enrollment-domain" }] });
  state.deploymentTemplates.mockResolvedValue({ items: [{ id: agent.id, version: 1, assigned_modules: [], collection_policy: {
    state: "active", interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864,
  } }] });
  state.deploymentTokens.mockResolvedValue({ items: [] }); state.deploymentWaves.mockResolvedValue({ items: [] });
  const view = mount();
  fireEvent.click(screen.getByRole("button", { name: t("agents.addComputer") }));
  await screen.findByRole("option", { name: "fixture-enrollment-domain" });
  fireEvent.change(screen.getByLabelText(t("agents.deployment.domain")), { target: { value: "1" } });
  fireEvent.change(screen.getByLabelText(t("agents.deployment.template")), { target: { value: agent.id } });
  fireEvent.click(screen.getByLabelText(t("agents.deployment.allComputers")));
  fireEvent.click(await screen.findByLabelText("fixture-enrollment-computer"));
  fireEvent.change(screen.getByLabelText(t("agents.deployment.registrationOrigin")), { target: { value: "https://sli.example.test" } });
  fireEvent.change(screen.getByLabelText(t("agents.deployment.registrationPin")), { target: { value: "a".repeat(64) } });
  const create = screen.getByRole("button", { name: t("agents.deployment.create") });
  await waitFor(() => expect((create as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(create);
  return view;
}
it("same-owner access evaluation change clears issued registration material; unchanged evaluation keeps it", async () => {
  const secret = "g".repeat(43);
  state.deploymentIssue.mockResolvedValue({ id: agent.id, group_id: agent.id, token: secret, expires_at: new Date(Date.now() + 3600000).toISOString() });
  const view = await prepareRegistrationSession();
  expect(await screen.findByText(secret)).toBeTruthy();
  view.rerender(<QueryClientProvider client={view.client}><AgentsPage/></QueryClientProvider>);
  expect(screen.getByText(secret)).toBeTruthy();
  state.accessRevision = "second";
  view.rerender(<QueryClientProvider client={view.client}><AgentsPage/></QueryClientProvider>);
  expect(screen.queryByText(secret)).toBeNull();
  expect(screen.queryByRole("button", { name: t("agents.deployment.registrationDownload", { computer: "fixture-enrollment-computer" }) })).toBeNull();
});
it("same-owner access evaluation change discards pending registration issuance", async () => {
  const secret = "g".repeat(43);
  let resolve!: (value: { id: string; group_id: string; token: string; expires_at: string }) => void;
  state.deploymentIssue.mockImplementation(() => new Promise((done) => { resolve = done; }));
  const view = await prepareRegistrationSession();
  await waitFor(() => expect(resolve).toBeDefined());
  state.accessRevision = "second";
  view.rerender(<QueryClientProvider client={view.client}><AgentsPage/></QueryClientProvider>);
  await act(async () => resolve({ id: agent.id, group_id: agent.id, token: secret, expires_at: new Date(Date.now() + 3600000).toISOString() }));
  expect(state.deploymentIssue).toHaveBeenCalledOnce();
  expect(screen.queryByText(secret)).toBeNull();
  expect(screen.queryByRole("button", { name: t("agents.deployment.registrationDownload", { computer: "fixture-enrollment-computer" }) })).toBeNull();
});


// @vitest-environment jsdom
import { chooseOption } from "../../../tests/select-option";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiResponseError, type AgentItem } from "../../api/client";
import { localeRuntime, setLocale, t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";

const state = vi.hoisted(() => ({ list: vi.fn(), action: vi.fn(), token: vi.fn(), auditStatus: vi.fn(), auditCatalog: vi.fn(), accessRevision: "first", owner: false, capabilities: [] as string[], deploymentDirectory: vi.fn(), deploymentTemplates: vi.fn(), deploymentTokens: vi.fn(), deploymentIssue: vi.fn(), deploymentWaves: vi.fn(),
  configurePackage: vi.fn(), consoleSettings: vi.fn(), consoleTokens: vi.fn(), revokeConsoleToken: vi.fn(), setupStatus: vi.fn() }));
vi.mock("../App", () => ({ useEffectiveAccess: () => ({ platform_owner: state.owner, capabilities: state.capabilities, subject: { type: "session", id: 1, username: "fixture-owner" }, evaluated_at_utc: state.accessRevision }), useTimeZone: () => ({ timeZone: "UTC" }) }));
vi.mock("../../api/client", async (original) => ({ ...await original<typeof import("../../api/client")>(), api: {
  agentFileAuditStatus: (agentId: string) => state.auditStatus(agentId),
  agentFileAuditCatalog: (agentId: string) => state.auditCatalog(agentId),
  agentDeploymentDirectory: (body: { domain_id?: number }) => state.deploymentDirectory(body),
  agentTemplates: () => state.deploymentTemplates(), agentGroupTokens: () => state.deploymentTokens(),
  createAgentGroupToken: (body: unknown) => state.deploymentIssue(body), agentUpdateWaves: () => state.deploymentWaves(),
  agents: (id?: string, after?: string) => state.list(id, after), agentAction: (kind: string, body: unknown) => state.action(kind, body), createAgentToken: (body: unknown) => state.token(body),
  setupStatus: () => state.setupStatus(),
  agentInstallPackage: () => state.consoleSettings(),
  configureAgentInstallPackage: (settings: unknown) => state.configurePackage(settings), agentConsoleTokens: () => state.consoleTokens(),
  revokeAgentInstallPackage: (id: string) => state.revokeConsoleToken(id),
  revokeAgentConsoleToken: (id: string) => state.revokeConsoleToken(id),
} }));
import { AgentsPage } from "./agents";

const agent: AgentItem = {
  id: "00000000-0000-4000-8000-000000000001", host_id: "00000000-0000-4000-8000-000000000002",
  host_name: "fixture-host", status: "active", last_seen: null, policy_revision: 2, applied_policy_revision: 1,
  assigned_modules: [{ module_id: "sli.workstations", enabled: true, config: { policy_revision: "2" } }],
  certificates: [{ serial: "a1", not_after: "2030-01-01T00:00:00Z", revoked_at: null }], rights_probe: {},
};
const packageInfo = {
  server_url: "https://agents.example.test:8443/",
  package_url: "/api/v1/admin/agent-install-package/download?revision=fixture",
  sha256: "a".repeat(64),
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
  state.auditStatus.mockRejectedValue(new ApiResponseError(404));
  state.setupStatus.mockResolvedValue({});
  state.deploymentDirectory.mockResolvedValue({ domains: [] }); state.deploymentTemplates.mockResolvedValue({ items: [] });
  state.deploymentTokens.mockResolvedValue({ items: [] }); state.deploymentWaves.mockResolvedValue({ items: [] });
  state.consoleTokens.mockResolvedValue({ items: [] });
  state.consoleSettings.mockResolvedValue(packageInfo);
  state.configurePackage.mockImplementation(async (settings) => ({ ...packageInfo, ...settings }));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });
async function openCard(name = agent.host_name!) {
  fireEvent.click((await screen.findByText(name)).closest("tr")!);
  return screen.getByRole("dialog", { name });
}
function alternativeRegistration() {
  fireEvent.click(screen.getByRole("button", { name: t("agents.registrationSettings") }));
}
async function manual() {
  alternativeRegistration();
  fireEvent.click(await screen.findByRole("tab", { name: t("agents.manualEnrollment") }));
  fireEvent.change(screen.getByLabelText(t("agents.host")), { target: { value: agent.host_id } });
  fireEvent.change(screen.getByLabelText(t("agents.fingerprint")), { target: { value: "a".repeat(64) } });
}

it("applies the reported share to the agent opened in the card", async () => {
  const share = { share_name: "Finance", path: "C:\\Finance", collection_scope_id: "scope:finance" };
  state.list.mockResolvedValue({ items: [{ ...agent, collection_policy: { manage_windows_audit: true } }] });
  state.auditCatalog.mockResolvedValue({ state: "ready", items: [share], saved_selection: null, saved_command: null });
  state.action.mockImplementation(async (_kind, body) => ({ state: "pending", command_id: body.command.command_id, policy_revision: 3 }));

  const user = userEvent.setup();
  mount();
  const card = within(await openCard());
  await user.click(card.getByRole("checkbox", { name: t("agents.fileServer.role") }));
  await user.click(card.getByLabelText(t("agents.fileServer.folder"), { selector: "button" }));
  await user.click(await screen.findByRole("option", { name: `${share.share_name} · ${share.path}` }));
  await user.click(card.getByRole("button", { name: t("agents.saveAudit") }));
  await waitFor(() => expect(state.action).toHaveBeenCalledWith("file-audit", expect.objectContaining({
    agent_id: agent.id, expected_revision: 2, enabled: true, activate_collection: true,
    command: expect.objectContaining({ action: "apply", collection_scope_ids: ["scope:finance"] }),
    config: expect.objectContaining({ source_kind: "server", roots: [expect.objectContaining(share)] }),
  })));
});

it("removes the file-server role and displays the agent's restoration receipt after reopening the card", async () => {
  const root = { share_name: "Finance", path: "C:\\Finance", collection_scope_id: "scope:finance", important: false,
    sacl: { trustee_sids: ["S-1-1-0"], inherit_files: true, inherit_directories: true } };
  state.list.mockResolvedValue({ items: [{ ...agent,
    assigned_modules: [{ module_id: "sli.file-audit", enabled: true, config: { source_kind: "server", roots: [root] } }] }] });
  vi.spyOn(window, "confirm").mockReturnValue(true);
  state.action.mockImplementation(async (_kind, body) => {
    state.list.mockResolvedValue({ items: [{ ...agent, policy_revision: 3 }] });
    state.auditStatus.mockResolvedValue({ command: body.command, state: "verified", reported_at: "2026-11-26T12:05:00Z",
      may_own_audit: false, folders: { "scope:finance": root.path }, scopes: { "scope:finance": { state: "verified", reason_code: "ok" } } });
    return { state: "pending", command_id: body.command.command_id, policy_revision: 3 };
  });
  const user = userEvent.setup();
  mount();
  const card = within(await openCard());
  await user.click(card.getByRole("checkbox", { name: t("agents.fileServer.role") }));
  await waitFor(() => expect(state.action).toHaveBeenCalledWith("file-audit", expect.objectContaining({
    agent_id: agent.id, remove_assignment: true, command: expect.objectContaining({ action: "restore", collection_scope_ids: ["scope:finance"] }),
  })));
  await card.findByText(new RegExp(t("agents.fileServer.restored")));
  await user.click(card.getByRole("button", { name: t("drawer.close") }));
  const reopened = within(await openCard());
  expect((reopened.getByRole("checkbox", { name: t("agents.fileServer.role") }) as HTMLInputElement).checked).toBe(false);
  await reopened.findByText(new RegExp(t("agents.fileServer.restored")));
});

it("denies before loading inventory without owner or access.manage", () => {
  state.owner = false; mount(); expect(state.list).not.toHaveBeenCalled();
  expect(screen.queryByRole("button", { name: t("agents.addComputer") })).toBeNull();
});

it("links a connected workstation with no assigned collection to its plugin", async () => {
  state.list.mockResolvedValue({ items: [{ ...agent, machine_role: "workstation",
    last_seen: new Date().toISOString(), assigned_modules: [] }] });
  mount();
  const row = within((await screen.findByText("fixture-host")).closest("tr")!);
  expect(row.getByRole("cell", { name: "Рабочая станция" })).toBeTruthy();
  expect(row.getByRole("cell", { name: "На связи · сбор не назначен" })).toBeTruthy();
  expect(row.getByRole("link", { name: "Включить сбор" }).getAttribute("href")).toBe("/app/admin/plugins/sli.workstations");
  expect(row.queryByText(t("systemStatus.action.agent"))).toBeNull();
});

it.each([
  ["updating", null, "Обновляется до 26.0.185"],
  ["updated", null, "Обновлён"],
  ["failed", "agent_update_verification_failed", "Не удалось: проверка MSI не пройдена"],
] as const)("shows the running version and %s in the agent row", async (status, reason, label) => {
  const version = status === "updated" ? "26.0.185" : "26.0.136";
  state.list.mockResolvedValue({ items: [{ ...agent, agent_version: version,
    update: { status, version: "26.0.185", reason } }] });
  mount();
  const row = (await screen.findByText("fixture-host")).closest("tr")!;
  expect(within(row).getByRole("cell", { name: `${version} · ${label}` })).toBeTruthy();
});

it.each([
  ["en", "Agent certificate was revoked. Register the agent again."],
  ["ru", "Сертификат агента отозван. Зарегистрируйте агент заново."],
] as const)("shows the certificate rejection in the action cell for the matched agent (%s)", async (locale, message) => {
  setLocale(locale);
  const other = { ...agent, id: "00000000-0000-4000-8000-000000000003", host_id: "00000000-0000-4000-8000-000000000004",
    host_name: "other-fixture" };
  state.list.mockResolvedValue({ items: [{ ...agent, last_seen: new Date().toISOString(), certificate_rejection_reason: "revoked" }, other] });
  mount();
  const row = (await screen.findByText("fixture-host")).closest("tr")!;
  expect(within(row).getByRole("cell", { name: message })).toBeTruthy();
  const otherRow = (await screen.findByText("other-fixture")).closest("tr")!;
  expect(within(otherRow).getByRole("cell", { name: t("systemStatus.action.agent") })).toBeTruthy();
});

it.each([
  [5, "Нет доступа к журналу Security", "Проверьте права службы SLIAgentNet"],
  [1502, "Журнал Security переполнен", "Увеличьте размер журнала Windows"],
])("shows the reported journal failure with its time and action (%s)", async (winerror, reason, action) => {
  const time = new Date(Date.now() - 1000).toISOString();
  state.list.mockResolvedValue({ items: [{ ...agent, last_seen: time, applied_policy_revision: 2,
    eventlog_diagnostics: { reported_at: time, items: [{ channel: "Security", observed_at_utc: time, policy_revision: 2,
      error: { exception_class: "EventLogException", winerror } }] },
  }] });
  mount();
  const observation = `${reason} · ${formatDateTime(time, "UTC", { withYear: false })}`;
  const row = (await screen.findByText(observation)).closest("tr")!;
  expect(within(row).getByText(action)).toBeTruthy();
  expect(within(await openCard()).getByText(`${observation}. ${action}`)).toBeTruthy();
});

it("does not use journal errors reported before the current collection settings", async () => {
  const time = new Date(Date.now() - 1000).toISOString();
  state.list.mockResolvedValue({ items: [{ ...agent, last_seen: time,
    eventlog_diagnostics: { reported_at: time, items: [{ channel: "Security", observed_at_utc: time, policy_revision: 1,
      error: { exception_class: "EventLogException", winerror: 5 } }] },
  }] });
  mount();
  const table = await screen.findByRole("table", { name: t("agents.title") });
  expect(within(table).queryByText(/Нет доступа к журналу Security/)).toBeNull();
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

it("opens the ready download from the registration link without creating a command", async () => {
  window.history.replaceState(null, "", "/app/agents?register=1");
  state.list.mockResolvedValue({ items: [] });
  const download = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  mount();
  const panel = within(await screen.findByRole("dialog", { name: t("agents.addComputer") }));
  const address = panel.getByLabelText(t("agents.console.serverUrl"));
  await waitFor(() => expect(address).toHaveProperty("value", packageInfo.server_url));
  expect(panel.getByText("SHA-256").nextElementSibling?.textContent).toBe(packageInfo.sha256);
  fireEvent.click(panel.getByRole("button", { name: t("agents.console.download") }));
  expect(download).toHaveBeenCalledOnce();
  expect(download.mock.contexts[0]).toHaveProperty("href", new URL(packageInfo.package_url, window.location.origin).href);
  expect(state.configurePackage).not.toHaveBeenCalled();
  expect(panel.queryAllByRole("textbox")).toEqual([address]);
  expect(panel.queryByRole("checkbox")).toBeNull();
  expect(state.deploymentDirectory).not.toHaveBeenCalled();
});

it("shows the reissue fact without an owner action to a reader", async () => {
  state.owner = false; state.capabilities = ["access.manage"];
  state.list.mockResolvedValue({ items: [agent, { ...agent, id: "00000000-0000-4000-8000-000000000003",
    status: "replaced", agent_version: "0.2.2", certificate_reissue_required: true }] });
  mount();
  await screen.findByText(t("agents.certificateReissueRequired", { name: "fixture-host" }));
  const table = screen.getByRole("table", { name: t("agents.oldAgents") });
  expect(within(table).queryByRole("columnheader", { name: t("systemStatus.action") })).toBeNull();
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
  fireEvent.click(screen.getByRole("button", { name: "Отключённые 1" }));
  expect(screen.getByText("disabled.example.test")).toBeTruthy(); expect(screen.queryByText(agent.host_name!)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Все 1" }));
  expect(screen.queryByText("disabled.example.test")).toBeNull();
});

it("filters silent computers and disabled audit requirements from received observations", async () => {
  state.list.mockResolvedValue({ items: [{ ...agent, last_seen: new Date().toISOString() }, { ...agent,
    id: "silent-agent", host_id: "silent-host", host_name: "silent.example.test", last_seen: "2026-01-01T00:00:00Z",
    windows_audit: { policy_revision: 2, reported_at: "2026-11-13T00:00:00Z", management_state: "applied", command_line_enabled: false, families: {
      logons: { state: "missing", required: [{ guid: "fixture-logon", subcategory: "logon", success: true, failure: true, actual_success: false, actual_failure: true }], non_security_channels: [] } } },
  }] });
  mount(); await screen.findByText("silent.example.test");
  fireEvent.click(screen.getByRole("button", { name: "Молчат 1" }));
  expect(screen.queryByText(agent.host_name!)).toBeNull();
  expect(screen.getByText(/^Молчит с/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Аудит выключен 1" }));
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

it.each([["managed_by_gpo", "agents.auditBlockedByPolicy"], ["unknown", "agents.auditApplyFailed"]] as const)(
  "gives an action for a DC audit failure reported as %s", async (auditState, message) => {
    const controller: AgentItem = { ...agent, last_seen: new Date().toISOString(),
      assigned_modules: [{ module_id: "sli.windows.ad-dc", enabled: true, config: {} }],
      collection_policy: { state: "active", interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864, manage_windows_audit: true },
      windows_audit: { policy_revision: 2, reported_at: "2026-11-20T00:00:00Z", management_state: "blocked", command_line_enabled: null,
        families: { domain_controller: { state: auditState, non_security_channels: [], required: [{
          guid: "fixture-logon", subcategory: "logon", state: auditState, success: true, failure: true,
          actual_success: false, actual_failure: false,
        }] } } },
    };
    state.list.mockResolvedValue({ items: [controller] });
    mount();
    const row = (await screen.findByText(controller.host_name!)).closest("tr")!;
    expect(within(row).getByText(t(message))).toBeTruthy();
    expect(within(row).queryByText(t("agents.auditOffStatus", { count: 1 }))).toBeNull();
  });

it("reports the blocking group policy even when the current settings match", async () => {
  const controller: AgentItem = { ...agent, last_seen: new Date().toISOString(),
    assigned_modules: [{ module_id: "sli.windows.ad-dc", enabled: true, config: {} }],
    collection_policy: { state: "active", interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864, manage_windows_audit: true },
    windows_audit: { policy_revision: 2, reported_at: "2026-11-20T00:00:00Z", management_state: "blocked", command_line_enabled: null,
      families: { domain_controller: { state: "managed_by_gpo", non_security_channels: [], required: [{
        guid: "fixture-logon", subcategory: "logon", state: "managed_by_gpo", policy_name: "Fixture Audit",
        success: true, failure: true, actual_success: true, actual_failure: true,
      }] } } },
  };
  state.list.mockResolvedValue({ items: [controller] });
  mount();
  const row = (await screen.findByText(controller.host_name!)).closest("tr")!;
  expect(within(row).getByText(t("agents.auditBlockedByNamedPolicy", { name: "Fixture Audit" }))).toBeTruthy();
  expect(within(row).queryByText(t("agents.auditConfigured"))).toBeNull();
});

it("reads back the saved DC audit setting in the card", async () => {
  const control = { state: "active" as const, interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864 };
  const controller: AgentItem = { ...agent, assigned_modules: [{ module_id: "sli.windows.ad-dc", enabled: true, config: {} }],
    collection_policy: { ...control, manage_windows_audit: false } };
  state.list.mockResolvedValue({ items: [controller] });
  state.action.mockImplementationOnce(async () => {
    state.list.mockResolvedValue({ items: [{ ...controller, policy_revision: 3, collection_policy: { ...control, manage_windows_audit: true } }] });
    return {};
  });
  mount();
  const card = within(await openCard());
  const audit = () => card.getByRole("checkbox", { name: t("agents.manageWindowsAudit") });
  expect(audit()).toHaveProperty("checked", false);
  fireEvent.click(audit());
  fireEvent.click(card.getByRole("button", { name: t("agents.saveAudit") }));
  expect(await card.findByText(/^Сохранено в \d{2}:\d{2}$/)).toBeTruthy();
  await waitFor(() => expect(card.getByRole("button", { name: t("agents.saveAudit") })).toHaveProperty("disabled", true));
  expect(audit()).toHaveProperty("checked", true);
});

it("renders one row per computer using its active registration", async () => {
  state.list.mockResolvedValue({ items: [agent, { ...agent, id: "old-registration", status: "disabled", host_name: "old.example.test" }] });
  mount(); await screen.findByText(agent.host_name!);
  expect(screen.queryByText("old.example.test")).toBeNull();
  expect(screen.getByRole("button", { name: "Все 1" })).toBeTruthy();
});

it("opens a deep-linked computer directly in its card", async () => {
  window.history.replaceState(null, "", `/app/agents?agent_id=${agent.id}#agent-${agent.id}`);
  mount(); expect(await screen.findByRole("dialog", { name: agent.host_name! })).toBeTruthy();
});

it("opens the domain form for the linked domain controller", async () => {
  state.list.mockResolvedValue({ items: [{ ...agent,
    assigned_modules: [{ module_id: "sli.windows.ad-dc", enabled: true, config: {} }],
    password_detection_domain: { status: "unconfigured", domain_id: null, domain_fqdn: null },
  }] });
  window.history.replaceState(null, "", `/app/agents?agent_id=${agent.id}&configure=password-domain`);
  mount();
  const card = within(await screen.findByRole("dialog", { name: agent.host_name! }));
  const domain = card.getByRole("textbox", { name: t("agents.passwordDomain.fqdn") });
  expect(domain.closest("details")).toHaveProperty("open", true);
  await userEvent.setup().type(domain, "example.test");
  await waitFor(() => expect(card.getByRole("button", { name: t("agents.passwordDomain.save") })).toHaveProperty("disabled", false));
});

it("offers registration in the add panel and hides file audit", async () => {
  mount(); await screen.findByText(agent.host_name!);
  expect(state.deploymentDirectory).not.toHaveBeenCalled();
  expect(screen.queryByText(t("agents.fileAudit.title"))).toBeNull();
  alternativeRegistration();
  const drawer = screen.getByRole("dialog", { name: t("agents.addComputer") });
  expect(within(drawer).getByRole("tab", { name: t("agents.deployment.title") }).getAttribute("aria-selected")).toBe("true");
  expect(within(drawer).getByRole("button", { name: t("agents.deployment.create") })).toBeTruthy();
  fireEvent.click(within(drawer).getByRole("tab", { name: t("agents.manualEnrollment") }));
  expect(within(drawer).getByRole("button", { name: t("agents.createToken") })).toBeTruthy();
});

it("names the next step and opens the add panel from an empty list", async () => {
  state.list.mockResolvedValue({ items: [] }); mount();
  const empty = await screen.findByText(t("agents.emptyComputers"));
  fireEvent.click(within(empty.parentElement!).getByRole("button", { name: t("agents.addComputer") }));
  expect(screen.getByRole("dialog", { name: t("agents.addComputer") })).toBeTruthy();
  expect(state.configurePackage).not.toHaveBeenCalled();
});

async function openPackageDialog() {
  mount();
  await screen.findByText(agent.host_name!);
  fireEvent.click(screen.getByRole("button", { name: t("agents.addComputer") }));
  return within(screen.getByRole("dialog", { name: t("agents.addComputer") }));
}

it("saves the address and optional limits before downloading a rebuilt package", async () => {
  const settings = { server_url: "https://branch.example.test/", host_limit: 300, expires_at: "2037-01-21T23:59:59.999Z" };
  const rebuilt = { ...packageInfo, ...settings, sha256: "b".repeat(64), package_url: packageInfo.package_url + "-updated" };
  state.configurePackage.mockResolvedValueOnce(rebuilt);
  const download = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  const panel = await openPackageDialog();
  const address = panel.getByLabelText(t("agents.console.serverUrl"));
  await waitFor(() => expect(address).toHaveProperty("value", packageInfo.server_url));
  fireEvent.change(address, { target: { value: settings.server_url } });
  fireEvent.click(panel.getByRole("button", { name: t("agents.console.restrict") }));
  fireEvent.change(panel.getByLabelText(t("agents.console.hostLimit")), { target: { value: "300" } });
  fireEvent.change(panel.getByLabelText(t("agents.console.expiry")), { target: { value: "2037-01-21" } });
  fireEvent.click(panel.getByRole("button", { name: t("agents.console.download") }));
  await waitFor(() => expect(download).toHaveBeenCalledOnce());
  expect(download.mock.contexts[0]).toHaveProperty("href", new URL(rebuilt.package_url, window.location.origin).href);
  expect(state.configurePackage).toHaveBeenCalledExactlyOnceWith(settings);
  expect(panel.getByText("SHA-256").nextElementSibling?.textContent).toBe(rebuilt.sha256);
});

it("shows the certificate names beside a rejected address", async () => {
  state.configurePackage.mockRejectedValueOnce(new ApiResponseError(400, "invalid_agent_console_server_url", undefined,
    { allowed_hosts: ["agents.example.test", "192.0.2.40"] }));
  const panel = await openPackageDialog();
  const address = panel.getByLabelText(t("agents.console.serverUrl"));
  await waitFor(() => expect(address).toHaveProperty("value", packageInfo.server_url));
  fireEvent.change(address, { target: { value: "https://other.example.test" } });
  fireEvent.click(panel.getByRole("button", { name: t("agents.console.download") }));
  expect(await panel.findByRole("alert")).toHaveProperty("textContent",
    t("agents.console.serverUrlInvalid", { hosts: "agents.example.test, 192.0.2.40" }));
  expect(address.getAttribute("aria-invalid")).toBe("true");
  expect(state.configurePackage).toHaveBeenCalledExactlyOnceWith({ server_url: "https://other.example.test" });
});

it("can retry loading the saved address", async () => {
  state.consoleSettings.mockRejectedValueOnce(new Error("fixture settings failure"));
  const panel = await openPackageDialog();
  fireEvent.click(await panel.findByRole("button", { name: t("state.retry") }));
  const address = panel.getByLabelText(t("agents.console.serverUrl"));
  await waitFor(() => expect(address).toHaveProperty("value", packageInfo.server_url));
  expect(panel.queryByRole("alert")).toBeNull();
  expect(state.consoleSettings).toHaveBeenCalledTimes(2);
});

it("reports when the server has no ready package", async () => {
  state.consoleSettings.mockResolvedValueOnce({ server_url: null, package_url: null });
  const panel = await openPackageDialog();
  expect(await panel.findByRole("alert")).toHaveProperty("textContent", t("agents.console.packageError"));
  expect(panel.getByRole("button", { name: t("agents.console.download") })).toHaveProperty("disabled", true);
});

it("shows the package key, computer count and revocation action", async () => {
  state.consoleTokens.mockResolvedValueOnce({ items: [{ id: agent.id, created_at: "2026-11-26T12:05:00Z", expires_at: null,
    remaining: null, connected: 3, packaged: true }] });
  state.revokeConsoleToken.mockResolvedValue({});
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  mount(); await screen.findByText(agent.host_name!);
  fireEvent.click(screen.getByRole("button", { name: t("agents.console.keys") }));
  const panel = within(screen.getByRole("dialog", { name: t("agents.console.keys") }));
  await panel.findByText(t("agents.console.packagedKey", { time: "12:05", count: 3 }));
  fireEvent.click(panel.getByRole("button", { name: t("agents.console.revoke") }));
  expect(confirm).toHaveBeenCalledOnce();
  await waitFor(() => expect(state.revokeConsoleToken).toHaveBeenCalledExactlyOnceWith(agent.id));
  expect(state.consoleTokens).toHaveBeenCalledTimes(2);
});

it("shows a rejected enrollment as a non-interactive row with its time and reason", async () => {
  const time = "2026-11-26T12:05:00Z";
  state.list.mockResolvedValue({ items: [agent], rejected_enrollments: [
    { id: "41", reported_hostname: "new-computer", occurred_at: time, reason: "enrollment_token_revoked" },
  ] });
  mount();
  const row = (await screen.findByText("new-computer")).closest("tr")!;
  expect(within(row).getByText(t("agents.notConnected"))).toBeTruthy();
  expect(within(row).getByText(t("agents.enrollmentReason.keyRevoked"))).toBeTruthy();
  expect(within(row).getByText(formatDateTime(time, "UTC", { withYear: false }))).toBeTruthy();
  expect(row.getAttribute("tabindex")).toBeNull();
});

it("changes the computer role on the agent card", async () => {
  mount();
  const card = within(await openCard());
  await chooseOption(card.getByLabelText(t("agents.computerRole"), { selector: "button" }), "file_server");
  await waitFor(() => expect(state.action).toHaveBeenCalledExactlyOnceWith("role", {
    agent_id: agent.id, machine_role: "file_server",
  }));
});

it("loads earlier agent registrations using the inventory cursor", async () => {
  const earlier = { ...agent, id: "00000000-0000-4000-8000-000000000003", host_id: "00000000-0000-4000-8000-000000000004", host_name: "earlier-computer" };
  state.list.mockImplementation(async (_id, after) => after ? { items: [earlier] } : { items: [agent], next_cursor: agent.id });
  mount();
  fireEvent.click(await screen.findByRole("button", { name: t("table.loadMore") }));
  expect(await screen.findByText(earlier.host_name)).toBeTruthy();
  expect(screen.getByText(agent.host_name!)).toBeTruthy();
  expect(state.list).toHaveBeenLastCalledWith(undefined, agent.id);
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

it("shows the allowed workstation event IDs and keeps the saved module setting visible after refusal", async () => {
  state.list.mockResolvedValue({ items: [{
    ...agent, assigned_modules: [{ module_id: "sli.workstations", enabled: false,
      config: { policy_revision: "2", allow_event_ids: [4624, 4688], families: { processes: true } } }]
  }] });
  state.action.mockRejectedValueOnce(new ApiResponseError(400, "workstation_journal_profile_unsupported", undefined,
    { allowed_event_ids: [1102, 4624, 4625, 4698, 4732, 4733, 5001, 5010, 5012, 7036, 7040, 7045] }));
  mount(); const drawer = await openCard();
  const checkbox = within(drawer).getByRole("checkbox", { name: t("agents.moduleWorkstations") });
  fireEvent.click(checkbox);
  const alert = await within(drawer).findByRole("alert");
  expect(alert.textContent).toContain(t("agents.invalidPolicy"));
  expect(alert.textContent).toContain(t("agents.allowIds") + ": 1102, 4624, 4625");
  expect(checkbox).toHaveProperty("checked", false);
  expect(state.action).toHaveBeenCalledWith("modules", { agent_id: agent.id,
    module_id: "sli.workstations", enabled: true, config: {}, expected_revision: agent.policy_revision });
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
  alternativeRegistration();
  await chooseOption(screen.getByLabelText(t("agents.deployment.domain"), { selector: "button" }), "1");
  await chooseOption(screen.getByLabelText(t("agents.deployment.template"), { selector: "button" }), agent.id);
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


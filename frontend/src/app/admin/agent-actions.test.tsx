// @vitest-environment jsdom
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { AgentItem } from "../../api/client";
import { localeRuntime, setLocale, t, type Locale } from "../../i18n";
import { en } from "../../i18n/en";
import { ru } from "../../i18n/ru";
import { AgentActions, agentHostName, agentModuleName } from "./agent-actions";

const agent: AgentItem = {
  id: "00000000-0000-4000-8000-000000000001", host_id: "00000000-0000-4000-8000-000000000002",
  host_name: "fixture-host", instance_name: "fixture-collector", status: "active", last_seen: null,
  policy_revision: 2, applied_policy_revision: 1, assigned_modules: [], rights_probe: {},
  certificates: [
    { serial: "a1", not_after: "2030-01-01T00:00:00Z", revoked_at: null },
    { serial: "b2", not_after: "2030-01-01T00:00:00Z", revoked_at: "2029-01-01T00:00:00Z" },
  ],
};
const change = vi.fn();
beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  // React Aria uses CSS.escape for collection keys; jsdom 25 lacks this API.
  vi.stubGlobal("CSS", { ...globalThis.CSS, escape: (value: string) =>
    Array.from(String(value), (character) => `\\${(character.codePointAt(0) || 0xfffd).toString(16)} `).join("") });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.clearAllMocks(); vi.unstubAllGlobals(); });
async function openMenu(user: Pick<typeof userEvent, "click"> = userEvent) {
  await user.click(screen.getByRole("button", { name: t("agents.actionsFor", { host: "fixture-host" }) }));
  return screen.findByRole("menu");
}

it("requires explicit owner scope and confirmation for uninstall with certificate revocation", async () => {
  render(<AgentActions agent={agent} busy={false} canRemove change={change}/>);
  const menu = await openMenu();
  await userEvent.click(within(menu).getByRole("menuitem", { name: t("agents.remove") }));
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText(t("agents.confirmRemove"))).toBeTruthy();
  expect(change).not.toHaveBeenCalled();
  await userEvent.click(within(dialog).getByRole("button", { name: t("agents.remove") }));
  expect(change).toHaveBeenCalledWith("remove", { agent_ids: [agent.id], operation_id: expect.any(String) });
});

it("omits uninstall without owner scope", async () => {
  render(<AgentActions agent={agent} busy={false} change={change}/>);
  expect(within(await openMenu()).queryByRole("menuitem", { name: t("agents.remove") })).toBeNull();
});

it.each(["ru", "en"] as const)("groups destructive actions separately in %s and omits revoked certificates", async (locale) => {
  setLocale(locale);
  render(<AgentActions agent={agent} busy={false} change={change}/>);
  expect(screen.queryByRole("menuitem")).toBeNull();
  const menu = await openMenu();
  const group = within(menu).getByRole("group", { name: t("agents.destructiveActions") });
  expect(within(group).getAllByRole("menuitem")).toHaveLength(2);
  expect(within(group).getByRole("menuitem", { name: t("agents.disable") }).className).toContain("agent-actions-danger");
  expect(within(group).getByRole("menuitem", { name: t("agents.revokeSerial", { serial: "a1" }) }).className).toContain("agent-actions-danger");
  expect(within(group).queryByRole("menuitem", { name: t("agents.pause") })).toBeNull();
  expect(within(menu).getByRole("separator")).toBeTruthy();
  expect(within(menu).queryByText(/b2/)).toBeNull();
  expect(change).not.toHaveBeenCalled();
});

it.each(["ru", "en"] as const)("identifies host, agent and certificate and describes revocation in %s", async (locale) => {
  setLocale(locale);
  const { container } = render(<AgentActions agent={agent} busy={false} change={change}/>);
  const menu = await openMenu();
  await userEvent.click(within(menu).getByRole("menuitem", { name: t("agents.revokeSerial", { serial: "a1" }) }));
  const dialog = await screen.findByRole("dialog", { name: t("agents.confirmTitle", { action: t("agents.revoke"), host: "fixture-host" }) });
  // React Aria hides the background instead of using aria-modal (a Safari workaround).
  await waitFor(() => expect(container.getAttribute("aria-hidden")).toBe("true"));
  expect(screen.queryByRole("button", { name: t("agents.actionsFor", { host: "fixture-host" }) })).toBeNull();
  expect(within(dialog).getByText(t("agents.confirmTarget", { agent: `fixture-collector (${agent.id})`, host: agent.host_id }))).toBeTruthy();
  expect(within(dialog).getByText(t("agents.certificateSerial", { serial: "a1" }))).toBeTruthy();
  expect(document.getElementById(dialog.getAttribute("aria-describedby")!)?.textContent).toBe(t("agents.confirmRevoke"));
  expect(change).not.toHaveBeenCalled();
  await userEvent.click(within(dialog).getByRole("button", { name: t("agents.revoke") }));
  expect(change).toHaveBeenCalledTimes(1);
  expect(change).toHaveBeenCalledWith("revoke", { agent_id: agent.id, serial: "a1" });
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await waitFor(() => expect(container.getAttribute("aria-hidden")).toBeNull());
  expect(screen.getByRole("button", { name: t("agents.actionsFor", { host: "fixture-host" }) })).toBeTruthy();
});

it.each(["cancel", "escape"])("cancels with %s, traps focus and restores the actions trigger", async (method) => {
  render(<AgentActions agent={agent} busy={false} change={change}/>);
  const menu = await openMenu();
  await userEvent.click(within(menu).getByRole("menuitem", { name: t("agents.disable") }));
  const dialog = await screen.findByRole("dialog");
  const cancel = within(dialog).getByRole("button", { name: t("agents.cancel") });
  await waitFor(() => expect(document.activeElement).toBe(cancel));
  await userEvent.tab();
  expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: t("agents.disable") }));
  await userEvent.tab();
  expect(document.activeElement).toBe(cancel);
  if (method === "escape") await userEvent.keyboard("{Escape}");
  else await userEvent.click(cancel);
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: t("agents.actionsFor", { host: "fixture-host" }) })));
  expect(change).not.toHaveBeenCalled();
});

it("opens and navigates the menu with the keyboard", async () => {
  render(<AgentActions agent={agent} busy={false} change={change}/>);
  screen.getByRole("button").focus();
  await userEvent.keyboard("{ArrowDown}");
  const menu = await screen.findByRole("menu");
  await waitFor(() => expect(document.activeElement).toBe(within(menu).getByRole("menuitem", { name: t("agents.pause") })));
  await userEvent.keyboard("{ArrowDown}{Enter}");
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText(t("agents.confirmDrain"))).toBeTruthy();
  expect(change).not.toHaveBeenCalled();
});

it("assigns a DC module with the revision and blocks a conflicting workstation assignment", async () => {
  const { rerender } = render(<AgentActions agent={agent} busy={false} change={change}/>);
  let menu = await openMenu();
  await userEvent.click(within(menu).getByRole("menuitem", { name: t("agents.assignDc") }));
  expect(change).toHaveBeenCalledWith("modules", { agent_id: agent.id, module_id: "sli.windows.ad-dc", enabled: true,
    config: { source_name: agent.host_id, connect_address: "localhost" }, expected_revision: 2 });
  rerender(<AgentActions agent={{ ...agent, assigned_modules: [{ module_id: "sli.windows.ad-dc", enabled: true, config: {} }] }} busy={false} change={change}/>);
  menu = await openMenu();
  const workstation = within(menu).getByRole("menuitem", { name: t("agents.assignWorkstations") });
  expect(workstation.getAttribute("aria-disabled")).toBe("true");
  await userEvent.click(workstation);
  expect(change).toHaveBeenCalledTimes(1);
});

it("blocks a pending action and a disabled agent without losing certificate revocation", async () => {
  const { rerender } = render(<AgentActions agent={{ ...agent, status: "disabled" }} busy={false} change={change}/>);
  const menu = await openMenu();
  for (const key of ["agents.pause", "agents.checkAccess", "agents.disable"] as const) {
    const item = within(menu).getByRole("menuitem", { name: t(key) });
    expect(item.getAttribute("aria-disabled")).toBe("true");
    await userEvent.click(item);
  }
  expect(change).not.toHaveBeenCalled();
  await userEvent.click(within(menu).getByRole("menuitem", { name: t("agents.revokeSerial", { serial: "a1" }) }));
  const dialog = await screen.findByRole("dialog");
  rerender(<AgentActions agent={agent} busy change={change}/>);
  const confirm = within(dialog).getByRole("button", { name: t("agents.revoke") });
  expect((confirm as HTMLButtonElement).disabled).toBe(true);
  await userEvent.click(confirm);
  expect(change).not.toHaveBeenCalled();
});

it.each(["ru", "en"] as const)("keeps module names, enrollment help and consequence texts in %s", (locale: Locale) => {
  setLocale(locale);
  const dictionary = locale === "ru" ? ru : en;
  expect(agentModuleName("sli.workstations")).toBe(dictionary["agents.moduleWorkstations"]);
  expect(agentModuleName("sli.windows.ad-dc")).toBe(dictionary["agents.moduleDc"]);
  expect(agentModuleName("fixture.module")).toBe("fixture.module");
  expect(dictionary["agents.enrollmentTitle"]).not.toBe(dictionary["agents.createToken"]);
  expect(dictionary["agents.fingerprintHelp"]).toMatch(/64/);
  expect(dictionary["agents.confirmDisable"]).toMatch(locale === "ru" ? /данные и история сохранятся/ : /data and history will be kept/);
  expect(dictionary["agents.confirmDisable"]).toMatch(locale === "ru" ? /Отменить отключение.*нельзя/ : /cannot be undone/);
  expect(dictionary["agents.confirmRevoke"]).toMatch(locale === "ru" ? /Отзыв необратим/ : /Revocation is irreversible/);
  expect(dictionary["agents.confirmPause"]).toMatch(locale === "ru" ? /Сбор можно возобновить/ : /Collection can be resumed/);
});

it("prefers provided host names and keeps unknown names honest", () => {
  expect(agentHostName(agent)).toBe("fixture-host");
  expect(agentHostName({ ...agent, host_name: null, hostname: "fixture-hostname" })).toBe("fixture-hostname");
  expect(agentHostName({ ...agent, host_name: " " })).toBe(t("agents.unknownHost"));
  expect(agentHostName({ ...agent, host_name: agent.host_id })).toBe(t("agents.unknownHost"));
});

it.each(["ru", "en"] as const)("requires confirmation to enable audit management in %s with command lines off by default", async (locale) => {
  setLocale(locale);
  render(<AgentActions agent={agent} busy={false} change={change}/>);
  const menu = await openMenu();
  await userEvent.click(within(menu).getByRole("menuitem", { name: t("agents.auditEnable") }));
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText(t("agents.auditConfirmEnable"))).toBeTruthy();
  expect((within(dialog).getByRole("checkbox", { name: t("agents.auditCommandLineConsent") }) as HTMLInputElement).checked).toBe(false);
  expect(change).not.toHaveBeenCalled();
  await userEvent.click(within(dialog).getByRole("button", { name: t("agents.auditEnable") }));
  expect(change).toHaveBeenCalledWith("policy", { agent_id: agent.id, expected_revision: 2,
    collection_policy: { manage_windows_audit: true, audit_process_command_line: false } });
});

it("sends command line consent only after selection and cancels without a mutation", async () => {
  const user = userEvent.setup();
  render(<AgentActions agent={agent} busy={false} change={change}/>);
  const trigger = screen.getByRole("button", { name: t("agents.actionsFor", { host: "fixture-host" }) });
  let menu = await openMenu(user);
  await user.click(within(menu).getByRole("menuitem", { name: t("agents.auditEnable") }));
  let dialog = await screen.findByRole("dialog");
  const selected = within(dialog).getByRole<HTMLInputElement>("checkbox", { name: t("agents.auditCommandLineConsent") });
  await user.click(selected);
  expect(selected.checked).toBe(true);
  await user.click(within(dialog).getByRole("button", { name: t("agents.cancel") }));
  await waitFor(() => {
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
  expect(change).not.toHaveBeenCalled();
  menu = await openMenu(user);
  await user.click(within(menu).getByRole("menuitem", { name: t("agents.auditEnable") }));
  dialog = await screen.findByRole("dialog");
  const consent = within(dialog).getByRole<HTMLInputElement>("checkbox", { name: t("agents.auditCommandLineConsent") });
  expect(consent.checked).toBe(false);
  await user.click(consent);
  expect(change).not.toHaveBeenCalled();
  await user.click(within(dialog).getByRole("button", { name: t("agents.auditEnable") }));
  expect(change).toHaveBeenCalledTimes(1);
  expect(change).toHaveBeenCalledWith("policy", { agent_id: agent.id, expected_revision: 2,
    collection_policy: { manage_windows_audit: true, audit_process_command_line: true } });
});

it("confirms restoration when audit management is turned off and blocks a pending confirmation", async () => {
  const managed = { ...agent, collection_policy: { state: "active" as const, interval_seconds: 60, batch_size: 32,
    rate_limit_per_minute: 120, spool_max_bytes: 67108864, manage_windows_audit: true, audit_process_command_line: true } };
  const { rerender } = render(<AgentActions agent={managed} busy={false} change={change}/>);
  const menu = await openMenu();
  await userEvent.click(within(menu).getByRole("menuitem", { name: t("agents.auditDisable") }));
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText(t("agents.auditConfirmDisable"))).toBeTruthy();
  expect(within(dialog).queryByRole("checkbox")).toBeNull();
  rerender(<AgentActions agent={managed} busy change={change}/>);
  await userEvent.click(within(dialog).getByRole("button", { name: t("agents.auditDisable") }));
  expect(change).not.toHaveBeenCalled();
  rerender(<AgentActions agent={managed} busy={false} change={change}/>);
  await userEvent.click(within(dialog).getByRole("button", { name: t("agents.auditDisable") }));
  expect(change).toHaveBeenCalledWith("policy", { agent_id: agent.id, expected_revision: 2,
    collection_policy: { manage_windows_audit: false, audit_process_command_line: false } });
});

// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { AgentItem, AgentWindowsAudit } from "../../api/client";
import { localeRuntime, setLocale, t } from "../../i18n";
import { AgentWindowsAuditStatus } from "./agent-windows-audit";

const agent: AgentItem = {
  id: "00000000-0000-4000-8000-000000000001", host_id: "00000000-0000-4000-8000-000000000002",
  host_name: "LAB-DC01", status: "active", last_seen: null, policy_revision: 3, applied_policy_revision: 3,
  certificates: [], rights_probe: {}, assigned_modules: [{ module_id: "sli.windows.ad-dc", enabled: true, config: {} }],
};
const observation: AgentWindowsAudit = {
  policy_revision: 3, reported_at: "2026-11-15T01:19:00Z", management_state: "disabled", command_line_enabled: null,
  families: { domain_controller: { state: "missing", non_security_channels: [], required: [{
    subcategory: "kerberos_authentication_service", guid: "0cce9242-69ae-11d9-bed3-505054503030", success: true, failure: true,
    actual_success: false, actual_failure: false, state: "missing", detections: [1, 2, 5], domain_changes: false, enabled_at: null, policy_name: null,
  }] } },
};
beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });
it.each(["ru", "en"] as const)("names rare-event audit requirements and their journal screen in %s", (locale) => {
  setLocale(locale);
  const names = ["directory_service_access", "other_account_management", "authentication_policy_change", "authorization_policy_change"];
  const required = names.map((subcategory) => ({ ...observation.families.domain_controller!.required[0]!, subcategory,
    guid: subcategory, detections: [], domain_changes: false }));
  render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: { ...observation, families: {
    domain_controller: { state: "missing", required, non_security_channels: [] },
  } } }}/>);
  const labels = locale === "ru" ? ["Доступ к службе каталогов", "Другие события управления учетными записями",
    "Изменение политики проверки подлинности", "Изменение политики авторизации"]
    : ["Directory Service Access", "Other Account Management Events", "Authentication Policy Change", "Authorization Policy Change"];
  for (const label of labels) {
    const row = screen.getByText(label).closest("tr")!;
    expect(within(row).getByText(t("shell.nav.events"))).toBeTruthy();
  }
});
it.each(["ru", "en"] as const)("shows DC requirements and dependencies without GUID or old GPO instructions in %s", (locale) => {
  setLocale(locale); const change = vi.fn();
  const { container } = render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: observation }} change={change}/>);
  const table = screen.getByRole("table");
  expect(within(table).getByRole("columnheader", { name: locale === "ru" ? "Зачем" : "Why" })).toBeTruthy();
  expect(table.textContent).toContain(`1. ${t("security.problems.presentation.qw.password-brute-force.title")}`);
  expect(table.textContent).toContain(`2. ${t("security.problems.presentation.qw.password-spray.title")}`);
  expect(table.textContent).toContain(`5. ${t("security.problems.presentation.asrep_title")}`);
  expect(container.innerHTML).not.toMatch(/0cce9242|69ae-11d9|Примените GPO|gpupdate/);
  fireEvent.click(screen.getByRole("button", { name: locale === "ru" ? "Включить" : "Enable" }));
  expect(change).toHaveBeenCalledWith("policy", { agent_id: agent.id, expected_revision: 3, collection_policy: { manage_windows_audit: true } });
});
it.each(["ru", "en"] as const)("shows confirmed time per setting in %s", (locale) => {
  setLocale(locale);
  const row = { ...observation.families.domain_controller!.required[0]!, state: "ok" as const, actual_success: true, actual_failure: true, enabled_at: "2026-11-15T01:18:00Z" };
  render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: { ...observation, management_state: "applied", families: {
    domain_controller: { state: "ok", required: [row], non_security_channels: [] },
  } } }} timeZone="UTC"/>);
  expect(screen.getByRole("table").textContent).toMatch(locale === "ru" ? /Включено в 01:18/ : /Enabled at 01:18/);
});
it("names the policy and copies a command without exposing GUIDs", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  const row = { ...observation.families.domain_controller!.required[0]!, state: "managed_by_gpo" as const, policy_name: "LAB Audit" };
  const { container } = render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: { ...observation, management_state: "blocked", families: {
    domain_controller: { state: "managed_by_gpo", required: [row], non_security_channels: [] },
  } } }}/>);
  expect(screen.getByText("Задаёт политика LAB Audit")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("agents.copy") }));
  expect(writeText).toHaveBeenCalledWith(expect.stringContaining("/success:enable /failure:enable"));
  expect(container.innerHTML).not.toMatch(/0cce9242|69ae-11d9|Примените GPO|gpupdate/);
});
it("asks for confirmation with the computer name before restore", () => {
  const change = vi.fn();
  render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: observation }} change={change}/>);
  fireEvent.click(screen.getByRole("button", { name: "Вернуть как было" }));
  expect(change).not.toHaveBeenCalled();
  expect(screen.getByRole("dialog").textContent).toContain("LAB-DC01");
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Вернуть как было" }));
  expect(change).toHaveBeenCalledWith("policy", { agent_id: agent.id, expected_revision: 3, collection_policy: { manage_windows_audit: false, audit_process_command_line: false } });
});
it("names the audit command when clipboard access is unavailable", async () => {
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
  const row = { ...observation.families.domain_controller!.required[0]!, state: "managed_by_gpo" as const };
  render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: { ...observation, management_state: "blocked", families: {
    domain_controller: { state: "managed_by_gpo", required: [row], non_security_channels: [] },
  } } }}/>);
  fireEvent.click(screen.getByRole("button", { name: t("agents.copy") }));
  expect((await screen.findByRole("alert")).textContent).toBe("Не удалось скопировать команду аудита");
});
it("does not show stale observations as confirmed results", () => {
  render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: { ...observation, policy_revision: 2 } }}/>);
  expect(screen.queryByText(/Включено в|Настроен/)).toBeNull();
});
it.each(["ru", "en"] as const)("requires separate AD consent before enabling domain-root audit in %s", (locale) => {
  setLocale(locale);
  const change = vi.fn();
  const row = { ...observation.families.domain_controller!.required[0]!, subcategory: "domain_root_sacl", guid: "domain_root_sacl", state: "missing" as const, detections: [], domain_changes: true };
  render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: { ...observation, families: {
    domain_controller: { state: "missing", required: [row], non_security_channels: [] },
  } } }} change={change}/>);
  expect(screen.getByRole("table").textContent).toContain(locale === "ru" ? "Запись аудита на корне домена" : "Domain root audit entry");
  fireEvent.click(screen.getByRole("button", { name: locale === "ru" ? "Включить" : "Enable" }));
  expect(change).not.toHaveBeenCalled();
  const dialog = screen.getByRole("dialog");
  expect(dialog.textContent).toContain("LAB-DC01");
  expect(dialog.textContent).toContain(locale === "ru" ? "изменение в Active Directory" : "change in Active Directory");
  fireEvent.click(within(dialog).getByRole("button", { name: locale === "ru" ? "Включить" : "Enable" }));
  expect(change).toHaveBeenCalledWith("policy", { agent_id: agent.id, expected_revision: 3,
    collection_policy: { manage_windows_audit: true, manage_domain_root_sacl: true } });
});
it.each(["ok", "missing", "restored"] as const)("shows the domain-root result %s", (state) => {
  const row = { ...observation.families.domain_controller!.required[0]!, subcategory: "domain_root_sacl", guid: "domain_root_sacl", state,
    actual_success: state === "ok", failure: false, actual_failure: false, detections: [], domain_changes: true,
    enabled_at: state === "ok" ? "2026-11-15T01:18:00Z" : null };
  render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: { ...observation, families: {
    domain_controller: { state: state === "ok" ? "ok" : "missing", required: [row], non_security_channels: [] },
  } } }} timeZone="UTC"/>);
  const table = screen.getByRole("table");
  expect(table.textContent).toContain({ ok: "Настроен", missing: "Не настроен", restored: "Отменён" }[state]);
  if (state === "ok") expect(table.textContent).toContain("Включено в 01:18");
  expect(within(table).queryByText(/auditpol/)).toBeNull();
});
it("can cancel AD consent or enable subcategories without granting AD writes", () => {
  const change = vi.fn();
  const row = { ...observation.families.domain_controller!.required[0]!, subcategory: "domain_root_sacl", guid: "domain_root_sacl" };
  render(<AgentWindowsAuditStatus agent={{ ...agent, windows_audit: { ...observation, families: {
    domain_controller: { state: "missing", required: [row], non_security_channels: [] },
  } } }} change={change}/>);
  fireEvent.click(screen.getByRole("button", { name: "Включить" }));
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Отмена" }));
  expect(change).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Включить" }));
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Только подкатегории" }));
  expect(change).toHaveBeenCalledWith("policy", { agent_id: agent.id, expected_revision: 3, collection_policy: { manage_windows_audit: true } });
});
it("keeps AD restore confirmation when the latest report has not arrived", () => {
  const change = vi.fn();
  render(<AgentWindowsAuditStatus agent={{ ...agent, collection_policy: { state: "active", interval_seconds: 60, batch_size: 32,
    rate_limit_per_minute: 120, spool_max_bytes: 67108864, manage_windows_audit: true, manage_domain_root_sacl: true } }} change={change}/>);
  fireEvent.click(screen.getByRole("button", { name: "Вернуть как было" }));
  const dialog = screen.getByRole("dialog");
  expect(dialog.textContent).toContain("изменение в Active Directory");
  expect(change).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole("button", { name: "Вернуть как было" }));
  expect(change).toHaveBeenCalledWith("policy", { agent_id: agent.id, expected_revision: 3,
    collection_policy: { manage_windows_audit: false, manage_domain_root_sacl: false, audit_process_command_line: false } });
});

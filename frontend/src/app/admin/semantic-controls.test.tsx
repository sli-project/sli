// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { SemanticControls } from "../../api/client";

vi.mock("../../design-system/useDateFormatters", () => ({
  useDateFormatters: () => ({ formatDateTime: (value: string) => `formatted:${value}` }),
}));

const state = vi.hoisted(() => ({ list: vi.fn(), update: vi.fn() }));
vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, semanticControls: () => state.list(), updateSemanticControl: (body: unknown) => state.update(body) } };
});
import { localeRuntime, setLocale, t } from "../../i18n";
import { SemanticControlsPanel } from "./semantic-controls";

const data = { policies: [{ policy_id: "test-policy", policy_version: 2, title: "Synthetic audit rule", version_created_at: "2026-10-01T12:00:00+00:00", lifecycle_status: "shadow", enabled: false, managed: false }],
  suppressions: [{ id: 1, semantic_type: "semantic.audit.policy.changed", domain_id: 1, scope_kind: "bucket", scope_value: "machine_account", reason: "Test maintenance", expires_at: "2026-10-07T00:00:00Z", created_by: "test-owner", state: "active" }], audit: [], limit: 200 };
function mount(audit: SemanticControls["audit"] = []) {
  state.list.mockResolvedValue({ ...data, audit });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><SemanticControlsPanel/></QueryClientProvider>);
}
beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.clearAllMocks(); });

it.each(["ru", "en"] as const)("omits change audit from platform settings even when the server returns records in %s", async (locale) => {
  setLocale(locale);
  mount([
    { action: "suppression_create", target: "fixture-audit-target", actor: "fixture-audit-actor", occurred_at: "2026-10-01T10:00:00Z" },
    { action: "policy_admission", target: "fixture-admission-target", actor: "fixture-admission-actor", occurred_at: "2026-10-01T11:00:00Z" },
    { action: "legacy_action", target: "fixture-legacy-target", actor: "fixture-legacy-actor", occurred_at: "2026-10-01T12:00:00Z" },
  ]);
  await screen.findByRole("checkbox", { name: /Synthetic audit rule/ });
  expect(screen.getByRole("button", { name: t("semanticControls.create") })).toBeTruthy();
  expect(screen.getByRole("button", { name: t("semanticControls.revoke") })).toBeTruthy();
  expect(screen.queryByRole("heading", { name: /Аудит изменений|Change audit/ })).toBeNull();
  expect(screen.queryByText(/fixture-(?:audit|admission|legacy)-(?:target|actor)/)).toBeNull();
  expect(screen.queryByText(/записей аудита|audit records/)).toBeNull();
});

it("admits an explicit version and revokes an explicit suppression", async () => {
  state.update.mockResolvedValue({ status: "ok" });
  mount();
  await screen.findByRole("checkbox", { name: /Synthetic audit rule/ });
  fireEvent.change(screen.getByLabelText("Причина допуска политики или отзыва правила"), { target: { value: " Test decision " } });
  fireEvent.click(screen.getByRole("checkbox", { name: /Synthetic audit rule/ }));
  await waitFor(() => expect(state.update).toHaveBeenCalledWith({ action: "policy_admission", policy_id: "test-policy", policy_version: 2, enabled: true, reason: "Test decision" }));
  fireEvent.click(screen.getByRole("button", { name: "Отозвать" }));
  await waitFor(() => expect(state.update).toHaveBeenCalledWith({ action: "revoke_suppression", id: 1, reason: "Test decision" }));
});

it("requires scope, reason and expiry before creating a rule", async () => {
  state.update.mockResolvedValue({ status: "ok" });
  mount();
  await screen.findByRole("checkbox", { name: /Synthetic audit rule/ });
  const save = screen.getByRole("button", { name: "Создать правило" }) as HTMLButtonElement;
  expect(save.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("Семантический тип находки"), { target: { value: "semantic.audit.policy.changed" } });
  fireEvent.change(screen.getByLabelText("ID домена"), { target: { value: "1" } });
  fireEvent.change(screen.getByLabelText("SID субъекта"), { target: { value: "S-1-5-21-1-2-3-1001" } });
  fireEvent.change(screen.getByLabelText("Причина"), { target: { value: "Test maintenance" } });
  const expiry = new Date(Date.now() + 86400000).toISOString().slice(0, 16);
  fireEvent.change(screen.getByLabelText("Срок действия (местное время, до 90 дней)"), { target: { value: expiry } });
  expect(save.disabled).toBe(false);
  fireEvent.click(save);
  await waitFor(() => expect(state.update).toHaveBeenCalledWith(expect.objectContaining({ action: "create_suppression", domain_id: 1, scope_kind: "subject_sid", reason: "Test maintenance", scope_value: "S-1-5-21-1-2-3-1001" })));
});

it("shows mutation errors without a success message", async () => {
  state.update.mockRejectedValue(new Error("policy_not_ready"));
  mount();
  await screen.findByRole("checkbox");
  fireEvent.change(screen.getByLabelText("Причина допуска политики или отзыва правила"), { target: { value: "Test decision" } });
  fireEvent.click(screen.getByRole("checkbox"));
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.queryByRole("status")).toBeNull();
});

it("requires a human reason before admission or revocation", async () => {
  mount();
  const admission = await screen.findByRole("checkbox") as HTMLInputElement;
  const revoke = screen.getByRole("button", { name: "Отозвать" }) as HTMLButtonElement;
  expect(admission.disabled).toBe(true);
  expect(revoke.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("Причина допуска политики или отзыва правила"), { target: { value: " " } });
  expect(admission.disabled).toBe(true);
  expect(revoke.disabled).toBe(true);
  expect(state.update).not.toHaveBeenCalled();
});


it.each(["ru", "en"] as const)("shows title and registered date with technical details in %s", async (locale) => {
  setLocale(locale);
  mount();
  const checkbox = await screen.findByRole("checkbox", { name: /Synthetic audit rule/ });
  expect(checkbox.getAttribute("type")).toBe("checkbox");
  expect(screen.getByText(/formatted:2026-10-01T12:00:00\+00:00/)).toBeTruthy();
  const details = screen.getByText("test-policy · 2").closest("details");
  expect(details).toBeTruthy();
  expect(details?.open).toBe(false);
  expect(screen.getAllByText(t("semanticControls.policyDetails")).length).toBeGreaterThan(0);
  expect(screen.getByText(new RegExp(locale === "ru" ? "Версия зарегистрирована" : "Version registered"))).toBeTruthy();
});

const defaultPolicies = [
  ["account-decoy", "Registered decoy account used", "account_decoy"],
  ["file-decoy", "Registered decoy file touched", "file_decoy"],
  ["file-ransom", "Suspected ransomware: mass file changes", "file_ransom"],
  ["file-acl-broad-write", "Write permissions granted to a broad group", "file_acl"],
  ["disabled-account-logon", "Sign-in attempted with a disabled account", "disabled_logon"],
  ["password-spray", "Passwords tried across several accounts", "password_spray"],
  ["password-brute-force", "Repeated password attempts against one account", "password_brute"],
] as const;

it.each(["ru", "en"] as const)("uses rule-quality names for generated default policies in %s", async (locale) => {
  setLocale(locale);
  const policies = defaultPolicies.map(([rule, title]) => ({ ...data.policies[0],
    policy_id: `default:qw.${rule}:${"a".repeat(32)}`, policy_version: 1, title, managed: true }));
  state.list.mockResolvedValue({ ...data, policies,
    audit: [{ action: "semantic_risk_quarantine_requeue_v256", target: "synthetic-job", actor: "migration:256", occurred_at: "2026-10-25T10:00:00Z" }] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><SemanticControlsPanel/></QueryClientProvider>);
  for (const [rule, , name] of defaultPolicies) {
    const checkbox = await screen.findByRole("checkbox", { name: new RegExp(t(`reports.v2.security.rule-quality.names.${name}`)) });
    expect((checkbox as HTMLInputElement).disabled).toBe(true);
    const details = screen.getByText(`default:qw.${rule}:${"a".repeat(32)} · 1`).closest("details");
    expect(details?.open).toBe(false);
  }
  expect(screen.queryByText(/migration:256/)).toBeNull();
  expect(screen.queryByText(/Недостаточно фактов · synthetic-job/)).toBeNull();
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Synthetic admission" } });
  fireEvent.click(screen.getAllByRole("checkbox")[0]);
  await waitFor(() => expect(state.update).toHaveBeenCalledWith({ action: "policy_admission", policy_id: policies[0].policy_id,
    policy_version: 1, enabled: true, reason: "Synthetic admission" }));
});

it.each([
  { id: `custom:qw.account-decoy:${"a".repeat(32)}`, title: "Registered decoy account used" },
  { id: `default:qw.account-decoy:${"a".repeat(32)}`, title: "Custom decoy policy" },
  { id: `default:qw.account-decoy:invalid`, title: "Registered decoy account used" },
])("preserves custom policy metadata ($id, $title)", async ({ id, title }) => {
  state.list.mockResolvedValue({ ...data, policies: [{ ...data.policies[0], policy_id: id, title }] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><SemanticControlsPanel/></QueryClientProvider>);
  expect(await screen.findByRole("checkbox", { name: new RegExp(title) })).toBeTruthy();
});

const builtinPolicies = [
  { policy_id: "l1-eventlog-cleared", title: "Security event log was cleared", key: "security.problems.presentation.eventlog_cleared_title" },
  { policy_id: "l1-audit-policy-changed", title: "Audit policy was changed", key: "security.problems.presentation.audit_title" },
  { policy_id: "l1-privileged-group-member-added", title: "Member was added to a privileged group", key: "security.problems.presentation.privileged_group_title" },
  { policy_id: "l1-scheduled-task-created", title: "Scheduled task was registered", key: "security.problems.presentation.scheduled_task_title" },
] as const;

it.each(["ru", "en"] as const)("localizes only exact built-in version 2 policy titles in %s without changing admission", async (locale) => {
  setLocale(locale);
  const policies = builtinPolicies.map(({ policy_id, title }) => ({ ...data.policies[0], policy_id, title }));
  state.list.mockResolvedValue({ ...data, policies });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><SemanticControlsPanel/></QueryClientProvider>);
  for (const policy of builtinPolicies) {
    const checkbox = await screen.findByRole("checkbox", { name: new RegExp(t(policy.key)) }) as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    expect(checkbox.disabled).toBe(true);
    expect(screen.getByText(`${policy.policy_id} · 2`).closest("details")).toBeTruthy();
  }
  expect(state.update).not.toHaveBeenCalled();
});

it.each((['ru', 'en'] as const).flatMap((locale) => builtinPolicies.flatMap((policy) => [
  { locale, ...policy, title: `Custom ${policy.title}`, policy_version: 2, variation: "custom title" },
  { locale, ...policy, policy_version: 3, variation: "different revision" },
  { locale, ...policy, policy_id: `custom-${policy.policy_id}`, policy_version: 2, variation: "different id" },
  { locale, ...policy, title: ` ${policy.title} `, policy_version: 2, variation: "nonexact title" },
])))("preserves $variation in $locale for $policy_id", async ({ locale, policy_id, policy_version, title }) => {
  setLocale(locale);
  state.list.mockResolvedValue({ ...data, policies: [{ ...data.policies[0], policy_id, policy_version, title }] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><SemanticControlsPanel/></QueryClientProvider>);
  await screen.findByRole("checkbox", { name: new RegExp(title.trim()) });
  expect(screen.getByText(`${policy_id} · ${policy_version}`).closest("details")).toBeTruthy();
  expect(state.update).not.toHaveBeenCalled();
});

it.each((["ru", "en"] as const).flatMap((locale) => [undefined, "", "not-a-date"].map((date) => ({ locale, date }))))("keeps policies editable without metadata in $locale ($date)", async ({ locale, date }) => {
  setLocale(locale);
  state.update.mockResolvedValue({ status: "ok" });
  state.list.mockResolvedValue({ ...data, policies: [{ ...data.policies[0], title: " ", version_created_at: date }] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><SemanticControlsPanel/></QueryClientProvider>);
  await screen.findByRole("checkbox", { name: new RegExp(t("semanticControls.policyTitleUnknown")) });
  expect(screen.getByText(new RegExp(t("semanticControls.versionDateUnknown")))).toBeTruthy();
  expect(screen.queryByText(/formatted:not-a-date/)).toBeNull();
  expect(screen.getByText("test-policy · 2").closest("details")).toBeTruthy();
  fireEvent.change(screen.getByLabelText(t("semanticControls.decisionReason")), { target: { value: "Synthetic decision" } });
  fireEvent.click(screen.getByRole("checkbox", { name: new RegExp(t("semanticControls.policyTitleUnknown")) }));
  await waitFor(() => expect(state.update).toHaveBeenCalledWith({ action: "policy_admission", policy_id: "test-policy", policy_version: 2, enabled: true, reason: "Synthetic decision" }));
});

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiResponseError } from "../../api/client";
import type { NotificationChannel, SmtpSetup } from "../../api/notification-types";
import { OverlayProvider } from "../../design-system";
import { localeRuntime, setLocale, t } from "../../i18n";

const mock = vi.hoisted(() => ({ status: vi.fn(), save: vi.fn(), test: vi.fn(), workspace: vi.fn() }));
vi.mock("../../api/client", async (original) => {
  const actual = await original<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, smtpSetupStatus: () => mock.status(), smtpSetupSave: (...args: unknown[]) => mock.save(...args), testNotificationChannel: (...args: unknown[]) => mock.test(...args), notificationWorkspace: (...args: unknown[]) => mock.workspace(...args) } };
});
import { SmtpSetupPanel } from "./smtp-setup";

const channel: NotificationChannel = { kind: "smtp", enabled: true, tls_mode: "starttls", secret_ref: "SLI_NOTIFY_SMTP_PASSWORD",
  state: "not_configured", revision: 3, updated_at: "2026-10-18T00:00:00Z", last_accepted_at: null, last_attempt_at: null, last_result_code: null, secret_status: null };
const status = (): SmtpSetup => ({ host: "mail.example.test", port: 587, username: "test-login", sender: "sender@example.test",
  secret_set: true, self_user_id: 2, needs_save: false, recipients: [{ user_id: 2, mailbox: "recipient@example.test" }], revision: 3, tls_mode: "starttls", enabled: true });
function mount(canConfigure = true) {
  const onClose = vi.fn(), onSave = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const result = render(<QueryClientProvider client={client}><OverlayProvider><SmtpSetupPanel item={channel} canConfigure={canConfigure}
    onClose={onClose} onSave={onSave} subscriptions={[{ id: "fixture-subscription", owner_user_id: 2, recipient_user_id: 2, channel: "smtp", enabled: true, revision: 1, updated_at: "2026-11-14T01:00:00Z" }]}/></OverlayProvider></QueryClientProvider>);
  return { ...result, client, onClose, onSave };
}
beforeEach(() => { vi.clearAllMocks(); vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); mock.status.mockResolvedValue(status()); mock.save.mockResolvedValue(status()); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("edits the existing SMTP form and preserves an omitted password in %s", async (locale) => {
  setLocale(locale); const view = mount();
  const host = await screen.findByLabelText(t("notify.smtp.host"));
  expect((screen.getByLabelText(t("notify.smtp.password")) as HTMLInputElement).value).toBe("");
  expect(screen.queryByDisplayValue("2")).toBeNull();
  fireEvent.change(host, { target: { value: "replacement.example.test" } });
  expect((screen.getByRole("button", { name: t("notify.sendTest") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: t("notify.save") }));
  await waitFor(() => expect(view.onSave).toHaveBeenCalledOnce());
  expect(mock.save).toHaveBeenCalledWith({ host: "replacement.example.test", port: 587, username: "test-login",
    sender: "sender@example.test", password: "", recipients: [{ user_id: 2, mailbox: "recipient@example.test" }],
    revision: 3, tls_mode: "starttls", enabled: true });
  expect(mock.test).not.toHaveBeenCalled();
});

it("clears the write-only password immediately, prevents repeated saves, and never caches it in mutations", async () => {
  let finish!: (value: SmtpSetup) => void;
  mock.save.mockImplementation(() => new Promise<SmtpSetup>((resolve) => { finish = resolve; }));
  const view = mount();
  const password = await screen.findByLabelText(t("notify.smtp.password")) as HTMLInputElement;
  fireEvent.change(password, { target: { value: "synthetic-only-password" } });
  fireEvent.click(screen.getByRole("button", { name: t("notify.save") }));
  await waitFor(() => expect(mock.save).toHaveBeenCalledOnce());
  expect(password.value).toBe("");
  expect((screen.getByRole("button", { name: t("notify.save") }) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole("button", { name: t("notify.sendTest") }) as HTMLButtonElement).disabled).toBe(true);
  expect(view.client.getMutationCache().getAll()).toHaveLength(0);
  finish(status()); await waitFor(() => expect(view.onSave).toHaveBeenCalledOnce());
});

it("sends the test in the SMTP panel and waits for the exact job's result", async () => {
  const item = { id: "fixture-test", channel: "smtp", state: "pending", result_code: null, updated_at: "2026-11-14T15:41:00Z" };
  mock.test.mockResolvedValue({ item });
  mock.workspace.mockResolvedValue({ items: [{ ...item, state: "accepted", result_code: "accepted" }], has_more: false });
  mount(); await screen.findByLabelText(t("notify.smtp.host"));
  fireEvent.click(screen.getByRole("button", { name: t("notify.sendTest") }));
  expect(await screen.findByText("Доставлено в 22:41")).toBeTruthy();
  expect(screen.getByLabelText(t("notify.smtp.host"))).toBeTruthy();
  expect(mock.save).not.toHaveBeenCalled();
});

it("fails closed for denied or malformed status without editable credential fields", async () => {
  mock.status.mockResolvedValue({ ...status(), tls_mode: "none" });
  const view = mount();
  expect((await screen.findByRole("alert")).textContent).toBe("Не удалось загрузить настройки почты");
  expect(screen.queryByLabelText(t("notify.smtp.password"))).toBeNull();
  expect(mock.save).not.toHaveBeenCalled(); view.unmount();
  mount(false); await screen.findByRole("alert"); expect(mock.status).toHaveBeenCalledTimes(1);
});

it("does not render raw provider errors or retain a failed password", async () => {
  mock.save.mockRejectedValue(new ApiResponseError(503, "synthetic-private-provider-reply"));
  mount(); const password = await screen.findByLabelText(t("notify.smtp.password")) as HTMLInputElement;
  fireEvent.change(password, { target: { value: "synthetic-only-password" } });
  fireEvent.click(screen.getByRole("button", { name: t("notify.save") }));
  expect((await screen.findByRole("alert")).textContent).toBe("Не удалось сохранить настройки почты");
  expect(password.value).toBe("");
  expect(screen.queryByText("synthetic-private-provider-reply")).toBeNull();
  expect(screen.queryByText("synthetic-only-password")).toBeNull();
});

it("requires a first password and recipient mailbox before saving from zero", async () => {
  mock.status.mockResolvedValue({ ...status(), host: "", username: "", sender: "", secret_set: false, enabled: false,
    recipients: [{ user_id: 2, mailbox: "" }] });
  mount(); await screen.findByLabelText(t("notify.smtp.host"));
  for (const [key, value] of [["host", "mail.example.test"], ["username", "test-login"], ["sender", "sender@example.test"]] as const)
    fireEvent.change(screen.getByLabelText(t(`notify.smtp.${key}`)), { target: { value } });
  expect((screen.getByRole("button", { name: t("notify.save") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText(t("notify.smtp.password")), { target: { value: "synthetic-only-password" } });
  fireEvent.change(screen.getByLabelText(t("notify.smtp.selfRecipient")), { target: { value: "recipient@example.test" } });
  expect((screen.getByRole("button", { name: t("notify.save") }) as HTMLButtonElement).disabled).toBe(false);
});

it("preserves recipient identities while allowing an unconfigured secondary mailbox", async () => {
  mock.status.mockResolvedValue({ ...status(), recipients: [{ user_id: 2, mailbox: "recipient@example.test" }, { user_id: 5, mailbox: "" }] });
  mount(); await screen.findByLabelText(t("notify.smtp.host"));
  fireEvent.change(screen.getByLabelText(t("notify.smtp.recipient", { number: 2 })), { target: { value: "secondary@example.test" } });
  fireEvent.click(screen.getByRole("button", { name: t("notify.save") }));
  await waitFor(() => expect(mock.save).toHaveBeenCalledOnce());
  expect(mock.save.mock.calls[0][0].recipients).toEqual([{ user_id: 2, mailbox: "recipient@example.test" }, { user_id: 5, mailbox: "secondary@example.test" }]);
});

it("discards unsaved credentials on close and never prefills a password from status", async () => {
  mock.status.mockResolvedValue({ ...status(), password: "synthetic-server-field" });
  const view = mount(); const password = await screen.findByLabelText(t("notify.smtp.password")) as HTMLInputElement;
  expect(password.value).toBe(""); fireEvent.change(password, { target: { value: "synthetic-unsaved" } });
  fireEvent.click(screen.getByRole("button", { name: t("notify.cancel") }));
  expect(view.onClose).toHaveBeenCalledOnce(); expect(mock.save).not.toHaveBeenCalled();
  view.unmount(); mount();
  expect((await screen.findByLabelText(t("notify.smtp.password")) as HTMLInputElement).value).toBe("");
});

it("requires an explicit password and coherent save for legacy settings", async () => {
  mock.status.mockResolvedValue({ ...status(), secret_set: false, needs_save: true });
  mount(); await screen.findByLabelText(t("notify.smtp.host"));

  expect((screen.getByRole("button", { name: t("notify.sendTest") }) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole("button", { name: t("notify.save") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText(t("notify.smtp.password")), { target: { value: "synthetic-only-password" } });
  fireEvent.click(screen.getByRole("button", { name: t("notify.save") }));
  await waitFor(() => expect(mock.save).toHaveBeenCalledOnce());
});


it("reloads a changed revision after a failed save before retrying or testing", async () => {
  mock.status.mockResolvedValueOnce(status()).mockResolvedValue({ ...status(), revision: 4, enabled: false,
    secret_set: false, needs_save: true });
  mock.save.mockRejectedValueOnce(new ApiResponseError(503, "synthetic-unavailable")).mockResolvedValue({ secret_set: true, needs_save: false, revision: 6 });
  const view = mount();
  fireEvent.change(await screen.findByLabelText(t("notify.smtp.password")), { target: { value: "synthetic-first" } });
  fireEvent.click(screen.getByRole("button", { name: t("notify.save") }));
  await waitFor(() => expect(mock.status).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.getByLabelText(t("notify.smtp.password"))).toHaveProperty("value", ""));
  expect(mock.status).toHaveBeenCalledTimes(2);
  expect((screen.getByRole("button", { name: t("notify.sendTest") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText(t("notify.smtp.password")), { target: { value: "synthetic-retry" } });
  fireEvent.click(screen.getByRole("button", { name: t("notify.save") }));
  await waitFor(() => expect(view.onSave).toHaveBeenCalledOnce());
  expect(mock.save.mock.calls[1][0].revision).toBe(4);
  expect(mock.test).not.toHaveBeenCalled();
});

it("keeps recipient identities at the bottom of the panel, outside the fields", async () => {
  mock.status.mockResolvedValue({ ...status(), recipients: [{ user_id: 2, mailbox: "recipient@example.test" }, { user_id: 5, mailbox: "" }] });
  mount(); await screen.findByLabelText(t("notify.smtp.host"));
  const identity = screen.getByText("5");
  expect(identity.closest("dl")).not.toBeNull();
  expect(identity.closest(".sli-ds-field")).toBeNull();
  expect(screen.queryByDisplayValue("5")).toBeNull();
  expect(screen.queryByRole("group")).toBeNull();
});

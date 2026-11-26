// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { NotificationWorkspace } from "../../api/notification-types";
import { ApiResponseError } from "../../api/client";
import { OverlayProvider } from "../../design-system";
import { localeRuntime, setLocale, t } from "../../i18n";

const mock = vi.hoisted(() => ({ list: vi.fn(), update: vi.fn(), save: vi.fn(), test: vi.fn(), telegram: vi.fn(), smtpStatus: vi.fn(), smtpSave: vi.fn(), schedules: vi.fn(), saveSchedule: vi.fn(), definition: vi.fn() }));
vi.mock("../../api/client", async (original) => {
  const actual = await original<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, notificationWorkspace: (params: URLSearchParams) => mock.list(params),
    updateNotificationChannel: (...args: unknown[]) => mock.update(...args),
    saveNotificationSubscription: (...args: unknown[]) => mock.save(...args),
    testNotificationChannel: (...args: unknown[]) => mock.test(...args),
    notificationSchedules: () => mock.schedules(),
    saveNotificationSchedule: (...args: unknown[]) => mock.saveSchedule(...args),
    reportV2Definition: (key: string) => mock.definition(key),
    telegramSetup: (...args: unknown[]) => mock.telegram(...args),
    smtpSetupStatus: () => mock.smtpStatus(), smtpSetupSave: (...args: unknown[]) => mock.smtpSave(...args) } };
});
import { NotificationsPage } from "./notifications";

function fixture(): NotificationWorkspace {
  return { channels: [{ kind: "smtp", enabled: true, tls_mode: "starttls", secret_ref: "SLI_NOTIFY_SMTP_PASSWORD",
    state: "configured", revision: 3, updated_at: "2026-10-18T00:00:00Z", last_accepted_at: null, last_attempt_at: null,
    last_result_code: null, secret_status: null }],
  subscriptions: [{ id: "fixture-subscription", owner_user_id: 1, recipient_user_id: 2, channel: "smtp", enabled: true,
    revision: 4, updated_at: "2026-10-18T00:00:00Z" }],
  counts: { total: 401, accepted: 390, errors: 4, waiting: 3, other: 4, new_count: null },
  items: [{ id: "fixture-job", subscription_id: "fixture-subscription", object_id: "fixture-object", object_kind: "test_problem",
    object_severity: null, channel: "smtp", state: "retry", attempts: 2, result_code: "smtp_unavailable",
    created_at: "2026-10-18T00:00:00Z", updated_at: "2026-10-18T00:01:00Z", available_at: "2026-10-18T00:06:00Z", finding_id: null }],
  has_more: false, next_cursor: null, previous_login_at: null, can_configure: true };
}
function mount(client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })) {
  return render(<QueryClientProvider client={client}><OverlayProvider><NotificationsPage/></OverlayProvider></QueryClientProvider>);
}

function telegramFixture() {
  const data = fixture();
  data.channels = [{ ...data.channels[0], kind: "telegram" as const, tls_mode: "tls" as const,
    secret_ref: "SLI_NOTIFY_TELEGRAM_TOKEN", state: "not_configured" }];
  return data;
}

it.each((["ru", "en"] as const).flatMap((locale) => (["503", "403", "malformed", "no_token"] as const).map((failure) => ({ locale, failure }))))(
  "blocks a retained discovered choice after $failure status and permits binding only after recovery in $locale", async ({ locale, failure }) => {
    const data = telegramFixture();
    data.channels[0].enabled = false;
    mock.list.mockResolvedValue(data);
    let failed = false;
    mock.telegram.mockImplementation(async (action: string) => {
      if (action === "chats") return { chats: [{ choice: "fixture-choice", name: "Fixture chat" }, { choice: "other-choice", name: "Other fixture" }] };
      if (action === "bind") return { secret_set: true, chat_name: "Fixture chat" };
      if (failed && failure === "503") throw new ApiResponseError(503, "telegram_setup_unavailable");
      if (failed && failure === "403") throw new ApiResponseError(403, "notification_channels_access_denied");
      if (failed && failure === "malformed") return { secret_set: true, chat_name: null };
      return { secret_set: !(failed && failure === "no_token"), chat_bound: false, chat_name: null };
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    setLocale(locale); mount(client);
    fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
    const panel = screen.getByRole("dialog", { name: "Telegram" });
    const find = within(panel).getByRole("button", { name: t("notify.telegram.find") });
    await waitFor(() => expect(find).toHaveProperty("disabled", false));
    fireEvent.click(find);
    const choices = await within(panel).findByLabelText(t("notify.telegram.choose"));
    fireEvent.change(choices, { target: { value: "fixture-choice" } });
    const save = within(panel).getByRole("button", { name: t("notify.save") });
    expect(save).toHaveProperty("disabled", false);
    failed = true;
    await act(async () => { await client.refetchQueries({ queryKey: ["telegram-setup"] }); });
    await waitFor(() => expect(find).toHaveProperty("disabled", true));
    // Retained discovery data must not authorize binding when status is no
    // longer confirmed, including a successful readback with no saved token.
    await act(async () => { fireEvent.click(save); });
    expect(mock.telegram.mock.calls.filter(([action]) => action === "bind")).toHaveLength(0);
    expect(save).toHaveProperty("disabled", true);
    expect(choices).toHaveProperty("disabled", true);
    fireEvent.change(choices, { target: { value: "other-choice" } });
    expect(choices).toHaveProperty("value", "fixture-choice");
    failed = false;
    await act(async () => { await client.refetchQueries({ queryKey: ["telegram-setup"] }); });
    await waitFor(() => expect(save).toHaveProperty("disabled", false));
    expect(choices).toHaveProperty("disabled", false);
    fireEvent.click(save);
    await waitFor(() => expect(mock.telegram.mock.calls.filter(([action]) => action === "bind")).toEqual([["bind", { choice: "fixture-choice" }]]));
  },
);

const setupErrors = [
  ["telegram_setup_invalid_token", "notify.telegram.error.invalidToken", 400],
  ["telegram_setup_network", "notify.telegram.error.network", 503],
  ["telegram_setup_tls", "notify.telegram.error.tls", 503],
  ["telegram_setup_timeout", "notify.telegram.error.timeout", 504],
  ["telegram_setup_unavailable", "notify.telegram.error.unavailable", 503],
  ["telegram_setup_provider_unavailable", "notify.telegram.error.provider", 503],
  ["telegram_setup_rate_limited", "notify.telegram.error.rateLimited", 429],
  ["telegram_setup_conflict", "notify.telegram.error.conflict", 409],
  ["telegram_setup_protocol", "notify.telegram.error.protocol", 502],
  ["telegram_setup_failed", "notify.telegram.error.failed", 400],
] as const;
it.each((["ru", "en"] as const).flatMap((locale) => setupErrors.map(([code, key, status]) => ({ locale, code, key, status }))))(
  "shows fixed $code setup failure without private details in $locale", async ({ locale, code, key, status }) => {
    mock.list.mockResolvedValue(telegramFixture());
    const privateText = "synthetic-private-token-recipient";
    mock.telegram.mockImplementation(async (action: string) => {
      if (action === "status") return { secret_set: false, chat_bound: false, chat_name: null };
      throw new ApiResponseError(status, code, privateText, { description: privateText });
    });
    setLocale(locale); mount();
    fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
    const panel = screen.getByRole("dialog", { name: "Telegram" });
    const field = await within(panel).findByLabelText(t("notify.telegram.token"));
    fireEvent.change(field, { target: { value: privateText } });
    fireEvent.click(within(panel).getByRole("button", { name: t("notify.telegram.verify") }));
    expect(await within(panel).findByRole("alert")).toHaveProperty("textContent", t(key));
    expect(field).toHaveProperty("value", "");
    expect(panel.textContent).not.toContain(privateText);
    expect(within(panel).getByRole("switch", { name: t("notify.enabled") })).toHaveProperty("disabled", true);
  },
);

it.each(["ru", "en"] as const)("redacts unknown setup failures and explains token prerequisites in %s", async (locale) => {
  mock.list.mockResolvedValue(telegramFixture());
  mock.telegram.mockImplementation(async (action: string) => {
    if (action === "status") return { secret_set: false, chat_bound: false, chat_name: null };
    throw new ApiResponseError(500, "synthetic-private-code", "synthetic-private-token");
  });
  setLocale(locale); mount();
  fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
  const panel = screen.getByRole("dialog", { name: "Telegram" });
  const field = await within(panel).findByLabelText(t("notify.telegram.token"));
  const control = within(panel).getByRole("switch", { name: t("notify.enabled") });
  expect(document.getElementById(control.getAttribute("aria-describedby")!)).toHaveProperty("textContent", t("notify.telegram.needToken"));
  fireEvent.change(field, { target: { value: "synthetic-private-token" } });
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.telegram.verify") }));
  expect(await within(panel).findByRole("alert")).toHaveProperty("textContent", t("notify.telegram.error.unavailable"));
  expect(panel.textContent).not.toContain("synthetic-private");
});

it.each(["ru", "en"] as const)("preserves unavailable status despite cached prerequisites and a successful pending action in %s", async (locale) => {
  mock.list.mockResolvedValue(telegramFixture());
  let failStatus = false;
  let finishTest: (value: { job_id: string; state: string }) => void = () => undefined;
  mock.telegram.mockImplementation(async (action: string) => {
    if (action === "test") return new Promise((resolve) => { finishTest = resolve; });
    if (failStatus) throw new ApiResponseError(503, "telegram_setup_unavailable", "synthetic-private");
    return { secret_set: true, chat_bound: true, chat_name: null };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  setLocale(locale); mount(client);
  fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
  const panel = screen.getByRole("dialog", { name: "Telegram" });
  const control = within(panel).getByRole("switch", { name: t("notify.enabled") });
  await waitFor(() => expect(control).toHaveProperty("disabled", false));
  expect(panel.textContent).toContain(`${t("notify.destination")}: —`);
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.sendTest") }));
  await waitFor(() => expect(mock.telegram).toHaveBeenCalledWith("test"));
  failStatus = true;
  await act(async () => { await client.refetchQueries({ queryKey: ["telegram-setup"] }); });
  expect(client.getQueryData(["telegram-setup"])).toEqual({ secret_set: true, chat_bound: true, chat_name: null });
  await act(async () => { finishTest({ job_id: "synthetic-job", state: "pending" }); });
  await waitFor(() => expect(control).toHaveProperty("disabled", true));
  expect(within(panel).getByRole("button", { name: t("notify.sendTest") })).toHaveProperty("disabled", true);
  expect(within(panel).getByRole("button", { name: t("notify.telegram.find") })).toHaveProperty("disabled", true);
  expect(within(panel).queryByText("Токен не задан")).toBeNull();
  expect(within(panel).queryByText("Чат не подключён")).toBeNull();
  expect((await within(panel).findAllByRole("alert")).map((node) => node.textContent)).toContain(t("notify.telegram.error.unavailable"));
});

it.each(["ru", "en"] as const)("retries status and gates binding independently from a display name in %s", async (locale) => {
  mock.list.mockResolvedValue(telegramFixture());
  let mode: "unavailable" | "unbound" | "bound" = "unavailable";
  mock.telegram.mockImplementation(async () => {
    if (mode === "unavailable") throw new ApiResponseError(503, "telegram_setup_unavailable");
    return { secret_set: true, chat_bound: mode === "bound", chat_name: null };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  setLocale(locale); mount(client);
  fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
  const panel = screen.getByRole("dialog", { name: "Telegram" });
  await within(panel).findByRole("alert");
  mode = "unbound";
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.telegram.retryStatus") }));
  expect(await within(panel).findByText(t("notify.telegram.needChat"))).toBeTruthy();
  const control = within(panel).getByRole("switch", { name: t("notify.enabled") });
  expect(control).toHaveProperty("disabled", true);
  mode = "bound";
  await act(async () => { await client.refetchQueries({ queryKey: ["telegram-setup"] }); });
  await waitFor(() => expect(control).toHaveProperty("disabled", false));
  expect(panel.textContent).toContain(`${t("notify.destination")}: —`);
  expect(within(panel).queryByRole("alert")).toBeNull();
  expect(mock.telegram.mock.calls.every(([action]) => action === "status")).toBe(true);
});

it.each(["ru", "en"] as const)("toggles with revisions and clears superseded conflict errors in %s", async (locale) => {
  const data = telegramFixture();
  mock.list.mockImplementation(async () => structuredClone(data));
  mock.telegram.mockResolvedValue({ secret_set: true, chat_bound: true, chat_name: null });
  let conflict = true;
  mock.update.mockImplementation(async (_kind: string, body: { enabled: boolean; revision: number }) => {
    if (conflict) { conflict = false; throw new ApiResponseError(409, "notification_channel_revision_conflict"); }
    expect(body.revision).toBe(data.channels[0].revision);
    data.channels[0].enabled = body.enabled; data.channels[0].revision++;
    return {};
  });
  setLocale(locale); mount();
  fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
  const panel = screen.getByRole("dialog", { name: "Telegram" });
  const control = within(panel).getByRole("switch", { name: t("notify.enabled") });
  await waitFor(() => expect(control).toHaveProperty("disabled", false));
  fireEvent.click(control);
  fireEvent.click(screen.getByRole("button", { name: t("notify.confirm") }));
  expect(await within(panel).findByRole("alert")).toHaveProperty("textContent", t("notify.conflict"));
  fireEvent.click(control);
  fireEvent.click(screen.getByRole("button", { name: t("notify.confirm") }));
  await waitFor(() => expect(control).toHaveProperty("checked", false));
  expect(within(panel).queryByRole("alert")).toBeNull();
  fireEvent.click(control);
  await waitFor(() => expect(control).toHaveProperty("checked", true));
  expect(mock.update.mock.calls.map(([, body]) => body)).toEqual([
    { enabled: false, tls_mode: "tls", secret_ref: "SLI_NOTIFY_TELEGRAM_TOKEN", revision: 3 },
    { enabled: false, tls_mode: "tls", secret_ref: "SLI_NOTIFY_TELEGRAM_TOKEN", revision: 3 },
    { enabled: true, tls_mode: "tls", secret_ref: "SLI_NOTIFY_TELEGRAM_TOKEN", revision: 4 },
  ]);
});

it.each(["ru", "en"] as const)("does not turn unavailable Telegram status into absent credentials in %s", async (locale) => {
  const data = fixture();
  data.channels = [{ ...data.channels[0], kind: "telegram", enabled: true, tls_mode: "tls", secret_ref: "SLI_NOTIFY_TELEGRAM_TOKEN" }];
  mock.list.mockResolvedValue(data);
  mock.telegram.mockRejectedValue(new ApiResponseError(503, "telegram_setup_network", "synthetic-private-error"));
  setLocale(locale); mount();
  await screen.findByRole("button", { name: "Telegram" });
  await waitFor(() => expect(mock.telegram).toHaveBeenCalledWith("status"));
  expect(screen.queryByText("Токен не задан")).toBeNull();
  expect(screen.queryByText("Чат не подключён")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Telegram" }));
  const panel = screen.getByRole("dialog", { name: "Telegram" });
  await within(panel).findByRole("alert");
  expect(within(panel).getByRole("switch", { name: t("notify.enabled") })).toHaveProperty("disabled", true);
  expect(panel.textContent).not.toContain("synthetic-private-error");
});

it.each((["ru", "en"] as const).flatMap((locale) => (["loading", "denied", "malformed"] as const).map((state) => ({ locale, state }))))(
  "keeps $state Telegram status distinct from absent setup in $locale", async ({ locale, state }) => {
    mock.list.mockResolvedValue(telegramFixture());
    mock.telegram.mockImplementation(async () => {
      if (state === "loading") return new Promise(() => undefined);
      if (state === "denied") throw new ApiResponseError(403, "notification_channels_access_denied", "synthetic-private");
      return { secret_set: true, chat_name: "synthetic-private" }; // Missing required binding boolean.
    });
    setLocale(locale); mount();
    fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
    const panel = screen.getByRole("dialog", { name: "Telegram" });
    const label = t(state === "loading" ? "notify.telegram.statusLoading" : state === "denied" ? "notify.denied" : "notify.telegram.statusUnavailable");
    await waitFor(() => expect(within(panel).getAllByText(label).length).toBeGreaterThan(0));
    expect(within(panel).getByRole("switch", { name: t("notify.enabled") })).toHaveProperty("disabled", true);
    expect(within(panel).queryByLabelText(t("notify.telegram.token"))).toBeNull();
    expect(screen.queryByText("Токен не задан")).toBeNull();
    expect(screen.queryByText("Чат не подключён")).toBeNull();
    expect(panel.textContent).not.toContain("synthetic-private");
  },
);

it.each(["ru", "en"] as const)("connects Telegram and waits for worker acceptance in %s", async (locale) => {
  const data = fixture();
  data.channels = [{ ...data.channels[0], kind: "telegram", enabled: false, tls_mode: "tls", secret_ref: "SLI_NOTIFY_TELEGRAM_TOKEN" }];
  mock.list.mockImplementation(async () => structuredClone(data));
  let secret = false;
  let chat: string | null = null;
  let sent = false;
  mock.telegram.mockImplementation(async (action: string) => {
    if (action === "token") { secret = true; return { secret_set: true, bot_name: "Fixture bot" }; }
    if (action === "chats") return { chats: [{ choice: "fixture-choice", name: "Fixture chat" }] };
    if (action === "bind") { chat = "Fixture chat"; data.channels[0].enabled = true; return { chat_name: chat, secret_set: true }; }
    if (action === "test") { sent = true; data.items = [{ ...data.items[0], id: "fixture-test", channel: "telegram", state: "accepted", result_code: "accepted", updated_at: "2026-11-14T15:41:00Z" }]; return { job_id: "fixture-test", state: "pending" }; }
    return { secret_set: secret, chat_bound: !!chat, chat_name: chat, test_job_id: sent ? "fixture-test" : null, test_state: sent ? "accepted" : null };
  });
  setLocale(locale); mount();
  fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
  const panel = screen.getByRole("dialog", { name: "Telegram" });
  expect(within(panel).queryByText("Нет данных")).toBeNull();
  expect(within(panel).getByRole("switch", { name: t("notify.enabled") })).toHaveProperty("disabled", true);
  const token = crypto.randomUUID();
  const field = within(panel).getByLabelText(t("notify.telegram.token"));
  fireEvent.change(field, { target: { value: token } });
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.telegram.verify") }));
  await screen.findByText(t("notify.telegram.bot", { name: "Fixture bot" }));
  expect(panel.textContent).not.toContain(token);
  expect(within(panel).queryByLabelText(t("notify.telegram.token"))).toBeNull();
  expect(within(panel).getByRole("button", { name: t("notify.telegram.change") })).toBeTruthy();
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.telegram.find") }));
  const choices = await within(panel).findByLabelText(t("notify.telegram.choose"));
  fireEvent.change(choices, { target: { value: "fixture-choice" } });
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.save") }));
  await waitFor(() => expect(within(panel).getByRole("button", { name: t("notify.sendTest") })).toHaveProperty("disabled", false));
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.sendTest") }));
  await within(panel).findByText(t("notify.deliveredAt", { time: "22:41" }), {}, { timeout: 4000 });
  expect(mock.telegram).toHaveBeenCalledWith("token", { token, proxy_url: "" });
  expect(mock.telegram).toHaveBeenCalledWith("bind", { choice: "fixture-choice" });
});

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  mock.list.mockResolvedValue(fixture()); mock.update.mockResolvedValue({}); mock.save.mockResolvedValue({});
  mock.test.mockResolvedValue({ item: fixture().items[0] });
  mock.telegram.mockResolvedValue({ secret_set: false, chat_bound: false, chat_name: null });
  mock.smtpStatus.mockResolvedValue({ host: "mail.example.test", port: 587, username: "fixture-login", sender: "sender@example.test",
    secret_set: true, self_user_id: 2, needs_save: false, recipients: [{ user_id: 2, mailbox: "recipient@example.test" }], revision: 3, tls_mode: "starttls", enabled: true });
  mock.smtpSave.mockResolvedValue({});
  window.history.replaceState({}, "", "/app/notifications");
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.clearAllMocks(); });

it.each(["ru", "en"] as const)("shows email configuration before the first delivery (%s)", async (locale) => {
  setLocale(locale); mount();
  expect(await screen.findByText(t("notify.configured"))).toBeTruthy();
  expect(screen.getByText(t("notify.noAcceptedDelivery"))).toBeTruthy();
  expect(screen.queryByRole("columnheader", { name: t("notify.destination") })).toBeNull();
});

it.each(["ru", "en"] as const)("offers configuration for an unconfigured email channel (%s)", async (locale) => {
  setLocale(locale);
  const data = fixture();
  data.channels[0].state = "not_configured";
  mock.list.mockResolvedValue(data);
  mock.smtpStatus.mockResolvedValue({ host: "", port: 587, username: "", sender: "", secret_set: false,
    needs_save: true, recipients: [{ user_id: 2, mailbox: "" }], self_user_id: 2, revision: 3, enabled: true, tls_mode: "starttls" });
  mount();
  expect(await screen.findByText(t("notify.disconnected"))).toBeTruthy();
  const row = screen.getByRole("button", { name: t("reports.v2.notifications.channels.columns.kind.labels.smtp") }).closest("tr")!;
  const configure = await within(row).findByRole("button", { name: t("notify.edit") });
  fireEvent.click(configure);
  expect(await screen.findByRole("dialog")).toBeTruthy();
});

it("does not infer email configuration from an old successful delivery when status is unavailable", async () => {
  const data = fixture();
  data.channels[0].state = "not_configured";
  data.channels[0].last_accepted_at = "2026-10-24T12:00:00Z";
  mock.list.mockResolvedValue(data);
  mock.smtpStatus.mockRejectedValue(new ApiResponseError(503, "smtp_setup_unavailable"));
  mount();
  const row = (await screen.findByRole("button", { name: "Почта" })).closest("tr")!;
  await waitFor(() => expect(mock.smtpStatus).toHaveBeenCalled());
  expect(within(row).queryByText(t("notify.accepted"))).toBeNull();
  expect(within(row).queryByText(t("notify.configured"))).toBeNull();
  expect(within(row).getByText(t("notify.disconnected"))).toBeTruthy();
});

it("keeps the confirmed Telegram status and accepted time when setup cannot be read", async () => {
  const data = telegramFixture();
  data.channels[0].state = "configured";
  data.channels[0].last_accepted_at = "2026-10-24T12:00:00Z";
  mock.list.mockResolvedValue(data);
  mock.telegram.mockRejectedValue(new ApiResponseError(503, "telegram_setup_unavailable"));
  mount();
  const row = (await screen.findByRole("button", { name: "Telegram" })).closest("tr")!;
  expect(within(row).getByText(t("notify.configured"))).toBeTruthy();
  expect(within(row).getByText(/24\.10\.2026/)).toBeTruthy();
});

it("keeps the channel list readable when SMTP settings are malformed", async () => {
  mock.smtpStatus.mockResolvedValue({ host: "mail.example.test", sender: "sender@example.test", secret_set: true, needs_save: false });
  mount();
  const table = await screen.findByRole("table", { name: t("notify.channels") });
  await waitFor(() => expect(mock.smtpStatus).toHaveBeenCalled());
  expect(within(table).getByText(t("notify.configured"))).toBeTruthy();
  fireEvent.click(within(table).getByRole("button", { name: t("notify.edit") }));
  const panel = screen.getByRole("dialog");
  expect(await within(panel).findByRole("alert")).toBeTruthy();
  expect(within(panel).queryByLabelText(t("notify.smtp.password"))).toBeNull();
});

it.each(["ru", "en"] as const)("opens editable SMTP settings from the existing registry in %s", async (locale) => {
  setLocale(locale); mount();
  await screen.findByRole("tab", { name: t("notify.channels") });
  expect(screen.queryByText("Нет данных")).toBeNull();
  expect(screen.queryByText(/SLI_NOTIFY_SMTP_PASSWORD/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("notify.edit") }));
  const host = await screen.findByLabelText(t("notify.smtp.host"));
  const panel = screen.getByRole("dialog");
  expect(panel.contains(host)).toBe(true);
  expect(panel.isConnected).toBe(true);
  expect((within(panel).getByLabelText(t("notify.smtp.password")) as HTMLInputElement).value).toBe("");
  expect(panel.textContent).not.toContain("••");
  fireEvent.change(within(panel).getByLabelText(t("notify.tls")), { target: { value: "tls" } });
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.save") }));
  await waitFor(() => expect(mock.smtpSave).toHaveBeenCalledWith({
    host: "mail.example.test", port: 587, username: "fixture-login", sender: "sender@example.test", password: "",
    recipients: [{ user_id: 2, mailbox: "recipient@example.test" }], enabled: true, tls_mode: "tls", revision: 3,
  }));
});

it.each(["ru", "en"] as const)("keeps the mockup sections and both channel settings reachable in %s", async (locale) => {
  const data = fixture();
  data.channels.push({ ...data.channels[0], kind: "telegram", tls_mode: "tls", secret_ref: "SLI_NOTIFY_TELEGRAM_TOKEN" });
  mock.list.mockResolvedValue(data);
  setLocale(locale); mount();
  await screen.findByRole("tab", { name: t("notify.channels") });
  expect(screen.getAllByRole("tab")).toHaveLength(3);
  const channels = screen.getByRole("table", { name: t("notify.channels") });
  expect(within(channels).getByRole("button", { name: t("reports.v2.notifications.channels.columns.kind.labels.smtp") })).toBeTruthy();
  fireEvent.click(within(channels).getByRole("button", { name: "Telegram" }));
  const editor = screen.getByRole("dialog", { name: "Telegram" });
  expect(within(editor).getByLabelText(t("notify.enabled"))).toBeTruthy();
  expect(within(editor).getByRole("switch", { name: t("notify.enabled") })).toBeTruthy();
  expect(within(editor).getByLabelText(t("notify.telegram.token"))).toHaveProperty("type", "password");
  fireEvent.click(within(editor).getByRole("button", { name: t("notify.cancel") }));
  fireEvent.click(screen.getByRole("tab", { name: t("notify.rules") }));
  expect(screen.getByRole("button", { name: t("notify.addRule") })).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: t("notify.journal") }));
  expect(screen.getByLabelText(t("notify.period"))).toBeTruthy();
  expect(screen.getByRole("button", { name: t("notify.testProblem") })).toBeTruthy();
});

it("shows a denial instead of cached rows or zero counts", async () => {
  mock.list.mockRejectedValue(new ApiResponseError(403)); mount();
  await screen.findByText(t("notify.denied"));
  expect(screen.queryByRole("table")).toBeNull();
});

it("names a notification loading failure in a plain retry line", async () => {
  mock.list.mockRejectedValueOnce(new ApiResponseError(500));
  const { container } = mount();
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("Не удалось загрузить оповещения");
  expect(container.querySelector(".sli-ds-state")).toBeNull();
  fireEvent.click(within(alert).getByRole("button", { name: t("state.retry") }));
  expect(await screen.findByRole("table", { name: t("notify.channels") })).toBeTruthy();
});

it("keeps delivery actions disabled without the configuration grant and never loads removed schedules", async () => {
  const data = fixture(); data.can_configure = false; mock.list.mockResolvedValue(data);
  mount();
  expect(await screen.findByRole("button", { name: t("notify.test") })).toHaveProperty("disabled", true);
  fireEvent.click(screen.getByRole("tab", { name: t("notify.rules") }));
  expect(screen.getByRole("button", { name: t("notify.addRule") })).toHaveProperty("disabled", true);
  expect(screen.getByRole("tabpanel").textContent).not.toMatch(/Подписки на отчёты|Нет данных|недоступн/);
  fireEvent.click(within(screen.getByRole("table", { name: t("notify.rules") })).getByText(t("notify.publishedProblems")).closest("tr")!);
  const panel = screen.getByRole("dialog");
  expect(within(panel).getByRole("button", { name: t("notify.save") })).toHaveProperty("disabled", true);
  expect(within(panel).getByLabelText(t("notify.enabled"))).toHaveProperty("disabled", true);
  expect(mock.test).not.toHaveBeenCalled(); expect(mock.save).not.toHaveBeenCalled();
  expect(mock.schedules).not.toHaveBeenCalled(); expect(mock.saveSchedule).not.toHaveBeenCalled();
});

it("keeps aggregate counts, safe reasons and a delivery drawer", async () => {
  mount(); await screen.findByRole("tab", { name: t("notify.journal") });
  fireEvent.click(screen.getByRole("tab", { name: t("notify.journal") }));
  expect(screen.getByRole("button", { name: `${t("notify.all")} 401` })).toBeTruthy();
  expect(screen.getByText(t("reports.v2.notifications.deliveries.columns.result_code.labels.smtp_unavailable"))).toBeTruthy();
  expect(screen.queryByText(/Новых с прошлого входа/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("notify.testProblem") }));
  expect(screen.getByRole("dialog").textContent).toContain(t("notify.repeats"));
  expect(screen.getByRole("dialog").textContent).toContain("1");
});

it("names the delivered problem and links its drawer to the exact problem", async () => {
  window.history.replaceState({}, "", "/app/notifications?tab=journal");
  const data = fixture();
  const title = "Critical · Password guessing · synthetic-user · 192.0.2.1";
  data.items = [{ ...data.items[0], object_kind: "semantic_finding", finding_id: 42, problem_title: title }];
  mock.list.mockResolvedValue(data);
  mount();
  fireEvent.click(await screen.findByRole("button", { name: title }));
  expect(screen.getByRole("dialog", { name: title })).toBeTruthy();
  expect(screen.getByRole("link", { name: t("notify.openProblem") }).getAttribute("href"))
    .toBe("/app/report/security.problems?id=42");
});

it("requests server filters and never treats a page length as the total", async () => {
  mount(); await screen.findByRole("tab", { name: t("notify.journal") });
  fireEvent.click(screen.getByRole("tab", { name: t("notify.journal") }));
  fireEvent.click(screen.getByRole("button", { name: `${t("notify.errors")} 4` }));
  await waitFor(() => expect(mock.list.mock.calls.at(-1)?.[0].get("status")).toBe("errors"));
  fireEvent.change(await screen.findByLabelText(t("notify.period")), { target: { value: "30" } });
  await waitFor(() => expect(mock.list.mock.calls.at(-1)?.[0].get("days")).toBe("30"));
});

it("edits a rule through its row and confirms disabling it by name", async () => {
  mount(); fireEvent.click(await screen.findByRole("tab", { name: t("notify.rules") }));
  const table = screen.getByRole("table", { name: t("notify.rules") });
  fireEvent.click(within(table).getByText(t("notify.publishedProblems")).closest("tr")!);
  const dialog = screen.getByRole("dialog");
  expect(within(dialog).getByRole("button", { name: t("notify.save") })).toHaveProperty("disabled", true);
  fireEvent.click(within(dialog).getByLabelText(t("notify.enabled")));
  fireEvent.click(within(dialog).getByRole("button", { name: t("notify.save") }));
  expect(screen.getByRole("dialog", { name: "Отключить «Проблемы → Почта (recipient@example.test)»?" })).toBeTruthy();
  expect(mock.save).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: t("notify.confirm") }));
  await waitFor(() => expect(mock.save).toHaveBeenCalledWith("fixture-subscription", {
    recipient_user_id: 2, channel: "smtp", enabled: false, revision: 4,
  }));
});

it("names the rule save operation when the server rejects it", async () => {
  mock.save.mockRejectedValueOnce(new ApiResponseError(500));
  mount();
  fireEvent.click(await screen.findByRole("tab", { name: t("notify.rules") }));
  fireEvent.click(screen.getByRole("button", { name: t("notify.addRule") }));
  const dialog = screen.getByRole("dialog");
  fireEvent.change(within(dialog).getByLabelText(t("notify.destination")), { target: { value: "2" } });
  fireEvent.click(within(dialog).getByRole("button", { name: t("notify.save") }));
  expect((await within(dialog).findByRole("alert")).textContent).toBe("Не удалось сохранить правило оповещений");
});

it("does not label a dry run as delivered and reuses the test identity on retry", async () => {
  mock.test.mockRejectedValue(new ApiResponseError(503));
  mount(); await screen.findByRole("button", { name: t("notify.test") });
  fireEvent.click(screen.getByRole("button", { name: t("notify.test") }));
  await screen.findByLabelText(t("notify.smtp.host"));
  fireEvent.click(screen.getByRole("button", { name: t("notify.sendTest") }));
  await screen.findByText(t("notify.testFailed", { channel: t("notify.smtp.title") }));
  fireEvent.click(screen.getByRole("button", { name: t("notify.sendTest") }));
  await waitFor(() => expect(mock.test).toHaveBeenCalledTimes(2));
  expect(mock.test.mock.calls[0]).toEqual(mock.test.mock.calls[1]);
});


it.each(["ru", "en"] as const)("explains history suppression and pipeline delay without a channel failure in %s", async (locale) => {
  setLocale(locale);
  window.history.replaceState({}, "", "/app/notifications?tab=journal");
  const data = fixture();
  data.channels[0].last_result_code = "historical_replay";
  data.items = [
    { ...data.items[0], id: "fixture-history", state: "cancelled", attempts: 0, result_code: "historical_replay", delivery_reason: "historical_replay", delay_minutes: 0 },
    { ...data.items[0], id: "fixture-import", state: "cancelled", attempts: 0, result_code: "history_import", delivery_reason: "history_import", delay_minutes: 0 },
    { ...data.items[0], id: "fixture-delayed", state: "accepted", result_code: "accepted", delivery_reason: "pipeline_delay", delay_minutes: 120 },
  ];
  mock.list.mockResolvedValue(data);
  const view = mount();
  expect(await screen.findByText(t("reports.v2.notifications.deliveries.columns.result_code.labels.historical_replay"))).toBeTruthy();
  expect(screen.getByText(t("reports.v2.notifications.deliveries.columns.result_code.labels.history_import"))).toBeTruthy();
  fireEvent.click(screen.getByText(t("reports.v2.notifications.deliveries.columns.state.labels.accepted")).closest("tr")!);
  expect(screen.getByText(t("notifications.delivery.delayed", { minutes: 120 }))).toBeTruthy();
  expect(view.container.querySelector('[role="alert"]')).toBeNull();
  expect(view.container.querySelector(".sli-ds-callout")).toBeNull();
});

it.each(["ru", "en"] as const)("passes the visible saved proxy through token verification in %s", async (locale) => {
  mock.list.mockResolvedValue(telegramFixture());
  mock.telegram.mockImplementation(async (action: string) => action === "status"
    ? { secret_set: false, chat_bound: false, proxy_url: "http://proxy.example.test:3128" }
    : { secret_set: true, chat_bound: false });
  setLocale(locale); mount();
  fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
  const panel = screen.getByRole("dialog", { name: "Telegram" });
  const label = locale === "ru" ? "Прокси для Telegram (необязательно)" : "Telegram proxy (optional)";
  const field = await within(panel).findByLabelText(label);
  expect(field).toHaveProperty("value", "http://proxy.example.test:3128");
  fireEvent.change(field, { target: { value: "http://other.example.test:8080" } });
  fireEvent.change(within(panel).getByLabelText(t("notify.telegram.token")), { target: { value: "synthetic-token" } });
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.telegram.verify") }));
  await waitFor(() => expect(mock.telegram).toHaveBeenCalledWith("token", { token: "synthetic-token", proxy_url: "http://other.example.test:8080" }));
});

it.each([undefined, "http://proxy.example.test:3128"])("clears proxy explicitly for direct verification from %s", async (savedProxy) => {
  mock.list.mockResolvedValue(telegramFixture());
  mock.telegram.mockResolvedValue({ secret_set: false, chat_bound: false, proxy_url: savedProxy });
  mount();
  fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
  const panel = screen.getByRole("dialog", { name: "Telegram" });
  const field = await within(panel).findByLabelText("Прокси для Telegram (необязательно)");
  expect(field).toHaveProperty("value", savedProxy ?? "");
  fireEvent.change(field, { target: { value: "" } });
  fireEvent.change(within(panel).getByLabelText(t("notify.telegram.token")), { target: { value: "synthetic-token" } });
  fireEvent.click(within(panel).getByRole("button", { name: t("notify.telegram.verify") }));
  await waitFor(() => expect(mock.telegram).toHaveBeenCalledWith("token", { token: "synthetic-token", proxy_url: "" }));
});
it("keeps journal day and timestamp in the selected zone across midnight", async () => {
  window.history.replaceState({}, "", "/app/notifications?tab=journal");
  const data = fixture();
  data.items[0].created_at = "2026-10-18T23:05:00Z";
  mock.list.mockResolvedValue(data);
  // The application context defaults to Asia/Novosibirsk, not the browser zone.
  mount();
  expect(await screen.findByRole("table", { name: t("notify.journal") })).toBeTruthy();
  expect(screen.getAllByText("19.10.2026, 06:05").length).toBeGreaterThan(0);
});



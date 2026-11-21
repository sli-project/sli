// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { NotificationWorkspace } from "../../api/notification-types";
import { OverlayProvider } from "../../design-system";
import { localeRuntime, setLocale, t } from "../../i18n";

const mock = vi.hoisted(() => ({ workspace: vi.fn(), telegram: vi.fn() }));
vi.mock("../../api/client", async (original) => {
  const actual = await original<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, notificationWorkspace: (...args: unknown[]) => mock.workspace(...args),
    telegramSetup: (...args: unknown[]) => mock.telegram(...args), smtpSetupStatus: async () => ({
      host: "mail.example.test", port: 587, username: "fixture", sender: "sender@example.test", secret_set: true,
      self_user_id: 2, needs_save: false, recipients: [{ user_id: 2, mailbox: "recipient@example.test" }],
      revision: 1, tls_mode: "starttls", enabled: true,
    }) } };
});
import { NotificationsPage } from "./notifications";

const workspace = (): NotificationWorkspace => ({
  channels: [{ kind: "telegram", enabled: true, tls_mode: "tls", secret_ref: "SLI_NOTIFY_TELEGRAM_TOKEN", state: "active",
    revision: 1, updated_at: "2026-11-14T01:00:00Z", last_accepted_at: null, last_attempt_at: "2026-11-14T02:01:00Z", last_result_code: "telegram_chat_denied", secret_status: null }],
  subscriptions: [{ id: "fixture-subscription", owner_user_id: 2, recipient_user_id: 2, channel: "telegram", enabled: true,
    revision: 1, updated_at: "2026-11-14T01:00:00Z" }],
  items: [{ id: "fixture-test", subscription_id: "fixture-subscription", object_id: "fixture-object", object_kind: "test_problem",
    object_severity: null, channel: "telegram", state: "failed", attempts: 1, result_code: "telegram_chat_denied",
    created_at: "2026-11-14T02:00:00Z", updated_at: "2026-11-14T02:01:00Z", available_at: null, finding_id: null }],
  counts: { total: 1, accepted: 0, errors: 1, waiting: 0, other: 0, new_count: null },
  has_more: false, next_cursor: null, previous_login_at: null, can_configure: true,
});
function mount() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <OverlayProvider><NotificationsPage/></OverlayProvider>
  </QueryClientProvider>);
}
beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru");
  window.history.replaceState({}, "", "/app/notifications");
  mock.workspace.mockResolvedValue(workspace());
  mock.telegram.mockResolvedValue({ secret_set: false, chat_bound: false, chat_name: null });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.clearAllMocks(); });

it("separates configuration from history in five columns", async () => {
  const view = mount();
  const table = await screen.findByRole("table", { name: "Каналы" });
  const row = within(table).getByRole("button", { name: "Telegram" }).closest("tr")!;
  const state = within(row).getAllByRole("cell")[1];
  expect(await within(state).findByText("Не подключён")).toBeTruthy();
  expect(within(table).getAllByRole("columnheader")).toHaveLength(5);
  expect(within(table).queryByRole("columnheader", { name: "Куда" })).toBeNull();
  expect(within(row).queryByText("Не подтверждена")).toBeNull();
  expect(within(row).getAllByRole("cell")[3].textContent).toBe("—");
  expect(state.querySelectorAll("div, .sli-ds-badge")).toHaveLength(0);
  expect(row.textContent).not.toMatch(/Токен не задан|Чат не подключён/);
  expect(view.container.querySelector(".sli-ds-callout, .sli-ds-header__subtitle")).toBeNull();
  expect(within(table).getByRole("columnheader", { name: "Последняя доставка" })).toBeTruthy();
});

it("keeps only actionable rules named after their content and destination", async () => {
  mock.telegram.mockResolvedValue({ secret_set: true, chat_bound: true, chat_name: "Fixture chat" });
  mount();
  fireEvent.click(await screen.findByRole("tab", { name: "Правила" }));
  const table = await screen.findByRole("table", { name: "Правила" });
  expect(await within(table).findByText("Telegram (Fixture chat)")).toBeTruthy();
  expect(within(table).getByRole("columnheader", { name: "Что отправляется" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "Добавить правило" })).toBeTruthy();
  expect(screen.getByRole("tabpanel").textContent).not.toMatch(/Нет данных|недоступн|Политика по важности|Тихие часы|Подписки на отчёты|получателю №|Появятся позже/);
});

it("gives the next action for an empty rules list without a generic no-data block", async () => {
  const data = workspace(); data.subscriptions = []; mock.workspace.mockResolvedValue(data);
  mount(); fireEvent.click(await screen.findByRole("tab", { name: "Правила" }));
  expect(screen.getByRole("tabpanel").textContent).not.toMatch(/Нет данных|недоступн/);
  expect(screen.getByText("Правил нет. Добавьте правило.")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Добавить правило" })).toHaveProperty("disabled", false);
});

it("sends a Telegram test in the panel and shows the actual delivery time", async () => {
  mock.telegram.mockImplementation(async (action: string) => action === "test" ? { job_id: "fixture-test", state: "pending" }
    : { secret_set: true, chat_bound: true, chat_name: "Fixture chat" });
  const data = workspace(); data.items[0] = { ...data.items[0], state: "accepted", result_code: "accepted" };
  mock.workspace.mockResolvedValue(data);
  mount();
  fireEvent.click(await screen.findByRole("button", { name: "Telegram" }));
  const panel = screen.getByRole("dialog", { name: "Telegram" });
  fireEvent.click(await within(panel).findByRole("button", { name: "Отправить проверку" }));
  expect(await within(panel).findByText("Доставлено в 09:01")).toBeTruthy();
});

it.each(["ru", "en"] as const)("keeps configured channels separate from an old failed attempt (%s)", async (locale) => {
  setLocale(locale);
  mock.telegram.mockResolvedValue({ secret_set: true, chat_bound: true, chat_name: "Fixture chat" });
  mount();
  const table = await screen.findByRole("table", { name: t("notify.channels") });
  const row = within(table).getByRole("button", { name: "Telegram" }).closest("tr")!;
  expect(await within(row).findByText(t("notify.configured"))).toBeTruthy();
  const cells = within(row).getAllByRole("cell");
  expect(cells[2].textContent).toMatch(/2026.*9:01|09:01/);
  expect(cells[2].textContent).toContain(t("reports.v2.notifications.deliveries.columns.result_code.labels.telegram_chat_denied"));
  expect(cells[3].textContent).toBe("—");
});

// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ApiResponseError } from "../../api/client";
import { localeRuntime, setLocale } from "../../i18n";
import { ChannelTest } from "./channel-test";

const mock = vi.hoisted(() => ({ send: vi.fn(), workspace: vi.fn() }));
vi.mock("../../api/client", async (original) => {
  const actual = await original<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, telegramSetup: () => mock.send(), notificationWorkspace: (params: URLSearchParams) => mock.workspace(params) } };
});
const job = { id: "fixture-test", channel: "telegram", state: "pending", updated_at: "2026-11-14T15:41:00Z", result_code: null };
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><ChannelTest channel="telegram" enabled onRefresh={() => undefined}/></QueryClientProvider>);
  return client;
}
beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru");
  mock.send.mockResolvedValue({ job_id: job.id, state: "pending" });
  mock.workspace.mockResolvedValue({ items: [job], has_more: false });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.clearAllMocks(); });

it("waits for its own delivery and follows server pages before showing delivery time", async () => {
  let accepted = false;
  mock.workspace.mockImplementation(async (params: URLSearchParams) => params.has("cursor")
    ? { items: [{ ...job, state: accepted ? "accepted" : "pending" }], has_more: false }
    : { items: [{ ...job, id: "unrelated-job", state: "accepted" }], has_more: true, next_cursor: "fixture-cursor" });
  const client = mount();
  fireEvent.click(screen.getByRole("button", { name: "Отправить проверку" }));
  expect(await screen.findByText("Ожидаем результат службы доставки…")).toBeTruthy();
  await waitFor(() => expect(mock.workspace.mock.calls.some(([params]) => params.get("cursor") === "fixture-cursor")).toBe(true));
  expect(screen.queryByText(/Доставлено/)).toBeNull();
  expect(screen.getByRole("button", { name: "Отправить проверку" })).toHaveProperty("disabled", true);
  accepted = true;
  await act(async () => { await client.refetchQueries({ queryKey: ["notification-test"] }); });
  expect(await screen.findByText("Доставлено в 22:41")).toBeTruthy();
});

it.each(["telegram_chat_denied", "synthetic-private-token <script>fixture</script>"])("shows a safe service failure for %s", async (code) => {
  mock.workspace.mockResolvedValue({ items: [{ ...job, state: "failed", result_code: code }], has_more: false });
  mount(); fireEvent.click(screen.getByRole("button", { name: "Отправить проверку" }));
  expect(await screen.findByText(code === "telegram_chat_denied"
    ? "Ошибка: Чат Telegram недоступен для отправки, 22:41" : "Ошибка: Служба доставки отклонила сообщение, 22:41")).toBeTruthy();
  expect(document.body.textContent).not.toContain("synthetic-private");
  expect(screen.queryByText(/Доставлено/)).toBeNull();
});

it("does not turn a failed result read into delivery success and allows readback retry", async () => {
  mock.workspace.mockRejectedValue(new ApiResponseError(503, "synthetic-private-reply"));
  mount(); fireEvent.click(screen.getByRole("button", { name: "Отправить проверку" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Не удалось загрузить результат проверки: Telegram Повторить");
  expect(document.body.textContent).not.toContain("synthetic-private");
  mock.workspace.mockResolvedValue({ items: [{ ...job, state: "accepted" }], has_more: false });
  fireEvent.click(screen.getByRole("button", { name: "Повторить" }));
  expect(await screen.findByText("Доставлено в 22:41")).toBeTruthy();
});

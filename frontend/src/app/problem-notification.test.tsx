// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { t } from "../i18n";
const state = vi.hoisted(() => ({ allowed: false }));
vi.mock("./App", () => ({ useEffectiveAccess: () => ({ capabilities: state.allowed ? ["access.manage"] : [],
  reports: ["notifications.channels", "notifications.deliveries"].map((report_key) => ({ report_key, allowed: state.allowed })) }) }));
import { ProblemNotification } from "./problem-notification";
function mount() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ProblemNotification findingId={11}/></QueryClientProvider>);
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); state.allowed = false; });
it("does not request or link restricted notification data", () => {
  const read = vi.spyOn(api, "notificationWorkspace"); mount();
  expect(read).not.toHaveBeenCalled(); expect(screen.queryByRole("link")).toBeNull();
  expect(screen.getByText(t("notify.notificationLine", { status: t("notify.noData") }))).toBeTruthy();
});
it("shows per-channel outcomes without claiming confirmed receipt", async () => {
  state.allowed = true;
  const read = vi.spyOn(api, "notificationWorkspace").mockResolvedValue({ counts: { total: 2, accepted: 1, errors: 1, waiting: 0, other: 0, new_count: null } } as never);
  mount();
  await screen.findByText(t("notify.notificationLine", { status: `${t("notify.accepted")} 1 · ${t("notify.errors")} 1` }));
  expect(read.mock.calls[0][0].get("finding_id")).toBe("11");
  expect(screen.getByRole("link").getAttribute("href")).toContain("finding_id=11");
});
it("keeps an unavailable or empty history unknown", async () => {
  state.allowed = true;
  vi.spyOn(api, "notificationWorkspace").mockRejectedValue(new Error("unavailable")); mount();
  expect(await screen.findByText(t("notify.notificationLine", { status: t("notify.noData") }))).toBeTruthy();
});

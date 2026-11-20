// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { WatchEntry } from "../api/watch-types";
import { ApiResponseError } from "../api/client";
import { OverlayProvider } from "../design-system";
import { localeRuntime, setLocale, t } from "../i18n";
import { ru } from "../i18n/ru";
import { en } from "../i18n/en";

const state = vi.hoisted(() => ({ list: vi.fn(), save: vi.fn(), visible: true }));
vi.mock("./App", () => ({ useEffectiveAccess: () => ({ reports: [{ report_key: "watch.registry", allowed: state.visible }] }) }));
vi.mock("../api/client", async (original) => ({ ...await original<typeof import("../api/client")>(),
  api: { watchEntries: (params: URLSearchParams) => state.list(params), saveWatchEntry: (...args: unknown[]) => state.save(...args) } }));
import { AccountWatch } from "./account-watch";

const entry: WatchEntry = { id: "fixture-entry", revision: 2,
  identity: { entity_id: 12, domain_id: 1, sid: "S-1-5-21-1-2-3-1001", guid: "00000000-0000-4000-8000-000000000001" },
  owner: "fixture-team", reason: "fixture watch reason", active: true, expires_at: "2099-10-18T00:00:00Z",
  active_from: "2026-10-18T00:00:00Z", valid_from: "2026-10-18T00:00:00Z", valid_to: null,
  actor_type: "session", actor_id: 1, status: "active", can_manage: true };

function mount(entityId?: number) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><OverlayProvider><AccountWatch entityId={entityId}/></OverlayProvider></QueryClientProvider>);
}
beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  state.visible = true;
  state.list.mockResolvedValue({ items: [entry], has_more: false, next_cursor: null, can_manage: true });
  state.save.mockResolvedValue({ item: { id: "fixture-entry", revision: 3 } });
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); vi.clearAllMocks(); });

it.each(["ru", "en"] as const)("shows the same reason, expiry and revision in card and list in %s", async (locale) => {
  setLocale(locale);
  mount(12);
  expect(await screen.findByText(entry.reason)).toBeTruthy();
  expect(screen.getByText(entry.owner)).toBeTruthy();
  expect(screen.getByRole("link", { name: entry.identity.sid }).getAttribute("href")).toBe("/app/entities/12");
  expect(state.list.mock.calls[0][0].get("entity_id")).toBe("12");
  expect(screen.getByText(t("watch.expiresAt"))).toBeTruthy();
  cleanup(); mount();
  expect(await screen.findByText(entry.reason)).toBeTruthy();
  expect(state.list.mock.calls.at(-1)?.[0].has("entity_id")).toBe(false);
});

it("starts from the card with a mandatory reason and a future default expiry", async () => {
  state.list.mockResolvedValue({ items: [], has_more: false, can_manage: true });
  mount(12);
  const start = await screen.findByRole("button", { name: t("watch.start") });
  await waitFor(() => expect((start as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(start);
  const drawer = within(screen.getByRole("dialog"));
  const expiry = drawer.getByLabelText(t("watch.expiresAt")) as HTMLInputElement;
  const days = (new Date(expiry.value).getTime() - Date.now()) / 86400_000;
  expect(days).toBeGreaterThan(6.9); expect(days).toBeLessThanOrEqual(7);
  fireEvent.change(drawer.getByLabelText(t("watch.owner")), { target: { value: "fixture-team" } });
  expect((drawer.getByRole("button", { name: t("watch.save") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(drawer.getByLabelText(t("watch.reason")), { target: { value: "fixture create" } });
  fireEvent.change(expiry, { target: { value: "2000-01-01T00:00" } });
  expect((drawer.getByRole("button", { name: t("watch.save") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(expiry, { target: { value: "2099-01-01T00:00" } });
  fireEvent.click(drawer.getByRole("button", { name: t("watch.save") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledWith(null, {
    entity_id: 12, owner: "fixture-team", reason: "fixture create", expires_at: new Date("2099-01-01T00:00").toISOString(), active: true, revision: 0,
  }));
});

it.each([true, false])("extends or stops the current revision, active=%s", async (active) => {
  mount(); await screen.findByText(entry.reason);
  fireEvent.click(screen.getByRole("button", { name: t("watch.edit") }));
  const drawer = within(screen.getByRole("dialog"));
  expect((drawer.getByLabelText(t("watch.reason")) as HTMLTextAreaElement).value).toBe("");
  fireEvent.change(drawer.getByLabelText(t("watch.reason")), { target: { value: "fixture change" } });
  if (!active) fireEvent.click(drawer.getByLabelText(t("watch.active")));
  fireEvent.click(drawer.getByRole("button", { name: t("watch.save") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledWith(entry.id, {
    entity_id: 12, owner: entry.owner, reason: "fixture change", expires_at: entry.expires_at.replace("Z", ".000Z"), active, revision: 2,
  }));
});

it("keeps a stopped entry disabled until explicitly enabled again", async () => {
  state.list.mockResolvedValue({ items: [{ ...entry, active: false, status: "disabled" }], has_more: false });
  mount(); await screen.findByText(entry.reason);
  fireEvent.click(screen.getByRole("button", { name: t("watch.edit") }));
  const drawer = within(screen.getByRole("dialog"));
  expect((drawer.getByLabelText(t("watch.active")) as HTMLInputElement).checked).toBe(false);
  fireEvent.change(drawer.getByLabelText(t("watch.reason")), { target: { value: "fixture keep disabled" } });
  fireEvent.click(drawer.getByRole("button", { name: t("watch.save") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledWith(entry.id, expect.objectContaining({ active: false, revision: 2 })));
});

it("shows expiry and retained reasons in history", async () => {
  state.list.mockImplementation((params: URLSearchParams) => Promise.resolve({ items: params.has("id")
    ? [{ ...entry, revision: 1, reason: "fixture original reason", valid_to: "2026-10-18T01:00:00Z" }] : [{ ...entry, status: "expired" }], has_more: false }));
  mount(); await screen.findByText(entry.reason);
  expect(screen.getByText(t("watch.expired"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("watch.history") }));
  const drawer = within(screen.getByRole("dialog"));
  expect(await drawer.findByText("fixture original reason")).toBeTruthy();
  expect(drawer.getByText(t("watch.validTo"))).toBeTruthy();
});

it("does not query without registry access and disables changes on readonly entries", async () => {
  state.visible = false; mount(12);
  expect(state.list).not.toHaveBeenCalled();
  expect(screen.queryByText(t("watch.title"))).toBeNull();
  cleanup(); state.visible = true;
  state.list.mockResolvedValue({ items: [{ ...entry, can_manage: false }], has_more: false, can_manage: false });
  mount(12); await screen.findByText(entry.reason);
  expect((screen.getByRole("button", { name: t("watch.edit") }) as HTMLButtonElement).disabled).toBe(true);
  expect(state.save).not.toHaveBeenCalled();
});

it("shows denial without a misleading empty state", async () => {
  state.list.mockRejectedValue(new ApiResponseError(403, "watch_access_denied"));
  const view = mount(12);
  await waitFor(() => expect(view.container.querySelector('[data-state="denied"]')).toBeTruthy());
  expect(view.container.querySelector('[data-state="empty"]')).toBeNull();
});

it("shows a revision conflict and keeps the editor open", async () => {
  state.save.mockRejectedValue(new ApiResponseError(409, "watch_revision_conflict"));
  mount(); await screen.findByText(entry.reason);
  fireEvent.click(screen.getByRole("button", { name: t("watch.edit") }));
  const drawer = within(screen.getByRole("dialog"));
  fireEvent.change(drawer.getByLabelText(t("watch.reason")), { target: { value: "fixture change" } });
  fireEvent.click(drawer.getByRole("button", { name: t("watch.save") }));
  expect(await drawer.findByText(t("watch.conflict"))).toBeTruthy();
});

it("has matching WATCH keys in both dictionaries", () => {
  const keys = Object.keys(ru).filter((key) => key.startsWith("watch."));
  expect(Object.keys(en).filter((key) => key.startsWith("watch."))).toEqual(keys);
  expect(keys.every((key) => en[key as keyof typeof en] && ru[key as keyof typeof ru])).toBe(true);
});

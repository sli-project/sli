// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { DecoyLabel } from "../../api/decoy-types";
import { ApiResponseError } from "../../api/client";
import { OverlayProvider } from "../../design-system";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ru } from "../../i18n/ru";
import { en } from "../../i18n/en";

const state = vi.hoisted(() => ({ list: vi.fn(), touches: vi.fn(), save: vi.fn(), manage: true }));
vi.mock("../App", () => ({ useEffectiveAccess: () => ({ subject: { coarse_role: state.manage ? "admin" : "viewer" },
  capabilities: state.manage ? ["decoys.manage"] : [], reports: [{ report_key: "decoys.registry", allowed: true, allowed_actions: ["view", "manage_decoy"] }] }) }));
vi.mock("../../api/client", async (original) => ({ ...await original<typeof import("../../api/client")>(),
  api: { decoys: (params: URLSearchParams) => state.list(params), decoyTouches: (params: URLSearchParams) => state.touches(params),
    saveDecoy: (...args: unknown[]) => state.save(...args) } }));
import { DecoyRegistry } from "./decoys";

const account: DecoyLabel = { id: "fixture-account", kind: "account", identity: { domain_id: 1, entity_id: 12,
  sid: "S-1-5-21-1-2-3-1001", guid: "00000000-0000-4000-8000-000000000004" }, owner: "fixture-owner",
  reason: "fixture account reason", active: true, revision: 2, active_from: "2026-10-18T00:00:00Z", active_to: null,
  actor_type: "session", actor_id: 1, can_manage: true,
  readiness: { state: "not_ready", reasons: ["authentication_audit_unverified"], checked_at: "2026-10-18T00:00:00Z", last_observation_at: null } };
const file: DecoyLabel = { ...account, id: "fixture-file", kind: "file", reason: "fixture file reason",
  identity: { agent_id: "00000000-0000-4000-8000-000000000001", source_instance_id: "fixture-source", collection_scope_id: "scope:one", path: "c:\\decoys\\bait.txt" },
  readiness: { ...account.readiness, reasons: ["read_audit_missing", "exclusions_conflict"] } };

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><OverlayProvider><DecoyRegistry/></OverlayProvider></QueryClientProvider>);
}
beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  state.manage = true;
  state.list.mockResolvedValue({ items: [account, file], has_more: false, next_cursor: null });
  state.save.mockResolvedValue({ item: { id: "fixture-new", revision: 1 } });
});
afterEach(() => { cleanup(); window.history.replaceState(null, "", "/"); setLocale("ru"); vi.restoreAllMocks(); vi.clearAllMocks(); });

it.each(["ru", "en"] as const)("shows both objects, owners, reasons and honest audit readiness in %s", async (locale) => {
  setLocale(locale); mount();
  expect(await screen.findByText(account.reason)).toBeTruthy();
  expect(screen.getByText(file.reason)).toBeTruthy();
  expect(screen.getByText("fixture-source · scope:one")).toBeTruthy();
  expect(screen.getAllByText(account.owner).length).toBeGreaterThan(0);
  expect(screen.getByText(t("decoys.readiness.read_audit_missing"))).toBeTruthy();
  expect(screen.getByText(t("decoys.readiness.authentication_audit_unverified"))).toBeTruthy();
  expect(screen.queryByText(t("decoys.ready"))).toBeNull();
  expect(screen.getByText(t("decoys.description"))).toBeTruthy();
});

it.each(["account", "file"] as const)("registers an existing %s with a reason and exact identity", async (kind) => {
  mount();
  await screen.findByText(account.reason);
  fireEvent.click(screen.getByRole("button", { name: t("decoys.register") }));
  const drawer = within(screen.getByRole("dialog"));
  fireEvent.change(drawer.getByLabelText(t("decoys.kind")), { target: { value: kind } });
  const selected = kind === "account" ? account : file;
  for (const [key, value] of Object.entries(selected.identity)) {
    fireEvent.change(drawer.getByLabelText(t(`decoys.identity.${key}` as keyof typeof ru)), { target: { value: String(value) } });
  }
  fireEvent.change(drawer.getByLabelText(t("decoys.owner")), { target: { value: "fixture-team" } });
  expect((drawer.getByRole("button", { name: t("decoys.save") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(drawer.getByLabelText(t("decoys.reason")), { target: { value: "fixture new label" } });
  expect(drawer.queryByLabelText(/password|пароль/i)).toBeNull();
  fireEvent.click(drawer.getByRole("button", { name: t("decoys.save") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledWith(null, {
    kind, identity: selected.identity, owner: "fixture-team", reason: "fixture new label", active: true, revision: 0,
  }));
});

it("disables a label with a new reason and the current revision", async () => {
  mount(); await screen.findByText(account.reason);
  fireEvent.click(screen.getAllByRole("button", { name: t("decoys.edit") })[0]);
  const drawer = within(screen.getByRole("dialog"));
  expect((drawer.getByLabelText(t("decoys.reason")) as HTMLTextAreaElement).value).toBe("");
  fireEvent.change(drawer.getByLabelText(t("decoys.reason")), { target: { value: "fixture maintenance" } });
  fireEvent.click(drawer.getByLabelText(t("decoys.active")));
  fireEvent.click(drawer.getByRole("button", { name: t("decoys.save") }));
  await waitFor(() => expect(state.save).toHaveBeenCalledWith(account.id, { kind: "account", identity: account.identity,
    owner: account.owner, reason: "fixture maintenance", active: false, revision: 2 }));
});

it("keeps readonly grants from registering or editing", async () => {
  state.manage = false;
  state.list.mockResolvedValue({ items: [{ ...account, can_manage: false }], has_more: false, next_cursor: null });
  mount(); await screen.findByText(account.reason);
  expect((screen.getByRole("button", { name: t("decoys.register") }) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole("button", { name: t("decoys.edit") }) as HTMLButtonElement).disabled).toBe(true);
  expect(state.save).not.toHaveBeenCalled();
});

it("shows retained version reasons and intervals in history", async () => {
  state.list.mockImplementation((params: URLSearchParams) => Promise.resolve(params.has("id")
    ? { items: [account, { ...account, revision: 1, reason: "fixture original reason", active_to: "2026-10-18T00:00:00Z" }], has_more: false }
    : { items: [account, file], has_more: false }));
  mount(); await screen.findByText(account.reason);
  fireEvent.click(screen.getAllByRole("button", { name: t("decoys.history") })[0]);
  const drawer = within(screen.getByRole("dialog"));
  expect(await drawer.findByText("fixture original reason")).toBeTruthy();
  expect(drawer.getAllByText(t("decoys.active_to")).length).toBe(2);
  expect(state.list.mock.calls.some(([params]) => params.get("id") === account.id)).toBe(true);
});

it.each(["ru", "en"] as const)("opens an exact historical version directly, beyond the first history page in %s", async (locale) => {
  setLocale(locale);
  const id = "00000000-0000-4000-8000-000000000003";
  window.history.replaceState(null, "", `/?decoy_id=${id}&decoy_revision=1#decoys`);
  state.list.mockImplementation((params: URLSearchParams) => Promise.resolve(params.has("id")
    ? { items: [{ ...account, id, revision: 1, reason: "fixture event-time reason" }], has_more: false }
    : { items: [{ ...account, id, revision: 201 }], has_more: false }));
  mount();
  const drawer = within(await screen.findByRole("dialog"));
  expect(await drawer.findByText("fixture event-time reason")).toBeTruthy();
  expect(drawer.getByText(id)).toBeTruthy();
  expect(state.list.mock.calls.some(([params]) => params.get("id") === id && params.get("revision") === "1" && !params.has("cursor"))).toBe(true);
});

it("shows an unavailable version without substituting the current label", async () => {
  window.history.replaceState(null, "", "/?decoy_id=00000000-0000-4000-8000-000000000003&decoy_revision=1");
  state.list.mockImplementation((params: URLSearchParams) => Promise.resolve({ items: params.has("id") ? [] : [account], has_more: false }));
  mount();
  expect(await within(await screen.findByRole("dialog")).findByText(t("decoys.version_missing"))).toBeTruthy();
});

it("shows access denial without a misleading empty registry", async () => {
  state.list.mockRejectedValue(new ApiResponseError(403, "decoy_access_denied"));
  const view = mount();
  await waitFor(() => expect(view.container.querySelector('[data-state="denied"]')).toBeTruthy());
  expect(view.container.querySelector('[data-state="empty"]')).toBeNull();
  expect(screen.queryByText(account.reason)).toBeNull();
});

it("mirrors every decoy string in both dictionaries", () => {
  const keys = Object.keys(ru).filter((key) => key.startsWith("decoys."));
  expect(Object.keys(en).filter((key) => key.startsWith("decoys."))).toEqual(keys);
  expect(keys.every((key) => en[key as keyof typeof en] && ru[key as keyof typeof ru])).toBe(true);
});

it.each(["ru", "en"] as const)("shows exact read/denial details and collection loss in %s", async (locale) => {
  setLocale(locale);
  state.list.mockResolvedValue({ items: [{ ...file, readiness: { ...file.readiness, reasons: ["collection_gap"] } }], has_more: false });
  state.touches.mockResolvedValue({ items: [
    { id: "a".repeat(64), mode: "enabled", revision: 2, path: "c:\\decoys\\bait.txt", observed_at: file.active_from,
      event_id: 4663, meaning: "read", outcome: "success", denial_layer: null, subject_sid: "S-1-5-18", access_mask: 1,
      evidence_key: "b".repeat(64), sha256: "c".repeat(64) },
    { id: "d".repeat(64), mode: "shadow", revision: 2, path: "c:\\decoys\\bait.txt", observed_at: file.active_from,
      event_id: 5145, meaning: "access_denied", outcome: "failure", denial_layer: "smb", subject_sid: null, access_mask: 1,
      evidence_key: "e".repeat(64), sha256: "f".repeat(64) },
  ], has_more: false });
  mount(); await screen.findByText(file.reason);
  expect(screen.getByText(t("decoys.readiness.collection_gap"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: locale === "ru" ? "Обращения к файлу" : "File touches" }));
  const drawer = within(screen.getByRole("dialog"));
  expect(await drawer.findByText(locale === "ru" ? "Чтение данных" : "Data read")).toBeTruthy();
  expect(drawer.getByText(locale === "ru" ? "Отказ в доступе" : "Access denied")).toBeTruthy();
  expect(drawer.getByText("5145")).toBeTruthy();
  expect(drawer.getByText("e".repeat(64))).toBeTruthy();
  expect(drawer.getByText(locale === "ru" ? "Теневой режим" : "Shadow mode")).toBeTruthy();
  expect(state.touches.mock.calls[0][0].get("revision")).toBe("2");
  expect(state.touches.mock.calls[0][0].get("touches")).toBe(file.id);
});

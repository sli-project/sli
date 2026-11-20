// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, type AdCredentialList, type AdOperationCredential } from "../../api/client";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ru } from "../../i18n/ru";
import { en } from "../../i18n/en";
import { AdAccountsPage } from "./ad-accounts";

const first: AdOperationCredential = { credential_id: "10000000-0000-4000-8000-000000000002", domain_id: 1,
  label: "synthetic-one", username: "fixture@synthetic.invalid", credential_revision: 1,
  created_by: "session:1", created_at: "2026-10-17T01:00:00Z", updated_by: "session:1", updated_at: "2026-10-17T01:00:00Z",
  check_status: "not_checked", checked_at: null, password_status: "saved", usages: [] };
const second: AdOperationCredential = { ...first, credential_id: "10000000-0000-4000-8000-000000000003", label: "synthetic-two", username: "second@synthetic.invalid" };
const created: AdOperationCredential = { ...first, credential_id: "10000000-0000-4000-8000-000000000004", label: "new-synthetic" };
let data: AdCredentialList;

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  data = { items: [first, second], domains: [{ id: 1, fqdn: "synthetic.invalid" }], key_status: { available: true, error_code: null }, write_enabled: false };
  vi.spyOn(api, "adOperationCredentials").mockImplementation(async () => data);
  vi.spyOn(api, "createAdOperationCredential").mockImplementation(async () => { data = { ...data, items: [...data.items, created] }; return created; });
  vi.spyOn(api, "replaceAdOperationPassword").mockResolvedValue({ ...first, credential_revision: 2 });
  vi.spyOn(api, "deleteAdOperationCredential").mockResolvedValue({ status: "deleted" });
  vi.spyOn(api, "checkAdOperationCredential").mockRejectedValue(new Error("ad_check_transport_unavailable"));
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  render(<QueryClientProvider client={client}><AdAccountsPage/></QueryClientProvider>);
  return client;
}

async function add() {
  mount();
  fireEvent.click(await screen.findByRole("button", { name: t("adAccounts.add") }));
  return screen.findByRole("dialog", { name: t("adAccounts.add") });
}

it.each(["ru", "en"] as const)("shows distinct records without interpreting saved credentials as successful checks in %s", async (locale) => {
  setLocale(locale);
  const client = mount();
  await screen.findByText(first.label);
  expect(screen.getByText(second.label)).toBeTruthy();
  expect(screen.getAllByText(t("adAccounts.notChecked"))).toHaveLength(2);
  expect(document.querySelector('input[type="password"]')).toBeNull();
  expect(JSON.stringify(client.getQueryData(["ad-operation-credentials"]))).not.toContain('"password":');
});

it("clears the write-only field after submit and distinguishes saved from check unavailable", async () => {
  const dialog = await add();
  fireEvent.change(within(dialog).getByLabelText(t("adAccounts.label")), { target: { value: "new-synthetic" } });
  fireEvent.change(within(dialog).getByLabelText(t("adAccounts.account")), { target: { value: "fixture" } });
  const input = within(dialog).getByLabelText(t("adAccounts.password")) as HTMLInputElement;
  expect(input.type).toBe("password");
  expect(input.autocomplete).toBe("new-password");
  fireEvent.change(input, { target: { value: "synthetic-password-marker" } });
  fireEvent.click(within(dialog).getByRole("button", { name: t("adAccounts.saveCheck") }));
  await screen.findByRole("alert");
  expect(api.createAdOperationCredential).toHaveBeenCalledWith({ domain_id: 1, label: "new-synthetic", username: "fixture", password: "synthetic-password-marker" });
  expect(api.checkAdOperationCredential).toHaveBeenCalledWith({ credential_id: created.credential_id, credential_revision: 1 });
  expect(screen.getByText(t("adAccounts.checkUnavailable"))).toBeTruthy();
  expect(document.body.innerHTML).not.toContain("synthetic-password-marker");
  expect(document.querySelector('input[type="password"]')).toBeNull();
});

it("does not claim the account was saved when storage rejects it", async () => {
  vi.mocked(api.createAdOperationCredential).mockRejectedValue(new Error("ad_master_key_unavailable"));
  const dialog = await add();
  fireEvent.change(within(dialog).getByLabelText(t("adAccounts.label")), { target: { value: "new-synthetic" } });
  fireEvent.change(within(dialog).getByLabelText(t("adAccounts.account")), { target: { value: "fixture" } });
  fireEvent.change(within(dialog).getByLabelText(t("adAccounts.password")), { target: { value: "synthetic-marker" } });
  fireEvent.click(within(dialog).getByRole("button", { name: t("adAccounts.saveCheck") }));
  await waitFor(() => expect(screen.getByRole("alert").textContent).toBe(t("adAccounts.error")));
  expect(api.checkAdOperationCredential).not.toHaveBeenCalled();
  expect((screen.getByLabelText(t("adAccounts.password")) as HTMLInputElement).value).toBe("");
});

it("replacement sends the selected revision and exposes only saved status in details", async () => {
  mount();
  fireEvent.click(await screen.findByRole("button", { name: first.label }));
  expect(screen.getByText(t("adAccounts.saved"))).toBeTruthy();
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: t("adAccounts.replace") }));
  const dialog = screen.getByRole("dialog", { name: t("adAccounts.replace") });
  fireEvent.change(within(dialog).getByLabelText(t("adAccounts.newPassword")), { target: { value: "synthetic-replacement" } });
  fireEvent.click(within(dialog).getByRole("button", { name: t("adAccounts.saveCheck") }));
  await waitFor(() => expect(api.replaceAdOperationPassword).toHaveBeenCalledWith({ credential_id: first.credential_id, credential_revision: 1, password: "synthetic-replacement" }));
  await waitFor(() => expect(api.checkAdOperationCredential).toHaveBeenCalledWith({ credential_id: first.credential_id, credential_revision: 2 }));
});

it("requires explicit deletion confirmation and leaves the other record available", async () => {
  mount();
  await screen.findByText(first.label);
  fireEvent.click(document.querySelector("summary")!);
  fireEvent.click(screen.getAllByRole("button", { name: t("adAccounts.delete") })[0]);
  const dialog = await screen.findByRole("dialog");
  expect(api.deleteAdOperationCredential).not.toHaveBeenCalled();
  expect(within(dialog).getByText(t("adAccounts.noAdChange"))).toBeTruthy();
  fireEvent.click(within(dialog).getByRole("button", { name: t("adAccounts.deleteTitle") }));
  await waitFor(() => expect(api.deleteAdOperationCredential).toHaveBeenCalledWith({ credential_id: first.credential_id, credential_revision: 1 }));
  expect(screen.getByText(second.label)).toBeTruthy();
});

it("disables secret input when the KEK is unavailable while allowing deletion", async () => {
  data.key_status = { available: false, error_code: "ad_master_key_not_configured" };
  mount();
  const addButton = await screen.findByRole("button", { name: t("adAccounts.add") });
  expect((addButton as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(t("adAccounts.keyUnavailable"))).toBeTruthy();
  fireEvent.click(document.querySelector("summary")!);
  expect((screen.getAllByRole("button", { name: t("adAccounts.check") })[0] as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getAllByRole("button", { name: t("adAccounts.delete") })[0] as HTMLButtonElement).disabled).toBe(false);
});

it("renders permission denial without credential metadata or a role bypass", async () => {
  vi.mocked(api.adOperationCredentials).mockRejectedValue(new Error("ad_operations_denied"));
  mount();
  await screen.findByText(t("adAccounts.permission"));
  expect(screen.queryByText(first.label)).toBeNull();
  expect(screen.queryByRole("button", { name: t("adAccounts.add") })).toBeNull();
});

it("provides matching Russian and English account-page keys", () => {
  const keys = Object.keys(ru).filter((key) => key.startsWith("adAccounts."));
  expect(keys.length).toBeGreaterThan(30);
  expect(Object.keys(en).filter((key) => key.startsWith("adAccounts."))).toEqual(keys);
  for (const key of keys) expect(en[key as keyof typeof en]).toBeTruthy();
});

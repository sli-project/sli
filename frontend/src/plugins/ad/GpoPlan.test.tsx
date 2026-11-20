// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { api, type GpoPlan } from "../../api/client";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ru } from "../../i18n/ru";
import { en } from "../../i18n/en";
import { ComputerGpoPlan, GpoPlanButton } from "./GpoPlan";

const selection = { domain_id: 1, computer_entity_ids: [3] };
const credential = { credential_id: "00000000-0000-4000-8000-000000000010", credential_revision: 1,
  label: "fixture", username: "EXAMPLE\\fixture", check_status: "not_checked", eligible: true };
const credentialFields = { credential_id: credential.credential_id, credential_revision: credential.credential_revision };
const plan: GpoPlan = { plan_id: "00000000-0000-4000-8000-000000000001", plan_sha256: "a".repeat(64),
  domain_id: 1, domain_name: "synthetic.invalid", expires_at: new Date(Date.now() + 600000).toISOString(),
  targets: [{ entity_id: 3, name: "synthetic-host" }], ou_entity_ids: [2], ous: [{ entity_id: 2, name: "synthetic-ou" }], package: {},
  credential_binding: { ...credentialFields, authorization_sha256: "c".repeat(64), recipient: { agent_id: "00000000-0000-4000-8000-000000000020",
    certificate_sha256: "b".repeat(64), assignment_revision: 1 } }, write_enabled: false, token_ttl_seconds: 604800 };

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  vi.spyOn(api, "gpoPlanCredentials").mockResolvedValue({ items: [credential], selected_credential_id: credential.credential_id, write_enabled: false });
  vi.spyOn(api, "previewGpoPlan").mockResolvedValue(plan);
  vi.spyOn(api, "confirmGpoPlan").mockResolvedValue({ plan_id: plan.plan_id, status: "confirmed", write_enabled: false });
  vi.spyOn(api, "cancelGpoPlan").mockResolvedValue({ plan_id: plan.plan_id, status: "cancelled", write_enabled: false });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

async function open() {
  render(<GpoPlanButton selection={selection}/>);
  fireEvent.click(screen.getByRole("button", { name: t("reports.ad.gpo.open") }));
  await screen.findByRole("dialog");
  await screen.findByText("synthetic-host");
}

it("shows the exact finite selection and requires acknowledgment before saving an intention", async () => {
  await open();
  expect(api.gpoPlanCredentials).toHaveBeenCalledWith(selection);
  expect(api.previewGpoPlan).toHaveBeenCalledWith({ ...selection, ...credentialFields });
  expect(screen.getByText("synthetic-host")).toBeTruthy();
  expect(screen.getByText(t("reports.ad.gpo.readOnly"))).toBeTruthy();
  expect(screen.getByText(t("reports.ad.gpo.packageUnknown"))).toBeTruthy();
  const confirm = screen.getByRole("button", { name: t("reports.ad.gpo.confirm") });
  expect((confirm as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(confirm); fireEvent.click(confirm);
  await screen.findByText(t("reports.ad.gpo.confirmed"));
  expect(api.confirmGpoPlan).toHaveBeenCalledTimes(1);
  expect(api.confirmGpoPlan).toHaveBeenCalledWith({ plan_id: plan.plan_id, plan_sha256: plan.plan_sha256,
    acknowledged: true, ...credentialFields });
  expect(api.cancelGpoPlan).not.toHaveBeenCalled();
});

it("cancels the plan instead of confirming it", async () => {
  await open();
  fireEvent.click(screen.getByRole("button", { name: t("reports.ad.gpo.cancel") }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(api.cancelGpoPlan).toHaveBeenCalledWith({ plan_id: plan.plan_id, plan_sha256: plan.plan_sha256 });
  expect(api.confirmGpoPlan).not.toHaveBeenCalled();
});

it("blocks expired confirmation and lets the operator close the expired preview", async () => {
  vi.mocked(api.previewGpoPlan).mockResolvedValue({ ...plan, expires_at: new Date(Date.now() - 1).toISOString() });
  await open();
  expect(screen.getByText(t("reports.ad.gpo.expired"))).toBeTruthy();
  expect((screen.getByRole("button", { name: t("reports.ad.gpo.confirm") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: t("reports.ad.gpo.cancel") }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(api.confirmGpoPlan).not.toHaveBeenCalled();
});

it("shows a safe denial and does not render server exception text", async () => {
  vi.mocked(api.previewGpoPlan).mockRejectedValue(new Error("private-source-data"));
  render(<GpoPlanButton selection={selection}/>);
  fireEvent.click(screen.getByRole("button", { name: t("reports.ad.gpo.open") }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", t("reports.ad.gpo.error"));
  expect(screen.queryByText("private-source-data")).toBeNull();
  expect(api.confirmGpoPlan).not.toHaveBeenCalled();
});

it("keeps drift rejection visible without reporting a configured policy", async () => {
  vi.mocked(api.confirmGpoPlan).mockRejectedValue(new Error("gpo_plan_drift"));
  await open(); fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: t("reports.ad.gpo.confirm") }));
  await screen.findByRole("alert");
  expect(screen.queryByText(t("reports.ad.gpo.confirmed"))).toBeNull();
  expect(screen.getByRole("dialog")).toBeTruthy();
});

it("splits domains and excludes DC and unknown identities from action selections", async () => {
  render(<ComputerGpoPlan rows={[{ domain_id: 1, entity_id: 3 }, { domain_id: 2, entity_id: 4 },
    { domain_id: 1, entity_id: 5, computer_type: "domain_controller" }, { domain_id: 1 }, { domain_id: 1, entity_id: 3 }]}/>);
  const buttons = screen.getAllByRole("button", { name: t("reports.ad.gpo.open") });
  expect(buttons).toHaveLength(2);
  fireEvent.click(buttons[0]);
  await screen.findByRole("dialog");
  await waitFor(() => expect(api.previewGpoPlan).toHaveBeenCalledWith({ ...selection, ...credentialFields }));
});

it("requires an explicit account when there is no eligible last choice", async () => {
  vi.mocked(api.gpoPlanCredentials).mockResolvedValue({ items: [credential], selected_credential_id: null, write_enabled: false });
  render(<GpoPlanButton selection={selection}/>);
  fireEvent.click(screen.getByRole("button", { name: t("reports.ad.gpo.open") }));
  const select = await screen.findByRole("combobox");
  await waitFor(() => expect((select as HTMLSelectElement).disabled).toBe(false));
  expect(api.previewGpoPlan).not.toHaveBeenCalled();
  expect((screen.getByRole("button", { name: t("reports.ad.gpo.confirm") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(select, { target: { value: credential.credential_id } });
  await screen.findByText("synthetic-host");
  expect(api.previewGpoPlan).toHaveBeenCalledWith({ ...selection, ...credentialFields });
});

it("disables an unsuitable account and never replaces it with another saved account", async () => {
  const unusable = { ...credential, eligible: false };
  vi.mocked(api.gpoPlanCredentials).mockResolvedValue({ items: [unusable, { ...credential, credential_id: "other" }],
    selected_credential_id: credential.credential_id, write_enabled: false });
  render(<GpoPlanButton selection={selection}/>);
  fireEvent.click(screen.getByRole("button", { name: t("reports.ad.gpo.open") }));
  await waitFor(() => expect(screen.getAllByRole("option")).toHaveLength(3));
  expect((screen.getAllByRole("option")[1] as HTMLOptionElement).disabled).toBe(true);
  expect((screen.getByRole("combobox") as HTMLSelectElement).value).toBe("");
  expect(api.previewGpoPlan).not.toHaveBeenCalled();
});

it("replaces the preview and clears acknowledgment when the account changes", async () => {
  const other = { ...credential, credential_id: "00000000-0000-4000-8000-000000000011", label: "other" };
  vi.mocked(api.gpoPlanCredentials).mockResolvedValue({ items: [credential, other], selected_credential_id: credential.credential_id, write_enabled: false });
  await open();
  fireEvent.click(screen.getByRole("checkbox"));
  vi.mocked(api.previewGpoPlan).mockResolvedValue({ ...plan, plan_id: "second-plan",
    credential_binding: { ...plan.credential_binding, credential_id: other.credential_id } });
  fireEvent.change(screen.getByRole("combobox"), { target: { value: other.credential_id } });
  await waitFor(() => expect(api.previewGpoPlan).toHaveBeenCalledTimes(2));
  await waitFor(() => expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false));
  expect(api.cancelGpoPlan).toHaveBeenCalledTimes(1);
  expect((screen.getByRole("button", { name: t("reports.ad.gpo.confirm") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: t("reports.ad.gpo.confirm") }));
  await waitFor(() => expect(api.confirmGpoPlan).toHaveBeenCalledWith({ plan_id: "second-plan", plan_sha256: plan.plan_sha256,
    acknowledged: true, credential_id: other.credential_id, credential_revision: 1 }));
});

it("shows the three approved methods and never issues an AD credential for a manual package", async () => {
  await open();
  expect(screen.getAllByRole("radio")).toHaveLength(3);
  fireEvent.click(screen.getByRole("radio", { name: new RegExp(t("reports.ad.gpo.method.manual")) }));
  await waitFor(() => expect(screen.queryByRole("combobox")).toBeNull());
  expect((screen.getByRole("button", { name: t("reports.ad.gpo.confirm") }) as HTMLButtonElement).disabled).toBe(true);
  expect(api.previewGpoPlan).toHaveBeenCalledTimes(1);
  expect(api.cancelGpoPlan).toHaveBeenCalledTimes(1);
  expect(api.confirmGpoPlan).not.toHaveBeenCalled();
});

it("keeps identical translated keys in both locales", () => {
  const keys = Object.keys(ru).filter((key) => key.startsWith("reports.ad.gpo."));
  expect(keys.length).toBeGreaterThan(20);
  expect(keys.sort()).toEqual(Object.keys(en).filter((key) => key.startsWith("reports.ad.gpo.")).sort());
  for (const key of keys) expect(en[key as keyof typeof en]).toBeTruthy();
});

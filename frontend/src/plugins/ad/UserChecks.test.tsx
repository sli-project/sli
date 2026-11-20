// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ru } from "../../i18n/ru";
import { en } from "../../i18n/en";
import { api } from "../../api/client";
import type { ReportColumnDto, ReportResultDto } from "../../api/report-v2-types";
import { UserChanges, UserChecks, UserReasons, userTableColumns } from "./UserChecks";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it("keeps identical nonempty user workspace keys in Russian and English", () => {
  const keys = (catalog: Record<string, string>) => Object.keys(catalog).filter((key) => key.startsWith("reports.ad.users.") || key.startsWith("reports.v2.ad.users.v2.params.account_state.")).sort();
  expect(keys(ru)).toEqual(keys(en));
  for (const key of keys(en)) expect(en[key as keyof typeof en]).not.toMatch(/[А-Яа-яЁё]/);
});

it("keeps compact mobile columns and account buttons instead of navigation links", () => {
  const columns: ReportColumnDto[] = [
    { key: "name", path: "display_name", label: "Account", kind: "text", link: "/app/entities/{entity_id}" },
    { key: "state", path: "enabled", label: "Enabled", kind: "boolean" },
    { key: "ou", path: "ou", label: "OU", kind: "text" },
  ];
  const mapped = userTableColumns(columns, vi.fn(), false);
  expect(mapped.map((column) => column.mobile)).toEqual([true, true, false]);
  expect(mapped[0].hiddenByDefault).toBe(false);
});

it("shows saved group paths and explicit missing history in the card", () => {
  render(<UserReasons row={{ membership_paths: [{ nodes: [{ name: "synthetic-account" }, { name: "synthetic-team" }, { name: "synthetic-admins" }] }] }}/>);
  expect(screen.getByText("synthetic-account → synthetic-team → synthetic-admins")).toBeTruthy();
  expect(screen.getByRole("heading", { name: "История" }).nextElementSibling?.textContent).toBe("—");
  expect(screen.queryByText("0")).toBeNull();
});

it("opens a change account in the same overlay callback and hides secondary mobile columns", () => {
  const select = vi.fn();
  const row = { id: 1, sam: "synthetic-account", actor: null, label: "Synthetic change" };
  const { container } = render(<UserChanges title="Changes" rows={[row]} onSelect={select} columns={[
    { key: "name", path: "sam", label: "Account", kind: "text", link: "/app/entities/{id}" },
    { key: "change", path: "label", label: "Change", kind: "text" },
    { key: "actor", path: "actor", label: "Actor", kind: "text" },
  ]}/>);
  fireEvent.click(screen.getByRole("button", { name: "synthetic-account" }));
  expect(select).toHaveBeenCalledWith(row);
  expect(screen.queryByRole("link")).toBeNull();
  expect(screen.getByRole("cell", { name: "—" })).toBeTruthy();
  expect(container.querySelector('th[data-mobile="false"]')?.textContent).toBe("Actor");
});

it("keeps the check action and retries a failed user list without a callout", async () => {
  const result: ReportResultDto = {
    contract_id: "sli.report-result.v2", report_key: "ad.users.v2", state: "ok",
    items: [{ key: "synthetic-check", title: "Synthetic check", status: "new", total: 2, action: "Synthetic action",
      remediation: "Synthetic remediation", objects: [{ entity_id: 7, name: "synthetic-user" }] }],
    has_more: false, next_cursor: null, filtered_count: 1, metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {},
  };
  const request = vi.spyOn(api, "reportV2Data").mockRejectedValueOnce(new Error("Internal error"))
    .mockResolvedValueOnce({ ...result, items: [{ entity_id: 8, name: "synthetic-user-two" }] });
  const { container } = render(<QueryClientProvider client={new QueryClient()}>
    <UserChecks result={result} baseParams="" onSelect={vi.fn()}/>
  </QueryClientProvider>);
  fireEvent.click(screen.getByText("Synthetic check").closest("summary")!);
  expect(await screen.findByText("Synthetic action", { exact: false })).toBeTruthy();
  expect(screen.queryByText("Synthetic remediation")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("reports.ad.users.open_all") }));
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain(t("reports.ad.users.objects_unavailable", { check: "Synthetic check" }));
  expect(container.querySelector(".sli-ds-callout")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("state.retry") }));
  expect(await screen.findByRole("button", { name: "synthetic-user-two" })).toBeTruthy();
  expect(request).toHaveBeenCalledTimes(2);
});

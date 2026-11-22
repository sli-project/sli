// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale } from "../../i18n";
import { ru } from "../../i18n/ru";
import { en } from "../../i18n/en";
import type { ReportColumnDto } from "../../api/report-v2-types";
import { DataTable } from "../../design-system";
import { UserChanges, userTableColumns } from "./UserChecks";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it("keeps identical nonempty user workspace keys in Russian and English", () => {
  const keys = (catalog: Record<string, string>) => Object.keys(catalog).filter((key) => key.startsWith("reports.ad.users.") || key.startsWith("reports.v2.ad.users.v2.params.account_state.")).sort();
  expect(keys(ru)).toEqual(keys(en));
  for (const key of keys(en)) expect(en[key as keyof typeof en]).not.toMatch(/[А-Яа-яЁё]/);
});

it("opens the account and its privilege paths from the corresponding cells", () => {
  const columns: ReportColumnDto[] = [
    { key: "name", path: "display_name", label: "Account", kind: "text", link: "/app/entities/{entity_id}" },
    { key: "state", path: "enabled", label: "Enabled", kind: "boolean" },
    { key: "ou", path: "ou", label: "OU", kind: "text" },
    { key: "privilege_basis", path: "privilege_basis", label: "Privileges", kind: "list" },
  ];
  const select = vi.fn();
  const row = { id: 1, sam: "synthetic-account", display_name: "Synthetic Account", nested_privilege_groups: ["Synthetic Admins"] };
  render(<DataTable caption="Accounts" columns={userTableColumns(columns, select)} rows={[row]} rowKey={(item) => String(item.id)}/>);
  fireEvent.click(screen.getByRole("button", { name: "synthetic-account" }));
  expect(select).toHaveBeenLastCalledWith(row);
  fireEvent.click(screen.getByRole("button", { name: "Synthetic Admins" }));
  expect(select).toHaveBeenLastCalledWith(row, "rights");
});

it("opens an account from its change and omits an unrecorded initiator column", () => {
  const select = vi.fn();
  const row = { id: 1, sam: "synthetic-account", actor: null, label: "Synthetic change" };
  render(<UserChanges title="Changes" rows={[row]} onSelect={select} columns={[
    { key: "name", path: "sam", label: "Account", kind: "text", link: "/app/entities/{id}" },
    { key: "change", path: "label", label: "Change", kind: "text" },
    { key: "actor", path: "actor", label: "Actor", kind: "text" },
  ]}/>);
  fireEvent.click(screen.getByRole("button", { name: "synthetic-account" }));
  expect(select).toHaveBeenCalledWith(row);
  expect(screen.queryByRole("link")).toBeNull();
  expect(screen.queryByRole("columnheader", { name: "Actor" })).toBeNull();
});

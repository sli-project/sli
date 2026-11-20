// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale } from "../../i18n";
import { ru } from "../../i18n/ru";
import { en } from "../../i18n/en";
import type { ReportColumnDto } from "../../api/report-v2-types";
import { UserChanges, UserReasons, userTableColumns } from "./UserChecks";

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

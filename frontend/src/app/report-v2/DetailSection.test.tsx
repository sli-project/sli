// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale, t } from "../../i18n";
import { DataTable } from "../../design-system";
import { tableColumns } from "./DetailSection";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("renders plain cells without methodological details (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const row = Object.freeze({ control_id: "dc.dns", basis: "DCDiag DNS <synthetic>" });
  const column = tableColumns([{ key: "basis", label: "Basis", kind: "text", path: "basis" }])[0];
  const { container } = render(<DataTable caption="Checks" columns={[column]} rows={[row]} rowKey={() => "check"}/>);
  expect(screen.queryByText(t("reports.passport.more"))).toBeNull();
  expect(container.querySelector("details")).toBeNull();
  expect(screen.getByText(row.basis).innerHTML).toContain("&lt;synthetic&gt;");
  expect(column.value!(row)).toBe(row.basis);
  setLocale("ru");
});

import { expect, it } from "vitest";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { FILE_AUDIT_TABS, fileAuditFields, fileAuditParams, isFileAuditReport } from "./report";

const definition: ReportDefinitionDto = {
  key: "file-audit.actions", section: "reports/file-audit", title: "Fixture report", description: "", archetype: "list",
  params: [
    { key: "period", kind: "period", label: "Period", required: true, default: "24h" },
    { key: "source_kind", kind: "choice", label: "Source", options: [{ value: "server", label: "Servers" }, { value: "workstation", label: "Workstations" }] },
    { key: "path", kind: "text", label: "Path" },
    { key: "include_nested", kind: "choice", label: "Nested", options: [{ value: "true", label: "Yes" }, { value: "false", label: "No" }] },
    { key: "employee", kind: "text", label: "Employee" },
    { key: "share", kind: "multichoice", label: "Share", options_from: "share" },
    { key: "operation", kind: "choice", label: "Operation" },
  ],
  columns: [{ key: "path", path: "path", label: "Object", kind: "text" }],
  views: [{ key: "table", kind: "table", source: "items" }],
  row_key: "id", detail: "fields", export: true, limits: { default: 50, max: 100 }, presets: [], row_links: [],
  filter_options: { share: [{ value: "scope:one", label: "Synthetic server · Share", important: true }] },
};

it("recognizes exactly eight report identifiers", () => {
  expect(FILE_AUDIT_TABS).toHaveLength(8);
  for (const tab of FILE_AUDIT_TABS) expect(isFileAuditReport(`file-audit.${tab}`)).toBe(true);
  expect(isFileAuditReport("file-audit.actions/extra")).toBe(false);
  expect(isFileAuditReport("file-audit.unreviewed")).toBe(false);
});

it("pins preset windows to the applied instant for cursor pages and export", () => {
  const anchor = new Date("2026-10-10T12:00:00Z");
  const first = fileAuditParams(definition, { period: { preset: "24h" } }, "UTC", null, anchor)!;
  const next = fileAuditParams(definition, { period: { preset: "24h" } }, "UTC", "next", anchor)!;
  expect(first.get("period")).toBe("custom");
  expect(first.get("from")).toBe("2026-10-09T12:00:00.000Z");
  expect(first.get("to")).toBe(next.get("to"));
  expect(first.get("from")).toBe(next.get("from"));
});

it("requests each supported page size and refuses a size beyond the declaration limit", () => {
  const current = { ...definition, limits: { default: 50, max: 200 } };
  for (const limit of [25, 50, 100, 200]) {
    const params = fileAuditParams(current, { period: { preset: "24h" } }, "UTC", null, new Date("2026-10-10T12:00:00Z"), limit)!;
    expect(params.get("limit")).toBe(String(limit));
  }
  expect(fileAuditParams(definition, { period: { preset: "24h" } }, "UTC", null, new Date(), 200)?.get("limit")).toBe("100");
});

it("declares a single share field, nested paths and four date-time presets", () => {
  const fields = fileAuditFields(definition);
  expect(fields.map((field) => field.key)).toEqual(["period", "source_kind", "path", "employee", "share", "operation"]);
  expect(fields[0]).toMatchObject({ presets: ["24h", "7d", "30d", "custom"], precision: "datetime-local" });
  expect(fields[2]).toMatchObject({ wide: true, nested: { key: "include_nested" } });
  expect(fields[4]).toMatchObject({ kind: "search-multiselect", options: [{ important: true }] });
});

it("sends the exact selected time range in the SLI time zone, all shares and a bounded page", () => {
  const params = fileAuditParams(definition, {
    period: { preset: "custom", from: "2026-10-01T09:15", to: "2026-10-01T10:45" },
    path: "C:\\Synthetic\\Folder", include_nested: "false", employee: "synthetic-user", share: ["scope:one", "scope:two"], operation: "delete",
  }, "Asia/Bangkok", "synthetic-cursor")!;
  expect(params.get("from")).toBe("2026-10-01T02:15:00.000Z");
  expect(params.get("to")).toBe("2026-10-01T03:45:00.000Z");
  expect(params.getAll("share")).toEqual(["scope:one", "scope:two"]);
  expect(params.get("include_nested")).toBe("false");
  expect(params.get("path")).toBe("C:\\Synthetic\\Folder");
  expect(params.get("employee")).toBe("synthetic-user");
  expect(params.get("operation")).toBe("delete");
  expect(params.get("cursor")).toBe("synthetic-cursor");
  expect(params.get("limit")).toBe("50");
});

it("does not query an incomplete, reversed, empty or invalid-zone time range", () => {
  for (const period of [
    { preset: "custom" as const, from: "2026-10-01T09:00" },
    { preset: "custom" as const, from: "2026-10-02T09:00", to: "2026-10-01T09:00" },
    { preset: "custom" as const, from: "2026-10-01T09:00", to: "2026-10-01T09:00" },
  ]) expect(fileAuditParams(definition, { period }, "UTC")).toBeNull();
  expect(fileAuditParams(definition, { period: { preset: "custom", from: "2026-10-01T09:00", to: "2026-10-02T09:00" } }, "invalid:synthetic")).toBeNull();
});

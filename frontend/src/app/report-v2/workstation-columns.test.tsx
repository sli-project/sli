// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import type { TableColumn } from "../../design-system";
import { localeRuntime, setLocale, t } from "../../i18n";
import { workstationColumns } from "./workstation-columns";

type Row = Record<string, unknown>;
const columns: TableColumn<Row>[] = ["event_id", "semantic_type", "logon_type", "process_image", "device_id", "device_class", "device_description"]
  .map((key) => ({ key, label: key, value: (row) => row[key] }));
beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => {}); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });
const show = (report: string, column: string, row: Row) => {
  const selected = workstationColumns(report, columns).find((item) => item.key === column)!;
  render(<>{selected.render!(row)}</>);
};

it.each(["ru", "en"] as const)("shows actual process paths and device descriptions, never IDs as names (%s)", (locale) => {
  setLocale(locale);
  const facts = Object.freeze({ process_name: "C:\\synthetic\\worker.exe", device_description: "Synthetic removable drive",
    device_id: "synthetic-device-id", device_class: "synthetic-class-id" });
  const row = Object.freeze({ facts });
  show("workstations.processes", "process_image", row);
  expect(screen.getByText("C:\\synthetic\\worker.exe")).toBeTruthy();
  show("workstations.usb", "device_description", row);
  expect(screen.getByText("Synthetic removable drive")).toBeTruthy();
  expect(workstationColumns("workstations.usb", columns).some((item) => ["device_id", "device_class"].includes(item.key))).toBe(false);
  expect(facts.device_id).toBe("synthetic-device-id");
  cleanup();
  show("workstations.usb", "device_description", { facts: { device_id: "synthetic-id", device_description: "  " } });
  expect(screen.getByText(locale === "ru" ? "Название не получено" : "Name not received")).toBeTruthy();
  expect(screen.queryByText("synthetic-id")).toBeNull();
});

it.each([undefined, null, "", "99", {}, "toString"])("marks unsupported logon type %s unknown", (logon_type) => {
  show("workstations.logons", "logon_type", { facts: { logon_type } });
  expect(screen.getByText("Тип входа не определён")).toBeTruthy();
});

it.each([
  ["workstations.logons", 4624, "process.started.fragment"],
  ["workstations.processes", 4624, "authentication.session.created"],
  ["workstations.logons", "4624", "authentication.session.created"],
  ["workstations.usb", 9999, "device.external.observed"],
  ["workstations.processes", null, null],
])("does not guess operations for incompatible %s / %s / %s", (report, event_id, semantic_type) => {
  show(String(report), "event_id", { event_id, semantic_type });
  expect(screen.getByText("Название операции не определено")).toBeTruthy();
});

it.each([
  ["workstations.processes", 4688, "process.started.fragment", "Запущен процесс"],
  ["workstations.processes", 7045, "service.installed.fragment", "Установлена служба"],
  ["workstations.usb", 6416, "device.external.observed", "Обнаружено внешнее устройство"],
])("uses the canonical pair within its report (%s / %s)", (report, event_id, semantic_type, expected) => {
  show(String(report), "event_id", { event_id, semantic_type });
  expect(screen.getByText(String(expected))).toBeTruthy();
});

it("does not rewrite other reports or source column definitions", () => {
  const before = [...columns];
  expect(workstationColumns("security.events.chains", columns)).toBe(columns);
  workstationColumns("workstations.logons", columns);
  expect(columns).toEqual(before);
  expect(columns.find((item) => item.key === "event_id")?.render).toBeUndefined();
});

const ancillaryProcessKeys = ["process_command_line", "service_name", "service_file", "task_name", "task_change"];
const processColumns: TableColumn<Row>[] = ["observed_at", "host_name", "event_id", "process_image", ...ancillaryProcessKeys]
  .map((key) => Object.freeze({ key, label: key, value: (row: Row) => (row.facts as Row | undefined)?.[key] }));
const visibleProcessKeys = (rows: Row[]) => workstationColumns("workstations.processes", processColumns, rows).map((column) => column.key);

it("hides only the five absent process facts without changing evidence definitions or rows", () => {
  const facts = Object.freeze({ process_image: "synthetic.exe", process_command_line: null, service_name: "", service_file: "  " });
  const row = Object.freeze({ facts });
  const before = [...processColumns];
  expect(visibleProcessKeys([row])).toEqual(["observed_at", "host_name", "event_id", "process_image"]);
  expect(processColumns).toEqual(before);
  expect(processColumns.map((column) => column.key)).toEqual(["observed_at", "host_name", "event_id", "process_image", ...ancillaryProcessKeys]);
  expect(row.facts).toBe(facts);
});

it.each(["-", "unknown", "not_collected", 0, false])("retains a nonempty native process value %s", (value) => {
  for (const key of ancillaryProcessKeys) expect(visibleProcessKeys([{ facts: { [key]: value } }])).toContain(key);
});

it("keeps the definition for zero rows and restores facts found on a later loaded page", () => {
  expect(visibleProcessKeys([])).toEqual(processColumns.map((column) => column.key));
  const first = { facts: { process_image: "synthetic.exe" } };
  expect(visibleProcessKeys([first])).not.toContain("task_name");
  expect(visibleProcessKeys([first, { facts: { task_name: "Synthetic task" } }])).toContain("task_name");
});

it.each(["workstations.logons", "workstations.usb", "demo.events"])("does not prune absent process keys in %s", (report) => {
  const selected = workstationColumns(report, processColumns, [{ facts: {} }]);
  expect(selected.map((column) => column.key)).toEqual(processColumns.map((column) => column.key));
});


it.each(["ru", "en"] as const)("shows the station name and its display-only provenance in all four reports (%s)", (locale) => {
  setLocale(locale);
  for (const family of ["logons", "processes", "usb", "protection"]) {
    const column = workstationColumns(`workstations.${family}`, [{ key: "host_name", label: "Computer" }])[0];
    const { unmount } = render(<>{column.render!({ host_name: "PC-01", host_name_source: "agent_reported" })}</>);
    expect(screen.getByText("PC-01").title).toBe(t("workstations.display.name_source.agent_reported"));
    unmount();
  }
});


it("marks a legacy Windows event name as unverified display metadata", () => {
  const column = workstationColumns("workstations.protection", [{ key: "host_name", label: "Computer" }])[0];
  render(<>{column.render!({ host_name: "PC-LEGACY", host_name_source: "event_reported" })}</>);
  expect(screen.getByText("PC-LEGACY").title).toBe(t("workstations.display.name_source.event_reported"));
});

it.each(["ru", "en"] as const)("explains protection without changing support evidence (%s)", (locale) => {
  setLocale(locale);
  const row = Object.freeze({ semantic_type: "security.protection.state" });
  show("workstations.protection", "semantic_type", row);
  expect(screen.getByText(t("workstations.display.protection_unknown"))).toBeTruthy();
  expect(row.semantic_type).toBe("security.protection.state");
  expect(columns.find((item) => item.key === "semantic_type")?.render).toBeUndefined();
});

it.each(["ru", "en"] as const)("summarizes protection flags and preserves original evidence in %s", (locale) => {
  setLocale(locale);
  for (const [facts, key] of [[{ antivirus_enabled: true, real_time_protection_enabled: true }, "protection_on"], [{ antivirus_enabled: false }, "protection_off"], [{ antivirus_enabled: true }, "protection_unknown"]] as const) {
    const row = Object.freeze({ semantic_type: "security.protection.state", facts: Object.freeze(facts) });
    const selected = workstationColumns("workstations.protection", [...columns, { key: "antivirus_enabled", label: "AV" }]);
    expect(selected.some((column) => column.key === "antivirus_enabled")).toBe(false);
    const { unmount } = render(<>{selected.find((column) => column.key === "semantic_type")!.render!(row)}</>);
    expect(screen.getByText(t(`workstations.display.${key}`))).toBeTruthy();
    unmount();
  }
});
it("keeps six rule-quality metrics and a word-wrapped rule name", () => {
  const all = ["rule_name", "findings_produced", "confirmed", "false_positive", "false_positive_rate", "complete_evidence_share", "closed", "suppressed", "repeat_rate"].map((key) => ({ key, label: key, render: () => "A long rule name" }));
  const main = workstationColumns("security.rule-quality", all);
  expect(main).toHaveLength(6);
  expect(all).toHaveLength(9);
  expect(main[0].minWidth).toBe("var(--sli-field-max-width)");
  render(<>{main[0].render!({})}</>);
  expect(screen.getByText("A long rule name").style.overflowWrap).toBe("normal");
});

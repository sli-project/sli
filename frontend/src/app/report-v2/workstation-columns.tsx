import type { TableColumn } from "../../design-system";
import { t, type MessageKey } from "../../i18n";

type Row = Record<string, unknown>;
const reports = new Set(["workstations.logons", "workstations.processes", "workstations.usb", "workstations.protection"]);

// These pairs belong to the workstation source-owner normalizer, which checks
// channel/provider before producing semantic_type. Never interpret an ID alone.
const operations: Record<string, readonly (readonly [number, string, string])[]> = {
  "workstations.logons": [
    [4624, "authentication.session.created", "signed_in"],
    [4625, "authentication.session.failed", "sign_in_failed"],
    [4634, "authentication.session.ended", "session_ended"],
    [4647, "authentication.logout.requested", "logout_requested"],
  ],
  "workstations.processes": [
    [4688, "process.started.fragment", "process_started"],
    [4697, "service.installed.fragment", "service_installed"],
    [7045, "service.installed.fragment", "service_installed"],
    [4698, "scheduled_task.created.fragment", "task_created"],
    [4699, "scheduled_task.deleted.fragment", "task_deleted"],
    [4700, "scheduled_task.enabled.fragment", "task_enabled"],
    [4701, "scheduled_task.disabled.fragment", "task_disabled"],
    [4702, "scheduled_task.updated.fragment", "task_updated"],
  ],
  "workstations.usb": [6416, 400, 410, 420, 2003, 2100, 2101].map((id) =>
    [id, "device.external.observed", "device_observed"] as const),
};
const signInTypes: Record<string, string> = {
  "0": "system", "2": "interactive", "3": "network", "4": "batch", "5": "service",
  "7": "unlock", "8": "network_cleartext", "9": "new_credentials", "10": "remote_interactive",
  "11": "cached_interactive", "12": "cached_remote_interactive", "13": "cached_unlock",
};
const label = (key: string) => t(`workstations.display.${key}` as MessageKey);
const factsOf = (row: Row): Row => row.facts && typeof row.facts === "object" && !Array.isArray(row.facts) ? row.facts as Row : {};
const sourceText = (value: unknown): string | undefined => typeof value === "string" && value.trim() && value.trim() !== "-" ? value : undefined;
const ancillaryProcessColumns = new Set(["process_command_line", "service_name", "service_file", "task_name", "task_change"]);

/** Main-table presentation only: the original definition still drives evidence drawers and exports. */
export function workstationColumns(report: string, columns: TableColumn<Row>[], rows: Row[] = []): TableColumn<Row>[] {
  if (reports.has(report) || report === "workstations.protection") columns = columns.map((column) => column.key === "host_name"
    ? { ...column, render: (row: Row) => {
      const source = typeof row.host_name_source === "string" && ["ad_enrollment", "agent_reported", "event_reported", "module_config"].includes(row.host_name_source)
        ? row.host_name_source : "unknown";
      return <span title={label(`name_source.${source}`)}>{sourceText(row.host_name) ?? "—"}</span>;
    } } : column);
  if (report === "security.rule-quality") return columns.filter((column) => [columns.some((item) => item.key === "rule_name") ? "rule_name" : "rule_code", "findings_produced", "confirmed", "false_positive", "false_positive_rate", "complete_evidence_share"].includes(column.key)).map((column) => column.key === "rule_name"
    ? { ...column, minWidth: "var(--sli-field-max-width)", render: column.render ? (row: Row) => <span style={{ overflowWrap: "normal", wordBreak: "normal" }}>{column.render!(row)}</span> : undefined } : column);
  if (!reports.has(report)) return columns;
  const hasOperation = columns.some((column) => column.key === "event_id");
  return columns.filter((column) => !(report === "workstations.protection" && !["observed_at", "host_name", "semantic_type", "group", "member", "change"].includes(column.key))
    && !(hasOperation && report !== "workstations.protection" && column.key === "semantic_type")
    && !(report === "workstations.usb" && ["device_id", "device_class"].includes(column.key))
    // Loaded rows only: a later page can restore a column. Keep the empty-view
    // definition and all nonempty values, including literal "-" and unknowns.
    && !(report === "workstations.processes" && rows.length > 0 && ancillaryProcessColumns.has(column.key)
      && rows.every((row) => {
        const value = factsOf(row)[column.key];
        return value == null || typeof value === "string" && !value.trim();
      }))).map((column) => {
    if (report === "workstations.protection" && column.key === "semantic_type") return { ...column,
      label: label("protection_state"), minWidth: "var(--sli-field-min-width)", render: (row: Row) => {
        if (row.semantic_type !== "security.protection.state") return label("unknown_operation");
        const facts = factsOf(row);
        const flags = [facts.antivirus_enabled, facts.real_time_protection_enabled];
        return label(flags.some((value) => value === false) ? "protection_off" : flags.every((value) => value === true) ? "protection_on" : "protection_unknown");
      } };
    if (column.key === "event_id" && report !== "workstations.protection") return { ...column, label: label("operation"), kind: "text" as const, render: (row: Row) => {
      const match = operations[report].find(([id, semantic]) => row.event_id === id && row.semantic_type === semantic);
      return label(match?.[2] ?? "unknown_operation");
    } };
    if (report === "workstations.logons" && column.key === "logon_type") return { ...column, render: (row: Row) => {
      const value = factsOf(row).logon_type;
      const code = typeof value === "string" || typeof value === "number" ? String(value) : "";
      return label(`logon.${Object.hasOwn(signInTypes, code) ? signInTypes[code] : "unknown"}`);
    } };
    if (report === "workstations.processes" && column.key === "process_image") return { ...column, render: (row: Row) => {
      const facts = factsOf(row);
      return sourceText(facts.process_image) ?? sourceText(facts.process_name) ?? label("name_unavailable");
    } };
    if (report === "workstations.usb" && column.key === "device_description") return { ...column,
      render: (row: Row) => sourceText(factsOf(row).device_description) ?? label("name_unavailable") };
    return column;
  });
}
